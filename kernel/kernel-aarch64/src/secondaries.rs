// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Starting the machine's other CPUs, and what they do when they arrive.
//!
//! # The entry contract is firmware's, not the kernel's
//!
//! A CPU started through the power-control interface begins executing at a
//! **physical** address with translation off, at the exception level of the CPU
//! that asked, with nothing else set up: no stack, no vectors, no identity of
//! its own beyond the one word passed as the start request's context.
//!
//! That is the same contract the boot CPU was entered under, and the stub below
//! is deliberately the boot stub with three things removed. It does not
//! normalize the exception level (firmware started it at EL1, where the boot
//! CPU already is), it does not build page tables (they exist), and it does not
//! clear `.bss` (that would erase the running kernel). What is left is: take a
//! stack, turn translation on, get into the high half, and call Rust.
//!
//! # Which tables, and why two sets
//!
//! The coarse boot tables are still there — they are reserved frames inside the
//! image, which the allocator never hands out — and they are the only tables
//! reachable from a CPU with the MMU off, because reaching the kernel's real
//! roots means reading a `static`, and reading a `static` means translation.
//! So a secondary comes up on the boot tables exactly as the boot CPU did, gets
//! into the high half where the kernel's own roots are legible, and adopts
//! them. The stack it is using across that switch is in `.bss`, which both
//! high-half roots map at the same address, which is what makes the switch
//! survivable mid-function.
//!
//! **The frame the stub pushes across the MMU switch is written with caches off
//! and read with them on**, which on real hardware can read a stale line. That
//! is not new here: the boot stub's own `bl aarch64_boot_mmu_up` has the same
//! shape, this port has always had it, and it is invisible under an emulator
//! that does not model caches. Naming it is worth more than a fix that only
//! this half of the boot path would carry.
//!
//! This is the same two-stage shape the x86-64 port uses
//! (`kernel/kernel/src/secondaries.rs`) and for a related reason: on that port
//! the second stage exists because the destination did not exist when the CPU
//! was moved, here because the destination is not addressable until the CPU has
//! moved. Neither port can do it in one.
//!
//! # What an arriving CPU is allowed to touch
//!
//! One bit in `kcore::smp`'s arrival bitmap, and nothing else. It does not
//! enter the scheduler, take a lock, allocate, or print: this kernel dispatches
//! to one CPU (build/README.md, D8), and the rest of the kernel's state is
//! written under justifications that still say so. Making bring-up and
//! scheduling separate steps is what keeps that honest — the CPUs are here, and
//! the kernel says so, before anything relies on them being here.
//!
//! Normative: docs/roadmap/02-smp-bring-up-plan.md ("Phase 2"),
//! docs/kernel/08-multicore-scalability.md
//! Budget: none (boot path)

use crate::*;
use tessera_karch::{CpuBringUp, CpuLocal, CpuStartError};

/// How long the boot CPU waits for a started CPU to reach kernel code.
///
/// A spin count rather than a time, because there is no clock yet — the tick is
/// started later — and because what it bounds is not a duration anyone cares
/// about, only the difference between reporting an absent CPU and hanging on
/// it. Generous enough that an emulated CPU coming up under a loaded host is
/// not called absent, and short enough that a boot which loses every CPU still
/// finishes.
pub(crate) const ARRIVAL_SPINS: u64 = 200_000_000;

/// Stack bytes reserved for each secondary CPU.
///
/// Small on purpose. The boot CPU's stack is 2 MiB because the boot path builds
/// kcore objects by value on it; a secondary calls four functions and halts, and
/// sizing its stack like the boot CPU's would reserve megabytes per CPU for a
/// call depth of four. It must stay a power of two the stub can form with a
/// single `movz`.
const SECONDARY_STACK_BYTES: usize = 16 * 1024;

/// One stack per CPU slot, including the boot CPU's — whose slot is never used,
/// because it arrived on the stack the linker gave it. The unused slot buys an
/// index that means the same thing here as everywhere else, which is worth more
/// than the bytes.
///
/// In `.bss`, so the boot CPU's zeroing pass covers it and both high-half roots
/// map it read-write as part of the kernel image.
/// The alignment is the point of the wrapper: a `u8` array is byte-aligned, and
/// a stack pointer must be 16-byte aligned or the first `stp` through it is a
/// fault — silently on a machine whose `SCTLR_EL1.SA` happens to be clear, and
/// then not silently on the next one.
#[repr(align(16))]
// The field is read by the entry stub and by nothing else, which is what makes
// it dead to the compiler and load-bearing to the machine.
#[allow(dead_code)]
struct SecondaryStacks([[u8; SECONDARY_STACK_BYTES]; kcore::percpu::MAX_CPUS]);

// SAFETY: the entry stub reaches this array by name from `global_asm!`, so the
// symbol must survive; nothing else in the image defines it.
#[unsafe(no_mangle)]
static mut SECONDARY_STACKS: SecondaryStacks =
    SecondaryStacks([[0; SECONDARY_STACK_BYTES]; kcore::percpu::MAX_CPUS]);

/// The kernel's real translation roots, published by the boot CPU once it has
/// switched to them, for arriving CPUs to adopt. Zero until then.
static KERNEL_TTBR0: AtomicU64 = AtomicU64::new(0);
static KERNEL_TTBR1: AtomicU64 = AtomicU64::new(0);

/// Records the roots a secondary is to adopt.
///
/// Called by the boot CPU immediately after it switches to them, and before any
/// CPU is started — a secondary that arrived first would find zeros and have
/// nowhere to go.
pub(crate) fn publish_kernel_tables(ttbr0: PhysAddr, ttbr1: PhysAddr) {
    KERNEL_TTBR0.store(ttbr0.as_u64(), Ordering::Release);
    KERNEL_TTBR1.store(ttbr1.as_u64(), Ordering::Release);
}

// SAFETY: this declares a symbol defined by the `global_asm!` block below. Its
// only use is as the physical entry address handed to firmware, which is
// exactly what the power-control interface specifies.
unsafe extern "C" {
    fn aarch64_secondary_entry(context: u64) -> !;
}

core::arch::global_asm!(
    r#"
.section .text.secondary_entry
.globl aarch64_secondary_entry
aarch64_secondary_entry:
    // x0 is the start request's context word: this CPU's dense index. Park it
    // in a callee-saved register — everything below clobbers the argument
    // registers, and the index has to survive as far as the Rust call.
    mov     x20, x0

    // Mask D/A/I/F. This CPU has no vector base of its own yet, so an
    // exception taken here would branch to whatever firmware left behind.
    msr     daifset, #0xf

    // EL1 state on arrival, matching what the boot stub establishes: MMU off,
    // caches off, RES1 bits set. Firmware's SCTLR_EL1 is firmware's.
    ldr     x0, =0x30d00800
    msr     sctlr_el1, x0
    isb

    // This CPU's stack, at its physical address: translation is still off, so
    // `adrp` resolves the symbol to where it physically sits.
    adrp    x1, SECONDARY_STACKS
    add     x1, x1, #:lo12:SECONDARY_STACKS
    mov     x2, #{stack_bytes}
    madd    x1, x20, x2, x1         // base + index * size
    add     x1, x1, x2              // ...and up to the top of the slot
    mov     sp, x1

    // Translation on, using the coarse boot tables the boot CPU left in place.
    adrp    x0, boot_ttbr0_root
    add     x0, x0, #:lo12:boot_ttbr0_root
    adrp    x1, boot_ttbr1_root
    add     x1, x1, #:lo12:boot_ttbr1_root
    bl      aarch64_secondary_mmu_up

    // TTBR0 identity-maps this physical code for one more instant. Branch to
    // the high half, where the kernel's own roots become legible.
    ldr     x0, =aarch64_secondary_high
    br      x0

.globl aarch64_secondary_high
aarch64_secondary_high:
    // Same stack slot, now by its high-half address.
    ldr     x1, =SECONDARY_STACKS
    mov     x2, #{stack_bytes}
    madd    x1, x20, x2, x1
    add     x1, x1, x2
    mov     sp, x1

    mov     x0, x20
    bl      aarch64_secondary_main

    // `aarch64_secondary_main` is `-> !`; if it ever returns, stop rather than
    // run on through whatever follows in memory.
1:
    wfi
    b       1b
"#,
    stack_bytes = const SECONDARY_STACK_BYTES,
);

/// Turns translation on for an arriving CPU, using roots that already exist.
///
/// The boot CPU's equivalent (`aarch64_boot_mmu_up`) builds the tables first;
/// this one must not, and the difference is the whole reason it is a separate
/// function rather than a shared one with a flag. Like that one it forwards its
/// arguments to a position-independent primitive and touches no static, which
/// is what makes it correct while executing at the physical load address.
///
/// # Safety
///
/// Called once per arriving CPU, with the MMU off, naming the two live boot
/// roots.
#[unsafe(no_mangle)]
unsafe extern "C" fn aarch64_secondary_mmu_up(ttbr0_root: u64, ttbr1_root: u64) {
    // SAFETY: the roots are the boot tables, still mapped and still covering
    // this code and this CPU's stack; the caller's contract is the rest.
    unsafe { tessera_karch_aarch64::enable_mmu_raw(ttbr0_root, ttbr1_root) };
}

/// Where an arriving CPU lands, in the high half on its own stack.
///
/// # Safety
///
/// Called once, by the entry stub, by the CPU that `index` names, with
/// translation on through the boot tables.
#[unsafe(no_mangle)]
unsafe extern "C" fn aarch64_secondary_main(index: u32) -> ! {
    // Off the boot tables and onto the kernel's. The stack this is running on
    // is in `.bss`, which both high-half roots map identically, so the
    // instruction after the switch still fetches and this frame is still there.
    let ttbr0 = PhysAddr::new(KERNEL_TTBR0.load(Ordering::Acquire));
    let ttbr1 = PhysAddr::new(KERNEL_TTBR1.load(Ordering::Acquire));
    // SAFETY: the boot CPU published these after switching to them itself, and
    // is running on them now; the high-half root maps this code and stack at
    // the addresses they already have.
    unsafe { switch_tables(ttbr0, ttbr1) };

    // Its own vector base. `VBAR_EL1` is per-CPU, so the boot CPU's write did
    // nothing for this one, and a fault here would otherwise branch into
    // whatever firmware left.
    // SAFETY: the kernel's text is mapped executable at its current address by
    // the root just adopted.
    unsafe { tessera_karch_aarch64::init_vectors() };

    // Its own identity, in the register the core reads it back from.
    // SAFETY: this CPU, once, and the register needs nothing set up first.
    unsafe { <Cpu as CpuLocal>::install(index) };

    // Its own interrupt-controller interface. These registers are banked, so
    // the boot CPU's writes reached its own copies and no other's: a CPU whose
    // interface was never enabled takes no interrupt at all, and says nothing
    // about it.
    // SAFETY: the GIC is mapped by the low-half root adopted above, and this
    // runs once on this CPU with interrupts still masked.
    unsafe {
        tessera_karch_aarch64::init_gic_cpu_interface();
        tessera_karch_aarch64::init_ipi_cpu(index);
    }

    kcore::smp::announce_arrival(index);

    // Nothing dispatches here (D8), but it can now be interrupted, so
    // interrupts come off the mask. That is the whole difference between a CPU
    // that is parked and one that is merely idle, and it is the last thing done
    // — after the vector base, the interface, and the announcement, because an
    // interrupt arriving before any of those has nowhere to go.
    <Cpu as tessera_karch::InterruptControl>::enable();

    // Halt rather than spin: a halted CPU costs an emulated host nothing and a
    // real one no power. `wfi` returns when an interrupt is *pending* whether
    // or not it is taken, so the loop is what keeps it halted rather than
    // decoration.
    loop {
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// This port's bring-up mechanism: the firmware power-control call, aimed at
/// the entry stub above.
pub(crate) struct Psci;

impl CpuBringUp for Psci {
    // SAFETY: the trait's contract. This port's share of it is the stack slot,
    // which the bound below proves exists before firmware is asked for anything.
    unsafe fn start(hw_id: u64, index: u32) -> Result<(), CpuStartError> {
        if index >= kcore::percpu::MAX_CPUS as u32 {
            // The stack slot the stub will index does not exist. Refusing here
            // rather than letting the stub compute an address past the array is
            // the difference between a reported failure and a CPU scribbling on
            // whatever `.bss` follows.
            return Err(CpuStartError::UnknownCpu);
        }
        // The entry address firmware needs is physical, and this code runs in
        // the high half. The kernel image's high mapping is `virt = phys |
        // KERNEL_VIRT_BASE`, so masking recovers the physical address — the
        // same conversion `discovery` uses to report where the image sits.
        let entry = (aarch64_secondary_entry as *const ()) as u64 & PHYS_MASK;
        // SAFETY: the entry stub is MMU-off-safe and stack-free until it takes
        // the slot this index names, which the bound above proves exists.
        unsafe { tessera_karch_aarch64::psci_cpu_on(hw_id, entry, u64::from(index)) }
    }
}

/// What a CPU does when another interrupts it.
///
/// Counts it, and nothing else. The reason this kernel can send —
/// `IpiReason::Reschedule` — asks the target to look at its run queue, and no
/// CPU here has one (build/README.md, D8). Counting is what makes the delivery
/// observable from the CPU that sent it, which is the whole of what this
/// milestone claims.
pub(crate) fn ipi_hook(_sgi: u32) {
    kcore::smp::note_ipi(kcore::percpu::current_index());
}
