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
//! # No device interrupt reaches a CPU but the boot CPU
//!
//! Worth stating on its own, because a great deal of this kernel's recorded
//! memory-safety argument now rests on it. A shared peripheral interrupt is
//! delivered to whatever CPU interfaces the distributor's target register names
//! for it, and that register is written by `gic::enable` with the *calling*
//! CPU's own bit. The boot CPU enables every device interrupt, so every one of
//! them names the boot CPU and no other. What a secondary enables for itself is
//! its timer's private interrupt and the one software-generated id this kernel
//! sends — both banked, both its own.
//!
//! So the boot glue's device-interrupt hook, and every check static it reaches,
//! is touched by one CPU. That is why those justifications can say "the boot
//! CPU" and mean it, rather than saying "single-threaded" and meaning something
//! that stopped being true (build/README.md, D225/D226).
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
        // ...and its own timer interrupt. Banked like the interface, so the
        // boot CPU's enable reached its own copy and nobody else's.
        tessera_karch_aarch64::enable_irq(tessera_karch_aarch64::TIMER_INTID);
    }

    kcore::smp::announce_arrival(index);

    // Nothing dispatches here (D8), but it can now be interrupted, so
    // interrupts come off the mask. That is the whole difference between a CPU
    // that is parked and one that is merely idle, and it is the last thing done
    // — after the vector base, the interface, and the announcement, because an
    // interrupt arriving before any of those has nowhere to go.
    <Cpu as tessera_karch::InterruptControl>::enable();

    // Its own periodic tick. Nothing dispatches to this CPU, so nothing is
    // preempted by it — what it establishes is that the tick is per CPU, which
    // is the thing a second scheduler will need and the thing a machine-wide
    // timer could never have provided.
    <tessera_karch_aarch64::GenericTimer as tessera_karch::TimerControl>::start_periodic_this_cpu(
        crate::TICK_HZ,
    );

    // Its half of the executive, and whatever the boot CPU left on its run
    // queue. This is where the CPU stops being parked and starts being a CPU
    // this kernel runs work on; it never returns.
    //
    // The executive is built by the boot CPU before any other CPU is started
    // (`kmain`), so it is here to be found — and the PSCI call that released
    // this CPU orders the two: this CPU did not exist when the write happened.
    // If it is somehow absent this CPU has nothing to run and halts, rather
    // than faulting where nothing is set up to report it; the boot CPU sees
    // that as a withheld `smp.second-cpu-runs`.
    // SAFETY: the boot CPU built it and reaches it through its own accessor;
    // this narrows immediately to a shared reference, which is what the runner
    // takes and what two CPUs may hold at once.
    let Some(exec) = (unsafe { crate::el0::kcore_exec() }) else {
        loop {
            <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
        }
    };

    // SAFETY: this CPU, once, with its own tables, controller interface and
    // tick all established above and interrupts enabled.
    unsafe {
        kcore::secondary::run_this_cpu::<ContextSwitch, Cpu>(
            index,
            &SECONDARY_HANDOFF,
            exec,
            QUANTUM,
        )
    }
}

/// Interrupts `cpu` so it looks at its wakeup bitmap.
///
/// The port's half of `kcore::wakeup`: neutral code that wants to wake a
/// thread on another CPU cannot name this port's `Ipi` implementation, so this
/// is installed once and called through.
fn prompt_cpu(cpu: u32) -> bool {
    // SAFETY: every CPU this kernel started enabled its own interrupt-controller
    // interface before announcing itself, which is what `Ipi::send` requires;
    // one that never arrived is not in the table this resolves through and the
    // send reports `false`.
    unsafe {
        <tessera_karch_aarch64::Sgi as tessera_karch::Ipi>::send(
            cpu,
            tessera_karch::IpiReason::Reschedule,
        )
    }
}

/// Installs this port's way of prompting another CPU.
///
/// # Safety
///
/// The boot CPU, once, after the interrupt controller is up.
pub(crate) unsafe fn install_wakeup_prompt() {
    // SAFETY: the caller's contract, and `prompt_cpu`'s own.
    unsafe { kcore::wakeup::install_prompt(prompt_cpu) };
}

/// Ticks a secondary's thread runs before its scheduler considers it done.
/// One, because the thread the check hands over exits on its own and the
/// quantum only bounds how long it may hold the CPU if it does not.
const QUANTUM: u32 = 1;

/// Threads the boot CPU builds for other CPUs to run.
pub(crate) static SECONDARY_HANDOFF: kcore::secondary::Handoff<ContextSwitch> =
    kcore::secondary::Handoff::new();

/// Claimed by the first secondary to reach its worker, so exactly one serves
/// the cross-CPU call.
static CROSS_CALL_SERVER: AtomicU64 = AtomicU64::new(0);

/// How many times each secondary's worker thread has run.
pub(crate) static SECONDARY_WORK: [AtomicU64; kcore::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; kcore::percpu::MAX_CPUS];

/// The work a secondary's first thread does: count itself, once, and end.
///
/// Deliberately trivial. What is being shown is not the work but where it
/// happened — a thread taken off a run queue that belongs to a CPU which is not
/// the one that built the thread, context-switched into by that CPU, running on
/// a stack that CPU was given. The counter is how the boot CPU sees it, since
/// nothing else a secondary does is visible from here.
extern "C" fn secondary_worker(index: usize) -> ! {
    if index < kcore::percpu::MAX_CPUS {
        SECONDARY_WORK[index].fetch_add(1, Ordering::Release);
    }

    // ...and then, on whichever CPU gets here first, serve one channel call
    // for the boot CPU. Claimed rather than pinned to CPU 1: a machine where
    // CPU 1 never arrived would otherwise leave the check unserved and passing
    // silently, which is the failure mode a hard-coded index has.
    if CROSS_CALL_SERVER.swap(1, Ordering::AcqRel) == 0
        && kcore::cross_call::opened()
        // SAFETY: this CPU, inside a thread its own scheduler dispatched; the
        // executive was built before any CPU was started.
        && let Some(exec) = unsafe { crate::el0::kcore_exec() }
    {
        kcore::cross_call::serve(exec);
    }

    // SAFETY: a kernel thread dispatched by `run_this_cpu` on this CPU, which
    // is the only context this may be called from.
    unsafe { kcore::secondary::exit_here::<ContextSwitch>() };
    // `exit_current` switches away and never comes back to this thread.
    loop {
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// How many times the CPU at `index` has run its worker.
pub(crate) fn work_done(index: u32) -> u64 {
    SECONDARY_WORK
        .get(index as usize)
        .map_or(0, |slot| slot.load(Ordering::Acquire))
}

/// Builds one thread for each arrived CPU and leaves it where that CPU will
/// find it.
///
/// # Safety
///
/// The boot CPU, before any secondary has been released into its run loop, with
/// `space` the kernel space every CPU is running on.
pub(crate) unsafe fn hand_work_to_secondaries(
    kernel_arch: &KernelAddressSpace,
    frames: &mut dyn tessera_karch::FrameSource,
) -> usize {
    use tessera_karch::AddressSpaceOps;
    // An alias of the live kernel high half, wrapped so `Thread::spawn` can map
    // through it. It maps stacks and nothing else, and is dropped here — the
    // real space is the one every CPU is running on.
    // SAFETY: `kernel_arch` is the active kernel high half; the alias is never
    // torn down.
    let alias = unsafe { KernelAddressSpace::from_root(kernel_arch.root_phys(), DIRECT_MAP_BASE) };
    let mut space = kcore::vm::AddressSpace::from_arch(alias, kcore::vm::Asid(0), 0);
    let space = &mut space;
    let mut given = 0usize;
    for index in 1..kcore::percpu::PerCpu::<u8>::capacity() {
        if !kcore::smp::cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        let base = VirtAddr::new(SECONDARY_THREAD_STACKS + u64::from(index) * THREAD_STACK_BYTES);
        let Ok(thread) = kcore::thread::Thread::spawn(
            secondary_worker,
            index as usize,
            base,
            THREAD_STACK_BYTES / FRAME_SIZE,
            space,
            frames,
        ) else {
            continue;
        };
        // SAFETY: the boot CPU, once per index, and that CPU has not been
        // released into its run loop — it is waiting to be, below.
        if unsafe { SECONDARY_HANDOFF.give(index, thread) } {
            given += 1;
        }
    }
    given
}

/// Samples the cross-CPU call benchmark takes, in counter ticks.
static mut CROSS_BENCH_BUF: [u64; kcore::cross_call::BENCH_ROUNDS] =
    [0; kcore::cross_call::BENCH_ROUNDS];
/// The same, for the same-core baseline.
static mut LOCAL_BENCH_BUF: [u64; kcore::cross_call::BENCH_ROUNDS] =
    [0; kcore::cross_call::BENCH_ROUNDS];

/// The two sample buffers, through one place.
///
/// `<*mut T>::as_mut` rather than an immediate dereference, as everywhere else
/// this crate reaches a `static mut`: the pointer method is the one form
/// clippy has no finding for, and its suggestion for the other is to name the
/// static, which edition 2024 forbids. `None` is unreachable — this is the
/// address of a static — and is folded into the caller's existing "could not
/// set the benchmark up" path rather than panicking.
///
/// # Safety
///
/// The boot CPU alone, with no other live borrow of either buffer.
#[allow(clippy::type_complexity)]
unsafe fn bench_buffers() -> Option<(
    &'static mut [u64; kcore::cross_call::BENCH_ROUNDS],
    &'static mut [u64; kcore::cross_call::BENCH_ROUNDS],
)> {
    // SAFETY: the caller's contract, restated.
    unsafe {
        Some((
            (&raw mut CROSS_BENCH_BUF).as_mut()?,
            (&raw mut LOCAL_BENCH_BUF).as_mut()?,
        ))
    }
}

/// The same-core server, on the boot CPU.
extern "C" fn cross_call_local_server(_arg: usize) -> ! {
    // SAFETY: the boot CPU, inside a thread the executive dispatched.
    if let Some(exec) = unsafe { crate::el0::kcore_exec() } {
        kcore::cross_call::serve_local(exec);
        exec.scheduler().exit_current();
    }
    loop {
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// This port's serialized counter read, for the benchmark to bracket with.
///
/// `CNTVCT_EL0` is the system counter: one source for the whole machine, so a
/// timestamp taken on one CPU is comparable with one taken on another. That is
/// what a cross-core measurement needs and what a per-core cycle counter
/// cannot give without calibration.
fn cross_bench_now() -> u64 {
    <Cpu as tessera_karch::CpuOps>::counter_serialized()
}

/// Scheduling passes the boot CPU makes waiting for the cross-CPU call.
///
/// **Much smaller than `ARRIVAL_SPINS`, because an iteration here is not a
/// spin.** Each one drains this CPU's wakeup bitmap, asks the run queue for
/// work, and scans the ports — hundreds of nanoseconds, against the couple of
/// microseconds the other CPU needs to take the wakeup and answer. A bound
/// borrowed from the arrival spin turns a lost wakeup into a boot that hangs
/// for minutes instead of a check that fails.
const CROSS_CALL_PASSES: u64 = 200_000;

/// The boot CPU's half of the cross-CPU call: one synchronous call out of a
/// kernel thread, to a server parked on another CPU.
extern "C" fn cross_call_caller(_arg: usize) -> ! {
    // SAFETY: the boot CPU, inside a thread the executive dispatched.
    if let Some(exec) = unsafe { crate::el0::kcore_exec() } {
        kcore::cross_call::call(exec);
        // In this thread rather than on the boot context, because the frame
        // that resumes when the reply arrives is the only one that can bracket
        // the whole of it.
        // SAFETY: the boot CPU alone; this buffer is written only here and
        // read only after this thread has ended.
        // ...and then the same round trip, timed against a same-core pair —
        // budget B24 against its B3 baseline, interleaved so the ratio is
        // taken under one set of conditions.
        // SAFETY: the boot CPU alone; these buffers are written only here and
        // read only after this thread has ended.
        if let Some((cross, local)) = unsafe { bench_buffers() } {
            kcore::cross_call::bench(exec, cross_bench_now, cross, local);
        }
        // Back to the boot context, which is spinning in the pump below.
        exec.scheduler().yield_to_boot();
    }
    loop {
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// Runs the cross-CPU call and returns what it did.
///
/// # Safety
///
/// The boot CPU, after the secondaries have been handed work, with `space` the
/// kernel space every CPU is running on.
pub(crate) unsafe fn cross_cpu_call(
    kernel_arch: &KernelAddressSpace,
    frames: &mut dyn tessera_karch::FrameSource,
) -> kcore::cross_call::CrossCall {
    use tessera_karch::AddressSpaceOps;
    // SAFETY: the boot CPU, and the executive was built before any CPU started.
    let Some(exec) = (unsafe { crate::el0::kcore_exec() }) else {
        return kcore::cross_call::outcome();
    };
    // An alias of the live kernel high half, as `hand_work_to_secondaries`
    // makes: it maps this one stack and nothing else, and the real space is the
    // one every CPU is running on.
    // SAFETY: `kernel_arch` is the active kernel high half; the alias is never
    // torn down.
    let alias = unsafe { KernelAddressSpace::from_root(kernel_arch.root_phys(), DIRECT_MAP_BASE) };
    let mut space = kcore::vm::AddressSpace::from_arch(alias, kcore::vm::Asid(0), 0);
    let space = &mut space;

    // Wait for the server to register itself on its end. See
    // `kcore::cross_call::server_parked` for why this is waited for rather
    // than assumed — without it the request never crosses.
    let mut left = ARRIVAL_SPINS;
    while !kcore::cross_call::server_parked(exec) && left > 0 {
        core::hint::spin_loop();
        left -= 1;
    }

    // The same-core server first, so it runs first and parks as its
    // endpoint's blocked receiver — which is what lets `call` hand off to it
    // directly rather than taking the slower path B3 is not about.
    for (entry, slot) in [
        (
            cross_call_local_server as extern "C" fn(usize) -> !,
            u64::from(kcore::percpu::PerCpu::<u8>::capacity()),
        ),
        (cross_call_caller as extern "C" fn(usize) -> !, 0),
    ] {
        let base = VirtAddr::new(SECONDARY_THREAD_STACKS + slot * THREAD_STACK_BYTES);
        let Ok(thread) = kcore::thread::Thread::spawn(
            entry,
            0,
            base,
            THREAD_STACK_BYTES / FRAME_SIZE,
            space,
            frames,
        ) else {
            return kcore::cross_call::outcome();
        };
        if exec.add_thread(thread).is_err() {
            return kcore::cross_call::outcome();
        }
    }

    // **A pump, not one `run`.** The caller blocks on a reply that comes from
    // another CPU, so this CPU has nothing runnable in between — `run` returns
    // rather than waiting, and each fresh call to it drains whatever the other
    // CPU has posted before deciding again. The bound is what stops a lost
    // wakeup hanging the boot instead of failing the check.
    let mut left = CROSS_CALL_PASSES;
    while !kcore::cross_call::finished() && left > 0 {
        exec.run();
        left -= 1;
    }
    // ...and again for the benchmark's round trips, which the same caller
    // thread makes after the check. A separate bound because it is a separate
    // wait: two hundred round trips, not one.
    // ...and again for the benchmark's round trips, through the tight loop
    // rather than the pump above: what this waits for arrives from another
    // CPU, and `Executive::run`'s port and page-in bookkeeping is a per-pass
    // cost that would otherwise be most of what B24 reported.
    let mut left = CROSS_CALL_PASSES.saturating_mul(kcore::cross_call::BENCH_ROUNDS as u64);
    while !kcore::cross_call::bench_complete() && left > 0 {
        exec.run();
        left -= 1;
    }
    // SAFETY: the boot CPU, after the caller thread has ended; nothing else
    // reads or writes these buffers.
    if let Some((cross, local)) = unsafe { bench_buffers() } {
        report_cross_call_bench(cross, local);
    }
    kcore::cross_call::outcome()
}

/// Prints the cross-CPU call round trip against budget B24.
///
/// **Reported beside B7 and read the same way**: under QEMU/TCG every number
/// in this tree is a regression tripwire and never an R1 measurement
/// (build/README.md, D34/D56), so the budget is printed as context rather than
/// asserted as a claim. What a claim would be asserting on this machine is the
/// emulator's scheduling, not the kernel's.
fn report_cross_call_bench(cross: &mut [u64], local: &mut [u64]) {
    if !kcore::cross_call::bench_complete() {
        return kprintln!(
            "perf: B24 cross-call   incomplete ({} cross, {} same-core, of {} each)",
            cross.iter().filter(|&&s| s != 0).count(),
            local.iter().filter(|&&s| s != 0).count(),
            kcore::cross_call::BENCH_ROUNDS
        );
    }
    let hz = <Cpu as tessera_karch::CpuOps>::counter_hz()
        .unwrap_or(1)
        .max(1);
    let to_ns = |samples: &mut [u64]| {
        for slot in samples.iter_mut() {
            *slot = slot.saturating_mul(1_000_000_000) / hz;
        }
        kcore::bench::Stats::from_samples(samples)
    };
    let (Some(near), Some(far)) = (to_ns(local), to_ns(cross)) else {
        return kprintln!("perf: B24 cross-call   no samples");
    };
    line("B3 same-core call", near);
    line("B24 cross-call", far);
    // **The ratio is the part that survives the emulator.** Both paths were
    // measured the same way on the same boot, so what QEMU/TCG multiplies it
    // multiplies equally; `docs/prototypes/01` asks for exactly this, because
    // growth in the ratio is the signal that a service needs sharding before
    // its budget fails.
    // One decimal, because the whole of what this line says is a ratio and
    // integer division turns 3.1 and 3.9 into the same number.
    let tenths = far.p50.saturating_mul(10) / near.p50.max(1);
    kprintln!(
        "perf: B24/B3 ratio     p50 {}.{}x against a budgeted {}.{}x (B3 {}us, B24 {}us; QEMU/TCG)",
        tenths / 10,
        tenths % 10,
        (B24_BUDGET_US * 10) / B3_BUDGET_US / 10,
        (B24_BUDGET_US * 10) / B3_BUDGET_US % 10,
        B3_BUDGET_US,
        B24_BUDGET_US
    );
}

/// The synchronous-call budgets from `docs/architecture/03-performance-budgets.md`.
/// Printed for context and not asserted: what a claim would be asserting on
/// this machine is the emulator's scheduling (build/README.md, D34/D56).
const B3_BUDGET_US: u64 = 2;
const B24_BUDGET_US: u64 = 6;

fn line(name: &str, s: kcore::bench::Stats) {
    kprintln!(
        "perf: {name:<16} n={} p50={} p90={} p99={} max={} mean={}",
        s.count,
        kcore::bench::Nanos(s.p50),
        kcore::bench::Nanos(s.p90),
        kcore::bench::Nanos(s.p99),
        kcore::bench::Nanos(s.max),
        kcore::bench::Nanos(s.mean)
    );
}

/// Where each secondary's worker thread's stack is mapped. High half, one slot
/// per CPU, clear of the image and the direct map.
///
/// Slot zero belongs to no secondary — the handoff starts at CPU 1 — so it is
/// where the boot CPU's own cross-call thread goes.
const SECONDARY_THREAD_STACKS: u64 = 0xffff_0000_5200_0000;
const THREAD_STACK_BYTES: u64 = 4 * FRAME_SIZE;

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
/// Counts it, services a shootdown, and answers the translation probe — and
/// deliberately does **not** touch this CPU's run queue. `IpiReason::Reschedule`
/// asks the target to look at its run queue, and looking is what the run loop
/// does when this handler returns; a handler that looked itself would be
/// reaching into a scheduler the interrupted code may be in the middle of.
pub(crate) fn ipi_hook(sgi: u32) {
    let index = kcore::percpu::current_index();
    kcore::smp::note_ipi(index);

    // A shootdown is not a reschedule and does not share its handling: the
    // sender is blocked on the answer, so the flush happens here, now, before
    // anything else this handler might do.
    if tessera_karch_aarch64::reason_of(sgi) == Some(tessera_karch::IpiReason::TlbShootdown) {
        // SAFETY: this CPU's interrupt path, and `flush_tlb_local` drops every
        // translation it has cached.
        unsafe { kcore::shootdown::service_here(index, tessera_karch_aarch64::flush_tlb_local) };
        return;
    }

    // **The wakeups are deliberately not drained here.** This handler used to
    // take them off the bitmap and throw them away, which was honest while no
    // CPU had a run queue (D8) and became a way to lose them the moment one
    // did (D236). Draining them *properly* is worse: it would mean reaching
    // this CPU's run queue from an interrupt that may have landed inside the
    // scheduler's own context switch, aliasing a `&mut` the interrupted code
    // holds. The bit is the message and this is only the prompt — the run loop
    // this CPU returns to drains it, which is the next thing it does.

    // SAFETY: this CPU's interrupt path; the boot CPU keeps whatever it asked
    // about mapped until the answer is in.
    unsafe { kcore::smp::serve_probe() };
}

/// Kernel virtual page the shootdown check maps, remaps, and asks another CPU
/// to read. High half, clear of the image and the direct map, and unmapped
/// again before anything else runs.
const SHOOTDOWN_PROBE_VA: u64 = 0xffff_0000_5100_0000;

/// The two values the probe page holds, before and after the remap. Any two
/// distinct values would do; these are distinguishable in a hex dump, which is
/// where they turn up when this goes wrong.
const BEFORE: u64 = 0x1111_1111_1111_1111;
const AFTER: u64 = 0x2222_2222_2222_2222;

/// Does an invalidate on this CPU reach the others?
///
/// **The only property in Phase 2 that a single CPU cannot demonstrate.** This
/// architecture's invalidate takes the inner-shareable form, and
/// `AddressSpaceOps::INVALIDATE_IS_BROADCAST` says so — a constant the neutral
/// shootdown will use to delete its entire cross-CPU half. A constant asserted
/// against itself proves nothing, so this asks another CPU.
///
/// The sequence: map the page to one frame and have another CPU read it, which
/// is what puts the translation in *that* CPU's TLB; remap it to a second
/// frame, invalidating only here; ask the same CPU again. It sees the second
/// frame only if this CPU's invalidate reached it.
///
/// Returns `None` when there is no other CPU to ask, which is not a failure and
/// is not reported as a pass either.
///
/// # Safety
///
/// The boot CPU, after bring-up, with at least the frames below available and
/// `space` the kernel space every CPU is running on.
pub(crate) unsafe fn shootdown_reaches_other_cpus(
    space: &mut KernelAddressSpace,
    frames: &mut dyn tessera_karch::FrameSource,
    spins: u64,
) -> Option<bool> {
    use tessera_karch::AddressSpaceOps;

    // **One CPU is asked, not all of them.** A broadcast wakes every other CPU
    // into the same handler, and the boot CPU cannot know when the last of them
    // has finished reading — it learns only that *a* CPU answered. It then
    // unmaps the probe page, and a slower CPU that had already loaded the
    // address faults on it. That is not hypothetical: it is what four CPUs did
    // here, as a translation fault at the probe address on a CPU nobody was
    // waiting for. A targeted send has exactly one reader, and waiting for its
    // answer is waiting for all of them.
    let target = first_arrived()?;
    let page = VirtAddr::new(SHOOTDOWN_PROBE_VA);
    let first = frames.alloc_frame()?;
    let second = frames.alloc_frame()?;

    // Two frames with distinguishable contents, written through the direct map
    // so the probe page's own mapping is not what put them there.
    space.fill_frame(first, 0);
    space.fill_frame(second, 0);
    write_word(space, first, BEFORE);
    write_word(space, second, AFTER);

    let mut verdict = None;
    // SAFETY: a high-half address this kernel maps nothing else at, mapped
    // read-only into the space every CPU is on and unmapped again below.
    unsafe {
        if space
            .map(page, first, PageFlags::ro().global(), frames)
            .is_ok()
        {
            let generation = kcore::smp::probe_at(SHOOTDOWN_PROBE_VA);
            <tessera_karch_aarch64::Sgi as tessera_karch::Ipi>::send(
                target,
                tessera_karch::IpiReason::Reschedule,
            );
            if kcore::smp::probe_answer(generation, spins) == Some(BEFORE) {
                // The other CPU has the translation cached now. Remap, and
                // invalidate only here.
                if space.unmap(page).is_ok()
                    && space
                        .map(page, second, PageFlags::ro().global(), frames)
                        .is_ok()
                {
                    let generation = kcore::smp::probe_at(SHOOTDOWN_PROBE_VA);
                    <tessera_karch_aarch64::Sgi as tessera_karch::Ipi>::send(
                        target,
                        tessera_karch::IpiReason::Reschedule,
                    );
                    verdict = Some(kcore::smp::probe_answer(generation, spins) == Some(AFTER));
                }
            }
            kcore::smp::probe_off();
            let _ = space.unmap(page);
        }
    }
    frames.free_frame(first);
    frames.free_frame(second);
    verdict
}

/// The lowest-numbered CPU other than the boot CPU that has arrived.
fn first_arrived() -> Option<u32> {
    (1..kcore::percpu::PerCpu::<u8>::capacity())
        .find(|&index| kcore::smp::cpu(index).is_some_and(|state| state.arrived))
}

/// Writes one word into `frame` through the direct map.
fn write_word(space: &KernelAddressSpace, frame: tessera_karch::PhysFrame, value: u64) {
    use tessera_karch::AddressSpaceOps;
    space.write_bytes_to_frame(frame, 0, &value.to_le_bytes());
}
