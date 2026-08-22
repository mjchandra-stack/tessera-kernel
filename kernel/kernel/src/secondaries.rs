// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Taking the application processors off the bootloader's memory and parking
//! them on the kernel's, x86-64.
//!
//! # Why this exists before there is any SMP
//!
//! Asking the bootloader how many CPUs the machine has is not a read. The
//! protocol answers that question by *starting* every application processor
//! into a wait loop of its own, and that loop's code sits in memory the same
//! boot protocol reports as **usable** — because a kernel that asks for the
//! list is expected to take the CPUs, after which the memory is genuinely free.
//!
//! This kernel starts no CPU (build/README.md, D8), so without this module it
//! would ask for the list, hand that memory to the frame allocator, and write
//! its own page tables over an instruction stream another core is executing.
//! That is not a theoretical hazard: it is what happened, and the symptom was a
//! triple fault on a core with a null IDT and the bootloader's `CR3`, tens of
//! thousands of instructions after the boot appeared to have gone fine.
//!
//! So the count is not free, and this is its price.
//!
//! # Two stages, because the destination does not exist yet
//!
//! The frames that overwrite the wait loop are spent *building* the kernel's
//! page tables, so by the time there is a kernel `CR3` to move a core onto, the
//! damage is done. Parking therefore happens first, in two stages:
//!
//! 1. [`park_all`], before the first frame is allocated. Each core is sent to
//!    the stub below, which lives in kernel text — memory the allocator never
//!    hands out — and waits there. It is still on the bootloader's page tables,
//!    which is survivable because those live in bootloader-reclaimable memory
//!    and this kernel allocates only from usable.
//! 2. [`adopt_tables`], once the kernel's root exists. Each core loads it and
//!    halts. After this nothing the cores touch belongs to the bootloader, and
//!    that invariant stops being an unstated dependency on which memory kind
//!    the allocator happens to use.
//!
//! # The stub
//!
//! It is entered with the bootloader's address space active, so it must be
//! mapped in both — it is, because the kernel image is mapped at its link
//! address by the bootloader and by the kernel's own tables, and every
//! reference below is `rip`-relative. It uses no stack: no call, no push. The
//! bootloader gave it one, and that stack is in the memory being reclaimed.
//!
//! Normative: docs/roadmap/02-smp-bring-up-plan.md ("Phase 0"),
//! docs/kernel/08-multicore-scalability.md
//! Budget: none (boot path)

use crate::limine;
use core::sync::atomic::{AtomicU64, Ordering};

/// The kernel `CR3` the stub installs, or zero while there is not one yet.
/// Read by each parked core through the same virtual address in both address
/// spaces.
// SAFETY: the stub reaches this static by name from `global_asm!`, so it must keep
// the symbol the assembly refers to; nothing else in the image defines it.
#[unsafe(no_mangle)]
static SECONDARY_KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

/// Incremented by each core once it is executing kernel text (stage 1).
// SAFETY: as above — named by the `global_asm!` stub, defined nowhere else.
#[unsafe(no_mangle)]
static SECONDARIES_PARKED: AtomicU64 = AtomicU64::new(0);

/// Incremented by each core once it is on the kernel's page tables (stage 2).
// SAFETY: as above — named by the `global_asm!` stub, defined nowhere else.
#[unsafe(no_mangle)]
static SECONDARIES_ADOPTED: AtomicU64 = AtomicU64::new(0);

// SAFETY: this declares a symbol defined by the `global_asm!` block below. Its
// only use is as the address written into a bootloader `goto_address` field,
// which is exactly the signature the protocol specifies.
unsafe extern "C" {
    fn secondary_park_stub(info: *mut core::ffi::c_void) -> !;
}

core::arch::global_asm!(
    r#"
.section .text.secondary_park
.globl secondary_park_stub
secondary_park_stub:
    // Interrupts off before anything else: this core has no IDT of its own and
    // any vector it took would be the bootloader's, or nothing at all.
    cli

    // Stage 1. Announce arrival. The boot CPU counts these before it allocates
    // a single frame, so reaching here is what makes the bootloader's usable
    // memory safe to spend.
    lock inc qword ptr [rip + SECONDARIES_PARKED]

    // Wait for a kernel root to exist. Zero means the boot CPU has not built
    // one yet. This spins rather than halts because there is no interrupt
    // coming to end it — the boot CPU signals by store, not by IPI, which it
    // has no way to send this milestone (build/README.md, D8).
1:
    pause
    mov rax, qword ptr [rip + SECONDARY_KERNEL_CR3]
    test rax, rax
    jz 1b

    // Stage 2. Onto the kernel's page tables. Every byte touched from here —
    // this code, the counter below — is mapped at the same address by both,
    // which is what makes the switch survivable mid-instruction-stream.
    mov cr3, rax
    lock inc qword ptr [rip + SECONDARIES_ADOPTED]

    // Halt. Not a spin: a halted core costs a host nothing under emulation and
    // no power on hardware, and this one has nothing to do until bring-up gives
    // it something. With interrupts masked `hlt` wakes only for an NMI, so the
    // loop is what keeps it halted rather than decoration.
2:
    hlt
    jmp 2b
"#
);

/// Stage 1: moves every application processor out of the bootloader's wait loop
/// and into kernel text.
///
/// Returns how many were parked, or `None` if the bootloader reported no CPU
/// list. Blocks until every one has acknowledged: returning earlier would hand
/// the caller a licence to allocate memory that is still executing, which is
/// the whole hazard this module exists to close.
///
/// # Safety
///
/// Call once, on the boot CPU, **before the first frame is allocated** — the
/// bootloader's response memory must still be intact.
pub unsafe fn park_all() -> Option<usize> {
    // SAFETY: the caller's contract — nothing has been reclaimed yet.
    let found = unsafe {
        limine::for_each_application_processor(|info| {
            info.goto_address
                .store(secondary_park_stub as *mut _, Ordering::Release);
        })?
    };

    // No timeout, deliberately: a core that does not arrive is one still
    // running in memory about to be overwritten, and a boot that stops here is
    // strictly better than one that continues.
    while (SECONDARIES_PARKED.load(Ordering::Acquire) as usize) < found {
        core::hint::spin_loop();
    }
    Some(found)
}

/// Stage 2: publishes the kernel's page-table root and waits for every parked
/// core to adopt it.
///
/// # Safety
///
/// `kernel_cr3` must be a live top-level root that maps this kernel's text and
/// data at their link addresses. Call once, on the boot CPU, after
/// [`park_all`] returned `Some(parked)`.
pub unsafe fn adopt_tables(kernel_cr3: u64, parked: usize) {
    SECONDARY_KERNEL_CR3.store(kernel_cr3, Ordering::Release);
    while (SECONDARIES_ADOPTED.load(Ordering::Acquire) as usize) < parked {
        core::hint::spin_loop();
    }
}
