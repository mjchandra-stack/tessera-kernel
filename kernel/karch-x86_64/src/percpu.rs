// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Per-CPU data through `IA32_GS_BASE`. Per-CPU is the default state model
//! from day one (docs/kernel/08-multicore-scalability.md) even while only
//! the boot CPU exists — application processors get their own blocks with
//! SMP bring-up.
//!
//! Normative: docs/kernel/08-multicore-scalability.md
//! Budget: none (init path; accessors are two instructions)

use core::arch::asm;

const IA32_GS_BASE: u32 = 0xc000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// Layout is load-bearing: `current_cpu_index` reads `gs:[CPU_INDEX_OFFSET]`, and the
/// SYSCALL entry stub (`syscall.rs`) reads/writes `gs:[KERNEL_RSP_OFFSET]` and
/// `gs:[USER_RSP_SCRATCH_OFFSET]`.
#[repr(C)]
struct PerCpu {
    /// Points at this block itself, so `gs:[0]` recovers a linear pointer.
    self_ptr: u64,
    /// The **assigned** dense index of this CPU, not its APIC id — the
    /// hardware's own number is `CpuOps::hw_id`, read from CPUID, and is not
    /// stored anywhere because it cannot go stale.
    cpu_index: u32,
    _pad: u32,
    /// Kernel stack top the SYSCALL entry stub switches to (SYSCALL does not
    /// use TSS.RSP0). Updated on every switch to a user thread.
    kernel_rsp: u64,
    /// Scratch cell where the SYSCALL entry stub parks the user RSP for the two
    /// instructions between `swapgs` and having a kernel stack to push onto.
    ///
    /// **Live for those two instructions and no longer.** The stub copies it
    /// straight onto the kernel stack, because the user RSP is a per-thread
    /// fact and this cell is per-CPU: a thread that blocks mid-syscall would
    /// otherwise have another thread's syscall overwrite it and return onto the
    /// wrong stack. Interrupts are masked across the window by SFMASK.
    user_rsp_scratch: u64,
}

const CPU_INDEX_OFFSET: usize = 8;
pub(crate) const KERNEL_RSP_OFFSET: usize = 16;
pub(crate) const USER_RSP_SCRATCH_OFFSET: usize = 24;
const _: () = assert!(core::mem::offset_of!(PerCpu, cpu_index) == CPU_INDEX_OFFSET);
const _: () = assert!(core::mem::offset_of!(PerCpu, kernel_rsp) == KERNEL_RSP_OFFSET);
const _: () = assert!(core::mem::offset_of!(PerCpu, user_rsp_scratch) == USER_RSP_SCRATCH_OFFSET);

static mut BSP_PERCPU: PerCpu = PerCpu {
    self_ptr: 0,
    cpu_index: 0,
    _pad: 0,
    kernel_rsp: 0,
    user_rsp_scratch: 0,
};

/// Installs the boot CPU's per-CPU block.
///
/// # Safety
///
/// Call exactly once, on the boot CPU, before anything reads per-CPU state.
pub(crate) unsafe fn init_bsp() {
    // SAFETY: single boot-CPU call per contract; the static outlives the
    // kernel and the MSR writes only program the GS bases.
    unsafe {
        let base = (&raw mut BSP_PERCPU) as u64;
        (*(&raw mut BSP_PERCPU)).self_ptr = base;
        asm!(
            "wrmsr",
            in("ecx") IA32_GS_BASE,
            in("eax") base as u32,
            in("edx") (base >> 32) as u32,
            options(nostack, preserves_flags),
        );
        // The kernel runs with GS_BASE = this block and KERNEL_GS_BASE = the
        // user GS (0, no user yet). `enter_user`/`syscall_entry` swapgs across
        // the ring boundary so kernel entries always recover this block and the
        // user never sees it. Set it explicitly rather than trust boot state.
        asm!(
            "wrmsr",
            in("ecx") IA32_KERNEL_GS_BASE,
            in("eax") 0u32,
            in("edx") 0u32,
            options(nostack, preserves_flags),
        );
    }
}

/// Sets the kernel stack top the SYSCALL entry stub loads (`gs:[kernel_rsp]`).
/// Called on every switch to a user thread, alongside `gdt::set_kernel_stack`
/// (which sets TSS.RSP0 for the interrupt/exception path).
pub(crate) fn set_kernel_rsp(top: u64) {
    // SAFETY: GS base points at this CPU's live PerCpu block; the offset is
    // compile-checked against the struct layout, and this is the only writer.
    unsafe {
        asm!(
            "mov gs:[{off}], {val}",
            off = const KERNEL_RSP_OFFSET,
            val = in(reg) top,
            options(nostack, preserves_flags),
        );
    }
}

/// Records this CPU's dense index in its own block.
///
/// # Safety
///
/// This CPU's per-CPU block must be installed (`init_bsp`, or an application
/// processor's equivalent), and this must run on the CPU it names.
pub(crate) unsafe fn set_cpu_index(index: u32) {
    // SAFETY: GS base points at this CPU's live PerCpu block per the caller's
    // contract; the offset is compile-checked against the struct layout, and
    // the field belongs to this CPU alone.
    unsafe {
        asm!(
            "mov gs:[{off}], {val:e}",
            off = const CPU_INDEX_OFFSET,
            val = in(reg) index,
            options(nostack, preserves_flags),
        );
    }
}

/// The executing CPU's dense index. Only valid after `init_bsp` and
/// `set_cpu_index` have run on this CPU.
pub(crate) fn current_cpu_index() -> u32 {
    let index: u32;
    // SAFETY: GS base points at a live PerCpu block (set in init_bsp);
    // the offset is verified against the struct layout at compile time.
    unsafe {
        asm!(
            "mov {0:e}, gs:[{off}]",
            out(reg) index,
            off = const CPU_INDEX_OFFSET,
            options(nostack, preserves_flags, readonly),
        );
    }
    index
}
