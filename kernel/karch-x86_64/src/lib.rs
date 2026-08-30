// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! x86-64 implementation of the architecture porting layer: serial console,
//! CPU operations, and (as the milestone grows) CPU tables, interrupt
//! controller, and timers. All assembly for this architecture lives in this
//! crate; nothing outside it (and the boot glue) may contain x86-specific
//! code.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md,
//! docs/lifecycle/04-coding-guidelines.md ("Languages")
//! Budget: none (init paths only, this milestone)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
// **`deref_addrof` is a false positive on this crate's one way of reaching a
// `static mut`.** `(*(&raw mut STATIC)).method()` names a place through a raw
// pointer, which is what edition 2024 requires: the fix clippy suggests —
// `STATIC.method()` — autorefs the static and fails to compile with
// `error: creating a mutable reference to mutable static`, denied by
// `static_mut_refs`. Measured, not assumed: applying the suggestion to one site
// in `smmu.rs` produced exactly that error. 445 findings across the five ports
// were this lint, which is most of what the arch-lint baseline was carrying
// (build/README.md, D297).
#![allow(clippy::deref_addrof)]

mod apic;
pub mod com2;
mod context;
mod cpu;
mod gdt;
mod hpet;
mod idt;
mod io;
mod ioapic;
mod ipi;
mod paging;
mod percpu;
mod syscall;
mod timer;
mod trap;
mod uart;

pub use context::{Context, ContextSwitch};
pub use cpu::{
    Cpu, DebugExit, read_cr2, read_cr3, read_stack_pointer, read_tsc, read_tsc_serialized,
    tsc_invariant,
};
pub use gdt::loaded_gdt_base;
pub use io::{device_in, device_out, inl, outl};
pub use ipi::{InterCpu, reason_of};
pub use paging::{
    KernelAddressSpace, KernelSection, access_prevention_enabled, build_kernel_address_space,
    enable_paging_features, execution_prevention_cpus, flush_tlb_local, set_user_access,
    smap_supported, smep_supported, user_access,
};
pub use syscall::{
    SyscallFrame, SyscallHandler, USER_IF_ON_ENTRY, init_syscall, set_syscall_handler,
};
pub use timer::{
    ApicTimer, IPI_VECTOR, InterruptInitError, SHOOTDOWN_VECTOR, init_cpu_interrupts,
    init_interrupts, mask_irq, spurious_irqs, timer_hz, unexpected_irqs, unmask_irq,
};
pub use trap::{
    PageFaultResolver, TrapFrame, TrapHandler, UserFaultHandler, set_device_irq_hook, set_ipi_hook,
    set_page_fault_resolver, set_secondary_tick_hook, set_tick_hook, set_trap_handler,
    set_user_fault_handler, vector_name,
};
pub use uart::Uart16550;

/// How many CPUs this port builds descriptor tables, task-state segments, fault
/// stacks, and per-CPU blocks for.
///
/// **Deliberately the port's own number and not the kernel's `MAX_CPUS`.** That
/// one is a kcore setting declared in `config/kernel.config`, and the porting
/// layer reading kernel configuration would invert the dependency this crate
/// exists to keep pointing one way. The two must be compatible, so the boot
/// glue — the one crate that sees both — asserts it at compile time, and a
/// configuration that outgrew this port fails to build rather than running with
/// CPUs it has no table for.
pub const CPU_TABLE_SLOTS: usize = 8;

/// Installs the boot CPU's GDT/TSS, IDT, and per-CPU block.
///
/// # Safety
///
/// Call exactly once, on the boot CPU, before interrupts are enabled.
pub unsafe fn init_bsp_tables() {
    // SAFETY: the boot CPU takes index 0 by construction — it is the first CPU
    // to be given one, and the assignment is dense from zero.
    unsafe { init_cpu_tables(0) }
}

/// Installs the GDT/TSS, IDT, and per-CPU block of the CPU `index` names, and
/// programs its syscall MSRs.
///
/// The IDT is shared and its contents are built once, by the boot CPU; every
/// CPU after that only loads it. Everything else here is per-CPU state that
/// exists once per slot.
///
/// # Safety
///
/// Call exactly once per CPU, on the CPU `index` names, before interrupts are
/// enabled there. `index` must be below [`CPU_TABLE_SLOTS`] and held by no
/// other CPU.
pub unsafe fn init_cpu_tables(index: u32) {
    // SAFETY: contract forwarded verbatim to each initializer; ordering
    // matters — the IDT gates reference the GDT's code selector, the per-CPU
    // block must exist before its index is written into it, and init_syscall's
    // STAR bases reference the GDT's segment layout.
    unsafe {
        gdt::init_cpu(index);
        idt::init_cpu(index);
        percpu::init_cpu(index);
        percpu::set_cpu_index(index);
        // Execution prevention, here rather than beside the other paging
        // features, because `CR4` is per CPU and this is the path every CPU
        // takes. Whether it took is counted, not assumed — see
        // `paging::enable_execution_prevention`.
        let _ = paging::enable_execution_prevention();
    }
    syscall::init_syscall();
}
