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

pub mod com2;
mod context;
mod cpu;
mod gdt;
mod idt;
mod io;
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
pub use io::{device_in, device_out};
pub use paging::{
    KernelAddressSpace, KernelSection, build_kernel_address_space, enable_paging_features,
};
pub use syscall::{
    SyscallFrame, SyscallHandler, USER_IF_ON_ENTRY, init_syscall, set_syscall_handler,
};
pub use timer::{Pit, init_pic, mask_irq, unexpected_irqs, unmask_irq};
pub use trap::{
    PageFaultResolver, TrapFrame, TrapHandler, UserFaultHandler, set_device_irq_hook,
    set_page_fault_resolver, set_tick_hook, set_trap_handler, set_user_fault_handler, vector_name,
};
pub use uart::Uart16550;

/// Installs the boot CPU's GDT/TSS, IDT, and per-CPU block.
///
/// # Safety
///
/// Call exactly once, on the boot CPU, before interrupts are enabled.
pub unsafe fn init_bsp_tables() {
    // SAFETY: contract forwarded verbatim to each initializer; ordering
    // matters — the IDT gates reference the GDT's code selector, and
    // init_syscall's STAR bases reference the GDT's segment layout.
    unsafe {
        gdt::init_bsp();
        idt::init_bsp();
        percpu::init_bsp();
    }
    syscall::init_syscall();
}
