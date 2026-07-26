// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! AArch64 implementation of the architecture porting layer: the second
//! port, and therefore the first evidence that `tessera-karch` is an
//! abstraction rather than a description of x86-64.
//!
//! The port covers boot, console, CPU control, platform exit, four-level
//! paging with a higher-half kernel (the kernel in `TTBR1`, the low half in
//! `TTBR0`), context switch, the generic timer, the GIC, and EL0 (the `svc`
//! boundary and lower-EL vectors). Nothing here is a stub standing in for an
//! unimplemented primitive: a primitive is either implemented or absent.
//!
//! The target triple is `aarch64-unknown-none-softfloat`. Kernel code emits
//! no FP/SIMD, and FP access from EL1 is left trapping rather than enabled,
//! so a stray FP instruction is a reported fault instead of silently
//! corrupting state that no context switch saves.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Architecture
//! Porting Layer", "Porting Rules"), docs/kernel/01-kernel-model.md
//! ("Architecture Layer")
//! Budget: none (init and panic paths in this milestone)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod context;
mod cpu;
mod exit;
mod gic;
mod mmio;
mod paging;
mod timer;
mod trap;
mod uart;

pub use context::{Context, ContextSwitch};
pub use cpu::{Cpu, counter_frequency, read_counter, read_counter_serialized};
pub use exit::SemihostingExit;
pub use mmio::{read32 as mmio_read32, write32 as mmio_write32};
pub use paging::{
    DIRECT_MAP_BASE, KernelAddressSpace, KernelSection, PHYS_MASK, build_boot_tables,
    build_high_space, build_low_space, enable_mmu_raw, switch_tables,
};
pub use timer::{GenericTimer, TIMER_INTID, stop as stop_timer};
pub use trap::{
    DeviceIrqHook, El0SyncHook, TickHook, TrapFrame, TrapHandler, exception_class_name,
    init_vectors, is_svc, is_write_fault, set_device_irq_hook, set_el0_sync_hook, set_tick_hook,
    set_trap_handler, svc_imm, unexpected_irqs,
};
pub use uart::Pl011;

pub use gic::{disable as disable_irq, enable as enable_irq, init as init_gic};
