// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! RISC-V 64 implementation of the architecture porting layer: the **third**
//! port, and the one that turns "`tessera-karch` is an abstraction" from a
//! two-point line into a result.
//!
//! Two ports can share an assumption and call it an interface. This one was
//! chosen next because it is the most distant of the three from the other
//! two — firmware in the boot path (SBI), a single trap vector instead of a
//! table, a page-table format with no device-memory attribute, an
//! instruction cache the architecture declares incoherent, and no
//! architectural report of the timer's own frequency. Every one of those is a
//! place where a x86-64-or-AArch64-shaped abstraction would have shown a
//! seam, and where the seam appeared it is named in the module that found it
//! rather than smoothed over here.
//!
//! The port covers boot, console, CPU control, platform exit, Sv39 paging,
//! context switch, the supervisor timer, the PLIC, and the trap vector.
//! Nothing here is a stub standing in for an unimplemented primitive: a
//! primitive is either implemented or absent. Absent, deliberately, are the
//! unprivileged level (`UserContextOps` is not implemented, so a user thread
//! cannot be spawned — a compile error, not a runtime surprise) and the
//! higher-half kernel split; both are the next milestones on this port, in
//! the order AArch64 took them.
//!
//! The target triple is `riscv64gc-unknown-none-elf` — IMAFDC, the base the
//! RVA23 profile mandates. There is no softfloat variant to pick as there is
//! on AArch64; instead `sstatus.FS` is left at `Off`, so a stray floating-
//! point instruction traps as illegal rather than silently corrupting state
//! that no context switch saves.
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
mod paging;
mod timer;
mod trap;

pub use context::{Context, ContextSwitch};
pub use cpu::{Cpu, init_plic, read_counter, read_counter_serialized};
pub use exit::TestFinisherExit;

// The `virt` platform's devices are the same at both RISC-V word sizes and
// live in one crate (see `tessera-karch-riscv-common`). They are re-exported
// here so the boot glue names one porting-layer crate, as it does on every
// other architecture.
pub use paging::{
    DIRECT_MAP_BASE, KernelAddressSpace, KernelSection, PAGE_1G, PAGE_2M, PAGE_4K,
    build_kernel_space,
};
pub use tessera_karch_riscv_common::plic::{disable as disable_irq, enable as enable_irq};
pub use tessera_karch_riscv_common::{
    Ns16550a, fence_io, read32 as mmio_read32, write32 as mmio_write32,
};
pub use timer::{SupervisorTimer, TIMEBASE_HZ, stop as stop_timer};
pub use trap::{
    DeviceIrqHook, TickHook, TrapFrame, TrapHandler, exception_name, init_vectors, is_write_fault,
    set_device_irq_hook, set_tick_hook, set_trap_handler, unexpected_irqs,
};
