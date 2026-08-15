// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! RISC-V 32 implementation of the architecture porting layer — the **fourth**
//! port, and the first at a 32-bit word size.
//!
//! Its value is not that it adds another machine. It is that it is the first
//! port where `usize` is not 64 bits, so it is the first real test of the
//! word-size work the kernel core did in the abstract (build/README.md, D88):
//! the porting layer's `PhysAddr` is a fixed 64-bit type, the core's 64-bit
//! counter is two halves where the target has no 64-bit atomic, and neither of
//! those had ever been exercised by a running kernel until this port booted.
//!
//! What is shared with the 64-bit port and what is not is deliberate. The
//! `virt` platform's devices — PLIC, NS16550A, test finisher — are identical
//! at both word sizes and live in `tessera-karch-riscv-common`. Everything
//! here is the part that genuinely differs: the register width, `scause`'s
//! interrupt bit at 31 rather than 63, a timer compare split across two CSRs,
//! a context frame of 4-byte slots, and **Sv32**, whose physical addresses are
//! *wider* than its pointers.
//!
//! The port covers boot, CPU control, platform exit, Sv32 paging, context
//! switch, the supervisor timer, and the trap vector. Absent, deliberately:
//! the unprivileged level (`UserContextOps` is not implemented, so a user
//! thread cannot be spawned — a compile error, not a runtime surprise) and the
//! higher-half kernel split.
//!
//! The target triple is `riscv32imac-unknown-none-elf`. No F or D: the kernel
//! emits no floating point, and `sstatus.FS` is left at `Off` so a stray FP
//! instruction traps rather than corrupting state no context switch saves.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Architecture
//! Porting Layer", "Endianness And Word Size", "Porting Rules")
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
pub use paging::{
    DIRECT_MAP_BASE, KernelAddressSpace, KernelSection, PAGE_4K, PAGE_4M, build_kernel_space,
};
pub use timer::{SupervisorTimer, TIMEBASE_HZ, stop as stop_timer};
pub use trap::{
    DeviceIrqHook, EXCEPTION_ECALL_FROM_USER, TickHook, TrapFrame, TrapHandler, UserTrapHook,
    allow_user_memory_access, exception_name, from_user, init_vectors, is_write_fault,
    set_device_irq_hook, set_tick_hook, set_trap_handler, set_user_trap_hook, unexpected_irqs,
};

// The `virt` platform's devices are the same at both RISC-V word sizes and
// live in one crate. They are re-exported here so the boot glue names one
// porting-layer crate, as it does on every other architecture.
pub use tessera_karch_riscv_common::mmio::set_device_access_base;
pub use tessera_karch_riscv_common::plic::{disable as disable_irq, enable as enable_irq};
pub use tessera_karch_riscv_common::{
    Ns16550a, fence_io, read32 as mmio_read32, write32 as mmio_write32,
};
