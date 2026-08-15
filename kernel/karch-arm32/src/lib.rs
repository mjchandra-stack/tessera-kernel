// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! ARM 32-bit implementation of the architecture porting layer — the fifth
//! and last port in the matrix.
//!
//! It arrives last for a reason that is not effort: it is the only port that
//! could be written with no new *core* work. Its word size is the one the
//! RISC-V 32 port already proved out, and unlike that port it has 64-bit
//! atomics, so it exercises the delegating branch of
//! `tessera_karch::atomic::AtomicU64` rather than the split one. Its board is
//! the one the AArch64 port already drives — QEMU's `virt` is the same
//! machine at both widths — so the PL011 and the GICv2 come from
//! `tessera-karch-arm-common` unchanged.
//!
//! What is genuinely this port's own is the *privileged* architecture, which
//! ARMv7-A does differently from AArch64 in every particular: banked
//! processor modes instead of exception levels, an eight-entry vector table
//! instead of a sixteen-slot one, coprocessor 15 instead of named system
//! registers, and **LPAE** — a three-level long-descriptor format whose
//! entries look like AArch64's but whose root table has four entries rather
//! than five hundred and twelve, because a 32-bit address needs only two bits
//! at the top level.
//!
//! The port covers boot, CPU control, platform exit, LPAE paging, context
//! switch, the generic timer, and the vector table. Absent, deliberately: the
//! unprivileged level (`UserContextOps` is not implemented, so a user thread
//! cannot be spawned — a compile error, not a runtime surprise) and the
//! higher-half kernel split.
//!
//! The target triple is `armv7a-none-eabi`: ARM state, no hardware floating
//! point in kernel code, and the VFP/NEON unit left disabled so a stray FP
//! instruction traps rather than corrupting state no context switch saves.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Architecture
//! Porting Layer", "Porting Rules")
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
pub use cpu::{Cpu, counter_frequency, read_counter, read_counter_serialized};
pub use exit::SemihostingExit;
pub use paging::{
    DIRECT_MAP_BASE, KernelAddressSpace, KernelSection, PAGE_1G, PAGE_2M, PAGE_4K,
    build_kernel_space, clear_user_root, install_kernel_space,
};
pub use timer::{GenericTimer, TIMER_INTID, stop as stop_timer};
pub use trap::{
    DeviceIrqHook, KIND_DATA_ABORT, KIND_PREFETCH_ABORT, TickHook, TrapFrame, TrapHandler,
    UserAbortHook, UserFrame, UserSyscallHook, exception_name, from_user, init_vectors,
    is_write_fault, set_device_irq_hook, set_tick_hook, set_trap_handler, set_user_abort_hook,
    set_user_syscall_hook, unexpected_irqs,
};

// The `virt` board's devices are the same at both Arm word sizes and live in
// one crate. Re-exported so the boot glue names one porting-layer crate.
pub use tessera_karch_arm_common::gic::{
    disable as disable_irq, enable as enable_irq, init as init_gic,
};
pub use tessera_karch_arm_common::mmio::set_device_access_base;
pub use tessera_karch_arm_common::{Pl011, read32 as mmio_read32, write32 as mmio_write32};
