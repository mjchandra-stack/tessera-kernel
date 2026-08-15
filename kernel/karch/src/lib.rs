// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Architecture porting layer: the trait boundary and plain types every
//! architecture implements and the kernel core is generic over. No
//! architecture-specific code may exist outside implementations of this
//! layer — the kernel core never reaches into architecture registers
//! directly.
//!
//! This is deliberately the subset the current milestone needs; the full
//! porting-layer surface (page-table operations, TLB shootdown, per-CPU
//! accessors, vector units) grows here as the kernel grows, never ad hoc.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Architecture
//! Porting Layer"), docs/kernel/01-kernel-model.md ("Architecture Layer")
//! Budget: none (interface definitions only)

// The porting interface declares genuine unsafe capabilities
// (`ContextOps::init`/`switch`, `AddressSpaceOps::activate`) as `unsafe fn`
// signatures, so this crate is `deny(unsafe_op_in_unsafe_fn)` rather than
// `deny(unsafe_code)`: it contains unsafe *declarations* but no unsafe
// *operations* (those live in the ports). The declared sites are recorded
// in unsafe-inventory.toml.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod addr;
pub mod atomic;
pub mod boot;
pub mod error;
pub mod traits;
pub mod vm;

pub use addr::{FRAME_SIZE, PhysAddr, PhysFrame, VirtAddr};
pub use boot::{BootInfo, MemoryKind, MemoryRegion, normalize_memory_map};
pub use error::KError;
pub use traits::{
    ContextOps, CpuOps, EarlyConsole, ExitCode, InterruptControl, PlatformExit, TimerControl,
    UserContextOps,
};
pub use vm::{AddressSpaceOps, FrameSource, PageFlags};
