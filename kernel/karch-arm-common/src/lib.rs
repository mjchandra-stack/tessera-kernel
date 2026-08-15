// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The platform devices both Arm ports drive, and nothing else.
//!
//! AArch64 and ARM 32-bit are two ports of the porting layer, not one port
//! with a switch: the register width, the exception model, the page-table
//! entry point and the context switch all differ, and each lives in its own
//! `karch-{aarch64,arm32}` crate. What does not differ is the machine. QEMU's
//! `virt` board is the *same board* at both widths — RAM at 0x4000_0000, a
//! PL011 at 0x0900_0000, a GICv2 at 0x0800_0000 — so its drivers are the same
//! code, and a second byte-for-byte copy of each is the drift
//! `tessera-arch-conformance` exists to prevent one level up.
//!
//! The dividing line is the one `tessera-karch-riscv-common` states for the
//! other family: **a device is shared, a system register is not.** The GIC
//! here touches only its own MMIO. Masking interrupts is `DAIF` on AArch64
//! and `CPSR.I` on ARM 32-bit — different instructions on different register
//! widths — so it stays in each port's `cpu` module.
//!
//! Nothing here executes a privileged instruction or knows the pointer width.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Platform Support
//! Package"), docs/hardware/04-device-memory-and-unified-memory.md
//! Budget: none (init, console and interrupt paths)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod gic;
pub mod mmio;
pub mod uart;

pub use mmio::{read32, write32};
pub use uart::Pl011;
