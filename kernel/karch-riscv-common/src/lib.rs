// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The platform devices both RISC-V ports drive, and nothing else.
//!
//! # What belongs here, and what does not
//!
//! RISC-V 32 and RISC-V 64 are two ports of the porting layer, not one port
//! with a switch: the register width, the page-table format, the trap frame,
//! the context switch and the CSR set all differ, and each lives in its own
//! `karch-riscv{32,64}` crate. What does *not* differ is the machine hanging
//! off the CPU. The `virt` platform's PLIC, its NS16550A console and its test
//! finisher are memory-mapped devices with 32-bit registers, identical at
//! both word sizes, and a second byte-for-byte copy of each is exactly the
//! kind of drift `tessera-arch-conformance` exists to prevent one level up.
//!
//! The dividing line is deliberate and worth stating, because it is easy to
//! put things on the wrong side of it: **a device is shared, a CSR is not.**
//! The PLIC here manipulates only its own MMIO registers. Unmasking external
//! interrupts is a write to `sie`, which is architectural state whose width
//! is the register width, so it stays in each port's `cpu` module — and that
//! is not pedantry: `in(reg) <u64 value>` does not compile on a 32-bit
//! target, so a shared CSR helper would have had to be generic over the very
//! thing that makes the two ports two ports.
//!
//! Nothing here reads or writes a CSR, executes a privileged instruction, or
//! knows the pointer width.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Platform Support
//! Package"), docs/hardware/04-device-memory-and-unified-memory.md
//! Budget: none (init, console and interrupt paths)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod finisher;
pub mod mmio;
pub mod plic;
pub mod uart;

pub use finisher::request_exit;
pub use mmio::{fence_io, read8, read32, write8, write32};
pub use uart::Ns16550a;
