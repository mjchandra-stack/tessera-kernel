// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The SiFive test finisher the `virt` machine provides at `test@100000` —
//! how a CI run on this platform ends.
//!
//! Each port reaches its exit differently and reports identically, which is
//! the point. x86-64 writes QEMU's `isa-debug-exit`, AArch64 issues an Arm
//! semihosting `SYS_EXIT`, and both RISC-V ports write this register — but
//! all of them yield process status 33 for success and 65 for failure, so one
//! `smoke_boot` script shape works for every architecture.
//!
//! The finisher's own vocabulary has to be translated to get that. Writing
//! `FINISHER_PASS` exits QEMU with status **0**, which would collide with
//! "QEMU itself ran fine" and destroy exactly the distinction
//! `karch-x86_64/src/cpu.rs` documents keeping. `FINISHER_FAIL` is the only
//! encoding that carries an arbitrary status — the device treats the upper
//! half-word as the exit code — so both outcomes are reported through it.
//! "Fail" is the device's word for "stop and hand back this number", not a
//! verdict on the run.
//!
//! Unlike AArch64 semihosting this needs no QEMU command-line flag: the
//! device is part of the `virt` machine. It is a test device all the same,
//! and no more shippable than the other two — real hardware implements
//! `PlatformExit` as a halt, which is what each port's caller already does
//! when this write goes nowhere.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")
//! Budget: none (exit path)

use crate::mmio::write32;

/// The `virt` machine's SiFive test finisher.
const TEST_FINISHER: usize = 0x0010_0000;

/// Finisher status meaning "terminate with the status in the upper half-word".
const FINISHER_FAIL: u32 = 0x3333;

/// Asks the platform to terminate with process status `status`.
///
/// Returns if the platform has no finisher — the caller must halt rather than
/// run on, and both ports do.
pub fn request_exit(status: u32) {
    // SAFETY: the finisher is a 4-byte register at a fixed address on this
    // machine, identity-mapped read-write for the life of the kernel (it lies
    // inside the device range both ports' kernel spaces map). Under a host
    // that implements it the write terminates the VM and never returns; under
    // one that does not the write is inert.
    unsafe { write32(TEST_FINISHER, (status << 16) | FINISHER_FAIL) };
}
