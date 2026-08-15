// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Platform exit for test and CI runs, via Arm semihosting — the same
//! mechanism the AArch64 port uses, through a different instruction and a
//! different operation number.
//!
//! AArch64 issues `hlt #0xf000` and calls `SYS_EXIT` (0x18), whose parameter
//! block carries a reason *and* a subcode used as the process status. On ARM
//! 32-bit `SYS_EXIT` predates that: it takes the reason code **directly** in
//! `r1` and has no way to carry a status, so it can only report "stopped",
//! not "stopped with 33". The extended call **`SYS_EXIT_EXTENDED` (0x20)**
//! exists precisely to fix that, taking the same two-word block the 64-bit
//! call does.
//!
//! Using it is what keeps this port's contract identical to every other's:
//! status 33 for success, 65 for failure, one `smoke_boot` script shape
//! everywhere. Falling back to plain `SYS_EXIT` would exit 0 on success and
//! destroy the distinction between "the kernel passed" and "QEMU ran".
//!
//! The call instruction in ARM state is `svc #0x123456`. Semihosting must be
//! enabled on the QEMU command line, as on AArch64.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")
//! Budget: none (exit path)

use crate::cpu::Cpu;
use core::arch::asm;
use tessera_karch::{CpuOps, ExitCode, PlatformExit};

/// Semihosting operation taking a reason *and* an exit status.
const SYS_EXIT_EXTENDED: u32 = 0x20;

/// Reason code meaning a normal application exit.
const ADP_STOPPED_APPLICATION_EXIT: u32 = 0x2_0026;

/// Statuses the harness keys on, matching every other port's.
const EXIT_STATUS_SUCCESS: u32 = 33;
const EXIT_STATUS_FAILURE: u32 = 65;

pub struct SemihostingExit;

impl PlatformExit for SemihostingExit {
    fn exit(code: ExitCode) -> ! {
        let status = match code {
            ExitCode::Success => EXIT_STATUS_SUCCESS,
            ExitCode::Failure => EXIT_STATUS_FAILURE,
        };
        let parameters = [ADP_STOPPED_APPLICATION_EXIT, status];

        // SAFETY: `svc #0x123456` is the ARM-state semihosting call. Under a
        // host that implements semihosting it terminates the VM and never
        // returns; under one that does not it raises a supervisor call that,
        // if it ever returns, drops into the halt loop below. `parameters`
        // lives on this (never-unwound) frame and is read by the host before
        // the call completes.
        unsafe {
            asm!(
                "svc #0x123456",
                in("r0") SYS_EXIT_EXTENDED,
                in("r1") parameters.as_ptr(),
                options(nostack),
            );
        }

        loop {
            Cpu::halt_until_interrupt();
        }
    }
}
