// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Platform exit for test and CI runs. The device and the reason the status
//! is encoded the way it is live in
//! [`tessera_karch_riscv_common::finisher`]; what stays here is the port's
//! own halt, which is what a machine with no finisher does instead.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")
//! Budget: none (exit path)

use crate::cpu::Cpu;
use tessera_karch::{CpuOps, ExitCode, PlatformExit};
use tessera_karch_riscv_common::request_exit;

/// Statuses the harness keys on, matching every other port's.
const EXIT_STATUS_SUCCESS: u32 = 33;
const EXIT_STATUS_FAILURE: u32 = 65;

pub struct TestFinisherExit;

impl PlatformExit for TestFinisherExit {
    fn exit(code: ExitCode) -> ! {
        request_exit(match code {
            ExitCode::Success => EXIT_STATUS_SUCCESS,
            ExitCode::Failure => EXIT_STATUS_FAILURE,
        });

        // Reached only where the platform has no finisher; halting beats
        // running on into whatever follows.
        loop {
            Cpu::halt_until_interrupt();
        }
    }
}
