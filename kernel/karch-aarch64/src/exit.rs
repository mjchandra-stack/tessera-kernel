// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Platform exit for test and CI runs, via Arm semihosting.
//!
//! The x86-64 port writes QEMU's `isa-debug-exit` device, which turns a byte
//! into the process exit status `(value << 1) | 1`. AArch64 has no port I/O
//! and the `virt` machine has no such device, so the mechanism differs — but
//! the *contract* the harness sees does not, and that is deliberate.
//!
//! Semihosting `SYS_EXIT` with `ADP_Stopped_ApplicationExit` propagates an
//! arbitrary status, so this port reports the same 33 (success) and 65
//! (failure) the x86-64 harness already keys on, and one `smoke_boot` script
//! shape works for both. The alternative — PSCI `SYSTEM_OFF` — exits QEMU
//! with status 0, which would collide with "QEMU ran fine" and destroy
//! exactly the distinction `karch-x86_64/src/cpu.rs` documents keeping.
//!
//! Semihosting must be enabled on the QEMU command line
//! (`-semihosting-config enable=on,target=native`). Without it the `hlt`
//! traps as an undefined instruction instead of exiting; the smoke-boot
//! script owns that flag.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")
//! Budget: none (exit path)

use crate::cpu::Cpu;
use core::arch::asm;
use tessera_karch::{CpuOps, ExitCode, PlatformExit};

/// Semihosting operation number for "the application has exited".
const SYS_EXIT: u64 = 0x18;

/// Reason code meaning a normal application exit, whose subcode QEMU uses as
/// the process exit status.
const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x2_0026;

/// Statuses the harness keys on, matching the x86-64 port's.
const EXIT_STATUS_SUCCESS: u64 = 33;
const EXIT_STATUS_FAILURE: u64 = 65;

pub struct SemihostingExit;

impl PlatformExit for SemihostingExit {
    fn exit(code: ExitCode) -> ! {
        let status = match code {
            ExitCode::Success => EXIT_STATUS_SUCCESS,
            ExitCode::Failure => EXIT_STATUS_FAILURE,
        };
        // On AArch64 `SYS_EXIT` takes a pointer to a two-word parameter
        // block: the reason code, then the subcode used as the exit status.
        let parameters = [ADP_STOPPED_APPLICATION_EXIT, status];

        // SAFETY: `hlt #0xf000` is the semihosting call instruction. Under a
        // host that implements semihosting it terminates the VM and never
        // returns; under one that does not it raises an exception, and if
        // that exception ever returns we halt forever below. `parameters`
        // lives on this (never-unwound) stack frame and is read by the host
        // before the call completes.
        unsafe {
            asm!(
                "hlt #0xf000",
                in("x0") SYS_EXIT,
                in("x1") parameters.as_ptr(),
                options(nostack),
            );
        }

        loop {
            Cpu::halt_until_interrupt();
        }
    }
}
