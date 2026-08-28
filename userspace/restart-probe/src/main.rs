// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **restart probe**: a service that fails on purpose, so that something
//! else can be seen to restart it.
//!
//! It exits with the code its parent passed as its startup argument. A non-zero
//! code models a crash; zero models coming up clean. A supervisor that hands it
//! a countdown gets a service that fails that many times and then works, which
//! is the smallest thing a restart policy can be exercised against.
//!
//! **The point is that the policy is not in here.** How many times to retry,
//! whether to give up, and what to do then are the supervisor's decisions; this
//! program only has to fail predictably. Putting the countdown in the argument
//! rather than in the program is what lets one binary serve both the recovery
//! path and the give-up path.
//!
//! Normative: docs/kernel/05-jobs-containment-and-resource-control.md,
//! docs/architecture/01-system-architecture.md ("Component Model")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use tessera_uabi::syscall2;

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_PROCESS_EXIT: u64 = 5;

/// The ELF entry point. `arg` is what the supervisor passed in
/// `ProcessStartArgs::arg`: the code to exit with.
///
/// **`usize` rather than `u64`**, which matters on exactly one kind of machine
/// and matters completely there: the kernel hands this over in a single
/// argument register, and on a 32-bit port a `u64` parameter is passed in a
/// register *pair* — so the program would read its startup argument out of two
/// registers the kernel wrote one of (build/README.md, D259).
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: usize) -> ! {
    syscall2(SYS_PROCESS_EXIT, arg as u64, 0);
    // The kernel does not return from an exit; spin rather than fall off the
    // end of the entry point if a future one ever did.
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // A panic here is a failure of a program whose whole job is to fail
    // predictably, so it exits with a code no countdown ever produces.
    syscall2(SYS_PROCESS_EXIT, 0xff, 0);
    loop {
        core::hint::spin_loop();
    }
}
