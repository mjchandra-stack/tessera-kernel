// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **A program that exists only on a disk.**
//!
//! Every other ring-3 program in this tree is built into a container the kernel
//! image carries. This one is placed on the ext2 volume by the build and is not
//! in any store, any accessor and any image — so a kernel that runs it ran
//! something it was not carrying, which is what `docs/roadmap/03` Phase 2's
//! third bullet is for.
//!
//! It does one thing, and that is deliberate: what is under test is where its
//! bytes came from, not what they do. A program with behaviour worth checking
//! would make a failure ambiguous between the delivery and the program.
//!
//! Normative: docs/roadmap/03-composition-and-self-hosting.md ("Phase 2")

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// What this program reports, and the only thing it does.
///
/// A value nothing else in the tree writes, so a sink carrying it carries it
/// because *this* program ran.
const FROM_DISK: u64 = 0x0d15_c0de_0d15_c0de;

const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in this
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    tessera_uabi::syscall2(SYS_DEBUG_WRITE, FROM_DISK, 0);
    tessera_uabi::syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    tessera_uabi::syscall2(SYS_PROCESS_EXIT, 1, 0);
    loop {
        core::hint::spin_loop();
    }
}
