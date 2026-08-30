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

/// A marker in this program's own bytes, for the check outside the machine.
///
/// The report above says a program ran; this says **which image it came out
/// of**. The boot check greps for it in the ext2 volume, where it must be, and
/// in the kernel image, where it must not — and neither of those questions can
/// be answered from inside the machine that is making the claim.
///
/// A string rather than the report constant: at `-Copt-level=2` an integer
/// immediate is built in registers and never lands in `.rodata` at all, so
/// grepping for its bytes finds nothing in either image and the check passes
/// for the wrong reason.
///
// SAFETY: `link_section` places this in `.rodata`, the section the linker
// script already emits for read-only data; nothing else in this program names
// that section, so there is no placement to conflict with, and the value is a
// plain byte array with no initializer to run.
#[used]
#[unsafe(link_section = ".rodata")]
static VOLUME_MARK: [u8; 32] = *b"tessera program off the volume\n\0";

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
