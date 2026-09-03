// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A C program that says something a person can read, run and checked here.
//!
//! **The fourth claim about C on this machine, and the one that was available
//! all along.** `<tessera/syscall.h>` said no port had a console a ring-3
//! program could put text on, so every C program here reported a number.
//! x86-64's `user_debug_write` has read up to 128 bytes out of the calling
//! process and printed them for as long as this port has had a syscall handler.
//! Nothing in C could reach it, and the header said so as though it were a
//! property of the system rather than of the header (`build/README.md`, D318).
//!
//! **This check sees half of it, and says which half.** The text goes to the
//! kernel's console, which this code cannot read back — so what is asserted
//! here is the byte count the syscall answered with, and
//! `tools/qemu/smoke_boot.sh` greps the serial log for the line itself. They
//! fail apart, which is the point: a call that accepted the buffer and printed
//! nothing gives the count without the text, and that is exactly what happens
//! when the bytes are not valid UTF-8.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 4")

use crate::*;

/// What the program is told to say.
///
/// **Two arguments rather than one**, so the line it builds is assembled from
/// pieces it had to measure separately rather than copied whole — which is what
/// gives `strlen` and `memcpy` their callers.
const ARGV: &[&[u8]] = &[b"hello", b"tessera"];

/// How many bytes the console should say it took: `"c-say:"` plus a space and
/// each argument.
///
/// **Spelled as arithmetic over the arguments above**, so changing them changes
/// this and a copied-over number cannot go stale. Six for the tag, then two
/// bytes of separator and twelve of argument.
const EXPECTED_BYTES: u64 = 6 + (1 + 5) + (1 + 7);

const PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c4);

/// Runs `c-say-probe` and returns how many bytes the console accepted.
///
/// `Ok(None)` when this image carries no such program.
pub(crate) fn c_say_check(
    kernel_vm: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<Option<u64>, u32> {
    let image = crate::user::components::c_say_probe();
    if image.is_empty() {
        return Ok(None);
    }

    // SAFETY: one-shot registration before this check's ring-3 thread runs.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(crate::pci_bus::bind_observer);
    set_user_fault_handler(crate::pci_bus::bind_user_fault_handler);
    crate::syscalls::publish_frames(frames);

    let wrote = crate::cparent::run_once(image, ARGV, PROC_OBJ, 1480, "c-say", kernel_vm, frames)?;

    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    // **The count is the kernel's own answer**, not the program's belief about
    // what it sent: `user_debug_write` returns what it took after clamping to
    // the console's limit, so a line this program built too long would come
    // back short and be caught here rather than read as a shorter line.
    if wrote != EXPECTED_BYTES {
        kprintln!("c-say: console took {wrote} bytes, wanted {EXPECTED_BYTES}");
        return Err(1490);
    }
    Ok(Some(wrote))
}
