// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A C program told what to work on, run and checked from here.
//!
//! **The third claim about C on this machine, and it is not the first two.**
//! `cprog` says a program the host toolchain compiled runs; `cheap` says such a
//! program can ask the kernel for memory. This one says its runtime can read
//! the message its parent left it and hand `main` the two parameters C spells
//! arguments with (`docs/roadmap/04` Phase 4; `build/README.md`, D317). A C
//! program that cannot run, one that cannot allocate and one that cannot read
//! its own startup message are three findings, and one report for all three
//! would make each look like the others.
//!
//! **Nothing above this is a parent, so the kernel plays one.** A ring-3
//! launcher builds a `StartupArgs` and names its address in
//! `ProcessStartArgs::message_va` — the root task has done that since D261 and
//! `arg-probe` is checked that way. On this port the boot glue is what starts
//! the C programs, so it builds the message itself, through the *generated*
//! binding rather than by hand, and hands the child the address in its entry
//! register.
//!
//! **Run twice, with different arguments, and required to answer differently.**
//! That is the whole design of this check. A program reporting a value folded
//! from its arguments could in principle have the value compiled in; a program
//! that must produce two different values from one image, with the strings
//! chosen here and appearing nowhere in that image, could not. The two
//! expectations are also asserted to differ from each other, so a fold that
//! collapsed every input to one number would fail rather than pass twice.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 4"),
//! api/isl/examples/process_abi.isl ("StartupArgs")

use crate::*;

/// The first run's arguments, and the second's.
///
/// **Chosen here and nowhere in the program's image**, which is what makes the
/// reports below evidence rather than a constant agreeing with itself. Three
/// arguments in the second, so `argc` differs too and not only the bytes.
const ARGV_FIRST: &[&[u8]] = &[b"/one"];
const ARGV_SECOND: &[&[u8]] = &[b"/two", b"three", b"four!"];

/// What `c-arg-probe` reports for [`ARGV_FIRST`] and [`ARGV_SECOND`]: the fold
/// over `argc`, each argument's length, and every one of its bytes.
///
/// Spelled here and computed there. Neither value is in the program's image and
/// neither is derivable from the other without the strings.
const REPORT_FIRST: u64 = 0x0000_0400_17f7_3f5c;
const REPORT_SECOND: u64 = 0xbc7d_d923_470b_4885;

/// The two runs' process objects, distinct from each other and from every other
/// check's.
const PROC_OBJ_FIRST: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c2);
const PROC_OBJ_SECOND: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c3);

/// Runs `c-arg-probe` twice and returns the two values it reported.
///
/// `Ok(None)` when this image carries no such program, which is how every check
/// here answers on a machine that was not built with one.
pub(crate) fn c_args_check(
    kernel_vm: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<Option<(u64, u64)>, u32> {
    if crate::user::components::c_arg_probe().is_empty() {
        return Ok(None);
    }
    // **The guard on the whole claim, and it is here rather than after the
    // runs.** "The same image answered twice, differently" needs the two
    // expectations to differ; they are hand-copied from the fold, and a typo
    // that made them equal would leave a check that passed while claiming
    // nothing. Comparing the two *observations* afterwards would be dead code
    // once this holds and both match, so this is the only place the sentence
    // can be defended.
    if REPORT_FIRST == REPORT_SECOND {
        return Err(1443);
    }

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(crate::pci_bus::bind_observer);
    set_user_fault_handler(crate::pci_bus::bind_user_fault_handler);
    crate::syscalls::publish_frames(frames);

    // Distinct error bases, so a spawn that fails says which of the two runs
    // it was: they differ in their arguments alone, and a failure common to
    // both is a different fact from one the second run alone provokes.
    let image = crate::user::components::c_arg_probe();
    let first = crate::cparent::run_once(
        image,
        ARGV_FIRST,
        PROC_OBJ_FIRST,
        1450,
        "c-args",
        kernel_vm,
        frames,
    )?;
    let second = crate::cparent::run_once(
        image,
        ARGV_SECOND,
        PROC_OBJ_SECOND,
        1470,
        "c-args",
        kernel_vm,
        frames,
    )?;

    // SAFETY: both runs are over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    if first != REPORT_FIRST {
        kprintln!("c-args: first run reported {first:#x}, wanted {REPORT_FIRST:#x}");
        return Err(1462);
    }
    if second != REPORT_SECOND {
        kprintln!("c-args: second run reported {second:#x}, wanted {REPORT_SECOND:#x}");
        return Err(1463);
    }
    Ok(Some((first, second)))
}
