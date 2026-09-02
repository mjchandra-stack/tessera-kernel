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
use process_abi::{StartupArg, StartupArgs, StartupHandles};
use tessera_isl_runtime::{HandleRef, encode};

/// Where the child finds its startup message.
///
/// **A page this glue names, and the child is told rather than assuming it**:
/// the address travels in the entry register, so nothing depends on the two
/// sides having compiled the same constant — which is the reasoning
/// `//userspace/roottask` writes down for the same decision. Clear of a C
/// program's segments at `0x400000`, its stack below `USER_STACK_BASE`, and the
/// heap window `tessera/layout.h` names.
const MESSAGE_VA: u64 = 0x6900_0000;

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

/// Builds the startup message a child with `argv` and no capabilities receives.
///
/// **Encoded through the generated binding**, never assembled by hand: the
/// child decodes the same schema from C, and the one thing that must not differ
/// between the two is what a byte at an offset means.
fn message(argv: &[&[u8]], out: &mut [u8; StartupArgs::WIRE_SIZE]) -> Result<(), u32> {
    let mut args = StartupArgs {
        size: StartupArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        // **No capabilities, and that is deliberate.** This check is about the
        // argument vector; a child handed an endpoint would be measuring the
        // grant as well, which `cprog` already declined to do for the same
        // reason.
        handles: StartupHandles {
            size: StartupHandles::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            endpoint: HandleRef::new(0),
            port: HandleRef::new(0),
        },
        output: HandleRef::new(0),
        count: argv.len() as u32,
        reserved: 0,
        args: [StartupArg {
            len: 0,
            reserved: 0,
            bytes: [0u8; 128],
        }; 4],
    };
    if argv.len() > args.args.len() {
        return Err(1440);
    }
    for (slot, value) in args.args.iter_mut().zip(argv) {
        if value.len() > slot.bytes.len() {
            return Err(1441);
        }
        slot.len = value.len() as u32;
        slot.bytes[..value.len()].copy_from_slice(value);
    }
    encode(&args, out).map(|_| ()).map_err(|_| 1442u32)
}

/// Runs `c-arg-probe` once with `argv` and returns the single value it
/// reported.
fn run_once(
    argv: &[&[u8]],
    process_obj: kcore::object::ObjectId,
    base_err: u32,
    kernel_vm: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<u64, u32> {
    crate::pci_bus::BIND_FAULTED.store(false, Ordering::SeqCst);
    crate::pci_bus::BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &crate::pci_bus::BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }

    let mut wire = [0u8; StartupArgs::WIRE_SIZE];
    message(argv, &mut wire)?;

    let (thread, process) = crate::pci_bus::spawn_elf_process_with_message(
        crate::user::components::c_arg_probe(),
        // **The address is the argument.** This is the whole handoff: `crt0`
        // reads its first parameter, and a zero there is a program that was
        // given no message rather than one whose message was empty.
        MESSAGE_VA as usize,
        Some((MESSAGE_VA, &wire)),
        process_obj,
        kernel_vm,
        frames,
        base_err,
    )?;

    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let faulted = crate::pci_bus::BIND_FAULTED.load(Ordering::SeqCst);
    let report = crate::pci_bus::BIND_REPORTS[0].load(Ordering::SeqCst);
    let count = crate::pci_bus::BIND_REPORT_COUNT.load(Ordering::SeqCst);

    // SAFETY: transient raw access; the thread is off-CPU and the process is
    // released once.
    unsafe {
        exec_ref().scheduler().reap(thread);
        if let Some(mut gone) = (&mut *&raw mut PROCESSES).remove(process) {
            gone.space_mut().teardown(frames);
        }
    }

    // **A fault is not a wrong answer**, and here it is the likeliest way to
    // get the message page wrong: an address the child was told about and
    // nothing was mapped at reads as a fault rather than as a bad value.
    if faulted {
        kprintln!(
            "c-args: ring-3 fault vector {} at {:#x}, rip {:#x}",
            crate::pci_bus::BIND_FAULT[0].load(Ordering::SeqCst),
            crate::pci_bus::BIND_FAULT[1].load(Ordering::SeqCst),
            crate::pci_bus::BIND_FAULT[2].load(Ordering::SeqCst),
        );
        return Err(1460);
    }
    // More than one report means `crt0` or the probe refused a step and said
    // so before exiting; the first of them names which.
    if count != 1 {
        kprintln!("c-args: {count} reports, first {report:#x} — a step refused");
        return Err(1461);
    }
    Ok(report)
}

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
    let first = run_once(ARGV_FIRST, PROC_OBJ_FIRST, 1450, kernel_vm, frames)?;
    let second = run_once(ARGV_SECOND, PROC_OBJ_SECOND, 1470, kernel_vm, frames)?;

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
