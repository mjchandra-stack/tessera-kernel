// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The boot glue playing parent to a C program.
//!
//! **Extracted when there were two, not when there was one.** `cargs` wrote
//! this to run a program with arguments and read the single value it reported;
//! `csay` needed exactly the same thing, and a second copy of a spawn, a
//! scheduler run, a reap and a report-count check is the shape this tree
//! extracts rather than anticipates (the rule `//userspace/elfload` records,
//! where the ELF parser moved out of `roottask` only when a second loader
//! needed it — D294).
//!
//! **What a parent does, and why the kernel is doing it.** A ring-3 launcher
//! builds a `StartupArgs`, names its address in `ProcessStartArgs::message_va`,
//! starts the child and collects what it said. The root task has done that
//! since D261. Nothing above these checks on this port is a launcher, so the
//! boot glue does it — the mechanism is the real one, a page the parent names
//! and the child is told about, and what is not real is the parent
//! (`build/README.md`, D318).
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 4"),
//! api/isl/examples/process_abi.isl ("StartupArgs")

use crate::*;
use process_abi::{StartupArg, StartupArgs, StartupHandles};
use tessera_isl_runtime::{HandleRef, encode};

/// Where a child finds its startup message.
///
/// **A page this glue names, and the child is told rather than assuming it**:
/// the address travels in the entry register, so nothing depends on the two
/// sides having compiled the same constant — which is the reasoning
/// `//userspace/roottask` writes down for the same decision. Clear of a C
/// program's segments at `0x400000`, its stack below `USER_STACK_BASE`, and the
/// heap window `tessera/layout.h` names.
pub(crate) const MESSAGE_VA: u64 = 0x6900_0000;

/// Builds the startup message a child with `argv` and no capabilities receives.
///
/// **Encoded through the generated binding**, never assembled by hand: the
/// child decodes the same schema from C, and the one thing that must not differ
/// between the two is what a byte at an offset means.
pub(crate) fn message(argv: &[&[u8]], out: &mut [u8; StartupArgs::WIRE_SIZE]) -> Result<(), u32> {
    let mut args = StartupArgs {
        size: StartupArgs::WIRE_SIZE as u32,
        version: 2,
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
            bytes: [0u8; 160],
        }; 12],
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

/// Runs a C program once with `argv` and returns the single value it
/// reported.
///
/// **One report is the contract.** These programs report once on success and
/// once per refusal — `crt0` when the startup message will not decode, the
/// heap when it cannot serve a request, the program itself when a step fails —
/// so a count other than one means something gave up, and the first value names
/// which. Checked here rather than by each caller, because getting it wrong
/// reads as a wrong answer instead of as a refusal.
pub(crate) fn run_once(
    image: &'static [u8],
    argv: &[&[u8]],
    process_obj: kcore::object::ObjectId,
    base_err: u32,
    what: &str,
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
        image,
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
            "{what}: ring-3 fault vector {} at {:#x}, rip {:#x}",
            crate::pci_bus::BIND_FAULT[0].load(Ordering::SeqCst),
            crate::pci_bus::BIND_FAULT[1].load(Ordering::SeqCst),
            crate::pci_bus::BIND_FAULT[2].load(Ordering::SeqCst),
        );
        return Err(1460);
    }
    // More than one report means `crt0` or the probe refused a step and said
    // so before exiting; the first of them names which.
    if count != 1 {
        kprintln!("{what}: {count} reports, first {report:#x} — a step refused");
        return Err(1461);
    }
    Ok(report)
}
