// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A ring-3 program written in C, run and checked from here.
//!
//! **What is new is the language, and that is the whole claim.** The loader,
//! the address space, the trap and the exit are all the ones every other ring-3
//! program on this port uses; nothing in the kernel knows or cares what a
//! program was written in. What had never been true is that anything but Rust
//! could produce one — a `no_std` binary with a `_start` that never returns is
//! not a shape a C toolchain emits, and a ported compiler, a shell and every
//! core utility are written as `int main(void)` (`docs/roadmap/04`, Phase 4;
//! `build/README.md`, D306).
//!
//! **The report is computed, not stored.** `c-probe` accumulates across a
//! static in its data segment, a local, and a function the compiler had to
//! emit; a program that wrote a constant would prove the loader ran something
//! and nothing about it having run *this*.
//!
//! **And its syscall numbers came from the published ABI.** The program
//! includes `<tessera/syscall_abi.h>`, which `islc` generates and
//! `//tools/checks:surface_test` holds to `SyscallNumber` — so this check also
//! says D305's headers are usable for the thing they exist for, rather than
//! only that they compile.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 4")

use crate::*;

/// What `c-probe` reports: `(0x0c00 + 0xde)` mixed three rounds.
///
/// **Spelled here and computed there**, which is the point of it being
/// arithmetic rather than a constant: the program does not carry this number
/// and neither does its image, so the two agreeing means the machine executed
/// the loop.
pub(crate) const C_PROBE_REPORT: u64 = 0x00cd_edcf;

/// The C program's process object, distinct from every other check's.
pub(crate) const C_PROBE_PROC_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0x1c0);

/// Runs `c-probe` and returns what it reported.
///
/// `Ok(None)` when this image carries no such program, which is how every check
/// here answers on a machine that was not built with one.
pub(crate) fn c_program_check(
    kernel_vm: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<Option<u64>, u32> {
    if crate::user::components::c_probe().is_empty() {
        return Ok(None);
    }

    // SAFETY: one-shot registration before this check's ring-3 thread runs.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(crate::pci_bus::bind_observer);
    set_user_fault_handler(crate::pci_bus::bind_user_fault_handler);
    crate::pci_bus::BIND_FAULTED.store(false, Ordering::SeqCst);
    crate::pci_bus::BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &crate::pci_bus::BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    // `frames` outlives the run; the loan is withdrawn before return.
    crate::syscalls::publish_frames(frames);

    // **No handles, and no startup argument.** This program is given nothing:
    // the authority to report and to exit is what a process has by being one,
    // and a probe that needed a capability would be measuring the capability
    // rather than the language.
    let (thread, process) = crate::pci_bus::spawn_elf_process(
        crate::user::components::c_probe(),
        0,
        C_PROBE_PROC_OBJ,
        kernel_vm,
        frames,
        1400,
    )?;

    // One program, two syscalls, no waiting on anything: the scheduler runs to
    // quiescence without a tick to prod it.
    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    // **A fault is not a wrong answer.** A C program that took an exception has
    // said something different from one that ran and computed the wrong number,
    // and the two must not report the same failure: the first means the image
    // or the mapping is wrong, the second means the compiler or this constant
    // is.
    if crate::pci_bus::BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(1410);
    }
    let report = crate::pci_bus::BIND_REPORTS[0].load(Ordering::SeqCst);

    // SAFETY: transient raw access; the thread is off-CPU and the process is
    // released once.
    unsafe {
        exec_ref().scheduler().reap(thread);
        if let Some(mut gone) = (&mut *&raw mut PROCESSES).remove(process) {
            gone.space_mut().teardown(frames);
        }
    }

    if report != C_PROBE_REPORT {
        return Err(1411);
    }
    Ok(Some(report))
}
