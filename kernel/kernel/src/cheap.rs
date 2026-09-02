// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A C program that allocates, run and checked from here.
//!
//! **What is new is the heap, and it is a different claim from `cprog`'s.**
//! That check says a program the host C toolchain compiled runs on this
//! machine; this one says such a program can ask the kernel for memory and get
//! it back — `malloc` and `free` from `//userspace/libc` over `MemoryCreate`
//! and `MemoryMap` (`docs/roadmap/04` Phase 4; `build/README.md`, D316). They
//! are two programs rather than one because they fail differently: a C program
//! that cannot run and a heap that cannot allocate are not the same finding.
//!
//! **The program's claims are addresses, not successes**, which is what makes
//! this hard to pass without the mechanism. It allocates 128 KiB — larger than
//! `MAX_OBJECT_PAGES` allows one memory object to be, so it exists only
//! because two objects were mapped adjacently and the free list coalesced
//! them — frees it and asks again for the same size, requiring the *same
//! address* back, and finally gives three adjacent ranges back and takes one
//! larger than any of them, requiring the base. An allocator that only ever
//! bumped upward satisfies none of the last three.
//!
//! **And the number it reports is computed out of the heap**: a mix over bytes
//! written into allocated memory and read back from it, so a console carrying
//! the value carries it because this machine stored and reloaded them.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 4")

use crate::*;

/// What `c-heap-probe` reports: the mix over the bytes it wrote into the heap
/// and read back.
///
/// **Spelled here and computed there.** Neither the program nor its image
/// carries this number — it is a fold over 32 page tags and 4096 words the
/// program derived — so the two agreeing means the machine ran the loops
/// against memory it had allocated.
pub(crate) const C_HEAP_PROBE_REPORT: u64 = 0xcf21_d5cf_07d1_e010;

/// The program's process object, distinct from every other check's.
pub(crate) const C_HEAP_PROBE_PROC_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0x1c1);

/// Runs `c-heap-probe` and returns what it reported.
///
/// `Ok(None)` when this image carries no such program, which is how every check
/// here answers on a machine that was not built with one.
pub(crate) fn c_heap_check(
    kernel_vm: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<Option<u64>, u32> {
    if crate::user::components::c_heap_probe().is_empty() {
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
    // `frames` outlives the run; the loan is withdrawn before return. This is
    // also what `MemoryCreate` allocates out of, so the loan is load-bearing
    // here in a way it is not for `cprog`: without it the program's first
    // growth is refused rather than its first report being lost.
    crate::syscalls::publish_frames(frames);

    // **No handles, and no startup argument**, exactly as `cprog` gives none.
    // Allocating needs no capability — `MemoryCreate` makes an object the
    // caller then holds — and a probe that had to be handed one would be
    // measuring the grant rather than the heap.
    let (thread, process) = crate::pci_bus::spawn_elf_process(
        crate::user::components::c_heap_probe(),
        0,
        C_HEAP_PROBE_PROC_OBJ,
        kernel_vm,
        frames,
        1420,
    )?;

    // One program, no waiting on anything: the scheduler runs to quiescence
    // without a tick to prod it. Its syscalls — three `MemoryCreate`, three
    // `MemoryMap`, one `DebugWrite`, one `ProcessExit` — all answer inline.
    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    // **A fault is not a wrong answer**, and here the distinction earns more
    // than it does for `cprog`: this program writes every page of a 128 KiB
    // block, so a mapping the kernel reported as made and did not make shows
    // up as a fault rather than as a wrong number. The two must not report the
    // same failure.
    if crate::pci_bus::BIND_FAULTED.load(Ordering::SeqCst) {
        // The vector, the faulting address and the instruction, because a
        // ring-3 fault with none of them says only that something went wrong
        // in a program with no debugger and no console.
        kprintln!(
            "c-heap: ring-3 fault vector {} at {:#x}, rip {:#x}",
            crate::pci_bus::BIND_FAULT[0].load(Ordering::SeqCst),
            crate::pci_bus::BIND_FAULT[1].load(Ordering::SeqCst),
            crate::pci_bus::BIND_FAULT[2].load(Ordering::SeqCst),
        );
        return Err(1430);
    }
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

    // **More than one report means a step refused**, and that is a distinct
    // failure from a wrong mix: the program reports once on success and once
    // per refusal, and `libc`'s heap reports too. Checked before the value, so
    // a run that failed at step three does not get read as arithmetic.
    if count != 1 {
        kprintln!("c-heap: {count} reports, first {report:#x} — a step refused");
        return Err(1431);
    }
    if report != C_HEAP_PROBE_REPORT {
        kprintln!("c-heap: report {report:#x}, wanted {C_HEAP_PROBE_REPORT:#x}");
        return Err(1432);
    }
    Ok(Some(report))
}
