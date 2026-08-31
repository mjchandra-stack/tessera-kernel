// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A ring-3 program that allocates, checked from here.
//!
//! **What is new is not the syscalls.** `MemoryCreate` and `MemoryMap` have
//! been reachable from ring 3 since D131 and every driver in this tree calls
//! them. What has never happened is a program calling them *because it ran out
//! of room* — deciding at run time how much memory it needs, rather than naming
//! a size at compile time and living inside it. That is the whole of
//! `docs/roadmap/04` Phase 0, and every phase after it needs it: a compiler's
//! working set is a property of its input (`build/README.md`, D301).
//!
//! **The check is the reuse, not the allocation.** A probe that only proved a
//! `Vec` could grow would pass against an allocator that never reclaimed a
//! byte — and a heap that never reclaims is a program that dies at whatever
//! size its input happens to reach. So `heap-probe` frees its largest vector
//! and allocates one the same size again, having recorded that the heap did not
//! grow to serve it, and reports the step that failed rather than only that one
//! did.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 0")

// The crate root holds this machine's statics, its layout constants and its
// object ids, and every check reaches for them.
use crate::*;
// `components` is a module rather than an item, so the root glob does not carry
// it here; named directly.
use crate::host::components;

/// The probe's process object, and its kernel stack window.
///
/// Hand-picked in this port's `0xffff_000f_` range, which is where its checks'
/// windows live and which nothing else in the tree uses; the pooled allocator
/// D53 provides is for the restart loops that recycle windows, and this check
/// starts one process once.
pub(crate) const HEAP_PROBE_PROC_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0x1f8);
pub(crate) const HEAP_PROBE_KSTACK_VA: u64 = 0xffff_000f_a000_0000;

/// What the probe reports when every step passed.
///
/// Agreed with `userspace/heap-probe`, which is the only thing that writes it.
pub(crate) const HEAP_PROBE_OK: u64 = 0x4845_4150_0000_0001;

/// Runs `heap-probe` and returns what it reported.
///
/// `Ok(None)` when this image carries no such program, which is how every
/// check here answers on a machine that was not built with one — a boot that
/// skipped is a boot that says so rather than one that passes quietly.
pub(crate) fn heap_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<Option<u64>, u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    if components::heap_probe().is_empty() {
        return Ok(None);
    }

    // A fresh executive: this check's threads are its own.
    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        crate::el0::kcore_exec_restart(9);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down, and the loader maps the child's kernel stack through it.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // **No handles are installed, and that is the point.** This program is
    // given nothing: no channel, no device, no bus. Everything it does it does
    // by asking the kernel for memory, which is the one authority a process has
    // by being a process. A probe that needed a capability to allocate would be
    // measuring the capability.
    let (probe_idx, probe_proc) = ring3_host_spawn(
        components::heap_probe(),
        HEAP_PROBE_KSTACK_VA,
        0,
        HEAP_PROBE_PROC_OBJ,
        &mut kernel_space,
        frames,
        1310,
    )?;

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // The timer runs for the same reason every other check here runs it: a
    // program that wedged would otherwise spin to its bound rather than being
    // taken off the CPU and reported.
    tessera_karch_aarch64::GenericTimer::start_periodic_this_cpu(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.run();
        }
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: the boot CPU alone; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    // **A fault is not a failed step.** A program that took an exception on a
    // heap address has told us something quite different from one that ran and
    // disagreed with itself, and the two must not report the same number: the
    // first means the mapping is wrong and the second means the arithmetic is.
    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(1330);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);

    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(probe_idx);
        }
    }
    use tessera_karch::FrameSource;
    for page in 0..RING3_HOST_KSTACK_PAGES {
        if let Ok(frame) = kernel_space
            .arch_mut()
            .unmap(VirtAddr::new(HEAP_PROBE_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }
    // SAFETY: transient raw access; the process is removed and torn down once.
    // **`release_memory_of` is what frees the heap**: every growth was a memory
    // object this process created and holds, so a teardown that only unmapped
    // would leak sixty-four kilobytes per growth into a machine that has more
    // checks to run.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(probe_proc) {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.release_memory_of(process.id(), frames, None);
            }
            process.space_mut().teardown(frames);
        }
    }

    if report != HEAP_PROBE_OK {
        // The probe puts the failing step in the low byte, so the error names
        // which of its seven claims went wrong rather than that one did.
        return Err(1340 + (report & 0xff) as u32);
    }
    Ok(Some(report))
}
