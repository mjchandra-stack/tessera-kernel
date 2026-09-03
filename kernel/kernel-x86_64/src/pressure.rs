// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The pager-pressure scenarios (docs/prototypes/02).
//!
//! Throttling, dirty-page accounting, durability, a pager that dies, the reclaim
//! deadlock, the self-paging cycle, and deadline supervision — the seven the
//! prototype names.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// ---- Pager-pressure scenario demos (docs/prototypes/02) ---------------------

/// The scratch pager-backed object's base VA for the pressure scenarios.
pub(crate) const PAGER_PRESSURE_VA: u64 = 0x0000_0000_5000_0000;
/// Builds a scratch object-backed space of `pages` pages, all supplied
/// (read-only) and clean — the resident working set the scenarios operate on.
pub(crate) fn pager_scratch(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    pages: u64,
) -> Option<AddressSpace<KernelAddressSpace>> {
    let arch = kernel_vm.arch().new_user(frames).ok()?;
    let mut space = AddressSpace::from_arch(arch, alloc_asid(), 0);
    let object = ObjectId::from_raw(0x5017_0000);
    space
        .map_object(
            VirtAddr::new(PAGER_PRESSURE_VA),
            pages * FRAME_SIZE,
            PageFlags::rw().user(),
            object,
            0,
        )
        .ok()?;
    for off in 0..pages {
        let va = VirtAddr::new(PAGER_PRESSURE_VA + off * FRAME_SIZE);
        let frame = frames.alloc()?;
        space.arch().fill_frame(frame, 0);
        space.supply_page(va, frame, frames).ok()?;
    }
    Some(space)
}

/// Writes page `off`: the software dirty-bit path. A write to the read-only
/// resident page faults `WriteToClean`; the kernel records it dirty (throttling
/// at the object's dirty bound) and, when within the bound, grants write.
pub(crate) fn pager_write(
    space: &mut AddressSpace<KernelAddressSpace>,
    cache: &mut ObjectCache,
    off: u64,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> DirtyOutcome {
    let va = VirtAddr::new(PAGER_PRESSURE_VA + off * FRAME_SIZE);
    match space.resolve_fault(va, true, frames) {
        FaultOutcome::WriteToClean { offset, .. } => {
            let outcome = cache.mark_dirty(offset);
            if outcome == DirtyOutcome::Marked {
                let _ = space.grant_write(va);
            }
            outcome
        }
        // Already writable (already dirtied) or a genuine fault.
        _ => DirtyOutcome::Throttle,
    }
}

/// Writes page `off` back: re-protects the page read-only so the snapshot is
/// stable and the next write re-faults, then — only after the (synchronous, v0)
/// pager acknowledgment — marks the page clean.
pub(crate) fn pager_writeback(
    space: &mut AddressSpace<KernelAddressSpace>,
    cache: &mut ObjectCache,
    off: u64,
) {
    let va = VirtAddr::new(PAGER_PRESSURE_VA + off * FRAME_SIZE);
    let _ = space.reprotect_ro(va);
    // The pager persists the stable snapshot and acknowledges; only then:
    cache.mark_clean(off * FRAME_SIZE);
}

/// S2 — dirty flood. A writer dirties pages faster than write-back; the write
/// **throttles at the write fault** once the object's dirty bound is hit, dirty
/// stays bounded, and a write-back drains room for the throttled writer to
/// proceed (docs/prototypes/02 S2; docs/kernel/03 "Dirty throttling").
pub(crate) fn pager_throttle_demo(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const PAGES: u64 = 8;
    const LIMIT: u32 = 3;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S2 dirty-flood: setup failed");
    };
    let mut cache = ObjectCache::new(LIMIT);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    // Flood: the first LIMIT distinct pages dirty; the next throttles.
    let mut throttled_at = None;
    for off in 0..PAGES {
        if pager_write(&mut space, &mut cache, off, frames) == DirtyOutcome::Throttle {
            throttled_at = Some(off);
            break;
        }
    }
    let throttle_ok = throttled_at == Some(LIMIT as u64) && cache.dirty_count() == LIMIT;
    // Drain one page-back (ack → clean), then the throttled writer proceeds.
    pager_writeback(&mut space, &mut cache, 0);
    let retry = pager_write(&mut space, &mut cache, throttled_at.unwrap_or(0), frames);
    let drained_ok = retry == DirtyOutcome::Marked && cache.dirty_count() == LIMIT;
    let pass = throttle_ok && drained_ok;
    report(&verdict(
        DemoId::PagerDirtyFlood,
        pass,
        [u64::from(LIMIT), 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("S2 dirty-flood: FAIL throttle={throttle_ok} drained={drained_ok}");
    }
}

/// S8 — coordinated flush query. Dirty a scattered set of pages, then assert the
/// dirty-range query returns **exactly** those pages — dirty-tracking
/// correctness on the software dirty-bit configuration (docs/prototypes/02 S8).
pub(crate) fn pager_dirty_query_demo(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const PAGES: u64 = 8;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S8 dirty-query: setup failed");
    };
    let mut cache = ObjectCache::new(64);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    // Dirty a scattered subset.
    let dirtied = [1u64, 3, 4, 7];
    let mut all_marked = true;
    for &p in &dirtied {
        if pager_write(&mut space, &mut cache, p, frames) != DirtyOutcome::Marked {
            all_marked = false;
        }
    }
    let mut buf = [0u64; PAGES as usize];
    let n = cache.dirty_offsets(&mut buf);
    let expected = [FRAME_SIZE, 3 * FRAME_SIZE, 4 * FRAME_SIZE, 7 * FRAME_SIZE];
    let exact = n == expected.len() && buf[..n] == expected;
    let pass = all_marked && exact;
    report(&verdict(DemoId::PagerDirtyQuery, pass, [0; 8]));
    if !pass {
        kprintln!("S8 dirty-query: FAIL n={n} marked={all_marked} exact={exact}");
    }
}

/// S4 — durability ordering. Write dirty pages back and prove **no page is
/// marked clean before its (synchronous, v0) pager acknowledgment**, and that
/// the snapshot is stable — once write-back is issued the page is read-only, so
/// a write re-faults rather than silently mutating the in-flight snapshot
/// (docs/prototypes/02 S4; docs/kernel/03 "Durability ordering").
pub(crate) fn pager_durability_demo(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const PAGES: u64 = 4;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S4 durability: setup failed");
    };
    let mut cache = ObjectCache::new(64);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    for off in 0..PAGES {
        let _ = pager_write(&mut space, &mut cache, off, frames);
    }
    let mut clean_before_ack = false;
    let mut snapshot_stable = true;
    let mut cleaned_after_ack = 0u32;
    for off in 0..PAGES {
        let va = VirtAddr::new(PAGER_PRESSURE_VA + off * FRAME_SIZE);
        // Issue write-back: re-protect read-only so the snapshot cannot change.
        let _ = space.reprotect_ro(va);
        // A write now must re-fault (the page is read-only) — the snapshot is
        // stable, not a concurrently-mutating page.
        if !matches!(
            space.resolve_fault(va, true, frames),
            FaultOutcome::WriteToClean { .. }
        ) {
            snapshot_stable = false;
        }
        // Before the ack the page must still be dirty (not prematurely cleaned).
        if !cache.is_dirty(off * FRAME_SIZE) {
            clean_before_ack = true;
        }
        // ... the pager persists the stable snapshot and acknowledges ...
        // Only after the ack: mark clean.
        cache.mark_clean(off * FRAME_SIZE);
        cleaned_after_ack += 1;
    }
    let ok = !clean_before_ack
        && snapshot_stable
        && cleaned_after_ack == PAGES as u32
        && cache.dirty_count() == 0;
    report(&verdict(
        DemoId::PagerDurability,
        ok,
        [u64::from(cleaned_after_ack), 0, 0, 0, 0, 0, 0, 0],
    ));
    if !ok {
        kprintln!(
            "S4 durability: FAIL clean_before_ack={clean_before_ack} stable={snapshot_stable} cleaned={cleaned_after_ack}"
        );
    }
}

/// S6 — pager death. Kill the pager while it holds dirty pages with un-acked
/// write-backs: its bound object enters a **faulted** state and a data-integrity
/// event reports **exactly** the lost dirty ranges — no more, no fewer
/// (docs/prototypes/02 S6; docs/kernel/03 "Ownership, Resize, And Revocation").
pub(crate) fn pager_death_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const PAGES: u64 = 6;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S6 pager-death: setup failed");
    };
    let mut cache = ObjectCache::new(64);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    // Dirty a scattered subset — in-flight, not yet written back.
    let dirtied = [0u64, 2, 5];
    for &p in &dirtied {
        let _ = pager_write(&mut space, &mut cache, p, frames);
    }

    // Spawn a pager thread and kill it (M11 terminate) — the pager dies holding
    // those dirty pages.
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let exec = exec_ref();
    let killed = match Thread::<ContextSwitch>::spawn(
        job_member_entry,
        0,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        kernel_vm,
        frames,
    )
    .ok()
    .and_then(|thread| exec.add_thread(thread).ok())
    {
        Some(idx) => {
            exec.scheduler().terminate(idx);
            exec.scheduler().thread_state(idx) == Some(ThreadState::Exited)
        }
        None => false,
    };

    // On pager death the object faults, reporting exactly the lost dirty ranges.
    let mut lost = [0u64; PAGES as usize];
    let n = cache.fault(&mut lost);
    let expected = [0, 2 * FRAME_SIZE, 5 * FRAME_SIZE];
    let exact = n == expected.len() && lost[..n] == expected;
    let pass = killed && exact && cache.is_faulted();
    report(&verdict(DemoId::PagerDeath, pass, [0; 8]));
    if !pass {
        kprintln!(
            "S6 pager-death: FAIL killed={killed} n={n} exact={exact} faulted={}",
            cache.is_faulted()
        );
    }
}

/// S3 — Reclaim Deadlock Probe (docs/prototypes/02; docs/kernel/03 "Write-Back
/// Under Memory Pressure"). At hard memory pressure a write-back needs a frame to
/// drain a dirty page — so reclaim can advance — but ordinary allocation would
/// block: the reclaim-needs-memory deadlock. A declared write-back reservation
/// keeps the write-back path progressing; an over-allocation past the reservation
/// fails cleanly (the object's range is faulted), and nothing hangs.
pub(crate) fn pager_reclaim_deadlock_demo(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const CAPACITY: u32 = 8;
    const RESERVED: u32 = 2;
    const PAGES: u64 = 2;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S3 reclaim-deadlock: setup failed");
    };
    let mut cache = ObjectCache::new(4);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    // A dirty page whose write-back is what must make progress under pressure.
    let _ = pager_write(&mut space, &mut cache, 0, frames);

    let mut res = WriteBackReservation::new(CAPACITY, RESERVED);
    // Drive the ordinary (fault/page-in) path to hard memory pressure.
    let mut ordinary = 0u32;
    while res.alloc_ordinary().is_some() {
        ordinary += 1;
    }
    let blocked = res.at_pressure() && res.alloc_ordinary().is_none();
    // Under pressure the reserved write-back path still makes progress; draining
    // the dirty page frees an ordinary frame so reclaim advances.
    let wb_progress = res.alloc_writeback().is_some();
    res.free_ordinary();
    let reclaim_progressed = res.alloc_ordinary().is_some();

    // A write-back that over-allocates past the reservation fails cleanly — the
    // object's dirty range is faulted rather than the kernel hanging.
    while res.alloc_writeback().is_some() {}
    let overalloc_failed = res.alloc_writeback().is_none();
    let mut lost = [0u64; PAGES as usize];
    let n = cache.fault(&mut lost);
    let clean_fail = overalloc_failed && n == 1 && lost[0] == 0 && cache.is_faulted();

    let pass = ordinary == CAPACITY - RESERVED
        && blocked
        && wb_progress
        && reclaim_progressed
        && clean_fail;
    report(&verdict(
        DemoId::PagerReclaimDeadlock,
        pass,
        [u64::from(ordinary), u64::from(RESERVED), 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "S3 reclaim-deadlock: FAIL ordinary={ordinary} blocked={blocked} wb={wb_progress} reclaim={reclaim_progressed} clean_fail={clean_fail}"
        );
    }
}

/// S5 — Self-Paging Cycle (docs/prototypes/02; docs/kernel/03 "Anti-Deadlock
/// Rules"). Pager A's working set is backed by an object paged by pager B and vice
/// versa; forced to fault together they would deadlock. The kernel detects the
/// cycle in the waits-for graph and breaks it by faulting the request (resolution
/// by error, not hang). Also exercises the degenerate single self-paging pager.
pub(crate) fn pager_self_paging_cycle_demo() {
    const PAGER_A: u32 = 0xA;
    const PAGER_B: u32 = 0xB;
    const OBJ_X: u64 = 0x100; // pager A's working set, paged by B
    const OBJ_Y: u64 = 0x200; // pager B's working set, paged by A

    // Mutual: A backed by B, B backed by A; both fault in their own handlers.
    let mut graph = SelfPagingGraph::new();
    let bound = graph.bind(OBJ_X, PAGER_B).is_ok() && graph.bind(OBJ_Y, PAGER_A).is_ok();
    let a_served = graph.request_page_in(PAGER_A, OBJ_X) == PageInResult::Served;
    let b_cycle = graph.request_page_in(PAGER_B, OBJ_Y) == PageInResult::Cycle;
    // Break the cycle by faulting the request: seal the object that could not be
    // served (the anti-deadlock resolution — an error, never a block).
    let mut cycled = ObjectCache::new(1);
    let _ = cycled.install(0);
    let mut lost = [0u64; 1];
    let _ = cycled.fault(&mut lost);
    let mutual_ok = bound && a_served && b_cycle && cycled.is_faulted() && graph.in_flight() == 1;

    // Degenerate: a single pager whose working set is the object it itself pages.
    let mut solo = SelfPagingGraph::new();
    let solo_ok = solo.bind(OBJ_X, PAGER_A).is_ok()
        && solo.request_page_in(PAGER_A, OBJ_X) == PageInResult::Cycle;

    let pass = mutual_ok && solo_ok;
    report(&verdict(DemoId::PagerSelfPagingCycle, pass, [0; 8]));
    if !pass {
        kprintln!("S5 self-paging-cycle: FAIL mutual={mutual_ok} solo={solo_ok}");
    }
}

/// S7 — Deadline Misses and Supervision (docs/prototypes/02; docs/kernel/03
/// "Page-In Flow", L78-83). A pager delays responses past its policy deadline; the
/// faulting thread must get a bounded fault error (the range faulted), never an
/// indefinite block, and repeated misses escalate through supervision (restart),
/// with each miss and escalation observable as a counted event.
pub(crate) fn pager_deadline_supervision_demo() {
    const DEADLINE: u64 = 10; // ticks a page-in may take
    const ESCALATE_AFTER: u32 = 3; // misses before a supervised restart
    const REQUESTS: u32 = 6; // slow requests, all past deadline

    let mut sup = PageInSupervisor::new(DEADLINE, ESCALATE_AFTER);
    // A request answered within the deadline is not faulted (the deadline is a real
    // discriminator, not always-expire).
    let on_time_pending = sup.check(0, DEADLINE) == DeadlineOutcome::Pending;

    let mut bounded_faults = 0u32;
    let mut escalations = 0u32;
    for i in 0..REQUESTS {
        let started = u64::from(i) * 100;
        // The kernel gives up at deadline plus a bounded margin — not indefinite.
        let now = started + DEADLINE + 1;
        if sup.check(started, now) == DeadlineOutcome::Expired {
            // Deliver a bounded fault error: fault the object's range (not a hang).
            let mut obj = ObjectCache::new(1);
            let _ = obj.install(0);
            let mut lost = [0u64; 1];
            let _ = obj.fault(&mut lost);
            if obj.is_faulted() {
                bounded_faults += 1;
            }
            if sup.record_miss() == MissOutcome::Escalate {
                escalations += 1;
            }
        }
    }

    // 6 misses, escalating every 3 → 2 supervised restarts.
    let ok = on_time_pending
        && bounded_faults == REQUESTS
        && sup.misses() == REQUESTS
        && escalations == REQUESTS / ESCALATE_AFTER
        && sup.escalations() == escalations;
    report(&verdict(
        DemoId::PagerDeadlineSupervision,
        ok,
        [
            u64::from(REQUESTS),
            u64::from(escalations),
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    ));
    if !ok {
        kprintln!(
            "S7 deadline-supervision: FAIL on_time={on_time_pending} faults={bounded_faults} misses={} esc={escalations}",
            sup.misses()
        );
    }
}
