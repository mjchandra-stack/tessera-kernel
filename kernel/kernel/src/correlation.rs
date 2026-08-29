// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Correlation-id propagation (docs/observability/02).
//!
//! Events were causally anonymous until D59 — timestamped and typed, with nothing
//! tying a page-in to the fault that caused it. Read against the events the
//! preceding checks actually emitted, not a synthetic sequence.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

/// Correlation-id propagation (docs/observability/02, "Correlation IDs,
/// Normatively"; build/README.md D59). Events were causally anonymous until now —
/// timestamped and typed, but with nothing tying a page-in to the fault that
/// caused it. This proves the four properties the design names, against the
/// events the *preceding* demos actually emitted:
///
/// 1. every record carries a live 128-bit id (the boot epoch plus an
///    origin-minted sequence) and the identity of the thread that emitted it;
/// 2. a synchronous call propagated the caller's id to the callee "for the
///    duration of handling" and restored the callee's own afterwards, so a server
///    does not misattribute its later work to its last caller;
/// 3. spawning fans out — each branch minted a *fresh* id and emitted a link
///    event naming its parent, so traces form a tree;
/// 4. a contained ring-3 fault reported with the faulting thread's id.
///
/// Runs last, so the ring holds the link and fault events from the restart-heavy
/// supervision demos rather than a synthetic sequence.
pub(crate) fn correlation_demo() {
    use kcore::event::{self, Component, EventKind, Severity};
    const CAP: usize = event::EVENT_RING_CAPACITY;

    let epoch = kcore::trace::epoch();
    let blank = event::record(
        EventKind::EventsDropped,
        Severity::Debug,
        Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );
    let mut drained = [blank; CAP];
    let n = event::drain(&mut drained);

    // 1. Stamping: a live id, and the epoch agreeing on every record.
    let mut stamped = 0u64;
    let mut identified = 0u64;
    let mut epoch_ok = n > 0;
    for e in &drained[..n] {
        if e.correlation_lo != 0 {
            stamped += 1;
        }
        if e.thread_id != 0 {
            identified += 1;
        }
        if e.correlation_hi != epoch {
            epoch_ok = false;
        }
    }

    // 3. Fan-out: link events naming a real parent.
    let mut links = 0u64;
    let mut parent = 0u64;
    for e in drained[..n]
        .iter()
        .filter(|e| e.kind == EventKind::CorrelationLink)
    {
        // arg0 is the parent; the envelope carries the fresh child id. A branch
        // that shared its parent's id instead of minting would show them equal.
        if e.arg0 != 0 && e.correlation_lo != e.arg0 {
            links += 1;
            parent = e.arg0;
        }
    }

    // 4. Exception reports carrying the faulting thread's id.
    let faults = drained[..n]
        .iter()
        .filter(|e| e.kind == EventKind::UserFaultContained && e.correlation_lo != 0)
        .count() as u64;

    // 4b. The driver-host crash-recovery ladder, reported from the same drain.
    // It has to be this one: `observability_demo` runs *before* the supervision
    // demos, so this is the only drain that ever sees their records, and a
    // check of its own placed here would consume them instead.
    report_driver_host_ladder(&drained[..n]);

    // 2. Propagation across the synchronous call, sampled inside the round trip.
    let caller = CORRELATION_CALLER.load(Ordering::Relaxed);
    let during = CORRELATION_CALLEE_DURING_CALL.load(Ordering::Relaxed);
    let own = CORRELATION_CALLEE_OWN.load(Ordering::Relaxed);
    let restored = CORRELATION_CALLEE_RESTORED.load(Ordering::Relaxed);
    // The ids must be genuinely distinct, or "adopted" and "own" would be
    // indistinguishable and the check would pass vacuously.
    let distinct = caller != 0 && own != 0 && caller != own;
    let propagated = distinct && during == caller;
    let restored_ok = distinct && restored == own;

    // 5. Across a message boundary: the page-in request left the faulting thread
    //    with a cause and arrived at the pager still carrying it (D60) — the
    //    `docs/kernel/03` clause that the request carries a correlation id.
    let served = CORRELATION_PAGE_IN_SERVED.load(Ordering::Relaxed);
    let requests = CORRELATION_PAGE_IN_REQUESTS.load(Ordering::Relaxed);
    let matched = CORRELATION_PAGE_IN_MATCHED.load(Ordering::Relaxed);
    // Every request the in-kernel pager served arrived under the cause its
    // faulting thread sent it with — not merely the last one.
    let crossed = requests > 0 && matched == requests;

    let pass = epoch != 0
        && epoch_ok
        && stamped > 0
        && identified > 0
        && propagated
        && restored_ok
        && links > 0
        && faults > 0
        && crossed;
    report(&verdict(
        DemoId::Correlation,
        pass,
        [stamped, caller, restored, links, parent, faults, served, 0],
    ));
    if !pass {
        kprintln!(
            "correlation: FAIL epoch={epoch:#x}/{epoch_ok} drained={n} stamped={stamped} ident={identified}"
        );
        kprintln!(
            "correlation: FAIL caller={caller:#x} during={during:#x} own={own:#x} restored={restored:#x}"
        );
        kprintln!(
            "correlation: FAIL links={links} faults={faults} served={served:#x} matched={matched}/{requests}"
        );
    }
}

/// The driver-host crash-recovery ladder as the supervisor recorded it
/// (docs/drivers/01, "Crash Recovery"; build/README.md D112). The restart
/// demos already assert their own outcome from atomics they control; this
/// asserts the *records*, which is the thing a log service would have to work
/// from and which nobody was checking.
///
/// The counts are what the two supervised runs above must produce:
/// `driver_restart_budget_selftest` crashes 4 times against a budget of 4 and
/// then gives up; `driver_restart_demo` crashes twice and comes up clean. Each
/// contained crash is followed by exactly one reclaim-and-rebind, so crashes
/// and restarts must agree — a restart without a crash, or a crash the
/// supervisor never answered, is the interesting failure.
pub(crate) fn report_driver_host_ladder(drained: &[kcore::event::KernelEvent]) {
    // The reading itself is shared with every other port that runs a
    // supervisor (`kcore::event::summarize_driver_ladder`), and is host-tested
    // there against runs a boot cannot produce on purpose — a restart with no
    // crash behind it, a give-up filed at the wrong severity. What stays here
    // is the only part that is this boot's: how many crashes these two
    // supervised runs were driven to.
    let expected_crashes = u32::from(DRIVER_RESTART_BUDGET_SELFTEST_BUDGET) + 2;
    let s = kcore::event::summarize_driver_ladder(drained, kcore::trace::epoch());
    let pass = s.describes_a_contained_ladder(expected_crashes) && s.gave_up == 1;
    report(&verdict(
        DemoId::DriverHostLadder,
        pass,
        [
            u64::from(s.crashed),
            u64::from(s.restarted),
            u64::from(s.gave_up),
            s.reclaimed_frames,
            u64::from(expected_crashes),
            0,
            0,
            0,
        ],
    ));
    if !pass {
        kprintln!(
            "driver-ladder: FAIL crashed={} (expected {expected_crashes}) restarted={} gave_up={} frames={} component={} severities={} stamped={}",
            s.crashed,
            s.restarted,
            s.gave_up,
            s.reclaimed_frames,
            s.component_ok,
            s.severities_ok,
            s.stamped_ok,
        );
    }
}
