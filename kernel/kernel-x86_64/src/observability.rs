// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Structured events, drained and checked against their schema.
//!
//! Proves each record is wire-valid, and that a flood drops at the source and says
//! so — a bound that is invisible unless the silencing reports itself.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

/// Structured observability events (docs/observability/01, "Structured Logging";
/// build/README.md D57). Drains the ring the kernel mechanisms emitted into
/// during the preceding demos — page-in latencies, pager deadline misses and
/// supervision escalations, object-faulted data-integrity records, reclaim
/// overflows — proves every record is wire-valid against its ISL schema, and
/// shows the bound: a flood drops at the source, counts, and reports itself with
/// an `EVENTS_DROPPED` meta-event so the silencing is visible.
pub(crate) fn observability_demo() {
    use kcore::event::{self, Component, EventKind, KernelEvent, Severity};
    const CAP: usize = event::EVENT_RING_CAPACITY;
    const WIRE: usize = KernelEvent::WIRE_SIZE;

    // A blank record to initialize the drain buffer (overwritten by `drain`).
    let blank = event::record(
        EventKind::EventsDropped,
        Severity::Debug,
        Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );

    // 1. What the mechanisms emitted while the earlier demos ran.
    let mut drained = [blank; CAP];
    let n = event::drain(&mut drained);
    let (mut page_ins, mut misses, mut escalations, mut faulted) = (0u32, 0u32, 0u32, 0u32);
    for e in &drained[..n] {
        match e.kind {
            EventKind::PagerPageIn => page_ins += 1,
            EventKind::PagerDeadlineMiss => misses += 1,
            EventKind::PagerSupervisionEscalate => escalations += 1,
            EventKind::PagerObjectFaulted => faulted += 1,
            _ => {}
        }
    }

    // 2. Every emitted record is wire-valid against the generated ISL binding:
    //    encode to the golden size, decode back, compare.
    let mut wire_ok = n > 0;
    for e in &drained[..n] {
        let mut bytes = [0u8; WIRE];
        let encoded = tessera_isl_runtime::encode(e, &mut bytes).unwrap_or(0);
        let decoded: Option<KernelEvent> = tessera_isl_runtime::decode(&bytes).ok();
        if encoded != WIRE || decoded != Some(*e) {
            wire_ok = false;
        }
    }
    // The envelope every record carries (docs/observability/01's field set).
    let envelope_ok = drained[..n]
        .iter()
        .all(|e| e.size == WIRE as u32 && e.version == event::EVENT_SCHEMA_VERSION);

    // 3. The bound: overflow the ring, then confirm the drops were counted and
    //    the next emission with room reports them once as a meta-event.
    for _ in 0..(CAP as u32 + 8) {
        event::emit(
            EventKind::PagerPageIn,
            Severity::Debug,
            Component::Pager,
            [0; 4],
        );
    }
    let dropped = event::dropped();
    // Drain to make room, then one more emission carries the drop notice.
    let mut flood = [blank; CAP];
    let flooded = event::drain(&mut flood);
    event::emit(
        EventKind::PagerPageIn,
        Severity::Debug,
        Component::Pager,
        [0; 4],
    );
    let mut tail = [blank; CAP];
    let tail_n = event::drain(&mut tail);
    let notice = tail[..tail_n]
        .iter()
        .find(|e| e.kind == EventKind::EventsDropped);
    let bound_ok = dropped == 8
        && flooded == CAP
        && notice.is_some_and(|e| e.arg0 == 8 && e.severity == Severity::Warning)
        && event::dropped() == 0;

    let pass = n > 0
        && page_ins > 0
        && misses == 6
        && escalations == 2
        && faulted > 0
        && wire_ok
        && envelope_ok
        && bound_ok;
    report(&verdict(
        DemoId::ObservabilityEvents,
        pass,
        [
            n as u64,
            u64::from(page_ins),
            u64::from(misses),
            u64::from(escalations),
            u64::from(faulted),
            WIRE as u64,
            CAP as u64,
            dropped,
        ],
    ));
    if !pass {
        kprintln!(
            "events: FAIL n={n} page_ins={page_ins} misses={misses} esc={escalations} faulted={faulted}"
        );
        kprintln!(
            "events: FAIL wire={wire_ok} env={envelope_ok} bound={bound_ok} dropped={dropped}"
        );
    }
}

/// Empties the event ring, and says how much was in it.
///
/// **The checks that produce hundreds of records call this**, and the reason is
/// the same for each: five processes and a device's worth of I/O leave several
/// hundred where the checks around them leave tens, and a boot-context
/// declaration leaves records with no cause at all — which is a ladder record
/// that fails a stamp check made three checks later. The
/// ring holds [`EVENT_RING_CAPACITY`](kcore::event::EVENT_RING_CAPACITY) and
/// **drops the newest when it is full**, so a run that left its records there
/// did not merely waste space: it silently discarded the crash, fault and link
/// records of the checks that come after, which then failed reporting zero of
/// everything, several steps from the cause and with nothing pointing here.
///
/// Draining here is what the other port's checks already do for their own
/// assertions — "drained before the assertions so a full ring cannot swallow
/// them". Raising the capacity is the fix this is *not*: three drain sites
/// hold an array of `EVENT_RING_CAPACITY` records on a kernel stack, so a ring
/// sized for this boot's emission would overflow them (D324's shape again).
/// And what makes draining safe rather than destructive is the order — the
/// link records `correlation_demo` needs are minted by `loader_demo`, which
/// now runs *after* this (build/README.md, D325).
pub(crate) fn drain_ring() -> u64 {
    let blank = kcore::event::record(
        kcore::event::EventKind::EventsDropped,
        kcore::event::Severity::Debug,
        kcore::event::Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );
    let mut sink = [blank; kcore::event::EVENT_RING_CAPACITY];
    kcore::event::drain(&mut sink) as u64
}
