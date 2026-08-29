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
