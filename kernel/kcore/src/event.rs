// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Structured observability events: the bounded in-kernel ring the mechanisms
//! emit into. `docs/observability/01` requires records — not plain strings —
//! carrying timestamp, component, severity, event name, schema version,
//! correlation id, and data classification; the record type is ISL-generated from
//! `api/isl/examples/kernel_event.isl` (`crate::isl_binding::event`), so the
//! schema is the wire-layout source of truth.
//!
//! Emission is **bounded and never silent**: a full ring drops at the source and
//! counts the drop, and the next emission that finds room prefixes an
//! `EVENTS_DROPPED` meta-event carrying the accumulated count — one per drop
//! episode, so a chatty component silences itself but "the silencing is visible"
//! (docs/observability/02, "Flood control"; docs/lifecycle/04, "No Silent
//! Fallback"). Emission never blocks and never overwrites an unread record.
//!
//! [`EventRing`] is pure and host-tested; the global sink is a thin `SpinLock`
//! wrapper plus free functions, the shape `console.rs` already uses. A log
//! service that harvests and merges rings is Stage 1 (docs/observability/02);
//! this milestone builds the emit half only (build/README.md, D57).
//!
//! Normative: docs/observability/01-debugging-monitoring-tracing-logging.md
//! ("Structured Logging"), docs/observability/02-collection-persistence-and-
//! telemetry.md ("Flood control")
//! Budget: B31 (disabled tracepoint) — not met: v0 has no compile-time gating,
//! every emission is a live call (build/README.md, D57)

/// The ISL-generated record vocabulary, re-exported so emitters and consumers
/// name the event types through this module rather than the private binding.
pub use crate::isl_binding::event::{Classification, Component, EventKind, KernelEvent, Severity};

use crate::sync::SpinLock;
use crate::trace::TraceContext;

/// Events the ring holds before it must drop (bounded like every kcore pool —
/// no general allocator, D15/D29).
///
/// Sized for a whole boot's emission without an intervening harvest, because
/// nothing harvests yet (the log service is Stage 1). Fan-out link events made
/// that concrete: the restart-supervision demos spawn dozens of threads, and at
/// 64 the ring filled with links and — since a full ring drops the *newest* —
/// silently discarded the fault reports that came after them (D59).
pub const EVENT_RING_CAPACITY: usize = 256;

/// The schema version stamped into every emitted record.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

/// A monotonic source of timestamps, installed by boot glue (the kernel core is
/// architecture-independent, so the cycle counter arrives as a hook).
pub type Clock = fn() -> u64;

/// Builds a record with the mandated envelope filled in: the caller supplies the
/// classifying fields, the causal identity, the per-`EventKind` payload, and the
/// timestamp.
///
/// `trace` is passed in rather than read from the ambient context so this stays a
/// pure function — the global is read once, by [`emit`].
pub fn record(
    kind: EventKind,
    severity: Severity,
    component: Component,
    timestamp: u64,
    trace: TraceContext,
    args: [u64; 4],
) -> KernelEvent {
    KernelEvent {
        size: KernelEvent::WIRE_SIZE as u32,
        version: EVENT_SCHEMA_VERSION,
        flags: 0,
        kind,
        severity,
        component,
        // Every v0 payload is scalar counters and identifiers (D57).
        classification: Classification::Public,
        timestamp,
        // Causal identity: who was running and what cause the work belongs to
        // (`crate::trace`, D59). The 128-bit id is the per-boot epoch in `_hi`
        // and the origin-minted sequence in `_lo`; all zero only before boot
        // installs the epoch.
        thread_id: trace.thread_id,
        process_id: trace.process_id,
        correlation_lo: trace.correlation,
        correlation_hi: crate::trace::epoch(),
        arg0: args[0],
        arg1: args[1],
        arg2: args[2],
        arg3: args[3],
    }
}

/// A bounded FIFO of structured events. Full-ring emission drops at the source
/// and counts it; a drained record is never overwritten in place.
pub struct EventRing {
    slots: [Option<KernelEvent>; EVENT_RING_CAPACITY],
    head: usize,
    len: usize,
    dropped: u64,
}

impl EventRing {
    /// An empty ring.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; EVENT_RING_CAPACITY],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    /// Records `event`, or drops it (counting the drop) when the ring is full.
    /// Returns whether it was recorded — emission never blocks.
    pub fn emit(&mut self, event: KernelEvent) -> bool {
        if self.len == EVENT_RING_CAPACITY {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        let index = (self.head + self.len) % EVENT_RING_CAPACITY;
        self.slots[index] = Some(event);
        self.len += 1;
        true
    }

    /// If drops accumulated and the ring now has room, records one
    /// `EVENTS_DROPPED` meta-event carrying the accumulated count and resets it —
    /// one meta-event per drop episode (the rate limit), so the silencing is
    /// visible without the notice itself flooding. Returns whether one was added.
    pub fn flush_dropped(&mut self, timestamp: u64, trace: TraceContext) -> bool {
        if self.dropped == 0 || self.len == EVENT_RING_CAPACITY {
            return false;
        }
        let lost = self.dropped;
        self.dropped = 0;
        self.emit(record(
            EventKind::EventsDropped,
            Severity::Warning,
            Component::Observability,
            timestamp,
            trace,
            [lost, 0, 0, 0],
        ))
    }

    /// Drains up to `out.len()` events in emission order, returning the count.
    pub fn drain(&mut self, out: &mut [KernelEvent]) -> usize {
        let mut n = 0;
        while n < out.len() && self.len > 0 {
            if let Some(event) = self.slots[self.head].take() {
                out[n] = event;
                n += 1;
            }
            self.head = (self.head + 1) % EVENT_RING_CAPACITY;
            self.len -= 1;
        }
        n
    }

    /// Events dropped since the last meta-event (0 once reported).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Events currently buffered.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no event is buffered.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for EventRing {
    fn default() -> Self {
        Self::new()
    }
}

// --- The global sink (the `console.rs` shape: a SpinLock plus free functions) ---

static RING: SpinLock<EventRing> = SpinLock::new(EventRing::new());
static CLOCK: SpinLock<Option<Clock>> = SpinLock::new(None);

/// Installs the timestamp source. Until then events carry timestamp 0.
pub fn set_clock(clock: Clock) {
    *CLOCK.lock() = Some(clock);
}

/// Reads the installed clock. The function pointer is copied out and the lock
/// released *before* the call, so the clock never runs under a lock and the ring
/// lock is never nested inside it.
fn now() -> u64 {
    let clock = *CLOCK.lock();
    clock.map_or(0, |clock| clock())
}

/// Emits one structured event into the global ring. Never blocks; a full ring
/// drops and counts (surfaced by the next `EVENTS_DROPPED` meta-event).
pub fn emit(kind: EventKind, severity: Severity, component: Component, args: [u64; 4]) -> bool {
    // Timestamp first: `now()` takes and releases the clock lock before the ring
    // lock is acquired, so the two are never held together. The ambient causal
    // identity is read here, the one place the global is consulted.
    let timestamp = now();
    let trace = crate::trace::current();
    let event = record(kind, severity, component, timestamp, trace, args);
    let mut ring = RING.lock();
    ring.flush_dropped(timestamp, trace);
    ring.emit(event)
}

/// Drains up to `out.len()` events from the global ring.
pub fn drain(out: &mut [KernelEvent]) -> usize {
    RING.lock().drain(out)
}

/// Events dropped from the global ring since the last meta-event.
pub fn dropped() -> u64 {
    RING.lock().dropped()
}

/// Events currently buffered in the global ring.
pub fn buffered() -> usize {
    RING.lock().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinctive identity, so a record's causal stamp is visible in tests.
    const TRACE: TraceContext = TraceContext {
        thread_id: 3,
        process_id: 5,
        correlation: 9,
    };

    fn event(seq: u64) -> KernelEvent {
        record(
            EventKind::PagerPageIn,
            Severity::Info,
            Component::Pager,
            seq,
            TRACE,
            [seq, 0, 0, 0],
        )
    }

    #[test]
    fn the_envelope_is_filled_in() {
        let e = event(7);
        assert_eq!(e.size, KernelEvent::WIRE_SIZE as u32);
        assert_eq!(e.version, EVENT_SCHEMA_VERSION);
        assert_eq!(e.flags, 0);
        assert_eq!(e.classification, Classification::Public);
        assert_eq!(e.timestamp, 7);
        assert_eq!(e.arg0, 7);
    }

    #[test]
    fn the_record_carries_the_causal_identity_it_was_given() {
        let e = event(7);
        assert_eq!(e.thread_id, TRACE.thread_id);
        assert_eq!(e.process_id, TRACE.process_id);
        assert_eq!(e.correlation_lo, TRACE.correlation);
        // The high half is the boot epoch, not per-record state.
        assert_eq!(e.correlation_hi, crate::trace::epoch());
    }

    #[test]
    fn emit_and_drain_are_fifo() {
        let mut ring = EventRing::new();
        assert!(ring.is_empty());
        for i in 0..3 {
            assert!(ring.emit(event(i)));
        }
        assert_eq!(ring.len(), 3);
        let mut out = [event(u64::MAX); 8];
        assert_eq!(ring.drain(&mut out), 3);
        assert_eq!(out[0].arg0, 0);
        assert_eq!(out[1].arg0, 1);
        assert_eq!(out[2].arg0, 2);
        assert!(ring.is_empty());
        // A drained ring yields nothing further.
        assert_eq!(ring.drain(&mut out), 0);
    }

    #[test]
    fn a_full_ring_drops_at_the_source_and_counts() {
        let mut ring = EventRing::new();
        for i in 0..EVENT_RING_CAPACITY as u64 {
            assert!(ring.emit(event(i)));
        }
        // Full: further emission is dropped, not blocked, and never overwrites.
        assert!(!ring.emit(event(999)));
        assert!(!ring.emit(event(1000)));
        assert_eq!(ring.dropped(), 2);
        assert_eq!(ring.len(), EVENT_RING_CAPACITY);
        // The oldest record is intact — drops discard the new, not the unread.
        let mut out = [event(u64::MAX); EVENT_RING_CAPACITY];
        assert_eq!(ring.drain(&mut out), EVENT_RING_CAPACITY);
        assert_eq!(out[0].arg0, 0);
    }

    #[test]
    fn the_drop_meta_event_reports_once_per_episode() {
        let mut ring = EventRing::new();
        for i in 0..EVENT_RING_CAPACITY as u64 {
            ring.emit(event(i));
        }
        for _ in 0..5 {
            ring.emit(event(0));
        }
        assert_eq!(ring.dropped(), 5);
        // No room yet — the notice cannot be recorded.
        assert!(!ring.flush_dropped(42, TRACE));
        // Make room; the next flush records exactly one notice carrying the count.
        let mut out = [event(u64::MAX); 4];
        assert_eq!(ring.drain(&mut out), 4);
        assert!(ring.flush_dropped(42, TRACE));
        assert_eq!(ring.dropped(), 0, "the count resets once reported");
        // A second flush with nothing lost adds nothing (the rate limit).
        assert!(!ring.flush_dropped(43, TRACE));

        // The notice is the last record, and says how many were lost.
        let mut rest = [event(u64::MAX); EVENT_RING_CAPACITY];
        let n = ring.drain(&mut rest);
        let notice = rest[n - 1];
        assert_eq!(notice.kind, EventKind::EventsDropped);
        assert_eq!(notice.severity, Severity::Warning);
        assert_eq!(notice.component, Component::Observability);
        assert_eq!(notice.arg0, 5);
        assert_eq!(notice.timestamp, 42);
    }

    #[test]
    fn the_ring_wraps_without_losing_order() {
        let mut ring = EventRing::new();
        for i in 0..EVENT_RING_CAPACITY as u64 {
            ring.emit(event(i));
        }
        let mut out = [event(u64::MAX); 8];
        assert_eq!(ring.drain(&mut out), 8);
        // Refill into the freed slots (the head has wrapped past 0).
        for i in 100..108u64 {
            assert!(ring.emit(event(i)));
        }
        let mut all = [event(u64::MAX); EVENT_RING_CAPACITY];
        let n = ring.drain(&mut all);
        assert_eq!(n, EVENT_RING_CAPACITY);
        // Oldest surviving first, newest last — order preserved across the wrap.
        assert_eq!(all[0].arg0, 8);
        assert_eq!(all[n - 1].arg0, 107);
    }
}
