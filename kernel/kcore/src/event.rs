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
use core::sync::atomic::Ordering;

/// Events the ring holds before it must drop (bounded like every kcore pool —
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::EVENT_RING_CAPACITY;

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

/// What a drained run of records says about the device capabilities the kernel
/// mediated — the driver framework's story as told by its own records rather
/// than by the counters a boot check keeps on the side
/// (docs/drivers/01: lifecycle transitions are observable through structured
/// events).
///
/// Pure and host-tested, so the ports that run the framework share one reading
/// of their events instead of each writing their own.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DeviceEventSummary {
    /// Register windows granted through a capability carrying MAP.
    pub mapped: u32,
    /// Windows revoked because the capability was handed to another process.
    pub revoked_on_transfer: u32,
    /// Windows revoked because the last handle naming the device was closed.
    pub revoked_on_close: u32,
    /// Mappings refused — the capability system saying no.
    pub refused: u32,
    /// DMA buffers granted against a device capability.
    pub dma_granted: u32,
    /// Device capabilities reclaimed from a dying process and delivered.
    pub reclaimed: u32,
    /// Device capabilities reclaim could not deliver — devices genuinely lost.
    pub reclaim_lost: u32,
    /// Transactions the IOMMU refused and reported.
    pub dma_faults: u32,
    /// Faults that a policy answered by ending the device's lease.
    pub dma_isolations: u32,
    /// Faults naming a stream the graph has no device for. Counted apart from
    /// [`Self::dma_faults`] because the two mean opposite things: an
    /// attributed fault is a device being held to its aperture, an
    /// unattributed one is the kernel's own stream wiring being wrong.
    pub dma_faults_unattributed: u32,
    /// Interrupt routes torn down because the capability behind them left.
    pub irq_revoked: u32,
    /// How many register-window grants each device object received, as
    /// `(object, count)` pairs over the first [`crate::devmgr::MAX_DEVICES`]
    /// devices named — read with [`Self::grants_of`].
    ///
    /// A device granted **more than once** is the rebind's signature in the
    /// record stream: one driver bound it, died, and another bound the same
    /// physical transport. It is kept per device rather than as a single
    /// "something was regranted" answer because a boot that runs several demos
    /// has several devices in its ring, and "some device was granted twice" is
    /// a question any of them could answer — including one that has nothing to
    /// do with the claim being checked.
    pub grants: [(u32, u32); crate::devmgr::MAX_DEVICES],
    /// Distinct device objects recorded in [`Self::grants`].
    pub devices: u32,
    /// Revocations whose unmap did not come down cleanly — the window table
    /// and the page tables disagreeing, which is supposed to be impossible.
    pub unmap_errors: u32,
    /// Revocations naming a `(device, VA)` window that was never granted, or
    /// that a previous revocation already took down.
    ///
    /// This is the clause that makes the revocation records *evidence* rather
    /// than narration. Counting revocations proves nothing on its own — a
    /// kernel that reported a revocation on every capability departure,
    /// including the ones it correctly declined to act on, would produce a
    /// perfectly plausible-looking count. Pairing each revocation against an
    /// outstanding grant is what catches that, and it is exactly the case
    /// `revoke_device_windows_unless_held`'s `holds` guard exists to prevent
    /// (D93: a process that duplicated its capability and gave one copy away
    /// keeps the window, and must not be reported as having lost it).
    pub unmatched_revokes: u32,
    /// Grants that could not be tracked because more windows were outstanding
    /// at once than this summary can hold. Non-zero makes `unmatched_revokes`
    /// unreliable, so it fails the reading rather than being ignored.
    pub grant_overflow: u32,
    /// Every driver record carried a live timestamp and a causal id from this
    /// boot's epoch. Thread identity is deliberately **not** part of this:
    /// kernel-originated work — reclaiming a dead process's devices — has no
    /// running thread to name, and the boot harness has always counted
    /// "stamped with a cause" and "identifies a thread" as separate questions
    /// (D59). A cause is mandatory; a thread is not always available.
    /// Derived from the counts below, which exist so a failure names the field
    /// rather than leaving a caller to guess.
    pub envelope_ok: bool,
    /// Records with no timestamp — no clock was installed when they were made.
    pub no_timestamp: u32,
    /// Records with no causal id: emitted from a context no origin had stamped.
    pub no_correlation: u32,
    /// Records whose correlation id came from a different boot epoch.
    pub wrong_epoch: u32,
    /// Records naming no thread — reported, not required. A syscall-path
    /// record always has one; a kernel-originated one legitimately does not.
    pub no_thread: u32,
    /// The `EventKind` of the first record that failed the envelope, so a
    /// failure points at the emission site instead of at the whole run.
    pub envelope_offender: u32,
    /// Driver records seen at all — `envelope_ok` on an empty run is vacuous.
    pub records: u32,
}

impl DeviceEventSummary {
    /// How many register-window grants `device` received.
    pub fn grants_of(&self, device: u32) -> u32 {
        self.grants[..self.devices as usize]
            .iter()
            .find(|(id, _)| *id == device)
            .map_or(0, |(_, count)| *count)
    }

    /// Whether these records, on their own, describe a driver framework that
    /// bound a device, revoked the grant when the capability moved on, and
    /// granted **this** device a second time — a rebind, read from the
    /// kernel's records rather than from a boot check's own bookkeeping.
    ///
    /// Shared by the ports that run the framework so "what counts as the
    /// framework working" has one definition, checked on the host rather than
    /// written twice in two boot glues.
    pub fn describes_a_rebind(&self, device: u32) -> bool {
        self.records > 0
            && self.envelope_ok
            // Grants outnumber transfer-revocations: the manager maps each
            // device to classify it and hands one on, and the run ends with a
            // driver still holding what it was given.
            && self.mapped > self.revoked_on_transfer
            && self.revoked_on_transfer > 0
            // The claim itself — about *this* device, not about whichever one
            // in the ring happens to have been granted twice.
            && self.grants_of(device) >= 2
            // Every revocation took down a window that had actually been
            // granted — without this the count could be inflated by reports of
            // revocations that never happened.
            && self.unmatched_revokes == 0
            && self.grant_overflow == 0
            // Nothing drifted between the window table and the page tables,
            // and no device was lost on the way back to the manager.
            && self.unmap_errors == 0
            && self.reclaim_lost == 0
    }

    /// Whether these records describe a DMA fault that was **harvested and
    /// acted on** — the second clause of `docs/drivers/01`'s "DMA faults are
    /// logged and can trigger driver isolation".
    ///
    /// Both halves are required, and neither is worth much alone. A fault
    /// record with no isolation is a system that watched a device misbehave
    /// and did nothing; an isolation with no fault behind it would be a lease
    /// torn down for a reason nothing recorded, which is the shape a bug in
    /// the harvest path produces.
    ///
    /// Unattributed faults fail the reading rather than being ignored. A fault
    /// the kernel cannot trace to a device is its own stream wiring being
    /// wrong, and a run containing one has not demonstrated that isolation
    /// picks the right driver — it has demonstrated that it could not tell.
    pub fn describes_a_fault_isolation(&self) -> bool {
        self.records > 0
            && self.envelope_ok
            && self.dma_faults > 0
            && self.dma_isolations > 0
            && self.dma_faults_unattributed == 0
    }
}

/// Reads a drained run of records as a device-capability story. `epoch` is the
/// boot epoch every record's `correlation_hi` must carry.
pub fn summarize_device_events(drained: &[KernelEvent], epoch: u64) -> DeviceEventSummary {
    // Which device objects were granted a window, and how often. Bounded by
    // the resource graph's node count — a run naming more devices than the
    // graph can hold is not something this summary needs to represent.
    let mut objects = [(0u32, 0u32); crate::devmgr::MAX_DEVICES];
    let mut tracked = 0usize;

    // Windows currently outstanding, as `(device, VA)`. A revocation must find
    // one here or it is describing something that never happened. Sized for
    // every device holding its full complement of windows at once.
    let mut outstanding =
        [(0u32, 0u64); crate::devmgr::MAX_DEVICES * crate::process::MAX_DEVICE_WINDOWS];
    let mut live = 0usize;

    let mut s = DeviceEventSummary::default();
    for e in drained {
        if e.component != Component::Driver {
            continue;
        }
        s.records += 1;
        if (e.timestamp == 0 || e.correlation_lo == 0 || e.correlation_hi != epoch)
            && s.envelope_offender == 0
        {
            s.envelope_offender = e.kind as u32;
        }
        if e.timestamp == 0 {
            s.no_timestamp += 1;
        }
        if e.correlation_lo == 0 {
            s.no_correlation += 1;
        }
        if e.correlation_hi != epoch {
            s.wrong_epoch += 1;
        }
        if e.thread_id == 0 {
            s.no_thread += 1;
        }
        match e.kind {
            EventKind::DeviceWindowMapped => {
                s.mapped += 1;
                let object = e.arg0 as u32;
                match objects[..tracked].iter_mut().find(|(id, _)| *id == object) {
                    Some((_, count)) => *count += 1,
                    None => {
                        if tracked < objects.len() {
                            objects[tracked] = (object, 1);
                            tracked += 1;
                        }
                    }
                }
                if live < outstanding.len() {
                    outstanding[live] = (object, e.arg1);
                    live += 1;
                } else {
                    s.grant_overflow += 1;
                }
            }
            EventKind::DeviceWindowRevoked => {
                if e.arg2 == crate::process::WindowRevokeReason::Transferred as u64 {
                    s.revoked_on_transfer += 1;
                } else {
                    s.revoked_on_close += 1;
                }
                if e.arg3 != 0 {
                    s.unmap_errors += 1;
                }
                // Take down the window this claims to have taken down. A
                // revocation with nothing to match is a report of something
                // that did not happen.
                let window = (e.arg0 as u32, e.arg1);
                match outstanding[..live].iter().position(|w| *w == window) {
                    Some(at) => {
                        outstanding.swap(at, live - 1);
                        live -= 1;
                    }
                    None => s.unmatched_revokes += 1,
                }
            }
            EventKind::DeviceMapRefused => s.refused += 1,
            EventKind::DeviceDmaGranted => s.dma_granted += 1,
            EventKind::DeviceReclaimed => s.reclaimed += 1,
            EventKind::DeviceReclaimLost => s.reclaim_lost += 1,
            EventKind::DeviceDmaFault => {
                s.dma_faults += 1;
                if e.arg0 == 0 {
                    s.dma_faults_unattributed += 1;
                }
            }
            EventKind::DeviceDmaIsolated => s.dma_isolations += 1,
            EventKind::DeviceIrqRevoked => s.irq_revoked += 1,
            _ => {}
        }
    }
    s.grants = objects;
    s.devices = tracked as u32;
    s.envelope_ok = s.no_timestamp == 0 && s.no_correlation == 0 && s.wrong_epoch == 0;
    s
}

/// What a drained run of records says about the crash-recovery ladder
/// (`docs/drivers/01`, "Crash Recovery").
///
/// The supervised runs assert their own outcome from state they control; this
/// asserts the **records**, which is the thing a log service would have to
/// work from. The two are not the same claim, and a ladder that worked while
/// recording nothing useful would pass the first and fail this.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DriverLadderSummary {
    /// Hosts that faulted and were contained.
    pub crashed: u32,
    /// Corpses reclaimed and rebound.
    pub restarted: u32,
    /// Supervisors that spent their budget and stopped.
    pub gave_up: u32,
    /// Frames recovered across every restart. Zero over a run with restarts
    /// means reclaim recovered nothing, which is a leak per launch.
    pub reclaimed_frames: u64,
    /// Every ladder record came from the driver component.
    pub component_ok: bool,
    /// Severity carried the escalation: error, notice, critical. A log service
    /// filtering on severity must be able to tell a restart from a give-up
    /// without decoding the payload.
    pub severities_ok: bool,
    /// Every ladder record carried a causal id from this boot's epoch — what
    /// joins a restart to the crash that provoked it, and most of what these
    /// records are for (docs/observability/02).
    pub stamped_ok: bool,
    /// Step 2: devices a manager marked degraded.
    pub degraded_marks: u32,
    /// Step 3: crash dumps taken.
    pub crash_dumps: u32,
    /// Trace records those dumps captured. Zero across a run with dumps means
    /// every dump was empty, which is a dump mechanism that runs and collects
    /// nothing — indistinguishable from no crash at all if the dump is the
    /// only evidence.
    pub crash_dump_records: u64,
    /// Step 4: notifications sent to dependent services.
    pub dependents_notified: u64,
    /// Notifications that could not be delivered. A dependent that never
    /// learns its device is gone waits on it for ever.
    pub dependents_unreachable: u64,
    /// Step 5: resets attempted.
    pub resets: u32,
    /// Resets the hardware refused.
    pub resets_failed: u32,
    /// Devices policy stopped offering.
    pub quarantined: u32,
    /// Lifecycle transitions recorded at all.
    pub transitions: u32,
    /// Transitions whose recorded `from` was not the state the previous
    /// transition left the device in. Zero is the claim that the record stream
    /// is a *sequence* — that the states join up end to end rather than merely
    /// each being plausible on its own.
    pub transition_gaps: u32,
}

impl DriverLadderSummary {
    /// Whether these records describe a ladder that contained every crash and
    /// answered each one exactly once.
    ///
    /// **Crashes and restarts must agree.** A restart with no crash behind it,
    /// or a crash the supervisor never answered, is the interesting failure —
    /// and counting only one of the two would miss both.
    pub fn describes_a_contained_ladder(&self, expected_crashes: u32) -> bool {
        self.crashed == expected_crashes
            && self.restarted == self.crashed
            && self.reclaimed_frames > 0
            && self.component_ok
            && self.severities_ok
            && self.stamped_ok
    }

    /// Whether these records describe the **whole** seven-step ladder
    /// `docs/drivers/01` writes down, rather than the three steps a supervisor
    /// can perform on its own.
    ///
    /// Steps 1, 6 and 7 are the supervisor's and are covered by
    /// [`Self::describes_a_contained_ladder`]. The four checked here are the
    /// ones that need somebody else: a manager to mark the device degraded, a
    /// dump to be taken, dependents to be told, and a reset to be attempted.
    /// A system that recorded only the supervisor's three would be running
    /// half a ladder and describing a whole one.
    ///
    /// `transition_gaps` is the clause that makes the lifecycle records
    /// evidence rather than narration, for exactly the reason
    /// `DeviceEventSummary::unmatched_revokes` exists: counting transitions
    /// proves nothing on its own, because a manager emitting plausible states
    /// in an impossible order would produce a perfectly healthy-looking count.
    pub fn describes_the_full_ladder(&self) -> bool {
        self.degraded_marks > 0
            && self.crash_dumps > 0
            && self.crash_dump_records > 0
            && self.dependents_notified > 0
            && self.dependents_unreachable == 0
            && self.resets > 0
            && self.resets_failed == 0
            && self.transitions > 0
            && self.transition_gaps == 0
    }
}

/// Reads a drained run of records as a crash-recovery ladder. `epoch` is the
/// boot epoch every record's `correlation_hi` must carry.
pub fn summarize_driver_ladder(drained: &[KernelEvent], epoch: u64) -> DriverLadderSummary {
    let mut s = DriverLadderSummary {
        component_ok: true,
        severities_ok: true,
        stamped_ok: true,
        ..DriverLadderSummary::default()
    };
    // The state each device's last recorded transition left it in, so the
    // next one's `from` can be checked against it. Bounded by the graph, like
    // every other per-device reading here.
    let mut last_state = [(0u32, 0u32); crate::devmgr::MAX_DEVICES];
    let mut devices = 0usize;
    for e in drained {
        let expected = match e.kind {
            EventKind::DriverHostCrashed => {
                s.crashed += 1;
                Severity::Error
            }
            EventKind::DriverHostRestarted => {
                s.restarted += 1;
                s.reclaimed_frames += e.arg2;
                Severity::Notice
            }
            EventKind::DriverHostGaveUp => {
                s.gave_up += 1;
                Severity::Critical
            }
            EventKind::DriverCrashDump => {
                s.crash_dumps += 1;
                s.crash_dump_records += e.arg2;
                Severity::Error
            }
            EventKind::DeviceDependentsNotified => {
                s.dependents_notified += e.arg1;
                s.dependents_unreachable += e.arg2;
                if e.arg2 > 0 {
                    Severity::Error
                } else {
                    Severity::Notice
                }
            }
            EventKind::DeviceReset => {
                s.resets += 1;
                if e.arg1 == 0 {
                    Severity::Warning
                } else {
                    s.resets_failed += 1;
                    Severity::Error
                }
            }
            EventKind::DeviceQuarantined => {
                s.quarantined += 1;
                Severity::Critical
            }
            EventKind::DriverLifecycleTransition => {
                s.transitions += 1;
                let to = e.arg2 as u32;
                if to == crate::lifecycle::DriverState::Degraded as u32 {
                    s.degraded_marks += 1;
                }
                // The sequence check. Each device's recorded `from` must be
                // where the last transition for that device left it; the first
                // transition for a device has nothing to compare against and
                // is taken as given, which is the same latitude the kernel's
                // own table allows and for the same reason.
                let device = e.arg0 as u32;
                match last_state[..devices].iter_mut().find(|(d, _)| *d == device) {
                    Some((_, previous)) => {
                        if *previous != e.arg1 as u32 {
                            s.transition_gaps += 1;
                        }
                        *previous = to;
                    }
                    None => {
                        if devices < last_state.len() {
                            last_state[devices] = (device, to);
                            devices += 1;
                        } else {
                            // More devices than the summary can follow: the
                            // gap check would be unreliable, so it fails
                            // rather than quietly covering fewer devices.
                            s.transition_gaps += 1;
                        }
                    }
                }
                match to {
                    t if t == crate::lifecycle::DriverState::Failed as u32 => Severity::Critical,
                    t if t == crate::lifecycle::DriverState::Degraded as u32 => Severity::Error,
                    t if t == crate::lifecycle::DriverState::Removed as u32
                        || t == crate::lifecycle::DriverState::Resetting as u32 =>
                    {
                        Severity::Warning
                    }
                    _ => Severity::Notice,
                }
            }
            _ => continue,
        };
        if e.component != Component::Driver {
            s.component_ok = false;
        }
        if e.severity != expected {
            s.severities_ok = false;
        }
        if e.correlation_lo == 0 || e.correlation_hi != epoch {
            s.stamped_ok = false;
        }
    }
    s
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

    /// Copies up to `out.len()` of the **most recent** events, newest last,
    /// without consuming them.
    ///
    /// The crash-dump reader (`crate::supervise`). A dump wants the trail
    /// leading up to a fault, and draining to get it would take those records
    /// away from the one consumer that exists — the boot check that reads the
    /// whole run afterwards. So this copies, and the ring is still drained
    /// exactly once per boot.
    ///
    /// The *tail* rather than the head, because a crash dump is about what
    /// happened just before the crash. A ring holding a whole boot's emission
    /// would otherwise hand back the earliest records, which are the least
    /// likely to be about the thing that died.
    pub fn tail(&self, out: &mut [KernelEvent]) -> usize {
        let want = out.len().min(self.len);
        let skip = self.len - want;
        for (n, slot) in out.iter_mut().take(want).enumerate() {
            let index = (self.head + skip + n) % EVENT_RING_CAPACITY;
            match self.slots[index] {
                Some(event) => *slot = event,
                // A hole inside the occupied span cannot happen — `drain` is
                // the only thing that empties a slot and it advances the head
                // past it — so reaching here means the ring's bookkeeping has
                // drifted. Stopping is the honest answer: the caller gets the
                // records that were definitely there and a count that says so.
                None => return n,
            }
        }
        want
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

/// Records stamped before a clock was installed, so the gap is countable rather
/// than indistinguishable from a boot that began at zero.
static UNSTAMPED: crate::atomic::AtomicU64 = crate::atomic::AtomicU64::new(0);

/// Installs the timestamp source, returning how many records were emitted
/// before it — every one of them stamped 0.
///
/// The count is returned rather than dropped because `docs/observability/01`
/// makes a timestamp mandatory on every record, so an unstamped one is a
/// degradation, and `docs/lifecycle/04` ("No Silent Fallback") says a
/// degradation has to be visible. `console::init_global` reports its dropped
/// writes for the same reason and in the same shape.
///
/// `must_use` on purpose: a port that installs a clock and ignores what it is
/// told is a port whose early records are silently zero — which is exactly the
/// state ARM 32 was in, undetected, because nothing made the answer awkward to
/// discard.
#[must_use]
pub fn set_clock(clock: Clock) -> u64 {
    *CLOCK.lock() = Some(clock);
    UNSTAMPED.swap(0, Ordering::Relaxed)
}

/// Reads the installed clock **without blocking**, or `None` when there is none
/// — or when the clock lock is momentarily held, which on one core means this
/// call interrupted the read and blocking would never return.
///
/// The function pointer is copied out and the lock released *before* the call,
/// so the clock never runs under a lock and no other lock is ever nested inside
/// it. `console` renders its timestamp from this on the panic path, where a
/// console that deadlocks instead of reporting is worse than one with no times.
pub fn timestamp_now() -> Option<u64> {
    let clock = *CLOCK.try_lock()?;
    clock.map(|clock| clock())
}

/// [`timestamp_now`] for the ring, counting an unstamped record rather than
/// letting a zero pass for a time.
fn now() -> u64 {
    match timestamp_now() {
        Some(ticks) => ticks,
        None => {
            UNSTAMPED.fetch_add(1, Ordering::Relaxed);
            0
        }
    }
}

/// Emits one structured event into the global ring. Never blocks; a full ring
/// drops and counts (surfaced by the next `EVENTS_DROPPED` meta-event).
pub fn emit(kind: EventKind, severity: Severity, component: Component, args: [u64; 4]) -> bool {
    emit_with_flags(kind, severity, component, 0, args)
}

/// [`emit`], with the envelope's `flags` word carrying a per-kind payload.
///
/// A fifth slot, in effect, and deliberately a narrow one. Four `arg` words is
/// what the record schema gives, and every event so far has fitted; a
/// lifecycle transition does not, because the transition itself spends all
/// four and a manager's `detail` — a probe's exit code, a crash's fault
/// address — has nowhere else to go. Putting it in `flags` rather than growing
/// the record keeps the wire layout an ABI nobody has to re-agree on, at the
/// cost of a field whose meaning is per-kind. That cost is documented where it
/// is paid, in `kernel_event.isl`, and not everywhere else.
pub fn emit_with_flags(
    kind: EventKind,
    severity: Severity,
    component: Component,
    flags: u64,
    args: [u64; 4],
) -> bool {
    // Timestamp first: `now()` takes and releases the clock lock before the ring
    // lock is acquired, so the two are never held together. The ambient causal
    // identity is read here, the one place the global is consulted.
    let timestamp = now();
    let trace = crate::trace::current();
    let mut event = record(kind, severity, component, timestamp, trace, args);
    event.flags = flags;
    let mut ring = RING.lock();
    ring.flush_dropped(timestamp, trace);
    ring.emit(event)
}

/// Drains up to `out.len()` events from the global ring.
pub fn drain(out: &mut [KernelEvent]) -> usize {
    RING.lock().drain(out)
}

/// Copies the most recent events from the global ring without consuming them.
pub fn tail(out: &mut [KernelEvent]) -> usize {
    RING.lock().tail(out)
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
#[path = "tests/event.rs"]
mod tests;
