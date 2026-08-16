// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::event`.

use super::*;
use crate::lifecycle::DriverState;
use crate::process::WindowRevokeReason;

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

/// A driver record with a live envelope, for the summary tests.
fn driver_event(kind: EventKind, args: [u64; 4]) -> KernelEvent {
    let mut e = record(
        kind,
        Severity::Info,
        Component::Driver,
        7,
        TraceContext {
            thread_id: 2,
            process_id: 3,
            correlation: 11,
        },
        args,
    );
    e.correlation_hi = 99;
    e
}

#[test]
fn the_summary_reads_a_bind_revoke_rebind_run() {
    // A manager probes two devices, hands one to a driver (its window is
    // revoked by the transfer), the driver maps it, dies, and a second
    // driver is granted the *same* device.
    let events = [
        driver_event(
            EventKind::DeviceWindowMapped,
            [21, 0x4000_0000, 0xa00_3000, 0x1000],
        ),
        driver_event(
            EventKind::DeviceWindowMapped,
            [22, 0x4000_1000, 0xa00_4000, 0x1000],
        ),
        driver_event(
            EventKind::DeviceWindowRevoked,
            [21, 0x4000_0000, WindowRevokeReason::Transferred as u64, 0],
        ),
        driver_event(
            EventKind::DeviceWindowMapped,
            [21, 0x1000_0000, 0xa00_3000, 0x1000],
        ),
        driver_event(
            EventKind::DeviceDmaGranted,
            [21, 0x1001_0000, 0x4711_0000, 0x1000],
        ),
        driver_event(EventKind::DeviceReclaimed, [21, 0x85, 0, 0]),
        driver_event(
            EventKind::DeviceWindowMapped,
            [21, 0x1000_0000, 0xa00_3000, 0x1000],
        ),
    ];
    let s = summarize_device_events(&events, 99);
    assert_eq!(s.mapped, 4);
    assert_eq!(s.revoked_on_transfer, 1);
    assert_eq!(s.revoked_on_close, 0);
    assert_eq!(s.dma_granted, 1);
    assert_eq!(s.reclaimed, 1);
    assert_eq!(s.records, 7);
    assert!(s.envelope_ok);
    // Device 21 was granted three times; 22 only once. The rebind is a
    // question about 21, and 22 must not answer it.
    assert_eq!(s.grants_of(21), 3);
    assert_eq!(s.grants_of(22), 1);
    assert_eq!(s.grants_of(99), 0, "a device with no grants at all");
    assert!(s.describes_a_rebind(21));
    assert!(!s.describes_a_rebind(22));
}

/// The rebind reading is a conjunction, and each clause has to be able to
/// fail on its own — otherwise the boot check that uses it would pass on
/// runs it should reject.
#[test]
fn the_rebind_reading_rejects_each_way_it_can_be_wrong() {
    let good = DeviceEventSummary {
        records: 7,
        envelope_ok: true,
        mapped: 4,
        revoked_on_transfer: 1,
        grants: [
            (21, 2),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ],
        devices: 1,
        ..DeviceEventSummary::default()
    };
    assert!(good.describes_a_rebind(21));

    // A device that was never granted at all cannot have been rebound,
    // however healthy the rest of the run looks.
    assert!(!good.describes_a_rebind(22));
    // No records at all: nothing was emitted, and every other clause is
    // vacuously satisfiable.
    assert!(!DeviceEventSummary { records: 0, ..good }.describes_a_rebind(21));
    // Records with no cause are records a log service cannot use.
    assert!(
        !DeviceEventSummary {
            envelope_ok: false,
            ..good
        }
        .describes_a_rebind(21)
    );
    // Nothing was ever handed on, so nothing was bound by a manager.
    assert!(
        !DeviceEventSummary {
            revoked_on_transfer: 0,
            ..good
        }
        .describes_a_rebind(21)
    );
    // Every grant was revoked: the run ends with no driver holding anything.
    assert!(
        !DeviceEventSummary {
            revoked_on_transfer: 4,
            ..good
        }
        .describes_a_rebind(21)
    );
    // The window table and the page tables disagreed.
    assert!(
        !DeviceEventSummary {
            unmap_errors: 1,
            ..good
        }
        .describes_a_rebind(21)
    );
    // A device was reclaimed but never delivered — genuinely lost.
    assert!(
        !DeviceEventSummary {
            reclaim_lost: 1,
            ..good
        }
        .describes_a_rebind(21)
    );
}

#[test]
fn a_device_granted_once_is_not_a_rebind() {
    let events = [
        driver_event(EventKind::DeviceWindowMapped, [21, 0x4000_0000, 0, 0x1000]),
        driver_event(EventKind::DeviceWindowMapped, [22, 0x4000_1000, 0, 0x1000]),
    ];
    let s = summarize_device_events(&events, 99);
    assert_eq!(s.grants_of(21), 1);
    assert!(!s.describes_a_rebind(21));
}

/// A revocation that names no outstanding window is a report of something
/// that did not happen — the shape a kernel would produce if it emitted on
/// every capability departure instead of only the ones it acted on.
///
/// This test exists because a boot-level negative check found the reading
/// blind to it: injecting exactly that bug into
/// `revoke_device_windows_unless_held` left the boot passing, because
/// counting revocations cannot tell a real one from an invented one.
#[test]
fn a_revocation_of_a_window_that_was_never_granted_is_caught() {
    let events = [
        driver_event(EventKind::DeviceWindowMapped, [21, 0x4000_0000, 0, 0x1000]),
        // The window that was granted comes down: matched.
        driver_event(
            EventKind::DeviceWindowRevoked,
            [21, 0x4000_0000, WindowRevokeReason::Transferred as u64, 0],
        ),
        // A second revocation of the same window, and one of a window that
        // was never granted at all.
        driver_event(
            EventKind::DeviceWindowRevoked,
            [21, 0x4000_0000, WindowRevokeReason::Transferred as u64, 0],
        ),
        driver_event(
            EventKind::DeviceWindowRevoked,
            [21, 0, WindowRevokeReason::Transferred as u64, 0],
        ),
    ];
    let s = summarize_device_events(&events, 99);
    assert_eq!(s.revoked_on_transfer, 3, "all three are still counted");
    assert_eq!(s.unmatched_revokes, 2, "only one had a window to take down");
    assert!(!s.describes_a_rebind(21));
}

/// The same records without the invented revocations pass, so the test
/// above fails for the reason it claims to.
#[test]
fn a_revocation_matching_its_grant_is_not_flagged() {
    let events = [
        driver_event(EventKind::DeviceWindowMapped, [21, 0x4000_0000, 0, 0x1000]),
        driver_event(EventKind::DeviceWindowMapped, [21, 0x5000_0000, 0, 0x1000]),
        driver_event(
            EventKind::DeviceWindowRevoked,
            [21, 0x4000_0000, WindowRevokeReason::Transferred as u64, 0],
        ),
    ];
    let s = summarize_device_events(&events, 99);
    assert_eq!(s.unmatched_revokes, 0);
    assert!(s.describes_a_rebind(21));
}

/// A fault that was recorded and answered — the reading a boot check uses
/// to say the second clause of "logged and can trigger driver isolation"
/// is true of this system rather than only of its documentation.
#[test]
fn the_summary_reads_a_fault_that_was_harvested_and_acted_on() {
    let events = [
        driver_event(EventKind::DeviceDmaFault, [21, 0x20_0000, 1, 0x10]),
        driver_event(EventKind::DeviceDmaIsolated, [21, 0x51, 2, 1]),
        driver_event(
            EventKind::DeviceDmaLeaseEnded,
            [
                21,
                0x51,
                crate::devmgr::LeaseEndReason::FaultIsolated as u64,
                0,
            ],
        ),
    ];
    let s = summarize_device_events(&events, 99);
    assert_eq!(s.dma_faults, 1);
    assert_eq!(s.dma_isolations, 1);
    assert_eq!(s.dma_faults_unattributed, 0);
    assert!(s.describes_a_fault_isolation());
}

/// Each clause of the fault reading has to be able to fail on its own,
/// or a boot check would pass on runs it should reject.
#[test]
fn the_fault_reading_rejects_each_way_it_can_be_wrong() {
    let good = DeviceEventSummary {
        records: 3,
        envelope_ok: true,
        dma_faults: 1,
        dma_isolations: 1,
        ..DeviceEventSummary::default()
    };
    assert!(good.describes_a_fault_isolation());

    // Nothing was emitted at all; every other clause is vacuous.
    assert!(!DeviceEventSummary { records: 0, ..good }.describes_a_fault_isolation());
    // Records a log service could not attribute to a cause.
    assert!(
        !DeviceEventSummary {
            envelope_ok: false,
            ..good
        }
        .describes_a_fault_isolation()
    );
    // A lease was torn down with no fault recorded behind it — the shape a
    // bug in the harvest path produces, and not evidence of anything.
    assert!(
        !DeviceEventSummary {
            dma_faults: 0,
            ..good
        }
        .describes_a_fault_isolation()
    );
    // The system watched a device misbehave and did nothing.
    assert!(
        !DeviceEventSummary {
            dma_isolations: 0,
            ..good
        }
        .describes_a_fault_isolation()
    );
    // A fault the kernel could not trace to a device means it could not
    // tell which driver to isolate, so this run has not shown that
    // isolation picks the right one.
    assert!(
        !DeviceEventSummary {
            dma_faults_unattributed: 1,
            ..good
        }
        .describes_a_fault_isolation()
    );
}

/// A fault naming a stream no device backs is the kernel's own wiring
/// being wrong. It is still counted as a fault — it happened — and
/// separately as unattributed, because conflating the two would let a
/// misconfigured stream table read as an aperture doing its job.
#[test]
fn a_fault_naming_no_device_is_counted_apart() {
    let events = [
        driver_event(EventKind::DeviceDmaFault, [0, 0x20_0000, 3, 0x1f]),
        driver_event(EventKind::DeviceDmaFault, [21, 0x20_0000, 1, 0x10]),
    ];
    let s = summarize_device_events(&events, 99);
    assert_eq!(s.dma_faults, 2);
    assert_eq!(s.dma_faults_unattributed, 1);
}

/// Interrupt revocations are counted, so a boot check can say a route was
/// taken down rather than infer it from the absence of interrupts — which
/// a device that simply stopped firing would produce just as readily.
#[test]
fn the_summary_counts_interrupt_revocations() {
    let events = [
        driver_event(
            EventKind::DeviceIrqRevoked,
            [
                21,
                79,
                crate::devmgr::RouteEndReason::Transferred as u64,
                0x51,
            ],
        ),
        driver_event(
            EventKind::DeviceIrqRevoked,
            [
                22,
                80,
                crate::devmgr::RouteEndReason::HolderGone as u64,
                0x52,
            ],
        ),
    ];
    assert_eq!(summarize_device_events(&events, 99).irq_revoked, 2);
}

/// A ladder record with a live envelope, for the ladder-summary tests.
fn ladder_event(kind: EventKind, severity: Severity, args: [u64; 4]) -> KernelEvent {
    let mut e = record(
        kind,
        severity,
        Component::Driver,
        7,
        TraceContext {
            thread_id: 2,
            process_id: 3,
            correlation: 11,
        },
        args,
    );
    e.correlation_hi = 99;
    e
}

/// Two crashes, each answered by exactly one reclaim-and-rebind, and a
/// third launch that came up clean.
#[test]
fn the_ladder_summary_reads_a_contained_run() {
    let events = [
        ladder_event(
            EventKind::DriverHostCrashed,
            Severity::Error,
            [0x0e, 0, 1, 0],
        ),
        ladder_event(
            EventKind::DriverHostRestarted,
            Severity::Notice,
            [1, 7, 12, 0],
        ),
        ladder_event(
            EventKind::DriverHostCrashed,
            Severity::Error,
            [0x0e, 0, 2, 0],
        ),
        ladder_event(
            EventKind::DriverHostRestarted,
            Severity::Notice,
            [2, 6, 12, 0],
        ),
    ];
    let s = summarize_driver_ladder(&events, 99);
    assert_eq!(s.crashed, 2);
    assert_eq!(s.restarted, 2);
    assert_eq!(s.gave_up, 0);
    assert_eq!(s.reclaimed_frames, 24);
    assert!(s.describes_a_contained_ladder(2));
    // And it is a claim about *how many*, so a run with a different crash
    // count than the supervisor was driven to does not pass.
    assert!(!s.describes_a_contained_ladder(3));
}

/// Each clause has to be able to fail on its own, or a boot check reading
/// the ladder would pass on runs it should reject.
#[test]
fn the_ladder_reading_rejects_each_way_it_can_be_wrong() {
    let good = DriverLadderSummary {
        crashed: 2,
        restarted: 2,
        reclaimed_frames: 24,
        component_ok: true,
        severities_ok: true,
        stamped_ok: true,
        ..DriverLadderSummary::default()
    };
    assert!(good.describes_a_contained_ladder(2));

    // A crash the supervisor never answered — the host died and nothing
    // brought it back, which is the failure the ladder exists to prevent.
    assert!(
        !DriverLadderSummary {
            restarted: 1,
            ..good
        }
        .describes_a_contained_ladder(2)
    );
    // A restart with no crash behind it: something respawned a host that
    // had not died.
    assert!(
        !DriverLadderSummary {
            restarted: 3,
            ..good
        }
        .describes_a_contained_ladder(2)
    );
    // Restarts that recovered nothing — every launch leaked its frames.
    assert!(
        !DriverLadderSummary {
            reclaimed_frames: 0,
            ..good
        }
        .describes_a_contained_ladder(2)
    );
    // Records a log service cannot filter, or cannot join to a cause.
    assert!(
        !DriverLadderSummary {
            severities_ok: false,
            ..good
        }
        .describes_a_contained_ladder(2)
    );
    assert!(
        !DriverLadderSummary {
            stamped_ok: false,
            ..good
        }
        .describes_a_contained_ladder(2)
    );
    assert!(
        !DriverLadderSummary {
            component_ok: false,
            ..good
        }
        .describes_a_contained_ladder(2)
    );
}

/// A record at the wrong severity or from the wrong boot fails the
/// reading, because both make it useless to the thing that would consume
/// it.
#[test]
fn a_ladder_record_that_cannot_be_consumed_fails_the_reading() {
    // The right kind, the wrong severity: a give-up filed as a notice
    // would be invisible to anything watching for escalation.
    let wrong_severity = [ladder_event(
        EventKind::DriverHostGaveUp,
        Severity::Notice,
        [3, 177, 0, 0],
    )];
    assert!(!summarize_driver_ladder(&wrong_severity, 99).severities_ok);

    let right = [ladder_event(
        EventKind::DriverHostGaveUp,
        Severity::Critical,
        [3, 177, 0, 0],
    )];
    assert!(summarize_driver_ladder(&right, 99).severities_ok);
    // From another boot: the id cannot be joined to anything in this one.
    assert!(!summarize_driver_ladder(&right, 100).stamped_ok);
}

/// A lifecycle record with a live envelope, for the sequence tests.
fn transition(device: u64, from: DriverState, to: DriverState) -> KernelEvent {
    let severity = match to {
        DriverState::Failed => Severity::Critical,
        DriverState::Degraded => Severity::Error,
        DriverState::Removed | DriverState::Resetting => Severity::Warning,
        _ => Severity::Notice,
    };
    ladder_event(
        EventKind::DriverLifecycleTransition,
        severity,
        [device, from as u64, to as u64, 0],
    )
}

/// The whole seven-step ladder, read from records: a supervisor's three
/// steps plus the four that need somebody else — a manager marking the
/// device, a dump, dependents told, a reset attempted.
#[test]
fn the_summary_reads_the_whole_ladder_and_not_just_the_supervisors_part() {
    use DriverState::*;
    let events = [
        transition(26, Discovered, Matched),
        transition(26, Matched, Starting),
        transition(26, Starting, Probing),
        transition(26, Probing, Active),
        ladder_event(
            EventKind::DriverHostCrashed,
            Severity::Error,
            [0x0e, 0, 1, 0],
        ),
        ladder_event(
            EventKind::DriverCrashDump,
            Severity::Error,
            [0x51, 0, 3, 0x0e],
        ),
        transition(26, Active, Degraded),
        ladder_event(
            EventKind::DeviceDependentsNotified,
            Severity::Notice,
            [26, 2, 0, Degraded as u64],
        ),
        transition(26, Degraded, Resetting),
        ladder_event(EventKind::DeviceReset, Severity::Warning, [26, 0, 0, 2]),
        transition(26, Resetting, Probing),
        ladder_event(
            EventKind::DriverHostRestarted,
            Severity::Notice,
            [2, 7, 12, 0],
        ),
        transition(26, Probing, Active),
    ];
    let s = summarize_driver_ladder(&events, 99);
    assert!(s.describes_a_contained_ladder(1));
    assert!(s.describes_the_full_ladder());
    assert_eq!(s.degraded_marks, 1);
    assert_eq!(s.crash_dumps, 1);
    assert_eq!(s.crash_dump_records, 3);
    assert_eq!(s.dependents_notified, 2);
    assert_eq!(s.resets, 1);
    assert_eq!(s.transitions, 8);
    assert_eq!(s.transition_gaps, 0);
}

/// The clause that makes lifecycle records evidence rather than narration.
/// Plausible states in an impossible order produce a perfectly healthy
/// count, and only checking that each `from` is where the last transition
/// left the device catches it.
#[test]
fn a_transition_that_does_not_follow_the_last_one_is_a_gap() {
    use DriverState::*;
    let events = [
        transition(26, Discovered, Matched),
        // Skips Starting and Probing entirely: each record is a legal edge
        // on its own, and together they are not a history.
        transition(26, Probing, Active),
    ];
    let s = summarize_driver_ladder(&events, 99);
    assert_eq!(s.transitions, 2);
    assert_eq!(s.transition_gaps, 1);
    assert!(!s.describes_the_full_ladder());
}

/// Two devices have two histories, and one device's transition must not
/// satisfy another's `from`.
#[test]
fn each_devices_transitions_are_sequenced_independently() {
    use DriverState::*;
    let events = [
        transition(26, Discovered, Matched),
        transition(27, Discovered, Matched),
        transition(26, Matched, Starting),
        transition(27, Matched, Starting),
    ];
    assert_eq!(summarize_driver_ladder(&events, 99).transition_gaps, 0);
}

/// Each clause of the full-ladder reading fails on its own, or a boot
/// check would pass on a system running half a ladder.
#[test]
fn the_full_ladder_reading_rejects_each_missing_step() {
    let good = DriverLadderSummary {
        degraded_marks: 1,
        crash_dumps: 1,
        crash_dump_records: 3,
        dependents_notified: 2,
        resets: 1,
        transitions: 8,
        ..DriverLadderSummary::default()
    };
    assert!(good.describes_the_full_ladder());

    // Step 2: nobody marked the device.
    assert!(
        !DriverLadderSummary {
            degraded_marks: 0,
            ..good
        }
        .describes_the_full_ladder()
    );
    // Step 3: no dump, or a dump that collected nothing — which is a dump
    // mechanism that ran and captured no evidence at all.
    assert!(
        !DriverLadderSummary {
            crash_dumps: 0,
            ..good
        }
        .describes_the_full_ladder()
    );
    assert!(
        !DriverLadderSummary {
            crash_dump_records: 0,
            ..good
        }
        .describes_the_full_ladder()
    );
    // Step 4: nobody was told, or somebody could not be reached.
    assert!(
        !DriverLadderSummary {
            dependents_notified: 0,
            ..good
        }
        .describes_the_full_ladder()
    );
    assert!(
        !DriverLadderSummary {
            dependents_unreachable: 1,
            ..good
        }
        .describes_the_full_ladder()
    );
    // Step 5: no reset attempted, or one the hardware refused.
    assert!(!DriverLadderSummary { resets: 0, ..good }.describes_the_full_ladder());
    assert!(
        !DriverLadderSummary {
            resets_failed: 1,
            ..good
        }
        .describes_the_full_ladder()
    );
    // And the sequence itself.
    assert!(
        !DriverLadderSummary {
            transition_gaps: 1,
            ..good
        }
        .describes_the_full_ladder()
    );
}

/// Records from other components share the ring and are not the ladder's.
#[test]
fn the_ladder_summary_ignores_records_that_are_not_the_ladders() {
    let events = [
        event(1),
        driver_event(EventKind::DeviceWindowMapped, [21, 0, 0, 0x1000]),
    ];
    let s = summarize_driver_ladder(&events, 99);
    assert_eq!(s.crashed, 0);
    assert_eq!(s.restarted, 0);
    // Vacuously clean, which is why a caller checks the counts too.
    assert!(s.component_ok && s.severities_ok && s.stamped_ok);
    assert!(!s.describes_a_contained_ladder(0));
}

#[test]
fn the_summary_separates_the_two_revocation_routes() {
    let events = [
        driver_event(
            EventKind::DeviceWindowRevoked,
            [21, 0x4000_0000, WindowRevokeReason::Transferred as u64, 0],
        ),
        driver_event(
            EventKind::DeviceWindowRevoked,
            [21, 0x4000_1000, WindowRevokeReason::HandleClosed as u64, 0],
        ),
    ];
    let s = summarize_device_events(&events, 99);
    assert_eq!(s.revoked_on_transfer, 1);
    assert_eq!(s.revoked_on_close, 1);
    assert_eq!(s.unmap_errors, 0);
}

/// The "impossible" case the record exists to surface: a window whose page
/// would not come down, meaning the window table and the page tables had
/// drifted. It must be counted, not averaged away.
#[test]
fn an_unclean_unmap_is_counted() {
    let events = [driver_event(
        EventKind::DeviceWindowRevoked,
        [
            21,
            0x4000_0000,
            WindowRevokeReason::Transferred as u64,
            tessera_karch::KError::NotMapped as u64,
        ],
    )];
    assert_eq!(summarize_device_events(&events, 99).unmap_errors, 1);
}

#[test]
fn a_record_from_another_boot_epoch_fails_the_envelope() {
    let events = [driver_event(EventKind::DeviceWindowMapped, [21, 0, 0, 0])];
    assert!(summarize_device_events(&events, 99).envelope_ok);
    assert!(!summarize_device_events(&events, 100).envelope_ok);
}

/// Records from other components share the ring and must not be read as
/// the driver framework's.
#[test]
fn the_summary_ignores_records_from_other_components() {
    let events = [
        event(1),
        record(
            EventKind::UserFaultContained,
            Severity::Error,
            Component::Exception,
            7,
            TRACE,
            [14, 0, 0, 0],
        ),
    ];
    let s = summarize_device_events(&events, 99);
    assert_eq!(s.records, 0);
    assert_eq!(s.mapped, 0);
    // Vacuously true, which is why a caller must check `records` too.
    assert!(s.envelope_ok);
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
