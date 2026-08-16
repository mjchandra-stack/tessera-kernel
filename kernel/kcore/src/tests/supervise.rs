// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::supervise`.

use super::*;
use crate::event::{KernelEvent, drain};

/// A blank record, for initialising buffers the ring overwrites.
const BLANK: KernelEvent = KernelEvent {
    size: 0,
    version: 0,
    flags: 0,
    kind: EventKind::EventsDropped,
    severity: Severity::Info,
    component: Component::Driver,
    classification: crate::event::Classification::Public,
    timestamp: 0,
    thread_id: 0,
    process_id: 0,
    correlation_lo: 0,
    correlation_hi: 0,
    arg0: 0,
    arg1: 0,
    arg2: 0,
    arg3: 0,
};

/// A dump with nothing in it, for the capture tests to fill.
const EMPTY_DUMP: CrashDump = CrashDump {
    process: ObjectId::from_raw(0),
    cause: 0,
    address: 0,
    correlation: 0,
    captured: 0,
    trace: [BLANK; CRASH_TRACE_TAIL],
};

/// Empties the global ring and returns the ladder records in it.
///
/// The ring is process-wide and these tests share it, which is why each
/// drains before it acts as well as after — a neighbouring test's records
/// would otherwise be counted as this one's.
fn ladder() -> std::vec::Vec<KernelEvent> {
    let mut out = [BLANK; crate::event::EVENT_RING_CAPACITY];
    let n = drain(&mut out);
    out[..n]
        .iter()
        .copied()
        .filter(|e| {
            matches!(
                e.kind,
                EventKind::DriverHostCrashed
                    | EventKind::DriverHostRestarted
                    | EventKind::DriverHostGaveUp
            )
        })
        .collect()
}

/// A crash dump keeps the records the **dead host** emitted and drops the
/// ones it did not.
///
/// This is the whole reason the tail is filtered by correlation rather than
/// taken as the last N records. A boot runs several things at once and the
/// ring interleaves them; a dump that presented a neighbour's records as
/// the crashed host's history would be actively misleading, which is worse
/// than an empty dump.
#[test]
fn a_crash_dump_captures_only_the_dead_hosts_own_trail() {
    let _ = ladder();
    const MINE: u64 = 0x51;
    const THEIRS: u64 = 0x52;
    let emit_under = |correlation, arg0| {
        crate::trace::set_current_correlation(correlation);
        emit(
            EventKind::DeviceWindowMapped,
            Severity::Info,
            Component::Driver,
            [arg0, 0, 0, 0],
        );
    };
    emit_under(MINE, 1);
    emit_under(THEIRS, 2);
    emit_under(MINE, 3);

    let mut dump = EMPTY_DUMP;
    capture_crash_dump(&mut dump, ObjectId::from_raw(26), 0x0e, 0xdead, MINE);
    assert_eq!(dump.captured, 2, "the neighbour's record is not mine");
    assert_eq!(dump.records()[0].arg0, 1, "oldest first");
    assert_eq!(dump.records()[1].arg0, 3);
    assert_eq!(dump.process, ObjectId::from_raw(26));
    assert_eq!(dump.address, 0xdead);
    let _ = ladder();
}

/// The ring is copied, not drained: the boot check that reads the whole
/// run afterwards is its one consumer, and a dump that consumed records to
/// describe them would delete the evidence it was summarising.
#[test]
fn capturing_a_dump_leaves_the_ring_intact() {
    let _ = ladder();
    crate::trace::set_current_correlation(0x61);
    emit(
        EventKind::DeviceWindowMapped,
        Severity::Info,
        Component::Driver,
        [7, 0, 0, 0],
    );
    let before = crate::event::buffered();
    let mut dump = EMPTY_DUMP;
    capture_crash_dump(&mut dump, ObjectId::from_raw(26), 0, 0, 0x61);
    assert_eq!(dump.captured, 1);
    // One more than before: the dump's own record went in. Nothing was
    // taken out.
    assert_eq!(crate::event::buffered(), before + 1);
    let _ = ladder();
    let mut rest = [EMPTY_DUMP.trace[0]; crate::event::EVENT_RING_CAPACITY];
    crate::event::drain(&mut rest);
}

/// A dump that captured nothing is the failure worth seeing, so the count
/// is in the record and not only in the struct. Nothing matches a
/// correlation of zero: that is the value a record carries when no origin
/// stamped it, and treating it as a match would fill the dump with records
/// belonging to nobody.
#[test]
fn a_dump_with_no_trail_says_so_rather_than_inventing_one() {
    let _ = ladder();
    let mut dump = EMPTY_DUMP;
    capture_crash_dump(&mut dump, ObjectId::from_raw(26), 0x0e, 0, 0);
    assert_eq!(dump.captured, 0);
    assert!(dump.records().is_empty());

    let mut out = [EMPTY_DUMP.trace[0]; crate::event::EVENT_RING_CAPACITY];
    let n = crate::event::drain(&mut out);
    let record = out[..n]
        .iter()
        .find(|e| e.kind == EventKind::DriverCrashDump)
        .expect("a dump was recorded even though it captured nothing");
    assert_eq!(record.arg2, 0, "and the record says how little it got");
}

/// More matching records than room keeps the **latest**, because a crash
/// dump is about what happened just before the crash.
#[test]
fn a_dump_keeps_the_most_recent_records_when_it_overflows() {
    let _ = ladder();
    const MINE: u64 = 0x71;
    crate::trace::set_current_correlation(MINE);
    for i in 0..(CRASH_TRACE_TAIL as u64 + 3) {
        emit(
            EventKind::DeviceWindowMapped,
            Severity::Info,
            Component::Driver,
            [i, 0, 0, 0],
        );
    }
    let mut dump = EMPTY_DUMP;
    capture_crash_dump(&mut dump, ObjectId::from_raw(26), 0, 0, MINE);
    assert_eq!(dump.captured, CRASH_TRACE_TAIL);
    assert_eq!(dump.records()[0].arg0, 3, "the earliest three fell off");
    assert_eq!(
        dump.records()[CRASH_TRACE_TAIL - 1].arg0,
        CRASH_TRACE_TAIL as u64 + 2,
        "and the newest is kept",
    );
    let mut out = [EMPTY_DUMP.trace[0]; crate::event::EVENT_RING_CAPACITY];
    crate::event::drain(&mut out);
}

/// The policy's rungs are independent thresholds, and the more severe one
/// wins. A device past the quarantine threshold has already been through
/// whatever the fallback was.
#[test]
fn the_failure_policy_escalates_through_its_rungs() {
    let policy = FailurePolicy::DEFAULT;
    assert_eq!(policy.after(0), FailureAction::RestoreBinding);
    assert_eq!(policy.after(1), FailureAction::RestoreBinding);
    assert_eq!(policy.after(2), FailureAction::Fallback);
    assert_eq!(policy.after(3), FailureAction::Fallback);
    assert_eq!(policy.after(4), FailureAction::Quarantine);
    assert_eq!(policy.after(99), FailureAction::Quarantine);
}

/// `None` is not a threshold of zero. A device with exactly one driver has
/// no fallback to try, and hardware the system cannot do without is never
/// quarantined however often it fails — both are policies, and reading
/// either as "immediately" would be the opposite of what was asked for.
#[test]
fn an_absent_threshold_never_fires() {
    let policy = FailurePolicy {
        fallback_after: None,
        quarantine_after: None,
        restore_on_recovery: true,
    };
    assert_eq!(policy.after(0), FailureAction::RestoreBinding);
    assert_eq!(policy.after(1_000), FailureAction::RestoreBinding);

    // And a policy that does not restore leaves the binding disabled
    // rather than quietly restoring it anyway.
    let cautious = FailurePolicy {
        restore_on_recovery: false,
        ..policy
    };
    assert_eq!(cautious.after(0), FailureAction::DisableBinding);
}

/// A host that crashes twice against a budget of eight comes back both
/// times, and the ladder never reaches its end.
#[test]
fn a_recoverable_host_is_restarted_and_never_given_up_on() {
    let _ = ladder();
    let mut sup = RestartSupervisor::new(DEFAULT_RESTART_BUDGET);
    for _ in 0..2 {
        sup.launched();
        assert!(sup.may_restart());
        sup.crashed(0x0e, 0x0);
        sup.restarted(12);
    }
    sup.launched();
    let outcome = sup.outcome();
    assert_eq!(outcome.launches, 3, "two crashes, then a clean third");
    assert_eq!(outcome.faults, 2);
    assert_eq!(outcome.budget, DEFAULT_RESTART_BUDGET - 2);
    assert!(!outcome.gave_up);

    let records = ladder();
    assert_eq!(records.len(), 4, "two crashes and two restarts");
    assert!(
        !records
            .iter()
            .any(|e| e.kind == EventKind::DriverHostGaveUp)
    );
}

/// The budget is what makes "repeated crashes" a thing the system can act
/// on. Without it the supervisor is a loop, and this test is the negative
/// that proves the loop terminates.
#[test]
fn a_persistently_crashing_host_exhausts_its_budget_and_is_given_up_on() {
    let _ = ladder();
    let mut sup = RestartSupervisor::new(3);
    let mut launches = 0;
    while sup.may_restart() {
        sup.launched();
        launches += 1;
        sup.crashed(0x0e, 0x0);
        sup.restarted(4);
        // A runaway guard for the test itself: if `may_restart` never went
        // false this would spin for ever rather than fail.
        assert!(launches <= 8, "the budget did not stop the loop");
    }
    sup.give_up(177);
    let outcome = sup.outcome();
    assert_eq!(outcome.launches, 3, "exactly the budget, no more");
    assert_eq!(outcome.faults, 3);
    assert_eq!(outcome.budget, 0);
    assert!(outcome.gave_up);

    let records = ladder();
    let gave_up: std::vec::Vec<_> = records
        .iter()
        .filter(|e| e.kind == EventKind::DriverHostGaveUp)
        .collect();
    assert_eq!(gave_up.len(), 1, "one record, not one per iteration");
    assert_eq!(gave_up[0].arg0, 3, "launches made");
    assert_eq!(gave_up[0].arg1, 177, "the supervisor's own identity");
}

/// A budget of zero means "run it once", not "run it for ever". Reading it
/// as unlimited is how a typo becomes a machine that never stops
/// respawning.
#[test]
fn a_budget_of_zero_allows_no_restart_at_all() {
    let _ = ladder();
    let mut sup = RestartSupervisor::new(0);
    assert!(!sup.may_restart());
    sup.give_up(1);
    // And a second call adds nothing: a supervisor that loops on
    // `may_restart` must not emit a record per iteration.
    sup.give_up(1);
    assert_eq!(ladder().len(), 1);
}

/// Severity carries the escalation. A log service filtering on it must be
/// able to tell a restart from a give-up without decoding the payload.
#[test]
fn the_three_rungs_escalate_in_severity() {
    let _ = ladder();
    let mut sup = RestartSupervisor::new(1);
    sup.launched();
    sup.crashed(0x0e, 0xdead);
    sup.restarted(7);
    sup.give_up(177);
    let records = ladder();
    for e in &records {
        assert_eq!(e.component, Component::Driver);
    }
    let severity = |kind| {
        records
            .iter()
            .find(|e| e.kind == kind)
            .map(|e| e.severity)
            .expect("record present")
    };
    assert_eq!(severity(EventKind::DriverHostCrashed), Severity::Error);
    assert_eq!(severity(EventKind::DriverHostRestarted), Severity::Notice);
    assert_eq!(severity(EventKind::DriverHostGaveUp), Severity::Critical);
}

/// The crash record says what killed the host, not merely that one died.
/// A ladder whose records could not distinguish a null dereference from a
/// bad instruction would leave every crash looking the same.
#[test]
fn the_crash_record_carries_what_killed_the_host() {
    let _ = ladder();
    let mut sup = RestartSupervisor::new(2);
    sup.launched();
    sup.crashed(0x0e, 0xdead_beef);
    let reclaimed = 19;
    sup.restarted(reclaimed);
    let records = ladder();
    let crash = records
        .iter()
        .find(|e| e.kind == EventKind::DriverHostCrashed)
        .expect("crash record");
    assert_eq!(crash.arg0, 0x0e, "the vector");
    assert_eq!(crash.arg1, 0xdead_beef, "the faulting address");
    assert_eq!(crash.arg2, 1, "the launch that died");
    let restart = records
        .iter()
        .find(|e| e.kind == EventKind::DriverHostRestarted)
        .expect("restart record");
    assert_eq!(restart.arg1, 1, "budget remaining");
    assert_eq!(
        restart.arg2, reclaimed,
        "frames recovered, per launch rather than only in a total",
    );
}
