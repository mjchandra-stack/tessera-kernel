// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The crash-recovery ladder's policy: how many times a driver host that keeps
//! dying is brought back, and what the system records at each rung.
//!
//! `docs/drivers/01` ("Crash Recovery") lists seven steps and closes with
//! *"repeated crashes can trigger rollback, fallback drivers, or device
//! quarantine"*. That last sentence is the reason this type exists at all: a
//! supervisor that restarts unconditionally is not implementing a ladder, it
//! is implementing a loop. The budget is what makes "repeated" a thing the
//! system can notice.
//!
//! **Policy and records only — no scheduler, no allocator, no address
//! spaces.** Spawning a host and reclaiming a corpse are architecture work and
//! stay in the ports; deciding whether there is another restart left, and
//! emitting the three records that let a log service reconstruct what
//! happened, are not, and were being written a second time in every port that
//! grew a driver framework. Keeping them here is also what makes the ladder
//! *testable* on the host: a boot check can only observe the ladder it ran,
//! and this can be driven through every branch including the ones a healthy
//! machine never takes.
//!
//! The three records and what separates them:
//!
//! - `DRIVER_HOST_CRASHED` — the host faulted and the kernel did not. Carries
//!   what killed it, so the record says *why* rather than merely that one
//!   died.
//! - `DRIVER_HOST_RESTARTED` — the corpse was reclaimed and a replacement will
//!   be launched against the same binding. Carries the frames recovered,
//!   because a restart that leaks is still a restart and the leak has to be
//!   visible per launch rather than only in a final total.
//! - `DRIVER_HOST_GAVE_UP` — the budget is spent. The loudest thing a
//!   supervisor does, and the one that must never be only a console line.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Crash Recovery"),
//! docs/architecture/01-system-architecture.md ("Failure Model")
//! Budget: none (recovery path)

use crate::event::{Component, EventKind, KernelEvent, Severity, emit};
use crate::object::ObjectId;

/// Records kept with a crash dump — the trail leading up to the fault.
///
/// Small on purpose. The whole ring is a boot's emission and most of it has
/// nothing to do with the host that died; what a dump is for is the last few
/// things that happened, and a dump that carried everything would be a copy of
/// the log rather than a summary of a failure.
pub const CRASH_TRACE_TAIL: usize = 8;

/// Ladder step 3: what was captured when a driver host faulted.
///
/// **Two halves, and the second is the one that was missing.** The fault
/// itself — what killed the host and where — the supervisor already had. The
/// *trace tail* is the records emitted under the dead host's own causal id
/// before it died: the window it mapped, the DMA it was granted, the interrupt
/// it was waiting on. Without them a crash report says a process died; with
/// them it says what it was doing.
///
/// Filtering by correlation rather than taking the last N records is what makes
/// that true. A boot runs several things at once and the ring interleaves them;
/// the last eight records before a crash are mostly somebody else's, and a dump
/// that presented them as the crashed host's history would be actively
/// misleading.
#[derive(Clone, Copy)]
pub struct CrashDump {
    /// The process that died.
    pub process: ObjectId,
    /// What killed it, as the port reports causes.
    pub cause: u64,
    /// The address it faulted on.
    pub address: u64,
    /// The causal id it was running under — the key the trace tail is
    /// filtered by, and what joins this dump to everything else the host did.
    pub correlation: u64,
    /// How many records were captured. **Zero is the failure worth seeing**:
    /// a dump that captured nothing is indistinguishable from no crash at all
    /// if the dump is the only evidence, which is why the count goes into the
    /// record as well as into this struct.
    pub captured: usize,
    /// The records themselves, oldest first.
    pub trace: [KernelEvent; CRASH_TRACE_TAIL],
}

impl CrashDump {
    /// The records actually captured.
    pub fn records(&self) -> &[KernelEvent] {
        &self.trace[..self.captured]
    }
}

/// Captures a crash dump into `dump` and records that one was taken.
///
/// Filled in place rather than returned: a dump is most of a kilobyte, and the
/// callers are supervisors running on a boot stack that has already been sized
/// for something else.
///
/// The ring is **copied, not drained** — the boot check that reads the whole
/// run afterwards is the ring's one consumer, and a dump that consumed records
/// to describe them would delete the evidence it was summarising.
pub fn capture_crash_dump(
    dump: &mut CrashDump,
    process: ObjectId,
    cause: u64,
    address: u64,
    correlation: u64,
) {
    dump.process = process;
    dump.cause = cause;
    dump.address = address;
    dump.correlation = correlation;
    dump.captured = 0;

    let mut window = [dump.trace[0]; crate::event::EVENT_RING_CAPACITY];
    let n = crate::event::tail(&mut window);
    // Newest last, so walking backwards and filling from the end keeps the
    // captured records in emission order while keeping the *latest* ones when
    // there are more matches than room.
    for event in window[..n].iter().rev() {
        if dump.captured == CRASH_TRACE_TAIL {
            break;
        }
        // A correlation of zero matches nothing on purpose: it is the value a
        // record carries when no origin had stamped it, and treating it as a
        // match would fill the dump with records belonging to nobody.
        if correlation == 0 || event.correlation_lo != correlation {
            continue;
        }
        dump.trace[CRASH_TRACE_TAIL - 1 - dump.captured] = *event;
        dump.captured += 1;
    }
    // Shift to the front so `records()` is a plain prefix.
    dump.trace.rotate_left(CRASH_TRACE_TAIL - dump.captured);

    emit(
        EventKind::DriverCrashDump,
        Severity::Error,
        Component::Driver,
        [process.raw() as u64, address, dump.captured as u64, cause],
    );
}

/// What to do with a binding once the supervisor has given up on it —
/// `docs/drivers/01` step 7's *"binding is restored or disabled based on
/// failure policy"*, and the sentence after it: *"repeated crashes can trigger
/// rollback, fallback drivers, or device quarantine"*.
///
/// Four outcomes because those are four different states of the world, and a
/// system with fewer would have to pretend one of them was another. The values
/// are ABI (`kernel_event.isl`, `DEVICE_QUARANTINED`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum FailureAction {
    /// Put the binding back: the failure was transient and the device is
    /// bindable again by the same driver.
    RestoreBinding = 1,
    /// Leave the device unbound but offerable. Nothing will drive it now; an
    /// operator or a later policy pass may.
    DisableBinding = 2,
    /// Try a different driver configuration before giving up on the device.
    Fallback = 3,
    /// Stop offering the device at all.
    Quarantine = 4,
}

/// When each of those applies.
///
/// A struct rather than a single number because the thresholds are
/// independent: a device may be worth a fallback after two failures and worth
/// quarantining after six, and collapsing them into one "give up at N" would
/// make the middle rung unreachable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FailurePolicy {
    /// Failures after which a different driver configuration is tried. `None`
    /// means there is no alternative to try — the honest state for a device
    /// with exactly one driver, and not the same thing as a threshold of zero.
    pub fallback_after: Option<u64>,
    /// Failures after which the device stops being offered. `None` means never
    /// quarantine: the device keeps being offered however often it fails,
    /// which is a legitimate policy for hardware the system cannot do without.
    pub quarantine_after: Option<u64>,
    /// Whether a binding that recovered is restored, or left disabled for
    /// something else to decide about.
    pub restore_on_recovery: bool,
}

impl FailurePolicy {
    /// The conservative default: try a fallback once things have gone wrong
    /// more than once, quarantine after a run of failures, and restore a
    /// binding that recovered.
    pub const DEFAULT: Self = Self {
        fallback_after: Some(2),
        quarantine_after: Some(4),
        restore_on_recovery: true,
    };

    /// What to do after `faults` contained failures of this binding.
    ///
    /// Ordered from most severe: quarantine wins over fallback, because a
    /// device that has crossed the quarantine threshold has already been
    /// through whatever the fallback was.
    pub fn after(&self, faults: u64) -> FailureAction {
        if self.quarantine_after.is_some_and(|n| faults >= n) {
            return FailureAction::Quarantine;
        }
        if self.fallback_after.is_some_and(|n| faults >= n) {
            return FailureAction::Fallback;
        }
        if self.restore_on_recovery {
            FailureAction::RestoreBinding
        } else {
            FailureAction::DisableBinding
        }
    }
}

/// How many times a persistently crashing host is brought back before the
/// supervisor stops.
///
/// A default rather than a constant every caller must repeat, and small enough
/// that a runaway is bounded well under the object and handle table sizes a
/// launch consumes. A supervisor with a different tolerance passes its own.
pub const DEFAULT_RESTART_BUDGET: u32 = 8;

/// What one supervised run did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RestartOutcome {
    /// Hosts launched, including the one that is running now.
    pub launches: u64,
    /// Contained faults — launches that died rather than finishing.
    pub faults: u64,
    /// Restarts still available.
    pub budget: u32,
    /// Whether the supervisor stopped because the budget ran out.
    pub gave_up: bool,
}

/// The ladder's bookkeeping and its records.
///
/// One per supervised binding. A supervisor drives it in the order the ladder
/// is written: [`Self::launched`] before each host runs,
/// [`Self::crashed`] when one faults, [`Self::restarted`] once its corpse has
/// been reclaimed, and [`Self::may_restart`] to decide whether to go round
/// again — with [`Self::give_up`] when it says no.
pub struct RestartSupervisor {
    budget: u32,
    launches: u64,
    faults: u64,
    gave_up: bool,
}

impl RestartSupervisor {
    /// A supervisor that will bring a host back at most `budget` times.
    ///
    /// A budget of zero is legitimate and means "run it once; if it dies, that
    /// is the end of it" — a policy for a driver whose failure is not worth
    /// retrying. It is not treated as unlimited, which is the reading that
    /// would turn a typo into a machine that never stops respawning.
    pub const fn new(budget: u32) -> Self {
        Self {
            budget,
            launches: 0,
            faults: 0,
            gave_up: false,
        }
    }

    /// Records that a host is being launched. Called before it runs, so a
    /// crash record can name the launch that produced it.
    pub const fn launched(&mut self) -> u64 {
        self.launches += 1;
        self.launches
    }

    /// Ladder step 1, recorded: the host faulted and the kernel contained it.
    ///
    /// `vector` and `address` come from the contained-fault handler so the
    /// record says what killed the host. They are passed in rather than read
    /// from anywhere here because what a "vector" is differs per
    /// architecture — an x86 trap number, an AArch64 exception class, a
    /// RISC-V cause — and normalizing them is not this type's business.
    ///
    /// **The caller must adopt the dead host's correlation id first.** A
    /// supervisor reached here through a yield back to boot, whose ambient
    /// context is boot's own id, so without that the ladder roots a fresh
    /// trace and nothing joins a restart to the crash that provoked it.
    pub fn crashed(&mut self, vector: u64, address: u64) {
        self.faults += 1;
        emit(
            EventKind::DriverHostCrashed,
            Severity::Error,
            Component::Driver,
            [vector, address, self.launches, 0],
        );
    }

    /// Ladder steps 6 and 7, recorded: the corpse is reclaimed and the binding
    /// will be handed to a replacement. Spends one restart from the budget.
    ///
    /// `frames_reclaimed` rides along because a restart that leaks is still a
    /// restart, and a leak that only shows up in a final total cannot be
    /// attributed to the launch that caused it.
    ///
    /// Returns the budget left.
    pub fn restarted(&mut self, frames_reclaimed: u64) -> u32 {
        self.budget = self.budget.saturating_sub(1);
        emit(
            EventKind::DriverHostRestarted,
            Severity::Notice,
            Component::Driver,
            [self.launches, u64::from(self.budget), frames_reclaimed, 0],
        );
        self.budget
    }

    /// Whether another launch is allowed.
    pub const fn may_restart(&self) -> bool {
        self.budget > 0 && !self.gave_up
    }

    /// The ladder's end: a host that keeps crashing is not restarted for ever.
    ///
    /// `code` is the supervisor's own give-up identity, so two supervisors
    /// giving up in one boot are distinguishable in the record stream.
    /// Idempotent — a supervisor that checks [`Self::may_restart`] in a loop
    /// and calls this on the way out must not emit one record per iteration.
    pub fn give_up(&mut self, code: u64) {
        if self.gave_up {
            return;
        }
        self.gave_up = true;
        emit(
            EventKind::DriverHostGaveUp,
            Severity::Critical,
            Component::Driver,
            [self.launches, code, 0, 0],
        );
    }

    /// What this run did so far.
    pub const fn outcome(&self) -> RestartOutcome {
        RestartOutcome {
            launches: self.launches,
            faults: self.faults,
            budget: self.budget,
            gave_up: self.gave_up,
        }
    }
}

#[cfg(test)]
mod tests {
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
}
