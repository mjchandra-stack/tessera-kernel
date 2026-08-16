// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Trace event schema validation**: whether the records a system emitted say
//! what the schema says they say.
//!
//! One of the checks `docs/drivers/01` ("Certification") requires, and the one
//! whose subject already exists in this tree — `kernel_event.isl` fixes the
//! record and `kcore::event` emits into a bounded ring. What did not exist is
//! anything that reads those records back and asks whether they are usable.
//!
//! # What a decoder already proves, and where it stops
//!
//! The generated decoder refuses a record whose `kind`, `severity`, `component`
//! or `classification` is outside its enum. That is worth having and it is not
//! validation, because **it says nothing about any field that is not an enum**.
//! A record can decode perfectly with its timestamp zero, its correlation id
//! zero, and three of its four payload slots holding values the schema never
//! described. Such a record renders without complaint, joins to nothing, and
//! carries whatever the emitter happened to put in it.
//!
//! So the clauses here are exactly the ones decoding cannot make. They are
//! checked over plain integers rather than the generated types, for the reason
//! `api/class-conformance` takes a `u32` status: a validator that could only
//! accept values already inside the enums could never see the record it exists
//! to catch.
//!
//! # The catalog
//!
//! `kernel_event.isl` documents, in prose, what each event's four payload slots
//! mean and how many of them are used. [`CATALOG`] is that prose made
//! checkable: one entry per kind, saying how many slots the schema gives a
//! meaning to and which component the kind belongs to.
//!
//! **The arity is the load-bearing part.** A slot the schema does not describe
//! is an undeclared payload: no renderer will show it, no reviewer classified
//! it, and nothing downstream can tell it from padding. It is the one place in
//! a structured-logging facility where a value can travel without anybody
//! having agreed that it should — which is where a secret ends up in a trace.
//! [`Clause::UndeclaredArgsAreEmpty`] is the whole reason the catalog records a
//! count rather than just a set of known kinds.
//!
//! **The component is the other half.** `kernel_event.isl` says why, about the
//! one it added last: filing a security decision under a component nobody reads
//! for security decisions puts the record where it will not be found. A record
//! in the wrong stream is not lost and not readable either.
//!
//! Normative: docs/observability/01-debugging-monitoring-tracing-logging.md
//! ("Structured Logging"), docs/drivers/01-driver-framework.md
//! ("Certification")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// The record size this validator understands, as `kernel_event.isl` lays it
/// out.
///
/// Hard-coded rather than taken from the generated binding, and that is the
/// point: a record of another size is from a schema this validator does not
/// know, and one that adopted whatever size it was handed could never say so.
pub const RECORD_WIRE_SIZE: u32 = 104;

/// The schema version this validator understands.
pub const SCHEMA_VERSION: u32 = 1;

/// How many payload slots a record has.
pub const ARG_SLOTS: usize = 4;

/// One emitted record, as plain integers.
///
/// Deliberately not the generated `KernelEvent`. Every enum field is a `u32`
/// here so that a kind outside the catalog, or a component outside the
/// vocabulary, is something this validator can *see* — a type that refused to
/// hold such a value would refuse to hold the evidence.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Record {
    pub size: u32,
    pub version: u32,
    pub kind: u32,
    pub severity: u32,
    pub component: u32,
    pub classification: u32,
    pub timestamp: u64,
    /// The process the record was emitted on behalf of, so a caller can ask
    /// about one driver's records rather than about the whole machine's.
    pub process_id: u64,
    /// The low half of the 128-bit causal id.
    pub correlation_lo: u64,
    /// The high half — the per-boot epoch.
    pub correlation_hi: u64,
    pub args: [u64; ARG_SLOTS],
}

/// What a record has to be for something downstream to use it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Clause {
    /// The record declares the size and schema version this validator knows.
    RecordIsTheDeclaredShape = 1,
    /// The envelope fields a decoder cannot check are filled: a record with no
    /// timestamp and no causal id is one nothing can order or join.
    EnvelopeIsFilled = 2,
    /// The kind has a catalog entry, so its payload has a documented meaning.
    KindIsInTheCatalog = 3,
    /// The kind was emitted under the component the schema files it beneath.
    ComponentMatchesTheCatalog = 4,
    /// Every payload slot the schema does not describe is zero.
    UndeclaredArgsAreEmpty = 5,
}

/// Every clause, so a caller can iterate without knowing the count.
pub const ALL_CLAUSES: [Clause; 5] = [
    Clause::RecordIsTheDeclaredShape,
    Clause::EnvelopeIsFilled,
    Clause::KindIsInTheCatalog,
    Clause::ComponentMatchesTheCatalog,
    Clause::UndeclaredArgsAreEmpty,
];

impl Clause {
    /// This clause's bit in a [`Verdict`]'s masks.
    pub const fn bit(self) -> u32 {
        1 << self as u32
    }
}

/// The components, as `kernel_event.isl` numbers them.
pub mod component {
    pub const PAGER: u32 = 1;
    pub const MEMORY: u32 = 2;
    pub const DRIVER: u32 = 3;
    pub const SCHEDULER: u32 = 4;
    pub const IPC: u32 = 5;
    pub const OBSERVABILITY: u32 = 6;
    pub const EXCEPTION: u32 = 7;
    pub const SECURITY: u32 = 8;
}

/// What the schema says about one event kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventSpec {
    /// The kind, as `EventKind` numbers it.
    pub kind: u32,
    /// How many of the four payload slots the schema gives a meaning to.
    ///
    /// A slot documented as *reserved* is **not** counted: reserved means the
    /// schema has said what belongs there, and what belongs there is nothing.
    pub args: u8,
    /// The component this kind is filed under.
    pub component: u32,
}

const fn spec(kind: u32, args: u8, component: u32) -> EventSpec {
    EventSpec {
        kind,
        args,
        component,
    }
}

/// Every event kind `kernel_event.isl` defines, with the arity and component
/// its prose states.
///
/// Transcribed from that file, which is the source of truth: where this table
/// and an emitter disagree, one of them is wrong and the disagreement is the
/// finding.
pub const CATALOG: [EventSpec; 45] = [
    spec(1, 3, component::PAGER),         // PagerPageIn
    spec(2, 3, component::PAGER),         // PagerDeadlineMiss
    spec(3, 2, component::PAGER),         // PagerSupervisionEscalate
    spec(4, 2, component::PAGER),         // PagerObjectFaulted
    spec(5, 2, component::MEMORY),        // MemReclaimOverflow
    spec(6, 1, component::OBSERVABILITY), // EventsDropped
    spec(7, 2, component::EXCEPTION),     // UserFaultContained
    spec(8, 2, component::SCHEDULER),     // CorrelationLink
    spec(9, 4, component::DRIVER),        // DeviceWindowMapped
    spec(10, 4, component::DRIVER),       // DeviceWindowRevoked
    spec(11, 3, component::DRIVER),       // DeviceMapRefused
    spec(12, 4, component::DRIVER),       // DeviceDmaGranted
    spec(13, 3, component::DRIVER),       // DeviceReclaimed
    spec(14, 2, component::DRIVER),       // DeviceReclaimLost
    spec(15, 3, component::DRIVER),       // DriverHostCrashed
    spec(16, 3, component::DRIVER),       // DriverHostRestarted
    spec(17, 2, component::DRIVER),       // DriverHostGaveUp
    spec(18, 3, component::DRIVER),       // DeviceDmaUnscoped
    spec(19, 4, component::DRIVER),       // DeviceDmaScoped
    spec(20, 4, component::DRIVER),       // DeviceDmaLeaseBegan
    spec(21, 3, component::DRIVER),       // DeviceDmaLeaseEnded
    spec(22, 4, component::DRIVER),       // DeviceDmaFault
    spec(23, 4, component::DRIVER),       // DeviceDmaIsolated
    spec(24, 4, component::DRIVER),       // DeviceIrqRevoked
    spec(25, 4, component::DRIVER),       // DriverLifecycleTransition
    spec(26, 4, component::DRIVER),       // DriverCrashDump
    spec(27, 4, component::DRIVER),       // DeviceDependentsNotified
    spec(28, 3, component::DRIVER),       // DeviceReset
    spec(29, 3, component::DRIVER),       // DeviceQuarantined
    spec(30, 4, component::MEMORY),       // MemoryGrantRevoked
    spec(31, 4, component::DRIVER),       // DeviceRemoved
    spec(32, 2, component::DRIVER),       // PowerWakeSourceArmed
    spec(33, 4, component::DRIVER),       // PowerWakeEvent
    spec(34, 4, component::DRIVER),       // PowerWakeHoldTaken
    spec(35, 3, component::DRIVER),       // PowerWakeHoldReleased
    spec(36, 2, component::DRIVER),       // PowerSuspendCommitted
    spec(37, 4, component::DRIVER),       // PowerSuspendAborted
    spec(38, 3, component::DRIVER),       // PowerResumed
    spec(39, 4, component::SECURITY),     // StoreMounted
    spec(40, 3, component::SECURITY),     // StoreRefused
    spec(41, 4, component::SECURITY),     // FirmwareLoaded
    spec(42, 4, component::SECURITY),     // FirmwareRefused
    spec(43, 4, component::SECURITY),     // MemoryClassified
    spec(44, 4, component::SECURITY),     // DmaProtectedRefused
    spec(45, 2, component::DRIVER),       // DmaContiguityRefused
];

/// The catalog entry for `kind`, or `None` if the schema does not define it.
pub fn spec_of(kind: u32) -> Option<&'static EventSpec> {
    CATALOG.iter().find(|entry| entry.kind == kind)
}

/// What validating a run of records produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Verdict {
    /// Clauses that were checked and held.
    pub passed: u32,
    /// Clauses that were checked and did not.
    pub failed: u32,
    /// Clauses no record reached.
    ///
    /// Reported, never counted as holding — the discipline
    /// `api/class-conformance` and `api/certification` both keep, and for the
    /// same reason: an empty run must not look like a clean one.
    pub unchecked: u32,
    /// How many records were examined.
    pub examined: u32,
    /// The kind of the first record that broke a clause, so a failure points at
    /// an event rather than at the whole run.
    pub offending_kind: u32,
    /// Its index in the run.
    pub offending_index: u32,
}

impl Verdict {
    /// Whether `clause` was checked and held.
    pub fn passed(&self, clause: Clause) -> bool {
        self.passed & clause.bit() != 0
    }

    /// Whether `clause` was checked and did not hold.
    pub fn failed(&self, clause: Clause) -> bool {
        self.failed & clause.bit() != 0
    }

    /// Whether any record reached `clause`.
    pub fn checked(&self, clause: Clause) -> bool {
        self.passed(clause) || self.failed(clause)
    }

    /// Whether every clause was reached and held — the certification answer.
    ///
    /// Requires records: a run of none reaches no clause, and the honest answer
    /// to "are this driver's events well formed" when there are no events is
    /// not yes.
    pub fn is_complete(&self) -> bool {
        self.failed == 0 && self.unchecked == 0 && self.examined > 0
    }
}

/// Validates a run of emitted records.
pub fn validate(records: &[Record]) -> Verdict {
    let mut verdict = Verdict {
        examined: records.len() as u32,
        ..Verdict::default()
    };
    let fail = |verdict: &mut Verdict, clause: Clause, index: usize, kind: u32| {
        verdict.failed |= clause.bit();
        verdict.passed &= !clause.bit();
        if verdict.offending_kind == 0 {
            verdict.offending_kind = kind;
            verdict.offending_index = index as u32;
        }
    };
    let pass = |verdict: &mut Verdict, clause: Clause| {
        // Never upgrade a failure: one bad record condemns the clause however
        // many good ones follow it.
        if verdict.failed & clause.bit() == 0 {
            verdict.passed |= clause.bit();
        }
    };

    for (index, record) in records.iter().enumerate() {
        if record.size == RECORD_WIRE_SIZE && record.version == SCHEMA_VERSION {
            pass(&mut verdict, Clause::RecordIsTheDeclaredShape);
        } else {
            fail(
                &mut verdict,
                Clause::RecordIsTheDeclaredShape,
                index,
                record.kind,
            );
            // A record of an unknown shape cannot be read further: every clause
            // below reads a field whose offset that shape defines, so
            // continuing would judge a driver on bytes nobody agrees about.
            continue;
        }

        // The fields no decoder can vouch for.
        if record.timestamp != 0 && (record.correlation_lo != 0 || record.correlation_hi != 0) {
            pass(&mut verdict, Clause::EnvelopeIsFilled);
        } else {
            fail(&mut verdict, Clause::EnvelopeIsFilled, index, record.kind);
        }

        let Some(entry) = spec_of(record.kind) else {
            fail(&mut verdict, Clause::KindIsInTheCatalog, index, record.kind);
            // Without an entry there is no arity and no component to compare
            // against, so the two clauses below are genuinely unreachable for
            // this record rather than satisfied by it.
            continue;
        };
        pass(&mut verdict, Clause::KindIsInTheCatalog);

        if record.component == entry.component {
            pass(&mut verdict, Clause::ComponentMatchesTheCatalog);
        } else {
            fail(
                &mut verdict,
                Clause::ComponentMatchesTheCatalog,
                index,
                record.kind,
            );
        }

        let declared = entry.args as usize;
        if record.args[declared..].iter().all(|slot| *slot == 0) {
            pass(&mut verdict, Clause::UndeclaredArgsAreEmpty);
        } else {
            fail(
                &mut verdict,
                Clause::UndeclaredArgsAreEmpty,
                index,
                record.kind,
            );
        }
    }

    // Everything neither passed nor failed was never reached.
    for clause in ALL_CLAUSES {
        if verdict.passed & clause.bit() == 0 && verdict.failed & clause.bit() == 0 {
            verdict.unchecked |= clause.bit();
        }
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record that holds every clause: `DeviceMapRefused`, whose schema gives
    /// three of the four slots a meaning.
    fn good() -> Record {
        Record {
            size: RECORD_WIRE_SIZE,
            version: SCHEMA_VERSION,
            kind: 11,
            severity: 40,
            component: component::DRIVER,
            classification: 0,
            timestamp: 0x1234,
            process_id: 5,
            correlation_lo: 7,
            correlation_hi: 2,
            args: [9, 3, 0x4000, 0],
        }
    }

    #[test]
    fn a_well_formed_record_holds_every_clause() {
        let verdict = validate(&[good()]);
        assert!(verdict.is_complete(), "{verdict:?}");
        for clause in ALL_CLAUSES {
            assert!(verdict.passed(clause), "{clause:?} did not hold");
        }
    }

    /// **The rule the crate keeps with its siblings.** A run of no records
    /// reaches nothing, and reaching nothing is not the same as being fine.
    #[test]
    fn an_empty_run_proves_nothing() {
        let verdict = validate(&[]);
        assert_eq!(verdict.failed, 0, "nothing failed, because nothing ran");
        assert!(!verdict.is_complete(), "and nothing was shown either");
        for clause in ALL_CLAUSES {
            assert!(!verdict.checked(clause));
        }
    }

    /// **The clause a decoder cannot make.** Every enum is valid, the shape is
    /// right, and the record can be ordered against nothing and joined to
    /// nothing.
    #[test]
    fn a_record_with_no_timestamp_or_cause_fails_although_it_decodes() {
        let mut record = good();
        record.timestamp = 0;
        record.correlation_lo = 0;
        record.correlation_hi = 0;
        let verdict = validate(&[record]);
        assert!(verdict.failed(Clause::EnvelopeIsFilled));
        assert!(
            verdict.passed(Clause::KindIsInTheCatalog),
            "the rest of the record is perfectly ordinary, which is the point",
        );
    }

    /// **The clause the catalog exists for.** A value in a slot the schema does
    /// not describe travels without anybody having agreed it should: no
    /// renderer shows it and no reviewer classified it.
    #[test]
    fn a_value_in_an_undeclared_slot_fails() {
        let mut record = good();
        record.args[3] = 0xdead_beef;
        let verdict = validate(&[record]);
        assert!(verdict.failed(Clause::UndeclaredArgsAreEmpty));
        assert_eq!(verdict.offending_kind, 11);
        assert_eq!(verdict.offending_index, 0);
    }

    /// A kind with no entry cannot be rendered: its payload would be printed
    /// under some other kind's meaning, or not at all.
    #[test]
    fn a_kind_the_schema_does_not_define_fails() {
        let mut record = good();
        record.kind = 999;
        let verdict = validate(&[record]);
        assert!(verdict.failed(Clause::KindIsInTheCatalog));
        assert!(
            !verdict.checked(Clause::UndeclaredArgsAreEmpty),
            "unreachable without an arity, and therefore unchecked rather than passed",
        );
    }

    /// A record filed under the wrong component is in a stream nobody reads for
    /// it — `kernel_event.isl` makes exactly this argument about its security
    /// events.
    #[test]
    fn a_record_in_the_wrong_stream_fails() {
        let mut record = good();
        record.component = component::SECURITY;
        let verdict = validate(&[record]);
        assert!(verdict.failed(Clause::ComponentMatchesTheCatalog));
        assert!(verdict.passed(Clause::KindIsInTheCatalog));
    }

    /// A record of another size is from a schema this validator does not know,
    /// and reading its other fields would be reading offsets nobody agrees on.
    #[test]
    fn a_record_of_another_shape_stops_being_read() {
        let mut record = good();
        record.version = 2;
        let verdict = validate(&[record]);
        assert!(verdict.failed(Clause::RecordIsTheDeclaredShape));
        for clause in ALL_CLAUSES {
            if clause == Clause::RecordIsTheDeclaredShape {
                continue;
            }
            assert!(
                !verdict.checked(clause),
                "{clause:?} was judged on bytes of unknown meaning",
            );
        }
    }

    /// One bad record condemns its clause however many good ones follow.
    #[test]
    fn a_later_good_record_does_not_clear_an_earlier_failure() {
        let mut bad = good();
        bad.args[3] = 1;
        let verdict = validate(&[bad, good(), good()]);
        assert!(verdict.failed(Clause::UndeclaredArgsAreEmpty));
        assert_eq!(verdict.examined, 3);
        assert_eq!(verdict.offending_index, 0);
    }

    /// The catalog covers every kind exactly once, and nothing claims more
    /// slots than a record has.
    #[test]
    fn the_catalog_is_one_entry_per_kind() {
        for (i, entry) in CATALOG.iter().enumerate() {
            assert!(entry.args as usize <= ARG_SLOTS, "{entry:?}");
            assert!(entry.kind != 0, "zero names no kind");
            for other in &CATALOG[i + 1..] {
                assert_ne!(entry.kind, other.kind, "duplicate entry for {}", entry.kind);
            }
        }
        assert_eq!(CATALOG.len(), 45);
    }
}
