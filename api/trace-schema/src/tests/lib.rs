// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

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
