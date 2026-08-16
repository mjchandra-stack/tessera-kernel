// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the certification record, and the cross-check that
//! keeps it agreeing with the rules that produce it.
//!
//! Two things are checked here and they are different. The ABI tests ask
//! whether the bytes are what the schema says. The **cross-check** asks whether
//! `api/certification`'s judgement and `certification.isl`'s wire format still
//! describe the same eleven checks — because they are declared twice, in two
//! languages, and nothing but a test walks both.
//!
//! The cross-check is written as two exhaustive `match` expressions rather than
//! a table of pairs. A table catches drift when somebody runs the test; a total
//! match catches it when somebody *builds*, because adding a check to either
//! declaration and not the other stops compiling. That is the difference
//! between a check that is enforced and one that is available.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Certification"),
//! docs/api/03-interface-schema-language.md

use certification::{CertificateDigest, CertificationCheck, CheckOutcome, CheckTier};
use tessera_certification::{ALL, ALL_CHECKS, Certificate as Verdict, Check, Subject, Tier};
use tessera_isl_runtime::{decode, encode};

/// The wire enum for a check the rules crate judges.
///
/// Exhaustive: a twelfth [`Check`] stops this compiling until the schema has
/// one too.
fn on_the_wire(check: Check) -> CertificationCheck {
    match check {
        Check::AbiConformance => CertificationCheck::AbiConformance,
        Check::ClassConformance => CertificationCheck::ClassConformance,
        Check::Fuzz => CertificationCheck::Fuzz,
        Check::SuspendResume => CertificationCheck::SuspendResume,
        Check::Hotplug => CertificationCheck::Hotplug,
        Check::DmaFault => CertificationCheck::DmaFault,
        Check::Power => CertificationCheck::Power,
        Check::CrashRecovery => CertificationCheck::CrashRecovery,
        Check::SecurityPolicy => CertificationCheck::SecurityPolicy,
        Check::PerfRegression => CertificationCheck::PerfRegression,
        Check::TraceSchema => CertificationCheck::TraceSchema,
    }
}

/// And back, which is the half that catches a check added to the schema and
/// never judged by anything.
fn in_the_rules(check: CertificationCheck) -> Check {
    match check {
        CertificationCheck::AbiConformance => Check::AbiConformance,
        CertificationCheck::ClassConformance => Check::ClassConformance,
        CertificationCheck::Fuzz => Check::Fuzz,
        CertificationCheck::SuspendResume => Check::SuspendResume,
        CertificationCheck::Hotplug => Check::Hotplug,
        CertificationCheck::DmaFault => Check::DmaFault,
        CertificationCheck::Power => Check::Power,
        CertificationCheck::CrashRecovery => Check::CrashRecovery,
        CertificationCheck::SecurityPolicy => Check::SecurityPolicy,
        CertificationCheck::PerfRegression => Check::PerfRegression,
        CertificationCheck::TraceSchema => Check::TraceSchema,
    }
}

/// **The cross-check.** Same checks, same numbers, both directions.
///
/// The numbers are what actually matters: the masks a certificate carries are
/// built from `1 << check`, so a check that is numbered 6 in the rules and 7 on
/// the wire produces a record in which every reader agrees about the bytes and
/// disagrees about which check passed.
#[test]
fn the_wire_and_the_rules_number_the_checks_identically() {
    for check in ALL_CHECKS {
        let wire = on_the_wire(check);
        assert_eq!(
            wire as u32, check as u32,
            "{check:?} is numbered differently on the wire",
        );
        assert_eq!(
            in_the_rules(wire),
            check,
            "the round trip is not the identity"
        );
    }
}

/// The outcome that claims nothing is the one a zeroed record decodes to.
///
/// A producer that filled every field but this one, or a buffer that was never
/// written, must not read as a driver that passed.
#[test]
fn a_zeroed_outcome_claims_nothing() {
    assert_eq!(CheckOutcome::NotRun as u32, 0);
    assert_eq!(CheckOutcome::Passed as u32, 1);
    assert_eq!(CheckOutcome::Failed as u32, 2);
}

/// Tiers are numbered by the tier they name, and agree with the rules crate.
#[test]
fn the_tiers_are_the_documents_tiers() {
    assert_eq!(CheckTier::Component as u32, 2);
    assert_eq!(CheckTier::System as u32, 3);
    assert_eq!(CheckTier::Performance as u32, 4);
    for check in ALL_CHECKS {
        let wire = match check.tier() {
            Tier::Component => CheckTier::Component,
            Tier::System => CheckTier::System,
            Tier::Performance => CheckTier::Performance,
        };
        assert_eq!(wire as u32, check.tier() as u32, "{check:?} moved tier");
    }
}

/// The record a completed run produces, there and back.
#[test]
fn a_certificate_round_trips() {
    let value = certification::Certificate {
        size: certification::Certificate::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        driver: 7,
        device_class: 10,
        contract_version: 1,
        ran: ALL,
        passed: ALL,
        digest_algorithm: CertificateDigest::Sha256,
        image: [0xa5; 32],
    };
    let mut bytes = [0u8; certification::Certificate::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<certification::Certificate>(&bytes).expect("decode");
    assert_eq!(back, value);
    assert_eq!(
        certification::Certificate::WIRE_SIZE,
        72,
        "a header, a subject, two masks and a measurement",
    );
}

/// **A record that arrived zeroed certifies nothing**, which is the property the
/// masks were shaped for: bit zero belongs to no check, so an empty mask means
/// "nothing ran" and cannot be read as "check zero ran".
#[test]
fn a_zeroed_record_certifies_nothing() {
    let blank = [0u8; certification::Certificate::WIRE_SIZE];
    let record = decode::<certification::Certificate>(&blank).expect("a zeroed record decodes");
    assert_eq!(record.ran, 0);
    assert_eq!(record.passed, 0);
    assert_eq!(record.digest_algorithm, CertificateDigest::None);

    let verdict = Verdict::from_parts(subject_of(&record), record.ran, record.passed)
        .expect("an empty record is honest, merely empty");
    assert!(!verdict.is_certified());
    assert_eq!(verdict.missing(), ALL, "every check is still to be asked");
}

/// **The one self-contradiction the wire can express.** The two masks are
/// independent fields, so a record claiming a check passed that never ran is
/// representable whatever produced it — and a decoder that accepted it would
/// hand downstream a forgery it could not tell from a certificate.
#[test]
fn a_record_claiming_a_check_that_never_ran_is_refused() {
    let value = certification::Certificate {
        size: certification::Certificate::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        driver: 7,
        device_class: 10,
        contract_version: 1,
        // Nothing ran, and everything passed.
        ran: 0,
        passed: ALL,
        digest_algorithm: CertificateDigest::None,
        image: [0; 32],
    };
    let mut bytes = [0u8; certification::Certificate::WIRE_SIZE];
    encode(&value, &mut bytes).expect("the bytes are perfectly well formed");
    let record = decode::<certification::Certificate>(&bytes).expect("and they decode");

    assert!(
        Verdict::from_parts(subject_of(&record), record.ran, record.passed).is_none(),
        "well-formed bytes are not the same thing as a certificate",
    );
}

/// A certificate that measured nothing is evidence about the checks and about
/// no bytes. It is a legitimate record — a runner with no artifact in front of
/// it produces one — and the algorithm field is what makes the absence
/// something a channel can act on rather than something it has to infer.
#[test]
fn a_certificate_that_measured_nothing_names_no_artifact() {
    let value = certification::Certificate {
        size: certification::Certificate::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        driver: 7,
        device_class: 10,
        contract_version: 1,
        ran: ALL,
        passed: ALL,
        digest_algorithm: CertificateDigest::None,
        image: [0; 32],
    };
    let mut bytes = [0u8; certification::Certificate::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let record = decode::<certification::Certificate>(&bytes).expect("decode");

    let verdict = Verdict::from_parts(subject_of(&record), record.ran, record.passed)
        .expect("the outcomes are consistent");
    assert!(
        verdict.is_certified(),
        "every check ran and passed, which is what the rules judge",
    );
    assert_eq!(
        record.digest_algorithm,
        CertificateDigest::None,
        "and it says, in a field rather than by omission, that it measured nothing",
    );
}

/// The subject travels with the verdict, contract version included — so a
/// certificate decoded somewhere else can still be asked what it is about.
#[test]
fn the_subject_survives_the_wire() {
    let value = certification::Certificate {
        size: certification::Certificate::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        driver: 7,
        device_class: 10,
        contract_version: 1,
        ran: ALL,
        passed: ALL,
        digest_algorithm: CertificateDigest::Sha256,
        image: [0x11; 32],
    };
    let mut bytes = [0u8; certification::Certificate::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let record = decode::<certification::Certificate>(&bytes).expect("decode");

    let verdict = Verdict::from_parts(subject_of(&record), record.ran, record.passed)
        .expect("consistent outcomes");
    assert!(verdict.covers(subject_of(&record)));
    assert!(
        !verdict.covers(Subject {
            contract_version: 2,
            ..subject_of(&record)
        }),
        "certified against version 1, and not evidence about version 2",
    );
}

fn subject_of(record: &certification::Certificate) -> Subject {
    Subject {
        driver: record.driver,
        class: record.device_class,
        contract_version: record.contract_version,
    }
}
