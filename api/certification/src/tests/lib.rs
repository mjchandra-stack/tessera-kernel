// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

const SUBJECT: Subject = Subject {
    driver: 7,
    class: 10,
    contract_version: 1,
};

fn full_run() -> Runner {
    let mut runner = Runner::new(SUBJECT);
    for check in ALL_CHECKS {
        runner.record(check, Outcome::Passed);
    }
    runner
}

#[test]
fn a_driver_that_passed_everything_is_certified() {
    let certificate = full_run().certificate();
    assert!(certificate.is_certified());
    assert_eq!(certificate.missing(), 0);
    assert_eq!(certificate.failures(), 0);
    for check in ALL_CHECKS {
        assert!(certificate.holds(check), "{check:?} did not hold");
    }
}

/// **The rule the crate exists for.** Nothing failed, because nothing was
/// asked — and that must not read as a clean bill of health.
#[test]
fn a_run_that_asked_nothing_certifies_nothing() {
    let certificate = Runner::new(SUBJECT).certificate();
    assert_eq!(certificate.failures(), 0, "nothing failed");
    assert!(!certificate.is_certified(), "and nothing was shown either");
    assert_eq!(certificate.missing(), ALL);
}

/// The refusal names the checks, so it distinguishes an unfit driver from
/// an absent rig.
#[test]
fn a_refusal_says_which_checks_are_missing() {
    let mut runner = Runner::new(SUBJECT);
    runner.record(Check::AbiConformance, Outcome::Passed);
    runner.record(Check::ClassConformance, Outcome::Passed);
    let certificate = runner.certificate();

    assert!(!certificate.is_certified());
    assert_eq!(certificate.failures(), 0);
    assert!(certificate.holds(Check::AbiConformance));
    assert!(!certificate.holds(Check::Fuzz));

    let missing = certificate.missing();
    assert_eq!(missing.count_ones(), 9);
    assert_eq!(missing & Check::AbiConformance.bit(), 0);
    assert_ne!(missing & Check::PerfRegression.bit(), 0);
}

/// A check that ran and failed is a different fact from one that never ran,
/// and the certificate keeps them apart.
#[test]
fn a_failure_is_not_an_absence() {
    let mut runner = full_run();
    runner.record(Check::Hotplug, Outcome::Failed);
    let certificate = runner.certificate();

    assert!(!certificate.is_certified());
    assert_eq!(certificate.failures(), Check::Hotplug.bit());
    assert_eq!(certificate.missing(), 0, "every check ran");
}

/// Recording `NotRun` is recording nothing — a check that declined to run
/// and a check nobody wrote are indistinguishable, and both block the
/// certificate.
#[test]
fn declining_to_run_a_check_is_the_same_as_never_writing_it() {
    let mut declined = Runner::new(SUBJECT);
    declined.record(Check::DmaFault, Outcome::NotRun);
    assert_eq!(
        declined.certificate(),
        Runner::new(SUBJECT).certificate(),
        "a declined check leaves no trace to mistake for evidence",
    );
    assert_eq!(declined.outcome(Check::DmaFault), Outcome::NotRun);
}

/// **A pass never overwrites a failure.** A rig that re-ran a flaky check
/// until it went green would otherwise certify the last attempt rather than
/// the driver.
#[test]
fn re_running_a_failed_check_does_not_clear_it() {
    let mut runner = full_run();
    runner.record(Check::CrashRecovery, Outcome::Failed);
    runner.record(Check::CrashRecovery, Outcome::Passed);
    runner.record(Check::CrashRecovery, Outcome::Passed);

    assert_eq!(runner.outcome(Check::CrashRecovery), Outcome::Failed);
    assert!(!runner.certificate().is_certified());
}

/// The order is the other half of the rule above: a check that passed and
/// then failed is failed too, which is the direction a naive `|=` gets
/// right and a naive overwrite gets wrong.
#[test]
fn a_check_that_passed_and_then_failed_is_failed() {
    let mut runner = Runner::new(SUBJECT);
    runner.record(Check::Power, Outcome::Passed);
    runner.record(Check::Power, Outcome::Failed);
    assert_eq!(runner.outcome(Check::Power), Outcome::Failed);
}

/// A record claiming a check passed that never ran is not a certificate,
/// and a decoder must be unable to make one.
#[test]
fn a_certificate_cannot_claim_a_check_that_never_ran() {
    assert!(
        Certificate::from_parts(SUBJECT, 0, Check::Fuzz.bit()).is_none(),
        "passed is not a subset of ran",
    );
    assert!(
        Certificate::from_parts(SUBJECT, ALL, ALL).is_some(),
        "the honest maximum decodes",
    );
}

/// A mask with a bit no check owns is a record from a version this one does
/// not understand, and reading it as eleven checks would silently drop what
/// the twelfth said.
#[test]
fn a_record_naming_an_unknown_check_is_refused() {
    let unknown = 1 << 31;
    assert!(Certificate::from_parts(SUBJECT, ALL | unknown, ALL).is_none());
}

/// **The field that is easy to omit.** The same driver, the same class, a
/// later contract — and the certificate is not about it.
#[test]
fn a_certificate_does_not_cover_a_later_contract_version() {
    let certificate = full_run().certificate();
    assert!(certificate.covers(SUBJECT));
    assert!(
        !certificate.covers(Subject {
            contract_version: 2,
            ..SUBJECT
        }),
        "certified against version 1, which is not evidence about version 2",
    );
    assert!(!certificate.covers(Subject {
        class: 1,
        ..SUBJECT
    }));
    assert!(!certificate.covers(Subject {
        driver: 8,
        ..SUBJECT
    }));
}

/// Every check has a tier, and the three that need no machine are the three
/// this tree can run on a host.
#[test]
fn every_check_says_where_it_has_to_run() {
    let component = ALL_CHECKS
        .iter()
        .filter(|c| c.tier() == Tier::Component)
        .count();
    let system = ALL_CHECKS
        .iter()
        .filter(|c| c.tier() == Tier::System)
        .count();
    let performance = ALL_CHECKS
        .iter()
        .filter(|c| c.tier() == Tier::Performance)
        .count();
    assert_eq!(component + system + performance, ALL_CHECKS.len());
    assert_eq!(performance, 1, "only the budgets need a rig");
    assert_eq!(Check::Hotplug.tier(), Tier::System);
}

/// The bits are distinct and all eleven fit the mask the wire carries.
#[test]
fn the_checks_have_distinct_bits() {
    let mut seen = 0u32;
    for check in ALL_CHECKS {
        assert_eq!(seen & check.bit(), 0, "{check:?} reuses a bit");
        seen |= check.bit();
    }
    assert_eq!(seen, ALL);
    assert_eq!(ALL.count_ones(), 11);
}
