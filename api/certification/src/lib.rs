// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Driver certification**: the checks a driver must pass, and a record that
//! cannot be issued on absence.
//!
//! `docs/drivers/01-driver-framework.md` ("Certification") lists ten checks and
//! one consequence — *"certified drivers can be distributed through signed
//! update channels"*. Most of the ten already have a mechanism somewhere in
//! this tree: surprise removal is scripted over QMP, a translation fault is
//! harvested and ends a lease, power votes are arbitrated and clamped, a driver
//! host is restarted and re-bound. What none of them produces is a **verdict
//! about a driver**, and a distribution channel needs one.
//!
//! # The one rule the rest is built around
//!
//! **A check nobody ran must never look like a check that passed.**
//!
//! That is not a hypothetical failure. The checks this tree already has are
//! shell scripts registered by hand in a `BUILD.bazel` file; delete a
//! registration and every remaining test still passes, so the tree reports
//! success for a question it stopped asking. A suite cannot notice this about
//! itself, because from the inside a check that was removed and a check that
//! never existed are the same absence.
//!
//! So [`Outcome::NotRun`] is a first-class answer, [`Certificate::is_certified`]
//! requires every check to have *run* as well as passed, and
//! [`Certificate::missing`] names the ones that did not — which makes the
//! refusal informative rather than merely negative. A certificate is evidence
//! that somebody asked, not just that nothing objected.
//!
//! # Why the record names its subject
//!
//! A certificate carries the driver, the class it was certified for, and the
//! **contract version** it was certified against. The third field is the one
//! that is easy to leave out and expensive to lack: a driver certified against
//! version 1 of its class and later shipped implementing version 2 has a
//! perfectly valid certificate for a contract it no longer implements, and
//! without the version recorded there is nothing in the record that could ever
//! say so. [`Certificate::covers`] is how a channel asks.
//!
//! # Why this is a rules crate and not a test runner
//!
//! For the reason `api/class-conformance` is: the rules must run where the
//! driver is and where the driver cannot be. Host tests drive them through
//! outcomes no real run would produce on demand — a check that passed after
//! failing, a certificate claiming a check that never ran — and a boot check
//! feeds them what a real machine actually observed. A crate that owned the
//! *running* would be usable only where it could run everything, which is
//! nowhere.
//!
//! `no_std`, dependency-free and allocation-free: eleven checks fit in a
//! bitmask, so the same code judges a driver in a host test and inside a ring-3
//! program with no allocator.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Certification"),
//! docs/lifecycle/02-build-and-test-infrastructure.md ("Test Tiers")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// One question certification asks about a driver.
///
/// Ten of these are `docs/drivers/01`'s list verbatim. The eleventh is
/// [`Check::ClassConformance`], which that document names separately as the
/// tenth element of a class contract rather than as a certification item — and
/// the two are genuinely different questions. `api/class-conformance`'s own
/// header states why: a driver can encode every struct perfectly and violate
/// every class rule, and can obey every class rule while disagreeing with its
/// client about a field offset. Certifying on either alone would certify half a
/// driver.
///
/// Values are a record's contents once [`Certificate`] goes on the wire: append
/// only, never renumbered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Check {
    /// The driver's structs encode to the bytes its schema defines.
    AbiConformance = 1,
    /// The driver obeys the rules its class contract states.
    ClassConformance = 2,
    /// Every parser of external input has a fuzz target, and it survives it.
    Fuzz = 3,
    /// The device works *after* a resume, not merely during one.
    SuspendResume = 4,
    /// Surprise removal is answered rather than waited out.
    Hotplug = 5,
    /// A refused DMA transaction is reported rather than retried.
    DmaFault = 6,
    /// The driver votes for a power state and honours an arbitrated answer.
    Power = 7,
    /// A killed driver host leaves no client waiting forever.
    CrashRecovery = 8,
    /// The rights the driver holds are the rights its manifest declared.
    SecurityPolicy = 9,
    /// No budget regressed past the gate.
    PerfRegression = 10,
    /// Every event the driver emitted decodes against its declared schema.
    TraceSchema = 11,
}

/// Every check, so a caller can iterate without knowing the count.
pub const ALL_CHECKS: [Check; 11] = [
    Check::AbiConformance,
    Check::ClassConformance,
    Check::Fuzz,
    Check::SuspendResume,
    Check::Hotplug,
    Check::DmaFault,
    Check::Power,
    Check::CrashRecovery,
    Check::SecurityPolicy,
    Check::PerfRegression,
    Check::TraceSchema,
];

/// Every check's bit set — what a complete run reaches.
pub const ALL: u32 = {
    let mut mask = 0;
    let mut i = 0;
    while i < ALL_CHECKS.len() {
        mask |= 1 << ALL_CHECKS[i] as u32;
        i += 1;
    }
    mask
};

/// Where a check has to run, in the vocabulary `docs/lifecycle/02` already
/// uses.
///
/// Recorded rather than inferred because it is the reason the eleven cannot be
/// one test target: four of them are arithmetic over captured data and run on a
/// host, six need a machine that can be interfered with from outside, and one
/// needs a measurement rig. A certificate that says nine checks did not run is
/// more useful when it can also say which of them nobody could have run here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Tier {
    /// Tier 2 — component and conformance: judged from captured data on a host.
    Component = 2,
    /// Tier 3 — system integration: needs a running machine and something
    /// outside it causing an event.
    System = 3,
    /// Tier 4 — performance: needs a measurement rig.
    Performance = 4,
}

impl Check {
    /// This check's bit in the masks a [`Certificate`] carries.
    pub const fn bit(self) -> u32 {
        1 << self as u32
    }

    /// What to call this check when refusing on it.
    ///
    /// A refusal that named only a bit number would leave whoever received it
    /// unable to act: the point of `missing()` is to distinguish an unfit
    /// driver from a rig that stopped asking, and that distinction is only
    /// useful if the answer says *which* rig.
    pub const fn name(self) -> &'static str {
        match self {
            Check::AbiConformance => "abi-conformance",
            Check::ClassConformance => "class-conformance",
            Check::Fuzz => "fuzz",
            Check::SuspendResume => "suspend-resume",
            Check::Hotplug => "hotplug",
            Check::DmaFault => "dma-fault",
            Check::Power => "power",
            Check::CrashRecovery => "crash-recovery",
            Check::SecurityPolicy => "security-policy",
            Check::PerfRegression => "perf-regression",
            Check::TraceSchema => "trace-schema",
        }
    }

    /// The tier this check belongs to.
    pub const fn tier(self) -> Tier {
        match self {
            Check::AbiConformance | Check::ClassConformance | Check::Fuzz | Check::TraceSchema => {
                Tier::Component
            }
            Check::SuspendResume
            | Check::Hotplug
            | Check::DmaFault
            | Check::Power
            | Check::CrashRecovery
            | Check::SecurityPolicy => Tier::System,
            Check::PerfRegression => Tier::Performance,
        }
    }
}

/// What running a check produced.
///
/// Three values and not two. A bare `bool` would force the caller to encode
/// "did not run" as a failure or as a pass, and both are wrong in ways that
/// matter: as a failure it blames a driver for a rig that was absent, and as a
/// pass it is the forgery this crate exists to make impossible.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u32)]
pub enum Outcome {
    /// Nobody asked. **Not a pass**, and never becomes one.
    #[default]
    NotRun = 0,
    /// Asked and answered correctly.
    Passed = 1,
    /// Asked and answered wrongly.
    Failed = 2,
}

impl Outcome {
    /// A check that ran, with `passed` deciding which way.
    ///
    /// The named door for the common case, so a caller that *did* run something
    /// never has to touch [`Outcome::NotRun`] and cannot reach it by accident.
    pub const fn ran(passed: bool) -> Self {
        if passed {
            Outcome::Passed
        } else {
            Outcome::Failed
        }
    }
}

/// What is being certified.
///
/// All three fields, every time. A certificate for "the block driver" says
/// nothing a channel can act on unless it also says which class contract and
/// which version of it — see [`Certificate::covers`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Subject {
    /// The driver, as its binding manifest names it.
    pub driver: u32,
    /// The class it was certified for, as `driver_bind.isl`'s `DeviceClass`
    /// numbers them.
    pub class: u32,
    /// The major version of that class contract.
    pub contract_version: u32,
}

/// Accumulates outcomes for one subject.
///
/// One subject per runner, by construction. A runner that could be handed
/// results for two drivers would be one bookkeeping mistake away from
/// certifying a driver with another driver's evidence, and no field in the
/// resulting certificate would record that it had happened.
#[derive(Clone, Copy, Debug)]
pub struct Runner {
    subject: Subject,
    ran: u32,
    passed: u32,
}

impl Runner {
    /// A runner with nothing recorded — which certifies nothing.
    pub const fn new(subject: Subject) -> Self {
        Runner {
            subject,
            ran: 0,
            passed: 0,
        }
    }

    /// Records what a check produced.
    ///
    /// **A failure is never undone.** Recording the same check twice takes the
    /// worse of the two answers, so a runner that re-ran a check until it
    /// passed certifies the driver it actually observed rather than the last
    /// attempt. Flakiness is a property of the driver under test as much as of
    /// the rig, and a runner that quietly kept the best result would erase the
    /// only evidence of it.
    ///
    /// [`Outcome::NotRun`] records nothing at all: a check that declined to run
    /// and a check nobody wrote are the same fact here, and both block a
    /// certificate.
    pub fn record(&mut self, check: Check, outcome: Outcome) {
        match outcome {
            Outcome::NotRun => {}
            Outcome::Passed => {
                // Read the verdict before recording this run, or marking the
                // check as having run makes it indistinguishable from one that
                // ran and failed.
                let already_failed = self.ran & !self.passed & check.bit() != 0;
                self.ran |= check.bit();
                if !already_failed {
                    self.passed |= check.bit();
                }
            }
            Outcome::Failed => {
                self.ran |= check.bit();
                self.passed &= !check.bit();
            }
        }
    }

    /// What has been recorded for `check` so far.
    pub fn outcome(&self, check: Check) -> Outcome {
        if self.ran & check.bit() == 0 {
            Outcome::NotRun
        } else {
            Outcome::ran(self.passed & check.bit() != 0)
        }
    }

    /// The record of this run.
    pub const fn certificate(&self) -> Certificate {
        Certificate {
            subject: self.subject,
            ran: self.ran,
            passed: self.passed,
        }
    }
}

/// What a run of the checks proved about one driver.
///
/// The fields are private and the two doors in are narrow on purpose. The
/// invariant worth protecting is `passed ⊆ ran`: a record claiming a check
/// passed that never ran is exactly the forgery this crate exists to prevent,
/// and once such a record exists nothing downstream can tell it from a real
/// one. [`Certificate::from_parts`] refuses to build one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Certificate {
    subject: Subject,
    ran: u32,
    passed: u32,
}

impl Certificate {
    /// Rebuilds a certificate from a decoded record, or `None` if it claims a
    /// check that never ran.
    ///
    /// The check a decoder needs and cannot skip. A certificate arrives from
    /// somewhere — a store, a channel manifest, another machine — and the
    /// bytes carry two independent masks, so a self-contradictory pair is
    /// representable on the wire whatever the encoder intended.
    pub const fn from_parts(subject: Subject, ran: u32, passed: u32) -> Option<Self> {
        if passed & !ran != 0 || ran & !ALL != 0 {
            return None;
        }
        Some(Certificate {
            subject,
            ran,
            passed,
        })
    }

    /// What this certificate is about.
    pub const fn subject(&self) -> Subject {
        self.subject
    }

    /// The checks that ran, as a bitmask of [`Check::bit`].
    pub const fn ran(&self) -> u32 {
        self.ran
    }

    /// The checks that ran and passed.
    pub const fn passed(&self) -> u32 {
        self.passed
    }

    /// The checks that ran and did not pass.
    pub const fn failures(&self) -> u32 {
        self.ran & !self.passed
    }

    /// The checks nobody ran.
    ///
    /// What makes a refusal worth reading: a channel told only "not certified"
    /// learns that the driver is unfit, while one told *which* checks are
    /// missing learns whether the driver is unfit or the rig is.
    pub const fn missing(&self) -> u32 {
        ALL & !self.ran
    }

    /// Whether `check` ran and passed.
    pub const fn holds(&self, check: Check) -> bool {
        self.passed & check.bit() != 0
    }

    /// **The certification answer.** Every check ran, and every check passed.
    pub const fn is_certified(&self) -> bool {
        self.ran == ALL && self.passed == ALL
    }

    /// Whether this certificate is evidence about `subject`.
    ///
    /// Exact on all three fields, including the contract version. A driver that
    /// moved to a later contract has not been certified against it, however
    /// thoroughly it was certified against the earlier one — the checks were
    /// run against different required ordinals, a different feature set and a
    /// different error range, so what they showed is about a contract this
    /// driver no longer implements.
    pub const fn covers(&self, subject: Subject) -> bool {
        self.subject.driver == subject.driver
            && self.subject.class == subject.class
            && self.subject.contract_version == subject.contract_version
    }
}

#[cfg(test)]
mod tests {
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
}
