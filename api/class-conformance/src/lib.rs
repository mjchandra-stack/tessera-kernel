// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **class conformance suite**: whether a driver honours its class
//! contract, as distinct from whether its bytes match the schema.
//!
//! `docs/drivers/01-driver-framework.md` lists "conformance tests" as the tenth
//! element of a class contract, and separately requires "ABI conformance" as
//! one item of driver certification — two different things that the tree
//! previously had one of. The ABI tests (`//api/isl:*_conformance_test`) ask
//! whether a struct encodes to the right bytes. This asks whether a *driver*
//! obeys the rules the contract states in prose and enums: that every required
//! method is answered, that an unimplemented optional one says so in the one
//! way the contract permits, that errors come from the closed set, that a
//! reset leaves what a reset is defined to leave, and that a vendor method is
//! unreachable until its namespace has been negotiated.
//!
//! **Neither implies the other**, which is why both exist. A driver can encode
//! every struct perfectly and violate every rule here; a driver can obey every
//! rule while disagreeing with its client about a field offset.
//!
//! # Why a transcript
//!
//! The suite reads a **transcript** — the sequence of calls a client made and
//! the answers it got — rather than calling a driver itself. That is what lets
//! the same rules run in two places that cannot share a caller: host tests
//! drive it with synthetic transcripts, including ones no real driver would
//! produce, and a boot check feeds it what a real ring-3 client actually
//! observed. A suite that owned the calling would be testable only where it
//! could call, which on this system means only at boot, where the failures
//! worth checking cannot be provoked.
//!
//! It also means the suite is honest about its reach: it can only judge what
//! the client exercised. [`Report::coverage`] says which clauses were reached,
//! so a transcript that never called `Reset` reports the reset clause as
//! *unchecked* rather than as passing.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts",
//! "Certification")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// Ordinals at or above this belong to a vendor extension namespace.
///
/// The boundary `docs/drivers/01`'s *"vendor-private methods are allowed only
/// through explicitly versioned extension namespaces"* needs in order to be
/// checkable. A framework-wide constant rather than a per-class one, because
/// both class contracts state the same rule and a class that chose its own
/// boundary would make the rule unenforceable in general.
pub const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// One call a client made and what came back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Exchange {
    /// The method ordinal the client invoked.
    pub ordinal: u32,
    /// The status the driver replied with, as the contract's error enum
    /// numbers them.
    ///
    /// Deliberately a `u32` and not the generated enum: a driver returning a
    /// value outside the closed set is precisely what
    /// [`Rule::ErrorsAreInTheClosedSet`] exists to catch, and a strict enum
    /// would refuse to decode it — leaving the suite unable to see the failure
    /// it is for.
    pub status: u32,
    /// Whether the driver answered at all. `false` is a call that timed out or
    /// was refused by the transport, which is a different failure from an
    /// error status and must not be read as one.
    pub answered: bool,
    /// A reason-specific observation, interpreted per rule: the power state a
    /// control method left the device in, the byte count a write reported.
    pub detail: u32,
}

/// What a class contract requires of a driver, as a checkable list.
///
/// One variant per clause rather than a single pass/fail, because a report
/// naming which clause failed is the difference between a conformance suite
/// and a smoke test.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Rule {
    /// Every method the contract marks required was called and answered.
    RequiredMethodsAnswered = 1,
    /// Every status the driver returned is in the contract's closed error set.
    ErrorsAreInTheClosedSet = 2,
    /// A method whose feature bit is clear answered `NOT_SUPPORTED`, and
    /// nothing else.
    ///
    /// **Both halves matter.** A driver that answered an unimplemented method
    /// with a generic I/O error would leave a client unable to tell "this
    /// driver cannot" from "this attempt failed" — and one that *succeeded* at
    /// a method it did not advertise is worse, because a client's feature
    /// check is then meaningless.
    UnsupportedOptionalsSaySo = 3,
    /// A method whose feature bit is set did not answer `NOT_SUPPORTED`. The
    /// converse of the rule above, and it fails on the other kind of lying
    /// `Describe`.
    AdvertisedOptionalsWork = 4,
    /// A reset left the device in the state the contract defines — `ACTIVE`
    /// power state, for both classes.
    ResetLeavesTheDefinedState = 5,
    /// A method in the vendor ordinal range was refused while no namespace was
    /// negotiated.
    VendorMethodsNeedANamespace = 6,
    /// The driver reported a contract version the client understands.
    ContractVersionIsUnderstood = 7,
}

/// Every rule, so a caller can iterate without knowing the count.
pub const ALL_RULES: [Rule; 7] = [
    Rule::RequiredMethodsAnswered,
    Rule::ErrorsAreInTheClosedSet,
    Rule::UnsupportedOptionalsSaySo,
    Rule::AdvertisedOptionalsWork,
    Rule::ResetLeavesTheDefinedState,
    Rule::VendorMethodsNeedANamespace,
    Rule::ContractVersionIsUnderstood,
];

/// What a class expects, so one checker serves both contracts.
///
/// The two class contracts differ in their ordinals, their error sets and
/// their feature bits, and agree on every *rule*. Passing the differences in as
/// data rather than writing a checker per class is what makes "the shape
/// generalises" a property the code demonstrates rather than a claim the
/// comments make.
#[derive(Clone, Copy)]
pub struct ClassSpec {
    /// Ordinals a conformant driver must answer.
    pub required: &'static [u32],
    /// Optional ordinals and the feature bit each is gated by.
    pub optional: &'static [(u32, u64)],
    /// The largest status value the contract's error enum defines. Statuses
    /// above it are outside the closed set.
    pub max_error: u32,
    /// The status a driver must use for an unimplemented optional method.
    pub not_supported: u32,
    /// The reset method's ordinal.
    pub reset_ordinal: u32,
    /// The power state a reset is defined to leave.
    pub state_after_reset: u32,
    /// The contract major version this client understands.
    pub contract_version: u32,
}

/// The block class, as the checker sees it.
pub const BLOCK: ClassSpec = ClassSpec {
    // Describe, Read, Reset, SetPower.
    required: &[1, 2, 5, 6],
    // Write gated by WRITE, Flush by FLUSH, Discard by DISCARD, and the
    // out-of-line pair by OUT_OF_LINE. `WriteFrom` is listed against
    // OUT_OF_LINE alone even though it also needs WRITE: the rule this table
    // drives is "advertised means implemented", and a driver that advertises
    // OUT_OF_LINE without WRITE answers it with READ_ONLY — an answer, which
    // is what the rule asks for, rather than NOT_SUPPORTED.
    optional: &[(3, 0x1), (4, 0x2), (7, 0x4), (10, 0x10), (11, 0x10)],
    // BlockError::Removed — the highest value the contract defines, and what
    // "a driver returned something outside the set" is measured against.
    max_error: 8,
    // BlockError::NotSupported.
    not_supported: 5,
    reset_ordinal: 5,
    // BlockPowerState::Active.
    state_after_reset: 1,
    contract_version: 1,
};

/// The network class. Same rules, different ordinals and bits — which is the
/// whole argument for the checker taking a spec.
pub const NETWORK: ClassSpec = ClassSpec {
    // Describe, Reset, SetPower.
    required: &[1, 3, 4],
    // Transmit gated by TRANSMIT, SetPromiscuous by PROMISCUOUS.
    optional: &[(2, 0x1), (5, 0x2)],
    // NetError::Removed.
    max_error: 8,
    not_supported: 5,
    reset_ordinal: 3,
    // NetPowerState::Active.
    state_after_reset: 1,
    contract_version: 1,
};

/// The clock controller class. **The third, and it needed no new rule** — which
/// is the finding rather than a convenience.
///
/// Two classes agreeing on a shape can be a coincidence of both being storage
/// and networking, which move data through queues and are more alike than they
/// look. This one moves nothing at all: every method carries a clock id and a
/// number. It still has required methods, optionals gated by feature bits, a
/// closed error set, a defined reset state and a vendor namespace — so the
/// rules that judge a block driver judge it unchanged, and the spec is the only
/// thing that differs.
pub const CLOCK: ClassSpec = ClassSpec {
    // Describe, Enable, Reset, SetPower, GetRate.
    required: &[1, 2, 5, 6, 8],
    // Disable gated by DISABLE, SetRate by SET_RATE, SetParent by MUX.
    optional: &[(3, 0x2), (4, 0x1), (7, 0x4)],
    // ClockError::Removed.
    max_error: 8,
    // ClockError::NotSupported — the same value on all three classes, which is
    // what lets one rule read it wherever it runs.
    not_supported: 5,
    reset_ordinal: 5,
    // ClockPowerState::Active.
    state_after_reset: 1,
    contract_version: 1,
};

/// The input class. The fourth, and the one that shows the rules do not know
/// what kind of device they are judging: nothing below mentions a keyboard, and
/// the only thing that changed is which ordinals are required.
pub const INPUT: ClassSpec = ClassSpec {
    // Describe, Poll, Reset, SetPower.
    required: &[1, 2, 5, 6],
    // SetReport gated by SET_REPORT, GetReport by GET_REPORT.
    optional: &[(3, 0x1), (4, 0x2)],
    // InputError::Removed.
    max_error: 8,
    // InputError::NotSupported — the same value on all four classes.
    not_supported: 5,
    reset_ordinal: 5,
    // InputPowerState::Active.
    state_after_reset: 1,
    contract_version: 1,
};

/// The GPIO class. The fifth, and the one whose optional methods span the two
/// halves of the rule at once: this controller drives and interrupts and has no
/// electrical control at all, so one transcript reaches both "advertised means
/// implemented" and "unadvertised means says so".
pub const GPIO: ClassSpec = ClassSpec {
    // Describe, ConfigureLine, Read, Reset, SetPower, ReleaseLine.
    required: &[1, 2, 3, 5, 6, 8],
    // Write gated by OUTPUT, WatchLine by INTERRUPTS, SetElectrical by
    // ELECTRICAL.
    optional: &[(4, 0x1), (7, 0x2), (9, 0x4)],
    // GpioError::Removed.
    max_error: 8,
    // GpioError::NotSupported — the same value on all five classes.
    not_supported: 5,
    reset_ordinal: 5,
    // GpioPowerState::Active.
    state_after_reset: 1,
    contract_version: 1,
};

/// The audio class. The sixth, and the one whose distinguishing value is an
/// *outcome* rather than a failure: a stream that ran dry answers `UNDERRUN`
/// and is still running, so the suite's "answered within the closed set" rule
/// counts it as a pass exactly as it counts an idle keyboard's `NO_REPORT`.
pub const AUDIO: ClassSpec = ClassSpec {
    // Describe, Configure, Start, Write, Reset, SetPower, Status.
    required: &[1, 2, 3, 4, 5, 6, 8],
    // Stop gated by PAUSE, SetVolume by VOLUME.
    optional: &[(7, 0x1), (9, 0x2)],
    // AudioError::Removed.
    max_error: 8,
    // AudioError::NotSupported — the same value on all six classes.
    not_supported: 5,
    reset_ordinal: 5,
    // AudioPowerState::Active.
    state_after_reset: 1,
    contract_version: 1,
};

/// The display class. The seventh, and the one whose interesting value —
/// `NO_SCANOUT` — is a state rather than a failure, as `NO_MEDIUM`,
/// `NO_REPORT` and `UNDERRUN` are on the classes before it.
pub const DISPLAY: ClassSpec = ClassSpec {
    // Describe, Blit, Flush, Reset, SetPower.
    required: &[1, 2, 3, 5, 6],
    // Fill gated by FILL, SetCursor by CURSOR.
    optional: &[(4, 0x1), (7, 0x2)],
    // DisplayError::Removed.
    max_error: 8,
    // DisplayError::NotSupported — the same value on all seven classes.
    not_supported: 5,
    reset_ordinal: 5,
    // DisplayPowerState::Active.
    state_after_reset: 1,
    contract_version: 1,
};

/// The crypto class. The eighth, and the first whose *refusals* are the
/// interesting behaviour: `NOT_SUPPORTED` here means an algorithm was named and
/// not performed, which is correct and is what the whole contract is shaped to
/// make possible. `NO_SESSION` is its "state rather than a failure" value, as
/// `NO_MEDIUM`, `NO_REPORT`, `UNDERRUN` and `NO_SCANOUT` are on the classes
/// before it.
pub const CRYPTO: ClassSpec = ClassSpec {
    // Describe, CreateSession, Encrypt, Reset, SetPower, DestroySession.
    // DestroySession is required, not optional: a session holds a key, and a
    // class where letting go of one was optional would have drivers that never
    // did.
    required: &[1, 2, 3, 5, 6, 7],
    // Decrypt gated by DECRYPT, SetIv by PER_MESSAGE_IV.
    optional: &[(4, 0x1), (8, 0x4)],
    // CryptoError::Removed.
    max_error: 8,
    // CryptoError::NotSupported — the same value on all eight classes.
    not_supported: 5,
    reset_ordinal: 5,
    // CryptoPowerState::Active.
    state_after_reset: 1,
    contract_version: 1,
};

/// What the driver said about itself, which most of the rules are relative to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Described {
    pub contract_version: u32,
    pub features: u64,
    /// The vendor extension namespace the driver declared, or zero for none.
    pub vendor: u32,
}

/// The outcome of running the suite.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Report {
    /// Rules that were checked and held, as a bitmask of `1 << Rule`.
    pub passed: u32,
    /// Rules that were checked and did not.
    pub failed: u32,
    /// Rules the transcript did not reach.
    ///
    /// **Reported, never counted as passing.** A suite that treated an
    /// unexercised clause as satisfied would give a driver a clean report for
    /// the methods nobody called, which is the failure mode a conformance
    /// suite exists to prevent rather than to have.
    pub unchecked: u32,
    /// The first ordinal that broke a rule, so a failure points at a method
    /// rather than at the whole run.
    pub offending_ordinal: u32,
    /// The status that broke it.
    pub offending_status: u32,
}

impl Report {
    /// Whether `rule` was checked and held.
    pub fn passed(&self, rule: Rule) -> bool {
        self.passed & (1 << rule as u32) != 0
    }

    /// Whether `rule` was checked and failed.
    pub fn failed(&self, rule: Rule) -> bool {
        self.failed & (1 << rule as u32) != 0
    }

    /// Whether the transcript exercised `rule` at all.
    pub fn checked(&self, rule: Rule) -> bool {
        self.passed(rule) || self.failed(rule)
    }

    /// Which rules the transcript reached, as a bitmask.
    pub fn coverage(&self) -> u32 {
        self.passed | self.failed
    }

    /// Whether the driver is conformant **as far as this transcript went**.
    ///
    /// The qualifier is the honest part: nothing failed, and a caller that
    /// needs "conformant" without it must also check [`Self::unchecked`] is
    /// zero. Folding the two together would let a transcript that called one
    /// method report a conformant driver.
    pub fn is_clean(&self) -> bool {
        self.failed == 0
    }

    /// Whether every rule was reached and held — the certification answer.
    pub fn is_complete(&self) -> bool {
        self.failed == 0 && self.unchecked == 0
    }
}

/// Runs the suite over a transcript.
///
/// `described` is what the driver's own `Describe` reply said; every rule about
/// optional methods is relative to it, because "optional" has no meaning
/// without the driver's claim about which ones it has.
pub fn check(spec: &ClassSpec, described: &Described, transcript: &[Exchange]) -> Report {
    let mut report = Report::default();
    let fail = |report: &mut Report, rule: Rule, ordinal: u32, status: u32| {
        report.failed |= 1 << rule as u32;
        report.passed &= !(1 << rule as u32);
        if report.offending_ordinal == 0 {
            report.offending_ordinal = ordinal;
            report.offending_status = status;
        }
    };
    let pass = |report: &mut Report, rule: Rule| {
        // Never upgrade a failure: one bad exchange condemns the rule however
        // many good ones follow it.
        if report.failed & (1 << rule as u32) == 0 {
            report.passed |= 1 << rule as u32;
        }
    };

    // 7. The version, first: every other rule reads ordinals whose meaning the
    // contract version defines, so a mismatch makes the rest meaningless
    // rather than merely additional.
    if described.contract_version == spec.contract_version {
        pass(&mut report, Rule::ContractVersionIsUnderstood);
    } else {
        fail(
            &mut report,
            Rule::ContractVersionIsUnderstood,
            0,
            described.contract_version,
        );
    }

    // 1. Every required method was called and answered.
    for required in spec.required {
        match transcript.iter().find(|e| e.ordinal == *required) {
            Some(exchange) if exchange.answered => pass(&mut report, Rule::RequiredMethodsAnswered),
            Some(exchange) => fail(
                &mut report,
                Rule::RequiredMethodsAnswered,
                *required,
                exchange.status,
            ),
            // Not called at all. The clause is *unchecked* rather than failed:
            // a transcript that skipped a method has not shown the driver
            // cannot answer it, and reporting otherwise would blame a driver
            // for its client's omission.
            None => report.unchecked |= 1 << Rule::RequiredMethodsAnswered as u32,
        }
    }

    for exchange in transcript {
        // 2. The closed error set.
        if exchange.answered {
            if exchange.status <= spec.max_error {
                pass(&mut report, Rule::ErrorsAreInTheClosedSet);
            } else {
                fail(
                    &mut report,
                    Rule::ErrorsAreInTheClosedSet,
                    exchange.ordinal,
                    exchange.status,
                );
            }
        }

        // 6. Vendor methods are unreachable until negotiated.
        if exchange.ordinal >= VENDOR_ORDINAL_BASE {
            let negotiated = described.vendor != 0;
            if negotiated || exchange.status == PROTOCOL_STATUS {
                pass(&mut report, Rule::VendorMethodsNeedANamespace);
            } else {
                fail(
                    &mut report,
                    Rule::VendorMethodsNeedANamespace,
                    exchange.ordinal,
                    exchange.status,
                );
            }
            continue;
        }

        // 3 and 4. Optional methods, both directions.
        if let Some((_, bit)) = spec.optional.iter().find(|(o, _)| *o == exchange.ordinal) {
            let advertised = described.features & bit != 0;
            if advertised {
                if exchange.status == spec.not_supported {
                    // Advertised and refused: `Describe` and the method
                    // disagree, and a client's feature check is worthless.
                    fail(
                        &mut report,
                        Rule::AdvertisedOptionalsWork,
                        exchange.ordinal,
                        exchange.status,
                    );
                } else {
                    pass(&mut report, Rule::AdvertisedOptionalsWork);
                }
            } else if exchange.status == spec.not_supported {
                pass(&mut report, Rule::UnsupportedOptionalsSaySo);
            } else {
                // Not advertised and it did something — succeeded, or failed
                // in some other way. Either leaves a client unable to trust
                // what `Describe` told it.
                fail(
                    &mut report,
                    Rule::UnsupportedOptionalsSaySo,
                    exchange.ordinal,
                    exchange.status,
                );
            }
        }

        // 5. Reset leaves the defined state.
        if exchange.ordinal == spec.reset_ordinal && exchange.answered {
            if exchange.detail == spec.state_after_reset {
                pass(&mut report, Rule::ResetLeavesTheDefinedState);
            } else {
                fail(
                    &mut report,
                    Rule::ResetLeavesTheDefinedState,
                    exchange.ordinal,
                    exchange.detail,
                );
            }
        }
    }

    // Everything neither passed nor failed was never reached.
    for rule in ALL_RULES {
        let bit = 1 << rule as u32;
        if report.passed & bit == 0 && report.failed & bit == 0 {
            report.unchecked |= bit;
        }
    }
    report
}

/// The status both contracts use for "malformed, or not admissible in this
/// state" — the answer a vendor method must get when nothing is negotiated.
///
/// Shared between the classes because the vendor rule is a framework rule; the
/// two contracts number it identically for exactly that reason.
pub const PROTOCOL_STATUS: u32 = 6;

#[cfg(test)]
mod tests {
    use super::*;

    const DESCRIBED: Described = Described {
        contract_version: 1,
        // WRITE and FLUSH, not DISCARD.
        features: 0x1 | 0x2,
        vendor: 0,
    };

    fn ok(ordinal: u32) -> Exchange {
        Exchange {
            ordinal,
            status: 0,
            answered: true,
            detail: 0,
        }
    }

    /// A transcript that exercises every rule of the block class and breaks
    /// none of it.
    fn clean_block() -> [Exchange; 6] {
        [
            ok(1), // Describe
            ok(2), // Read
            ok(3), // Write — advertised
            Exchange {
                ordinal: 5,
                status: 0,
                answered: true,
                detail: 1, // left ACTIVE
            },
            ok(6), // SetPower
            Exchange {
                ordinal: 7, // Discard — not advertised
                status: BLOCK.not_supported,
                answered: true,
                detail: 0,
            },
        ]
    }

    #[test]
    fn a_conformant_driver_passes_every_rule_the_transcript_reaches() {
        let report = check(&BLOCK, &DESCRIBED, &clean_block());
        assert!(report.is_clean());
        for rule in ALL_RULES {
            if rule == Rule::VendorMethodsNeedANamespace {
                // Never exercised by this transcript, and therefore unchecked
                // rather than passing.
                assert!(!report.checked(rule));
                continue;
            }
            assert!(report.passed(rule), "{rule:?} did not pass");
        }
        assert!(!report.is_complete(), "one clause was never reached");
    }

    /// **The clause that keeps the suite honest.** A transcript that called
    /// nothing must not produce a clean bill of health, and the difference
    /// between "nothing failed" and "everything held" is the whole distinction
    /// between a smoke test and a conformance suite.
    #[test]
    fn an_empty_transcript_proves_nothing() {
        let report = check(&BLOCK, &DESCRIBED, &[]);
        assert!(report.is_clean(), "nothing failed, because nothing ran");
        assert!(!report.is_complete(), "and nothing was shown either");
        for rule in ALL_RULES {
            if rule == Rule::ContractVersionIsUnderstood {
                // The version is checked from `Describe`'s own reply and needs
                // no exchange.
                continue;
            }
            assert!(!report.checked(rule), "{rule:?} was not exercised");
        }
    }

    /// A required method the client skipped is unchecked, not passed: the
    /// driver has not been shown to answer it, and blaming it for the client's
    /// omission would be as wrong as absolving it.
    #[test]
    fn a_required_method_nobody_called_is_unchecked() {
        let report = check(&BLOCK, &DESCRIBED, &[ok(1), ok(2)]);
        assert!(report.is_clean());
        assert!(
            report.unchecked & (1 << Rule::RequiredMethodsAnswered as u32) != 0,
            "Reset and SetPower were never called",
        );
    }

    /// A required method that was called and not answered fails, which is the
    /// other half of the rule and a different fact: the driver was asked and
    /// did not reply.
    #[test]
    fn a_required_method_that_went_unanswered_fails() {
        let mut transcript = clean_block();
        transcript[1].answered = false;
        let report = check(&BLOCK, &DESCRIBED, &transcript);
        assert!(report.failed(Rule::RequiredMethodsAnswered));
        assert_eq!(report.offending_ordinal, 2);
        assert!(!report.is_clean());
    }

    /// One bad exchange condemns a rule however many good ones follow it.
    /// Without this a driver could fail a call and pass the suite by making
    /// the same call again.
    #[test]
    fn a_later_success_does_not_absolve_an_earlier_failure() {
        let transcript = [
            Exchange {
                ordinal: 2,
                status: 99, // outside the closed set
                answered: true,
                detail: 0,
            },
            ok(2),
            ok(2),
        ];
        let report = check(&BLOCK, &DESCRIBED, &transcript);
        assert!(report.failed(Rule::ErrorsAreInTheClosedSet));
        assert!(!report.passed(Rule::ErrorsAreInTheClosedSet));
        assert_eq!(report.offending_status, 99);
    }

    /// An unimplemented optional method must say `NOT_SUPPORTED` and nothing
    /// else. A generic failure leaves a client unable to tell "this driver
    /// cannot" from "this attempt failed".
    #[test]
    fn an_unimplemented_optional_that_fails_generically_is_not_conformant() {
        let mut transcript = clean_block();
        // Discard is not advertised; answering IO_ERROR is the wrong refusal.
        transcript[5].status = 2;
        let report = check(&BLOCK, &DESCRIBED, &transcript);
        assert!(report.failed(Rule::UnsupportedOptionalsSaySo));
        assert_eq!(report.offending_ordinal, 7);
    }

    /// Worse than refusing wrongly: succeeding at a method that was never
    /// advertised, which makes every feature check a client performs
    /// meaningless.
    #[test]
    fn an_unadvertised_optional_that_works_is_not_conformant_either() {
        let mut transcript = clean_block();
        transcript[5].status = 0;
        let report = check(&BLOCK, &DESCRIBED, &transcript);
        assert!(report.failed(Rule::UnsupportedOptionalsSaySo));
    }

    /// And the converse: a driver that advertised a feature and then refused
    /// it. `Describe` and the method disagree, and the client believed
    /// `Describe`.
    #[test]
    fn an_advertised_optional_that_refuses_is_not_conformant() {
        let mut transcript = clean_block();
        transcript[2].status = BLOCK.not_supported;
        let report = check(&BLOCK, &DESCRIBED, &transcript);
        assert!(report.failed(Rule::AdvertisedOptionalsWork));
        assert_eq!(report.offending_ordinal, 3);
    }

    /// A reset that did not leave the state a reset is defined to leave. The
    /// contract says `ACTIVE`; a driver that came back suspended has left its
    /// client holding an assumption the contract made for it.
    #[test]
    fn a_reset_that_leaves_the_wrong_state_is_not_conformant() {
        let mut transcript = clean_block();
        transcript[3].detail = 3; // STANDBY
        let report = check(&BLOCK, &DESCRIBED, &transcript);
        assert!(report.failed(Rule::ResetLeavesTheDefinedState));
        assert_eq!(report.offending_status, 3);
    }

    /// A vendor-range method must be refused with `PROTOCOL` until its
    /// namespace has been negotiated. This is what stops a private extension
    /// from becoming reachable — and therefore public — by accident.
    #[test]
    fn a_vendor_method_is_unreachable_until_its_namespace_is_negotiated() {
        let refused = [Exchange {
            ordinal: VENDOR_ORDINAL_BASE,
            status: PROTOCOL_STATUS,
            answered: true,
            detail: 0,
        }];
        assert!(check(&BLOCK, &DESCRIBED, &refused).passed(Rule::VendorMethodsNeedANamespace));

        // Answered instead of refused, with nothing negotiated: the extension
        // is reachable by anyone who guesses an ordinal.
        let reachable = [ok(VENDOR_ORDINAL_BASE)];
        let report = check(&BLOCK, &DESCRIBED, &reachable);
        assert!(report.failed(Rule::VendorMethodsNeedANamespace));
        assert_eq!(report.offending_ordinal, VENDOR_ORDINAL_BASE);

        // With a namespace declared, the same call is legitimate.
        let negotiated = Described {
            vendor: 0x1af4,
            ..DESCRIBED
        };
        assert!(check(&BLOCK, &negotiated, &reachable).passed(Rule::VendorMethodsNeedANamespace));
    }

    /// A contract version the client does not understand fails first and
    /// loudest: every other rule reads ordinals whose meaning that version
    /// defines, so a mismatch makes the rest meaningless rather than merely
    /// additional.
    #[test]
    fn an_unknown_contract_version_fails() {
        let described = Described {
            contract_version: 2,
            ..DESCRIBED
        };
        let report = check(&BLOCK, &described, &clean_block());
        assert!(report.failed(Rule::ContractVersionIsUnderstood));
        assert!(!report.is_clean());
    }

    /// **The generalisation claim, checked rather than asserted.** The same
    /// checker, the same rules and the same report run against the network
    /// class with nothing but its spec changed — different ordinals, different
    /// feature bits, a different reset method. A rule that had quietly been
    /// about block devices would not survive this.
    #[test]
    fn the_same_rules_judge_the_network_class() {
        let described = Described {
            contract_version: 1,
            // TRANSMIT, not PROMISCUOUS.
            features: 0x1,
            vendor: 0,
        };
        let transcript = [
            ok(1), // Describe
            ok(2), // Transmit — advertised
            Exchange {
                ordinal: 3, // Reset
                status: 0,
                answered: true,
                detail: 1, // ACTIVE
            },
            ok(4), // SetPower
            Exchange {
                ordinal: 5, // SetPromiscuous — not advertised
                status: NETWORK.not_supported,
                answered: true,
                detail: 0,
            },
        ];
        let report = check(&NETWORK, &described, &transcript);
        assert!(report.is_clean());
        assert!(report.passed(Rule::RequiredMethodsAnswered));
        assert!(report.passed(Rule::AdvertisedOptionalsWork));
        assert!(report.passed(Rule::UnsupportedOptionalsSaySo));
        assert!(report.passed(Rule::ResetLeavesTheDefinedState));

        // And it catches the network class's own violations: `Reset` here is
        // ordinal 3, not the block class's 5, so a checker that had hardcoded
        // one would find nothing to judge.
        let mut bad = transcript;
        bad[2].detail = 4; // OFF
        assert!(check(&NETWORK, &described, &bad).failed(Rule::ResetLeavesTheDefinedState));
    }

    /// A transcript that reaches every rule reports complete — the state a
    /// certification run has to reach, and the one an incomplete transcript
    /// must never be mistaken for.
    #[test]
    fn a_transcript_that_reaches_every_rule_reports_complete() {
        let mut full = [ok(0); 7];
        full[..6].copy_from_slice(&clean_block());
        full[6] = Exchange {
            ordinal: VENDOR_ORDINAL_BASE,
            status: PROTOCOL_STATUS,
            answered: true,
            detail: 0,
        };
        let report = check(&BLOCK, &DESCRIBED, &full);
        assert!(report.is_complete());
        assert_eq!(report.unchecked, 0);
    }
    /// **The third class needs no new rule**, and this is what says so: the
    /// same seven rules, run against a spec whose class moves no data at all,
    /// with a transcript that exercises every one of them.
    ///
    /// Two classes agreeing on a shape can be a coincidence of both moving
    /// bytes through queues. A clock controller carries a clock id and a
    /// number, and the suite judges it unchanged.
    #[test]
    fn the_clock_class_is_judged_by_the_same_seven_rules() {
        let described = Described {
            contract_version: 1,
            // SET_RATE advertised, DISABLE and MUX not — so both optional rules
            // are reachable on one transcript.
            features: 0x1,
            vendor: 0,
        };
        let refused = |ordinal: u32, status: u32| Exchange {
            ordinal,
            status,
            answered: true,
            detail: 0,
        };
        let transcript = [
            ok(1),                           // Describe
            ok(2),                           // Enable
            ok(8),                           // GetRate
            ok(4),                           // SetRate — advertised, and it works
            refused(3, CLOCK.not_supported), // Disable — not advertised, says so
            Exchange {
                ordinal: 5,
                status: 0,
                answered: true,
                detail: 1, // a reset leaves ACTIVE
            },
            ok(6),                           // SetPower
            refused(VENDOR_ORDINAL_BASE, 6), // a vendor ordinal, PROTOCOL
        ];
        let report = check(&CLOCK, &described, &transcript);
        assert!(
            report.is_complete(),
            "every rule reached and held: {report:?}"
        );
    }

    /// A seventh class, and the table is still the only thing that changed.
    #[test]
    fn the_display_class_is_judged_by_the_same_seven_rules() {
        let described = Described {
            contract_version: 1,
            // FILL advertised, CURSOR not — both optional rules reachable on
            // one transcript, and honest: this driver fills and has no cursor
            // plane.
            features: 0x1,
            vendor: 0,
        };
        let transcript = [
            ok(1), // Describe
            ok(2), // Blit
            ok(3), // Flush
            ok(4), // Fill — advertised, and it works
            // SetCursor — not advertised, and it says so.
            Exchange {
                ordinal: 7,
                status: DISPLAY.not_supported,
                answered: true,
                detail: 0,
            },
            Exchange {
                ordinal: 5,
                status: 0,
                answered: true,
                detail: 1, // a reset leaves ACTIVE
            },
            ok(6), // SetPower
            // A vendor ordinal, answered PROTOCOL.
            Exchange {
                ordinal: VENDOR_ORDINAL_BASE,
                status: 6,
                answered: true,
                detail: 0,
            },
        ];
        let report = check(&DISPLAY, &described, &transcript);
        assert!(
            report.is_complete(),
            "every rule reached and held: {report:?}"
        );
    }

    /// **An eighth class, and the rule that judges it counts a refusal as a
    /// pass.** `NOT_SUPPORTED` for an algorithm this driver does not implement
    /// is not a shortfall — it is the behaviour the contract exists to
    /// guarantee, and the rule that says "answered within the closed set"
    /// already covers it. Which is the fifth class in a row to need no new rule.
    #[test]
    fn the_crypto_class_is_judged_by_the_same_seven_rules() {
        let described = Described {
            contract_version: 1,
            // It decrypts; it holds one session at a time.
            features: 0x1,
            vendor: 0,
        };
        let transcript = [
            ok(1), // Describe
            ok(2), // CreateSession
            ok(3), // Encrypt
            ok(4), // Decrypt — advertised, and it works
            // SetIv — not advertised, and it says so.
            Exchange {
                ordinal: 8,
                status: CRYPTO.not_supported,
                answered: true,
                detail: 0,
            },
            ok(7), // DestroySession
            Exchange {
                ordinal: 5,
                status: 0,
                answered: true,
                detail: 1, // a reset leaves ACTIVE, with every session gone
            },
            ok(6), // SetPower
            // A vendor ordinal, answered PROTOCOL.
            Exchange {
                ordinal: VENDOR_ORDINAL_BASE,
                status: 6,
                answered: true,
                detail: 0,
            },
        ];
        let report = check(&CRYPTO, &described, &transcript);
        assert!(
            report.is_complete(),
            "every rule reached and held: {report:?}"
        );
    }

    /// **An algorithm refused is inside the closed set, and a substitution is
    /// not detectable here at all.** Worth stating where the suite is defined:
    /// this rule catches a driver that answered with a code it has no business
    /// using, and it cannot catch a driver that answered `OK` after doing the
    /// wrong thing. That one is caught by a known-answer test against a
    /// published vector, outside this suite, and there is no rule that could
    /// replace it.
    #[test]
    fn refusing_an_algorithm_is_an_answer_within_the_set() {
        let described = Described {
            contract_version: 1,
            features: 0x1,
            vendor: 0,
        };
        let transcript = [
            ok(1),
            ok(2),
            // Encrypt, refused because the algorithm named is not implemented.
            // A *required* method answering NOT_SUPPORTED, which is still an
            // answer inside the closed set: the method exists and the algorithm
            // does not.
            Exchange {
                ordinal: 3,
                status: CRYPTO.not_supported,
                answered: true,
                detail: 0,
            },
            ok(4),
            // SetIv is not advertised, and says so.
            Exchange {
                ordinal: 8,
                status: CRYPTO.not_supported,
                answered: true,
                detail: 0,
            },
            ok(7),
            Exchange {
                ordinal: 5,
                status: 0,
                answered: true,
                detail: 1,
            },
            ok(6),
            Exchange {
                ordinal: VENDOR_ORDINAL_BASE,
                status: 6,
                answered: true,
                detail: 0,
            },
        ];
        let report = check(&CRYPTO, &described, &transcript);
        assert!(report.is_complete(), "a refusal is an answer: {report:?}");
    }

    /// **A sixth class, and the rule that judges it was written for disks.**
    /// A stream that ran dry answers `UNDERRUN` and is still running, and
    /// "answered within the closed set" counts that as a pass — the same
    /// sentence that counts an idle keyboard's `NO_REPORT`.
    #[test]
    fn the_audio_class_is_judged_by_the_same_seven_rules() {
        let described = Described {
            contract_version: 1,
            // PAUSE advertised, VOLUME not — both optional rules reachable on
            // one transcript, and honest: this driver pauses and has no mixer.
            features: 0x1,
            vendor: 0,
        };
        let transcript = [
            ok(1), // Describe
            ok(2), // Configure
            ok(3), // Start
            // Write, answered UNDERRUN: the stream ran dry, and that is a
            // value in the set rather than a failure of the call.
            Exchange {
                ordinal: 4,
                status: 1,
                answered: true,
                detail: 0,
            },
            ok(7), // Stop — advertised, and it works
            // SetVolume — not advertised, and it says so.
            Exchange {
                ordinal: 9,
                status: AUDIO.not_supported,
                answered: true,
                detail: 0,
            },
            Exchange {
                ordinal: 5,
                status: 0,
                answered: true,
                detail: 1, // a reset leaves ACTIVE
            },
            ok(6), // SetPower
            ok(8), // Status
            // A vendor ordinal, answered PROTOCOL.
            Exchange {
                ordinal: VENDOR_ORDINAL_BASE,
                status: 6,
                answered: true,
                detail: 0,
            },
        ];
        let report = check(&AUDIO, &described, &transcript);
        assert!(
            report.is_complete(),
            "every rule reached and held: {report:?}"
        );
    }

    /// **A fifth class, and still no new rule.** What a class contract *is*, is
    /// the table: which ordinals are required, which are gated by which bit,
    /// and what a reset leaves. Everything the suite does with that table was
    /// written for disks.
    #[test]
    fn the_gpio_class_is_judged_by_the_same_seven_rules() {
        let described = Described {
            contract_version: 1,
            // A PL061: it drives and it interrupts, and it has no bias or
            // drive strength — so both optional rules are reachable on one
            // transcript without contriving anything.
            features: 0x1 | 0x2,
            vendor: 0,
        };
        let transcript = [
            ok(1), // Describe
            ok(2), // ConfigureLine
            ok(3), // Read
            ok(4), // Write — advertised, and it works
            ok(7), // WatchLine — advertised, and it hands over the line
            // SetElectrical — not advertised, and it says so rather than
            // failing generically. A PL061 has no bias control at all.
            Exchange {
                ordinal: 9,
                status: GPIO.not_supported,
                answered: true,
                detail: 0,
            },
            Exchange {
                ordinal: 5,
                status: 0,
                answered: true,
                detail: 1, // a reset leaves ACTIVE
            },
            ok(6), // SetPower
            ok(8), // ReleaseLine
            // A vendor ordinal, answered PROTOCOL.
            Exchange {
                ordinal: VENDOR_ORDINAL_BASE,
                status: 6,
                answered: true,
                detail: 0,
            },
        ];
        let report = check(&GPIO, &described, &transcript);
        assert!(
            report.is_complete(),
            "every rule reached and held: {report:?}"
        );
    }

    /// **A fourth class, and the suite did not change.** The rules that judge a
    /// keyboard are the rules that judge a disk; what differs is the table.
    /// A class contract this suite could not read without being taught about it
    /// would be a description of one device rather than a framework.
    #[test]
    fn the_input_class_is_judged_by_the_same_seven_rules() {
        let described = Described {
            contract_version: 1,
            // GET_REPORT advertised and SET_REPORT not, so both optional rules
            // are reachable on one transcript — which for a keyboard means it
            // can be asked what is held down and cannot be told to light a lamp.
            features: 0x2,
            vendor: 0,
        };
        let transcript = [
            ok(1), // Describe
            // Poll, answered with NO_REPORT: **nothing happened, and that is a
            // pass.** The rule is "answered within the closed set", and an idle
            // keyboard is the ordinary case rather than an exception to it.
            Exchange {
                ordinal: 2,
                status: 1,
                answered: true,
                detail: 0,
            },
            Exchange {
                ordinal: 3,
                status: INPUT.not_supported,
                answered: true,
                detail: 0,
            },
            ok(4), // GetReport — advertised, and it works
            Exchange {
                ordinal: 5,
                status: 0,
                answered: true,
                detail: 1, // a reset leaves ACTIVE
            },
            ok(6), // SetPower
            // A vendor ordinal, answered PROTOCOL.
            Exchange {
                ordinal: VENDOR_ORDINAL_BASE,
                status: 6,
                answered: true,
                detail: 0,
            },
        ];
        let report = check(&INPUT, &described, &transcript);
        assert!(
            report.is_complete(),
            "every rule reached and held: {report:?}"
        );
    }
}
