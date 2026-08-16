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
#[path = "tests/lib.rs"]
mod tests;
