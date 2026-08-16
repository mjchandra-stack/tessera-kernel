// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Power conformance**: whether a driver reaches the power states it
//! advertises, refuses the ones it does not, and tells the truth about which
//! one it is in.
//!
//! One of the checks `docs/drivers/01` ("Certification") requires, and a
//! different question from the one `api/power` answers. That crate arbitrates
//! *between* voters — what a set of votes on one domain resolves to, and who
//! lost. This asks something narrower and prior to it: when the answer comes
//! back to a single driver, does the driver do what it says?
//!
//! # Why a peer can check this at all
//!
//! Nothing here can look at the hardware. What it can do is hold a driver to
//! **its own** `Describe` reply, which is the same leverage
//! `api/class-conformance` uses for optional methods: a driver that advertises
//! a state has said it can reach it, and a driver that does not advertise one
//! has said it cannot. Both halves are then checkable from outside, and neither
//! needs a wattmeter.
//!
//! # The rule nothing else catches
//!
//! [`Rule::ARefusalDoesNotMoveTheDevice`]. A driver asked for a state it does
//! not have should answer `NOT_SUPPORTED` and **stay where it was**. One that
//! refuses and moves anyway has done something nobody asked for and reported an
//! error while doing it, so a client that reads the status and stops looking —
//! which is every client — is now wrong about the device. That is
//! `docs/lifecycle/04`'s "No Silent Fallback" in the direction people forget:
//! not a degradation reported as success, but a change reported as a refusal.
//!
//! `no_std`, dependency-free and allocation-free, so the same rules run in a
//! host test and inside the ring-3 certifier.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Power Management",
//! "Certification"), docs/power/01-power-management.md

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// What a driver said about itself, and how its class numbers the two answers
/// these rules read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PowerSpec {
    /// The states the driver advertised, as a bitmask of `1 << state` — the
    /// `power_states` field every class contract carries.
    pub advertised: u32,
    /// The class's success status.
    pub ok: u32,
    /// The class's `NOT_SUPPORTED`, which is 5 on every class in this tree.
    pub not_supported: u32,
    /// The state a driver is defined to be in before anything asks it to move.
    pub initial: u32,
}

impl PowerSpec {
    fn advertises(&self, state: u32) -> bool {
        // A state numbered past the mask's width is not advertised, and asking
        // is not an error — the shift would be.
        state < 32 && self.advertised & (1 << state) != 0
    }
}

/// One `SetPower` and what came back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Observed {
    /// The state that was asked for.
    pub requested: u32,
    /// The status the driver replied with. A plain `u32` for the reason
    /// `api/class-conformance` takes one: a value outside the closed set is
    /// something these rules must be able to hold.
    pub status: u32,
    /// The state the reply says the device is now in.
    pub reported: u32,
}

/// What a driver has to do with its own power states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Rule {
    /// A state the driver advertised was asked for, and reached.
    AdvertisedStatesAreReachable = 1,
    /// A state it did not advertise was asked for, and refused.
    UnadvertisedStatesAreRefused = 2,
    /// Every reply names a state the driver advertised. One that reports a
    /// state it never claimed is describing a device nobody can reason about.
    ReplyNamesAnAdvertisedState = 3,
    /// A refusal left the device where it was.
    ARefusalDoesNotMoveTheDevice = 4,
}

/// Every rule, so a caller can iterate without knowing the count.
pub const ALL_RULES: [Rule; 4] = [
    Rule::AdvertisedStatesAreReachable,
    Rule::UnadvertisedStatesAreRefused,
    Rule::ReplyNamesAnAdvertisedState,
    Rule::ARefusalDoesNotMoveTheDevice,
];

impl Rule {
    pub const fn bit(self) -> u32 {
        1 << self as u32
    }
}

/// What checking a run of transitions found.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Verdict {
    pub passed: u32,
    pub failed: u32,
    /// Rules no transition reached. Reported, never counted as holding.
    pub unchecked: u32,
    /// How many transitions were examined.
    pub examined: u32,
    /// The state asked for when a rule first broke.
    pub offending_state: u32,
}

impl Verdict {
    pub fn passed(&self, rule: Rule) -> bool {
        self.passed & rule.bit() != 0
    }

    pub fn failed(&self, rule: Rule) -> bool {
        self.failed & rule.bit() != 0
    }

    pub fn checked(&self, rule: Rule) -> bool {
        self.passed(rule) || self.failed(rule)
    }

    /// Every rule reached and held, over at least one transition.
    pub fn is_complete(&self) -> bool {
        self.failed == 0 && self.unchecked == 0 && self.examined > 0
    }
}

/// Checks a run of `SetPower` calls against what the driver advertised.
pub fn check(spec: &PowerSpec, run: &[Observed]) -> Verdict {
    let mut verdict = Verdict {
        examined: run.len() as u32,
        ..Verdict::default()
    };
    let fail = |verdict: &mut Verdict, rule: Rule, state: u32| {
        verdict.failed |= rule.bit();
        verdict.passed &= !rule.bit();
        if verdict.offending_state == 0 {
            verdict.offending_state = state;
        }
    };
    let pass = |verdict: &mut Verdict, rule: Rule| {
        if verdict.failed & rule.bit() == 0 {
            verdict.passed |= rule.bit();
        }
    };

    // Where the device is, as the driver's own replies say. Started from the
    // contract's defined initial state rather than from the first reply, so a
    // driver whose very first answer moves without permission is caught.
    let mut settled = spec.initial;

    for step in run {
        if spec.advertises(step.reported) {
            pass(&mut verdict, Rule::ReplyNamesAnAdvertisedState);
        } else {
            fail(
                &mut verdict,
                Rule::ReplyNamesAnAdvertisedState,
                step.requested,
            );
        }

        if spec.advertises(step.requested) {
            if step.status == spec.ok && step.reported == step.requested {
                pass(&mut verdict, Rule::AdvertisedStatesAreReachable);
                settled = step.reported;
            } else {
                fail(
                    &mut verdict,
                    Rule::AdvertisedStatesAreReachable,
                    step.requested,
                );
            }
            continue;
        }

        // Not advertised: it must be refused, and the refusal must not move
        // anything.
        if step.status == spec.not_supported {
            pass(&mut verdict, Rule::UnadvertisedStatesAreRefused);
        } else {
            fail(
                &mut verdict,
                Rule::UnadvertisedStatesAreRefused,
                step.requested,
            );
        }
        if step.reported == settled {
            pass(&mut verdict, Rule::ARefusalDoesNotMoveTheDevice);
        } else {
            fail(
                &mut verdict,
                Rule::ARefusalDoesNotMoveTheDevice,
                step.requested,
            );
        }
    }

    for rule in ALL_RULES {
        if verdict.passed & rule.bit() == 0 && verdict.failed & rule.bit() == 0 {
            verdict.unchecked |= rule.bit();
        }
    }
    verdict
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
