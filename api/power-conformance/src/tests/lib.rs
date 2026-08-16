// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

/// The crypto class's numbering: ACTIVE 1, IDLE 2, STANDBY 3, OFF 4, and a
/// driver that has the first two.
const SPEC: PowerSpec = PowerSpec {
    advertised: (1 << 1) | (1 << 2),
    ok: 0,
    not_supported: 5,
    initial: 1,
};

fn step(requested: u32, status: u32, reported: u32) -> Observed {
    Observed {
        requested,
        status,
        reported,
    }
}

#[test]
fn a_driver_that_keeps_its_word_holds_every_rule() {
    let verdict = check(
        &SPEC,
        &[
            step(2, 0, 2), // Idle, advertised and reached
            step(1, 0, 1), // back to Active
            step(3, 5, 1), // Standby, refused, still Active
            step(4, 5, 1), // Off, refused, still Active
        ],
    );
    assert!(verdict.is_complete(), "{verdict:?}");
}

#[test]
fn an_empty_run_proves_nothing() {
    let verdict = check(&SPEC, &[]);
    assert_eq!(verdict.failed, 0);
    assert!(!verdict.is_complete());
}

/// A state the driver claimed and cannot reach: its own `Describe` is what
/// convicts it.
#[test]
fn an_advertised_state_that_is_refused_fails() {
    let verdict = check(&SPEC, &[step(2, 5, 1)]);
    assert!(verdict.failed(Rule::AdvertisedStatesAreReachable));
    assert_eq!(verdict.offending_state, 2);
}

/// Reporting success while staying put is the same failure wearing the
/// other face — a client reads the status and believes the device moved.
#[test]
fn claiming_success_without_moving_fails() {
    let verdict = check(&SPEC, &[step(2, 0, 1)]);
    assert!(verdict.failed(Rule::AdvertisedStatesAreReachable));
}

/// A state nobody advertised must not be quietly accepted.
#[test]
fn an_unadvertised_state_that_succeeds_fails() {
    let verdict = check(&SPEC, &[step(4, 0, 4)]);
    assert!(verdict.failed(Rule::UnadvertisedStatesAreRefused));
    assert!(
        verdict.failed(Rule::ReplyNamesAnAdvertisedState),
        "and it reported a state it never claimed to have",
    );
}

/// **The rule nothing else catches.** The driver refuses, and moves anyway.
/// The status says no, so a client stops reading — and is now wrong about
/// where the device is.
#[test]
fn a_refusal_that_moves_the_device_fails() {
    let verdict = check(&SPEC, &[step(3, 5, 2)]);
    assert!(verdict.failed(Rule::ARefusalDoesNotMoveTheDevice));
    assert!(
        verdict.passed(Rule::UnadvertisedStatesAreRefused),
        "the refusal itself was correct, which is what makes this one easy to miss",
    );
}

/// The settled state follows the driver's own successful transitions, so a
/// refusal after a legitimate move is judged against where it actually is.
#[test]
fn a_refusal_is_judged_against_the_last_state_reached() {
    let verdict = check(&SPEC, &[step(2, 0, 2), step(4, 5, 2)]);
    assert!(verdict.passed(Rule::ARefusalDoesNotMoveTheDevice));
    assert!(verdict.is_complete());
}

/// A state number past the mask's width is not advertised, and asking about
/// it must not shift past the end.
#[test]
fn a_state_outside_the_mask_is_simply_not_advertised() {
    let verdict = check(&SPEC, &[step(99, 5, 1)]);
    assert!(verdict.passed(Rule::UnadvertisedStatesAreRefused));
}
