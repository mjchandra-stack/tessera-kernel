// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

const BUS: u32 = 0;
const CARD: u32 = 7;
const CONTROLLER: u32 = 9;

fn table() -> ClockTable {
    let mut table = ClockTable::new();
    table
        .declare(
            BUS,
            ClockLine {
                min_hz: 400_000,
                max_hz: 50_000_000,
                default_hz: 400_000,
                critical: false,
            },
        )
        .expect("declare");
    table
}

/// **Off when the last one lets go, and not before.** Two consumers of one
/// clock is the normal case — a card and its controller share a bus clock —
/// and a driver that stopped on the first `Disable` would cut the clock out
/// from under whoever else was using it.
#[test]
fn a_clock_stops_when_the_last_holder_goes() {
    let mut table = table();
    assert_eq!(table.enable(BUS, CARD), Ok(true), "it had to be started");
    assert_eq!(
        table.enable(BUS, CONTROLLER),
        Ok(false),
        "already running, so nothing to write",
    );
    assert_eq!(table.holders(BUS), Ok(2));

    assert_eq!(
        table.disable(BUS, CARD),
        Ok(false),
        "somebody else still wants it",
    );
    assert_eq!(table.is_on(BUS), Ok(true));
    assert_eq!(table.disable(BUS, CONTROLLER), Ok(true), "now it stops");
    assert_eq!(table.is_on(BUS), Ok(false));
}

/// Asking twice takes one hold, and releasing a hold nobody has changes
/// nothing. Both halves are what stop a driver's cleanup path from having
/// to remember what its setup path did.
#[test]
fn holding_is_idempotent_in_both_directions() {
    let mut table = table();
    assert_eq!(table.enable(BUS, CARD), Ok(true));
    assert_eq!(table.enable(BUS, CARD), Ok(false));
    assert_eq!(table.holders(BUS), Ok(1), "one consumer, one hold");
    assert_eq!(table.disable(BUS, CONTROLLER), Ok(false), "never held it");
    assert_eq!(table.holders(BUS), Ok(1), "and took nobody else's");
    assert_eq!(table.disable(BUS, CARD), Ok(true));
}

/// **Refused, not clamped.** A consumer handed the nearest rate the
/// hardware could manage cannot tell it from having got what it asked for,
/// and its device runs at a speed nobody chose.
#[test]
fn a_rate_outside_the_range_is_refused() {
    let mut table = table();
    assert_eq!(
        table.set_rate(BUS, CARD, 100_000_000),
        Err(ClockError::BadRate),
    );
    assert_eq!(table.set_rate(BUS, CARD, 1_000), Err(ClockError::BadRate));
    assert_eq!(table.rate_of(BUS), Ok(400_000), "and nothing moved");
}

/// The range's ends are usable. A controller declaring 400 kHz as its
/// minimum and refusing exactly 400 kHz would refuse the identification
/// rate every SD card starts at.
#[test]
fn the_declared_ends_of_the_range_are_inclusive() {
    let mut table = table();
    assert_eq!(table.set_rate(BUS, CARD, 400_000), Ok(400_000));
    assert_eq!(table.set_rate(BUS, CARD, 50_000_000), Ok(50_000_000));
}

/// A rate change is not private. Moving a clock under a consumer that asked
/// for a different one leaves its device running at a speed its driver
/// believes it chose, so the second consumer is told `BUSY` and the two
/// have to agree.
#[test]
fn changing_a_shared_clocks_rate_is_refused() {
    let mut table = table();
    table.enable(BUS, CARD).expect("card");
    table.set_rate(BUS, CARD, 25_000_000).expect("card's rate");
    table.enable(BUS, CONTROLLER).expect("controller");
    assert_eq!(
        table.set_rate(BUS, CONTROLLER, 50_000_000),
        Err(ClockError::Busy),
    );
    assert_eq!(table.rate_of(BUS), Ok(25_000_000));
    // Asking for the rate it is already at is not a change, and is allowed:
    // a second consumer whose requirement the first already meets has
    // nothing to disagree about.
    assert_eq!(table.set_rate(BUS, CONTROLLER, 25_000_000), Ok(25_000_000));
}

/// A critical clock will not be stopped. The one refusal in this class that
/// protects the machine from its own drivers.
#[test]
fn a_critical_clock_refuses_to_stop() {
    let mut table = ClockTable::new();
    table
        .declare(
            1,
            ClockLine {
                min_hz: 24_000_000,
                max_hz: 24_000_000,
                default_hz: 24_000_000,
                critical: true,
            },
        )
        .expect("declare");
    table.enable(1, CARD).expect("enable");
    assert_eq!(table.disable(1, CARD), Err(ClockError::Critical));
    assert_eq!(table.is_on(1), Ok(true));
}

/// A reset releases every hold. The counts describe live requests, and a
/// reset ends them: a table that kept them would leave consumers holding
/// clocks through a reset nobody told them about.
#[test]
fn a_reset_releases_every_hold_and_restores_the_default() {
    let mut table = table();
    table.enable(BUS, CARD).expect("card");
    table.enable(BUS, CONTROLLER).expect("controller");
    table.set_rate(BUS, CARD, 25_000_000).ok();
    table.reset();
    assert_eq!(table.holders(BUS), Ok(0));
    assert_eq!(table.is_on(BUS), Ok(false));
    assert_eq!(table.rate_of(BUS), Ok(400_000));
}

/// A clock nobody declared is `NO_SUCH_CLOCK` on every path, not a panic
/// and not a silent success — a consumer walking past a controller's clock
/// count is an ordinary outcome.
#[test]
fn an_undeclared_clock_answers_rather_than_panics() {
    let mut table = table();
    assert_eq!(table.rate_of(5), Err(ClockError::NoSuchClock));
    assert_eq!(table.enable(5, CARD), Err(ClockError::NoSuchClock));
    assert_eq!(table.disable(5, CARD), Err(ClockError::NoSuchClock));
    assert_eq!(
        table.set_rate(5, CARD, 400_000),
        Err(ClockError::NoSuchClock)
    );
    assert_eq!(
        table.holders(MAX_CLOCKS as u32),
        Err(ClockError::NoSuchClock)
    );
}

/// A consumer arriving past the bound is refused rather than uncounted. An
/// uncounted holder is one whose release stops a clock somebody else wants.
#[test]
fn a_holder_past_the_bound_is_refused_not_dropped() {
    let mut table = table();
    for consumer in 0..MAX_HOLDERS as u32 {
        assert!(table.enable(BUS, consumer).is_ok());
    }
    assert_eq!(table.enable(BUS, 99), Err(ClockError::Busy));
    assert_eq!(table.holders(BUS), Ok(MAX_HOLDERS), "and none were lost");
}
