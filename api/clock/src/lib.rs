// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The clock-controller rules that are arithmetic rather than registers:
//! reference counting, and choosing a rate within a declared range.
//!
//! A driver of a clock controller has two jobs. One is writing divisors, which
//! is the controller's own and cannot be shared. The other is deciding *what*
//! to write — whether a clock should be running at all now that this consumer
//! has let go, and whether a requested rate is one this clock may produce — and
//! that is the same decision on every controller. It lives here, host-tested,
//! for the reason `api/power`'s arbitration does: it is where the mistakes are,
//! and none of them need hardware to make.
//!
//! # Reference counting is a rule of the contract
//!
//! Two consumers of one clock is the normal case — a card and its controller
//! share a bus clock — so "off when the last one lets go" cannot be left to
//! each driver. If it were, one consumer's `Disable` would race the other's
//! `Enable` and the answer would depend on order.
//!
//! # A rate outside the range is refused
//!
//! `docs/drivers/04` says consumers request rates through bounded APIs. Bounded
//! means the bound is enforced: a consumer handed a rate it did not ask for is
//! one whose device runs at a speed nobody chose, and it has no way to find out.
//!
//! Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
//! ("Clock Controller")
//! Budget: none (a control path, not a data path)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// Consumers one clock may have at once. Bounded like every pool in this tree;
/// a consumer arriving past the bound is refused rather than uncounted, because
/// an uncounted holder is one whose release stops a clock somebody else wants.
pub const MAX_HOLDERS: usize = 8;

/// Clocks one controller may own here.
pub const MAX_CLOCKS: usize = 8;

/// What can go wrong. Values match `ClockError` in `clock_controller.isl`, so a
/// driver answers with what this returns rather than translating.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum ClockError {
    /// The rate is outside what this clock declared.
    BadRate = 1,
    /// No clock by that id.
    NoSuchClock = 2,
    /// Critical for correctness; it will not be disabled.
    Critical = 3,
    /// No room for another holder.
    Busy = 4,
}

/// What a clock is: what it may be asked for, and whether it may be stopped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClockLine {
    /// The lowest and highest rates this clock declares, **inclusive**.
    ///
    /// Inclusive because a range whose ends are unusable is a range that lies
    /// about itself: a controller declaring 400 kHz as its minimum and refusing
    /// exactly 400 kHz would refuse the identification rate every SD card
    /// starts at.
    pub min_hz: u64,
    pub max_hz: u64,
    /// The rate a reset leaves this clock at.
    pub default_hz: u64,
    /// Whether the system needs this clock for correctness. A disable is
    /// refused rather than obeyed — the one refusal in this class that protects
    /// the machine from its own drivers.
    pub critical: bool,
}

impl ClockLine {
    /// The rate this clock will run at for `requested`, or why it will not.
    ///
    /// **Refused, never clamped.** The alternative is handing back the nearest
    /// thing the hardware could manage, which a consumer cannot distinguish
    /// from having got what it asked for — and a device running at a speed
    /// nobody chose is the failure this class exists to prevent.
    pub fn rate_for(&self, requested: u64) -> Result<u64, ClockError> {
        if requested < self.min_hz || requested > self.max_hz {
            return Err(ClockError::BadRate);
        }
        Ok(requested)
    }
}

/// One clock's live state: who is holding it on, and what it is running at.
#[derive(Clone, Copy)]
struct ClockState {
    line: ClockLine,
    rate_hz: u64,
    /// The consumers holding this clock on. Identities rather than a count,
    /// because the same consumer asking twice must not take two holds — a
    /// driver that enabled a clock on each of two code paths would otherwise
    /// have to remember which of them it had already run.
    holders: [Option<u32>; MAX_HOLDERS],
}

/// A controller's clocks and their holders.
pub struct ClockTable {
    clocks: [Option<ClockState>; MAX_CLOCKS],
}

impl ClockTable {
    pub const fn new() -> Self {
        Self {
            clocks: [None; MAX_CLOCKS],
        }
    }

    /// Declares clock `id`, at its default rate and held by nobody.
    pub fn declare(&mut self, id: u32, line: ClockLine) -> Result<(), ClockError> {
        let slot = self
            .clocks
            .get_mut(id as usize)
            .ok_or(ClockError::NoSuchClock)?;
        *slot = Some(ClockState {
            line,
            rate_hz: line.default_hz,
            holders: [None; MAX_HOLDERS],
        });
        Ok(())
    }

    fn state(&self, id: u32) -> Result<&ClockState, ClockError> {
        self.clocks
            .get(id as usize)
            .and_then(|slot| slot.as_ref())
            .ok_or(ClockError::NoSuchClock)
    }

    fn state_mut(&mut self, id: u32) -> Result<&mut ClockState, ClockError> {
        self.clocks
            .get_mut(id as usize)
            .and_then(|slot| slot.as_mut())
            .ok_or(ClockError::NoSuchClock)
    }

    /// What `id` may be asked for.
    pub fn line_of(&self, id: u32) -> Result<ClockLine, ClockError> {
        self.state(id).map(|state| state.line)
    }

    /// What `id` is running at.
    pub fn rate_of(&self, id: u32) -> Result<u64, ClockError> {
        self.state(id).map(|state| state.rate_hz)
    }

    /// How many consumers are holding `id` on. Zero means it is stopped.
    pub fn holders(&self, id: u32) -> Result<usize, ClockError> {
        self.state(id)
            .map(|state| state.holders.iter().flatten().count())
    }

    /// Whether `id` is running.
    pub fn is_on(&self, id: u32) -> Result<bool, ClockError> {
        self.holders(id).map(|held| held > 0)
    }

    /// Records that `consumer` wants `id` running, and answers whether the
    /// clock had to be **started** — which is what a driver acts on, since
    /// nothing needs writing when somebody else already had it on.
    ///
    /// Asking twice is idempotent and takes one hold. A driver that enabled a
    /// clock on each of two code paths would otherwise have to remember which
    /// of them it had already run, and a hold it forgot to release would stop
    /// the clock never turning off.
    pub fn enable(&mut self, id: u32, consumer: u32) -> Result<bool, ClockError> {
        let state = self.state_mut(id)?;
        let was_off = state.holders.iter().flatten().count() == 0;
        if state.holders.iter().flatten().any(|held| *held == consumer) {
            return Ok(false);
        }
        let slot = state
            .holders
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ClockError::Busy)?;
        *slot = Some(consumer);
        Ok(was_off)
    }

    /// Drops `consumer`'s hold on `id`, and answers whether the clock **stops**
    /// — true only when the last holder let go.
    ///
    /// A critical clock is refused. A consumer releasing a hold it does not
    /// have succeeds and changes nothing: that is the idempotent partner of
    /// `enable`, and treating it as an error would make a driver's cleanup path
    /// depend on remembering what its setup path did.
    pub fn disable(&mut self, id: u32, consumer: u32) -> Result<bool, ClockError> {
        let state = self.state_mut(id)?;
        if state.line.critical {
            return Err(ClockError::Critical);
        }
        for slot in state.holders.iter_mut() {
            if *slot == Some(consumer) {
                *slot = None;
                break;
            }
        }
        Ok(state.holders.iter().flatten().count() == 0)
    }

    /// Sets `id`'s rate, or refuses it. Returns the rate now in effect.
    ///
    /// Refused for a clock **another consumer is also holding** at a different
    /// rate: a rate change is not private, and moving a clock under a consumer
    /// that asked for a different one would leave its device running at a speed
    /// its driver believes it chose. `BUSY` says so, and the fix is for the two
    /// to agree rather than for the controller to pick.
    pub fn set_rate(&mut self, id: u32, consumer: u32, requested: u64) -> Result<u64, ClockError> {
        let state = self.state_mut(id)?;
        let rate = state.line.rate_for(requested)?;
        if rate != state.rate_hz && state.holders.iter().flatten().any(|held| *held != consumer) {
            return Err(ClockError::Busy);
        }
        state.rate_hz = rate;
        Ok(rate)
    }

    /// What a reset leaves: every clock at its default rate and **every hold
    /// released**.
    ///
    /// The counts describe live requests, and a reset ends them. A table that
    /// kept them would have consumers holding clocks through a reset they were
    /// never told about, and the first to let go would stop a clock the others
    /// still believe they asked for.
    pub fn reset(&mut self) {
        for state in self.clocks.iter_mut().flatten() {
            state.rate_hz = state.line.default_hz;
            state.holders = [None; MAX_HOLDERS];
        }
    }
}

impl Default for ClockTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
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
}
