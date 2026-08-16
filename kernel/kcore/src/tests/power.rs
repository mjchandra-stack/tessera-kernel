// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::power`.

use super::*;

const SOURCE: ObjectId = ObjectId::from_raw(0x50);
const MANAGER: ObjectId = ObjectId::from_raw(0x51);
const OTHER: ObjectId = ObjectId::from_raw(0x52);

/// The counter is what a suspend commit compares, so the one thing it must
/// do is move on every event — including two from the same source, which a
/// flag would fold into one.
#[test]
fn every_wake_moves_the_counter() {
    let mut wake = WakeState::new();
    assert_eq!(wake.events(), 0);
    wake.record_wake(SOURCE, 0);
    wake.record_wake(SOURCE, 0);
    wake.record_wake(OTHER, 0);
    assert_eq!(wake.events(), 3);
}

/// A wake takes a grace hold, so an event arriving just after a resume is
/// not lost to an immediate re-suspend — the manager has to have been
/// scheduled at least once to see it.
#[test]
fn a_wake_takes_a_grace_hold_that_expires_on_its_own() {
    let mut wake = WakeState::new();
    assert!(wake.record_wake(SOURCE, 100));
    assert!(wake.vetoed(100), "the commit is vetoed while it is fresh");
    assert_eq!(wake.holder_at(100, 0), Some(SOURCE), "attributed");

    // Still held at the last tick of the grace period, gone after it.
    assert!(wake.vetoed(100 + WAKE_GRACE_TICKS - 1));
    assert!(!wake.vetoed(100 + WAKE_GRACE_TICKS));
    assert_eq!(wake.expire(100 + WAKE_GRACE_TICKS), 1);
    assert_eq!(wake.held(100 + WAKE_GRACE_TICKS), 0);
}

/// A full table does not lose the *event*. The count is what a commit
/// compares, and it has already moved — so a machine that could not record
/// the grace hold still refuses to suspend through the wake.
#[test]
fn a_full_table_still_counts_the_wake() {
    let mut wake = WakeState::new();
    for _ in 0..MAX_WAKE_HOLDS {
        wake.acquire(MANAGER, None).expect("fits");
    }
    assert_eq!(wake.acquire(MANAGER, None), Err(WakeError::NoSpace));
    let before = wake.events();
    assert!(!wake.record_wake(SOURCE, 0), "no room for the grace hold");
    assert_eq!(wake.events(), before + 1, "but the event was counted");
}

/// A held hold vetoes and a released one does not — the whole kernel side
/// of a wake hold.
#[test]
fn a_hold_vetoes_until_it_is_released() {
    let mut wake = WakeState::new();
    assert!(!wake.vetoed(0));
    wake.acquire(MANAGER, None).expect("acquire");
    assert!(wake.vetoed(0));
    assert!(wake.vetoed(u64::MAX), "no deadline means it never expires");
    assert!(wake.release(MANAGER));
    assert!(!wake.vetoed(0));
    assert!(
        !wake.release(MANAGER),
        "and there is nothing left to release"
    );
}

/// Two holds are two reasons. Releasing one must not release the other, or
/// a component that took a hold for each of two things it was doing would
/// lose both by finishing one.
#[test]
fn releasing_one_hold_leaves_the_others() {
    let mut wake = WakeState::new();
    wake.acquire(MANAGER, None).expect("a");
    wake.acquire(MANAGER, None).expect("b");
    assert_eq!(wake.held(0), 2);
    assert!(wake.release(MANAGER));
    assert_eq!(wake.held(0), 1);
    assert!(wake.vetoed(0));
}

/// A holder that has gone takes its holds with it. Left behind, they are a
/// machine kept awake by something that no longer exists — and nothing
/// would ever release them, because the thing that would is dead.
#[test]
fn a_departing_holder_takes_every_hold_it_had() {
    let mut wake = WakeState::new();
    wake.acquire(MANAGER, None).expect("a");
    wake.acquire(MANAGER, Some(50)).expect("b");
    wake.acquire(OTHER, None).expect("c");
    assert_eq!(wake.release_all(MANAGER), 2);
    assert_eq!(wake.held(0), 1);
    assert_eq!(wake.holder_at(0, 0), Some(OTHER));
    assert_eq!(wake.release_all(MANAGER), 0);
}

/// Expiry is what makes a hold time-limited by policy rather than by the
/// good behaviour of whoever took it. A hold with no deadline is not swept
/// — every holder that predates deadlines has one, and giving them all a
/// lifetime they never agreed to would break them on the way in.
#[test]
fn expiry_sweeps_deadlines_and_leaves_open_holds() {
    let mut wake = WakeState::new();
    wake.acquire(MANAGER, Some(10)).expect("a");
    wake.acquire(OTHER, Some(20)).expect("b");
    wake.acquire(MANAGER, None).expect("c");
    assert_eq!(wake.expire(5), 0, "nothing has expired yet");
    assert_eq!(wake.expire(10), 1, "the deadline is inclusive");
    assert_eq!(wake.expire(100), 1);
    assert_eq!(wake.held(100), 1, "the open hold survives");
}

/// The counter never goes backwards, because a snapshot taken before a
/// reset would compare equal to a count taken after it — which is exactly
/// the race counting exists to close.
#[test]
fn the_counter_has_no_way_back() {
    let mut wake = WakeState::new();
    for _ in 0..16 {
        wake.record_wake(SOURCE, 0);
        wake.expire(u64::MAX - 1);
    }
    assert_eq!(wake.events(), 16);
    // Releasing and expiring everything leaves the count alone.
    wake.release_all(SOURCE);
    assert_eq!(wake.events(), 16);
    assert_eq!(wake.held(0), 0);
}
