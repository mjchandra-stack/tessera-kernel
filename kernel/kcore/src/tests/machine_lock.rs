// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::machine_lock`.

use super::*;

/// The lock's state is process-wide and the harness runs tests in parallel
/// threads, so this is deliberately **one** test walking its scenarios in
/// sequence. Several would pass most of the time, which is the worst outcome
/// available.
#[test]
fn a_hold_nests_and_a_park_puts_the_whole_of_it_down() {
    forget();
    assert!(!held_here());

    // Nesting is the point: the 173 accesses inside a method must not each be
    // their own critical section, and must not each release one.
    let outer = hold();
    assert!(held_here());
    {
        let _inner = hold();
        assert!(held_here());
    }
    assert!(
        held_here(),
        "an inner hold releasing the lock would open the method's update to \
         another CPU halfway through"
    );

    // A park puts down every level, not one. A method three deep still has to
    // let go of all three, or the thread goes off-CPU owning the tables.
    let _second = hold();
    let observed = park(held_here);
    assert!(!observed, "nothing may be held while the thread is off-CPU");
    assert!(held_here(), "and the hold comes back when it runs again");

    drop(_second);
    drop(outer);
    assert!(
        !held_here(),
        "the depth was restored exactly, not re-derived"
    );

    forget();
}

#[test]
fn a_park_that_skipped_the_release_is_counted_and_not_assumed_away() {
    // The discriminator for the whole module. `park` cannot be made the only
    // way to park — a direct `block_current` still compiles — so the check has
    // to be at the moment the scheduler takes the thread off the CPU. A
    // facility that only counted the parks routed through itself would report
    // zero for exactly the bug it exists to find.
    forget();

    assert_released();
    assert_eq!(parked_holding(), 0, "no hold, nothing to report");
    assert_eq!(report(), &["exec.lock-released-at-park"]);

    let held = hold();
    assert_released();
    assert_eq!(parked_holding(), 1);
    assert!(report().is_empty(), "the claim is withheld, not annotated");
    drop(held);

    forget();
}
