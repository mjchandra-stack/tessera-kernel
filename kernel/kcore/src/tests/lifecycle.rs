// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::lifecycle`.

use super::*;
use DriverState::*;

const ALL: [DriverState; 13] = [
    Discovered, Matched, Starting, Probing, Active, Suspending, Suspended, Resuming, Resetting,
    Degraded, Stopping, Removed, Failed,
];

const DEVICE: ObjectId = ObjectId::from_raw(26);

/// The point of writing the edges as data: every one of the 169 ordered
/// pairs has an answer, and none of them panics or falls off the end of a
/// match. Written as scattered conditions, the illegal pairs would be the
/// ones nobody thought to write a condition for.
#[test]
fn every_state_pair_has_an_answer() {
    let mut legal_edges = 0;
    for from in ALL {
        for to in ALL {
            if legal(from, to) {
                legal_edges += 1;
            }
        }
    }
    // Not a magic number to be updated when the table changes — a floor
    // and a ceiling. Below the floor the table cannot express the ladder;
    // at the ceiling it would be permitting everything, which is the same
    // as having no table.
    assert!(legal_edges > 20, "the table cannot express the ladder");
    assert!(legal_edges < ALL.len() * ALL.len(), "everything is legal");
}

/// A self-edge is not a transition, and recording one would put an event
/// in the stream describing a change that did not happen.
#[test]
fn no_state_transitions_to_itself() {
    for state in ALL {
        assert!(!legal(state, state), "{state:?} -> itself");
    }
}

/// `Removed` is the end. A re-plugged device is a new discovery of what
/// may or may not be the same hardware, and it gets a fresh node.
#[test]
fn removed_is_terminal() {
    for to in ALL {
        assert!(!legal(Removed, to), "Removed -> {to:?}");
    }
}

/// `Failed` is terminal but not final: it can be removed, or deliberately
/// re-discovered. That is what makes quarantine reversible by an
/// administrator rather than only by a crash loop.
#[test]
fn failed_is_reversible_only_by_removal_or_rediscovery() {
    assert!(legal(Failed, Removed));
    assert!(legal(Failed, Discovered));
    for to in ALL {
        if matches!(to, Removed | Discovered | Failed) {
            continue;
        }
        assert!(!legal(Failed, to), "Failed -> {to:?}");
    }
}

/// The crash-recovery ladder, walked as edges: a working device degrades,
/// is reset, comes back through probing to service — and, on the other
/// branch, degrades, restarts its host, and fails when the budget is out.
#[test]
fn the_ladder_is_a_path_through_the_table() {
    assert!(legal(Active, Degraded), "step 2: mark degraded");
    assert!(legal(Degraded, Resetting), "step 5: attempt a reset");
    assert!(legal(Resetting, Probing), "the driver re-probes");
    assert!(legal(Probing, Active), "step 7: binding restored");

    assert!(legal(Degraded, Starting), "step 6: restart the host");
    assert!(legal(Degraded, Failed), "the budget is spent");
    assert!(legal(Failed, Removed), "and quarantine can be undone");
}

/// A crash does not wait for a convenient state, so everything with a
/// running driver behind it can degrade — with one exception that is the
/// ladder's shape rather than an omission. From `Resetting` the system has
/// already decided the device is unhealthy and is applying its last weaker
/// remedy; a reset that does not work is `Failed`, and allowing it to be
/// recorded as merely degraded would let the ladder loop for ever one rung
/// below its end.
#[test]
fn anything_bound_can_degrade() {
    for state in ALL {
        if !is_bound(state) || matches!(state, Degraded | Resetting) {
            continue;
        }
        assert!(legal(state, Degraded), "{state:?} -> Degraded");
    }
    assert!(!legal(Resetting, Degraded));
    // And nothing unbound can: a Discovered device whose manager reports a
    // driver crash is describing a crash of a driver that never started.
    assert!(!legal(Discovered, Degraded));
    assert!(!legal(Matched, Degraded));
}

/// Power is a sequence, not a pair of flags: a device cannot jump from
/// Active to Suspended without passing through Suspending, because the
/// intermediate state is exactly where a suspend can fail.
#[test]
fn power_transitions_pass_through_their_intermediate_states() {
    assert!(legal(Active, Suspending));
    assert!(!legal(Active, Suspended));
    assert!(legal(Suspending, Suspended));
    assert!(legal(Suspended, Resuming));
    assert!(!legal(Suspended, Active));
    assert!(legal(Resuming, Active));
}

/// A lifecycle opens at the beginning or not at all. Without this, a
/// manager's first claim about a device could assert `Active` and skip
/// every state that would have had to happen first — and the kernel, with
/// nothing recorded to compare against, would have no way to object.
#[test]
fn a_lifecycle_cannot_open_part_way_through() {
    let mut table = LifecycleTable::new();
    assert_eq!(
        table.declare(DEVICE, Active, Degraded),
        Err(TransitionError::StaleFrom {
            recorded: Discovered
        }),
    );
    assert_eq!(table.state_of(DEVICE), None, "and nothing was recorded");
    // From the beginning it is accepted.
    assert_eq!(table.declare(DEVICE, Discovered, Matched), Ok(()));
    assert_eq!(table.state_of(DEVICE), Some(Matched));
}

/// The clause that makes the record stream a sequence rather than a set: a
/// transition whose `from` disagrees with what the kernel already recorded
/// is refused, and the recorded state is handed back so the caller knows
/// what it actually is.
#[test]
fn a_transition_from_the_wrong_state_is_refused() {
    let mut table = LifecycleTable::new();
    table.declare(DEVICE, Discovered, Matched).expect("open");
    assert_eq!(
        table.declare(DEVICE, Active, Degraded),
        Err(TransitionError::StaleFrom { recorded: Matched }),
    );
    // Refused means unchanged, not partially applied.
    assert_eq!(table.state_of(DEVICE), Some(Matched));
}

/// A legal `from` with an illegal edge is refused too, and distinguishably
/// — the caller's history is right and its request is not, which is a
/// different bug from the one above.
#[test]
fn an_illegal_edge_is_refused_distinguishably() {
    let mut table = LifecycleTable::new();
    table.declare(DEVICE, Discovered, Matched).expect("open");
    assert_eq!(
        table.declare(DEVICE, Matched, Active),
        Err(TransitionError::Illegal),
        "a device cannot reach service without being started and probed",
    );
    assert_eq!(table.state_of(DEVICE), Some(Matched));
}

/// Two devices have two lifecycles. A table that tracked one state for the
/// whole machine would let one device's transition satisfy another's
/// `from` check.
#[test]
fn devices_have_independent_lifecycles() {
    let mut table = LifecycleTable::new();
    let other = ObjectId::from_raw(27);
    table.declare(DEVICE, Discovered, Matched).expect("a");
    table.declare(other, Discovered, Matched).expect("b");
    table.declare(DEVICE, Matched, Starting).expect("a again");
    assert_eq!(table.state_of(DEVICE), Some(Starting));
    assert_eq!(table.state_of(other), Some(Matched), "untouched");
    assert_eq!(table.tracked(), 2);
}

/// A node leaving the graph takes its lifecycle with it, so a re-plugged
/// device does not inherit the history of whatever used to be there.
#[test]
fn forgetting_a_device_clears_its_history() {
    let mut table = LifecycleTable::new();
    table.declare(DEVICE, Discovered, Matched).expect("open");
    table.forget(DEVICE);
    assert_eq!(table.state_of(DEVICE), None);
    assert_eq!(table.tracked(), 0);
    // And the next lifecycle for that object starts at the beginning
    // again rather than continuing the old one.
    assert_eq!(
        table.declare(DEVICE, Matched, Starting),
        Err(TransitionError::StaleFrom {
            recorded: Discovered
        }),
    );
}

/// Leaves before parents, as a rule over states rather than a property of
/// whoever walks the tree. A bus going down under a device that is still
/// serving is the failure the ordering exists to prevent.
#[test]
fn a_parent_cannot_suspend_under_a_live_child() {
    assert_eq!(
        neighbours_permit(Suspending, &[Some(Active)], None),
        Err(NeighbourBlock::Child {
            index: 0,
            state: Active,
        }),
    );
    // The second child is named, not the first — a refusal that always
    // blamed child zero would send whoever is investigating to the wrong
    // device.
    assert_eq!(
        neighbours_permit(Suspending, &[Some(Suspended), Some(Resuming)], None),
        Err(NeighbourBlock::Child {
            index: 1,
            state: Resuming,
        }),
    );
    // Every child suspended, and the parent may go.
    assert_eq!(
        neighbours_permit(Suspending, &[Some(Suspended), Some(Suspended)], None),
        Ok(()),
    );
    assert_eq!(neighbours_permit(Suspending, &[], None), Ok(()), "a leaf");
}

/// The mirror: a leaf cannot come up through a bus that is still down. Its
/// registers are not reachable and its interrupts do not arrive, so a
/// resume that succeeded would be a driver talking to nothing.
#[test]
fn a_child_cannot_resume_through_a_suspended_parent() {
    assert_eq!(
        neighbours_permit(Resuming, &[], Some(Suspended)),
        Err(NeighbourBlock::Parent { state: Suspended }),
    );
    assert_eq!(
        neighbours_permit(Resuming, &[], Some(Resuming)),
        Err(NeighbourBlock::Parent { state: Resuming }),
        "a parent part-way back is not back",
    );
    assert_eq!(neighbours_permit(Resuming, &[], Some(Active)), Ok(()));
    assert_eq!(neighbours_permit(Resuming, &[], None), Ok(()), "no parent");
}

/// A neighbour with no recorded state, or one that is not bound, does not
/// block. Anything else would let a device nobody is using stop the
/// machine suspending for ever — which is a machine that never sleeps
/// because of hardware that is not there.
#[test]
fn an_unbound_neighbour_is_not_something_to_wait_for() {
    for child in [None, Some(Removed), Some(Failed), Some(Discovered)] {
        assert_eq!(
            neighbours_permit(Suspending, &[child], None),
            Ok(()),
            "{child:?} should not block a parent",
        );
    }
    for parent in [None, Some(Removed), Some(Failed), Some(Discovered)] {
        assert_eq!(
            neighbours_permit(Resuming, &[], parent),
            Ok(()),
            "{parent:?} should not block a child",
        );
    }
}

/// The ordering applies to the two power transitions and nothing else. A
/// crash does not wait for its neighbours, and neither does a removal —
/// requiring them to would mean a device that could not be recorded as
/// failed until its bus agreed.
#[test]
fn only_the_power_transitions_are_ordered() {
    for to in ALL {
        if matches!(to, Suspending | Resuming) {
            continue;
        }
        assert_eq!(
            neighbours_permit(to, &[Some(Active)], Some(Suspended)),
            Ok(()),
            "{to:?} should not consult its neighbours",
        );
    }
}

#[test]
fn a_full_table_refuses_rather_than_forgetting_a_device() {
    let mut table = LifecycleTable::new();
    for i in 0..MAX_TRACKED {
        table
            .declare(ObjectId::from_raw(i as u32 + 1), Discovered, Matched)
            .expect("fits");
    }
    assert_eq!(
        table.declare(ObjectId::from_raw(0xfff), Discovered, Matched),
        Err(TransitionError::OutOfSpace),
    );
}
