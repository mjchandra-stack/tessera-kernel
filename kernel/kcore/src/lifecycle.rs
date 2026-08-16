// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The driver lifecycle: which of the thirteen states a device is in, and
//! which moves between them are legal.
//!
//! **Who owns what.** The device manager owns the lifecycle — it decides when
//! a device is Matched, when probing has failed, when a degraded device is
//! worth resetting — because every one of those answers needs a driver table,
//! a class map, and a binding policy, none of which belong in a kernel. What
//! lives here is the two things a manager must not be the only holder of: the
//! **table of legal edges**, and the **state each device is actually in**.
//!
//! That split is not bureaucracy. `docs/drivers/01` asks for transitions to be
//! "observable through structured events", and a record stream is only
//! evidence if it is a *sequence*: a manager that emitted `Active -> Degraded`
//! twice, or skipped `Probing` entirely, would produce a perfectly plausible
//! history that never happened, and nothing downstream could tell. Validating
//! at the trust boundary — where the manager declares and the kernel records —
//! is what makes the difference. The kernel is not judging the policy; it is
//! checking that the story is consistent with the one it has already been told.
//!
//! **Why a table and not a check per call site.** Thirteen states admit 169
//! ordered pairs, of which a few dozen are meaningful. Written as conditions
//! scattered through a manager, the illegal ones are the ones nobody wrote a
//! condition for; written as data, every pair has an answer and the answers can
//! be tested exhaustively. [`legal`] is that data, and
//! `every_state_pair_has_an_answer` walks all 169.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Lifecycle")
//! Budget: none (a manager-driven control path)

/// The ISL-generated vocabulary, re-exported so emitters and consumers name
/// the states through this module rather than the private binding.
pub use crate::isl_binding::lifecycle::{DriverState, LifecycleTransitionArgs, TransitionReason};

use crate::object::ObjectId;

/// Devices the lifecycle table tracks — one per resource-graph node, because a
/// device that can be bound is a device that can have a lifecycle.
pub const MAX_TRACKED: usize = crate::devmgr::MAX_DEVICES;

/// Whether `from -> to` is a legal move.
///
/// The rules, in the order they decide:
///
/// 1. **A state never transitions to itself.** Not because it is harmful, but
///    because it is not a transition, and recording one would put an event in
///    the stream describing a change that did not happen.
/// 2. **`Removed` is terminal.** The device is gone from the machine; a
///    lifecycle cannot continue for hardware that is not there. Re-plugging is
///    a *new* discovery, of what may or may not be the same device, and the
///    graph gives it a fresh node.
/// 3. **`Failed` is terminal but not final.** A failed device may be
///    `Removed` — pulled, or its binding dismantled — and may be
///    `Discovered` again by a deliberate re-enumeration, which is what makes
///    quarantine reversible by an administrator rather than by a crash loop.
/// 4. **Anything bound can fail or degrade.** A crash does not wait for a
///    convenient state, so every state that has a running driver behind it —
///    `Starting` onward — can move to `Degraded` or `Failed`.
/// 5. Everything else is the ladder and the power sequence, written out.
pub const fn legal(from: DriverState, to: DriverState) -> bool {
    use DriverState::*;
    // A self-edge is never a transition.
    if from as u32 == to as u32 {
        return false;
    }
    match (from, to) {
        // Discovery to binding. A device may also be removed before anyone
        // binds it — hotplug does not wait for a manager to finish deciding —
        // and may fail to bind at all, which is Failed rather than Degraded:
        // nothing is running to be degraded.
        (Discovered, Matched | Removed | Failed) => true,
        (Matched, Starting | Removed | Failed) => true,
        // Bring-up. `Starting -> Failed` is a host that could not be launched;
        // `Probing -> Failed` is a driver that ran and could not confirm its
        // device, which is a different fact and the reason both edges exist.
        (Starting, Probing | Degraded | Stopping | Removed | Failed) => true,
        (Probing, Active | Degraded | Stopping | Removed | Failed) => true,
        // In service. Everything a working device can do next.
        (Active, Suspending | Resetting | Degraded | Stopping | Removed | Failed) => true,
        // Power. A suspend or resume that goes wrong lands in Degraded rather
        // than Failed: the device is still there and still bound, and the
        // system has not yet decided it is unusable.
        (Suspending, Suspended | Degraded | Removed | Failed) => true,
        // A suspended device's driver is quiescent, not gone: it can still
        // crash doing housekeeping, which is a degradation like any other.
        (Suspended, Resuming | Stopping | Degraded | Removed | Failed) => true,
        (Resuming, Active | Degraded | Removed | Failed) => true,
        // Reset — ladder step 5. Success returns the device to service;
        // failure is Failed, not Degraded, because a reset is what the system
        // tries *when* a device is degraded and there is nothing weaker left.
        (Resetting, Active | Probing | Failed | Removed) => true,
        // Degraded — ladder step 2, and the fork the ladder turns on. Reset it
        // (step 5), restart its driver (step 6, back through Starting),
        // restore it directly to service if the failure cleared itself, or
        // stop trying.
        (Degraded, Resetting | Starting | Active | Stopping | Removed | Failed) => true,
        // Teardown.
        (Stopping, Removed | Failed) => true,
        // Failed is terminal but reversible by re-enumeration; Removed is not
        // reversible at all — a re-plugged device is a new node.
        (Failed, Removed | Discovered) => true,
        _ => false,
    }
}

/// Whether a state has a driver host behind it that could crash.
///
/// The predicate ladder step 2 needs: *"the device manager marks the device
/// degraded"* presumes there was something to degrade. A `Discovered` device
/// whose manager reports a driver crash is describing a crash of a driver that
/// was never started, and refusing that is what stops a plausible-looking
/// record stream from being an invented one.
pub const fn is_bound(state: DriverState) -> bool {
    use DriverState::*;
    matches!(
        state,
        Starting | Probing | Active | Suspending | Suspended | Resuming | Resetting | Degraded
    )
}

/// Which neighbour in the device tree blocks a power transition.
///
/// The graph is Phase 2's: `DeviceTable`'s parent edges, walked by the caller,
/// which passes the recorded states in. Keeping the *rule* here and the *walk*
/// there is what makes the rule testable on a list of states with no graph at
/// all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NeighbourBlock {
    /// The child at this index is still bound and not suspended.
    Child { index: usize, state: DriverState },
    /// The parent is bound and not back in service.
    Parent { state: DriverState },
}

/// Whether the device tree permits this transition yet.
///
/// **The suspend order in `docs/power/01` step 5 — leaves before parents —
/// made a property of the machine rather than of one program's loop.** A power
/// manager walks the tree and suspends children first; a manager whose walk is
/// wrong produces a perfectly legal record of a suspend that powered a bus
/// down under a live device, and nothing downstream could tell. This is the
/// check that makes the walk's correctness observable at the moment it is
/// wrong.
///
/// Two rules, mirror images:
///
/// - **`Active -> Suspending` needs every child suspended.** A bus going down
///   under a device that is still serving is the failure the ordering exists
///   to prevent, and the moment to catch it is before the parent's driver
///   starts tearing down.
/// - **`Suspended -> Resuming` needs the parent back.** A leaf cannot come up
///   through a bus that is still down: its registers are not reachable and its
///   interrupts do not arrive, so a resume that succeeded would be a driver
///   talking to nothing.
///
/// **A neighbour with no recorded state does not block.** The table records
/// devices a manager has told the kernel about, so a child with no lifecycle
/// has no driver — there is nothing to suspend and nothing that could be
/// surprised by the bus going away. The same for a state that is not
/// [`is_bound`]: a `Removed` or `Failed` child is not something a parent has
/// to wait for. Anything else would make an unbound device permanently able to
/// stop the machine suspending, which is a machine that never sleeps because
/// of hardware nobody is using.
pub fn neighbours_permit(
    to: DriverState,
    children: &[Option<DriverState>],
    parent: Option<DriverState>,
) -> Result<(), NeighbourBlock> {
    match to {
        DriverState::Suspending => {
            for (index, child) in children.iter().enumerate() {
                if let Some(state) = child
                    && is_bound(*state)
                    && !matches!(state, DriverState::Suspended)
                {
                    return Err(NeighbourBlock::Child {
                        index,
                        state: *state,
                    });
                }
            }
            Ok(())
        }
        DriverState::Resuming => match parent {
            Some(state) if is_bound(state) && !matches!(state, DriverState::Active) => {
                Err(NeighbourBlock::Parent { state })
            }
            _ => Ok(()),
        },
        // Every other transition is the device's own business. A crash does
        // not wait for its neighbours, and neither does a removal.
        _ => Ok(()),
    }
}

/// Why a declared transition was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransitionError {
    /// The caller's `from` is not the state the kernel has recorded. The
    /// manager and the kernel disagree about the device's history, and
    /// recording either version would make the stream a fiction.
    StaleFrom {
        /// What the kernel has.
        recorded: DriverState,
    },
    /// The edge does not exist in the table.
    Illegal,
    /// The table is full — more devices have lifecycles than the resource
    /// graph has nodes, which cannot happen while the graph is the source of
    /// devices and is reported rather than assumed away.
    OutOfSpace,
    /// The edge is legal and the device tree does not permit it **yet**: a
    /// parent suspending under a live child, or a leaf resuming through a bus
    /// that is still down. Distinguishable from [`Self::Illegal`] because the
    /// caller's recovery is different — an illegal edge is a mistake, and this
    /// is an ordering that has not finished.
    OutOfOrder {
        /// The neighbour in the way, and what state it is in.
        neighbour: ObjectId,
        state: DriverState,
    },
}

/// One device's recorded state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Tracked {
    device: ObjectId,
    state: DriverState,
}

/// The kernel's record of where each device is in its lifecycle.
///
/// Bounded like every kcore pool. A device with no entry has **no recorded
/// state**, which is a different thing from being `Discovered`: the first
/// transition a manager declares for a device establishes the entry, and it is
/// the only transition whose `from` the kernel cannot check. That is stated
/// rather than hidden — see [`Self::declare`].
pub struct LifecycleTable {
    tracked: [Option<Tracked>; MAX_TRACKED],
}

impl LifecycleTable {
    pub const fn new() -> Self {
        Self {
            tracked: [const { None }; MAX_TRACKED],
        }
    }

    /// The state recorded for `device`, if any.
    pub fn state_of(&self, device: ObjectId) -> Option<DriverState> {
        self.tracked
            .iter()
            .flatten()
            .find(|t| t.device == device)
            .map(|t| t.state)
    }

    /// Records the transition `from -> to` for `device`, or says why it was
    /// refused.
    ///
    /// **The first transition for a device is trusted, and every one after it
    /// is checked.** There is no way around that: the kernel does not enumerate
    /// lifecycles, so until a manager has told it one thing about a device it
    /// has nothing to compare the next claim against. What it can do — and
    /// does — is refuse a first claim that starts anywhere but at the
    /// beginning: a device's first recorded state must be one nothing precedes
    /// (`Discovered`), so a manager cannot open by asserting a device is
    /// `Active` and skip the states that would have had to happen first.
    pub fn declare(
        &mut self,
        device: ObjectId,
        from: DriverState,
        to: DriverState,
    ) -> Result<(), TransitionError> {
        match self.state_of(device) {
            Some(recorded) if recorded as u32 != from as u32 => {
                return Err(TransitionError::StaleFrom { recorded });
            }
            Some(_) => {}
            None => {
                // Nothing recorded: the claim must start at the beginning.
                // `Discovered` is the only state with no predecessor, so it is
                // the only honest place a lifecycle can open.
                if from as u32 != DriverState::Discovered as u32 {
                    return Err(TransitionError::StaleFrom {
                        recorded: DriverState::Discovered,
                    });
                }
            }
        }
        if !legal(from, to) {
            return Err(TransitionError::Illegal);
        }
        match self
            .tracked
            .iter_mut()
            .flatten()
            .find(|t| t.device == device)
        {
            Some(entry) => entry.state = to,
            None => {
                let slot = self
                    .tracked
                    .iter_mut()
                    .find(|slot| slot.is_none())
                    .ok_or(TransitionError::OutOfSpace)?;
                *slot = Some(Tracked { device, state: to });
            }
        }
        Ok(())
    }

    /// Forgets `device`'s lifecycle — for a node leaving the graph, where
    /// keeping the state would have a re-plugged device inherit the history of
    /// whatever used to be in that slot.
    pub fn forget(&mut self, device: ObjectId) {
        for slot in self.tracked.iter_mut() {
            if matches!(slot, Some(t) if t.device == device) {
                *slot = None;
            }
        }
    }

    /// Devices with a recorded lifecycle.
    pub fn tracked(&self) -> usize {
        self.tracked.iter().flatten().count()
    }
}

impl Default for LifecycleTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
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
}
