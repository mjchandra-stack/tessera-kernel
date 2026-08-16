// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel's half of power management: the **system wake-event counter**
//! and the **wake holds** that veto a suspend.
//!
//! `docs/power/01-power-management.md` splits the work in two. The power
//! manager owns policy — when to suspend, when to idle, who may hold a wake
//! hold — and it lives in ring 3 (`//api/power`, `userspace/power-manager`).
//! What lives here is the part whose correctness cannot survive a service
//! round trip, because it has to be true *while the service is not running*: a
//! device interrupt that arrives during suspend entry has nobody to tell.
//!
//! # Why a counter and not a flag
//!
//! The lost-wakeup race is the one failure a suspend path has that ordering
//! alone cannot fix. Between the moment the manager decides to suspend and the
//! moment the CPU stops, a wake source can fire; if that event is merely
//! *delivered* — to a frozen process, to a port nobody is draining — the
//! machine goes to sleep with the reason to stay awake already past. A flag
//! set by the handler and cleared by the entry path races the same way, one
//! layer down.
//!
//! Counting closes it without any ordering at all. The manager takes a
//! snapshot before it begins, and the commit refuses if the counter has moved
//! since. Whether the event arrived before, during, or after the snapshot does
//! not matter — it either changed the number or it did not, and if it did the
//! entry aborts. `docs/power/01`: *"the lost-wakeup race is closed by
//! counting, not by hoping."*
//!
//! # Why a hold is a record and not an object
//!
//! `docs/power/01` calls wake holds "capability-gated objects granted by the
//! power manager, time-limited by policy, attributed to a component". The
//! gating is a capability here — `Rights::WAKE` on the power object — and the
//! hold itself is a **record in a bounded table**, attributed to the process
//! that took it and carrying a deadline. Making each hold its own kernel
//! object would buy transferability, which is precisely the property a
//! suspend blocker should not have: a hold that can be handed on is a hold
//! whose holder cannot be held responsible for it, which is the wakelock
//! lesson this design is written against.
//!
//! The deadline is in **scheduler ticks**, the only monotonic source the
//! kernel has, and it is a *liveness* bound rather than a wall clock — it
//! answers "is the holder still asking for this", exactly as a DMA lease's
//! deadline does (D135). A hold with no deadline never expires, because the
//! grace holds this facility takes for itself are the only ones that must, and
//! a policy that gave every hold a lifetime nobody agreed to would break its
//! users on the way in.
//!
//! Normative: docs/power/01-power-management.md ("Wakeup Sources And Wake
//! Holds"), docs/api/01-system-call-interface.md ("Power")
//! Budget: none (a counter and a bounded scan)

use crate::object::ObjectId;

/// Wake holds the kernel tracks at once.
///
/// Bounded like every pool here, and small deliberately: a full table is a
/// reportable condition, and a suspend blocker that could be taken without
/// limit is a machine that never sleeps for a reason nobody can enumerate.
pub const MAX_WAKE_HOLDS: usize = 8;

/// How long the grace hold a wake event takes for itself lasts, in scheduler
/// ticks.
///
/// Its job is narrow: an event that arrives *just after* a resume must not be
/// lost to an immediate re-suspend, and the manager needs to have been
/// scheduled at least once to see it. Short, because a grace period is not a
/// policy — it is the width of the window between the kernel knowing and the
/// service knowing.
pub const WAKE_GRACE_TICKS: u64 = 4;

/// Why a wake hold could not be taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WakeError {
    /// The table is full. Reported rather than silently not taken: a hold
    /// somebody believes they have and does not is a machine that suspends
    /// under a component that asked it not to.
    NoSpace,
}

/// One wake hold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Hold {
    /// Who is holding it. Attribution is not observability decoration — it is
    /// what makes an abusive holder nameable, and what lets a departing
    /// process's holds go with it.
    holder: ObjectId,
    /// The tick after which it stops counting, or `None` for a hold that lasts
    /// until it is released.
    expires_at: Option<u64>,
}

/// The system wake-event counter and the live wake holds.
pub struct WakeState {
    events: u64,
    holds: [Option<Hold>; MAX_WAKE_HOLDS],
}

impl WakeState {
    pub const fn new() -> Self {
        Self {
            events: 0,
            holds: [const { None }; MAX_WAKE_HOLDS],
        }
    }

    /// The system wake-event counter.
    ///
    /// Monotonic and never reset. A counter that could be zeroed would let a
    /// snapshot taken before the reset compare equal to a count taken after
    /// it, which is the race this whole facility exists to close.
    pub const fn events(&self) -> u64 {
        self.events
    }

    /// Records that `source` woke the machine, and takes a grace hold for it.
    ///
    /// Called from interrupt context, so it does exactly two things and
    /// neither of them can fail in a way that matters: the counter always
    /// moves, and the grace hold is taken **if there is room**. A full table
    /// does not lose the event — the count is what the commit compares, and it
    /// has already changed.
    ///
    /// Answers whether the grace hold was taken, so a caller that cares can
    /// say so rather than assume.
    pub fn record_wake(&mut self, source: ObjectId, now: u64) -> bool {
        self.events = self.events.wrapping_add(1);
        self.acquire(source, Some(now + WAKE_GRACE_TICKS)).is_ok()
    }

    /// Takes a hold for `holder`, expiring at `expires_at`.
    ///
    /// A holder may take more than one — they are separate reasons to stay
    /// awake and releasing one must not release the others. What bounds it is
    /// the table.
    pub fn acquire(&mut self, holder: ObjectId, expires_at: Option<u64>) -> Result<(), WakeError> {
        let slot = self
            .holds
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(WakeError::NoSpace)?;
        *slot = Some(Hold { holder, expires_at });
        Ok(())
    }

    /// Releases one of `holder`'s holds. Answers whether there was one.
    ///
    /// One rather than all, because a holder with two holds has two reasons
    /// and giving up one is not giving up the other. [`release_all`] is the
    /// operation for a holder that has gone.
    pub fn release(&mut self, holder: ObjectId) -> bool {
        match self
            .holds
            .iter_mut()
            .find(|slot| matches!(slot, Some(hold) if hold.holder == holder))
        {
            Some(slot) => {
                *slot = None;
                true
            }
            None => false,
        }
    }

    /// Releases every hold `holder` has, and answers how many went — for a
    /// process that has died or departed, where leaving its holds behind would
    /// be a machine kept awake by something that no longer exists.
    pub fn release_all(&mut self, holder: ObjectId) -> usize {
        let mut released = 0;
        for slot in self.holds.iter_mut() {
            if matches!(slot, Some(hold) if hold.holder == holder) {
                *slot = None;
                released += 1;
            }
        }
        released
    }

    /// Drops every hold whose deadline has passed, and answers how many.
    ///
    /// Expiry is what makes a hold time-limited by policy rather than by the
    /// good behaviour of whoever took it — the wakelock lesson in one method.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut expired = 0;
        for slot in self.holds.iter_mut() {
            if matches!(slot, Some(hold) if hold.expires_at.is_some_and(|at| at <= now)) {
                *slot = None;
                expired += 1;
            }
        }
        expired
    }

    /// Holds still counting at `now`.
    pub fn held(&self, now: u64) -> usize {
        self.holds
            .iter()
            .flatten()
            .filter(|hold| hold.expires_at.is_none_or(|at| at > now))
            .count()
    }

    /// Whether a suspend commit is vetoed at `now`.
    ///
    /// **The kernel side of a wake hold is exactly this and nothing else.**
    /// There is no polling, no callback and no notification: a held hold
    /// refuses the final commit, and everything about deciding whether to try
    /// again is the manager's.
    pub fn vetoed(&self, now: u64) -> bool {
        self.held(now) > 0
    }

    /// Who holds the *n*th live hold at `now`, for attribution in a refusal —
    /// so "somebody vetoed this" can name them.
    pub fn holder_at(&self, now: u64, index: usize) -> Option<ObjectId> {
        self.holds
            .iter()
            .flatten()
            .filter(|hold| hold.expires_at.is_none_or(|at| at > now))
            .nth(index)
            .map(|hold| hold.holder)
    }
}

impl Default for WakeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
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
}
