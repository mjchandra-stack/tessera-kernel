// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Power vote arbitration**: what a set of votes on one power domain
//! resolves to, and who lost.
//!
//! `docs/hardware/03-component-interaction-model.md` says drivers express
//! their requirements as votes and that "the power manager arbitrates votes
//! with user intent, battery state, thermal state, policy, and real-time
//! deadlines". Every contract in the tree already declares its half of that —
//! `block_driver.isl` names four device power states and reports the resume
//! latency of the deepest — and nothing has ever weighed one voter's
//! requirement against another's. This is the thing that does.
//!
//! # Why this is a crate and not a kernel module
//!
//! For the reason `api/binding` is: the rule has to run *both* on the host,
//! where a thermal emergency can be provoked deliberately and every ordered
//! pair of levels walked, and inside a ring-3 service, where neither is
//! possible. A kernel that held a latency number it could not verify and a
//! policy it could not test would be holding policy for the sake of being the
//! one holding it (`docs/power/01-power-management.md`, "The Power And
//! Thermal Manager": the service owns arbitration; the kernel owns the
//! mechanisms whose decision rate cannot tolerate a service round trip).
//!
//! # The one rule everything else qualifies
//!
//! **The highest vote wins.** A vote is a *requirement* — the level below
//! which the voter stops working — so a system that averaged them, or took
//! the most recent, or preferred a particular class, would break whichever
//! voter needed most and would do it silently. Everything after that is a
//! constraint from above (thermal, policy) or below (the policy floor), and a
//! constraint that lowers the answer below what the winner asked for is a
//! **degradation that is reported rather than applied quietly**
//! (`docs/lifecycle/04-coding-guidelines.md`, "No silent fallback").
//!
//! Normative: docs/power/01-power-management.md,
//! docs/hardware/03-component-interaction-model.md ("Power Domains")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// A power level, in the vocabulary `docs/hardware/03` defines.
///
/// Ordered, and the ordering *is* the arbitration rule — `Ord` is derived
/// from declaration order, so `Off < Retention < LowPowerActive <
/// FullActive < PerformanceBoost`. Numbered from 1 so zero stays "no level
/// recorded", the same convention `driver_lifecycle.isl` uses and for the
/// same reason: a decoder can tell an absent answer from a real one.
///
/// These values are ABI — `power_manager.isl`'s `PowerLevel` mirrors them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u32)]
pub enum PowerLevel {
    /// Powered down. Whatever was not flushed is gone.
    Off = 1,
    /// Powered down with state retained; resuming restores rather than
    /// re-initializes.
    Retention = 2,
    /// Running, at the lowest rate that still serves.
    LowPowerActive = 3,
    /// Running at the ordinary rate.
    FullActive = 4,
    /// Running above the ordinary rate. Permitted only where policy says so,
    /// which is why it is a level and not a flag: a boost that could not be
    /// refused would be a floor nobody agreed to.
    PerformanceBoost = 5,
}

impl PowerLevel {
    /// The wire value.
    pub const fn raw(self) -> u32 {
        self as u32
    }

    /// The level a wire value names, or `None` for one this build does not
    /// know — including zero, which is the absence of a level rather than a
    /// level.
    pub const fn from_raw(raw: u32) -> Option<PowerLevel> {
        match raw {
            1 => Some(PowerLevel::Off),
            2 => Some(PowerLevel::Retention),
            3 => Some(PowerLevel::LowPowerActive),
            4 => Some(PowerLevel::FullActive),
            5 => Some(PowerLevel::PerformanceBoost),
            _ => None,
        }
    }
}

/// Who is voting.
///
/// The class is not decoration: two of these do not vote at all in the
/// ordinary sense. A `Thermal` entry names the highest level currently
/// permitted rather than a level required, and `Policy` is the installation
/// itself. Keeping them in the same table as the real voters is deliberate —
/// see [`arbitrate`].
///
/// These values are ABI — `power_manager.isl`'s `VoterClass` mirrors them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum VoterClass {
    /// A user-facing program, voting on behalf of somebody's intent.
    User = 1,
    /// A system service.
    Service = 2,
    /// The driver bound to the device, voting for what it needs to serve.
    Driver = 3,
    /// A thermal zone. Its level is a **ceiling**, not a demand.
    Thermal = 4,
    /// The installation's own limits. Never appears in a vote table — it is
    /// the attribution [`arbitrate`] uses when the policy is what bound the
    /// answer, so a clamp always names something.
    Policy = 5,
}

impl VoterClass {
    pub const fn raw(self) -> u32 {
        self as u32
    }

    pub const fn from_raw(raw: u32) -> Option<VoterClass> {
        match raw {
            1 => Some(VoterClass::User),
            2 => Some(VoterClass::Service),
            3 => Some(VoterClass::Driver),
            4 => Some(VoterClass::Thermal),
            5 => Some(VoterClass::Policy),
            _ => None,
        }
    }

    /// Whether a vote of this class is a requirement to be satisfied, rather
    /// than a limit to be respected.
    pub const fn is_demand(self) -> bool {
        matches!(
            self,
            VoterClass::User | VoterClass::Service | VoterClass::Driver
        )
    }
}

/// Who cast a vote. The power manager's own identifier for a voter — an
/// endpoint index in practice — carried through so a resolution can be traced
/// back to the thing that caused it.
pub type VoterId = u32;

/// One vote on one power domain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vote {
    pub voter: VoterId,
    pub class: VoterClass,
    pub level: PowerLevel,
}

/// What this installation permits of a power domain, independent of who is
/// voting on it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PowerPolicy {
    /// The level the domain sits at when nothing demands anything. `Off` is a
    /// legitimate floor; so is `Retention` for a device whose re-initialization
    /// costs more than keeping it warm.
    pub floor: PowerLevel,
    /// The highest level permitted here, or `None` for no policy limit.
    /// Distinct from the thermal ceiling because they are different
    /// administrative situations: one is a decision somebody took and the
    /// other is the machine being too hot.
    pub ceiling: Option<PowerLevel>,
    /// Whether [`PowerLevel::PerformanceBoost`] may be granted at all.
    pub allow_boost: bool,
}

/// What bound the answer below what the winning voter asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Clamp {
    /// The level the winning vote asked for.
    pub from: PowerLevel,
    /// What class took it away.
    pub by: VoterClass,
    /// Which voter, where the clamp came from one. Zero for
    /// [`VoterClass::Policy`], which is the installation rather than a voter.
    pub source: VoterId,
}

/// What a domain's votes resolve to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Resolution {
    /// The level the domain should be driven to.
    pub level: PowerLevel,
    /// The voter whose demand was highest, or `None` when nothing demanded
    /// anything — in which case `level` is the policy floor. The difference
    /// matters: "the floor, because nobody asked" and "the floor, because
    /// somebody asked for exactly that" are different situations, and a
    /// resolution that reported them identically would leave an idle domain
    /// indistinguishable from a busy one that happens to need very little.
    pub winner: Option<VoterId>,
    /// `Some` exactly when `level` is below what `winner` asked for. This is
    /// the no-silent-fallback rule as a field: a degradation nobody is told
    /// about is a degradation nobody can fix.
    pub clamp: Option<Clamp>,
}

/// Resolves one power domain's votes.
///
/// **Thermal readings travel in the same table as the votes**, distinguished
/// by [`VoterClass::Thermal`], and that is a deliberate choice rather than a
/// shortcut. The alternative — a separate thermal argument — means the caller
/// has to route a thermal message somewhere different from every other
/// message, and a caller that routed it wrong would produce a thermal reading
/// treated as a demand: the machine would be driven *up* by being too hot.
/// One table, one message shape, and the class decides the meaning.
///
/// The order, and why each step is where it is:
///
/// 1. **The highest demand wins.** Ties go to the earlier vote, so the result
///    does not depend on the order two equal voters happened to arrive in.
/// 2. **Nothing demanded anything** resolves to the policy floor with no
///    winner and no clamp. Not `Off`: a domain nobody is using is not the
///    same as a domain somebody switched off, and the floor is where that
///    decision lives.
/// 3. **Boost is refused where policy does not permit it**, before the
///    ceilings, because it is a permission rather than a limit — a system
///    that clamped it as if it were a thermal ceiling would report the
///    machine as hot when it is merely not configured for boost.
/// 4. **The thermal ceiling**, then **the policy ceiling**. Thermal first so
///    that when both bind, the clamp names the tighter and more urgent one.
/// 5. **The policy floor raises** whatever is left. Raising is not a
///    degradation and is not reported as a clamp: a voter that asked for less
///    than the floor and got the floor got *more* than it needed, which
///    breaks nothing.
pub fn arbitrate(votes: &[Vote], policy: &PowerPolicy) -> Resolution {
    // 1. The highest demand, earliest on a tie.
    let mut winner: Option<(VoterId, PowerLevel)> = None;
    for vote in votes.iter().filter(|v| v.class.is_demand()) {
        // Strictly greater keeps the earlier voter on a tie.
        if winner.is_none_or(|(_, best)| vote.level > best) {
            winner = Some((vote.voter, vote.level));
        }
    }

    // 2. Nobody asked.
    let Some((winner_id, demanded)) = winner else {
        return Resolution {
            level: policy.floor,
            winner: None,
            clamp: None,
        };
    };

    let mut level = demanded;
    let mut clamp = None;

    // 3. Boost is a permission.
    if !policy.allow_boost && level == PowerLevel::PerformanceBoost {
        level = PowerLevel::FullActive;
        clamp = Some(Clamp {
            from: demanded,
            by: VoterClass::Policy,
            source: 0,
        });
    }

    // 4. The ceilings, tightest reported. A thermal zone reporting several
    // readings is bounded by the lowest of them — the hottest zone is the one
    // that decides.
    let thermal = votes
        .iter()
        .filter(|v| v.class == VoterClass::Thermal)
        .min_by_key(|v| v.level);
    if let Some(ceiling) = thermal
        && ceiling.level < level
    {
        level = ceiling.level;
        clamp = Some(Clamp {
            from: demanded,
            by: VoterClass::Thermal,
            source: ceiling.voter,
        });
    }
    if let Some(ceiling) = policy.ceiling
        && ceiling < level
    {
        level = ceiling;
        clamp = Some(Clamp {
            from: demanded,
            by: VoterClass::Policy,
            source: 0,
        });
    }

    // 5. The floor raises, and raising is not a degradation.
    if level < policy.floor {
        level = policy.floor;
        // A floor that lifts the answer back to or above what was asked for
        // means nothing was taken away after all, and reporting a clamp would
        // name a degradation that did not happen.
        if level >= demanded {
            clamp = None;
        }
    }

    Resolution {
        level,
        winner: Some(winner_id),
        clamp,
    }
}

/// The lowest level a parent may be driven to, given what its children
/// resolved to.
///
/// This is the clause that makes the arbitration happen *across the power
/// dependency graph* rather than once per device in isolation. A bus whose own
/// votes resolve to `Retention` while a device behind it resolved to
/// `FullActive` must still be `FullActive`: the device cannot be reached
/// through a bus that is down, and the vote that keeps the bus up was never
/// cast on it. The edges are Phase 2's — `DeviceTable::children_of` in the
/// kernel, `DeviceChild` from ring 3 — and this is the arithmetic over them.
///
/// `None` for a device with no children, which is not the same as `Some(Off)`:
/// a leaf has no floor imposed from below, and folding the two together would
/// have every leaf in the machine held at whatever `Off` maps to.
pub fn parent_floor(children: &[PowerLevel]) -> Option<PowerLevel> {
    children.iter().copied().max()
}

/// When an unused power domain drops below its floor, and how far.
///
/// Separate from [`PowerPolicy`] because it answers a different question.
/// `PowerPolicy` says where a domain sits *given the votes*; this says what
/// happens when there are none and time passes. A domain nobody is using is
/// not powered down the instant its last user leaves — a user may come
/// straight back, and resuming costs the resume latency the class contract
/// reports — so idling waits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IdlePolicy {
    /// Quiet scheduler ticks before an unvoted domain drops.
    ///
    /// Ticks, and honest about it: they are the only monotonic source this
    /// system has, and this is a liveness bound rather than a wall clock — it
    /// answers "has anybody asked for this lately".
    pub after_ticks: u64,
    /// Where it drops to.
    pub level: PowerLevel,
    /// The most resume latency this domain's users tolerate, in microseconds.
    /// Zero means no bound.
    ///
    /// **This is what `BlockDescribeReply.resume_latency_us` is for.** The
    /// class contracts have reported it since D128 and nothing read it; a
    /// number nobody consumes is a number nobody keeps accurate.
    pub max_resume_latency_us: u64,
}

/// What [`runtime_idle`] decided, and why.
///
/// An enum rather than an `Option<PowerLevel>`, for the reason `api/binding`'s
/// `Refusal` is one: "not idling because somebody is using it", "not
/// idling yet", and "not idling because coming back would take too long" are
/// three different situations with three different fixes, and a manager that
/// reported them identically would leave a domain that never idles looking
/// exactly like one that is permanently busy.
///
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdleDecision {
    /// Somebody is voting. The domain is in use, and the winner is named.
    InUse { winner: VoterId },
    /// Quiet, but not for long enough yet.
    TooSoon { quiet_ticks: u64, needs: u64 },
    /// The state would cost more to leave than this domain's users tolerate.
    ///
    /// **Reported rather than silently staying warm.** A domain that never
    /// idles because of a latency budget and one that never idles because the
    /// timer is wrong look identical from the outside, and only one of them is
    /// somebody's mistake.
    TooSlowToResume {
        resume_latency_us: u64,
        budget_us: u64,
    },
    /// Drop to this level.
    ///
    /// May equal where the domain already is; applying it is idempotent, and a
    /// decision that had to know the current state to be expressible would
    /// make the caller keep two answers consistent instead of one.
    Idle(PowerLevel),
}

/// Whether an unused power domain should drop below its floor, and why not.
///
/// `resume_latency_us` is what the driver's class contract reports for the
/// deepest state it implements — `BlockDescribeReply.resume_latency_us`. It is
/// an input rather than a constant because it is a property of a *device*: a
/// spun-down disc and a link-powered-down SSD differ by orders of magnitude,
/// which is the distinction `BlockPowerState` draws between `IDLE` and
/// `STANDBY` in the first place.
pub fn runtime_idle(
    resolution: &Resolution,
    quiet_ticks: u64,
    resume_latency_us: u64,
    policy: &IdlePolicy,
) -> IdleDecision {
    if let Some(winner) = resolution.winner {
        return IdleDecision::InUse { winner };
    }
    if quiet_ticks < policy.after_ticks {
        return IdleDecision::TooSoon {
            quiet_ticks,
            needs: policy.after_ticks,
        };
    }
    if policy.max_resume_latency_us != 0 && resume_latency_us > policy.max_resume_latency_us {
        return IdleDecision::TooSlowToResume {
            resume_latency_us,
            budget_us: policy.max_resume_latency_us,
        };
    }
    IdleDecision::Idle(policy.level)
}

/// Votes a power manager can hold at once, across every domain.
///
/// Bounded like every pool in this system, and small on purpose: the point of
/// a fixed table is that a full one is a reportable condition rather than an
/// allocation that might fail somewhere with no room to say so.
pub const MAX_VOTES: usize = 16;

/// Why a vote could not be recorded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VoteError {
    /// The table is full. Reported to the voter — a dropped vote is a device
    /// held at the wrong level with nothing anywhere saying why.
    NoSpace,
}

/// The votes a power manager is holding, and the bookkeeping over them.
///
/// This lives here rather than in the manager for the reason [`arbitrate`]
/// does: withdrawal, replacement and the one-vote-per-voter-per-domain rule
/// are where the interesting mistakes are, and none of them can be provoked
/// from inside a ring-3 program that is being driven by a boot script. Here
/// they are ordinary function calls with a test each.
pub struct VoteTable {
    /// `(domain, vote)` pairs. A flat array rather than per-domain buckets:
    /// the table is small, and buckets would fix a maximum number of domains
    /// as well as a maximum number of votes — two limits to be wrong about
    /// instead of one.
    votes: [Option<(u32, Vote)>; MAX_VOTES],
}

impl VoteTable {
    pub const fn new() -> Self {
        Self {
            votes: [const { None }; MAX_VOTES],
        }
    }

    /// Records `vote` on `domain`, replacing this voter's previous vote there.
    ///
    /// **One vote per voter per domain**, which is why there is no separate
    /// "change my vote" operation: a voter that could accumulate votes would
    /// be able to raise a domain by repetition, and the highest of its own
    /// votes would outlive whatever it currently believes it needs.
    pub fn cast(&mut self, domain: u32, vote: Vote) -> Result<(), VoteError> {
        if let Some(slot) = self.find_mut(domain, vote.voter) {
            *slot = Some((domain, vote));
            return Ok(());
        }
        let slot = self
            .votes
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(VoteError::NoSpace)?;
        *slot = Some((domain, vote));
        Ok(())
    }

    /// Drops this voter's vote on `domain`. Answers whether there was one.
    ///
    /// **Withdrawal is not a vote of [`PowerLevel::Off`]**, and the difference
    /// is the whole reason it exists as an operation. `Off` is a requirement
    /// like any other and competes with the rest; withdrawing says the voter
    /// has no opinion, which is what lets a domain fall to the policy floor. A
    /// table with only the first would leave a program that finished its work
    /// holding the domain at whatever it last asked for, for ever.
    pub fn withdraw(&mut self, domain: u32, voter: VoterId) -> bool {
        match self.find_mut(domain, voter) {
            Some(slot) => {
                *slot = None;
                true
            }
            None => false,
        }
    }

    /// Drops every vote this voter holds, on every domain, and answers how
    /// many went — for a voter that has gone away rather than one that changed
    /// its mind.
    pub fn forget_voter(&mut self, voter: VoterId) -> usize {
        let mut dropped = 0;
        for slot in self.votes.iter_mut() {
            if matches!(slot, Some((_, vote)) if vote.voter == voter) {
                *slot = None;
                dropped += 1;
            }
        }
        dropped
    }

    /// What `domain` resolves to under `policy`.
    pub fn resolve(&self, domain: u32, policy: &PowerPolicy) -> Resolution {
        let mut buffer = [Vote {
            voter: 0,
            class: VoterClass::User,
            level: PowerLevel::Off,
        }; MAX_VOTES];
        let mut count = 0;
        for (_, vote) in self.votes.iter().flatten().filter(|(d, _)| *d == domain) {
            buffer[count] = *vote;
            count += 1;
        }
        arbitrate(&buffer[..count], policy)
    }

    /// Votes currently held, across every domain.
    pub fn held(&self) -> usize {
        self.votes.iter().flatten().count()
    }

    fn find_mut(&mut self, domain: u32, voter: VoterId) -> Option<&mut Option<(u32, Vote)>> {
        self.votes
            .iter_mut()
            .find(|slot| matches!(slot, Some((d, vote)) if *d == domain && vote.voter == voter))
    }
}

impl Default for VoteTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PowerLevel::*;

    const ALL: [PowerLevel; 5] = [Off, Retention, LowPowerActive, FullActive, PerformanceBoost];

    const POLICY: PowerPolicy = PowerPolicy {
        floor: Off,
        ceiling: None,
        allow_boost: true,
    };

    const fn demand(voter: VoterId, level: PowerLevel) -> Vote {
        Vote {
            voter,
            class: VoterClass::User,
            level,
        }
    }

    const fn thermal(voter: VoterId, ceiling: PowerLevel) -> Vote {
        Vote {
            voter,
            class: VoterClass::Thermal,
            level: ceiling,
        }
    }

    /// The ordering is the arbitration rule, so it is worth asserting rather
    /// than assuming the derive did what the declaration order says.
    #[test]
    fn the_levels_are_ordered_from_off_upward() {
        for (i, low) in ALL.iter().enumerate() {
            for high in &ALL[i + 1..] {
                assert!(low < high, "{low:?} < {high:?}");
            }
        }
        assert_eq!(Off.raw(), 1, "zero stays 'no level recorded'");
        assert_eq!(PerformanceBoost.raw(), 5);
    }

    #[test]
    fn a_wire_value_round_trips_and_zero_is_not_a_level() {
        for level in ALL {
            assert_eq!(PowerLevel::from_raw(level.raw()), Some(level));
        }
        assert_eq!(PowerLevel::from_raw(0), None);
        assert_eq!(PowerLevel::from_raw(6), None);
        for class in [
            VoterClass::User,
            VoterClass::Service,
            VoterClass::Driver,
            VoterClass::Thermal,
            VoterClass::Policy,
        ] {
            assert_eq!(VoterClass::from_raw(class.raw()), Some(class));
        }
        assert_eq!(VoterClass::from_raw(0), None);
    }

    /// The whole rule, walked over every ordered pair: two voters, and the
    /// answer is the one that asked for more. A system that averaged, or took
    /// the last, would break the voter that needed most.
    #[test]
    fn the_highest_demand_wins_over_every_pair() {
        for a in ALL {
            for b in ALL {
                let votes = [demand(1, a), demand(2, b)];
                let resolved = arbitrate(&votes, &POLICY);
                assert_eq!(resolved.level, a.max(b), "{a:?} vs {b:?}");
                assert_eq!(resolved.clamp, None);
                // Ties keep the earlier voter, so the answer does not depend
                // on the order two equal voters arrived in.
                let expected = if b > a { 2 } else { 1 };
                assert_eq!(resolved.winner, Some(expected), "{a:?} vs {b:?}");
            }
        }
    }

    /// Nobody asking is not the same as somebody asking for nothing. The
    /// floor is where that decision lives, and the absent winner is what tells
    /// an idle domain from a busy one that needs very little.
    #[test]
    fn no_demands_resolve_to_the_floor_with_nobody_named() {
        let policy = PowerPolicy {
            floor: Retention,
            ..POLICY
        };
        let resolved = arbitrate(&[], &policy);
        assert_eq!(resolved.level, Retention);
        assert_eq!(resolved.winner, None);
        assert_eq!(resolved.clamp, None);

        // And a domain where somebody asked for exactly the floor is
        // distinguishable from it.
        let resolved = arbitrate(&[demand(9, Retention)], &policy);
        assert_eq!(resolved.level, Retention);
        assert_eq!(resolved.winner, Some(9));
    }

    /// A thermal reading is a ceiling, not a demand — the property that makes
    /// carrying it in the same table safe. If it were treated as a vote, a hot
    /// machine would be driven *up* by being hot.
    #[test]
    fn a_thermal_reading_never_raises_the_answer() {
        let votes = [demand(1, Retention), thermal(2, PerformanceBoost)];
        let resolved = arbitrate(&votes, &POLICY);
        assert_eq!(resolved.level, Retention, "the ceiling is not a demand");
        assert_eq!(resolved.winner, Some(1));
        assert_eq!(resolved.clamp, None);

        // With no demand at all, a thermal entry alone leaves the floor.
        assert_eq!(arbitrate(&[thermal(2, FullActive)], &POLICY).winner, None);
    }

    /// The no-silent-fallback rule as a test: a clamp is applied *and*
    /// reported, with what was asked for and who took it away.
    #[test]
    fn a_thermal_clamp_is_reported_with_its_source() {
        let votes = [demand(1, FullActive), thermal(7, Retention)];
        let resolved = arbitrate(&votes, &POLICY);
        assert_eq!(resolved.level, Retention);
        assert_eq!(resolved.winner, Some(1));
        assert_eq!(
            resolved.clamp,
            Some(Clamp {
                from: FullActive,
                by: VoterClass::Thermal,
                source: 7,
            })
        );
    }

    /// The hottest zone decides. Two readings and the lower one binds — the
    /// alternative would let a cool zone's ceiling mask a hot one's.
    #[test]
    fn the_lowest_thermal_ceiling_binds() {
        let votes = [
            demand(1, PerformanceBoost),
            thermal(7, LowPowerActive),
            thermal(8, Retention),
        ];
        let resolved = arbitrate(&votes, &POLICY);
        assert_eq!(resolved.level, Retention);
        assert_eq!(resolved.clamp.map(|c| c.source), Some(8));
    }

    /// Thermal and policy are different administrative situations, so when
    /// both would bind, the clamp names the tighter one rather than whichever
    /// the code happened to apply last.
    #[test]
    fn the_tighter_ceiling_is_the_one_named() {
        let hot = PowerPolicy {
            ceiling: Some(LowPowerActive),
            ..POLICY
        };
        let votes = [demand(1, PerformanceBoost), thermal(7, Retention)];
        assert_eq!(
            arbitrate(&votes, &hot).clamp.map(|c| c.by),
            Some(VoterClass::Thermal),
        );
        // And the other way round, with the policy the tighter of the two.
        let votes = [demand(1, PerformanceBoost), thermal(7, FullActive)];
        let resolved = arbitrate(&votes, &hot);
        assert_eq!(resolved.level, LowPowerActive);
        assert_eq!(resolved.clamp.map(|c| c.by), Some(VoterClass::Policy));
    }

    /// Boost is a permission, refused before the ceilings so that a system
    /// merely not configured for boost does not report itself as hot.
    #[test]
    fn boost_is_refused_as_policy_and_not_as_heat() {
        let no_boost = PowerPolicy {
            allow_boost: false,
            ..POLICY
        };
        let resolved = arbitrate(&[demand(1, PerformanceBoost)], &no_boost);
        assert_eq!(resolved.level, FullActive);
        assert_eq!(
            resolved.clamp,
            Some(Clamp {
                from: PerformanceBoost,
                by: VoterClass::Policy,
                source: 0,
            })
        );
        // And it does not touch a vote that never asked for boost.
        assert_eq!(arbitrate(&[demand(1, FullActive)], &no_boost).clamp, None);
    }

    /// Raising is not a degradation. A voter that asked for less than the
    /// floor and got the floor got more than it needed, and reporting that as
    /// a clamp would name a failure that did not happen.
    #[test]
    fn the_floor_raises_without_reporting_a_clamp() {
        let policy = PowerPolicy {
            floor: LowPowerActive,
            ..POLICY
        };
        let resolved = arbitrate(&[demand(1, Off)], &policy);
        assert_eq!(resolved.level, LowPowerActive);
        assert_eq!(resolved.winner, Some(1));
        assert_eq!(resolved.clamp, None);
    }

    /// A floor above a ceiling is a contradictory policy, and the floor wins
    /// because it is the safety end: a device held below the level it needs to
    /// function is broken, while one held above it merely costs power. The
    /// clamp is withdrawn because nothing was taken away in the end.
    #[test]
    fn a_floor_above_a_ceiling_wins_and_withdraws_the_clamp() {
        let contradictory = PowerPolicy {
            floor: FullActive,
            ceiling: Some(Retention),
            allow_boost: true,
        };
        let resolved = arbitrate(&[demand(1, FullActive)], &contradictory);
        assert_eq!(resolved.level, FullActive);
        assert_eq!(resolved.clamp, None, "nothing was taken away after all");
    }

    /// The graph clause: a parent is at least the maximum of its children, so
    /// a bus cannot go down under a live device.
    #[test]
    fn a_parent_is_held_up_by_its_liveliest_child() {
        assert_eq!(
            parent_floor(&[Retention, FullActive, Off]),
            Some(FullActive)
        );
        assert_eq!(parent_floor(&[Off, Off]), Some(Off));
    }

    /// A leaf has no floor imposed from below, which is not the same as having
    /// one of `Off` — folding them together would hold every leaf in the
    /// machine at whatever `Off` maps to.
    #[test]
    fn a_leaf_has_no_floor_from_below() {
        assert_eq!(parent_floor(&[]), None);
    }

    const DOMAIN: u32 = 1;
    const OTHER: u32 = 2;

    /// A voter has one vote per domain, and voting again replaces it. A table
    /// that accumulated would let a voter raise a domain by repetition, and
    /// the highest of its own past votes would outlive what it currently
    /// believes it needs.
    #[test]
    fn voting_twice_replaces_rather_than_accumulates() {
        let mut table = VoteTable::new();
        table.cast(DOMAIN, demand(1, FullActive)).expect("first");
        table.cast(DOMAIN, demand(1, Retention)).expect("second");
        assert_eq!(table.held(), 1);
        assert_eq!(table.resolve(DOMAIN, &POLICY).level, Retention);
    }

    /// Withdrawal is what lets a domain fall to the floor. A voter that could
    /// only vote `Off` would be stating a requirement, which competes; this
    /// states an absence, which does not.
    #[test]
    fn withdrawing_is_not_the_same_as_voting_off() {
        let policy = PowerPolicy {
            floor: LowPowerActive,
            ..POLICY
        };
        let mut table = VoteTable::new();
        table.cast(DOMAIN, demand(1, FullActive)).expect("cast");

        // Voting `Off` is a demand, and the floor lifts it — the domain does
        // not go down.
        table.cast(DOMAIN, demand(1, Off)).expect("cast off");
        let voted_off = table.resolve(DOMAIN, &policy);
        assert_eq!(voted_off.level, LowPowerActive);
        assert_eq!(voted_off.winner, Some(1), "somebody is still asking");

        // Withdrawing leaves nobody asking, which is a different fact even
        // though this policy resolves both to the same level.
        assert!(table.withdraw(DOMAIN, 1));
        let withdrawn = table.resolve(DOMAIN, &policy);
        assert_eq!(withdrawn.level, LowPowerActive);
        assert_eq!(withdrawn.winner, None, "and now nobody is");
    }

    /// Withdrawing something that was never cast says so rather than
    /// pretending. A manager that could not tell would answer a confused voter
    /// exactly as it answers a correct one.
    #[test]
    fn withdrawing_a_vote_that_was_never_cast_is_reported() {
        let mut table = VoteTable::new();
        assert!(!table.withdraw(DOMAIN, 1));
        table.cast(DOMAIN, demand(1, FullActive)).expect("cast");
        assert!(!table.withdraw(OTHER, 1), "a different domain");
        assert!(!table.withdraw(DOMAIN, 2), "a different voter");
        assert!(table.withdraw(DOMAIN, 1));
        assert_eq!(table.held(), 0);
    }

    /// Domains are independent. A table that resolved across all of them would
    /// have one busy device hold every other device in the machine up.
    #[test]
    fn domains_do_not_see_each_others_votes() {
        let mut table = VoteTable::new();
        table.cast(DOMAIN, demand(1, FullActive)).expect("a");
        table.cast(OTHER, demand(2, Retention)).expect("b");
        assert_eq!(table.resolve(DOMAIN, &POLICY).level, FullActive);
        assert_eq!(table.resolve(OTHER, &POLICY).level, Retention);
        // And a domain nobody has voted on resolves to the floor rather than
        // to whatever the busiest domain is doing.
        assert_eq!(table.resolve(99, &POLICY).winner, None);
    }

    /// A voter that has gone takes every vote it holds with it, on every
    /// domain — the operation a manager needs when a peer closes, as distinct
    /// from a voter changing its mind about one domain.
    #[test]
    fn forgetting_a_voter_clears_it_everywhere() {
        let mut table = VoteTable::new();
        table.cast(DOMAIN, demand(1, FullActive)).expect("a");
        table.cast(OTHER, demand(1, FullActive)).expect("b");
        table.cast(DOMAIN, demand(2, Retention)).expect("c");
        assert_eq!(table.forget_voter(1), 2);
        assert_eq!(table.held(), 1);
        assert_eq!(table.resolve(DOMAIN, &POLICY).winner, Some(2));
        assert_eq!(table.resolve(OTHER, &POLICY).winner, None);
    }

    /// A full table refuses rather than forgetting somebody's vote. A dropped
    /// vote is a device held at the wrong level with nothing anywhere saying
    /// why — which is the failure this whole facility exists to prevent.
    #[test]
    fn a_full_table_refuses_rather_than_dropping_a_vote() {
        let mut table = VoteTable::new();
        for voter in 0..MAX_VOTES as u32 {
            table.cast(DOMAIN, demand(voter, FullActive)).expect("fits");
        }
        assert_eq!(
            table.cast(DOMAIN, demand(999, FullActive)),
            Err(VoteError::NoSpace),
        );
        // And a replacement still fits, because it needs no new slot: a full
        // table must not stop an existing voter from *lowering* its vote.
        assert_eq!(table.cast(DOMAIN, demand(0, Retention)), Ok(()));
        assert_eq!(table.held(), MAX_VOTES);
    }

    const IDLE: IdlePolicy = IdlePolicy {
        after_ticks: 10,
        level: Retention,
        max_resume_latency_us: 0,
    };

    fn unused() -> Resolution {
        arbitrate(&[], &POLICY)
    }

    /// A domain somebody is using does not idle, however long it has been
    /// since anything changed. The winner is named, so a domain that never
    /// idles can say who is holding it.
    #[test]
    fn a_domain_in_use_does_not_idle() {
        let busy = arbitrate(&[demand(4, FullActive)], &POLICY);
        assert_eq!(
            runtime_idle(&busy, u64::MAX, 0, &IDLE),
            IdleDecision::InUse { winner: 4 },
        );
        // Even a voter asking for the lowest level is a voter: it is stating a
        // requirement, and idling under it would take away what it asked for.
        let quiet = arbitrate(&[demand(4, Off)], &POLICY);
        assert_eq!(
            runtime_idle(&quiet, u64::MAX, 0, &IDLE),
            IdleDecision::InUse { winner: 4 },
        );
    }

    /// An unused domain waits. A user may come straight back, and resuming
    /// costs what the class contract reports — so the timeout is the whole
    /// difference between runtime idle and switching a device off.
    #[test]
    fn an_unused_domain_waits_before_it_drops() {
        assert_eq!(
            runtime_idle(&unused(), 9, 0, &IDLE),
            IdleDecision::TooSoon {
                quiet_ticks: 9,
                needs: 10,
            },
        );
        assert_eq!(
            runtime_idle(&unused(), 10, 0, &IDLE),
            IdleDecision::Idle(Retention)
        );
        assert_eq!(
            runtime_idle(&unused(), u64::MAX, 0, &IDLE),
            IdleDecision::Idle(Retention),
        );
    }

    /// The resume latency the class contracts have reported since D128, doing
    /// something at last: a state that costs more to leave than this domain's
    /// users tolerate is not entered, and the refusal says both numbers.
    #[test]
    fn a_state_too_slow_to_leave_is_not_entered_and_says_so() {
        let bounded = IdlePolicy {
            max_resume_latency_us: 5_000,
            ..IDLE
        };
        assert_eq!(
            runtime_idle(&unused(), 100, 50_000, &bounded),
            IdleDecision::TooSlowToResume {
                resume_latency_us: 50_000,
                budget_us: 5_000,
            },
        );
        // At the budget exactly it is permitted — the bound is what users
        // tolerate, not what they tolerate less one microsecond.
        assert_eq!(
            runtime_idle(&unused(), 100, 5_000, &bounded),
            IdleDecision::Idle(Retention),
        );
        // And a policy with no bound does not care how slow the device is.
        assert_eq!(
            runtime_idle(&unused(), 100, u64::MAX, &IDLE),
            IdleDecision::Idle(Retention),
        );
    }

    /// The order the reasons are decided in is itself a decision: a busy
    /// domain is reported busy rather than as too slow to idle, because the
    /// latency is irrelevant while somebody is using it — and reporting the
    /// wrong one sends whoever is investigating to the wrong place.
    #[test]
    fn the_first_reason_that_applies_is_the_one_reported() {
        let bounded = IdlePolicy {
            max_resume_latency_us: 1,
            ..IDLE
        };
        let busy = arbitrate(&[demand(4, FullActive)], &POLICY);
        assert_eq!(
            runtime_idle(&busy, 0, u64::MAX, &bounded),
            IdleDecision::InUse { winner: 4 },
        );
        assert!(matches!(
            runtime_idle(&unused(), 0, u64::MAX, &bounded),
            IdleDecision::TooSoon { .. },
        ));
    }

    /// The transcript the boot proof walks, as three ordinary calls: a driver
    /// asks for what it needs, a user asks for more and gets it, and a thermal
    /// zone takes it away and is named for doing so.
    #[test]
    fn the_three_step_transcript_resolves_as_the_boot_proof_expects() {
        let mut table = VoteTable::new();

        table
            .cast(
                DOMAIN,
                Vote {
                    voter: 1,
                    class: VoterClass::Driver,
                    level: Retention,
                },
            )
            .expect("driver");
        let after_driver = table.resolve(DOMAIN, &POLICY);
        assert_eq!(after_driver.level, Retention);
        assert_eq!(after_driver.winner, Some(1));
        assert_eq!(after_driver.clamp, None);

        table.cast(DOMAIN, demand(2, FullActive)).expect("user");
        let after_user = table.resolve(DOMAIN, &POLICY);
        assert_eq!(after_user.level, FullActive);
        assert_eq!(after_user.winner, Some(2));
        assert_eq!(after_user.clamp, None, "nothing has taken anything away");

        table.cast(DOMAIN, thermal(3, Retention)).expect("thermal");
        let after_thermal = table.resolve(DOMAIN, &POLICY);
        assert_eq!(after_thermal.level, Retention);
        assert_eq!(after_thermal.winner, Some(2), "the user still won the vote");
        assert_eq!(
            after_thermal.clamp,
            Some(Clamp {
                from: FullActive,
                by: VoterClass::Thermal,
                source: 3,
            }),
        );
    }
}
