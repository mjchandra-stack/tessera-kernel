// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

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
