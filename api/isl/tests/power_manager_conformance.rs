// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated power vote protocol bindings (built
//! by the codegen genrule from `examples/power_manager.isl`, never committed).
//!
//! Like the block and binding protocols this is a user↔user contract the
//! kernel transports opaquely, so its wire stability rests entirely here.
//!
//! The values this file pins down are shared with `//api/power`, which holds
//! the arbitration rule in Rust: the two must agree on what a level is worth,
//! because the crate *compares* levels and a renumbering that reordered them
//! would silently invert the rule rather than fail to decode.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format"),
//! docs/power/01-power-management.md

use power_manager::{
    PowerError, PowerLevel, PowerManager, PowerVoteReply, PowerVoteRequest, VoterClass,
};
use tessera_isl_runtime::{decode, encode};

/// Golden encoding of the `PowerVoteRequest` value below: 32 bytes, LE.
const REQUEST_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x07, 0, 0, 0, // domain = 7
    0x04, 0, 0, 0, // level = FULL_ACTIVE
    0x01, 0, 0, 0, // class = USER
    0, 0, 0, 0, // reserved = 0
];

/// Golden encoding of the `PowerVoteReply` value below: 40 bytes, LE.
///
/// A clamped resolution, because that is the reply worth pinning: the voter
/// asked for `FULL_ACTIVE`, a thermal zone took it down to `RETENTION`, and
/// every one of those three facts is a separate field.
const REPLY_GOLDEN: [u8; 40] = [
    0x28, 0, 0, 0, // size = 40
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0, 0, 0, 0, // status = OK
    0x02, 0, 0, 0, // resolved = RETENTION
    0x04, 0, 0, 0, // clamped_from = FULL_ACTIVE
    0x04, 0, 0, 0, // clamped_by = THERMAL
    0x09, 0, 0, 0, // winner = 9
    0, 0, 0, 0, // reserved = 0
];

#[test]
fn a_vote_matches_golden_and_round_trips() {
    assert_eq!(PowerVoteRequest::WIRE_SIZE, 32);
    let value = PowerVoteRequest {
        size: 32,
        version: 1,
        flags: 0,
        domain: 7,
        level: PowerLevel::FullActive,
        class: VoterClass::User,
        reserved: 0,
    };
    let mut buf = [0u8; PowerVoteRequest::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).expect("encode"), 32);
    assert_eq!(buf, REQUEST_GOLDEN);
    let back: PowerVoteRequest = decode(&REQUEST_GOLDEN).expect("decode");
    assert_eq!(back, value);
}

#[test]
fn a_clamped_resolution_matches_golden_and_round_trips() {
    assert_eq!(PowerVoteReply::WIRE_SIZE, 40);
    let value = PowerVoteReply {
        size: 40,
        version: 1,
        flags: 0,
        status: 0,
        resolved: PowerLevel::Retention,
        clamped_from: PowerLevel::FullActive as u32,
        clamped_by: VoterClass::Thermal as u32,
        winner: 9,
        reserved: 0,
    };
    let mut buf = [0u8; PowerVoteReply::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).expect("encode"), 40);
    assert_eq!(buf, REPLY_GOLDEN);
    let back: PowerVoteReply = decode(&REPLY_GOLDEN).expect("decode");
    assert_eq!(back, value);
}

/// The ordering is the arbitration rule, so the numbers carrying it are ABI in
/// a stronger sense than most: renumbering `RETENTION` above `FULL_ACTIVE`
/// would not fail to decode anywhere, it would quietly invert what "the
/// highest vote wins" means.
#[test]
fn the_levels_are_stable_and_ordered() {
    assert_eq!(PowerLevel::Off as u32, 1);
    assert_eq!(PowerLevel::Retention as u32, 2);
    assert_eq!(PowerLevel::LowPowerActive as u32, 3);
    assert_eq!(PowerLevel::FullActive as u32, 4);
    assert_eq!(PowerLevel::PerformanceBoost as u32, 5);
}

/// Zero is not a level, which is what lets `clamped_from` say "nothing was
/// taken away" in the same field that otherwise carries one.
#[test]
fn zero_is_not_a_level_so_an_unclamped_reply_is_distinguishable() {
    let unclamped = PowerVoteReply {
        size: 40,
        version: 1,
        flags: 0,
        status: 0,
        resolved: PowerLevel::FullActive,
        clamped_from: 0,
        clamped_by: 0,
        winner: 9,
        reserved: 0,
    };
    let mut buf = [0u8; PowerVoteReply::WIRE_SIZE];
    encode(&unclamped, &mut buf).expect("encode");
    let back: PowerVoteReply = decode(&buf).expect("decode");
    assert_eq!(back.clamped_from, 0);
    // And a real level never encodes as zero, so the two can never be
    // confused on the wire.
    for level in [
        PowerLevel::Off,
        PowerLevel::Retention,
        PowerLevel::LowPowerActive,
        PowerLevel::FullActive,
        PowerLevel::PerformanceBoost,
    ] {
        assert_ne!(level as u32, 0);
    }
}

#[test]
fn the_voter_classes_and_errors_are_stable() {
    assert_eq!(VoterClass::User as u32, 1);
    assert_eq!(VoterClass::Service as u32, 2);
    assert_eq!(VoterClass::Driver as u32, 3);
    assert_eq!(VoterClass::Thermal as u32, 4);
    assert_eq!(VoterClass::Policy as u32, 5);
    assert_eq!(PowerError::Ok as u32, 0);
    assert_eq!(PowerError::Protocol as u32, 1);
    assert_eq!(PowerError::NoSuchDomain as u32, 2);
    assert_eq!(PowerError::NoSpace as u32, 3);
    assert_eq!(PowerError::DeviceRefused as u32, 4);
}

/// Withdrawal is a method, not a vote of `OFF`. A protocol with only the
/// second would make a program that finished its work hold the domain at
/// whatever it last asked for, for ever — so the two ordinals existing
/// separately is a property worth asserting rather than assuming.
#[test]
fn withdrawal_has_an_ordinal_of_its_own() {
    assert_eq!(PowerManager::VOTE, 1);
    assert_eq!(PowerManager::WITHDRAW, 2);
    assert_eq!(PowerManager::DESCRIBE, 3);
    assert_eq!(PowerManager::ON_RESOLUTION_CHANGED, 20);
}
