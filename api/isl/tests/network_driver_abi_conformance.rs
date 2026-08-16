// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the network class contract's ABI structs.
//!
//! **This is the ABI test, and it is deliberately not the class-conformance
//! suite.** What is checked here is that the bytes are what the schema says:
//! layout, ordering, round-tripping, and the values of the closed enums a
//! stored record is read by. Whether a *driver* honours the contract — that a
//! required method is answered, that an unimplemented optional one says
//! `NOT_SUPPORTED` rather than something worse, that a reset leaves what a
//! reset is defined to leave — is a different question about a different
//! artefact, and lives in `//api/class-conformance`.
//!
//! Both are needed and neither implies the other: a driver can encode every
//! struct perfectly and violate every rule in the contract, and a driver can
//! obey every rule while disagreeing with its client about a field offset.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts"),
//! docs/api/03-interface-schema-language.md ("Wire Format")

use network_driver::{
    NetControlReply, NetControlRequest, NetError, NetPowerState, NetTracePoint, NetTransmitReply,
    NetTransmitRequest,
};
use tessera_isl_runtime::{decode, encode};

/// Golden encoding of a transmit request: 24 bytes of envelope and length,
/// then the 64-byte frame.
const TRANSMIT_GOLDEN_PREFIX: [u8; 24] = [
    0x58, 0, 0, 0, // size = 88
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x2a, 0, 0, 0, // length = 42 (an ARP request)
    0, 0, 0, 0, // reserved
];

#[test]
fn transmit_request_matches_golden_and_round_trips() {
    assert_eq!(NetTransmitRequest::WIRE_SIZE, 88);
    let mut frame = [0u8; 64];
    frame[0] = 0xff;
    frame[41] = 0x5a;
    let value = NetTransmitRequest {
        size: 88,
        version: 1,
        flags: 0,
        length: 42,
        reserved: 0,
        frame,
    };
    let mut buf = [0u8; 88];
    assert_eq!(encode(&value, &mut buf).unwrap(), 88);
    assert_eq!(buf[..24], TRANSMIT_GOLDEN_PREFIX);
    assert_eq!(buf[24], 0xff, "the frame follows the envelope");
    assert_eq!(buf[24 + 41], 0x5a);
    assert_eq!(decode::<NetTransmitRequest>(&buf).unwrap(), value);
}

/// `sent` is a separate field from `status`, and the encoding proves it is
/// carried rather than derived: a truncated send is an outcome a status alone
/// would have to report as a lie in one direction or the other.
#[test]
fn a_transmit_reply_carries_both_an_outcome_and_a_count() {
    let value = NetTransmitReply {
        size: NetTransmitReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: NetError::Ok as u32,
        sent: 42,
    };
    let mut buf = [0u8; NetTransmitReply::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    let decoded: NetTransmitReply = decode(&buf).unwrap();
    assert_eq!(decoded.status, 0);
    assert_eq!(decoded.sent, 42);
}

/// The error set is closed and its values are ABI. This class's set is
/// deliberately not the block class's with words changed: `LINK_DOWN` is a
/// device that still accepts configuration, where the block class's
/// `NO_MEDIUM` is one that can do nothing at all.
#[test]
fn the_error_set_is_closed_and_stable() {
    assert_eq!(NetError::Ok as u32, 0);
    assert_eq!(NetError::BadLength as u32, 1);
    assert_eq!(NetError::IoError as u32, 2);
    assert_eq!(NetError::LinkDown as u32, 3);
    assert_eq!(NetError::NoBuffer as u32, 4);
    assert_eq!(NetError::NotSupported as u32, 5);
    assert_eq!(NetError::Protocol as u32, 6);
    assert_eq!(NetError::Degraded as u32, 7);
}

/// The power states carry the same four names as the block class, which is the
/// point: a power manager arbitrates across every device on the machine and
/// cannot do that against a per-class vocabulary. What differs between the
/// classes is what they cost, and that is reported by `Describe` rather than
/// named here.
#[test]
fn the_power_states_share_the_block_classs_vocabulary() {
    assert_eq!(NetPowerState::Active as u32, 1);
    assert_eq!(NetPowerState::Idle as u32, 2);
    assert_eq!(NetPowerState::Standby as u32, 3);
    assert_eq!(NetPowerState::Off as u32, 4);
}

/// A state the schema does not name is refused rather than decoded into
/// whichever variant sits nearby — the property that makes a strict enum worth
/// having over a bare integer.
#[test]
fn an_unnamed_power_state_is_refused() {
    let value = NetControlRequest {
        size: NetControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: NetPowerState::Active,
        enable: 0,
    };
    let mut buf = [0u8; NetControlRequest::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    assert!(decode::<NetControlRequest>(&buf).is_ok());
    // Byte 16 is the state discriminator; 9 names nothing.
    buf[16] = 9;
    assert!(decode::<NetControlRequest>(&buf).is_err());
}

#[test]
fn control_replies_round_trip() {
    let value = NetControlReply {
        size: NetControlReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: NetError::LinkDown as u32,
        state: NetPowerState::Standby,
    };
    let mut buf = [0u8; NetControlReply::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    assert_eq!(decode::<NetControlReply>(&buf).unwrap(), value);
}

/// The trace points a conformant driver emits. Named in the contract because
/// `docs/drivers/01` requires trace-event schema validation at certification,
/// and a schema nobody wrote down cannot be validated.
#[test]
fn the_trace_points_are_stable() {
    assert_eq!(NetTracePoint::FrameQueued as u32, 1);
    assert_eq!(NetTracePoint::FrameTransmitted as u32, 2);
    assert_eq!(NetTracePoint::FrameReceived as u32, 3);
    assert_eq!(NetTracePoint::FrameDropped as u32, 4);
    assert_eq!(NetTracePoint::DeviceReset as u32, 7);
}
