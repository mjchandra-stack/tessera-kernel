// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated driver-binding protocol bindings
//! (built by the codegen genrule from `examples/driver_bind.isl`, never
//! committed). Proves `BindRequest`/`BindReply` encode to fixed golden
//! layouts and decode back.
//!
//! Like the block protocol this is a user↔user contract the kernel transports
//! opaquely, so its wire stability rests entirely here.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{WireError, decode, encode};

/// Golden encoding of the `BindRequest` value below: 24 bytes, LE.
const REQUEST_GOLDEN: [u8; 24] = [
    0x18, 0, 0, 0, // size = 24
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x01, 0, 0, 0, // class = Block
    0, 0, 0, 0, // reserved = 0
];

/// Golden encoding of the `BindReply` value below: 24 bytes, LE.
const REPLY_GOLDEN: [u8; 24] = [
    0x18, 0, 0, 0, // size = 24
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0, 0, 0, 0, // status = 0 (bound)
    0x02, 0, 0, 0, // class = Network
];

#[test]
fn bind_request_matches_golden_and_round_trips() {
    assert_eq!(BindRequest::WIRE_SIZE, 24);
    let value = BindRequest {
        size: 24,
        version: 1,
        flags: 0,
        class: DeviceClass::Block,
        reserved: 0,
    };
    let mut buf = [0u8; BindRequest::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).expect("encode"), 24);
    assert_eq!(buf, REQUEST_GOLDEN);
    let back: BindRequest = decode(&REQUEST_GOLDEN).expect("decode");
    assert_eq!(back, value);
}

#[test]
fn bind_reply_matches_golden_and_round_trips() {
    assert_eq!(BindReply::WIRE_SIZE, 24);
    let value = BindReply {
        size: 24,
        version: 1,
        flags: 0,
        status: 0,
        class: DeviceClass::Network,
    };
    let mut buf = [0u8; BindReply::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).expect("encode"), 24);
    assert_eq!(buf, REPLY_GOLDEN);
    let back: BindReply = decode(&REPLY_GOLDEN).expect("decode");
    assert_eq!(back, value);
}

/// The classes are a `strict enum`, so a value outside the set is a decode
/// error rather than a silently-carried number. A manager that answered with
/// a class the driver's build does not know must not look like a valid bind.
#[test]
fn an_unknown_class_is_rejected() {
    let mut bytes = REQUEST_GOLDEN;
    bytes[16] = 0x7f;
    assert!(matches!(
        decode::<BindRequest>(&bytes),
        Err(WireError::BadEnum)
    ));
}
