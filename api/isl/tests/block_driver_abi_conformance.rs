// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated ring-3 block service protocol
//! bindings (built by the codegen genrule from `examples/block_driver.isl`,
//! never committed). Proves `BlockReadRequest`/`BlockReadReply` encode to
//! fixed golden layouts and decode back — the first user↔user protocol (the
//! kernel transports it opaquely), so its wire stability rests entirely here.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use block_driver_abi::{BlockReadReply, BlockReadRequest};
use tessera_isl_runtime::{WireError, decode, encode};

/// Golden encoding of the `BlockReadRequest` value below: 24 bytes, LE.
const REQUEST_GOLDEN: [u8; 24] = [
    0x18, 0, 0, 0, // size = 24
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x2a, 0, 0, 0, 0, 0, 0, 0, // sector = 42
];

#[test]
fn block_read_request_matches_golden_and_round_trips() {
    assert_eq!(BlockReadRequest::WIRE_SIZE, 24);
    let value = BlockReadRequest {
        size: 24,
        version: 1,
        flags: 0,
        sector: 42,
    };
    let mut buf = [0u8; 24];
    assert_eq!(encode(&value, &mut buf).unwrap(), 24);
    assert_eq!(buf, REQUEST_GOLDEN);
    assert_eq!(decode::<BlockReadRequest>(&REQUEST_GOLDEN).unwrap(), value);
}

#[test]
fn block_read_reply_matches_golden_and_round_trips() {
    assert_eq!(BlockReadReply::WIRE_SIZE, 88);
    // A non-trivial data array: the disk magic then a counting pattern, so
    // the golden covers real bytes rather than agreeing with zeroes.
    let mut data = [0u8; 64];
    data[..8].copy_from_slice(b"TESSERAV");
    for (i, slot) in data[8..].iter_mut().enumerate() {
        *slot = i as u8;
    }
    let value = BlockReadReply {
        size: 88,
        version: 1,
        flags: 0,
        status: 0,
        reserved: 0,
        data,
    };
    let mut golden = [0u8; 88];
    golden[0..4].copy_from_slice(&88u32.to_le_bytes());
    golden[4..8].copy_from_slice(&1u32.to_le_bytes());
    // flags @8, status @16, reserved @20 all zero.
    golden[24..88].copy_from_slice(&data);

    let mut buf = [0u8; 88];
    assert_eq!(encode(&value, &mut buf).unwrap(), 88);
    assert_eq!(buf, golden);
    assert_eq!(decode::<BlockReadReply>(&golden).unwrap(), value);
}

#[test]
fn a_truncated_buffer_is_rejected() {
    assert_eq!(
        decode::<BlockReadRequest>(&REQUEST_GOLDEN[..16]),
        Err(WireError::ShortBuffer)
    );
}
