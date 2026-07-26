// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated `handleops` bindings (built by the
//! codegen genrule, never committed). It proves the generated code compiles
//! and that its canonical encoding matches fixed golden byte vectors, decodes
//! back to the same value, and rejects non-canonical input — the "no interface
//! stabilizes without conformance tests" gate.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use handleops::{DuplicateArgs, ObjectType, QueryArgs, Rights};
use tessera_isl_runtime::{HandleRef, WireError, decode, encode};

/// Golden encoding of the `DuplicateArgs` value built in the test below.
/// Little-endian, 8-byte aligned, zero-padded, 40 bytes.
const DUPLICATE_GOLDEN: [u8; 40] = [
    0x28, 0, 0, 0, // size = 40
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x03, 0, 0, 0, // source handle index = 3
    0, 0, 0, 0, // padding to 8-byte boundary
    0x05, 0, 0, 0, 0, 0, 0, 0, // new_rights = READ | DUPLICATE
    0, 0, 0, 0, // reserved [0;4]
    0, 0, 0, 0, // tail padding to size 40
];

fn duplicate_value() -> DuplicateArgs {
    DuplicateArgs {
        size: 40,
        version: 1,
        flags: 0,
        source: HandleRef::new(3),
        new_rights: Rights(Rights::READ.bits() | Rights::DUPLICATE.bits()),
        reserved: [0; 4],
    }
}

#[test]
fn duplicate_args_matches_golden_and_round_trips() {
    assert_eq!(DuplicateArgs::WIRE_SIZE, 40);
    let value = duplicate_value();
    let mut buf = [0u8; 40];
    let n = encode(&value, &mut buf).unwrap();
    assert_eq!(n, 40);
    assert_eq!(
        buf, DUPLICATE_GOLDEN,
        "encoding must match the golden vector"
    );

    let decoded: DuplicateArgs = decode(&DUPLICATE_GOLDEN).unwrap();
    assert_eq!(decoded, value, "golden must decode back to the value");
}

#[test]
fn non_canonical_padding_is_rejected() {
    let mut bytes = DUPLICATE_GOLDEN;
    bytes[20] = 1; // a padding byte
    assert_eq!(
        decode::<DuplicateArgs>(&bytes),
        Err(WireError::NonCanonicalPadding)
    );
}

#[test]
fn undefined_bits_are_rejected() {
    let mut bytes = DUPLICATE_GOLDEN;
    bytes[25] = 0x01; // sets bit 8 of new_rights, which no flag defines
    assert_eq!(decode::<DuplicateArgs>(&bytes), Err(WireError::BadBits));
}

#[test]
fn strict_enum_round_trips_and_rejects_unknown() {
    let value = QueryArgs {
        size: 32,
        version: 1,
        flags: 0,
        target: HandleRef::new(1),
        observed_type: ObjectType::Channel,
        observed_rights: Rights(Rights::READ.bits()),
    };
    let mut buf = [0u8; 64];
    let n = encode(&value, &mut buf).unwrap();
    let decoded: QueryArgs = decode(&buf[..n]).unwrap();
    assert_eq!(decoded, value);

    // Corrupt the ObjectType field (at offset 20) to an undefined value.
    let mut bytes = buf[..n].to_vec();
    bytes[20] = 99;
    assert_eq!(decode::<QueryArgs>(&bytes), Err(WireError::BadEnum));
}
