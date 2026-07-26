// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated handle syscall ABI bindings (built
//! by the codegen genrule from `examples/handle_abi.isl`, never committed).
//! Proves the handle argument structs encode to a fixed golden layout, decode
//! back, and reject non-canonical input.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format"),
//! docs/api/01-system-call-interface.md ("Handles And Capabilities")

use handle_abi::{DuplicateArgs, Rights};
use tessera_isl_runtime::{HandleRef, WireError, decode, encode};

/// Golden encoding of the `DuplicateArgs` value below: little-endian, 8-byte
/// aligned, zero-padded, 32 bytes.
const DUPLICATE_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x05, 0, 0, 0, // source handle index = 5
    0, 0, 0, 0, // padding to 8-byte boundary
    0x41, 0, 0, 0, 0, 0, 0, 0, // new_rights = READ | DUPLICATE
];

#[test]
fn duplicate_args_matches_golden_and_round_trips() {
    assert_eq!(DuplicateArgs::WIRE_SIZE, 32);
    let value = DuplicateArgs {
        size: 32,
        version: 1,
        flags: 0,
        source: HandleRef::new(5),
        new_rights: Rights(Rights::READ.bits() | Rights::DUPLICATE.bits()),
    };
    let mut buf = [0u8; 32];
    let n = encode(&value, &mut buf).unwrap();
    assert_eq!(n, 32);
    assert_eq!(buf, DUPLICATE_GOLDEN);

    let decoded: DuplicateArgs = decode(&DUPLICATE_GOLDEN).unwrap();
    assert_eq!(decoded, value);
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
