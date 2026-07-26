// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated bounded-collection bindings (built by
//! the codegen genrule from `examples/collections.isl`, never committed).
//! Proves `string:N` and `vector<T>:N` in a table and a union: a fixed inline
//! field and a runtime-sized bounded field share one table encoding, a vector
//! of scalars and a vector of nested structs round-trip, and every bound and
//! canonicality rule is enforced (deviation D68).
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use collections::{Coord, Payload, Record};
use tessera_isl_runtime::{BoundedString, BoundedVec, WireError, decode, encode};

/// `Record { id: Some(1), label: Some("hi"), .. }`: an inline `uint64` field
/// (fixed-size envelope) then a `string:32` field (runtime-size envelope),
/// proving both size sources coexist in one table.
const RECORD_GOLDEN: [u8; 34] = [
    0x02, 0, 0, 0, // count = 2
    0x01, 0, 0, 0, // field 1 (id) ordinal
    0x08, 0, 0, 0, // field 1 size = 8
    0x01, 0, 0, 0, 0, 0, 0, 0, // id = 1
    0x02, 0, 0, 0, // field 2 (label) ordinal
    0x06, 0, 0, 0, // field 2 size = 6 (4 + 2)
    0x02, 0, 0, 0, // string length = 2
    b'h', b'i', // "hi"
];

fn string32(s: &str) -> BoundedString<32> {
    BoundedString::from_str(s).unwrap()
}

#[test]
fn a_record_with_an_inline_and_a_string_field_matches_its_golden() {
    let value = Record {
        id: Some(1),
        label: Some(string32("hi")),
        ..Default::default()
    };
    let mut buf = [0u8; 34];
    assert_eq!(encode(&value, &mut buf).unwrap(), 34);
    assert_eq!(buf, RECORD_GOLDEN);

    let decoded: Record = decode(&RECORD_GOLDEN).unwrap();
    assert_eq!(decoded.id, Some(1));
    assert_eq!(decoded.label.unwrap().as_str(), "hi");
    assert_eq!(decoded.samples, None);
}

#[test]
fn a_vector_of_scalars_and_of_structs_round_trips() {
    let mut samples = BoundedVec::<u32, 8>::new();
    samples.push(10).unwrap();
    samples.push(20).unwrap();
    samples.push(30).unwrap();
    let mut path = BoundedVec::<Coord, 4>::new();
    path.push(Coord { lat: 1, lon: 2 }).unwrap();
    path.push(Coord { lat: -3, lon: 4 }).unwrap();

    let value = Record {
        id: Some(9),
        label: Some(string32("route")),
        samples: Some(samples),
        path: Some(path),
    };
    let mut buf = [0u8; 256];
    let n = encode(&value, &mut buf).unwrap();
    let decoded: Record = decode(&buf[..n]).unwrap();

    let got = decoded.samples.unwrap();
    assert_eq!((got.len(), got.get(0), got.get(2)), (3, Some(10), Some(30)));
    let route = decoded.path.unwrap();
    assert_eq!(
        (route.len(), route.get(1)),
        (2, Some(Coord { lat: -3, lon: 4 }))
    );
}

#[test]
fn a_bounded_union_variant_round_trips() {
    let value = Payload::Note(BoundedString::<64>::from_str("hello world").unwrap());
    let mut buf = [0u8; 128];
    let n = encode(&value, &mut buf).unwrap();
    match decode::<Payload>(&buf[..n]).unwrap() {
        Payload::Note(s) => assert_eq!(s.as_str(), "hello world"),
        other => panic!("expected Note, got {other:?}"),
    }
}

#[test]
fn a_string_past_its_bound_is_rejected() {
    // label (field 2) with length 40 > 32.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_le_bytes()); // count = 1
    bytes.extend_from_slice(&2u32.to_le_bytes()); // ordinal 2 (label)
    bytes.extend_from_slice(&44u32.to_le_bytes()); // size = 4 + 40
    bytes.extend_from_slice(&40u32.to_le_bytes()); // string length = 40
    bytes.extend(std::iter::repeat_n(b'x', 40));
    assert_eq!(decode::<Record>(&bytes), Err(WireError::BoundExceeded));
}

#[test]
fn invalid_utf8_in_a_string_field_is_rejected() {
    // label with one byte 0xff, not valid UTF-8.
    let bytes = [
        0x01, 0, 0, 0, // count = 1
        0x02, 0, 0, 0, // ordinal 2 (label)
        0x05, 0, 0, 0, // size = 4 + 1
        0x01, 0, 0, 0,    // string length = 1
        0xff, // invalid byte
    ];
    assert_eq!(decode::<Record>(&bytes), Err(WireError::InvalidUtf8));
}

#[test]
fn a_vector_past_its_bound_is_rejected() {
    // samples (field 3, vector<uint32>:8) with count 9 > 8.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_le_bytes()); // count = 1
    bytes.extend_from_slice(&3u32.to_le_bytes()); // ordinal 3 (samples)
    bytes.extend_from_slice(&(4 + 9 * 4u32).to_le_bytes()); // size
    bytes.extend_from_slice(&9u32.to_le_bytes()); // element count = 9
    for _ in 0..9 {
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    assert_eq!(decode::<Record>(&bytes), Err(WireError::BoundExceeded));
}
