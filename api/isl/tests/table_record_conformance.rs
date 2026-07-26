// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated table bindings (built by the codegen
//! genrule from `examples/table_record.isl`, never committed). Proves the
//! present-field envelope list encodes to a fixed golden layout and decodes
//! back canonically: absent fields cost nothing, present fields are strictly
//! ascending by ordinal, a non-ascending or duplicate ordinal is rejected, an
//! unknown ordinal is skipped, and a non-minimal envelope size is rejected —
//! the wire behaviour table codegen must guarantee (deviation D67).
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use table_record::{Color, Point, Sample};
use tessera_isl_runtime::{WireError, decode, encode};

/// `Sample { id: Some(300), enabled: Some(true), .. }`: two present fields, in
/// ascending ordinal order, each in its own `ordinal + size + value` envelope.
const GOLDEN: [u8; 29] = [
    0x02, 0, 0, 0, // count = 2 present fields
    0x01, 0, 0, 0, // field 1 ordinal
    0x08, 0, 0, 0, // field 1 size = 8
    0x2c, 0x01, 0, 0, 0, 0, 0, 0, // id = 300
    0x02, 0, 0, 0, // field 2 ordinal
    0x01, 0, 0, 0,    // field 2 size = 1
    0x01, // enabled = true
];

fn sample() -> Sample {
    Sample {
        id: Some(300),
        enabled: Some(true),
        ..Default::default()
    }
}

#[test]
fn a_table_matches_its_golden_and_round_trips() {
    let value = sample();
    let mut buf = [0u8; 29];
    assert_eq!(encode(&value, &mut buf).unwrap(), 29);
    assert_eq!(buf, GOLDEN);

    let decoded: Sample = decode(&GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn absent_fields_cost_nothing() {
    // The all-absent value is exactly a zero count — four bytes.
    let empty = Sample::default();
    let mut buf = [0u8; 4];
    assert_eq!(encode(&empty, &mut buf).unwrap(), 4);
    assert_eq!(buf, [0, 0, 0, 0]);
    assert_eq!(decode::<Sample>(&[0, 0, 0, 0]).unwrap(), empty);
}

#[test]
fn every_field_including_a_nested_struct_round_trips() {
    let value = Sample {
        id: Some(u64::MAX),
        enabled: Some(false),
        hue: Some(Color::Blue),
        origin: Some(Point { x: -7, y: 9 }),
    };
    let mut buf = [0u8; 64];
    let n = encode(&value, &mut buf).unwrap();
    assert_eq!(decode::<Sample>(&buf[..n]).unwrap(), value);
}

#[test]
fn an_unknown_ordinal_is_skipped_and_known_fields_still_decode() {
    // count 2: an unknown field (ordinal 4, one payload byte) then the known
    // `enabled` field. The unknown is consumed and discarded; `enabled` sets.
    let bytes = [
        0x02, 0, 0, 0, // count = 2
        0x04, 0, 0, 0, // unknown ordinal 4
        0x01, 0, 0, 0,    // size = 1
        0xaa, // skipped payload
        0x05, 0, 0, 0, // ordinal 5 (origin) — must stay ascending
        0x08, 0, 0, 0, // size = 8
        0x01, 0, 0, 0, 0x02, 0, 0, 0, // Point { x: 1, y: 2 }
    ];
    let decoded: Sample = decode(&bytes).unwrap();
    assert_eq!(decoded.id, None);
    assert_eq!(decoded.origin, Some(Point { x: 1, y: 2 }));
}

#[test]
fn a_non_ascending_ordinal_is_rejected() {
    // Fields 2 then 1 — out of order, so not canonical.
    let bytes = [
        0x02, 0, 0, 0, // count = 2
        0x02, 0, 0, 0, 0x01, 0, 0, 0, 0x01, // field 2 (enabled = true)
        0x01, 0, 0, 0, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // field 1
    ];
    assert_eq!(decode::<Sample>(&bytes), Err(WireError::NonCanonicalTable));
}

#[test]
fn a_duplicate_ordinal_is_rejected() {
    // The same ordinal twice is not strictly ascending.
    let bytes = [
        0x02, 0, 0, 0, // count = 2
        0x02, 0, 0, 0, 0x01, 0, 0, 0, 0x01, // field 2
        0x02, 0, 0, 0, 0x01, 0, 0, 0, 0x00, // field 2 again
    ];
    assert_eq!(decode::<Sample>(&bytes), Err(WireError::NonCanonicalTable));
}

#[test]
fn a_non_minimal_envelope_size_is_rejected() {
    // Field 2 (bool, one byte) but size claims 2 — the sub-reader's `finish`
    // rejects the extra byte.
    let bytes = [0x01, 0, 0, 0, 0x02, 0, 0, 0, 0x02, 0, 0, 0, 0x01, 0x00];
    assert_eq!(decode::<Sample>(&bytes), Err(WireError::TrailingBytes));
}
