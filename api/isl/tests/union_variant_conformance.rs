// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated union bindings (built by the codegen
//! genrule from `examples/union_variant.isl`, never committed). Proves the
//! ordinal + size envelope encodes to a fixed golden layout and decodes back
//! canonically, that a strict union rejects an unknown tag, that a flexible
//! union preserves one, and that a non-canonical envelope size is rejected —
//! the wire behaviour union codegen must guarantee (deviation D66).
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use tessera_isl_runtime::{WireError, decode, encode};
use union_variant::{Point, Scalar, Signal};

/// `Scalar::Count(300)`: ordinal 2, an 8-byte `uint64` payload.
const SCALAR_GOLDEN: [u8; 16] = [
    0x02, 0, 0, 0, // ordinal = 2
    0x08, 0, 0, 0, // size = 8
    0x2c, 0x01, 0, 0, 0, 0, 0, 0, // count = 300
];

/// `Signal::At(Point { x: 5, y: -1 })`: ordinal 3, an 8-byte nested struct.
const SIGNAL_GOLDEN: [u8; 16] = [
    0x03, 0, 0, 0, // ordinal = 3
    0x08, 0, 0, 0, // size = 8
    0x05, 0, 0, 0, // x = 5
    0xff, 0xff, 0xff, 0xff, // y = -1
];

#[test]
fn a_strict_union_matches_its_golden_and_round_trips() {
    let value = Scalar::Count(300);
    let mut buf = [0u8; 16];
    assert_eq!(encode(&value, &mut buf).unwrap(), 16);
    assert_eq!(buf, SCALAR_GOLDEN);

    let decoded: Scalar = decode(&SCALAR_GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn a_nested_struct_variant_rides_the_envelope() {
    let value = Signal::At(Point { x: 5, y: -1 });
    let mut buf = [0u8; 16];
    assert_eq!(encode(&value, &mut buf).unwrap(), 16);
    assert_eq!(buf, SIGNAL_GOLDEN);

    let decoded: Signal = decode(&SIGNAL_GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn every_scalar_variant_round_trips() {
    for value in [
        Scalar::Flag(true),
        Scalar::Flag(false),
        Scalar::Count(0),
        Scalar::Count(u64::MAX),
    ] {
        let mut buf = [0u8; 16];
        let n = encode(&value, &mut buf).unwrap();
        assert_eq!(decode::<Scalar>(&buf[..n]).unwrap(), value);
    }
}

#[test]
fn a_strict_union_rejects_an_unknown_tag() {
    // Ordinal 5 is undefined; size 0.
    let bytes = [0x05, 0, 0, 0, 0x00, 0, 0, 0];
    assert_eq!(decode::<Scalar>(&bytes), Err(WireError::BadUnionTag));
}

#[test]
fn a_non_canonical_envelope_size_is_rejected() {
    // Ordinal 1 (bool, one payload byte) but size claims 2 — the variant
    // decodes one byte and the sub-reader's `finish` rejects the extra.
    let bytes = [0x01, 0, 0, 0, 0x02, 0, 0, 0, 0x01, 0x00];
    assert_eq!(decode::<Scalar>(&bytes), Err(WireError::TrailingBytes));
    // Size 0 where the bool needs one byte is the mirror failure.
    let bytes = [0x01, 0, 0, 0, 0x00, 0, 0, 0];
    assert_eq!(decode::<Scalar>(&bytes), Err(WireError::ShortBuffer));
}

#[test]
fn a_flexible_union_preserves_an_unknown_tag_and_re_encodes_it() {
    // Ordinal 7 is undefined; a 4-byte payload fits MAX_PAYLOAD (8).
    let bytes = [0x07, 0, 0, 0, 0x04, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef];
    let decoded: Signal = decode(&bytes).unwrap();
    match decoded {
        Signal::Unknown {
            ordinal,
            len,
            bytes: buf,
        } => {
            assert_eq!(ordinal, 7);
            assert_eq!(len, 4);
            assert_eq!(&buf[..4], &[0xde, 0xad, 0xbe, 0xef]);
        }
        other => panic!("expected preserved unknown, got {other:?}"),
    }
    // A preserved value re-encodes to exactly the bytes it came from.
    let mut buf = [0u8; 12];
    let n = encode(&decoded, &mut buf).unwrap();
    assert_eq!(&buf[..n], &bytes);
}

#[test]
fn a_flexible_unknown_larger_than_the_bound_is_rejected() {
    // Ordinal 9, size 12 — beyond MAX_PAYLOAD (8): reported, never truncated.
    let mut bytes = [0u8; 20];
    bytes[0] = 9;
    bytes[4] = 12;
    assert_eq!(decode::<Signal>(&bytes), Err(WireError::BoundExceeded));
}

#[test]
fn the_reserved_ordinal_is_not_a_variant() {
    // `Signal` reserves ordinal 2; decoding it as a known variant must not
    // happen — it falls through to unknown-preservation (flexible).
    let bytes = [0x02, 0, 0, 0, 0x00, 0, 0, 0];
    match decode::<Signal>(&bytes).unwrap() {
        Signal::Unknown { ordinal, len, .. } => {
            assert_eq!((ordinal, len), (2, 0));
        }
        other => panic!("reserved ordinal must not decode as a variant, got {other:?}"),
    }
}
