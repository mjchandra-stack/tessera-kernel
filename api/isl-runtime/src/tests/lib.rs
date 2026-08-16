// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

#[test]
fn handle_ref_is_an_index() {
    let h = HandleRef::new(7);
    assert_eq!(h.index(), 7);
}

// A hand-written frozen-struct impl, standing in for generated code, to
// exercise the encode/decode helpers end to end.
#[derive(Debug, PartialEq)]
struct Pair {
    a: u32,
    b: bool,
}

impl WireEncode for Pair {
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_u32(self.a)?;
        w.write_bool(self.b)?;
        w.write_zeros(3) // pad to 8
    }
    fn encoded_len(&self) -> usize {
        8
    }
}

impl WireDecode for Pair {
    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let a = r.read_u32()?;
        let b = r.read_bool()?;
        r.expect_zeros(3)?;
        Ok(Self { a, b })
    }
}

#[test]
fn helpers_roundtrip_and_enforce_canonical() {
    let mut buf = [0u8; 8];
    let n = encode(
        &Pair {
            a: 0xdead_beef,
            b: true,
        },
        &mut buf,
    )
    .unwrap();
    assert_eq!(n, 8);
    let p: Pair = decode(&buf).unwrap();
    assert_eq!(p.a, 0xdead_beef);
    assert!(p.b);

    // Non-canonical padding is rejected by decode.
    let mut bad = buf;
    bad[7] = 1;
    assert_eq!(decode::<Pair>(&bad), Err(WireError::NonCanonicalPadding));

    // Trailing bytes are rejected.
    let mut long = [0u8; 9];
    long[..8].copy_from_slice(&buf);
    assert_eq!(decode::<Pair>(&long), Err(WireError::TrailingBytes));
}
