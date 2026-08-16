// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `isl_runtime::bounded`.

use super::*;
use crate::{decode, encode};

#[test]
fn a_bounded_string_round_trips() {
    let s = BoundedString::<16>::from_str("hello").unwrap();
    let mut buf = [0u8; 32];
    let n = encode(&s, &mut buf).unwrap();
    assert_eq!(n, 4 + 5);
    let back: BoundedString<16> = decode(&buf[..n]).unwrap();
    assert_eq!(back.as_str(), "hello");
    assert_eq!(back, s);
}

#[test]
fn a_string_longer_than_its_bound_is_rejected() {
    assert_eq!(
        BoundedString::<4>::from_str("toolong"),
        Err(WireError::BoundExceeded)
    );
    // len = 5 in the encoding but N = 4.
    let bytes = [0x05, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'];
    assert_eq!(
        decode::<BoundedString<4>>(&bytes),
        Err(WireError::BoundExceeded)
    );
}

#[test]
fn invalid_utf8_is_rejected() {
    // len 1, byte 0xff is not valid UTF-8.
    let bytes = [0x01, 0, 0, 0, 0xff];
    assert_eq!(
        decode::<BoundedString<8>>(&bytes),
        Err(WireError::InvalidUtf8)
    );
}

#[test]
fn a_non_canonical_string_length_is_rejected() {
    // len claims 8 but only 5 bytes follow.
    let bytes = [0x08, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'];
    assert_eq!(
        decode::<BoundedString<16>>(&bytes),
        Err(WireError::ShortBuffer)
    );
}

#[test]
fn a_bounded_vector_round_trips() {
    let mut v = BoundedVec::<u32, 4>::new();
    v.push(0x1111_1111).unwrap();
    v.push(0x2222_2222).unwrap();
    let mut buf = [0u8; 32];
    let n = encode(&v, &mut buf).unwrap();
    assert_eq!(n, 4 + 2 * 4);
    let back: BoundedVec<u32, 4> = decode(&buf[..n]).unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back.get(0), Some(0x1111_1111));
    assert_eq!(back.get(1), Some(0x2222_2222));
    assert_eq!(back.get(2), None);
}

#[test]
fn a_vector_longer_than_its_bound_is_rejected() {
    let mut full = BoundedVec::<u8, 2>::new();
    full.push(1).unwrap();
    full.push(2).unwrap();
    assert_eq!(full.push(3), Err(WireError::BoundExceeded));
    // count = 3 in the encoding but N = 2.
    let bytes = [0x03, 0, 0, 0, 1, 2, 3];
    assert_eq!(
        decode::<BoundedVec<u8, 2>>(&bytes),
        Err(WireError::BoundExceeded)
    );
}
