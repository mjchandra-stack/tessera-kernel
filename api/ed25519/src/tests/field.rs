// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `ed25519::field`.

use super::*;

fn fe(n: u64) -> Fe {
    Fe([n, 0, 0, 0, 0])
}

#[test]
fn bytes_round_trip() {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i * 7 + 1) as u8;
    }
    bytes[31] &= 0x7f;
    assert_eq!(Fe::from_bytes(&bytes).to_bytes(), bytes);
}

#[test]
fn add_and_sub_are_inverse() {
    let a = fe(12345);
    let b = fe(999);
    assert!(a.add(b).sub(b).eq(a));
}

#[test]
fn multiplication_is_what_it_should_be() {
    assert!(fe(6).mul(fe(7)).eq(fe(42)));
    assert!(fe(1).mul(fe(1)).eq(Fe::ONE));
    assert!(fe(0).mul(fe(12345)).is_zero());
}

/// **The reduction, checked at the wrap.** p − 1 plus one is zero, which is
/// the one value where an off-by-one in the nineteen-folding shows.
#[test]
fn the_field_wraps_at_p() {
    let mut p_minus_1 = [0xffu8; 32];
    p_minus_1[0] = 0xec;
    p_minus_1[31] = 0x7f;
    let a = Fe::from_bytes(&p_minus_1);
    assert!(a.add(Fe::ONE).is_zero(), "p - 1 + 1 must be zero");
    assert!(Fe::ZERO.sub(Fe::ONE).eq(a), "and 0 - 1 must be p - 1");
}

#[test]
fn inversion_undoes_multiplication() {
    for n in [2u64, 3, 5, 12345, 1 << 40] {
        let a = fe(n);
        assert!(a.mul(a.invert()).eq(Fe::ONE), "inverse of {n}");
    }
}

/// A non-canonical encoding — one at or above p — must not round-trip to
/// itself, because the canonical form is what a signature comparison uses.
#[test]
fn encoding_is_canonical() {
    let mut at_p = [0xffu8; 32];
    at_p[0] = 0xed;
    at_p[31] = 0x7f;
    assert!(Fe::from_bytes(&at_p).is_zero(), "p reduces to zero");
}
