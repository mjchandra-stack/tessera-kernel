// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

/// RFC 8032 §7.1, test 1: the empty message.
const KEY_1: PublicKey = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const SIG_1: Signature = [
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
];

/// RFC 8032 §7.1, test 2: a one-byte message.
const KEY_2: PublicKey = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];
const MSG_2: [u8; 1] = [0x72];
const SIG_2: Signature = [
    0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
    0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
    0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
    0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
];

/// **The vectors, which are the whole anchor.** A verifier that returns
/// `true` for everything passes every test anybody writes about working
/// signatures, so these are necessary and nowhere near sufficient — which
/// is what the rejections below are for.
#[test]
fn the_published_vectors_verify() {
    assert!(verify(&KEY_1, b"", &SIG_1), "RFC 8032 test 1");
    assert!(verify(&KEY_2, &MSG_2, &SIG_2), "RFC 8032 test 2");
}

/// The same signature under a different key. Both keys are real and both
/// signatures are real; only the pairing is wrong.
#[test]
fn a_valid_signature_under_the_wrong_key_is_refused() {
    assert!(!verify(&KEY_2, b"", &SIG_1));
    assert!(!verify(&KEY_1, &MSG_2, &SIG_2));
}

/// The right key and signature over a message that changed by one bit.
#[test]
fn a_message_that_changed_is_refused() {
    assert!(!verify(&KEY_2, &[0x73], &SIG_2), "0x72 became 0x73");
    assert!(!verify(&KEY_1, b"x", &SIG_1), "the empty message grew");
}

/// Every single-bit change to the signature. A verifier that ignored part of
/// what it was given would pass the vectors and fail here.
#[test]
fn no_single_bit_of_the_signature_can_be_flipped() {
    for byte in 0..64 {
        for bit in 0..8 {
            let mut sig = SIG_2;
            sig[byte] ^= 1 << bit;
            assert!(
                !verify(&KEY_2, &MSG_2, &sig),
                "signature byte {byte} bit {bit} was ignored",
            );
        }
    }
}

/// And every single-bit change to the key.
#[test]
fn no_single_bit_of_the_key_can_be_flipped() {
    for byte in 0..32 {
        for bit in 0..8 {
            let mut key = KEY_2;
            key[byte] ^= 1 << bit;
            assert!(
                !verify(&key, &MSG_2, &SIG_2),
                "key byte {byte} bit {bit} was ignored",
            );
        }
    }
}

/// **A scalar at or above the group order is refused**, which RFC 8032
/// requires and which is the difference between a signature having one
/// encoding and having many.
#[test]
fn an_unreduced_scalar_is_refused() {
    let mut sig = SIG_2;
    sig[32..].copy_from_slice(&L_BYTES);
    assert!(!verify(&KEY_2, &MSG_2, &sig), "S = L");
    sig[32..].copy_from_slice(&[0xff; 32]);
    assert!(!verify(&KEY_2, &MSG_2, &sig), "S far above L");
}

/// Bytes that name no point on the curve are refused rather than worked
/// with, because arithmetic in a group nobody handed you means nothing.
#[test]
fn a_key_that_is_not_a_point_is_refused() {
    let mut key = [0xffu8; 32];
    key[31] = 0x7f;
    assert!(!verify(&key, &MSG_2, &SIG_2));
}

/// **The all-zero signature under the all-zero key.** This verified before
/// the subgroup check existed: `y = 0` is a genuine point of order four, and
/// a small-order key admits signatures anybody can produce. No suite of
/// honest vectors would ever have shown it.
#[test]
fn nothing_verifies_nothing() {
    assert!(!verify(&[0u8; 32], b"", &[0u8; 64]));
}

/// The other small-order encodings, which are the rest of that family: the
/// identity itself, and the two points of order eight.
#[test]
fn a_small_order_key_is_refused() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(!verify(&identity, &MSG_2, &SIG_2), "the identity as a key");

    let order_eight: PublicKey = [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ];
    assert!(!verify(&order_eight, &MSG_2, &SIG_2));
}
