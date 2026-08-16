// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Ed25519 signing, for build tools only.**
//!
//! `api/ed25519` verifies and deliberately does not sign: verification touches
//! only public data, which is what makes a hand-written implementation
//! defensible there. Signing holds a secret, and this crate is where that lives
//! — **on a build machine, never in a shipped artifact**. Nothing in `kernel/`
//! or `userspace/` may depend on it, and the fact that it sits under `tools/`
//! is the enforcement.
//!
//! # What it does not claim
//!
//! **Nothing here is constant-time**, and the key is an argument rather than
//! something this code stores, rotates or protects. A build machine that runs
//! this is trusted with the key by the act of having it; that is a statement
//! about the machine, not about this code, and `docs/security/02`'s signing
//! infrastructure — custody, rotation, revocation, an HSM — is untouched by
//! anything here (build/README.md, D173).
//!
//! # Why it exists at all
//!
//! Because a channel whose positive path is untested is a channel nobody has
//! run. `api/update-channel` could refuse everything and pass every test it
//! had, since none of them could produce a manifest that genuinely verifies.
//! This is what produces one.
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Trust Anchors And Signing Infrastructure")

#![forbid(unsafe_code)]

use tessera_ed25519::{PublicKey, Signature, base_mul};
use tessera_hash::Sha512;

/// The group order `L`, little-endian — the same constant `api/ed25519`
/// checks a signature's scalar against.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// A 512-bit little-endian integer as sixteen 32-bit limbs.
type Wide = [u32; 16];

fn wide_from_bytes(bytes: &[u8]) -> Wide {
    let mut out = [0u32; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let at = i * 4;
        if at + 4 <= bytes.len() {
            let mut four = [0u8; 4];
            four.copy_from_slice(&bytes[at..at + 4]);
            *slot = u32::from_le_bytes(four);
        }
    }
    out
}

fn wide_shl1(value: &mut Wide) {
    let mut carry = 0u32;
    for limb in value.iter_mut() {
        let next = *limb >> 31;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
}

fn wide_geq(a: &Wide, b: &Wide) -> bool {
    for i in (0..16).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn wide_sub(a: &mut Wide, b: &Wide) {
    let mut borrow = 0i64;
    for (x, y) in a.iter_mut().zip(b.iter()) {
        let value = i64::from(*x) - i64::from(*y) - borrow;
        if value < 0 {
            *x = (value + (1i64 << 32)) as u32;
            borrow = 1;
        } else {
            *x = value as u32;
            borrow = 0;
        }
    }
}

/// `value mod L`, by shift-and-subtract.
///
/// **Deliberately the slow, obvious algorithm.** The reference implementations
/// use a hand-derived 21-bit limb reduction that is fast and very easy to get
/// subtly wrong; this runs once per signature on a build machine, where the
/// only thing worth optimising for is being able to see that it is right.
fn reduce_mod_l(value: &[u8]) -> [u8; 32] {
    let mut remainder = [0u32; 16];
    let source = wide_from_bytes(value);
    let modulus = wide_from_bytes(&L);

    // Long division, most significant bit first: shift the remainder up, pull
    // in the next bit, and subtract the modulus whenever it fits.
    for bit in (0..512).rev() {
        wide_shl1(&mut remainder);
        remainder[0] |= (source[bit / 32] >> (bit % 32)) & 1;
        if wide_geq(&remainder, &modulus) {
            wide_sub(&mut remainder, &modulus);
        }
    }

    let mut out = [0u8; 32];
    for (i, limb) in remainder.iter().take(8).enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// `(a·b + c) mod L`, over 32-byte little-endian scalars.
fn mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    // The product is 512 bits, which is exactly what `reduce_mod_l` takes.
    let mut product = [0u64; 16];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            product[(i + j) / 4] += (u64::from(*x) * u64::from(*y)) << (8 * ((i + j) % 4));
        }
    }
    // Settle the limbs, then fold in `c`.
    let mut wide = [0u8; 64];
    let mut carry = 0u64;
    for (i, limb) in product.iter().enumerate() {
        let value = limb + carry;
        wide[i * 4..i * 4 + 4].copy_from_slice(&(value as u32).to_le_bytes());
        carry = value >> 32;
    }
    let mut sum = [0u8; 64];
    let mut borrow = 0u16;
    for i in 0..64 {
        let value = u16::from(wide[i]) + u16::from(if i < 32 { c[i] } else { 0 }) + borrow;
        sum[i] = value as u8;
        borrow = value >> 8;
    }
    reduce_mod_l(&sum)
}

/// The public key for `secret`, as RFC 8032 derives it.
pub fn public_key(secret: &[u8; 32]) -> PublicKey {
    let mut hash = Sha512::new();
    hash.update(secret);
    let h = hash.finish();
    base_mul(&clamp(&h))
}

/// The scalar RFC 8032 derives from the first half of the secret's hash.
///
/// The three cleared low bits put it in the prime-order subgroup and the fixed
/// high bit fixes its length; both are the standard's, and a signer that
/// skipped either would produce signatures that verify nowhere.
fn clamp(h: &[u8; 64]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    a
}

/// Signs `message` under `secret`, per RFC 8032 §5.1.6.
pub fn sign(secret: &[u8; 32], message: &[u8]) -> Signature {
    let mut hash = Sha512::new();
    hash.update(secret);
    let h = hash.finish();
    let a = clamp(&h);
    let public = base_mul(&a);

    // r = SHA-512(prefix ‖ M) mod L. The prefix is the half of the secret's
    // hash that is not the scalar, which is what makes Ed25519 deterministic:
    // no random number is drawn, so no bad one can be.
    let mut hash = Sha512::new();
    hash.update(&h[32..]);
    hash.update(message);
    let r = reduce_mod_l(&hash.finish());
    let r_point = base_mul(&r);

    // k = SHA-512(R ‖ A ‖ M) mod L
    let mut hash = Sha512::new();
    hash.update(&r_point);
    hash.update(&public);
    hash.update(message);
    let k = reduce_mod_l(&hash.finish());

    let s = mul_add(&k, &a, &r);
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_point);
    signature[32..].copy_from_slice(&s);
    signature
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera_ed25519::verify;

    /// RFC 8032 §7.1, test 1.
    const SECRET_1: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const PUBLIC_1: PublicKey = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const SIG_1: Signature = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    /// RFC 8032 §7.1, test 2.
    const SECRET_2: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    const SIG_2: Signature = [
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
        0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
        0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0,
        0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
        0x12, 0xbb, 0x0c, 0x00,
    ];

    /// **The signature has to be the RFC's own, byte for byte.** Ed25519 is
    /// deterministic — no nonce is drawn — so there is exactly one right answer
    /// and "it verifies" is a much weaker claim than "it is this".
    #[test]
    fn the_published_signatures_are_reproduced_exactly() {
        assert_eq!(public_key(&SECRET_1), PUBLIC_1);
        assert_eq!(sign(&SECRET_1, b""), SIG_1);
        assert_eq!(sign(&SECRET_2, &[0x72]), SIG_2);
    }

    /// And the two halves agree with each other, which is the property a
    /// channel actually depends on.
    #[test]
    fn what_this_signs_the_verifier_accepts() {
        for message in [&b""[..], b"x", b"a longer manifest-sized message" as &[u8]] {
            let signature = sign(&SECRET_1, message);
            assert!(verify(&PUBLIC_1, message, &signature), "{message:?}");
            assert!(
                !verify(&PUBLIC_1, b"something else", &signature),
                "and only that message",
            );
        }
    }

    /// The reduction, at the boundary that matters: `L` itself must reduce to
    /// zero, and `L - 1` must survive untouched.
    #[test]
    fn the_reduction_is_right_at_the_modulus() {
        let mut l_wide = [0u8; 64];
        l_wide[..32].copy_from_slice(&L);
        assert_eq!(reduce_mod_l(&l_wide), [0u8; 32]);

        let mut just_below = L;
        just_below[0] -= 1;
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&just_below);
        assert_eq!(reduce_mod_l(&wide), just_below);
    }

    /// `mul_add` against values whose answer is obvious.
    #[test]
    fn mul_add_agrees_with_arithmetic() {
        let mut two = [0u8; 32];
        two[0] = 2;
        let mut three = [0u8; 32];
        three[0] = 3;
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut seven = [0u8; 32];
        seven[0] = 7;
        assert_eq!(mul_add(&two, &three, &one), seven);
    }
}
