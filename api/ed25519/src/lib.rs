// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Ed25519 signature verification** (RFC 8032), and nothing else.
//!
//! `api/image-store` says why this exists, in its own header: `docs/security/02`
//! defines trust anchors as *"the public keys **and** measurements that
//! verifiers treat as authoritative"*, the store implements the second kind,
//! and *"a public-key anchor is what says [who produced a container], and it
//! arrives behind `DigestAlgorithm` and `anchor_id` without a format change"*.
//! This is that arrival. A measurement anchor can say these are the bytes it was
//! told to expect; only a signature can say who produced them, which is the
//! whole difference between a container that is intact and one that is *from*
//! somebody.
//!
//! # Verify only, and why that is a design decision rather than a shortcut
//!
//! Signing holds a secret; verifying does not. Every input here — the public
//! key, the signature, the message — is something an attacker already has, so
//! there is no secret whose timing could leak and **no constant-time claim is
//! needed or made**. That is what makes a hand-written implementation a
//! defensible thing to have in this tree at all. Signing lives outside the
//! kernel, in a build tool, where the key is a file somebody passed in.
//!
//! # What anchors it
//!
//! RFC 8032 §7.1's published test vectors, which is the same shape of proof the
//! crypto class contract used for AES: values fixed outside this machine that a
//! wrong implementation cannot agree with by accident. A verifier is exactly the
//! kind of code that cannot be checked by inspection — one that returns `true`
//! for everything passes every "does it work" test anybody writes — so the
//! negative vectors matter as much as the positive ones, and both are here.
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Trust Anchors And Signing Infrastructure", "Crypto Agility")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod field;

use field::Fe;
use tessera_hash::Sha512;

/// A public key: a compressed curve point.
pub type PublicKey = [u8; 32];
/// A signature: a compressed point `R` and a scalar `S`.
pub type Signature = [u8; 64];

/// The curve constant `d = -121665/121666`, little-endian.
const D_BYTES: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// A square root of −1, needed when the candidate `x` comes out wrong by that
/// factor.
const SQRT_M1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// The base point `B`, compressed. `y = 4/5`, sign bit clear.
const BASE_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// The group order `L = 2^252 + 27742317777372353535851937790883648493`, little
/// -endian. A signature whose scalar is at or above this is refused: RFC 8032
/// requires it, and without the check a signature has more than one valid
/// encoding, which is malleability rather than a formality.
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// A point in extended coordinates `(X : Y : Z : T)` with `x = X/Z`, `y = Y/Z`
/// and `x·y = T/Z`.
///
/// Extended rather than affine because the addition formulas then need no
/// inversion, and an inversion per addition would dominate everything else in a
/// verify.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Recovers a point from its compressed form, or `None` when the bytes name
    /// no point on the curve.
    ///
    /// **Returning `None` is load-bearing.** A verifier that accepted an
    /// off-curve key would be doing arithmetic in a group it was not given, and
    /// the answer it produced would mean nothing.
    fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        let y = Fe::from_bytes(bytes);
        let want_negative = bytes[31] >> 7 == 1;

        // x² = (y² − 1) / (d·y² + 1)
        let y2 = y.square();
        let numerator = y2.sub(Fe::ONE);
        let denominator = Fe::from_bytes(&D_BYTES).mul(y2).add(Fe::ONE);

        // The candidate root, by the exponent that works when one exists.
        let ratio = numerator.mul(denominator.invert());
        let mut x = ratio.pow_p58().mul(numerator).mul(denominator.invert());
        // Fix the candidate up: it can be right, wrong by a factor of √−1, or
        // there may be no root at all — and only the third is a rejection.
        let check = x.square().mul(denominator);
        if !check.eq(numerator) {
            let fixed = x.mul(Fe::from_bytes(&SQRT_M1_BYTES));
            if !fixed.square().mul(denominator).eq(numerator) {
                return None;
            }
            x = fixed;
        }
        if x.is_zero() && want_negative {
            // The one ambiguous encoding: x = 0 has no negative form, so a
            // sign bit set over it is a second spelling of the same point.
            return None;
        }
        if x.is_negative() != want_negative {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    /// Whether this is the identity, by encoding rather than by coordinates:
    /// the projective representation is not unique, so `(0, Z, Z, 0)` is the
    /// identity for every `Z` and comparing limbs would miss most of them.
    fn is_identity(&self) -> bool {
        self.compress() == Point::IDENTITY.compress()
    }

    fn compress(&self) -> [u8; 32] {
        let inv = self.z.invert();
        let x = self.x.mul(inv);
        let y = self.y.mul(inv);
        let mut out = y.to_bytes();
        out[31] |= (x.to_bytes()[0] & 1) << 7;
        out
    }

    fn double(&self) -> Point {
        self.add(self)
    }

    /// The unified addition formulas for a twisted Edwards curve with `a = −1`.
    /// Unified matters: the same formula handles a doubling and the identity,
    /// so no case analysis can be wrong about which one it is in.
    fn add(&self, other: &Point) -> Point {
        let d2 = Fe::from_bytes(&D_BYTES).add(Fe::from_bytes(&D_BYTES));
        let a = self.y.sub(self.x).mul(other.y.sub(other.x));
        let b = self.y.add(self.x).mul(other.y.add(other.x));
        let c = self.t.mul(other.t).mul(d2);
        let dd = self.z.mul(other.z);
        let dd = dd.add(dd);
        let e = b.sub(a);
        let f = dd.sub(c);
        let g = dd.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    /// `[scalar]self`, double-and-add over the scalar's bits, most significant
    /// first. `scalar` is little-endian.
    fn mul(&self, scalar: &[u8]) -> Point {
        let mut out = Point::IDENTITY;
        for byte in scalar.iter().rev() {
            for bit in (0..8).rev() {
                out = out.double();
                if byte >> bit & 1 == 1 {
                    out = out.add(self);
                }
            }
        }
        out
    }
}

/// `[scalar]B`, the base point multiplied by a 32-byte little-endian scalar,
/// compressed.
///
/// **A public group operation, exposed so that nothing has to reimplement this
/// curve.** A signer needs exactly this and nothing else from the arithmetic
/// here; the alternative was a second copy of the field and point code in a
/// build tool, and one implementation with one set of vectors behind it is
/// worth more than two of anything.
///
/// It is not constant-time, as nothing in this crate is. A caller passing a
/// *secret* scalar is accepting that, which is why the only such caller is a
/// host build tool signing with a key it was handed — and why the kernel's use
/// of this crate remains verification, where every input is public.
pub fn base_mul(scalar: &[u8; 32]) -> PublicKey {
    match Point::decompress(&BASE_BYTES) {
        Some(base) => base.mul(scalar).compress(),
        // Unreachable: the base point is a compile-time constant of this crate
        // and is a point. Returning zeros rather than panicking keeps the
        // no-panic property; a caller would find the answer verifies against
        // nothing.
        None => [0u8; 32],
    }
}

/// Whether `signature` is a valid Ed25519 signature over `message` under
/// `public_key`.
///
/// **Every rejection path returns `false`.** There is no error type, because a
/// caller has exactly one thing to do with any of them and a richer answer would
/// invite treating some failures as more acceptable than others.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    // The scalar must be reduced. RFC 8032 §5.1.7 step 1 requires it, and
    // without it every signature has many valid encodings — anything that
    // identifies a signature by its bytes then disagrees with anything that
    // identifies it by its meaning.
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    if !less_than(&s_bytes, &L_BYTES) {
        return false;
    }

    let Some(a) = Point::decompress(public_key) else {
        return false;
    };
    // **The key must be in the prime-order subgroup**, which `[L]A = identity`
    // says and nothing cheaper does.
    //
    // RFC 8032 does not require this, and leaving it out is how a verifier
    // accepts the all-zero signature under the all-zero key: `y = 0` is a
    // perfectly good point of order four, and small-order keys admit
    // signatures anybody can produce. Found exactly that way — the degenerate
    // case verified, which is the kind of thing a vector suite of honest keys
    // will never show.
    //
    // It also settles the scalar question below: with `A` of order `L`,
    // `[k]A` and `[k mod L]A` are the same point, so using the unreduced hash
    // is equivalence rather than approximation.
    if !a.mul(&L_BYTES).is_identity() {
        return false;
    }
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    // R is decompressed for one reason only: to reject bytes that name no
    // point. The comparison below is on encodings, so a valid R is used as it
    // was given.
    if Point::decompress(&r_bytes).is_none() {
        return false;
    }

    // k = SHA-512(R ‖ A ‖ M)
    let mut hash = Sha512::new();
    hash.update(&r_bytes);
    hash.update(public_key);
    hash.update(message);
    let k = hash.finish();

    // [S]B = R + [k]A, compared as encodings.
    //
    // **`k` is used unreduced**, all 512 bits of it. That is exact rather than
    // approximate because the subgroup check above has already established
    // that `A` has order `L`, so `[k]A` and `[k mod L]A` are the same point —
    // which is what lets this crate do without a modular reduction it would
    // otherwise need.
    let base = match Point::decompress(&BASE_BYTES) {
        Some(base) => base,
        None => return false,
    };
    let lhs = base.mul(&s_bytes);
    let rhs = match Point::decompress(&r_bytes) {
        Some(r) => r.add(&a.mul(&k)),
        None => return false,
    };
    lhs.compress() == rhs.compress()
}

/// Whether `a < b`, both little-endian 32-byte integers.
fn less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
