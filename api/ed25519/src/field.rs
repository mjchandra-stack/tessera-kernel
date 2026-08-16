// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Arithmetic in the field of integers modulo **p = 2^255 − 19**, which is the
//! field Curve25519 and Ed25519 are defined over.
//!
//! Five limbs of 51 bits, the layout every reference implementation uses. The
//! reason is the multiply: a schoolbook product of two 5-limb numbers fits in
//! `u128` intermediates with room for the nineteen-fold folding that reduces
//! the top limbs back down, so no step ever needs a wider integer than the
//! language offers. A radix that filled its limbs would have to carry after
//! every addition; at 51 bits an addition can be left un-normalised and the
//! carries settled once, in the multiply.
//!
//! **Nothing here is constant-time and nothing here claims to be.** Verification
//! reads a public key, a signature and a message — all of them public, all of
//! them things an attacker already has — so there is no secret whose timing
//! could leak. That is the property that makes a verify-only implementation a
//! reasonable thing to write, and it is why this crate does not sign.

/// A field element, five limbs of 51 bits, little-endian.
///
/// Limbs may exceed 2^51 between operations; [`Fe::reduce`] settles them, and
/// [`Fe::to_bytes`] settles them fully and canonically.
#[derive(Clone, Copy, Debug)]
pub struct Fe(pub [u64; 5]);

const MASK: u64 = (1 << 51) - 1;

impl Fe {
    pub const ZERO: Fe = Fe([0; 5]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Decodes 32 little-endian bytes, ignoring the top bit.
    ///
    /// The top bit is the sign of `x` in a compressed point and is never part
    /// of `y`, so masking it here is the encoding's rule rather than a
    /// convenience.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load = |at: usize| -> u64 {
            let mut eight = [0u8; 8];
            eight.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(eight)
        };
        let mut limbs = [0u64; 5];
        limbs[0] = load(0) & MASK;
        limbs[1] = (load(6) >> 3) & MASK;
        limbs[2] = (load(12) >> 6) & MASK;
        limbs[3] = (load(19) >> 1) & MASK;
        limbs[4] = (load(24) >> 12) & MASK;
        Fe(limbs)
    }

    /// Encodes canonically: fully reduced, 32 little-endian bytes.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut t = self.reduce().0;
        // One conditional subtraction of p. After `reduce` the value is below
        // 2p, so exactly one is enough — and it must be *conditional* on the
        // comparison rather than on a branch over secret data, which is
        // irrelevant here because there is no secret.
        let mut carry = 19u64;
        for limb in t.iter() {
            carry += limb;
            carry >>= 51;
        }
        // `carry` is 1 exactly when t >= p.
        t[0] += 19 * carry;
        let mut acc = 0u64;
        for limb in t.iter_mut() {
            *limb += acc;
            acc = *limb >> 51;
            *limb &= MASK;
        }
        t[4] &= (1 << 51) - 1;

        let mut out = [0u8; 32];
        let mut bit = 0usize;
        for limb in t {
            for i in 0..51 {
                if limb >> i & 1 == 1 {
                    out[(bit + i) / 8] |= 1 << ((bit + i) % 8);
                }
            }
            bit += 51;
        }
        out
    }

    /// Settles the carries so every limb is below 2^51.
    pub fn reduce(self) -> Fe {
        let mut t = self.0;
        for _ in 0..2 {
            let mut carry = 0u64;
            for limb in t.iter_mut() {
                *limb += carry;
                carry = *limb >> 51;
                *limb &= MASK;
            }
            // The wrap-around: 2^255 ≡ 19 (mod p), so what fell off the top
            // comes back at the bottom multiplied by nineteen.
            t[0] += 19 * carry;
        }
        Fe(t)
    }

    pub fn add(self, other: Fe) -> Fe {
        let mut out = [0u64; 5];
        for (slot, (a, b)) in out.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *slot = a + b;
        }
        Fe(out).reduce()
    }

    pub fn sub(self, other: Fe) -> Fe {
        // Add 2p before subtracting so no limb can go negative. 2p's limbs are
        // 2*(2^51-19) in the low position and 2*(2^51-1) above it.
        let mut out = [0u64; 5];
        out[0] = self.0[0] + 0xf_ffff_ffff_ffda - other.0[0];
        for (slot, (a, b)) in out
            .iter_mut()
            .zip(self.0.iter().zip(other.0.iter()))
            .skip(1)
        {
            *slot = a + 0xf_ffff_ffff_fffe - b;
        }
        Fe(out).reduce()
    }

    pub fn mul(self, other: Fe) -> Fe {
        let a = self.reduce().0;
        let b = other.reduce().0;
        // The nineteen-folded columns: a limb past position four wraps to
        // position (i+j-5) multiplied by 19, which is what makes this five
        // columns rather than nine.
        let b19 = [b[0], b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
        let m = |x: u64, y: u64| -> u128 { u128::from(x) * u128::from(y) };

        let mut c = [0u128; 5];
        for (i, ai) in a.iter().enumerate() {
            for (j, (bj, b19j)) in b.iter().zip(b19.iter()).enumerate() {
                let k = i + j;
                if k < 5 {
                    c[k] += m(*ai, *bj);
                } else {
                    c[k - 5] += m(*ai, *b19j);
                }
            }
        }

        let mut out = [0u64; 5];
        let mut carry = 0u128;
        for (slot, column) in out.iter_mut().zip(c.iter()) {
            let value = column + carry;
            *slot = (value as u64) & MASK;
            carry = value >> 51;
        }
        out[0] += 19 * (carry as u64);
        Fe(out).reduce()
    }

    pub fn square(self) -> Fe {
        self.mul(self)
    }

    /// `self` raised to the power `2^n`, by repeated squaring.
    fn square_times(self, n: u32) -> Fe {
        let mut out = self;
        for _ in 0..n {
            out = out.square();
        }
        out
    }

    /// `(self^(2^250 - 1), self^11)`, the shared prefix of the inversion and
    /// square-root exponentiations.
    ///
    /// Both intermediates are returned because both are needed downstream and
    /// recomputing `self^11` would mean writing the same four lines twice. The
    /// chain is the part of this file that is easy to get subtly wrong — the
    /// first attempt returned only the first value, which made `invert`
    /// compute `self^(2^255 - 31)` instead of `self^(p-2)`: an exponent ten
    /// away from correct, and an inverse that is simply a different field
    /// element with nothing about it to look wrong.
    fn pow_2_250_minus_1(self) -> (Fe, Fe) {
        let z2 = self.square();
        let z8 = z2.square_times(2);
        let z9 = self.mul(z8);
        let z11 = z2.mul(z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(z22);
        let z_10_5 = z_5_0.square_times(5);
        let z_10_0 = z_10_5.mul(z_5_0);
        let z_20_10 = z_10_0.square_times(10);
        let z_20_0 = z_20_10.mul(z_10_0);
        let z_40_20 = z_20_0.square_times(20);
        let z_40_0 = z_40_20.mul(z_20_0);
        let z_50_10 = z_40_0.square_times(10);
        let z_50_0 = z_50_10.mul(z_10_0);
        let z_100_50 = z_50_0.square_times(50);
        let z_100_0 = z_100_50.mul(z_50_0);
        let z_200_100 = z_100_0.square_times(100);
        let z_200_0 = z_200_100.mul(z_100_0);
        let z_250_50 = z_200_0.square_times(50);
        (z_250_50.mul(z_50_0), z11)
    }

    /// The multiplicative inverse, as `self^(p-2)` — Fermat, because the field
    /// is prime and an exponentiation needs no branching on the value.
    pub fn invert(self) -> Fe {
        let (z_250_0, z11) = self.pow_2_250_minus_1();
        // 2^255 - 32 + 11 = 2^255 - 21 = p - 2.
        z_250_0.square_times(5).mul(z11)
    }

    /// `self^((p-5)/8)`, the exponent the square root needs.
    pub fn pow_p58(self) -> Fe {
        // 2^252 - 4 + 1 = 2^252 - 3 = (p - 5) / 8.
        self.pow_2_250_minus_1().0.square_times(2).mul(self)
    }

    pub fn is_zero(self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    pub fn eq(self, other: Fe) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    /// The low bit of the canonical encoding — the "sign" a compressed point
    /// carries.
    pub fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    pub fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }
}

#[cfg(test)]
mod tests {
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
}
