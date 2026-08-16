// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **SHA-512 (FIPS 180-4)**, the second measurement primitive in this crate.
//!
//! It exists for one caller: Ed25519. RFC 8032 does not offer a choice —
//! Ed25519 *is* SHA-512, in the challenge and in the key expansion both — so a
//! signature verifier cannot be written without it and no other digest can be
//! substituted. That is the whole reason a tree that had exactly one hash
//! function now has two.
//!
//! Same shape as [`super::Sha256`] and for the same reasons: `no_std`,
//! allocation-free, and streaming over one 128-byte block, so measuring a
//! megabyte costs what measuring a byte costs. The differences are the ones the
//! standard dictates — 64-bit words, eighty rounds, a 128-byte block, and a
//! length field the standard makes 128 bits wide.
//!
//! **The length counter here is `u64` where the standard says 128.** A message
//! longer than 2^64 bits cannot be produced by anything this kernel can address,
//! so the high half is written as zero rather than tracked; recorded because a
//! reader comparing this against FIPS 180-4 will notice the field and should
//! find the reason rather than a bug.
//!
//! **This is a measurement primitive, not a cryptography module** — the same
//! sentence as its sibling. It computes a digest, makes no constant-time claim,
//! and holds no key. Ed25519 *verification* touches only public data, which is
//! why that is the operation this supports.
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Crypto Agility")

/// The 64-byte digest SHA-512 produces.
pub type Digest512 = [u8; 64];

/// One block, in bytes.
const BLOCK: usize = 128;

/// The first sixty-four bits of the fractional parts of the cube roots of the
/// first eighty primes (FIPS 180-4, §4.2.3).
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// The fractional parts of the square roots of the first eight primes
/// (FIPS 180-4, §5.3.5).
const INITIAL: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// An in-progress SHA-512.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    block: [u8; BLOCK],
    buffered: usize,
    /// Message length in bits. See the module header on why this is 64 bits
    /// where the standard's field is 128.
    bits: u64,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// A fresh hash over the empty message.
    pub const fn new() -> Self {
        Sha512 {
            state: INITIAL,
            block: [0; BLOCK],
            buffered: 0,
            bits: 0,
        }
    }

    /// Folds `data` into the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.bits = self.bits.wrapping_add((data.len() as u64).wrapping_mul(8));
        let mut rest = data;
        if self.buffered > 0 {
            let want = BLOCK - self.buffered;
            let take = want.min(rest.len());
            self.block[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered == BLOCK {
                let block = self.block;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while rest.len() >= BLOCK {
            let (block, tail) = rest.split_at(BLOCK);
            let mut whole = [0u8; BLOCK];
            whole.copy_from_slice(block);
            self.compress(&whole);
            rest = tail;
        }
        if !rest.is_empty() {
            self.block[..rest.len()].copy_from_slice(rest);
            self.buffered = rest.len();
        }
    }

    /// Finishes the hash and returns the digest.
    pub fn finish(mut self) -> Digest512 {
        let bits = self.bits;
        // The 0x80 terminator, then zeros, then the length in the last sixteen
        // bytes — of which the high eight are zero here.
        self.pad_byte(0x80);
        while self.buffered != BLOCK - 16 {
            self.pad_byte(0);
        }
        for byte in [0u8; 8] {
            self.pad_byte(byte);
        }
        for byte in bits.to_be_bytes() {
            self.pad_byte(byte);
        }
        let mut out = [0u8; 64];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Appends one padding byte, folding a block as soon as one is complete.
    /// Padding never touches `bits`, which is why this is not `update`.
    fn pad_byte(&mut self, byte: u8) {
        self.block[self.buffered] = byte;
        self.buffered += 1;
        if self.buffered == BLOCK {
            let block = self.block;
            self.compress(&block);
            self.buffered = 0;
        }
    }

    fn compress(&mut self, block: &[u8; BLOCK]) {
        let mut w = [0u64; 80];
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *slot = u64::from_be_bytes(bytes);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

/// The SHA-512 digest of `data`.
pub fn sha512(data: &[u8]) -> Digest512 {
    let mut hash = Sha512::new();
    hash.update(data);
    hash.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: &Digest512) -> [u8; 128] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 128];
        for (i, byte) in digest.iter().enumerate() {
            out[i * 2] = HEX[(byte >> 4) as usize];
            out[i * 2 + 1] = HEX[(byte & 0xf) as usize];
        }
        out
    }

    /// FIPS 180-4's own vectors, which is the only anchor a hash can have:
    /// values this code did not compute.
    #[test]
    fn the_published_vectors() {
        assert_eq!(
            hex(&sha512(b"abc")),
            *b"ddaf35a193617abacc417349ae204131\
12e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd\
454d4423643ce80e2a9ac94fa54ca49f",
        );
        assert_eq!(
            hex(&sha512(b"")),
            *b"cf83e1357eefb8bdf1542850d66d8007\
d620e4050b5715dc83f4a921d36ce9ce\
47d0d13c5d85f2b0ff8318d2877eec2f\
63b931bd47417a81a538327af927da3e",
        );
    }

    /// A message spanning more than one block, so the chaining is exercised
    /// rather than only the padding.
    #[test]
    fn a_multi_block_message() {
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(
            hex(&sha512(input)),
            *b"8e959b75dae313da8cf4f72814fc143f\
8f7779c6eb9f7fa17299aeadb6889018\
501d289e4900f7e4331b99dec4b5433a\
c7d329eeb6dd26545e96e55b874be909",
        );
    }

    /// **Streaming in pieces must agree with the one-shot**, over every split of
    /// an input spanning three blocks. This is the property the incremental form
    /// exists for, and one a hash that only ever saw whole buffers would never
    /// have to have.
    #[test]
    fn streaming_agrees_with_the_one_shot_at_every_split() {
        let mut input = [0u8; 300];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let whole = sha512(&input);
        for split in 0..input.len() {
            let mut hash = Sha512::new();
            hash.update(&input[..split]);
            hash.update(&input[split..]);
            assert_eq!(hash.finish(), whole, "split at {split}");
        }
    }

    /// The lengths where an off-by-one in the padding hides: just short of the
    /// length field, exactly at it, and either side of a whole block.
    #[test]
    fn the_block_boundaries() {
        let input = [0x5au8; 300];
        for len in [BLOCK - 17, BLOCK - 16, BLOCK - 1, BLOCK, BLOCK + 1] {
            let one_shot = sha512(&input[..len]);
            let mut hash = Sha512::new();
            for byte in &input[..len] {
                hash.update(&[*byte]);
            }
            assert_eq!(hash.finish(), one_shot, "length {len}");
        }
    }
}
