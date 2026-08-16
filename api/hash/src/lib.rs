// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **SHA-256 (FIPS 180-4), once, for the whole tree.**
//!
//! It existed twice before this — `api/isl/src/sha256.rs` for interface ids and
//! `tools/checks/src/sha256.rs` for the dependency allowlist — both `Vec`-based
//! and both host-only, which is deviation D13. Neither could go anywhere near a
//! kernel: a hash that allocates cannot run where allocation is fallible, and a
//! hash that copies its whole input to append eleven bytes of padding cannot run
//! over an image measured at boot.
//!
//! So this is `no_std`, `forbid(unsafe_code)`, and allocation-free: the
//! streaming [`Sha256`] keeps one 64-byte block and folds each as it fills, and
//! [`sha256`] is that streaming state used once. The two build tools call it and
//! their copies are gone.
//!
//! **This is a measurement primitive, not a cryptography module.** It computes a
//! digest; it makes no constant-time claim, holds no key, and nothing here
//! selects an algorithm — `docs/security/02` "Crypto Agility" puts algorithm
//! selection in a provider service and requires every signed artifact to name
//! its algorithm in its own header, which is where the identifier for this one
//! lives (`api/image-store`).
//!
//! Correctness is anchored by the FIPS 180-4 vectors, by a multi-block case, and
//! by streaming-in-pieces agreeing with the one-shot over every split of an
//! input that spans three blocks — the property the incremental form exists for
//! and the only one the old copies never had to have.
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Crypto Agility"), docs/api/03-interface-schema-language.md ("Protocols")

#![no_std]
#![forbid(unsafe_code)]

pub mod sha512;

pub use sha512::{Digest512, Sha512, sha512};

/// A SHA-256 digest: 32 raw bytes, big-endian per the standard.
pub type Digest = [u8; 32];

/// The block size the compression function consumes, in bytes.
const BLOCK: usize = 64;
/// Where the 8-byte big-endian bit length starts within the final block.
const LENGTH_OFFSET: usize = 56;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// An in-progress SHA-256.
///
/// Fold input with [`update`](Self::update) as often as convenient and take the
/// digest with [`finish`](Self::finish). The state is one block plus a counter,
/// so hashing a megabyte costs the same memory as hashing a byte — which is what
/// lets a kernel measure an image it has no room to copy.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    /// The partial block: `buffered` bytes are live, the rest is stale.
    block: [u8; BLOCK],
    buffered: usize,
    /// Message length in **bits**, which is what the padding encodes. `u64`
    /// rather than `usize` because the width is fixed by the standard, not by
    /// the host — this crate is built for 32-bit targets too.
    bits: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// A fresh hash over the empty message.
    pub const fn new() -> Self {
        Sha256 {
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
        // Top up a partial block first; only then can whole blocks be taken
        // straight from the input without touching the buffer at all.
        if self.buffered > 0 {
            let want = BLOCK - self.buffered;
            let take = want.min(rest.len());
            self.block[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            // Not enough to fold, so `rest` is spent — and returning here is
            // load-bearing: falling through would take the remainder of an
            // empty slice and set `buffered` back to zero, silently dropping
            // everything held so far.
            if self.buffered < BLOCK {
                return;
            }
            let block = self.block;
            compress(&mut self.state, &block);
            self.buffered = 0;
        }
        let mut chunks = rest.chunks_exact(BLOCK);
        for chunk in &mut chunks {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(chunk);
            compress(&mut self.state, &block);
        }
        let tail = chunks.remainder();
        self.block[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    /// Pads the message and returns the digest.
    pub fn finish(mut self) -> Digest {
        let bits = self.bits;
        // 0x80, then zeroes, then the length — spilling into a second block
        // when the mark and the length do not both fit in this one.
        self.block[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > LENGTH_OFFSET {
            self.block[self.buffered..].fill(0);
            let block = self.block;
            compress(&mut self.state, &block);
            self.buffered = 0;
        }
        self.block[self.buffered..LENGTH_OFFSET].fill(0);
        self.block[LENGTH_OFFSET..].copy_from_slice(&bits.to_be_bytes());
        let block = self.block;
        compress(&mut self.state, &block);

        let mut out = [0u8; 32];
        for (word, slot) in self.state.iter().zip(out.chunks_exact_mut(4)) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// The SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> Digest {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finish()
}

/// A digest as 64 lower-case hex bytes.
///
/// Returns the bytes rather than a `String` so callers that have no allocator
/// can use it; the one caller that wants text goes through
/// [`core::str::from_utf8`], which cannot fail on this output.
pub fn hex(digest: &Digest) -> [u8; 64] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (byte, slot) in digest.iter().zip(out.chunks_exact_mut(2)) {
        slot[0] = DIGITS[(byte >> 4) as usize];
        slot[1] = DIGITS[(byte & 0xf) as usize];
    }
    out
}

/// One application of the compression function to one 64-byte block.
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK]) {
    let mut w = [0u32; 64];
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (constant, word) in K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*constant)
            .wrapping_add(*word);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
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

    for (slot, add) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(add);
    }
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
