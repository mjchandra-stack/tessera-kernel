// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The internet checksum (RFC 1071): the one arithmetic every layer above the
//! link shares.
//!
//! **One implementation, three callers.** IPv4 sums its own header, UDP sums a
//! pseudo-header it never transmits plus its real one, and a receiver re-sums
//! the whole thing and expects zero. Writing it three times is how the three
//! disagree about the odd-length tail, which is the case none of them exercise
//! until a payload is an odd number of bytes.
//!
//! Normative: docs/network/01-network-stack.md

/// A one's-complement sum in progress.
///
/// Kept as a `u32` accumulator so a 16-bit add can carry without wrapping, and
/// folded only when the answer is wanted. The order bytes are added in does not
/// matter — the sum is commutative, which is what lets a pseudo-header be
/// summed before the datagram it describes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sum(u32);

impl Sum {
    /// A sum over nothing, which is the identity rather than zero-the-answer:
    /// folding it gives `0xffff`, the checksum of an empty span.
    pub const fn new() -> Self {
        Self(0)
    }

    /// Adds `bytes`, big-endian 16-bit at a time.
    ///
    /// **An odd tail is padded on the right with a zero byte**, and the pad is
    /// not carried into the next call: a caller adding two odd-length spans
    /// gets a different answer from one adding their concatenation, which is
    /// correct, because RFC 1071 pads the *message*, not each of its pieces.
    /// Every caller here adds the payload last for that reason.
    // Not `std::ops::Add`: this folds *bytes* into a running sum, which is a
    // different operation from adding two checksums, and the odd-tail rule
    // above is not something an `Add` impl could state.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, bytes: &[u8]) -> Self {
        let mut chunks = bytes.chunks_exact(2);
        for pair in &mut chunks {
            self.0 += u16::from_be_bytes([pair[0], pair[1]]) as u32;
        }
        if let [last] = chunks.remainder() {
            self.0 += u16::from_be_bytes([*last, 0]) as u32;
        }
        self
    }

    /// Adds one 16-bit field.
    pub const fn add_u16(mut self, value: u16) -> Self {
        self.0 += value as u32;
        self
    }

    /// Folds the carries in and complements: the value that goes on the wire.
    ///
    /// The fold runs twice because folding a 32-bit accumulator can itself
    /// produce a carry out of the low 16 bits — a sum of `0x1_ffff` folds to
    /// `0x1_0000` and needs one more pass to reach `0x0001`. One pass is the
    /// classic off-by-one here and it only shows on long inputs.
    pub const fn fold(self) -> u16 {
        let mut acc = self.0;
        acc = (acc & 0xffff) + (acc >> 16);
        acc = (acc & 0xffff) + (acc >> 16);
        !(acc as u16)
    }
}

/// The checksum of one contiguous span.
pub fn checksum(bytes: &[u8]) -> u16 {
    Sum::new().add(bytes).fold()
}
