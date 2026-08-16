// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `hash::sha512`.

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
