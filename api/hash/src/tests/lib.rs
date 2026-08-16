// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

fn hexed(data: &[u8]) -> [u8; 64] {
    hex(&sha256(data))
}

fn text(digest: &[u8; 64]) -> &str {
    core::str::from_utf8(digest).expect("hex output is ASCII")
}

/// The published vectors. Everything else here checks that this crate's
/// *shape* is right; this checks that it is SHA-256 at all.
#[test]
fn fips_vectors() {
    assert_eq!(
        text(&hexed(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        text(&hexed(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        text(&hexed(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

/// A message that spans several blocks, and one whose length lands exactly
/// where the padding needs a block of its own — the boundary `finish`
/// spills at, and the one an implementation gets wrong.
#[test]
fn multi_block_and_padding_boundaries() {
    let million = [b'a'; 1000];
    let mut hash = Sha256::new();
    for _ in 0..1000 {
        hash.update(&million);
    }
    assert_eq!(
        text(&hex(&hash.finish())),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );

    // 55 bytes: mark and length both fit. 56: they do not, and the length
    // goes in a second block. 64: the message fills a block exactly.
    for len in [55usize, 56, 57, 63, 64, 65] {
        let message = [b'x'; 65];
        let one_shot = sha256(&message[..len]);
        let mut streamed = Sha256::new();
        streamed.update(&message[..len]);
        assert_eq!(one_shot, streamed.finish(), "length {len}");
    }
}

/// Streaming in two pieces equals the one-shot at **every** split of an
/// input longer than two blocks. This is the property the incremental form
/// exists for, and the reason a buffer-management bug cannot hide: a wrong
/// top-up or a wrong remainder shows up at some split even when the
/// aligned cases agree.
#[test]
fn every_split_agrees_with_one_shot() {
    let mut message = [0u8; 200];
    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let expected = sha256(&message);
    for split in 0..=message.len() {
        let mut hash = Sha256::new();
        hash.update(&message[..split]);
        hash.update(&message[split..]);
        assert_eq!(hash.finish(), expected, "split at {split}");
    }
}

/// Many small updates, none of them block-aligned, still agree — the case
/// a caller measuring a store entry at a time produces.
#[test]
fn many_ragged_updates_agree() {
    let message = [b'q'; 300];
    let mut hash = Sha256::new();
    for piece in message.chunks(7) {
        hash.update(piece);
    }
    assert_eq!(hash.finish(), sha256(&message));
}
