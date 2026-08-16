// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A channel manifest that **genuinely verifies**, end to end.
//!
//! `api/update-channel`'s own tests could not do this. Nothing in the tree
//! signed, so every test that reached the signature used a manifest whose
//! signature was zeros — which meant the crate could have refused *everything*
//! and passed all of them, and it meant a mutation test had nothing to mutate:
//! changing a byte of a manifest that never verified proves nothing about a
//! manifest that did.
//!
//! This lives under `tools/` rather than beside the channel because the
//! dependency only runs in that direction: a build tool may use the kernel's
//! crates, and no kernel crate may use a signer.

use tessera_ed25519_signer::{public_key, sign};
use tessera_update_channel::{
    ENTRY_SIZE, Entry, HEADER_SIZE, MAGIC, Refusal, SIGNATURE_SIZE, VERSION, admit, open,
};

/// RFC 8032 §7.1 test 1's secret. A published key, used here because a test
/// fixture's key should be one nobody could mistake for a real one.
const SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Every check `api/certification` defines, all passed.
const ALL_CHECKS: u32 = {
    let mut mask = 0u32;
    let mut i = 1;
    while i <= 11 {
        mask |= 1 << i;
        i += 1;
    }
    mask
};

fn entry_bytes(entry: &Entry) -> [u8; ENTRY_SIZE] {
    let mut out = [0u8; ENTRY_SIZE];
    out[0..4].copy_from_slice(&entry.driver.to_le_bytes());
    out[4..8].copy_from_slice(&entry.class.to_le_bytes());
    out[8..12].copy_from_slice(&entry.contract_version.to_le_bytes());
    out[12..16].copy_from_slice(&entry.svn.to_le_bytes());
    out[16..20].copy_from_slice(&entry.ran.to_le_bytes());
    out[20..24].copy_from_slice(&entry.passed.to_le_bytes());
    out[32..64].copy_from_slice(&entry.image);
    out
}

/// Builds a manifest and signs it, the way a release pipeline would.
fn signed_manifest(entries: &[Entry]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&MAGIC.to_le_bytes());
    body.extend_from_slice(&VERSION.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes()); // channel
    body.extend_from_slice(&3u32.to_le_bytes()); // sequence
    body.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    body.resize(HEADER_SIZE, 0);
    for entry in entries {
        body.extend_from_slice(&entry_bytes(entry));
    }
    let signature = sign(&SECRET, &body);
    body.extend_from_slice(&signature);
    body
}

fn entry(driver: u32, certified: bool, svn: u32) -> Entry {
    Entry {
        driver,
        class: 10,
        contract_version: 1,
        svn,
        ran: ALL_CHECKS,
        passed: if certified {
            ALL_CHECKS
        } else {
            ALL_CHECKS & !(1 << 5)
        },
        image: [0xa5; 32],
    }
}

/// **The positive path, which nothing could reach before.**
#[test]
fn a_signed_manifest_opens_and_admits_what_it_should() {
    let anchor = public_key(&SECRET);
    let bytes = signed_manifest(&[entry(7, true, 9), entry(8, false, 9)]);

    let manifest = open(&bytes, &anchor).expect("a manifest this key signed");
    assert_eq!(manifest.channel, 1);
    assert_eq!(manifest.sequence, 3);
    assert_eq!(manifest.entries().len(), 2);

    assert_eq!(admit(&manifest.entries()[0], 5), Ok(()));
    assert_eq!(
        admit(&manifest.entries()[1], 5),
        Err(Refusal::NotCertified),
        "same manifest, same signature, and this one still does not enter",
    );
}

/// **The mutation test that was impossible.** Every byte of a manifest that
/// really verifies, changed one at a time — and every one of them must break
/// the signature. A signature covering less than the whole manifest passes the
/// positive test above and fails here.
#[test]
fn no_byte_of_a_signed_manifest_can_be_changed() {
    let anchor = public_key(&SECRET);
    let bytes = signed_manifest(&[entry(7, true, 9)]);
    let signed_len = HEADER_SIZE + ENTRY_SIZE;

    for at in 0..signed_len {
        let mut mutated = bytes.clone();
        mutated[at] ^= 0x01;
        let result = open(&mutated, &anchor);
        assert!(
            matches!(
                result,
                Err(Refusal::NotFromThisChannel) | Err(Refusal::Malformed)
            ),
            "byte {at} was outside what the signature covers: {result:?}",
        );
    }
}

/// And the signature itself is not ignorable either.
#[test]
fn no_byte_of_the_signature_can_be_changed() {
    let anchor = public_key(&SECRET);
    let bytes = signed_manifest(&[entry(7, true, 9)]);
    for at in 0..SIGNATURE_SIZE {
        let mut mutated = bytes.clone();
        mutated[HEADER_SIZE + ENTRY_SIZE + at] ^= 0x80;
        assert!(
            open(&mutated, &anchor).is_err(),
            "signature byte {at} was ignored",
        );
    }
}

/// A real manifest, correctly signed, offered to a system that trusts somebody
/// else. The bytes are perfect; only the authority is wrong.
#[test]
fn a_manifest_from_another_channel_is_refused() {
    let other_secret = [0x11u8; 32];
    let bytes = signed_manifest(&[entry(7, true, 9)]);
    assert_eq!(
        open(&bytes, &public_key(&other_secret)),
        Err(Refusal::NotFromThisChannel),
    );
}

/// The floor is the system's decision, and it outranks a manifest that is
/// correct in every other way.
#[test]
fn a_perfectly_signed_stale_image_is_still_refused() {
    let anchor = public_key(&SECRET);
    let bytes = signed_manifest(&[entry(7, true, 2)]);
    let manifest = open(&bytes, &anchor).expect("signed");
    assert_eq!(
        admit(&manifest.entries()[0], 5),
        Err(Refusal::BelowTheRollbackFloor),
    );
}
