// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;
use tessera_ed25519_signer::{public_key, sign};

const ANCHOR_ID: u32 = 7;

fn sample() -> [BuildEntry<'static>; 2] {
    [
        BuildEntry {
            name: "firmware.bin",
            svn: 3,
            image_version: 2,
            flags: 0,
            bytes: b"the firmware image, such as it is",
        },
        BuildEntry {
            name: "manifest.dat",
            svn: 1,
            image_version: 5,
            flags: 0x21,
            bytes: b"entries",
        },
    ]
}

fn built() -> ([u8; 512], usize) {
    let mut buffer = [0u8; 512];
    let built = build_into(&mut buffer, ANCHOR_ID, &sample(), false).expect("build");
    (buffer, built.len)
}

fn anchors(container: &[u8]) -> [Anchor; 1] {
    [Anchor {
        id: ANCHOR_ID,
        trust: Trust::Digest(measure(container).expect("measure")),
    }]
}

#[test]
fn round_trip() {
    let (buffer, len) = built();
    let container = &buffer[..len];
    let store = Store::mount(container, &anchors(container)).expect("mount");

    assert_eq!(store.len(), 2);
    assert!(!store.is_empty());
    assert_eq!(store.anchor_id(), ANCHOR_ID);
    assert_eq!(store.algorithm(), DigestAlgorithm::Sha256);

    let firmware = store.open("firmware.bin").expect("open");
    assert_eq!(firmware.bytes, b"the firmware image, such as it is");
    assert_eq!(firmware.svn, 3);
    assert_eq!(firmware.digest, tessera_hash::sha256(firmware.bytes));

    let manifest = store.open("manifest.dat").expect("open");
    assert_eq!(manifest.bytes, b"entries");
    assert_eq!(manifest.svn, 1);
    assert_eq!(manifest.flags, 0x21);

    assert_eq!(store.entry(0).expect("entry").name(), "firmware.bin");
    assert_eq!(store.entry(1).expect("entry").name(), "manifest.dat");
    assert_eq!(store.entry(2), Err(StoreError::NotFound));
    assert_eq!(store.open("absent"), Err(StoreError::NotFound));
}

/// A container is a pure function of its inputs, which is what makes a
/// checked-in anchor maintainable at all.
#[test]
fn build_is_deterministic() {
    let (first, first_len) = built();
    let (second, second_len) = built();
    assert_eq!(first_len, second_len);
    assert_eq!(first[..first_len], second[..second_len]);
}

/// A container built with room for a signature, and the key that made it.
///
/// The secret is a fixed seed because a test needs the *positive* path to be
/// reachable: `api/ed25519` verifies and cannot sign, so without something that
/// signs, every key-anchored assertion here would be a refusal and the check
/// would pass with verification stubbed out entirely.
fn signed() -> ([u8; 512], usize, [u8; 32]) {
    const SECRET: [u8; 32] = [7u8; 32];
    let mut buffer = [0u8; 512];
    let built = build_into(&mut buffer, ANCHOR_ID, &sample(), true).expect("build");
    let at = built.signature_at.expect("room was reserved");
    let signature = sign(&SECRET, &built.anchor);
    buffer[at..at + signature.len()].copy_from_slice(&signature);
    (buffer, built.len, public_key(&SECRET))
}

/// **A container can be authenticated by a key instead of a pinned
/// measurement** (D289), which is what makes a store of content that changes
/// every build possible at all.
#[test]
fn a_signed_container_mounts_against_its_key() {
    let (buffer, len, public) = signed();
    let container = &buffer[..len];
    let store = Store::mount(
        container,
        &[Anchor {
            id: ANCHOR_ID,
            trust: Trust::Key(public),
        }],
    )
    .expect("mount");
    assert_eq!(store.len(), 2);
    // And the same container still measures to something a pinned anchor could
    // hold: signing adds an authenticator, it does not change what a container
    // *is*.
    assert_eq!(store.anchor(), measure(container).expect("measure"));
}

/// A different key does not authenticate it. **The whole point of a key
/// anchor** — without this the mount would be accepting any signature at all.
#[test]
fn a_signed_container_is_refused_under_another_key() {
    let (buffer, len, _) = signed();
    let container = &buffer[..len];
    let stranger = public_key(&[9u8; 32]);
    assert_eq!(
        Store::mount(
            container,
            &[Anchor {
                id: ANCHOR_ID,
                trust: Trust::Key(stranger)
            }]
        )
        .err(),
        Some(StoreError::BadSignature),
    );
}

/// Changing anything the anchor covers invalidates the signature.
///
/// A blob's own bytes are checked when the blob is read; what has to fail at
/// *mount* is a change to the header or the directory, which is what the
/// signature is over.
#[test]
fn tampering_with_a_signed_container_is_refused() {
    let (mut buffer, len, public) = signed();
    // **The first entry's `flags`**, which the reader carries and never judges.
    // A byte flipped in a structural field — a length, a name, a reserved word
    // — fails the parse and never reaches the signature, so a test that
    // corrupted one would pass with verification stubbed out entirely. This
    // one can only be caught by the signature, which is the point; and it says
    // the useful thing besides, that the anchor covers everything measured
    // rather than only the fields somebody validates.
    let first_entry_flags = HEADER_SIZE + 4 + 4;
    buffer[first_entry_flags] ^= 0xff;
    assert_eq!(
        Store::mount(
            &buffer[..len],
            &[Anchor {
                id: ANCHOR_ID,
                trust: Trust::Key(public)
            }]
        )
        .err(),
        Some(StoreError::BadSignature),
    );
}

/// **An unsigned container is refused by a key anchor, never compared.**
///
/// Falling back to a measurement here would let an artifact choose to be
/// checked the weaker way by omitting the thing that makes the stronger check
/// possible — which is the whole of what a key anchor is for.
#[test]
fn an_unsigned_container_cannot_satisfy_a_key_anchor() {
    let (buffer, len) = built();
    let container = &buffer[..len];
    assert_eq!(
        Store::mount(
            container,
            &[Anchor {
                id: ANCHOR_ID,
                trust: Trust::Key(public_key(&[7u8; 32]))
            }]
        )
        .err(),
        Some(StoreError::Unsigned),
        "a container with no signature is not a container with a valid one",
    );
}

/// A signature moved inside the measured region is refused rather than read.
///
/// **It would be signing itself.** The anchor covers everything up to the end
/// of the directory; a signature there is part of what it attests to, and a
/// reader that allowed it would be verifying a circular claim.
#[test]
fn a_signature_inside_the_measured_region_is_refused() {
    let (mut buffer, len, public) = signed();
    // `signature_offset` is the last field of the header.
    let field = HEADER_SIZE - 8;
    buffer[field..field + 8].copy_from_slice(&(HEADER_SIZE as u64).to_le_bytes());
    assert_eq!(
        Store::mount(
            &buffer[..len],
            &[Anchor {
                id: ANCHOR_ID,
                trust: Trust::Key(public)
            }]
        )
        .err(),
        Some(StoreError::Malformed),
    );
}

/// The empty container: legal, mountable, and holding nothing.
#[test]
fn empty_container_mounts() {
    let mut buffer = [0u8; 128];
    let built = build_into(&mut buffer, ANCHOR_ID, &[], false).expect("build");
    let container = &buffer[..built.len];
    let store = Store::mount(container, &anchors(container)).expect("mount");
    assert!(store.is_empty());
    assert_eq!(store.open("anything"), Err(StoreError::NotFound));
}

/// **A byte flipped in a blob is caught when the blob is read, not when the
/// container is mounted** — the anchor covers the directory, and the
/// directory's digest of that blob is what fails.
#[test]
fn tampered_blob_mounts_but_will_not_open() {
    let (mut buffer, len) = built();
    let flip = len - 1;
    buffer[flip] ^= 0x01;
    let container = &buffer[..len];
    // Anchors computed over the *tampered* container, so this is not the
    // anchor check passing by accident of the tamper being outside it.
    let store = Store::mount(container, &anchors(container)).expect("mount");
    assert_eq!(store.open("manifest.dat"), Err(StoreError::DigestMismatch));
    // The blob nobody touched still opens: the failure is scoped to what
    // changed, rather than a container that fails as a whole.
    assert!(store.open("firmware.bin").is_ok());
}

/// A byte flipped in the directory changes the anchor, so the container
/// does not mount at all.
#[test]
fn tampered_directory_will_not_mount() {
    let (buffer, len) = built();
    let trusted = anchors(&buffer[..len]);
    let mut tampered = buffer;
    // The svn field of the first entry: a change with a motive.
    tampered[HEADER_SIZE + 56] ^= 0x04;
    assert_eq!(
        Store::mount(&tampered[..len], &trusted).err(),
        Some(StoreError::UntrustedAnchor)
    );
}

/// The same for the header, whose fields the anchor also covers.
#[test]
fn tampered_header_will_not_mount() {
    let (buffer, len) = built();
    let trusted = anchors(&buffer[..len]);
    let mut tampered = buffer;
    // `flags`, which nothing reads — so the mount still finds the anchor
    // by its id and fails on the measurement, rather than failing because
    // the id no longer names an anchor this verifier holds.
    tampered[8] ^= 0x01;
    assert_eq!(
        Store::mount(&tampered[..len], &trusted).err(),
        Some(StoreError::UntrustedAnchor)
    );
}

/// An anchor this verifier does not hold is refused even when the container
/// measures correctly — an anchor is selected by id, never by matching.
#[test]
fn unknown_anchor_id_is_refused() {
    let (buffer, len) = built();
    let container = &buffer[..len];
    let wrong = [Anchor {
        id: ANCHOR_ID + 1,
        trust: Trust::Digest(measure(container).expect("measure")),
    }];
    assert_eq!(
        Store::mount(container, &wrong).err(),
        Some(StoreError::UntrustedAnchor)
    );
    assert_eq!(
        Store::mount(container, &[]).err(),
        Some(StoreError::UntrustedAnchor)
    );
}

#[test]
fn not_a_store_at_all() {
    let noise = [0xa5u8; 256];
    assert_eq!(measure(&noise), Err(StoreError::BadMagic));
    assert_eq!(measure(&[]), Err(StoreError::Truncated));
    assert_eq!(measure(&[0u8; 40]), Err(StoreError::Truncated));
}

/// A container cut short is refused, and refused as *truncated* rather than
/// as anything about its contents.
#[test]
fn truncated_region_is_refused() {
    let (buffer, len) = built();
    for cut in [HEADER_SIZE, HEADER_SIZE + ENTRY_SIZE, len - 1] {
        assert_eq!(measure(&buffer[..cut]), Err(StoreError::Truncated), "{cut}");
    }
}

/// **Both directions, and the backward one is the interesting one.** A
/// version from the future is obviously refused; versions 1 and 2 — the format
/// D146 shipped and the one before headers carried a signature offset — are
/// refused too, rather than read for the fields whose names this reader still
/// recognizes. Every one of them sits at the same offset it did, which is
/// exactly what would make reading them look like it worked.
#[test]
fn unsupported_version_and_algorithm() {
    for version in [1u8, 2, 4] {
        let (mut buffer, len) = built();
        buffer[4] = version;
        assert_eq!(
            measure(&buffer[..len]),
            Err(StoreError::UnsupportedFormat),
            "version {version}"
        );
    }

    let (mut buffer, len) = built();
    buffer[24] = 0; // algorithm = Unspecified, which decode refuses outright
    assert_eq!(
        measure(&buffer[..len]),
        Err(StoreError::UnsupportedAlgorithm)
    );
}

/// An entry reaching past the end of the container is malformed — the check
/// that stops a directory from describing memory the container does not own.
#[test]
fn entry_out_of_range_is_malformed() {
    let (mut buffer, len) = built();
    // The first entry's length field, at directory + 24.
    buffer[HEADER_SIZE + 24] = 0xff;
    assert_eq!(measure(&buffer[..len]), Err(StoreError::Malformed));
}

/// A blob starting inside the directory is malformed too: it would be
/// measured as content and as directory at once.
#[test]
fn entry_overlapping_directory_is_malformed() {
    let (mut buffer, len) = built();
    buffer[HEADER_SIZE + 16] = 0x00; // first entry's offset -> 0
    assert_eq!(measure(&buffer[..len]), Err(StoreError::Malformed));
}

#[test]
fn builder_refuses_bad_names_and_disorder() {
    let mut buffer = [0u8; 512];
    let long = "a-name-far-too-long-for-the-field";
    assert_eq!(
        build_into(
            &mut buffer,
            ANCHOR_ID,
            &[BuildEntry {
                name: long,
                svn: 0,
                image_version: 0,
                flags: 0,
                bytes: b"x"
            }],
            false
        ),
        Err(BuildError::BadName)
    );
    assert_eq!(
        build_into(
            &mut buffer,
            ANCHOR_ID,
            &[BuildEntry {
                name: "",
                svn: 0,
                image_version: 0,
                flags: 0,
                bytes: b"x"
            }],
            false
        ),
        Err(BuildError::BadName)
    );
    assert_eq!(
        build_into(
            &mut buffer,
            ANCHOR_ID,
            &[BuildEntry {
                name: "has space",
                svn: 0,
                image_version: 0,
                flags: 0,
                bytes: b"x"
            }],
            false
        ),
        Err(BuildError::BadName)
    );

    let mut backwards = sample();
    backwards.swap(0, 1);
    assert_eq!(
        build_into(&mut buffer, ANCHOR_ID, &backwards, false),
        Err(BuildError::Unsorted)
    );

    let duplicate = [sample()[0], sample()[0]];
    assert_eq!(
        build_into(&mut buffer, ANCHOR_ID, &duplicate, false),
        Err(BuildError::Unsorted)
    );
}

#[test]
fn builder_refuses_a_buffer_that_does_not_fit() {
    let entries = sample();
    let needed = built_size(&entries, false).expect("size");
    let mut exact = [0u8; 512];
    assert_eq!(
        build_into(&mut exact[..needed - 1], ANCHOR_ID, &entries, false),
        Err(BuildError::BufferTooSmall)
    );
    assert_eq!(
        build_into(&mut exact[..needed], ANCHOR_ID, &entries, false).map(|built| built.len),
        Ok(needed)
    );
}
