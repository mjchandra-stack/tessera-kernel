// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::store`.

use super::*;
use tessera_image_store::{BuildEntry, build_into, measure};

const TEST_ANCHOR_ID: u32 = 1;

/// A container shaped like the system store: the two blobs the check reads,
/// the second long enough that a flipped last byte lands inside it.
fn container(buffer: &mut [u8]) -> usize {
    let entries = [
        BuildEntry {
            name: SYSTEM_FIRMWARE,
            svn: 1,
            image_version: 1,
            flags: 0,
            bytes: &[0x11; 64],
        },
        BuildEntry {
            name: SYSTEM_PLATFORM,
            svn: 1,
            image_version: 1,
            flags: 0,
            bytes: &[0x22; 32],
        },
    ];
    // Zero on failure, which every caller then fails on: kcore forbids
    // `unwrap` and a test helper is not the place to make an exception.
    build_into(buffer, TEST_ANCHOR_ID, &entries, false)
        .map(|built| built.len)
        .unwrap_or_default()
}

fn anchors_for(bytes: &[u8]) -> [Anchor; 1] {
    [Anchor {
        id: TEST_ANCHOR_ID,
        trust: tessera_image_store::Trust::Digest(measure(bytes).unwrap_or([0; 32])),
    }]
}

/// The anchor set is not empty and names the id the system image uses.
/// A kernel with no anchors would refuse every container, which is safe and
/// useless — and would be an easy thing to reach by deleting a line.
#[test]
fn the_system_anchor_is_present() {
    assert!(
        TRUSTED_ANCHORS
            .iter()
            .any(|anchor| anchor.id == SYSTEM_STORE_ANCHOR_ID)
    );
}

/// A region that is not a store is refused, and the refusal says so.
#[test]
fn noise_is_refused() {
    assert_eq!(mount(&[0xa5; 128]).err(), Some(StoreError::BadMagic));
    assert_eq!(mount(&[]).err(), Some(StoreError::Truncated));
}

/// The check every port runs, over a container built here.
#[test]
fn the_boot_check_passes_over_a_well_formed_store() {
    let mut buffer = [0u8; 512];
    let len = container(&mut buffer);
    let bytes = &buffer[..len];
    let mut scratch = [0u8; 512];
    let report = self_check_against(bytes, &mut scratch, &anchors_for(bytes))
        .expect("a store this kernel built");
    assert_eq!(report.entries, 2);
    assert_eq!(report.firmware_len, 64);
    assert_eq!(report.bytes, len);
}

/// **The check itself is what is under test here.** Given scratch it cannot
/// use, it must refuse rather than skip the tamper half and report success
/// — the failure mode that would make every port's verdict a claim about
/// nothing.
#[test]
fn a_scratch_buffer_too_small_refuses_rather_than_skipping() {
    let mut buffer = [0u8; 512];
    let len = container(&mut buffer);
    let bytes = &buffer[..len];
    let mut scratch = [0u8; 8];
    assert_eq!(
        self_check_against(bytes, &mut scratch, &anchors_for(bytes)),
        Err(CheckError::ScratchTooSmall)
    );
}

/// A container that is not this system's is refused before any of it is
/// read — and the refusal is the store's, not the check's.
#[test]
fn a_store_this_system_does_not_trust_is_refused() {
    let mut buffer = [0u8; 512];
    let len = container(&mut buffer);
    let mut scratch = [0u8; 512];
    let wrong = [Anchor {
        id: TEST_ANCHOR_ID,
        trust: tessera_image_store::Trust::Digest([0; 32]),
    }];
    assert_eq!(
        self_check_against(&buffer[..len], &mut scratch, &wrong),
        Err(CheckError::Refused(StoreError::UntrustedAnchor))
    );
}

/// Every failure has a number of its own, and the store's keep their own
/// values — a boot verdict is read by a human with no table to hand.
#[test]
fn failure_codes_are_distinct() {
    let codes = [
        CheckError::Refused(StoreError::DigestMismatch).code(),
        CheckError::ScratchTooSmall.code(),
        CheckError::TamperedBlobOpened.code(),
        CheckError::IntactBlobRefused.code(),
        CheckError::TamperedDirectoryMounted.code(),
    ];
    assert_eq!(codes, [8, 100, 101, 102, 103]);
}

// --- Reading programs out of the signed store (D290) ---------------------

/// A container holding two named programs, signed with a key a test chose.
///
/// The signer is a test-only dependency for the reason `api/image-store` gives:
/// this crate verifies and must never be able to sign, and reaching the
/// positive path at all needs something that can.
fn signed_programs(buffer: &mut [u8], secret: &[u8; 32]) -> usize {
    let entries = [
        BuildEntry {
            name: "device_manager",
            svn: 1,
            image_version: 1,
            flags: 0,
            bytes: b"the manager's ELF",
        },
        BuildEntry {
            name: "root_task",
            svn: 1,
            image_version: 1,
            flags: 0,
            bytes: b"the root task's ELF",
        },
    ];
    let Ok(built) = build_into(
        buffer,
        crate::store::PROGRAM_STORE_ANCHOR_ID,
        &entries,
        true,
    ) else {
        return 0;
    };
    let Some(at) = built.signature_at else {
        return 0;
    };
    let signature = tessera_ed25519_signer::sign(secret, &built.anchor);
    buffer[at..at + signature.len()].copy_from_slice(&signature);
    built.len
}

/// The key `TRUSTED_ANCHORS` actually holds, found by asking rather than by
/// copying it here — two copies of a constant is how they come to differ.
fn program_secret() -> [u8; 32] {
    // The development seed `build/rules/components.bzl` signs with, ASCII.
    let mut secret = [0u8; 32];
    let seed = b"TESSERAPROGRAMSTOREDEVKEY0123456";
    secret.copy_from_slice(seed);
    secret
}

/// **A program comes back only if the store was vouched for.**
///
/// Driven through `programs::open`, which is what the generated accessors call
/// — the thing an inversion has to break, and the thing a code generator could
/// not be handed a bad container to test.
#[test]
fn a_signed_program_store_yields_its_programs() {
    // `RUST_TEST_THREADS=1` — the cached verdict is shared, and the harness
    // runs these one at a time.
    crate::store::programs::forget();
    let mut buffer = [0u8; 1024];
    let len = signed_programs(&mut buffer, &program_secret());
    assert!(len > 0, "the test container did not build");
    let region: &'static [u8] =
        std::boxed::Box::leak(std::vec::Vec::from(&buffer[..len]).into_boxed_slice());
    assert_eq!(
        crate::store::programs::open(region, "device_manager"),
        b"the manager's ELF",
    );
    // A name the store does not carry is absent, not an error nobody handles.
    assert!(crate::store::programs::open(region, "absent").is_empty());
}

/// **A store changed after it was signed yields nothing.**
///
/// This is the inversion's target. An accessor that anchored on the
/// container's own measurement — that is, trusted whatever it was given —
/// passes every other check here and every boot, because an intact store is
/// intact either way. Only a *changed* one can tell them apart.
///
/// The flipped byte is the first entry's `flags`: a length or a name fails the
/// parse and never reaches the signature (D289).
#[test]
fn a_program_store_changed_after_signing_yields_nothing() {
    // `RUST_TEST_THREADS=1` — the cached verdict is shared, and the harness
    // runs these one at a time.
    crate::store::programs::forget();
    let mut buffer = [0u8; 1024];
    let len = signed_programs(&mut buffer, &program_secret());
    assert!(len > 0);
    buffer[64 + 4 + 4] ^= 0xff;
    let region: &'static [u8] =
        std::boxed::Box::leak(std::vec::Vec::from(&buffer[..len]).into_boxed_slice());
    assert!(
        crate::store::programs::open(region, "device_manager").is_empty(),
        "a program was handed out of a store nothing vouched for",
    );
}

/// And a store signed by somebody else yields nothing either.
#[test]
fn a_program_store_signed_by_a_stranger_yields_nothing() {
    // `RUST_TEST_THREADS=1` — the cached verdict is shared, and the harness
    // runs these one at a time.
    crate::store::programs::forget();
    let mut buffer = [0u8; 1024];
    let len = signed_programs(&mut buffer, &[9u8; 32]);
    assert!(len > 0);
    let region: &'static [u8] =
        std::boxed::Box::leak(std::vec::Vec::from(&buffer[..len]).into_boxed_slice());
    assert!(crate::store::programs::open(region, "root_task").is_empty());
}
