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
    build_into(buffer, TEST_ANCHOR_ID, &entries).unwrap_or_default()
}

fn anchors_for(bytes: &[u8]) -> [Anchor; 1] {
    [Anchor {
        id: TEST_ANCHOR_ID,
        digest: measure(bytes).unwrap_or([0; 32]),
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
        digest: [0; 32],
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
