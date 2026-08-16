// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **What this system is willing to trust, and the record of what it did.**
//!
//! The container format and every rule about it are in `//api/image-store`,
//! which is host-tested and knows nothing about this kernel. What is here is
//! the part that cannot be tested on a host because it is a *decision*: which
//! trust anchors this system holds, and the structured record of a mount
//! either succeeding or being refused.
//!
//! # The anchor is checked in, and that is the mechanism
//!
//! [`TRUSTED_ANCHORS`] is a constant in kernel source. It would have been far
//! more convenient to have the build emit both the container and its anchor —
//! and it would have verified nothing that matters. A build that decides what
//! it is trusted to produce authenticates transport and corruption, and
//! authorizes anything it happens to build; the digest would agree with the
//! bytes for the same reason a self-signed claim agrees with itself.
//!
//! With the anchor in source, changing what this kernel trusts is a source
//! change somebody reviews — which is the reviewable-trust property a signing
//! ceremony has, arrived at by the only means available to a tree with no
//! private key. The cost is real and deliberate: **changing the store's
//! contents fails the build until the constant is updated.**
//! `//store:anchor_test` prints the value to paste, and `mkstore anchor` prints
//! it for any container.
//!
//! This is a measurement anchor and not a public key. `docs/security/02`
//! ("Trust Anchors And Signing Infrastructure") names both kinds, so this is
//! one of the two rather than a stand-in for the other — but it establishes
//! *what* the bytes are and never *who* produced them. That distinction is the
//! milestone's headline deviation and is recorded as one (build/README.md,
//! D146).
//!
//! Normative: docs/security/01-security-model.md ("Boot Security"),
//! docs/security/02-cryptography-and-key-management.md ("Trust Anchors And
//! Signing Infrastructure")
//! Budget: none (one boot-time pass over the directory)

use tessera_image_store::{Anchor, Store, StoreError};

use crate::event::{Component, EventKind, Severity, emit};

/// The anchor id the system image's store carries.
///
/// A constant rather than "whatever the container says" on the reading side
/// too: a verifier that took the id from the artifact would let the artifact
/// choose which key checks it.
pub const SYSTEM_STORE_ANCHOR_ID: u32 = 1;

/// The measurements this kernel treats as authoritative.
///
/// **Update procedure**: run `bazel test //store:anchor_test`, which prints the
/// container's measurement when it disagrees with this, and paste it here. The
/// change is the reviewable act — see the module comment for why it is not
/// automated.
pub const TRUSTED_ANCHORS: [Anchor; 1] = [Anchor {
    id: SYSTEM_STORE_ANCHOR_ID,
    digest: [
        0x19, 0x5b, 0xc2, 0x08, 0x73, 0xca, 0xc8, 0x2a, 0xcd, 0x3f, 0xef, 0xa6, 0xf4, 0xb5, 0x44,
        0xbd, 0xff, 0x16, 0xd1, 0xdc, 0xfb, 0x61, 0x39, 0x70, 0x37, 0x57, 0x19, 0x57, 0x16, 0x65,
        0x6e, 0x48,
    ],
}];

/// Verifies `region` against [`TRUSTED_ANCHORS`] and records the outcome.
///
/// The record is emitted on **both** paths. A refusal that produced no event
/// would make an altered store and an absent one look identical from outside
/// the machine — the same symptom, two entirely different situations — which
/// is the silent degradation `docs/lifecycle/04` forbids.
pub fn mount(region: &[u8]) -> Result<Store<'_>, StoreError> {
    mount_against(region, &TRUSTED_ANCHORS)
}

/// [`mount`] against a given anchor set, and the *record* is the reason it is
/// separate rather than inlined: every mount emits one, so a path that verified
/// against different anchors and skipped the record would be the one mount
/// nobody could audit.
pub fn mount_against<'a>(region: &'a [u8], anchors: &[Anchor]) -> Result<Store<'a>, StoreError> {
    match Store::mount(region, anchors) {
        Ok(store) => {
            let anchor = store.anchor();
            let mut lead = [0u8; 8];
            lead.copy_from_slice(&anchor[..8]);
            emit(
                EventKind::StoreMounted,
                Severity::Notice,
                Component::Security,
                [
                    store.len() as u64,
                    store.algorithm() as u32 as u64,
                    store.anchor_id() as u64,
                    u64::from_be_bytes(lead),
                ],
            );
            Ok(store)
        }
        Err(error) => {
            emit(
                EventKind::StoreRefused,
                Severity::Error,
                Component::Security,
                [
                    error as u32 as u64,
                    region.len() as u64,
                    anchor_id_of(region),
                    0,
                ],
            );
            Err(error)
        }
    }
}

/// The anchor id a region names, where its header is intact enough to say.
///
/// Read from the raw bytes rather than from a mounted store, because the whole
/// point is to report it for a container that did **not** mount. Zero where the
/// region is too short to hold a header — which is not an anchor id anybody can
/// have, so nothing legitimate is being swallowed.
fn anchor_id_of(region: &[u8]) -> u64 {
    match region.get(28..32) {
        Some(bytes) => {
            let mut id = [0u8; 4];
            id.copy_from_slice(bytes);
            u32::from_le_bytes(id) as u64
        }
        None => 0,
    }
}

/// The blob every port's boot check reads.
pub const SYSTEM_FIRMWARE: &str = "firmware.bin";
/// The second blob, which exists so that looking a name up has to choose.
pub const SYSTEM_PLATFORM: &str = "platform.bin";

/// What a passing boot check reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StoreReport {
    /// The container's size, which is also what it claimed.
    pub bytes: usize,
    pub entries: usize,
    pub firmware_len: usize,
    /// The leading eight bytes of the firmware blob's measurement — enough to
    /// name *which* image was accepted in a line somebody reads.
    pub firmware_lead: u64,
}

/// Why a boot check failed.
///
/// `Refused` is the store saying no about itself; the other three are the
/// **check** saying no about the store's reader, and keeping them apart is the
/// point: a verifier that stopped verifying and a container that is bad are
/// opposite situations, and a single failure code would let the first hide
/// behind the second.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckError {
    /// The real container did not mount, or the blob did not come out.
    Refused(StoreError),
    /// No room to make the working copy the tamper half needs.
    ScratchTooSmall,
    /// A blob whose bytes were altered came out of the store anyway.
    TamperedBlobOpened,
    /// A blob nobody touched was refused: the tamper was not scoped to itself.
    IntactBlobRefused,
    /// A container whose directory was altered mounted anyway.
    TamperedDirectoryMounted,
}

impl CheckError {
    /// A number for a boot verdict line. `StoreError`s keep their own values
    /// (1–8); the check's own start at 100, so a reader of a failing boot can
    /// tell which half spoke without a table.
    pub fn code(self) -> u32 {
        match self {
            CheckError::Refused(error) => error as u32,
            CheckError::ScratchTooSmall => 100,
            CheckError::TamperedBlobOpened => 101,
            CheckError::IntactBlobRefused => 102,
            CheckError::TamperedDirectoryMounted => 103,
        }
    }
}

/// Byte offset of `svn` within a `StoreEntry`, from the schema: `size` 4,
/// `version` 4, `flags` 8, `offset` 8, `length` 8, `name` 24.
///
/// A field the reader carries and does not validate, which is what makes it the
/// right byte to change below — a refusal there is the *anchor* rejecting the
/// directory, and not a structural check catching an impossible value.
const ENTRY_SVN_OFFSET: usize = 56;

/// **Mounts the system store and proves, on the same code path, that it refuses
/// two kinds of altered one.**
///
/// One implementation driven by every port, for the reason `kcore::supervise`
/// is one implementation driven by every port: this is not architecture, and a
/// copy per port would be five chances for the interesting half to rot
/// somewhere nobody is looking.
///
/// **The interesting half is the refusal.** A check that only ever saw a valid
/// container would pass just as happily against a `mount` that returned success
/// unconditionally, so the same code is given a copy with one byte changed in a
/// blob — which must fail at `open`, because the anchor covers the directory
/// and the directory's digest of that blob is what disagrees — and a copy with
/// one byte changed in the directory, which must fail at `mount`, because that
/// is what the anchor covers. Two different failures from two different
/// tampers; one refusal could be anything. The untouched blob still opening is
/// the third claim: the refusal is scoped to what changed.
///
/// `scratch` is the caller's because a kernel stack's size is the caller's
/// business.
pub fn self_check(region: &[u8], scratch: &mut [u8]) -> Result<StoreReport, CheckError> {
    self_check_against(region, scratch, &TRUSTED_ANCHORS)
}

/// [`self_check`] against a given anchor set, so the tamper logic can be
/// host-tested over a container built in a test — which is the only way to
/// exercise it without a boot.
pub fn self_check_against(
    region: &[u8],
    scratch: &mut [u8],
    anchors: &[Anchor],
) -> Result<StoreReport, CheckError> {
    let store = Store::mount(region, anchors).map_err(CheckError::Refused)?;
    let entries = store.len();
    let firmware = store.open(SYSTEM_FIRMWARE).map_err(CheckError::Refused)?;
    let mut lead = [0u8; 8];
    lead.copy_from_slice(&firmware.digest[..8]);
    let report = StoreReport {
        bytes: region.len(),
        entries,
        firmware_len: firmware.bytes.len(),
        firmware_lead: u64::from_be_bytes(lead),
    };

    // Refused rather than truncated: a partial copy would be a tamper check
    // over bytes that are not the store (docs/lifecycle/04, "No Silent
    // Fallback").
    let working = scratch
        .get_mut(..region.len())
        .ok_or(CheckError::ScratchTooSmall)?;

    // A byte in the last blob. The directory still measures to the anchor, so
    // the container mounts — and that blob does not come out.
    working.copy_from_slice(region);
    let last = working.len() - 1;
    working[last] ^= 0x01;
    let tampered = Store::mount(working, anchors).map_err(CheckError::Refused)?;
    if tampered.open(SYSTEM_PLATFORM).is_ok() {
        return Err(CheckError::TamperedBlobOpened);
    }
    if tampered.open(SYSTEM_FIRMWARE).is_err() {
        return Err(CheckError::IntactBlobRefused);
    }

    // A byte in the directory — the first entry's security version number, a
    // change with a motive. This one the anchor catches, so nothing mounts.
    working.copy_from_slice(region);
    working[tessera_image_store::StoreHeader::WIRE_SIZE + ENTRY_SVN_OFFSET] ^= 0x04;
    if Store::mount(working, anchors).is_ok() {
        return Err(CheckError::TamperedDirectoryMounted);
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
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
}
