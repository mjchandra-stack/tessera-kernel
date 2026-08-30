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

use tessera_image_store::{Anchor, Store, StoreError, Trust};

use crate::event::{Component, EventKind, Severity, emit};

/// The anchor id the system image's store carries.
///
/// A constant rather than "whatever the container says" on the reading side
/// too: a verifier that took the id from the artifact would let the artifact
/// choose which key checks it.
pub const SYSTEM_STORE_ANCHOR_ID: u32 = 1;

/// The anchor id the machine's **program store** carries (D290).
///
/// A different id from the system store's, so a verifier holding both cannot
/// accept one where the other was meant — which is the whole reason anchors are
/// looked up by id rather than tried in turn.
pub const PROGRAM_STORE_ANCHOR_ID: u32 = 2;

/// The measurements this kernel treats as authoritative.
///
/// **Update procedure**: run `bazel test //store:anchor_test`, which prints the
/// container's measurement when it disagrees with this, and paste it here. The
/// change is the reviewable act — see the module comment for why it is not
/// automated.
/// [`TRUSTED_ANCHORS`] as a slice, for callers that want to pass the whole set
/// rather than name one.
pub const TRUSTED_ANCHORS_REF: &[Anchor] = &TRUSTED_ANCHORS;

pub const TRUSTED_ANCHORS: [Anchor; 2] = [
    Anchor {
        id: SYSTEM_STORE_ANCHOR_ID,
        // **A pinned measurement, and it stays one.** This container's blobs are
        // generated from fixed seeds and never change, so there is something
        // stable for a human to have approved — which is the stronger of the two
        // things an anchor can hold (D289). The program store that Phase 2 adds
        // cannot be anchored this way, because its contents are whatever the build
        // just compiled, and it uses a key instead.
        trust: Trust::Digest([
            0x10, 0x36, 0x0a, 0x68, 0x6e, 0x9c, 0x0a, 0x07, 0xd7, 0x04, 0xad, 0xae, 0x63, 0xb3,
            0x30, 0x29, 0x3c, 0xf9, 0x50, 0x71, 0x21, 0xb8, 0x72, 0x70, 0x3b, 0x30, 0xac, 0xbe,
            0x64, 0x32, 0xbb, 0xa6,
        ]),
    },
    Anchor {
        id: PROGRAM_STORE_ANCHOR_ID,
        // **A key, because there is nothing stable for a human to have approved.**
        // This container holds the programs the build just compiled; its
        // measurement is different every time any of them changes, so a pinned
        // digest here would be a constant nobody could keep current (D289). The
        // public half of the development key `build/rules/components.bzl` signs
        // with — printed by `mkstore pubkey` and pasted, the same reviewable act
        // the measurement above is.
        trust: Trust::Key([
            0x56, 0x28, 0x0e, 0x94, 0x20, 0xa8, 0x1b, 0xa0, 0x43, 0xa8, 0x47, 0x4c, 0x02, 0x6f,
            0x54, 0x86, 0x51, 0x5e, 0x53, 0x1a, 0x02, 0xec, 0xfc, 0x86, 0x5a, 0x25, 0x70, 0x78,
            0x4f, 0x0e, 0x54, 0xf2,
        ]),
    },
];

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
#[path = "tests/store.rs"]
mod tests;

/// Reading ring-3 programs out of the machine's signed program store (D290).
///
/// **The logic is here rather than in the generated accessors** because it is
/// code and not a list. `//components` emits one accessor per program; what
/// they all call is this, where it can be tested against a container a test
/// built — including a container that was changed after it was signed, which is
/// the case the whole mechanism exists for and which no generated crate could
/// be handed.
pub mod programs {
    use super::{PROGRAM_STORE_ANCHOR_ID, TRUSTED_ANCHORS};
    use tessera_image_store::{Anchor, Store, StoreError, Trust};

    /// What the first mount concluded: `None` until it has run, then the anchor
    /// the store measured to, or `Some(None)` for one this kernel will not
    /// trust.
    ///
    /// **The signature is a curve operation and there are thirty programs**, so
    /// it runs once and what is remembered is the measurement it vouched for.
    /// Every mount after that compares against it instead — and every `open`
    /// still checks the blob's own digest, which is the part that has to run
    /// per program anyway.
    ///
    /// A plain `static mut` rather than an atomic: this is reached on the boot
    /// CPU before anything else is scheduled, and a lock here would be a lock
    /// on the path that starts the first process.
    static mut VERIFIED: Option<Option<[u8; 32]>> = None;

    /// The store `region` holds, if this kernel trusts it.
    fn mounted(region: &'static [u8]) -> Option<Store<'static>> {
        // SAFETY: the boot CPU alone reaches this, before any other thread
        // exists — every caller is a port starting the first processes.
        let cached = unsafe { VERIFIED };
        match cached {
            // Refused once is refused for good: nothing about the container can
            // change between calls, so re-checking would be re-deciding.
            Some(None) => None,
            // **Against the measurement, not the key.** The signature already
            // said this digest is the one; comparing to it is the same decision
            // reached the cheap way.
            Some(Some(digest)) => Store::mount(
                region,
                &[Anchor {
                    id: PROGRAM_STORE_ANCHOR_ID,
                    trust: Trust::Digest(digest),
                }],
            )
            .ok(),
            None => {
                let store = Store::mount(region, &TRUSTED_ANCHORS);
                let remembered = store.as_ref().ok().map(|store| store.anchor());
                // SAFETY: as above.
                unsafe {
                    VERIFIED = Some(remembered);
                }
                store.ok()
            }
        }
    }

    /// One program's bytes, or an empty slice if the store does not vouch for
    /// it.
    ///
    /// **Empty rather than a panic, and empty rather than unchecked bytes.** A
    /// program that is absent is the case every boot check already reports — a
    /// kernel with nothing to start says so loudly — while returning bytes
    /// nobody vouched for would be the linked-symbol behaviour wearing a
    /// store's clothes.
    pub fn open(region: &'static [u8], name: &str) -> &'static [u8] {
        match mounted(region).map(|store| store.open(name)) {
            Some(Ok(blob)) => blob.bytes,
            Some(Err(StoreError::NotFound)) | None => &[],
            // A blob that does not measure to what its entry says is a
            // container changed after it was signed — impossible if the
            // signature held, and so worth refusing rather than assuming.
            Some(Err(_)) => &[],
        }
    }

    /// Forgets the cached verdict, so a test can present a second container.
    ///
    /// There is no such thing at run time: a machine has one program store for
    /// its whole life, which is exactly why the verdict may be cached at all.
    #[cfg(test)]
    pub fn forget() {
        // SAFETY: `RUST_TEST_THREADS=1` — the harness runs these one at a time.
        unsafe {
            VERIFIED = None;
        }
    }
}
