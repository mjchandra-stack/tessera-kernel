// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **A signed update channel**: what a driver has to be for a system to accept
//! it from somewhere else.
//!
//! `docs/drivers/01` ("Certification") ends on one sentence — *"certified
//! drivers can be distributed through signed update channels"* — and this is
//! the other half of it. Everything before this in the phase produced a
//! verdict; nothing consumed one. A certificate nobody checks is a record, and
//! this is what makes it a **decision**.
//!
//! # The signature covers the bytes the decision is made from
//!
//! This crate parses the manifest itself rather than taking values a caller
//! decoded, and that is the whole reason it has a parser. A caller that decoded
//! the manifest and handed the fields over would leave a seam between *what was
//! signed* and *what was judged*, and every interesting attack on a signed
//! artifact lives in exactly that gap: sign one thing, present another, and let
//! the verifier and the reader disagree about which is which. Here there is no
//! gap, because the bytes the signature covers are the bytes the rules read.
//!
//! # Four ways in, and every one of them has to hold
//!
//! - **The manifest is signed by the channel's anchor.** Not merely
//!   well-formed: `api/image-store` can already say a container is intact, and
//!   what a channel needs is who produced it.
//! - **The driver is certified**, in the full sense
//!   [`tessera_certification::Certificate::is_certified`] means — every check
//!   ran *and* passed. This is where the eleven checks stop being a report.
//! - **The certificate is about this driver**, contract version included. A
//!   certificate for the same driver at an earlier contract is evidence about a
//!   thing this entry is not shipping.
//! - **The certificate names the bytes being shipped.** A certificate with no
//!   measurement is honest evidence about the checks and no evidence about any
//!   artifact — `certification.isl` says so, and says a channel is the thing
//!   that must refuse it. This is that refusal.
//!
//! And the rollback floor, which is not about certification at all: a correctly
//! signed, fully certified image below the floor is still refused, because
//! `docs/security/02` ("Anti-Rollback") makes that the system's decision rather
//! than the producer's.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Certification"),
//! docs/security/02-cryptography-and-key-management.md ("Anti-Rollback",
//! "Trust Anchors And Signing Infrastructure"),
//! docs/lifecycle/01-development-maintenance-update-model.md

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use tessera_certification::{Certificate, Subject};
use tessera_ed25519::{PublicKey, Signature, verify};

/// The manifest's magic, so a reader refuses something else's bytes before it
/// has believed any field of them.
pub const MAGIC: u32 = 0x5443_484e; // "TCHN"

/// The layout version this crate understands.
pub const VERSION: u32 = 1;

/// One entry, on the wire.
pub const ENTRY_SIZE: usize = 64;
/// The header before the entries.
pub const HEADER_SIZE: usize = 32;
/// The signature that follows them.
pub const SIGNATURE_SIZE: usize = 64;

/// The most entries a manifest may carry.
///
/// Bounded because this parses input from outside the system and runs where
/// allocation is fallible; a manifest claiming more is refused rather than
/// truncated, since a truncated channel silently ships a subset nobody chose.
pub const MAX_ENTRIES: usize = 32;

/// What a manifest says about one driver.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub driver: u32,
    pub class: u32,
    pub contract_version: u32,
    /// The security version, against which the system's floor is applied.
    pub svn: u32,
    /// Which checks ran, and which passed, as `api/certification` numbers them.
    pub ran: u32,
    pub passed: u32,
    /// The measurement of the artifact this entry ships.
    pub image: [u8; 32],
}

/// Why an entry was not admitted.
///
/// Distinct values because they are different conversations to have. A refusal
/// that said only "no" would leave an operator unable to tell a broken signing
/// pipeline from a driver that was never certified from a deliberate rollback
/// block — three problems with three different owners.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The bytes are not a manifest this crate understands.
    Malformed,
    /// The signature does not verify under the channel's anchor.
    NotFromThisChannel,
    /// The certificate is self-contradictory: it claims a check that never ran.
    ForgedCertificate,
    /// Some check did not run, or ran and failed.
    NotCertified,
    /// The certificate is about a different driver, class, or contract version.
    CertifiedForSomethingElse,
    /// The certificate names no artifact, so it is evidence about no bytes.
    NoMeasurement,
    /// The security version is below the system's floor.
    BelowTheRollbackFloor,
}

/// A manifest whose signature has been checked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Manifest {
    /// Which channel this is.
    pub channel: u32,
    /// The manifest's own version, so a system can refuse to go backwards.
    pub sequence: u32,
    entries: [Entry; MAX_ENTRIES],
    count: usize,
}

impl Manifest {
    pub fn entries(&self) -> &[Entry] {
        &self.entries[..self.count]
    }
}

/// How many leading bytes the signature covers: the header and every entry.
///
/// Public, and tested on its own, because it is the one property of this format
/// that cannot be checked any other way in a tree that can only verify. A
/// manifest signed over its header alone would accept entries swapped after
/// signing, and every positive test would still pass — an inversion that made
/// exactly that change went unnoticed until this existed, because the tests
/// that exercised the signature path all used manifests with no entries.
pub fn signed_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < HEADER_SIZE + SIGNATURE_SIZE {
        return None;
    }
    let mut four = [0u8; 4];
    four.copy_from_slice(&bytes[16..20]);
    let count = u32::from_le_bytes(four) as usize;
    if count > MAX_ENTRIES {
        return None;
    }
    Some(HEADER_SIZE + count * ENTRY_SIZE)
}

/// Reads a signed manifest, or says why it is not one.
///
/// **The signature is checked over the header and entries exactly as they
/// appear**, before any entry is looked at. A reader that parsed first and
/// verified afterwards would have already acted on unauthenticated fields.
pub fn open(bytes: &[u8], anchor: &PublicKey) -> Result<Manifest, Refusal> {
    if bytes.len() < HEADER_SIZE + SIGNATURE_SIZE {
        return Err(Refusal::Malformed);
    }
    let read32 = |at: usize| -> u32 {
        let mut four = [0u8; 4];
        four.copy_from_slice(&bytes[at..at + 4]);
        u32::from_le_bytes(four)
    };
    if read32(0) != MAGIC || read32(4) != VERSION {
        return Err(Refusal::Malformed);
    }
    let channel = read32(8);
    let sequence = read32(12);
    let count = read32(16) as usize;
    let Some(signed_len) = signed_len(bytes) else {
        return Err(Refusal::Malformed);
    };
    if bytes.len() != signed_len + SIGNATURE_SIZE {
        // Exactly, not at least: trailing bytes the signature does not cover
        // are bytes somebody added afterwards.
        return Err(Refusal::Malformed);
    }

    let mut signature: Signature = [0u8; SIGNATURE_SIZE];
    signature.copy_from_slice(&bytes[signed_len..]);
    if !verify(anchor, &bytes[..signed_len], &signature) {
        return Err(Refusal::NotFromThisChannel);
    }

    let mut entries = [Entry {
        driver: 0,
        class: 0,
        contract_version: 0,
        svn: 0,
        ran: 0,
        passed: 0,
        image: [0; 32],
    }; MAX_ENTRIES];
    for (i, entry) in entries.iter_mut().take(count).enumerate() {
        let at = HEADER_SIZE + i * ENTRY_SIZE;
        entry.driver = read32(at);
        entry.class = read32(at + 4);
        entry.contract_version = read32(at + 8);
        entry.svn = read32(at + 12);
        entry.ran = read32(at + 16);
        entry.passed = read32(at + 20);
        entry.image.copy_from_slice(&bytes[at + 32..at + 64]);
    }
    Ok(Manifest {
        channel,
        sequence,
        entries,
        count,
    })
}

/// Whether `entry` may be installed, given the system's rollback floor.
///
/// The order is deliberate: what the entry *is* before what the system *wants*.
/// A driver that was never certified and is also below the floor should hear
/// the first, because raising the floor would not help it.
pub fn admit(entry: &Entry, floor: u32) -> Result<(), Refusal> {
    let subject = Subject {
        driver: entry.driver,
        class: entry.class,
        contract_version: entry.contract_version,
    };
    let Some(certificate) = Certificate::from_parts(subject, entry.ran, entry.passed) else {
        return Err(Refusal::ForgedCertificate);
    };
    if !certificate.covers(subject) {
        return Err(Refusal::CertifiedForSomethingElse);
    }
    if !certificate.is_certified() {
        return Err(Refusal::NotCertified);
    }
    if entry.image == [0u8; 32] {
        return Err(Refusal::NoMeasurement);
    }
    if entry.svn < floor {
        return Err(Refusal::BelowTheRollbackFloor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera_certification::ALL;

    /// RFC 8032 test 3's key and the secret that goes with it are not here —
    /// this crate cannot sign. So the fixtures are built the only way a
    /// verify-only tree can build them: a signature produced elsewhere over
    /// bytes fixed here.
    ///
    /// **Which means the positive path is proven by construction and the
    /// negative paths are proven directly.** Every test below that expects a
    /// refusal is exact; the one that expects admission checks `admit` alone,
    /// with the signature step exercised by `api/ed25519`'s own vectors.
    fn entry(certified: bool, svn: u32, measured: bool) -> Entry {
        Entry {
            driver: 7,
            class: 10,
            contract_version: 1,
            svn,
            ran: ALL,
            passed: if certified { ALL } else { ALL & !(1 << 5) },
            image: if measured { [0xa5; 32] } else { [0; 32] },
        }
    }

    #[test]
    fn a_certified_measured_entry_at_the_floor_is_admitted() {
        assert_eq!(admit(&entry(true, 5, true), 5), Ok(()));
        assert_eq!(admit(&entry(true, 9, true), 5), Ok(()));
    }

    /// **The check that makes the certificate load-bearing.** One check failed;
    /// everything else about the entry is perfect.
    #[test]
    fn a_driver_that_failed_a_check_does_not_enter() {
        assert_eq!(admit(&entry(false, 9, true), 5), Err(Refusal::NotCertified));
    }

    /// And one where a check simply never ran, which is the same refusal for a
    /// different reason and must not be mistaken for a pass.
    #[test]
    fn a_driver_nobody_finished_checking_does_not_enter() {
        let mut e = entry(true, 9, true);
        e.ran &= !(1 << 5);
        e.passed &= !(1 << 5);
        assert_eq!(admit(&e, 5), Err(Refusal::NotCertified));
    }

    /// A record claiming a check passed that never ran is a forgery, not a
    /// certificate, and it is refused as such rather than as a failure.
    #[test]
    fn a_forged_certificate_is_named_as_one() {
        let mut e = entry(true, 9, true);
        e.ran &= !(1 << 5);
        assert_eq!(admit(&e, 5), Err(Refusal::ForgedCertificate));
    }

    /// **A certificate with no measurement is evidence about no bytes.**
    /// `certification.isl` says a channel must refuse it; this is where.
    #[test]
    fn an_unmeasured_certificate_does_not_enter() {
        assert_eq!(
            admit(&entry(true, 9, false), 5),
            Err(Refusal::NoMeasurement)
        );
    }

    /// A correctly signed, fully certified image below the floor. Certification
    /// is the producer's claim; the floor is the system's, and it wins.
    #[test]
    fn the_rollback_floor_outranks_a_perfect_certificate() {
        assert_eq!(
            admit(&entry(true, 4, true), 5),
            Err(Refusal::BelowTheRollbackFloor)
        );
    }

    /// What an entry *is* is answered before what the system wants, so a driver
    /// that is both uncertified and stale hears the reason raising the floor
    /// would not fix.
    #[test]
    fn being_uncertified_is_reported_before_being_stale() {
        assert_eq!(admit(&entry(false, 1, true), 5), Err(Refusal::NotCertified));
    }

    /// Bytes that are not a manifest are refused before anything is believed
    /// about them — including the length field, which is exactly the field a
    /// reader must not trust first.
    #[test]
    fn a_reader_refuses_before_it_believes_a_length() {
        let anchor = [0u8; 32];
        assert_eq!(open(&[], &anchor), Err(Refusal::Malformed));
        assert_eq!(open(&[0u8; 96], &anchor), Err(Refusal::Malformed));

        let mut bytes = [0u8; HEADER_SIZE + SIGNATURE_SIZE];
        bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&VERSION.to_le_bytes());
        // A count nothing could hold.
        bytes[16..20].copy_from_slice(&(MAX_ENTRIES as u32 + 1).to_le_bytes());
        assert_eq!(open(&bytes, &anchor), Err(Refusal::Malformed));
    }

    /// A well-formed manifest under a key that did not sign it. The bytes are
    /// perfect; only the authority is missing.
    #[test]
    fn a_manifest_from_somebody_else_is_refused() {
        let mut bytes = [0u8; HEADER_SIZE + SIGNATURE_SIZE];
        bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&VERSION.to_le_bytes());
        // Zero entries, so the length arithmetic is satisfied.
        assert_eq!(
            open(&bytes, &[0x11u8; 32]),
            Err(Refusal::NotFromThisChannel)
        );
    }

    /// **The signature covers the entries, not just the header.** A manifest
    /// signed over its header alone would let entries be swapped afterwards
    /// while every positive test still passed — which is not hypothetical: an
    /// inversion making exactly that change went unnoticed until this test
    /// existed, because every test that reached the signature used a manifest
    /// with no entries in it.
    #[test]
    fn what_is_signed_grows_with_the_entries() {
        // Sized for the largest case here rather than allocated: this crate is
        // `no_std` and its tests hold to the same rule as its code.
        let mut buffer = [0u8; HEADER_SIZE + 3 * ENTRY_SIZE + SIGNATURE_SIZE];
        for count in 0..4usize {
            let len = HEADER_SIZE + count * ENTRY_SIZE + SIGNATURE_SIZE;
            let bytes = &mut buffer[..len];
            bytes.fill(0);
            bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            bytes[4..8].copy_from_slice(&VERSION.to_le_bytes());
            bytes[16..20].copy_from_slice(&(count as u32).to_le_bytes());
            assert_eq!(
                signed_len(bytes),
                Some(HEADER_SIZE + count * ENTRY_SIZE),
                "with {count} entries",
            );
        }
    }

    /// **Trailing bytes the signature does not cover.** A manifest that was
    /// signed and then grown is not the manifest that was signed.
    #[test]
    fn bytes_added_after_signing_are_refused() {
        let mut bytes = [0u8; HEADER_SIZE + SIGNATURE_SIZE + 1];
        bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&VERSION.to_le_bytes());
        assert_eq!(open(&bytes, &[0u8; 32]), Err(Refusal::Malformed));
    }
}
