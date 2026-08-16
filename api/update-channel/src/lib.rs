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
#[path = "tests/lib.rs"]
mod tests;
