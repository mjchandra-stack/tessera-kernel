// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

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
