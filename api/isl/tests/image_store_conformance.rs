// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated image-store bindings (built by the
//! codegen genrule from `examples/image_store.isl`, never committed). Proves
//! `StoreHeader` and `StoreEntry` encode to fixed golden layouts and decode
//! back.
//!
//! **This format's stability rests entirely here, and it rests harder than a
//! protocol's does.** A wire format is agreed between two live peers who can be
//! updated together; a *stored* format is agreed between a writer and a reader
//! that may be separated by a system update — a container built before it and
//! read after it. There is no negotiation and no second chance to ask.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format"),
//! docs/security/01-security-model.md ("Boot Security")

use image_store_abi::{DigestAlgorithm, StoreEntry, StoreHeader};
use tessera_isl_runtime::{WireError, decode, encode};

/// "TESSTORE" as a little-endian `u64`: the bytes T,E,S,S,T,O,R,E in order.
const MAGIC: u64 = 0x4552_4f54_5353_4554;

/// Golden encoding of the header below: 56 bytes, LE.
const HEADER_GOLDEN: [u8; 56] = [
    0x38, 0, 0, 0, // size = 56
    0x02, 0, 0, 0, // version = 2
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x54, 0x45, 0x53, 0x53, 0x54, 0x4f, 0x52, 0x45, // magic = "TESSTORE"
    0x01, 0, 0, 0, // algorithm = Sha256
    0x01, 0, 0, 0, // anchor_id = 1
    0x02, 0, 0, 0, // entry_count = 2
    0, 0, 0, 0, // reserved = 0
    0x38, 0, 0, 0, 0, 0, 0, 0, // directory_offset = 56
    0x00, 0x02, 0, 0, 0, 0, 0, 0, // total_length = 512
];

/// Golden encoding of the entry below: 104 bytes, LE.
///
/// **Version 2 split the artifact's version from its security version.** `svn`
/// is the monotonic anti-rollback counter of `docs/security/02`; `image_version`
/// is what its producer calls the release. They answer different questions under
/// different authorities, and the entry below has them deliberately unequal so a
/// codec that confused them could not pass.
const ENTRY_GOLDEN: [u8; 104] = [
    0x68, 0, 0, 0, // size = 104
    0x02, 0, 0, 0, // version = 2
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0xf8, 0, 0, 0, 0, 0, 0, 0, // offset = 248
    0x10, 0, 0, 0, 0, 0, 0, 0, // length = 16
    // name = "firmware.bin", NUL-padded to 24
    0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x2e, 0x62, 0x69, 0x6e, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, //
    0x07, 0, 0, 0, // svn = 7
    0x03, 0, 0, 0, // image_version = 3
    0, 0, 0, 0, // reserved = 0
    // digest = 0x00, 0x01, ... 0x1f
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0, 0, 0, 0, // tail padding to the struct's 8-byte alignment
];

fn golden_header() -> StoreHeader {
    StoreHeader {
        size: 56,
        version: 2,
        flags: 0,
        magic: MAGIC,
        algorithm: DigestAlgorithm::Sha256,
        anchor_id: 1,
        entry_count: 2,
        reserved: 0,
        directory_offset: 56,
        total_length: 512,
    }
}

fn golden_entry() -> StoreEntry {
    let mut name = [0u8; 24];
    name[..12].copy_from_slice(b"firmware.bin");
    let mut digest = [0u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = i as u8;
    }
    StoreEntry {
        size: 104,
        version: 2,
        flags: 0,
        offset: 248,
        length: 16,
        name,
        svn: 7,
        image_version: 3,
        reserved: 0,
        digest,
    }
}

#[test]
fn header_matches_golden_and_round_trips() {
    assert_eq!(StoreHeader::WIRE_SIZE, 56);
    let mut bytes = [0u8; 56];
    let written = encode(&golden_header(), &mut bytes).expect("encode");
    assert_eq!(written, 56);
    assert_eq!(bytes, HEADER_GOLDEN);
    assert_eq!(
        decode::<StoreHeader>(&HEADER_GOLDEN).expect("decode"),
        golden_header()
    );
}

#[test]
fn entry_matches_golden_and_round_trips() {
    assert_eq!(StoreEntry::WIRE_SIZE, 104);
    let mut bytes = [0u8; 104];
    let written = encode(&golden_entry(), &mut bytes).expect("encode");
    assert_eq!(written, 104);
    assert_eq!(bytes, ENTRY_GOLDEN);
    assert_eq!(
        decode::<StoreEntry>(&ENTRY_GOLDEN).expect("decode"),
        golden_entry()
    );
}

/// A truncated container must not decode into a header with plausible fields —
/// the one input a reader is guaranteed to meet when a store is cut short, and
/// the one where a partial parse would be worst.
#[test]
fn short_input_is_refused() {
    for len in [0usize, 8, 55] {
        assert_eq!(
            decode::<StoreHeader>(&HEADER_GOLDEN[..len]),
            Err(WireError::ShortBuffer),
            "length {len}"
        );
    }
}

/// An algorithm nobody has defined is refused rather than mapped onto the one
/// that exists. `docs/security/02` ("Crypto Agility") requires a verifier to
/// accept a set of valid algorithms and reject the rest — which it cannot do if
/// an unknown identifier silently becomes a known one.
#[test]
fn unknown_algorithm_is_refused() {
    let mut bytes = HEADER_GOLDEN;
    bytes[24] = 0x02;
    assert_eq!(decode::<StoreHeader>(&bytes), Err(WireError::BadEnum));
}
