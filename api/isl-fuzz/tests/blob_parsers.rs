// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Fuzz targets for the two parsers in this tree that read **bytes somebody
//! else wrote** and were not generated from a schema.
//!
//! `docs/lifecycle/02` ("Tier 2") makes fuzz targets mandatory for *"parsers
//! and binary interfaces"*, not only for generated ones. These two are the
//! whole non-generated population, and both sit at a trust boundary:
//!
//! - **the device tree** is firmware's word about the machine, parsed before
//!   anything has been verified and used to decide where memory and devices
//!   are;
//! - **the image store** is the container the system reads data it has to trust
//!   through, and its header is *"the first thing read from a region that may
//!   hold anything at all"*;
//! - **the update channel** is a manifest offered by whoever is distributing
//!   drivers, and its structure is read *before* its signature has been
//!   believed — a length field trusted too early is exactly the mistake a
//!   signed format is supposed to make impossible.
//!
//! # The oracle here is weaker, and that is the argument for generating
//!
//! For a generated decoder the compiler supplies field offsets, legal domains
//! and a record that decodes, so the engine knows what most answers should be.
//! Here it knows none of that: the only expectations are that the parser
//! **returns rather than panics** for every input, and that its own valid
//! example still parses.
//!
//! In safe Rust that is less thin than it sounds. A slice index past the end, a
//! length subtraction that wraps, an arithmetic overflow, and a loop that never
//! terminates are all failures here — and all of them are exactly what a
//! truncated device tree or a corrupt container would otherwise do inside a
//! kernel, before there is anything to report a fault to.
//!
//! **The parse walks the whole structure**, not just the header. A parser that
//! validated a header and then handed out accessors that trust it would pass a
//! header-only harness and fail in use.

use tessera_isl_fuzz::{BlobTarget, run_blobs};

/// A minimal, valid flattened device tree: the 40-byte header, an empty memory
/// reservation block, a root node with one property, and the strings block.
///
/// Written out by hand rather than captured from a machine, so the seed is
/// readable and its validity is something this file states rather than
/// inherits.
fn minimal_dtb() -> Vec<u8> {
    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_END: u32 = 9;

    // Strings block: one NUL-terminated name at offset 0.
    let strings: Vec<u8> = b"#address-cells\0".to_vec();

    // Struct block: root node, one property, end.
    let mut structure = Vec::new();
    structure.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    structure.extend_from_slice(b"\0\0\0\0"); // the root's empty name, padded
    structure.extend_from_slice(&FDT_PROP.to_be_bytes());
    structure.extend_from_slice(&4u32.to_be_bytes()); // value length
    structure.extend_from_slice(&0u32.to_be_bytes()); // name offset
    structure.extend_from_slice(&2u32.to_be_bytes()); // the value
    structure.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    structure.extend_from_slice(&FDT_END.to_be_bytes());

    let header_len = 40usize;
    let rsvmap_len = 16usize; // one terminating all-zero entry
    let off_rsvmap = header_len;
    let off_struct = off_rsvmap + rsvmap_len;
    let off_strings = off_struct + structure.len();
    let total = off_strings + strings.len();

    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(&0xd00d_feedu32.to_be_bytes()); // magic
    blob.extend_from_slice(&(total as u32).to_be_bytes());
    blob.extend_from_slice(&(off_struct as u32).to_be_bytes());
    blob.extend_from_slice(&(off_strings as u32).to_be_bytes());
    blob.extend_from_slice(&(off_rsvmap as u32).to_be_bytes());
    blob.extend_from_slice(&17u32.to_be_bytes()); // version
    blob.extend_from_slice(&16u32.to_be_bytes()); // last compatible version
    blob.extend_from_slice(&0u32.to_be_bytes()); // boot cpuid
    blob.extend_from_slice(&(strings.len() as u32).to_be_bytes());
    blob.extend_from_slice(&(structure.len() as u32).to_be_bytes());
    blob.extend_from_slice(&[0u8; 16]); // the reservation terminator
    blob.extend_from_slice(&structure);
    blob.extend_from_slice(&strings);
    blob
}

/// Parses a blob and walks everything the parse produced.
fn parse_dtb(bytes: &[u8]) -> bool {
    // `total_size` reads the header alone, and is what boot calls before it has
    // any idea how much of the region is the blob.
    let _ = tessera_devicetree::total_size(bytes);

    let Ok(fdt) = tessera_devicetree::DeviceTree::parse(bytes) else {
        return false;
    };
    // Every accessor, because a parser that validated a header and then handed
    // out accessors that trusted it would pass a header-only harness.
    let blank_region = tessera_karch::MemoryRegion {
        base: tessera_karch::PhysAddr::new(0),
        len: 0,
        kind: tessera_karch::MemoryKind::Usable,
    };
    let mut regions = [blank_region; 8];
    let _ = fdt.reserved_regions(&mut regions);
    let _ = fdt.memory_regions(&mut regions);
    let blank_device = tessera_devicetree::MmioDevice {
        base: 0,
        size: 0,
        intid: None,
        trigger: None,
    };
    let mut mmio = [blank_device; 8];
    let _ = fdt.virtio_mmio_regions(&mut mmio);
    let _ = fdt.first_mmio_device(b"arm,pl061");
    let _ = fdt.pci_host();
    let _ = fdt.len();
    let _ = fdt.is_empty();
    true
}

/// A valid store container, built by the store's own builder.
fn minimal_store() -> Vec<u8> {
    let entries = [
        tessera_image_store::BuildEntry {
            name: "firmware.bin",
            svn: 1,
            image_version: 1,
            flags: 0,
            bytes: &[0xa5; 64],
        },
        tessera_image_store::BuildEntry {
            name: "second.bin",
            svn: 2,
            image_version: 3,
            flags: 0,
            bytes: &[0x5a; 32],
        },
    ];
    let mut buf = vec![0u8; 4096];
    let written =
        tessera_image_store::build_into(&mut buf, 1, &entries).expect("the builder's own entries");
    buf.truncate(written);
    buf
}

/// Mounts a container against the anchor **its own bytes** measure to, then
/// reads every blob.
///
/// Deliberately not the seed's anchor. A mutated container does not measure to
/// the original digest — that is the store's whole point and it needs no
/// fuzzing — so anchoring on the seed would have every input refused at the
/// hash and leave the directory walk, the name lookup and the per-blob
/// measurement untouched. Those are the parser. Measuring the input first puts
/// the anchor check out of the way so that what is under test is the code that
/// runs *after* somebody has been convinced.
fn parse_store(bytes: &[u8]) -> bool {
    let Ok(digest) = tessera_image_store::measure(bytes) else {
        return false;
    };
    let anchor = tessera_image_store::Anchor { id: 1, digest };
    let Ok(store) = tessera_image_store::Store::mount(bytes, &[anchor]) else {
        return false;
    };
    for name in ["firmware.bin", "second.bin", "absent.bin", ""] {
        if let Ok(blob) = store.open(name) {
            // Touch the bytes the store handed back, so a length it computed
            // wrongly is a fault here rather than in a caller.
            let _ = blob.bytes.iter().fold(0u8, |a, b| a ^ b);
        }
    }
    true
}

/// A well-formed channel manifest with two entries. Unsigned, because this tree
/// cannot sign — see [`parse_channel`] for why that does not weaken the target.
fn minimal_channel() -> Vec<u8> {
    let header = tessera_update_channel::HEADER_SIZE;
    let entry = tessera_update_channel::ENTRY_SIZE;
    let count = 2usize;
    let mut bytes = vec![0u8; header + count * entry + tessera_update_channel::SIGNATURE_SIZE];
    bytes[0..4].copy_from_slice(&tessera_update_channel::MAGIC.to_le_bytes());
    bytes[4..8].copy_from_slice(&tessera_update_channel::VERSION.to_le_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&7u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        let at = header + i * entry;
        bytes[at..at + 4].copy_from_slice(&((i as u32) + 1).to_le_bytes());
        bytes[at + 32..at + 64].copy_from_slice(&[0xa5; 32]);
    }
    bytes
}

/// Parses a manifest and walks whatever it produced.
///
/// **"Accepted" here means the structure parsed**, not that the manifest was
/// admitted. This tree cannot sign, so no seed can carry a signature that
/// verifies — and the signature check is the last step anyway. What is under
/// test is everything before it: the magic, the version, the count, and the
/// length arithmetic that turns a count into a range. Those run on bytes nobody
/// has authenticated yet, which is precisely why they are worth fuzzing.
fn parse_channel(bytes: &[u8]) -> bool {
    match tessera_update_channel::open(bytes, &[0u8; 32]) {
        Err(tessera_update_channel::Refusal::Malformed) => false,
        Err(_) => true,
        Ok(manifest) => {
            for entry in manifest.entries() {
                let _ = tessera_update_channel::admit(entry, 1);
            }
            true
        }
    }
}

#[test]
fn the_hand_written_parsers_survive_what_they_are_handed() {
    let dtb = minimal_dtb();
    let store = minimal_store();
    let channel = minimal_channel();
    let dtb: &'static [u8] = Box::leak(dtb.into_boxed_slice());
    let store: &'static [u8] = Box::leak(store.into_boxed_slice());
    let channel: &'static [u8] = Box::leak(channel.into_boxed_slice());

    let targets = [
        BlobTarget {
            name: "devicetree",
            seed: dtb,
            parse: parse_dtb,
        },
        BlobTarget {
            name: "image_store",
            seed: store,
            parse: parse_store,
        },
        BlobTarget {
            name: "update_channel",
            seed: channel,
            parse: parse_channel,
        },
    ];

    let (coverage, finding) = run_blobs(&targets, 4000, 0x151_f022_9eed);
    assert_eq!(finding, None, "{finding:?}");
    assert!(
        coverage.accepted > 0 && coverage.rejected > 0,
        "a run that only ever accepted, or only ever refused, exercised one \
         half of the parser: {coverage:?}",
    );
    // A tenth of the inputs getting past the header is the bar for saying the
    // parser behind it was fuzzed at all. Without it this test would pass on a
    // run that never reached anything a malformed container could reach.
    assert!(
        coverage.accepted * 10 > coverage.inputs,
        "too few inputs reached the parser behind the header: {coverage:?}",
    );
}
