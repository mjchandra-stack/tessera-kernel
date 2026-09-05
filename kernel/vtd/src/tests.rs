// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What a host can check about VT-d without a VT-d: the encodings.
//!
//! Every test here pins a field position against the specification rather than
//! against this crate's own arithmetic — a table entry that agrees with the
//! function that built it proves nothing.

use super::*;

#[test]
fn source_id_packs_bus_device_function() {
    let sid = SourceId::new(0, 4, 0);
    assert_eq!(sid.0, 0x0020);
    assert_eq!(sid.bus(), 0);
    assert_eq!(sid.context_index(), 0x20);

    // The three fields do not run into one another: a function number of 7 and
    // a device of 31 fill the low byte exactly.
    let sid = SourceId::new(0xff, 31, 7);
    assert_eq!(sid.0, 0xffff);
    assert_eq!(sid.bus(), 0xff);
    assert_eq!(sid.context_index(), 0xff);
}

#[test]
fn source_id_ignores_bits_that_are_not_the_field() {
    // A device number wider than five bits and a function wider than three are
    // masked rather than allowed to overwrite the bus.
    assert_eq!(SourceId::new(1, 0xff, 0xff).0, SourceId::new(1, 31, 7).0);
}

#[test]
fn root_entry_carries_present_and_pointer() {
    let entry = root_entry(0x1234_5000).expect("aligned");
    assert_eq!(entry[0], 0x1234_5001);
    assert_eq!(entry[1], 0);
    assert_eq!(root_entry(0x1234_5001), Err(Error::Misaligned));
}

#[test]
fn context_entry_places_width_and_domain() {
    let width = AddressWidth {
        aw: 2,
        levels: 4,
        bits: 48,
    };
    let entry = context_entry(0xaaaa_0000, width, 0x0102).expect("aligned");
    // Present, translation type 00 — so nothing above bit 0 in the low byte.
    assert_eq!(entry[0], 0xaaaa_0001);
    // AW in bits 2:0, domain id in bits 23:8.
    assert_eq!(entry[1] & 0x7, 2);
    assert_eq!((entry[1] >> 8) & 0xffff, 0x0102);
    assert_eq!(context_entry(0xaaaa_0800, width, 0), Err(Error::Misaligned));
}

#[test]
fn address_width_takes_the_widest_offered() {
    // SAGAW bit 2 alone: 48-bit, four levels.
    let cap = 0b100u64 << 8;
    assert_eq!(
        address_width(cap),
        Ok(AddressWidth {
            aw: 2,
            levels: 4,
            bits: 48
        })
    );
    // Both 39- and 48-bit: the wider one.
    let cap = 0b110u64 << 8;
    assert_eq!(address_width(cap).expect("supported").bits, 48);
    // 39-bit alone.
    let cap = 0b010u64 << 8;
    assert_eq!(address_width(cap).expect("supported").levels, 3);
    // A unit offering none of them is refused rather than programmed.
    assert_eq!(address_width(0), Err(Error::UnsupportedAddressWidth));
}

#[test]
fn second_level_entries_are_readable_and_writable() {
    assert_eq!(page_entry(0x9000).expect("aligned"), 0x9003);
    assert_eq!(table_entry(0x9000).expect("aligned"), 0x9003);
    assert_eq!(page_entry(0x9001), Err(Error::Misaligned));
}

#[test]
fn level_index_splits_nine_bits_at_a_time() {
    // One address with a distinct index at every level of a four-level walk.
    let address = (4u64 << 39) | (3 << 30) | (2 << 21) | (1 << 12);
    assert_eq!(level_index(address, 1), 1);
    assert_eq!(level_index(address, 2), 2);
    assert_eq!(level_index(address, 3), 3);
    assert_eq!(level_index(address, 4), 4);
}

#[test]
fn fault_recording_offset_is_in_sixteen_byte_units() {
    // FRO = 0x20 (bits 33:24), NFR = 0 (bits 47:40) — one record at 0x200.
    let cap = 0x20u64 << 24;
    assert_eq!(
        fault_recording(cap),
        FaultRecording {
            offset: 0x200,
            count: 1
        }
    );
    // NFR holds one less than the number of registers.
    let cap = (0x20u64 << 24) | (3u64 << 40);
    assert_eq!(fault_recording(cap).count, 4);
}

#[test]
fn iotlb_offset_skips_the_first_register() {
    // IRO = 0x10 (bits 17:8): the block is at 0x100 and the invalidate
    // register eight bytes into it.
    assert_eq!(iotlb_invalidate_offset(0x10u64 << 8), 0x108);
}

#[test]
fn fault_decode_reads_the_record_the_hardware_writes() {
    // A write refused at 0x4000 by the function at 00:04.0, reason 0x05.
    let low = 0x4000u64 | 0xfff;
    let high = (1u64 << 63) | (0x05u64 << 32) | u64::from(SourceId::new(0, 4, 0).0);
    let fault = decode_fault(low, high);
    assert!(fault.valid);
    assert_eq!(fault.source, SourceId::new(0, 4, 0));
    // The bottom twelve bits are not recorded and must not be reported.
    assert_eq!(fault.address, 0x4000);
    assert_eq!(fault.reason, FaultReason::NotPresentOrPermission);
    assert!(!fault.read);

    // Bit 62 set makes it a read.
    assert!(decode_fault(low, high | (1 << 62)).read);
    // An empty register is not a fault, whatever else it holds.
    assert!(!decode_fault(low, high & !(1 << 63)).valid);
}

#[test]
fn unknown_fault_reasons_keep_their_number() {
    let high = (1u64 << 63) | (0x7fu64 << 32);
    assert_eq!(decode_fault(0, high).reason, FaultReason::Other(0x7f));
    // And the ones this kernel names are not folded together.
    let root = (1u64 << 63) | (0x01u64 << 32);
    let context = (1u64 << 63) | (0x02u64 << 32);
    assert_eq!(decode_fault(0, root).reason, FaultReason::RootNotPresent);
    assert_eq!(
        decode_fault(0, context).reason,
        FaultReason::ContextNotPresent
    );
}

#[test]
fn passthrough_entry_names_its_translation_type() {
    let width = AddressWidth {
        aw: 2,
        levels: 4,
        bits: 48,
    };
    let entry = context_entry_passthrough(width, 7);
    // Present, and translation type 10 in bits 3:2.
    assert_eq!(entry[0] & 1, 1);
    assert_eq!((entry[0] >> 2) & 0b11, 0b10);
    // No table pointer: pass-through has nothing to point at, and a stale
    // pointer left in the field is a table the unit might yet be told to walk.
    assert_eq!(entry[0] & !0xf, 0);
    // The width is still programmed.
    assert_eq!(entry[1] & 0x7, 2);
    assert_eq!((entry[1] >> 8) & 0xffff, 7);

    // And the scoped form is the other translation type, so the two cannot be
    // confused for one another.
    let scoped = context_entry(0x1000, width, 7).expect("aligned");
    assert_eq!((scoped[0] >> 2) & 0b11, u64::from(TRANSLATION_SECOND_LEVEL));
}

#[test]
fn passthrough_support_is_read_from_ecap() {
    assert!(passthrough_supported(1 << 6));
    assert!(!passthrough_supported(!(1u64 << 6)));
}
