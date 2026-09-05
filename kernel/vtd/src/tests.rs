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

#[test]
fn interrupt_capabilities_are_read_from_ecap() {
    assert!(queued_invalidation_supported(1 << 1));
    assert!(!queued_invalidation_supported(!(1u64 << 1)));
    assert!(interrupt_remapping_supported(1 << 3));
    assert!(!interrupt_remapping_supported(!(1u64 << 3)));
    assert!(extended_interrupt_mode_supported(1 << 4));
    assert!(!extended_interrupt_mode_supported(!(1u64 << 4)));
}

#[test]
fn interrupt_table_address_encodes_size_as_a_power_of_two() {
    // Bits 3:0 hold log2(entries) - 1, so 256 entries is 7 and 65536 is 15.
    let irta = interrupt_table_address(0x9000, 256, false).expect("aligned");
    assert_eq!(irta & 0xf, 7);
    assert_eq!(irta & !0xfff, 0x9000);
    assert_eq!(irta & (1 << 11), 0);
    assert_eq!(
        interrupt_table_address(0x9000, 1 << 16, true).expect("aligned") & 0xf,
        15
    );
    // The extended mode is a bit of its own, not folded into the size.
    assert_eq!(
        interrupt_table_address(0x9000, 256, true).expect("aligned") & (1 << 11),
        1 << 11
    );
    // And a size the field cannot express is refused rather than truncated.
    assert_eq!(
        interrupt_table_address(0x9000, 300, false),
        Err(Error::OutOfRange)
    );
    assert_eq!(
        interrupt_table_address(0x9001, 256, false),
        Err(Error::Misaligned)
    );
}

#[test]
fn interrupt_entry_names_a_vector_a_cpu_and_a_source() {
    let entry = interrupt_entry(52, 3, true, SourceId::new(0, 4, 0));
    assert_eq!(entry[0] & 1, 1, "present");
    assert_eq!((entry[0] >> 16) & 0xff, 52, "vector at 23:16");
    assert_eq!(
        entry[0] >> 32,
        3,
        "the whole destination under extended mode"
    );
    // Fixed delivery, edge triggered, physical destination: bits 7:2 clear.
    assert_eq!((entry[0] >> 2) & 0x3f, 0);
    // The reserved field at 15:12 and the entry-mode bit at 15 stay clear, or
    // the unit refuses the entry rather than the interrupt.
    assert_eq!((entry[0] >> 8) & 0xff, 0);
    assert_eq!(entry[1] & 0xffff, 0x0020, "source id");
    assert_eq!((entry[1] >> 16) & 0x3, 0, "compare all sixteen bits");
    assert_eq!((entry[1] >> 18) & 0x3, 1, "verify against the source id");
}

#[test]
fn the_destination_moves_when_the_extended_mode_is_not_available() {
    // Without it the identifier is eight bits at 47:40 of the entry, which is
    // 15:8 of the destination field — a shift that is *not* the identity, and
    // the reason it is asked rather than assumed.
    let old = interrupt_entry(52, 3, false, SourceId(0));
    assert_eq!(old[0] >> 32, 3 << 8);
    let new = interrupt_entry(52, 3, true, SourceId(0));
    assert_ne!(old[0], new[0]);
    // An identifier past eight bits cannot be named at all in the old mode, and
    // is masked rather than allowed to run into the reserved field above it.
    assert_eq!(
        interrupt_entry(52, 0x1ff, false, SourceId(0))[0] >> 32,
        0xff00
    );
}

#[test]
fn an_unverified_entry_asks_for_no_verification() {
    let entry = interrupt_entry_unverified(52, 1, true);
    assert_eq!(entry[0], interrupt_entry(52, 1, true, SourceId(0))[0]);
    assert_eq!(entry[1], 0, "source validation type 00");
    assert_eq!(INTERRUPT_ENTRY_ABSENT, [0, 0]);
}

#[test]
fn a_remappable_message_carries_a_handle_and_no_vector() {
    let (address, data) = remappable_message(0);
    assert_eq!(address, 0xfee0_0010, "the format bit and nothing else");
    assert_eq!(data, 0, "no sub-handle, so the handle is the index alone");

    // The low fifteen bits sit at 19:5 and the sixteenth at bit 2, so a handle
    // that crosses that boundary is the test worth having.
    let (address, _) = remappable_message(0x8001);
    assert_eq!((address >> 5) & 0x7fff, 1);
    assert_eq!((address >> 2) & 1, 1);
    assert_eq!(address & REMAPPABLE_FORMAT, REMAPPABLE_FORMAT);
    // **The neighbouring bit, pinned in the direction that bites.** With the
    // two transposed the message is a well-formed *compatibility* request that
    // a remapping unit passes through untouched — no fault, no error, and no
    // interrupt — so this asserts which of the two is which rather than merely
    // that one of them is set.
    assert_eq!(REMAPPABLE_FORMAT, 1 << 4);
    assert_eq!(SUBHANDLE_VALID, 1 << 3);
    assert_eq!(address & SUBHANDLE_VALID, 0, "sub-handle not valid");

    // And it is distinguishable from the old format at the one bit that says
    // so: a device writing the old message is not writing this one.
    assert_eq!(0xfee0_0000u64 & REMAPPABLE_FORMAT, 0);
}

#[test]
fn invalidation_descriptors_name_their_type_and_a_global_granularity() {
    assert_eq!(context_invalidate_descriptor()[0] & 0xf, 0x1);
    assert_eq!((context_invalidate_descriptor()[0] >> 4) & 0x3, 1);
    assert_eq!(iotlb_invalidate_descriptor()[0] & 0xf, 0x2);
    assert_eq!((iotlb_invalidate_descriptor()[0] >> 4) & 0x3, 1);
    assert_eq!(interrupt_entry_invalidate_descriptor()[0] & 0xf, 0x4);
    // Global for the interrupt cache is the granularity bit *clear*, which is
    // the opposite convention of the two above it.
    assert_eq!((interrupt_entry_invalidate_descriptor()[0] >> 4) & 1, 0);
}

#[test]
fn a_wait_descriptor_asks_for_a_status_write() {
    let wait = invalidate_wait_descriptor(0x3_0000, 0xa5).expect("aligned");
    assert_eq!(wait[0] & 0xf, 0x5);
    assert_eq!(wait[0] & (1 << 5), 1 << 5, "status write");
    assert_eq!(wait[0] >> 32, 0xa5);
    assert_eq!(wait[1], 0x3_0000);
    assert_eq!(
        invalidate_wait_descriptor(0x3_0001, 0),
        Err(Error::Misaligned)
    );
    assert_eq!(queue_address(0x2000), Ok(0x2000));
    assert_eq!(queue_address(0x2001), Err(Error::Misaligned));
    assert_eq!(QUEUE_DESCRIPTORS, 256);
}

#[test]
fn interrupt_faults_decode_to_reasons_of_their_own() {
    // The four the specification names for interrupt remapping, and the handle
    // recorded in place of an address.
    for (code, reason) in [
        (0x21u8, FaultReason::InterruptIndexOutOfRange),
        (0x22, FaultReason::InterruptEntryNotPresent),
        (0x25, FaultReason::InterruptCompatibilityBlocked),
        (0x26, FaultReason::InterruptSourceMismatch),
    ] {
        let fault = decode_fault(
            0x0041_0000_0000_0000,
            (1 << 63) | (u64::from(code) << 32) | 0x0020,
        );
        assert_eq!(fault.reason, reason);
        assert!(fault.is_interrupt());
        assert_eq!(fault.interrupt_handle(), 0x41);
        assert_eq!(fault.source, SourceId(0x0020));
    }

    // A translation fault is not one of them, and does not answer as if the top
    // of its address were a handle anybody should read.
    let translation = decode_fault(0x1_1000, (1 << 63) | (0x06 << 32));
    assert!(!translation.is_interrupt());
    assert_eq!(translation.reason, FaultReason::NotPresentOrPermission);
}
