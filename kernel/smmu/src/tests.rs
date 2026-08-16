// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Host tests for the encodings the SMMU reads out of memory. These are the
//! parts a running machine cannot help with: a stream-table entry with a
//! field in the wrong place produces a device that looks configured and
//! translates wrongly, and the hardware's only comment is a fault.

use super::*;

#[test]
fn an_abort_entry_is_not_valid() {
    let ste = stream_table_entry_abort();
    assert_eq!(ste[0] & 1, 0, "the valid bit is what makes it abort");
    assert_eq!(ste, [0; 8]);
}

#[test]
fn a_stage2_entry_carries_its_config_table_and_control() {
    let ste = stream_table_entry_s2(0x4321_0000, 7, 34, 1);
    assert_eq!(ste[0] & 1, 1, "valid");
    assert_eq!((ste[0] >> 1) & 0b111, ste_config::S2_TRANSLATE);
    assert_eq!(ste[3], 0x4321_0000, "the table root, low bits cleared");
    assert_eq!(ste[2] & 0xffff, 7, "VMID");
    assert_eq!((ste[2] >> 32) & 0x3f, 34, "T0SZ");
    assert_eq!((ste[2] >> 38) & 0b11, 1, "SL0");
    assert_eq!((ste[2] >> 46) & 0b11, 0, "TG = 4 KiB");
    assert_eq!((ste[2] >> 51) & 1, 1, "AA64");
    assert_eq!(
        (ste[2] >> 58) & 1,
        1,
        "S2R: faults are recorded, or a refusal cannot be observed"
    );
}

/// The root address is an address, not a bag of bits: anything below the page
/// boundary belongs to other fields and must not survive.
#[test]
fn a_misaligned_table_root_does_not_bleed_into_other_fields() {
    let ste = stream_table_entry_s2(0x4321_0fff, 0, 32, 1);
    assert_eq!(ste[3], 0x4321_0000);
}

#[test]
fn commands_carry_their_opcode_and_operand() {
    assert_eq!(cmd_cfgi_ste(0x10)[0] & 0xff, cmd::CFGI_STE);
    assert_eq!(cmd_cfgi_ste(0x10)[0] >> 32, 0x10, "StreamID");
    assert_eq!(
        cmd_cfgi_ste(0x10)[1] & 1,
        1,
        "Leaf: a linear table has no branch"
    );
    assert_eq!(cmd_sync()[0] & 0xff, cmd::SYNC);
    assert_eq!(cmd_tlbi_nsnh_all()[0] & 0xff, cmd::TLBI_NSNH_ALL);
}

/// The wrap bit is what distinguishes a full queue from an empty one — both
/// have equal index fields — and forgetting it is how a ring buffer silently
/// drops or replays entries.
#[test]
fn a_queue_index_wraps_into_its_wrap_bit() {
    // Four entries: two index bits plus one wrap bit.
    let mut at = QueueIndex::new(2, 0);
    assert_eq!((at.index(), at.wrap()), (0, 0));
    for expected in 1..4 {
        at = at.next();
        assert_eq!((at.index(), at.wrap()), (expected, 0));
    }
    at = at.next();
    assert_eq!((at.index(), at.wrap()), (0, 1), "wrapped");
    for expected in 1..4 {
        at = at.next();
        assert_eq!((at.index(), at.wrap()), (expected, 1));
    }
    at = at.next();
    assert_eq!((at.index(), at.wrap()), (0, 0), "wrapped back");
}

#[test]
fn a_full_queue_is_told_apart_from_an_empty_one() {
    let cons = QueueIndex::new(2, 0);
    // Empty: producer and consumer identical.
    assert!(cons.is_empty(cons));
    assert!(!cons.would_overrun(cons));

    // Three entries queued: index 3, same wrap. One more would wrap onto the
    // consumer's index with a different wrap — that is full.
    let prod = QueueIndex::new(2, 3);
    assert!(!prod.is_empty(cons));
    assert!(prod.would_overrun(cons));
}

#[test]
fn an_event_record_yields_its_kind_stream_and_address() {
    let event = decode_event([
        u64::from(event::F_TRANSLATION) | (0x10u64 << 32),
        0,
        0,
        0x8000_2000,
    ]);
    assert_eq!(event.kind, event::F_TRANSLATION);
    assert_eq!(event.stream, 0x10);
    assert_eq!(event.address, 0x8000_2000);
}

/// The three refusals a bring-up has to tell apart: nothing configured, a
/// malformed entry, and an address outside the aperture. They are the same
/// silence from the data's point of view.
#[test]
fn the_refusal_kinds_are_distinct() {
    let kinds = [
        event::C_BAD_STREAMID,
        event::C_BAD_STE,
        event::F_TRANSLATION,
        event::F_PERMISSION,
    ];
    for (i, a) in kinds.iter().enumerate() {
        for b in &kinds[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

/// Stage 2 puts the device's permissions at bits 7:6 and the memory
/// attributes directly at 5:2. Stage 1 uses those positions for `AP` and an
/// index into `MAIR`, so encoding one with the other's rules yields a
/// descriptor that looks plausible and translates wrongly.
#[test]
fn a_stage2_page_descriptor_is_readable_and_writable_by_the_device() {
    let d = stage2_page_descriptor(0x4711_2000);
    assert_eq!(d & 0b11, 0b11, "valid page descriptor");
    assert_eq!(d & !0xfff, 0x4711_2000, "the frame");
    assert_eq!((d >> 6) & 0b11, 0b11, "S2AP: device may read and write");
    assert_eq!((d >> 2) & 0b1111, 0b1111, "MemAttr, not a MAIR index");
    assert_eq!((d >> 10) & 1, 1, "access flag set, or every access faults");
}

#[test]
fn a_table_descriptor_points_at_the_next_level() {
    assert_eq!(stage2_table_descriptor(0x4711_3fff), 0x4711_3003);
}

/// A level index selects nine bits, and the shift depends on the level — get
/// it wrong and a walk indexes the right table with the wrong entry.
#[test]
fn level_indices_select_their_own_nine_bits() {
    let address = (1u64 << 30) | (2 << 21) | (3 << 12);
    assert_eq!(level_index(address, 1), 1);
    assert_eq!(level_index(address, 2), 2);
    assert_eq!(level_index(address, 3), 3);
}

/// `T0SZ` and the start level must agree: the level is determined by how much
/// address space `T0SZ` leaves, and an entry whose `SL0` disagrees faults on
/// every address with nothing in the table to explain it.
#[test]
fn t0sz_and_start_level_agree() {
    // A 30-bit input address has its top bit at 29, which is inside level 2's
    // slice (29:21) — so the walk starts at level 2 and its root table has
    // 2^(30-21) = 512 entries, exactly one frame.
    let (t0sz, level) = t0sz_and_start_level(30).expect("30-bit aperture");
    assert_eq!(t0sz, 34);
    assert_eq!(level, 2);
    assert_eq!(start_level_to_sl0(level), 0);

    // 31 bits reaches into level 1's slice (38:30).
    let (_, level) = t0sz_and_start_level(31).expect("31-bit aperture");
    assert_eq!(level, 1);
    assert_eq!(start_level_to_sl0(level), 1);

    // 21 bits fits entirely in level 3's slice (20:12).
    let (t0sz, level) = t0sz_and_start_level(21).expect("21-bit aperture");
    assert_eq!(t0sz, 43);
    assert_eq!(level, 3);
    assert_eq!(start_level_to_sl0(level), 3);

    // An address space this crate cannot express is an error, not a guess.
    assert_eq!(t0sz_and_start_level(48), Err(Error::ApertureTooSmall));
    assert_eq!(t0sz_and_start_level(12), Err(Error::ApertureTooSmall));
}

/// Every fault code this crate distinguishes maps to its own class, and the
/// two that look alike from outside — an address with no translation, and a
/// stream with no configuration — stay apart.
///
/// That separation is the point of classifying at all. Both produce "the DMA
/// did not arrive"; only one of them is the aperture working.
#[test]
fn fault_codes_classify_to_distinct_meanings() {
    let at = |kind| {
        Event {
            kind,
            stream: 3,
            address: 0x2000,
        }
        .class()
    };
    assert_eq!(at(event::F_TRANSLATION), FaultClass::Unmapped);
    assert_eq!(at(event::F_PERMISSION), FaultClass::Permission);
    assert_eq!(at(event::C_BAD_STREAMID), FaultClass::UnknownStream);
    assert_eq!(at(event::C_BAD_STE), FaultClass::BadConfiguration);
    // A record type nobody anticipated is still reported — silence here would
    // lose the one signal saying the unit is unhappy in an unexpected way.
    assert_eq!(at(0x7f), FaultClass::Other);
}

/// The event-queue interrupt has to be asked for. Without this bit the queue
/// still fills and nothing says so, which is a fault harvest that works only
/// when someone happens to look.
#[test]
fn the_event_queue_interrupt_is_its_own_bit() {
    assert_eq!(irq_ctrl::EVENTQ, 1 << 2);
    // And it is distinct from the two this kernel does not consume, so
    // enabling it cannot enable them by accident.
    assert_eq!(irq_ctrl::EVENTQ & (irq_ctrl::PRIQ | irq_ctrl::GERROR), 0);
}
