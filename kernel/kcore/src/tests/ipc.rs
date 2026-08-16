// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::ipc`.

use super::*;

fn msg(method: u32, body: &[u8]) -> Message {
    let mut m = Message::new(MessageHeader::new(0xabcd, method));
    m.set_inline(body).unwrap();
    m
}

#[test]
fn queue_is_fifo_and_bounded() {
    let mut ep = Endpoint::new();
    for i in 0..QUEUE_CAP {
        assert!(ep.enqueue(msg(i as u32, &[i as u8])).is_ok());
    }
    // Full.
    assert_eq!(ep.enqueue(msg(99, &[])), Err(KError::WouldBlock));
    // FIFO order out.
    for i in 0..QUEUE_CAP {
        let m = ep.dequeue().unwrap();
        assert_eq!(m.header().method_id, i as u32);
        assert_eq!(m.inline(), &[i as u8]);
    }
    assert!(ep.dequeue().is_none());
}

#[test]
fn message_header_round_trips_through_the_generated_binding() {
    use tessera_isl_runtime::{decode, encode};

    // A header with non-trivial values in every semantic field.
    let header = MessageHeader {
        interface_id: 0x1122_3344_5566_7788,
        method_id: 0x9abc_def0,
        flags: 0x0000_0005,
        txn_id: 0x00fe_dcba_9876_5432,
        correlation: 0x0123_4567_89ab_cdef,
    };

    // In-kernel -> wire -> bytes -> wire -> in-kernel, through the ISL binding.
    let wire = header.to_wire();
    let mut buf = [0u8; WireMessageHeader::WIRE_SIZE];
    let n = encode(&wire, &mut buf).expect("encode");
    assert_eq!(n, WireMessageHeader::WIRE_SIZE);
    let decoded: WireMessageHeader = decode(&buf).expect("decode");
    let back = MessageHeader::from_wire(&decoded).expect("in-range flags");

    // The semantic fields survive the full round trip — the in-kernel header is
    // a faithful subset of the ISL wire form (schema = source of truth). This
    // is what closes "shaped to by convention" for the message header.
    assert_eq!(back, header);
    // And the envelope carries exactly what the schema mandates.
    assert_eq!(wire.size, WireMessageHeader::WIRE_SIZE as u32);
    assert_eq!(wire.version, MESSAGE_HEADER_WIRE_VERSION);
    // The causal id crosses as 128 bits: the sequence from the header, the
    // epoch supplied by the trace facility (D60).
    assert_eq!(wire.correlation_lo, header.correlation);
    assert_eq!(wire.correlation_hi, crate::trace::epoch());
}

#[test]
fn a_stamped_correlation_rides_the_header() {
    let mut m = Message::new(MessageHeader::new(0x1, 1));
    // Unstamped means "no cause recorded", never a forged one.
    assert_eq!(m.header().correlation, 0);
    m.set_correlation(0xfeed);
    assert_eq!(m.header().correlation, 0xfeed);
    // And it survives the wire, which is the point of carrying it here.
    assert_eq!(m.header().to_wire().correlation_lo, 0xfeed);
}

#[test]
fn oversize_payload_and_handle_set_are_rejected() {
    let mut m = Message::new(MessageHeader::new(1, 1));
    assert_eq!(
        m.set_inline(&[0u8; MAX_INLINE_BYTES + 1]),
        Err(KError::Protocol)
    );
    assert!(m.set_inline(&[0u8; MAX_INLINE_BYTES]).is_ok());

    let h = TransferredHandle {
        object: ObjectId::from_raw(1),
        rights: Rights::READ,
    };
    for _ in 0..MAX_MSG_HANDLES {
        assert!(m.add_handle(h).is_ok());
    }
    assert_eq!(m.add_handle(h), Err(KError::Protocol));
    assert_eq!(m.handle_count(), MAX_MSG_HANDLES);
}

#[test]
fn create_channel_and_peer_sides() {
    let mut table = ChannelTable::new();
    let (a, b) = table.create().unwrap();
    assert_eq!(a.channel, b.channel);
    assert_eq!(a.side, 0);
    assert_eq!(b.side, 1);
    assert_eq!(Channel::peer(a.side), b.side);
}

#[test]
fn close_raises_peer_closed_on_the_other_end() {
    let mut ch = Channel::new();
    ch.close_side(0);
    assert!(ch.endpoint(1).peer_closed());
    assert!(!ch.endpoint(0).peer_closed());
}

#[test]
fn endpoint_object_binds_and_resolves_both_sides() {
    let mut table = ChannelTable::new();
    let (a, b) = table.create().unwrap();
    let oa = ObjectId::from_raw(0x11);
    let ob = ObjectId::from_raw(0x22);
    table.set_endpoint_object(a, oa);
    table.set_endpoint_object(b, ob);
    assert_eq!(table.endpoint_of_object(oa), Some(a));
    assert_eq!(table.endpoint_of_object(ob), Some(b));
}

#[test]
fn endpoint_of_unknown_object_is_none() {
    let mut table = ChannelTable::new();
    let (a, _b) = table.create().unwrap();
    table.set_endpoint_object(a, ObjectId::from_raw(0x11));
    assert_eq!(table.endpoint_of_object(ObjectId::from_raw(0x99)), None);
}

#[test]
fn freeing_a_channel_slot_clears_the_association() {
    let mut table = ChannelTable::new();
    let (a, _b) = table.create().unwrap();
    let oa = ObjectId::from_raw(0x11);
    table.set_endpoint_object(a, oa);
    assert_eq!(table.endpoint_of_object(oa), Some(a));
    // Freeing the slot (as channel teardown would) drops the binding with it.
    table.channels[a.channel] = None;
    assert_eq!(table.endpoint_of_object(oa), None);
}
