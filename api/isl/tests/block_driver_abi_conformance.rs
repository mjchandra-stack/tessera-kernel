// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated ring-3 block service protocol
//! bindings (built by the codegen genrule from `examples/block_driver.isl`,
//! never committed). Proves `BlockReadRequest`/`BlockReadReply` encode to
//! fixed golden layouts and decode back — the first user↔user protocol (the
//! kernel transports it opaquely), so its wire stability rests entirely here.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use block_driver_abi::{
    BlockBufferReply, BlockBufferRequest, BlockControlReply, BlockControlRequest,
    BlockDescribeReply, BlockDevice, BlockDeviceIncoming, BlockError, BlockPowerState,
    BlockReadReply, BlockReadRequest, BlockTracePoint, BlockWriteReply, BlockWriteRequest,
    BufferOwnership,
};
use tessera_isl_runtime::{HandleRef, Ownership, Reader, WireError, decode, encode};

/// Golden encoding of the `BlockReadRequest` value below: 24 bytes, LE.
const REQUEST_GOLDEN: [u8; 24] = [
    0x18, 0, 0, 0, // size = 24
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x2a, 0, 0, 0, 0, 0, 0, 0, // sector = 42
];

#[test]
fn block_read_request_matches_golden_and_round_trips() {
    assert_eq!(BlockReadRequest::WIRE_SIZE, 24);
    let value = BlockReadRequest {
        size: 24,
        version: 1,
        flags: 0,
        sector: 42,
    };
    let mut buf = [0u8; 24];
    assert_eq!(encode(&value, &mut buf).unwrap(), 24);
    assert_eq!(buf, REQUEST_GOLDEN);
    assert_eq!(decode::<BlockReadRequest>(&REQUEST_GOLDEN).unwrap(), value);
}

#[test]
fn block_read_reply_matches_golden_and_round_trips() {
    assert_eq!(BlockReadReply::WIRE_SIZE, 88);
    // A non-trivial data array: the disk magic then a counting pattern, so
    // the golden covers real bytes rather than agreeing with zeroes.
    let mut data = [0u8; 64];
    data[..8].copy_from_slice(b"TESSERAV");
    for (i, slot) in data[8..].iter_mut().enumerate() {
        *slot = i as u8;
    }
    let value = BlockReadReply {
        size: 88,
        version: 1,
        flags: 0,
        status: 0,
        reserved: 0,
        data,
    };
    let mut golden = [0u8; 88];
    golden[0..4].copy_from_slice(&88u32.to_le_bytes());
    golden[4..8].copy_from_slice(&1u32.to_le_bytes());
    // flags @8, status @16, reserved @20 all zero.
    golden[24..88].copy_from_slice(&data);

    let mut buf = [0u8; 88];
    assert_eq!(encode(&value, &mut buf).unwrap(), 88);
    assert_eq!(buf, golden);
    assert_eq!(decode::<BlockReadReply>(&golden).unwrap(), value);
}

#[test]
fn a_truncated_buffer_is_rejected() {
    assert_eq!(
        decode::<BlockReadRequest>(&REQUEST_GOLDEN[..16]),
        Err(WireError::ShortBuffer)
    );
}

// --- The class contract's other nine elements -------------------------------
//
// Everything above is the read path this file has always pinned. What follows
// pins the rest of the contract's ABI: the closed error set, the power states,
// the write path, and the reply that makes optionality discoverable. It is
// still the *wire* question — whether a driver **obeys** these rules is
// `//api/class-conformance`, and neither answer implies the other.

/// The error set is closed, and its values are what a client reads a status
/// by. Renumbering one would not fail to compile anywhere; it would silently
/// turn every recorded failure into a different failure.
#[test]
fn the_error_set_is_closed_and_stable() {
    assert_eq!(BlockError::Ok as u32, 0);
    assert_eq!(BlockError::OutOfRange as u32, 1);
    assert_eq!(BlockError::IoError as u32, 2);
    assert_eq!(BlockError::NoMedium as u32, 3);
    assert_eq!(BlockError::ReadOnly as u32, 4);
    assert_eq!(BlockError::NotSupported as u32, 5);
    assert_eq!(BlockError::Protocol as u32, 6);
    assert_eq!(BlockError::Degraded as u32, 7);
}

/// `NOT_SUPPORTED` is the one answer the contract permits for an
/// unimplemented optional method, so its value is load-bearing in a way the
/// others are not: a client tells "this driver cannot" from "this attempt
/// failed" by exactly this number.
#[test]
fn not_supported_is_distinct_from_every_other_failure() {
    for other in [
        BlockError::OutOfRange,
        BlockError::IoError,
        BlockError::NoMedium,
        BlockError::ReadOnly,
        BlockError::Protocol,
        BlockError::Degraded,
    ] {
        assert_ne!(BlockError::NotSupported as u32, other as u32);
    }
}

#[test]
fn the_power_states_are_stable() {
    assert_eq!(BlockPowerState::Active as u32, 1);
    assert_eq!(BlockPowerState::Idle as u32, 2);
    assert_eq!(BlockPowerState::Standby as u32, 3);
    assert_eq!(BlockPowerState::Off as u32, 4);
}

/// The ownership modes a class contract states per method. Named in the ABI
/// because "who owns this buffer and for how long" is the rule a message
/// definition cannot carry, and getting it wrong is a use-after-free across a
/// process boundary that no type system on either side can catch.
#[test]
fn the_buffer_ownership_modes_are_stable() {
    assert_eq!(BufferOwnership::CallerRetains as u32, 1);
    assert_eq!(BufferOwnership::Transferred as u32, 2);
    assert_eq!(BufferOwnership::SharedForCall as u32, 3);
}

/// The trace points a conformant driver emits, named so that
/// `docs/drivers/01`'s "trace event schema validation" has a schema to
/// validate against.
#[test]
fn the_trace_points_are_stable() {
    assert_eq!(BlockTracePoint::RequestAccepted as u32, 1);
    assert_eq!(BlockTracePoint::RequestSubmitted as u32, 2);
    assert_eq!(BlockTracePoint::RequestCompleted as u32, 3);
    assert_eq!(BlockTracePoint::ReplySent as u32, 4);
    assert_eq!(BlockTracePoint::DeviceReset as u32, 5);
    assert_eq!(BlockTracePoint::PowerChanged as u32, 6);
}

/// The write path's wire layout: the sector, then the payload.
#[test]
fn a_write_request_round_trips_with_its_payload() {
    assert_eq!(BlockWriteRequest::WIRE_SIZE, 88);
    let mut data = [0u8; 64];
    data[..8].copy_from_slice(b"TESSERAW");
    let value = BlockWriteRequest {
        size: 88,
        version: 1,
        flags: 0,
        sector: 2,
        data,
    };
    let mut buf = [0u8; 88];
    assert_eq!(encode(&value, &mut buf).unwrap(), 88);
    // size/version/flags, then the sector at 16, then the payload at 24.
    assert_eq!(buf[0], 88);
    assert_eq!(buf[16], 2);
    assert_eq!(&buf[24..32], b"TESSERAW");
    assert_eq!(decode::<BlockWriteRequest>(&buf).unwrap(), value);
}

/// `written` is carried, not derived. A short write is a real outcome — the
/// medium filled, the transfer truncated at a boundary — and a reply with only
/// a status forces a driver to report it as either success or an I/O error,
/// both of which are lies.
#[test]
fn a_write_reply_carries_both_an_outcome_and_a_count() {
    let value = BlockWriteReply {
        size: BlockWriteReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: BlockError::Ok as u32,
        written: 64,
    };
    let mut buf = [0u8; BlockWriteReply::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    let decoded: BlockWriteReply = decode(&buf).unwrap();
    assert_eq!(decoded.status, 0);
    assert_eq!(decoded.written, 64);
}

/// `Describe` is the method that makes the other nine elements usable:
/// optional methods, DMA rules, power states and the vendor namespace are all
/// facts about a *particular* driver, and a client with no way to ask them
/// would have to assume — which is the same as the contract not specifying
/// them.
#[test]
fn a_describe_reply_carries_every_fact_the_other_elements_need() {
    let value = BlockDescribeReply {
        size: BlockDescribeReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        contract_version: 1,
        status: BlockError::Ok,
        // WRITE | FLUSH, and deliberately not DISCARD.
        features: 0x1 | 0x2,
        sector_size: 512,
        reserved: 0,
        sector_count: 2048,
        dma_alignment: 4096,
        dma_max_transfer_sectors: 1,
        dma_scoped: 0,
        power_states: (1 << 1) | (1 << 2),
        resume_latency_us: 0,
        vendor: 0,
        vendor_namespace: 0,
        vendor_extension_version: 0,
        reserved2: 0,
    };
    let mut buf = [0u8; BlockDescribeReply::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    let decoded: BlockDescribeReply = decode(&buf).unwrap();
    assert_eq!(decoded, value);
    // Zero is the honest "declares no extension", distinguishable from a
    // driver that declared vendor 0.
    assert_eq!(decoded.vendor, 0);
    assert_eq!(decoded.features & 0x4, 0, "DISCARD is not advertised");
}

/// One control struct serves every method that carries no payload of its own.
/// Four distinguishable-only-by-name empty structs would be four ways to get
/// the same thing wrong.
#[test]
fn the_control_pair_round_trips() {
    let request = BlockControlRequest {
        size: BlockControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: BlockPowerState::Idle,
        reserved: 0,
    };
    let mut buf = [0u8; BlockControlRequest::WIRE_SIZE];
    encode(&request, &mut buf).unwrap();
    assert_eq!(decode::<BlockControlRequest>(&buf).unwrap(), request);
    // A state the schema does not name is refused rather than decoded into
    // whichever variant sits nearby.
    buf[16] = 9;
    assert!(decode::<BlockControlRequest>(&buf).is_err());

    let reply = BlockControlReply {
        size: BlockControlReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: BlockError::NotSupported as u32,
        state: BlockPowerState::Active,
    };
    let mut buf = [0u8; BlockControlReply::WIRE_SIZE];
    encode(&reply, &mut buf).unwrap();
    assert_eq!(decode::<BlockControlReply>(&buf).unwrap(), reply);
}

/// Golden encoding of the out-of-line request: 40 bytes, LE. The `buffer`
/// field is an **index** into the message's handle vector, which is why zero
/// appears where a reader might expect a handle number.
const BUFFER_REQUEST_GOLDEN: [u8; 40] = [
    0x28, 0, 0, 0, // size = 40
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x03, 0, 0, 0, 0, 0, 0, 0, // sector = 3
    0x00, 0x02, 0, 0, 0, 0, 0, 0, // length = 512
    0x00, 0, 0, 0, // buffer = handle index 0
    0, 0, 0, 0, // trailing padding to the struct's 8-byte alignment
];

#[test]
fn the_out_of_line_request_matches_its_golden_and_round_trips() {
    assert_eq!(BlockBufferRequest::WIRE_SIZE, 40);
    let value = BlockBufferRequest {
        size: 40,
        version: 1,
        flags: 0,
        sector: 3,
        length: 512,
        buffer: HandleRef::new(0),
    };
    let mut buf = [0u8; 40];
    assert_eq!(encode(&value, &mut buf).unwrap(), 40);
    assert_eq!(buf, BUFFER_REQUEST_GOLDEN);
    assert_eq!(
        decode::<BlockBufferRequest>(&BUFFER_REQUEST_GOLDEN).unwrap(),
        value
    );
}

/// **The declaration the schema made about `buffer`, as the generated code
/// carries it.** Both ring-3 programs build their transfer descriptor from
/// these, so the mask and the mode are one fact rather than two that happen to
/// agree — which is what they were when each program computed
/// `0x1 | 0x2 | 0x4 | 0x80` for itself.
#[test]
fn the_buffer_field_carries_the_rights_and_mode_it_declared() {
    assert_eq!(
        BlockBufferRequest::BUFFER_RIGHTS,
        0x1 | 0x2 | 0x4 | 0x80,
        "READ | WRITE | MAP | TRANSFER",
    );
    assert_eq!(
        BlockBufferRequest::BUFFER_OWNERSHIP,
        Ownership::Transfer,
        "the driver must be reading memory the client cannot change under it",
    );
}

/// A handle index past what the message carried is a **decode failure**. The
/// alternative is a driver resolving the index against a report that has
/// nothing at that position, and using whatever it finds.
#[test]
fn a_buffer_index_past_the_messages_handles_is_refused() {
    let mut bytes = BUFFER_REQUEST_GOLDEN;
    bytes[32] = 1; // index 1 …
    let mut r = Reader::in_message(&bytes, 1); // … of a one-handle message
    assert_eq!(
        BlockDeviceIncoming::decode(BlockDevice::READ_INTO, &mut r),
        Err(WireError::HandleIndexOutOfRange),
    );
}

/// The generated dispatch pairs each ordinal with the request type the
/// protocol declares — including `Discard`, which both ring-3 programs used to
/// pair with a control request instead. They agreed with each other and with
/// nothing else, which is precisely what a generated dispatch removes.
#[test]
fn the_out_of_line_ordinals_dispatch_to_their_declared_types() {
    let mut r = Reader::in_message(&BUFFER_REQUEST_GOLDEN, 1);
    assert!(matches!(
        BlockDeviceIncoming::decode(BlockDevice::READ_INTO, &mut r),
        Ok(BlockDeviceIncoming::ReadInto(_)),
    ));
    let mut r = Reader::in_message(&BUFFER_REQUEST_GOLDEN, 1);
    assert!(matches!(
        BlockDeviceIncoming::decode(BlockDevice::WRITE_FROM, &mut r),
        Ok(BlockDeviceIncoming::WriteFrom(_)),
    ));
    // Discard's request is a write request, not a control request.
    let mut write = [0u8; BlockWriteRequest::WIRE_SIZE];
    encode(
        &BlockWriteRequest {
            size: BlockWriteRequest::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            sector: 2,
            data: [0; 64],
        },
        &mut write,
    )
    .unwrap();
    let mut r = Reader::new(&write);
    assert!(matches!(
        BlockDeviceIncoming::decode(BlockDevice::DISCARD, &mut r),
        Ok(BlockDeviceIncoming::Discard(_)),
    ));
}

/// The out-of-line reply carries an outcome and a count, and no data — the
/// data is in the object that comes back attached to it.
#[test]
fn the_out_of_line_reply_round_trips() {
    let value = BlockBufferReply {
        size: BlockBufferReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: BlockError::Ok as u32,
        reserved: 0,
        transferred: 512,
    };
    let mut buf = [0u8; BlockBufferReply::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    assert_eq!(decode::<BlockBufferReply>(&buf).unwrap(), value);
}
