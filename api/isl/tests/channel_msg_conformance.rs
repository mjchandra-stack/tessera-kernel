// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated channel message ABI bindings (built
//! by the codegen genrule from `examples/channel_msg.isl`, never committed).
//! Proves the `MessageHeader` encodes to a fixed golden layout, decodes back,
//! and rejects non-canonical padding — the IPC message boundary is
//! ISL-expressible and wire-stable.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format"),
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels")

use channel_msg::{
    ChannelCreateArgs, ChannelMsgArgs, HandleTransfer, MessageHeader, Rights, TransferMode,
};
use tessera_isl_runtime::{WireError, decode, encode};

/// Golden encoding of the `MessageHeader` value below: little-endian, 8-byte
/// aligned, zero-padded, 56 bytes. Bytes 36..40 are *interior* canonical padding
/// after `method_id` (the 128-bit correlation id follows at 40/48), so the struct
/// has no trailing padding. The id halves are deliberately non-zero here, so the
/// golden actually covers them rather than agreeing with an unset field.
const HEADER_GOLDEN: [u8; 56] = [
    0x38, 0, 0, 0, // size = 56
    0x02, 0, 0, 0, // version = 2 (gained the correlation id, D60)
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x01, 0x00, 0x00, 0x00, 0xa0, 0xe2, 0x55, 0x7e, // interface_id = 0x7e55_e2a0_0000_0001
    0x2a, 0, 0, 0, 0, 0, 0, 0, // txn_id = 42
    0x01, 0, 0, 0, // method_id = 1 (PING)
    0, 0, 0, 0, // interior padding to the 8-byte boundary
    0x07, 0, 0, 0, 0, 0, 0, 0, // correlation_lo = 7 (origin-minted sequence)
    0x99, 0, 0, 0, 0, 0, 0, 0, // correlation_hi = 0x99 (per-boot epoch)
];

#[test]
fn message_header_matches_golden_and_round_trips() {
    assert_eq!(MessageHeader::WIRE_SIZE, 56);
    let value = MessageHeader {
        size: 56,
        version: 2,
        flags: 0,
        interface_id: 0x7e55_e2a0_0000_0001,
        txn_id: 42,
        method_id: 1,
        correlation_lo: 7,
        correlation_hi: 0x99,
    };
    let mut buf = [0u8; 56];
    let n = encode(&value, &mut buf).unwrap();
    assert_eq!(n, 56);
    assert_eq!(buf, HEADER_GOLDEN);

    let decoded: MessageHeader = decode(&HEADER_GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn non_canonical_padding_is_rejected() {
    let mut bytes = HEADER_GOLDEN;
    bytes[36] = 1; // an interior padding byte, between method_id and the id
    assert_eq!(
        decode::<MessageHeader>(&bytes),
        Err(WireError::NonCanonicalPadding)
    );
}

/// Golden encoding of the `ChannelCreateArgs` value below: 32 bytes, LE. Both
/// endpoints carry READ|WRITE|TRANSFER (0x83) — the channel-IPC rights set.
const CREATE_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x83, 0, 0, 0, 0, 0, 0, 0, // end0_rights = READ|WRITE|TRANSFER
    0x83, 0, 0, 0, 0, 0, 0, 0, // end1_rights = READ|WRITE|TRANSFER
];

#[test]
fn channel_create_args_matches_golden_and_round_trips() {
    assert_eq!(ChannelCreateArgs::WIRE_SIZE, 32);
    let rights = Rights(Rights::READ.bits() | Rights::WRITE.bits() | Rights::TRANSFER.bits());
    let value = ChannelCreateArgs {
        size: 32,
        version: 1,
        flags: 0,
        end0_rights: rights,
        end1_rights: rights,
    };
    let mut buf = [0u8; 32];
    assert_eq!(encode(&value, &mut buf).unwrap(), 32);
    assert_eq!(buf, CREATE_GOLDEN);
    assert_eq!(decode::<ChannelCreateArgs>(&CREATE_GOLDEN).unwrap(), value);
}

/// Golden encoding of the `ChannelMsgArgs` value below: 72 bytes, LE, no
/// trailing padding (the `method_id`/`msg_flags` u32 pair fills its 8-byte
/// slot). Pins the field offsets the kernel's hand-written
/// `decode_channel_msg_args` reads (16/24/32/36/40/48/56/64/72/80).
const MSG_GOLDEN: [u8; 88] = [
    0x58, 0, 0, 0, // size = 88
    0x02, 0, 0, 0, // version = 2 (added the installed-handle report)
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x01, 0x00, 0x00, 0x00, 0xa0, 0xe2, 0x55, 0x7e, // interface_id = 0x7e55_e2a0_0000_0001
    0, 0, 0, 0, 0, 0, 0, 0, // txn_id = 0 (kernel stamps on call)
    0x01, 0, 0, 0, // method_id = 1 (PING)
    0, 0, 0, 0, // msg_flags = 0
    0x00, 0x00, 0x40, 0x00, 0, 0, 0, 0, // inline_ptr = 0x0040_0000
    0x04, 0, 0, 0, 0, 0, 0, 0, // inline_len = 4
    0x00, 0x00, 0x68, 0x00, 0, 0, 0, 0, // handles_ptr = 0x0068_0000
    0x01, 0, 0, 0, 0, 0, 0, 0, // handle_count = 1
    0x00, 0x00, 0x70, 0x00, 0, 0, 0, 0, // installed_ptr = 0x0070_0000
    0x02, 0, 0, 0, 0, 0, 0, 0, // installed_cap = 2
];

#[test]
fn channel_msg_args_matches_golden_and_round_trips() {
    assert_eq!(ChannelMsgArgs::WIRE_SIZE, 88);
    let value = ChannelMsgArgs {
        size: 88,
        version: 2,
        flags: 0,
        interface_id: 0x7e55_e2a0_0000_0001,
        txn_id: 0,
        method_id: 1,
        msg_flags: 0,
        inline_ptr: 0x0040_0000,
        inline_len: 4,
        handles_ptr: 0x0068_0000,
        handle_count: 1,
        installed_ptr: 0x0070_0000,
        installed_cap: 2,
    };
    let mut buf = [0u8; 88];
    assert_eq!(encode(&value, &mut buf).unwrap(), 88);
    assert_eq!(buf, MSG_GOLDEN);
    assert_eq!(decode::<ChannelMsgArgs>(&MSG_GOLDEN).unwrap(), value);
}

/// Golden encoding of one `HandleTransfer`: 16 bytes, LE. Pins the offsets the
/// kernel's `decode_handle_transfer` reads (0/4/8), which are what tell a
/// handle number apart from a mode and a rights mask.
const TRANSFER_GOLDEN: [u8; 16] = [
    0x07, 0, 0, 0, // handle = 7
    0x00, 0, 0, 0, // mode = TRANSFER
    0x85, 0, 0, 0, 0, 0, 0, 0, // rights = READ|MAP|TRANSFER
];

#[test]
fn handle_transfer_matches_golden_and_round_trips() {
    assert_eq!(HandleTransfer::WIRE_SIZE, 16);
    let value = HandleTransfer {
        handle: 7,
        mode: TransferMode::Transfer,
        rights: 0x85,
    };
    let mut buf = [0u8; 16];
    assert_eq!(encode(&value, &mut buf).unwrap(), 16);
    assert_eq!(buf, TRANSFER_GOLDEN);
    assert_eq!(decode::<HandleTransfer>(&TRANSFER_GOLDEN).unwrap(), value);
}

/// **`TransferMode::TRANSFER` is zero, and that is a compatibility statement
/// rather than an arbitrary numbering.** Version 3 of the containing
/// `ChannelMsgArgs` required this word to be zero, so every descriptor a v3
/// producer ever emitted is a v4 descriptor asking for a transfer — the field
/// changed meaning without changing a byte, which is exactly what reserving it
/// was for.
#[test]
fn the_mode_word_is_where_version_threes_reserved_word_was() {
    let mut buf = [0u8; 16];
    encode(
        &HandleTransfer {
            handle: 7,
            mode: TransferMode::Transfer,
            rights: 0x85,
        },
        &mut buf,
    )
    .unwrap();
    assert_eq!(buf[4..8], [0, 0, 0, 0]);
}

/// A mode this ABI does not define **fails to decode**. The alternative —
/// reading it as `TRANSFER`, the zero value — would take a sender's capability
/// away in answer to a request it did not make.
#[test]
fn an_undefined_mode_is_refused_rather_than_read_as_transfer() {
    let mut bytes = TRANSFER_GOLDEN;
    bytes[4] = 9;
    assert_eq!(decode::<HandleTransfer>(&bytes), Err(WireError::BadEnum));
    // And `SHARE` decodes, because the ABI defines it — refusing it is the
    // kernel's decision to report, not the wire format's.
    bytes[4] = 1;
    assert_eq!(
        decode::<HandleTransfer>(&bytes).unwrap().mode,
        TransferMode::Share
    );
}
