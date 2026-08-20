// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Golden vectors for the filesystem service contract.
//!
//! Hand-spelled bytes rather than a round trip through the codec. A round trip
//! proves the encoder and the decoder agree with each other, which they would
//! even if both moved a field; these bytes are what a program on the other end
//! of the channel will actually be handed.

use fs_service::{
    FileSystem, FsCloseReply, FsCloseRequest, FsOpenReply, FsOpenRequest, FsReadReply,
    FsReadRequest,
};
use tessera_isl_runtime::{HandleRef, Reader, WireDecode, WireEncode, WireError};

/// `Open("/hello.txt")`, with the path zero-padded to its fixed width.
const OPEN_REQUEST: [u8; FsOpenRequest::WIRE_SIZE] = {
    let mut bytes = [0u8; FsOpenRequest::WIRE_SIZE];
    bytes[0] = FsOpenRequest::WIRE_SIZE as u8;
    bytes[4] = 1; // version
    // flags: 8 bytes of zero at 8..16
    bytes[16] = b'/';
    bytes[17] = b'h';
    bytes[18] = b'e';
    bytes[19] = b'l';
    bytes[20] = b'l';
    bytes[21] = b'o';
    bytes[22] = b'.';
    bytes[23] = b't';
    bytes[24] = b'x';
    bytes[25] = b't';
    bytes[144] = 10; // path_len, just past the 128-byte array
    bytes
};

#[test]
fn an_open_request_encodes_to_its_golden_bytes() {
    let mut path = [0u8; 128];
    path[..10].copy_from_slice(b"/hello.txt");
    let request = FsOpenRequest {
        size: FsOpenRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        path,
        path_len: 10,
        reserved: 0,
    };
    let mut out = [0u8; FsOpenRequest::WIRE_SIZE];
    request
        .encode(&mut tessera_isl_runtime::Writer::new(&mut out))
        .expect("encode");
    assert_eq!(out, OPEN_REQUEST);

    let back = FsOpenRequest::decode(&mut Reader::new(&OPEN_REQUEST)).expect("decode");
    assert_eq!(back.path_len, 10);
    assert_eq!(&back.path[..10], b"/hello.txt");
}

/// The read request carries the buffer as an **index into the message's handle
/// vector**, not as a handle number. A caller that put its own handle number
/// here would be naming a capability in somebody else's table.
#[test]
fn a_read_request_carries_the_buffer_by_index() {
    let request = FsReadRequest {
        size: FsReadRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        file: 7,
        reserved: 0,
        offset: 4096,
        length: 512,
        buffer: HandleRef::new(0),
    };
    let mut out = [0u8; FsReadRequest::WIRE_SIZE];
    request
        .encode(&mut tessera_isl_runtime::Writer::new(&mut out))
        .expect("encode");
    // file at 16, offset at 24, length at 32, handle index at 40.
    assert_eq!(u32::from_le_bytes([out[16], out[17], out[18], out[19]]), 7);
    assert_eq!(
        u64::from_le_bytes([
            out[24], out[25], out[26], out[27], out[28], out[29], out[30], out[31]
        ]),
        4096
    );
    assert_eq!(
        u64::from_le_bytes([
            out[32], out[33], out[34], out[35], out[36], out[37], out[38], out[39]
        ]),
        512
    );
    assert_eq!(u32::from_le_bytes([out[40], out[41], out[42], out[43]]), 0);
}

#[test]
fn the_replies_are_the_widths_the_contract_declares() {
    // 32 until the reply started carrying the file's memory object: a handle
    // and its padding, which is what turns a read from a message into a load.
    assert_eq!(FsOpenReply::WIRE_SIZE, 40);
    assert_eq!(
        FsOpenReply::OBJECT_RIGHTS,
        0x1 | 0x4,
        "READ and MAP: a caller that could SUPPLY would answer for a file it merely opened",
    );
    assert_eq!(FsReadReply::WIRE_SIZE, 32);
    assert_eq!(FsCloseReply::WIRE_SIZE, 24);
    assert_eq!(FsCloseRequest::WIRE_SIZE, 24);
}

/// Ordinals are ABI. A renumbering is a different contract wearing this one's
/// name, so they are spelled out rather than derived.
#[test]
fn the_ordinals_are_what_they_were() {
    assert_eq!(FileSystem::OPEN, 1);
    assert_eq!(FileSystem::READ, 2);
    assert_eq!(FileSystem::CLOSE, 3);
}

#[test]
fn a_truncated_request_is_short_buffer_rather_than_a_guess() {
    let err = FsOpenRequest::decode(&mut Reader::new(&OPEN_REQUEST[..16])).expect_err("short");
    assert_eq!(err, WireError::ShortBuffer);
}
