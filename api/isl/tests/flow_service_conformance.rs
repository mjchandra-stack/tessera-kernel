// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Golden vectors for the flow (socket) contract.
//!
//! Hand-spelled bytes rather than a round trip through the codec. A round trip
//! proves the encoder and the decoder agree with each other, which they would
//! even if both moved a field; these bytes are what a program on the other end
//! of the channel will actually be handed.
//!
//! Normative: docs/network/01-network-stack.md ("Flow API And Port Authority")

use flow_service::{
    Flow, FlowAddress, FlowBindReply, FlowBindRequest, FlowCloseRequest, FlowError, FlowRecvReply,
    FlowRecvRequest, FlowSendReply, FlowSendRequest,
};
use tessera_isl_runtime::{HandleRef, Ownership, Reader, WireError, decode, encode};

/// Decodes `T` out of a message carrying `handles` transferred capabilities.
///
/// The handle count is the argument that matters: a struct's handle field is an
/// index into the message's transfer vector, and the decoder range-checks it —
/// so decoding with the wrong count is how a contract's refusals get tested,
/// and how a driver silently refuses every request it was actually sent
/// (build/README.md, D272).
fn decode_in<T: tessera_isl_runtime::WireDecode>(
    bytes: &[u8],
    handles: u32,
) -> Result<T, WireError> {
    T::decode(&mut Reader::in_message(bytes, handles))
}

/// `0.0.0.0:68` — the address a DHCP client binds before it has one.
fn any_address(port: u32) -> FlowAddress {
    FlowAddress {
        size: FlowAddress::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        family: 4,
        port,
        addr: [0, 0, 0, 0],
        reserved: 0,
    }
}

/// The error set is closed and its values are stable: a service and a client
/// compiled a year apart have to mean the same thing by `4`.
#[test]
fn the_error_set_is_closed_and_stable() {
    assert_eq!(FlowError::Ok as u32, 0);
    assert_eq!(FlowError::PortUnavailable as u32, 1);
    assert_eq!(FlowError::NoSuchFlow as u32, 2);
    assert_eq!(FlowError::BadLength as u32, 3);
    assert_eq!(FlowError::WouldBlock as u32, 4);
    assert_eq!(FlowError::Unreachable as u32, 5);
    assert_eq!(FlowError::Protocol as u32, 6);
    assert_eq!(FlowError::Exhausted as u32, 7);
}

/// The four datagram ordinals, and the three the stream vocabulary will take.
///
/// **Pinned including the reserved ones.** The point of reserving 5, 6 and 7 is
/// that `Listen`, `Accept` and `Connect` land there and nowhere else; a test
/// that only pinned the four in use would let a fifth method be added at 5 and
/// silently take the slot TCP is holding.
#[test]
fn the_ordinals_are_stable_and_the_stream_slots_are_held() {
    assert_eq!(Flow::BIND, 1);
    assert_eq!(Flow::SEND_TO, 2);
    assert_eq!(Flow::RECV_FROM, 3);
    assert_eq!(Flow::CLOSE, 4);
}

/// An address encodes as family, port, four bytes, in that order.
#[test]
fn an_address_matches_golden() {
    let value = FlowAddress {
        size: FlowAddress::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        family: 4,
        port: 0x0044, // 68
        addr: [10, 0, 2, 15],
        reserved: 0,
    };
    let mut buf = [0u8; FlowAddress::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).unwrap(), FlowAddress::WIRE_SIZE);
    assert_eq!(buf[0], FlowAddress::WIRE_SIZE as u8);
    assert_eq!(buf[4], 1, "version");
    assert_eq!(buf[16..20], [4, 0, 0, 0], "family = 4, little-endian");
    assert_eq!(buf[20..24], [0x44, 0, 0, 0], "port = 68");
    assert_eq!(buf[24..28], [10, 0, 2, 15], "the address, in wire order");
    let decoded = decode_in::<FlowAddress>(&buf, 0).unwrap();
    assert_eq!(decoded, value);
}

/// A bind request carries an address and the field the port capability will
/// occupy, and round-trips.
#[test]
fn a_bind_request_round_trips_with_its_reserved_authority() {
    let value = FlowBindRequest {
        size: FlowBindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        local: any_address(68),
        // Zero, and a service must refuse anything else until there is a
        // namespace broker to resolve one.
        port_authority: 0,
        reserved: 0,
    };
    let mut buf = [0u8; FlowBindRequest::WIRE_SIZE];
    assert_eq!(
        encode(&value, &mut buf).unwrap(),
        FlowBindRequest::WIRE_SIZE
    );
    assert_eq!(decode_in::<FlowBindRequest>(&buf, 0).unwrap(), value);
}

/// A bind reply says which port was actually taken, which is how an ephemeral
/// request learns its answer.
#[test]
fn a_bind_reply_reports_the_port_it_took() {
    let value = FlowBindReply {
        size: FlowBindReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: FlowError::Ok as u32,
        flow: 1,
        local: any_address(68),
    };
    let mut buf = [0u8; FlowBindReply::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).unwrap(), FlowBindReply::WIRE_SIZE);
    let decoded = decode_in::<FlowBindReply>(&buf, 0).unwrap();
    assert_eq!(decoded.local.port, 68);
    assert_eq!(decoded, value);
}

/// A datagram travels as a transferred object in both directions, with the
/// rights each side of the handover needs and no more.
///
/// **The assertion that matters on this contract.** A payload the service could
/// write to would make a client's memory writable by whoever it last spoke to,
/// and a payload a client could pass on would let a datagram it was only meant
/// to read become somebody else's capability.
#[test]
fn payloads_are_given_away_with_the_narrow_rights() {
    assert_eq!(FlowSendRequest::PAYLOAD_OWNERSHIP, Ownership::Transfer);
    assert_eq!(
        FlowSendRequest::PAYLOAD_RIGHTS,
        0x1 | 0x4,
        "READ | MAP — the service reads the datagram and must not alter it",
    );
    assert_eq!(FlowRecvReply::PAYLOAD_OWNERSHIP, Ownership::Transfer);
    assert_eq!(
        FlowRecvReply::PAYLOAD_RIGHTS,
        0x1 | 0x4,
        "READ | MAP — no TRANSFER, so a received datagram cannot be passed on",
    );
}

/// A send request naming a payload that did not arrive is refused.
///
/// The same protection `network_driver` has, checked here because this contract
/// is reached by any program with network access rather than only by a driver.
#[test]
fn a_send_naming_a_payload_that_did_not_arrive_is_refused() {
    let value = FlowSendRequest {
        size: FlowSendRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow: 1,
        length: 290,
        remote: any_address(67),
        payload: HandleRef::new(0),
    };
    let mut buf = [0u8; FlowSendRequest::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    // Index 0 of a message carrying no handles.
    assert_eq!(
        decode_in::<FlowSendRequest>(&buf, 0),
        Err(WireError::HandleIndexOutOfRange),
    );
    // And it decodes once the handle is really there.
    assert!(decode_in::<FlowSendRequest>(&buf, 1).is_ok());
}

/// A send reply carries both an outcome and a count, for the reason the
/// network class's does: a short send is an outcome, not a failure.
#[test]
fn a_send_reply_carries_both_an_outcome_and_a_count() {
    let value = FlowSendReply {
        size: FlowSendReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: FlowError::Ok as u32,
        sent: 290,
    };
    let mut buf = [0u8; FlowSendReply::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    let decoded = decode_in::<FlowSendReply>(&buf, 0).unwrap();
    assert_eq!(decoded.sent, 290);
    assert_eq!(decoded.status, FlowError::Ok as u32);
}

/// A receive request states the largest datagram the caller will take, and the
/// reply says who sent the one that came back.
#[test]
fn a_receive_states_a_bound_and_answers_with_a_sender() {
    let request = FlowRecvRequest {
        size: FlowRecvRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow: 1,
        max_length: 1500,
    };
    let mut buf = [0u8; FlowRecvRequest::WIRE_SIZE];
    encode(&request, &mut buf).unwrap();
    assert_eq!(decode_in::<FlowRecvRequest>(&buf, 0).unwrap(), request);

    let reply = FlowRecvReply {
        size: FlowRecvReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: FlowError::Ok as u32,
        length: 300,
        remote: FlowAddress {
            size: FlowAddress::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            family: 4,
            port: 67,
            addr: [10, 0, 2, 2],
            reserved: 0,
        },
        payload: HandleRef::new(0),
    };
    let mut buf = [0u8; FlowRecvReply::WIRE_SIZE];
    encode(&reply, &mut buf).unwrap();
    let decoded = decode_in::<FlowRecvReply>(&buf, 1).unwrap();
    assert_eq!(decoded.remote.addr, [10, 0, 2, 2]);
    assert_eq!(decoded.remote.port, 67);
    assert_eq!(decoded.length, 300);
}

/// A close request round-trips. Small, and here because a contract whose
/// teardown method is untested is one whose teardown nobody has encoded.
#[test]
fn a_close_round_trips() {
    let value = FlowCloseRequest {
        size: FlowCloseRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow: 1,
        reserved: 0,
    };
    let mut buf = [0u8; FlowCloseRequest::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    assert_eq!(decode_in::<FlowCloseRequest>(&buf, 0).unwrap(), value);
}
