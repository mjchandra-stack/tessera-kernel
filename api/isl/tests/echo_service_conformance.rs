// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated `echo_service` bindings (built by the
//! codegen genrule from `examples/echo_service.isl`, never committed). The
//! reference service protocol, and the capstone of ISL codegen: its
//! `string:256` request/reply tables (D68) and its `protocol Echo` — interface
//! id, method ordinals, and typed request/response/event dispatch (D69) — now
//! all generate from one schema.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format",
//! "Protocols")

use echo_service::{Echo, EchoEvent, EchoIncoming, EchoOutgoing, EchoReply, EchoRequest};
use tessera_isl_runtime::{BoundedString, Reader, WireError, Writer, decode, encode};

/// `EchoRequest { message: Some("hi"), tag: Some(7) }`: a present `string:256`
/// field (envelope size = 4-byte length prefix + 2 content bytes) then the
/// inline `uint64` field.
const REQUEST_GOLDEN: [u8; 34] = [
    0x02, 0, 0, 0, // count = 2 present fields
    0x01, 0, 0, 0, // field 1 (message) ordinal
    0x06, 0, 0, 0, // field 1 size = 6 (4 + 2)
    0x02, 0, 0, 0, // string length = 2
    b'h', b'i', // "hi"
    0x02, 0, 0, 0, // field 2 (tag) ordinal
    0x08, 0, 0, 0, // field 2 size = 8
    0x07, 0, 0, 0, 0, 0, 0, 0, // tag = 7
];

#[test]
fn an_echo_request_matches_its_golden_and_round_trips() {
    let value = EchoRequest {
        message: Some(BoundedString::from_str("hi").unwrap()),
        tag: Some(7),
    };
    let mut buf = [0u8; 34];
    assert_eq!(encode(&value, &mut buf).unwrap(), 34);
    assert_eq!(buf, REQUEST_GOLDEN);

    let decoded: EchoRequest = decode(&REQUEST_GOLDEN).unwrap();
    assert_eq!(decoded.tag, Some(7));
    assert_eq!(decoded.message.unwrap().as_str(), "hi");
}

#[test]
fn an_echo_reply_round_trips_a_long_string() {
    // Right at half the bound — proves the 256-byte capacity is real.
    let text = "x".repeat(128);
    let value = EchoReply {
        reply: Some(BoundedString::from_str(&text).unwrap()),
    };
    let mut buf = [0u8; 512];
    let n = encode(&value, &mut buf).unwrap();
    let decoded: EchoReply = decode(&buf[..n]).unwrap();
    assert_eq!(decoded.reply.unwrap().as_str(), text);
}

#[test]
fn a_string_past_the_bound_is_rejected_through_the_table() {
    // Field 1 (message), envelope size 4 + 300, string length 300 > 256.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_le_bytes()); // count = 1
    bytes.extend_from_slice(&1u32.to_le_bytes()); // ordinal 1
    bytes.extend_from_slice(&304u32.to_le_bytes()); // size = 4 + 300
    bytes.extend_from_slice(&300u32.to_le_bytes()); // string length = 300
    bytes.extend(std::iter::repeat_n(b'x', 300));
    assert_eq!(decode::<EchoRequest>(&bytes), Err(WireError::BoundExceeded));
}

// --- protocol dispatch (D69) ---

#[test]
fn the_interface_id_and_method_ordinals_are_the_pinned_values() {
    // The interface id is the D11 derivation of "tessera.example.echo.Echo@1".
    assert_eq!(Echo::INTERFACE_ID, 0x282c_25eb_2fe0_8ac7);
    assert_eq!(Echo::ECHO, 1);
    assert_eq!(Echo::LOG, 2);
    assert_eq!(Echo::ON_HEARTBEAT, 3);
}

/// Frames a dispatch value the way a channel client would: encode the payload,
/// carry the method id alongside (it lives in the header, not the payload).
fn round_trip_incoming(value: &EchoIncoming) -> EchoIncoming {
    let mut buf = [0u8; 128];
    let mut w = Writer::new(&mut buf);
    value.encode(&mut w).unwrap();
    let n = w.position();
    let mut r = Reader::new(&buf[..n]);
    let back = EchoIncoming::decode(value.method_id(), &mut r).unwrap();
    r.finish().unwrap();
    back
}

#[test]
fn an_incoming_call_request_dispatches_by_method_id() {
    let request = EchoRequest {
        message: Some(BoundedString::from_str("ping").unwrap()),
        tag: Some(42),
    };
    let value = EchoIncoming::Echo(request);
    assert_eq!(value.method_id(), Echo::ECHO);
    match round_trip_incoming(&value) {
        EchoIncoming::Echo(got) => {
            assert_eq!(got.message.unwrap().as_str(), "ping");
            assert_eq!(got.tag, Some(42));
        }
        other => panic!("expected Echo, got {other:?}"),
    }
}

#[test]
fn the_call_response_and_the_event_dispatch_too() {
    let reply = EchoReply {
        reply: Some(BoundedString::from_str("pong").unwrap()),
    };
    let out = EchoOutgoing::Echo(reply);
    let mut buf = [0u8; 128];
    let mut w = Writer::new(&mut buf);
    out.encode(&mut w).unwrap();
    let n = w.position();
    let mut r = Reader::new(&buf[..n]);
    match EchoOutgoing::decode(out.method_id(), &mut r).unwrap() {
        EchoOutgoing::Echo(got) => assert_eq!(got.reply.unwrap().as_str(), "pong"),
    }

    // The event is a server-initiated one-way; its payload is the synthesized
    // inline struct.
    let evt = EchoEvent::decode(Echo::ON_HEARTBEAT, &mut Reader::new(&7u64.to_le_bytes())).unwrap();
    match evt {
        EchoEvent::OnHeartbeat(hb) => assert_eq!(hb.seq, 7),
    }
}

#[test]
fn an_unknown_method_ordinal_is_rejected() {
    let mut r = Reader::new(&[]);
    assert_eq!(
        EchoIncoming::decode(99, &mut r),
        Err(WireError::UnknownMethod)
    );
}
