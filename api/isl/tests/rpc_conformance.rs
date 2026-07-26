// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated `rpc` protocol bindings (built by the
//! codegen genrule from `examples/rpc.isl`, never committed). Covers the parts
//! `echo_service` does not: an empty-request one-way method (the unit dispatch
//! variant that frames zero bytes) and a second, independently-derived
//! interface id (deviation D69).
//!
//! Normative: docs/api/03-interface-schema-language.md ("Protocols")

use rpc::{GetArgs, GetReply, Store, StoreEvent, StoreIncoming, StoreOutgoing, TickEvent};
use tessera_isl_runtime::{Reader, WireError, Writer};

#[test]
fn the_interface_id_is_independently_derived() {
    // A different fully-qualified name than echo's, so a different id.
    assert_eq!(Store::INTERFACE_ID, 0x58ad_7428_d61a_931f);
    assert_eq!((Store::GET, Store::FLUSH, Store::TICK), (1, 2, 3));
}

fn round_trip_incoming(value: &StoreIncoming) -> StoreIncoming {
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    value.encode(&mut w).unwrap();
    let n = w.position();
    let mut r = Reader::new(&buf[..n]);
    let back = StoreIncoming::decode(value.method_id(), &mut r).unwrap();
    r.finish().unwrap();
    back
}

#[test]
fn a_named_call_request_round_trips() {
    let value = StoreIncoming::Get(GetArgs { key: 0xdead });
    assert_eq!(value.method_id(), Store::GET);
    match round_trip_incoming(&value) {
        StoreIncoming::Get(args) => assert_eq!(args.key, 0xdead),
        other => panic!("expected Get, got {other:?}"),
    }
}

#[test]
fn an_empty_request_one_way_frames_zero_bytes() {
    let value = StoreIncoming::Flush;
    assert_eq!(value.method_id(), Store::FLUSH);

    // The unit variant encodes nothing: the payload is empty.
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf);
    value.encode(&mut w).unwrap();
    assert_eq!(w.position(), 0);

    // And decodes from an empty reader.
    let mut r = Reader::new(&[]);
    let back = StoreIncoming::decode(Store::FLUSH, &mut r).unwrap();
    r.finish().unwrap();
    assert_eq!(back, StoreIncoming::Flush);
}

#[test]
fn the_response_and_event_dispatch() {
    let reply = StoreOutgoing::Get(GetReply {
        value: 7,
        found: true,
    });
    let mut buf = [0u8; 32];
    let mut w = Writer::new(&mut buf);
    reply.encode(&mut w).unwrap();
    let n = w.position();
    let mut r = Reader::new(&buf[..n]);
    match StoreOutgoing::decode(reply.method_id(), &mut r).unwrap() {
        StoreOutgoing::Get(got) => assert_eq!((got.value, got.found), (7, true)),
    }

    let evt = StoreEvent::Tick(TickEvent { seq: 99 });
    let mut buf = [0u8; 32];
    let mut w = Writer::new(&mut buf);
    evt.encode(&mut w).unwrap();
    let n = w.position();
    match StoreEvent::decode(Store::TICK, &mut Reader::new(&buf[..n])).unwrap() {
        StoreEvent::Tick(t) => assert_eq!(t.seq, 99),
    }
}

#[test]
fn an_unknown_method_ordinal_is_rejected() {
    let mut r = Reader::new(&[]);
    assert_eq!(
        StoreIncoming::decode(255, &mut r),
        Err(WireError::UnknownMethod)
    );
}
