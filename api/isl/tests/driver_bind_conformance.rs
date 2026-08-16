// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated driver-binding protocol bindings
//! (built by the codegen genrule from `examples/driver_bind.isl`, never
//! committed). Proves `BindRequest`/`BindReply` encode to fixed golden
//! layouts and decode back.
//!
//! Like the block protocol this is a user↔user contract the kernel transports
//! opaquely, so its wire stability rests entirely here.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{WireError, decode, encode};

/// Golden encoding of the `BindRequest` value below: 24 bytes, LE.
const REQUEST_GOLDEN: [u8; 24] = [
    0x18, 0, 0, 0, // size = 24
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x01, 0, 0, 0, // class = Block
    0, 0, 0, 0, // reserved = 0
];

/// Golden encoding of the `BindReply` value below: 72 bytes, LE.
///
/// Version 2 carries the binding's **outputs** (build/README.md, D130). Three
/// of `docs/drivers/01`'s six outputs — the host identity, the granted
/// capabilities and the resource leases — are produced by the transfer itself
/// and need no field; the other three are decisions a manifest made, and a
/// driver that was not told them would have to assume.
///
/// **Version 4 says which firmware image came with the device**: the security
/// version and image version of the object transferred beside it. Both zero is
/// a binding that carried none, which is most of them.
///
/// **Version 3 carries what the data path costs**: the declared latency of the
/// relaying ancestors between this device and the root, how many of them there
/// are, and the narrowest one. The value below is two hops totalling 35 µs
/// through a path whose slowest hop carries 500 Mbit/s.
const REPLY_GOLDEN: [u8; 72] = [
    0x18, 0, 0, 0, // size = 24 (see below: the value's own size field)
    0x04, 0, 0, 0, // version = 4
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0, 0, 0, 0, // status = 0 (bound)
    0x02, 0, 0, 0, // class = Network
    0x05, 0, 0, 0, // required_services = LOGGING | POWER
    0x01, 0, 0, 0, // update_channel = 1
    0x01, 0, 0, 0, // security_domain = 1
    0, 0, 0, 0, // power_domain = 0
    0x01, 0, 0, 0, // contract_version = 1
    0, 0, 0, 0, // reserved = 0
    0x23, 0, 0, 0, 0, 0, 0, 0, // accumulated_latency_us = 35
    0x02, 0, 0, 0, // relay_hops = 2
    0xf4, 0x01, 0, 0, // path_throughput_mbps = 500
    0x07, 0, 0, 0, // firmware_svn = 7
    0x03, 0, 0, 0, // firmware_image_version = 3
];

#[test]
fn bind_request_matches_golden_and_round_trips() {
    assert_eq!(BindRequest::WIRE_SIZE, 24);
    let value = BindRequest {
        size: 24,
        version: 1,
        flags: 0,
        class: DeviceClass::Block,
        reserved: 0,
    };
    let mut buf = [0u8; BindRequest::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).expect("encode"), 24);
    assert_eq!(buf, REQUEST_GOLDEN);
    let back: BindRequest = decode(&REQUEST_GOLDEN).expect("decode");
    assert_eq!(back, value);
}

#[test]
fn bind_reply_matches_golden_and_round_trips() {
    assert_eq!(BindReply::WIRE_SIZE, 72);
    let value = BindReply {
        // The `size` field is the *value's* declared size and the kernel does
        // not police it for a user<->user protocol; the golden keeps 24 to
        // show that, and the wire size is what the buffer must be.
        size: 24,
        version: 4,
        flags: 0,
        status: 0,
        class: DeviceClass::Network,
        required_services: 0x5,
        update_channel: 1,
        security_domain: 1,
        power_domain: 0,
        contract_version: 1,
        reserved: 0,
        accumulated_latency_us: 35,
        relay_hops: 2,
        path_throughput_mbps: 500,
        firmware_svn: 7,
        firmware_image_version: 3,
    };
    let mut buf = [0u8; BindReply::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).expect("encode"), 72);
    assert_eq!(buf, REPLY_GOLDEN);
    let back: BindReply = decode(&REPLY_GOLDEN).expect("decode");
    assert_eq!(back, value);
}

/// A refusal carries **which** refusal, and the outputs stay zero.
///
/// A device unbound because nothing matched, one unbound because its driver is
/// unsigned, and one unbound because an operator disabled it are three
/// administrative situations with three different fixes. A reply that reported
/// them identically would leave all three looking like missing hardware — and
/// one that filled in plausible outputs alongside the refusal would have a
/// driver proceed as though it had been bound.
#[test]
fn a_refusal_names_its_reason_and_carries_no_outputs() {
    // `tessera_binding::Refusal::UntrustedSignature`.
    let value = BindReply {
        size: 24,
        version: 4,
        flags: 0,
        status: 2,
        class: DeviceClass::Unknown,
        required_services: 0,
        update_channel: 0,
        security_domain: 0,
        power_domain: 0,
        contract_version: 0,
        reserved: 0,
        accumulated_latency_us: 0,
        relay_hops: 0,
        path_throughput_mbps: 0,
        firmware_svn: 0,
        firmware_image_version: 0,
    };
    let mut buf = [0u8; BindReply::WIRE_SIZE];
    encode(&value, &mut buf).expect("encode");
    let back: BindReply = decode(&buf).expect("decode");
    assert_eq!(back.status, 2);
    assert_eq!(back.required_services, 0);
    assert_eq!(back.update_channel, 0);
    assert_eq!(back.contract_version, 0);
    // The path costs stay zero too. A refused device has no path a driver
    // should act on, and a plausible-looking hop count next to a refusal is
    // exactly the reading a driver would take for a bind that happened.
    assert_eq!(back.accumulated_latency_us, 0);
    assert_eq!(back.relay_hops, 0);
    // And so do the firmware versions. A refused bind transferred no image,
    // and a driver reading a version beside a refusal would be reading about
    // an object it does not hold.
    assert_eq!(back.firmware_svn, 0);
    assert_eq!(back.firmware_image_version, 0);
}

/// The classes are a `strict enum`, so a value outside the set is a decode
/// error rather than a silently-carried number. A manager that answered with
/// a class the driver's build does not know must not look like a valid bind.
#[test]
fn an_unknown_class_is_rejected() {
    let mut bytes = REQUEST_GOLDEN;
    bytes[16] = 0x7f;
    assert!(matches!(
        decode::<BindRequest>(&bytes),
        Err(WireError::BadEnum)
    ));
}
