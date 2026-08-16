// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the USB host protocol's ABI structs.
//!
//! The ABI test, and deliberately not a class-conformance suite: what is
//! checked here is that the bytes are what the schema says. This protocol is
//! not a class contract — it is the transport a class driver uses in place of
//! the registers a USB device does not have.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("USB"),
//! docs/drivers/01-driver-framework.md ("Bus Topology And Data Paths"),
//! docs/api/03-interface-schema-language.md

use tessera_isl_runtime::{decode, encode};
use usb_host::{
    UsbControlRequest, UsbDeviceReply, UsbDeviceRequest, UsbError, UsbHost, UsbHostIncoming,
    UsbTransferKind, UsbTransferReply, UsbTransferRequest,
};

/// **The error set is numbered to the framework's discipline.** `NOT_SUPPORTED`
/// at 5, `PROTOCOL` at 6, `DEGRADED` at 7 and `REMOVED` at 8, as on every class
/// contract here, so the values the framework reads mean the same thing
/// wherever they appear.
#[test]
fn the_error_set_shares_the_frameworks_numbering() {
    assert_eq!(UsbError::Ok as u32, 0);
    assert_eq!(UsbError::Stall as u32, 1);
    assert_eq!(UsbError::NoDevice as u32, 2);
    assert_eq!(UsbError::TransferError as u32, 3);
    // The one this class has that no other does: the device is there, it
    // enumerated, and this system will not drive it.
    assert_eq!(UsbError::Unauthorized as u32, 4);
    assert_eq!(UsbError::NotSupported as u32, 5);
    assert_eq!(UsbError::Protocol as u32, 6);
    assert_eq!(UsbError::Degraded as u32, 7);
    assert_eq!(UsbError::Removed as u32, 8);
}

/// The transfer kinds are the values a device's own endpoint descriptor uses,
/// not a translation of them — so a class driver asks for what it read.
#[test]
fn the_transfer_kinds_are_the_endpoint_descriptors_own() {
    assert_eq!(UsbTransferKind::Control as u32, 0);
    assert_eq!(UsbTransferKind::Isochronous as u32, 1);
    assert_eq!(UsbTransferKind::Bulk as u32, 2);
    assert_eq!(UsbTransferKind::Interrupt as u32, 3);
}

/// A device is named by the address the host assigned it, and its reply carries
/// the **interface's** class rather than the device's — most devices declare
/// nothing at the device level, so device-level bytes would be zero for exactly
/// the devices a class driver wants.
#[test]
fn a_device_reply_round_trips_with_the_interfaces_class() {
    let value = UsbDeviceReply {
        size: UsbDeviceReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: UsbError::Ok,
        address: 2,
        vendor: 0x0463,
        product: 0x0001,
        class: 0x08,
        subclass: 0x06,
        protocol: 0x50,
        interface: 0,
        // Behind one hub, which is a fact nothing downstream could work out.
        depth: 1,
        reserved: 0,
    };
    let mut bytes = [0u8; UsbDeviceReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    assert_eq!(decode::<UsbDeviceReply>(&bytes).expect("decode"), value);
}

/// A control transfer carries its setup packet whole, and the **direction lives
/// in that packet** rather than in a field beside it. A second copy would be a
/// second place for it to be wrong, and the failure would be a stalled endpoint
/// rather than a rejected message.
#[test]
fn a_control_request_carries_its_setup_packet_whole() {
    let mut value = UsbControlRequest {
        size: UsbControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        address: 1,
        length: 18,
        // GET_DESCRIPTOR(device), eighteen bytes, device to host.
        setup: [0x80, 6, 0, 1, 0, 0, 18, 0],
        data: [0u8; 64],
    };
    value.data[0] = 0xa5;
    let mut bytes = [0u8; UsbControlRequest::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<UsbControlRequest>(&bytes).expect("decode");
    assert_eq!(back.setup, value.setup);
    assert_eq!(back.setup[0] & 0x80, 0x80, "the direction is in the packet");
    assert_eq!(back.data[0], 0xa5);
}

/// **A short transfer is a success with a smaller `transferred`.** A device is
/// allowed to send less than was asked for, and a client that ignored the field
/// would read stale bytes out of the tail of its own buffer.
#[test]
fn a_short_transfer_is_a_success_with_a_smaller_count() {
    let value = UsbTransferReply {
        size: UsbTransferReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: UsbError::Ok,
        transferred: 8,
        data: [0u8; 64],
    };
    let mut bytes = [0u8; UsbTransferReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<UsbTransferReply>(&bytes).expect("decode");
    assert_eq!(back.status, UsbError::Ok);
    assert_eq!(back.transferred, 8, "less than the sixty-four asked for");
}

/// One method for bulk and interrupt, keyed by what the endpoint descriptor
/// said. Two methods would be two names for the same ring, and a class driver
/// could pick the wrong one without being told.
#[test]
fn bulk_and_interrupt_share_one_method_keyed_by_the_endpoint() {
    let value = UsbTransferRequest {
        size: UsbTransferRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        address: 2,
        // Endpoint one, device to host.
        endpoint: 0x81,
        kind: UsbTransferKind::Interrupt,
        length: 8,
        data: [0u8; 64],
    };
    let mut bytes = [0u8; UsbTransferRequest::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    assert_eq!(decode::<UsbTransferRequest>(&bytes).expect("decode"), value);

    let mut bulk = value;
    bulk.kind = UsbTransferKind::Bulk;
    bulk.endpoint = 0x02;
    encode(&bulk, &mut bytes).expect("encode");
    assert_eq!(decode::<UsbTransferRequest>(&bytes).expect("decode"), bulk);
}

/// The dispatch enum decodes by ordinal, and an ordinal this protocol does not
/// define is `UnknownMethod` rather than a wrong method.
#[test]
fn dispatch_is_keyed_by_ordinal_and_an_unknown_one_is_refused() {
    assert_eq!(UsbHost::DESCRIBE, 1);
    assert_eq!(UsbHost::CONTROL, 2);
    assert_eq!(UsbHost::TRANSFER, 3);
    assert_eq!(UsbHost::ON_DEVICE_ARRIVED, 20);
    assert_eq!(UsbHost::ON_DEVICE_GONE, 21);

    let request = UsbDeviceRequest {
        size: UsbDeviceRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        address: 1,
        reserved: 0,
    };
    let mut bytes = [0u8; UsbDeviceRequest::WIRE_SIZE];
    encode(&request, &mut bytes).expect("encode");
    let decoded = UsbHostIncoming::decode(
        UsbHost::DESCRIBE,
        &mut tessera_isl_runtime::Reader::in_message(&bytes, 0),
    )
    .expect("decode");
    match decoded {
        UsbHostIncoming::Describe(value) => assert_eq!(value.address, 1),
        _ => panic!("the describe ordinal decoded as something else"),
    }
    assert!(
        UsbHostIncoming::decode(4, &mut tessera_isl_runtime::Reader::in_message(&bytes, 0))
            .is_err(),
        "a reserved ordinal is not a method",
    );
}
