// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the display output class contract's ABI structs.
//!
//! The ABI test, and deliberately not the class-conformance suite: what is
//! checked here is that the bytes are what the schema says.
//!
//! Normative: docs/drivers/03-graphics-display-media-sensors-ai.md
//! ("Display And Graphics"), docs/api/03-interface-schema-language.md

use display_output::{
    DisplayBlitReply, DisplayBlitRequest, DisplayControlReply, DisplayControlRequest,
    DisplayDescribeReply, DisplayError, DisplayEvent, DisplayFeature, DisplayFillRequest,
    DisplayFormat, DisplayOutput, DisplayPowerState, DisplayRectRequest, DisplayTracePoint,
};
use tessera_isl_runtime::{decode, encode};

/// **The error set is numbered to the framework's discipline.** `NOT_SUPPORTED`
/// at 5, `PROTOCOL` at 6, `DEGRADED` at 7 and `REMOVED` at 8 on every class.
/// What differs is 1 through 4, and that difference is what a class *is*.
#[test]
fn the_error_set_shares_the_frameworks_numbering() {
    assert_eq!(DisplayError::Ok as u32, 0);
    assert_eq!(DisplayError::NoScanout as u32, 1);
    assert_eq!(DisplayError::OutOfBounds as u32, 2);
    assert_eq!(DisplayError::BadFormat as u32, 3);
    assert_eq!(DisplayError::Busy as u32, 4);
    assert_eq!(DisplayError::NotSupported as u32, 5);
    assert_eq!(DisplayError::Protocol as u32, 6);
    assert_eq!(DisplayError::Degraded as u32, 7);
    assert_eq!(DisplayError::Removed as u32, 8);
}

/// The same four power-state names as the six classes before it.
#[test]
fn the_power_states_share_the_other_classes_vocabulary() {
    assert_eq!(DisplayPowerState::Active as u32, 1);
    assert_eq!(DisplayPowerState::Idle as u32, 2);
    assert_eq!(DisplayPowerState::Standby as u32, 3);
    assert_eq!(DisplayPowerState::Off as u32, 4);
}

/// `Describe` reports **the mode there is**, not one a client may ask for. A
/// client that guessed would draw off the edge of a display it never asked
/// about and see nothing — the same reason the block class reports a sector
/// size.
#[test]
fn describe_reports_the_mode_the_display_actually_has() {
    let value = DisplayDescribeReply {
        size: DisplayDescribeReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        contract_version: 1,
        status: DisplayError::Ok,
        // It fills, and it has no cursor plane and no hotplug.
        features: DisplayFeature::FILL.0,
        width: 1280,
        height: 800,
        format: DisplayFormat::B8g8r8a8,
        bytes_per_pixel: 4,
        power_states: (1 << DisplayPowerState::Active as u32)
            | (1 << DisplayPowerState::Idle as u32),
        resume_latency_us: 1000,
        vendor: 0,
        vendor_namespace: 0,
        vendor_extension_version: 0,
        reserved: 0,
    };
    let mut bytes = [0u8; DisplayDescribeReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<DisplayDescribeReply>(&bytes).expect("decode");
    assert_eq!(back, value);
    assert_eq!(back.features & DisplayFeature::CURSOR.0, 0);
    // A client can work out where it is writing without knowing what the
    // format enum means.
    assert_eq!(back.bytes_per_pixel, 4);
    assert_eq!(DisplayFormat::B8g8r8a8 as u32, 0);
}

/// **Nothing is visible until a flush**, and the two are separate methods. A
/// contract that folded them together would leave a client unable to build a
/// frame before showing any of it — and would make a driver that wrote pixels
/// and never showed them indistinguishable from one that works.
#[test]
fn writing_pixels_and_showing_them_are_different_calls() {
    assert_eq!(DisplayOutput::BLIT, 2);
    assert_eq!(DisplayOutput::FLUSH, 3);
    assert_ne!(DisplayOutput::BLIT, DisplayOutput::FLUSH);

    let mut request = DisplayBlitRequest {
        size: DisplayBlitRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        x: 4,
        y: 8,
        count: 16,
        reserved: 0,
        pixels: [0u8; 64],
    };
    request.pixels[0] = 0xff;
    let mut bytes = [0u8; DisplayBlitRequest::WIRE_SIZE];
    encode(&request, &mut bytes).expect("encode");
    assert_eq!(
        decode::<DisplayBlitRequest>(&bytes).expect("decode"),
        request
    );

    // A flush names a rectangle and carries no pixels at all: it moves nothing.
    let flush = DisplayRectRequest {
        size: DisplayRectRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        x: 0,
        y: 0,
        width: 1280,
        height: 800,
    };
    let mut bytes = [0u8; DisplayRectRequest::WIRE_SIZE];
    encode(&flush, &mut bytes).expect("encode");
    assert_eq!(decode::<DisplayRectRequest>(&bytes).expect("decode"), flush);
}

/// **`written` is authoritative.** A client that assumed the whole run landed
/// would draw the rest of its row one place to the left and see a picture that
/// is almost right, which is worse to debug than one that is obviously wrong.
#[test]
fn a_partial_blit_says_how_many_pixels_it_placed() {
    let value = DisplayBlitReply {
        size: DisplayBlitReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: DisplayError::Ok,
        written: 9,
    };
    let mut bytes = [0u8; DisplayBlitReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<DisplayBlitReply>(&bytes).expect("decode");
    assert_eq!(back.written, 9, "nine of the sixteen asked for");

    // **Refused rather than clipped.** A client whose request was quietly
    // trimmed would see a picture it did not compose and have nothing to check.
    let refused = DisplayBlitReply {
        status: DisplayError::OutOfBounds,
        written: 0,
        ..value
    };
    let mut bytes = [0u8; DisplayBlitReply::WIRE_SIZE];
    encode(&refused, &mut bytes).expect("encode");
    let back = decode::<DisplayBlitReply>(&bytes).expect("decode");
    assert_eq!(back.status, DisplayError::OutOfBounds);
    assert_eq!(back.written, 0);
}

#[test]
fn the_ordinals_and_the_remaining_payloads_are_stable() {
    assert_eq!(DisplayOutput::DESCRIBE, 1);
    assert_eq!(DisplayOutput::FILL, 4);
    assert_eq!(DisplayOutput::RESET, 5);
    assert_eq!(DisplayOutput::SET_POWER, 6);
    assert_eq!(DisplayOutput::SET_CURSOR, 7);
    assert_eq!(DisplayOutput::ON_MODE_CHANGED, 20);
    assert_eq!(DisplayOutput::ON_DEVICE_GONE, 22);

    let request = DisplayControlRequest {
        size: DisplayControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: DisplayPowerState::Active,
        reserved: 0,
    };
    let mut bytes = [0u8; DisplayControlRequest::WIRE_SIZE];
    encode(&request, &mut bytes).expect("encode");
    assert_eq!(
        decode::<DisplayControlRequest>(&bytes).expect("decode"),
        request
    );

    let reply = DisplayControlReply {
        size: DisplayControlReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        // A display with nothing attached: a state, not a fault.
        status: DisplayError::NoScanout,
        state: DisplayPowerState::Active,
    };
    let mut bytes = [0u8; DisplayControlReply::WIRE_SIZE];
    encode(&reply, &mut bytes).expect("encode");
    assert_eq!(
        decode::<DisplayControlReply>(&bytes).expect("decode"),
        reply
    );

    let fill = DisplayFillRequest {
        size: DisplayFillRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        x: 0,
        y: 0,
        width: 32,
        height: 32,
        colour: 0xff20_40a0,
        reserved: 0,
    };
    let mut bytes = [0u8; DisplayFillRequest::WIRE_SIZE];
    encode(&fill, &mut bytes).expect("encode");
    assert_eq!(decode::<DisplayFillRequest>(&bytes).expect("decode"), fill);

    let event = DisplayEvent {
        size: DisplayEvent::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        // The only event here with an effect outside the machine.
        trace_point: DisplayTracePoint::Flushed,
        status: DisplayError::Ok,
        reserved: 0,
    };
    let mut bytes = [0u8; DisplayEvent::WIRE_SIZE];
    encode(&event, &mut bytes).expect("encode");
    assert_eq!(decode::<DisplayEvent>(&bytes).expect("decode"), event);
    assert_eq!(DisplayTracePoint::BlitWritten as u32, 1);
    assert_eq!(DisplayTracePoint::PowerChanged as u32, 4);
}
