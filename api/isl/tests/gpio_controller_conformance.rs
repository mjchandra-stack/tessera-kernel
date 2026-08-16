// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the GPIO controller class contract's ABI structs.
//!
//! As with the other four classes, this is the ABI test and deliberately not
//! the class-conformance suite: what is checked here is that the bytes are what
//! the schema says. Whether a *driver* honours the contract lives in
//! `//api/class-conformance`.
//!
//! Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
//! ("GPIO And Pin Control"), docs/api/03-interface-schema-language.md

use gpio_controller::{
    GpioBias, GpioConfigRequest, GpioControlReply, GpioController, GpioDescribeReply,
    GpioDirection, GpioElectricalRequest, GpioError, GpioEvent, GpioFeature, GpioLevelReply,
    GpioLevelRequest, GpioLineRequest, GpioPowerState, GpioTracePoint, GpioTrigger,
};
use tessera_isl_runtime::{decode, encode};

/// **The error set is numbered to the framework's discipline, not to this
/// class's convenience.** `NOT_SUPPORTED` at 5, `PROTOCOL` at 6, `DEGRADED` at
/// 7 and `REMOVED` at 8 on every class, so the rules that read those values
/// read them the same way wherever they run. What differs is 1 through 4, and
/// that difference is what a class *is*.
#[test]
fn the_error_set_shares_the_frameworks_numbering() {
    assert_eq!(GpioError::Ok as u32, 0);
    assert_eq!(GpioError::NoSuchLine as u32, 1);
    assert_eq!(GpioError::BadConfig as u32, 2);
    assert_eq!(GpioError::LineBusy as u32, 3);
    assert_eq!(GpioError::WrongDirection as u32, 4);
    assert_eq!(GpioError::NotSupported as u32, 5);
    assert_eq!(GpioError::Protocol as u32, 6);
    assert_eq!(GpioError::Degraded as u32, 7);
    assert_eq!(GpioError::Removed as u32, 8);
}

/// The same four power-state names as the other four classes. A power manager
/// arbitrates across every device on the machine and cannot do that against a
/// per-class vocabulary.
#[test]
fn the_power_states_share_the_other_classes_vocabulary() {
    assert_eq!(GpioPowerState::Active as u32, 1);
    assert_eq!(GpioPowerState::Idle as u32, 2);
    assert_eq!(GpioPowerState::Standby as u32, 3);
    assert_eq!(GpioPowerState::Off as u32, 4);
}

/// **A trigger is one value across what is three registers on the hardware.**
/// A contract that let a client set sense, both-edges and event separately
/// would let it ask for a combination that has no meaning — both-edges on a
/// level-sensed line — and get one that does.
#[test]
fn a_trigger_is_one_value_and_not_having_one_is_a_value_too() {
    assert_eq!(GpioTrigger::None as u32, 0);
    assert_eq!(GpioTrigger::RisingEdge as u32, 1);
    assert_eq!(GpioTrigger::FallingEdge as u32, 2);
    assert_eq!(GpioTrigger::BothEdges as u32, 3);
    assert_eq!(GpioTrigger::HighLevel as u32, 4);
    assert_eq!(GpioTrigger::LowLevel as u32, 5);

    let value = GpioConfigRequest {
        size: GpioConfigRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        line: 3,
        direction: GpioDirection::Input,
        // A line configured for reading, which is a real answer rather than an
        // absent field.
        trigger: GpioTrigger::None,
        reserved: 0,
    };
    let mut bytes = [0u8; GpioConfigRequest::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    assert_eq!(decode::<GpioConfigRequest>(&bytes).expect("decode"), value);
}

/// `Describe` reports the line count, because a client that guessed it would be
/// a client that works on one part.
#[test]
fn describe_reports_how_many_lines_there_are() {
    let value = GpioDescribeReply {
        size: GpioDescribeReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        contract_version: 1,
        status: GpioError::Ok,
        // A PL061: it drives and it interrupts, and it has no bias or drive
        // strength at all — which is the contract working rather than a gap.
        features: GpioFeature::OUTPUT.0 | GpioFeature::INTERRUPTS.0,
        line_count: 8,
        vendor: 0,
        part: 0x061,
        power_states: (1 << GpioPowerState::Active as u32) | (1 << GpioPowerState::Idle as u32),
        resume_latency_us: 1000,
        vendor_namespace: 0,
        vendor_extension_version: 0,
        reserved: 0,
    };
    let mut bytes = [0u8; GpioDescribeReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<GpioDescribeReply>(&bytes).expect("decode");
    assert_eq!(back, value);
    assert_eq!(back.line_count, 8);
    assert_eq!(
        back.features & GpioFeature::ELECTRICAL.0,
        0,
        "and it says what it cannot do",
    );
}

/// A level is a request and a reply, and the reply carries the line it is
/// about — a client with several lines outstanding would otherwise have to
/// remember which answer belongs to which.
#[test]
fn a_level_round_trips_with_the_line_it_is_about() {
    let request = GpioLevelRequest {
        size: GpioLevelRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        line: 5,
        level: 1,
    };
    let mut bytes = [0u8; GpioLevelRequest::WIRE_SIZE];
    encode(&request, &mut bytes).expect("encode");
    assert_eq!(decode::<GpioLevelRequest>(&bytes).expect("decode"), request);

    let reply = GpioLevelReply {
        size: GpioLevelReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: GpioError::Ok,
        line: 5,
        level: 0,
        reserved: 0,
    };
    let mut bytes = [0u8; GpioLevelReply::WIRE_SIZE];
    encode(&reply, &mut bytes).expect("encode");
    assert_eq!(decode::<GpioLevelReply>(&bytes).expect("decode"), reply);
}

/// The electrical request exists so a controller that has none of it can answer
/// `NOT_SUPPORTED` rather than the contract pretending every part is alike.
#[test]
fn the_electrical_request_round_trips() {
    let value = GpioElectricalRequest {
        size: GpioElectricalRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        line: 2,
        bias: GpioBias::PullUp,
        drive_ma: 0,
        reserved: 0,
    };
    let mut bytes = [0u8; GpioElectricalRequest::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    assert_eq!(
        decode::<GpioElectricalRequest>(&bytes).expect("decode"),
        value
    );
    assert_eq!(GpioBias::Float as u32, 0);
    assert_eq!(GpioBias::PullDown as u32, 2);
}

/// **The ordinals, and the one that is not there.** There is no line-changed
/// event: an edge is delivered as the interrupt object `WatchLine` handed over,
/// and an event beside it would be a second, weaker path to the same news — one
/// every holder of the contract would receive rather than only the client that
/// was granted the line.
#[test]
fn the_ordinals_are_stable_and_there_is_no_line_changed_event() {
    assert_eq!(GpioController::DESCRIBE, 1);
    assert_eq!(GpioController::CONFIGURE_LINE, 2);
    assert_eq!(GpioController::READ, 3);
    assert_eq!(GpioController::WRITE, 4);
    assert_eq!(GpioController::RESET, 5);
    assert_eq!(GpioController::SET_POWER, 6);
    assert_eq!(GpioController::WATCH_LINE, 7);
    assert_eq!(GpioController::RELEASE_LINE, 8);
    assert_eq!(GpioController::SET_ELECTRICAL, 9);
    assert_eq!(GpioController::ON_ERROR, 20);
    assert_eq!(GpioController::ON_DEVICE_GONE, 21);
}

#[test]
fn the_control_pair_and_the_events_round_trip() {
    let reply = GpioControlReply {
        size: GpioControlReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: GpioError::LineBusy,
        state: GpioPowerState::Active,
    };
    let mut bytes = [0u8; GpioControlReply::WIRE_SIZE];
    encode(&reply, &mut bytes).expect("encode");
    assert_eq!(decode::<GpioControlReply>(&bytes).expect("decode"), reply);

    let line = GpioLineRequest {
        size: GpioLineRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        line: 3,
        reserved: 0,
    };
    let mut bytes = [0u8; GpioLineRequest::WIRE_SIZE];
    encode(&line, &mut bytes).expect("encode");
    assert_eq!(decode::<GpioLineRequest>(&bytes).expect("decode"), line);

    let event = GpioEvent {
        size: GpioEvent::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        // The moment one hardware interrupt becomes one client's, and the only
        // place that mapping is visible.
        trace_point: GpioTracePoint::InterruptDelivered,
        status: GpioError::Ok,
        line: 3,
        reserved: 0,
    };
    let mut bytes = [0u8; GpioEvent::WIRE_SIZE];
    encode(&event, &mut bytes).expect("encode");
    assert_eq!(decode::<GpioEvent>(&bytes).expect("decode"), event);
    assert_eq!(GpioTracePoint::LineConfigured as u32, 1);
    assert_eq!(GpioTracePoint::PowerChanged as u32, 5);
}
