// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the input device class contract's ABI structs.
//!
//! As with the other three classes, this is the ABI test and deliberately not
//! the class-conformance suite: what is checked here is that the bytes are what
//! the schema says. Whether a *driver* honours the contract lives in
//! `//api/class-conformance`.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts"),
//! docs/api/03-interface-schema-language.md

use input_device::{
    InputControlReply, InputDescribeReply, InputError, InputPowerState, InputReportReply,
    InputReportRequest, InputTracePoint,
};
use tessera_isl_runtime::{decode, encode};

/// **The error set is numbered to the framework's discipline, not to this
/// class's convenience.** `NOT_SUPPORTED` at 5, `PROTOCOL` at 6, `DEGRADED` at
/// 7 and `REMOVED` at 8 on every class, so the rules that read those values
/// read them the same way wherever they run. What differs is 1 through 4, and
/// that difference is what a class *is*.
#[test]
fn the_error_set_shares_the_frameworks_numbering() {
    assert_eq!(InputError::Ok as u32, 0);
    assert_eq!(InputError::NoReport as u32, 1);
    assert_eq!(InputError::IoError as u32, 2);
    assert_eq!(InputError::BadReportId as u32, 3);
    assert_eq!(InputError::Busy as u32, 4);
    assert_eq!(InputError::NotSupported as u32, 5);
    assert_eq!(InputError::Protocol as u32, 6);
    assert_eq!(InputError::Degraded as u32, 7);
    assert_eq!(InputError::Removed as u32, 8);
}

/// The same four power-state names as the other three classes. A power manager
/// arbitrates across every device on the machine and cannot do that against a
/// per-class vocabulary.
#[test]
fn the_power_states_share_the_other_classes_vocabulary() {
    assert_eq!(InputPowerState::Active as u32, 1);
    assert_eq!(InputPowerState::Idle as u32, 2);
    assert_eq!(InputPowerState::Standby as u32, 3);
    assert_eq!(InputPowerState::Off as u32, 4);
}

/// **"Nothing has happened" is a value, not a failure.** A keyboard nobody is
/// typing on is a working keyboard, and a client that could not tell it from a
/// broken one would report a fault every time the room went quiet.
#[test]
fn an_idle_device_answers_with_a_value_of_its_own() {
    let value = InputReportReply {
        size: InputReportReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: InputError::NoReport,
        report_id: 0,
        length: 0,
        reserved: 0,
        report: [0u8; 64],
    };
    let mut bytes = [0u8; InputReportReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<InputReportReply>(&bytes).expect("decode");
    assert_eq!(back.status, InputError::NoReport);
    assert_ne!(back.status, InputError::IoError, "and not a fault");
}

/// A report carries its own length, because a client that ignored it would read
/// whatever the previous report left in the tail of the buffer.
#[test]
fn a_report_carries_how_much_of_it_is_real() {
    let mut value = InputReportReply {
        size: InputReportReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: InputError::Ok,
        report_id: 0,
        length: 8,
        reserved: 0,
        report: [0u8; 64],
    };
    // A boot keyboard's report: modifiers, a reserved byte, six keycodes.
    value.report[2] = 0x04;
    let mut bytes = [0u8; InputReportReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<InputReportReply>(&bytes).expect("decode");
    assert_eq!(back.length, 8, "eight of the sixty-four");
    assert_eq!(back.report[2], 0x04);
    assert_eq!(decode::<InputReportReply>(&bytes).expect("decode"), value);
}

/// `Describe` reports the device's own vocabulary rather than a translated one.
/// Translating here would mean inventing a taxonomy every non-HID input
/// transport would then have to be forced into.
#[test]
fn describe_reports_the_devices_own_vocabulary() {
    let value = InputDescribeReply {
        size: InputDescribeReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        contract_version: 1,
        status: InputError::Ok,
        features: 0,
        // Boot interface, keyboard.
        subclass: 1,
        protocol: 1,
        max_report_len: 8,
        power_states: (1 << InputPowerState::Active as u32) | (1 << InputPowerState::Idle as u32),
        resume_latency_us: 1000,
        vendor: 0,
        vendor_namespace: 0,
        vendor_extension_version: 0,
        reserved: 0,
    };
    let mut bytes = [0u8; InputDescribeReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    assert_eq!(decode::<InputDescribeReply>(&bytes).expect("decode"), value);
}

#[test]
fn a_control_reply_and_a_set_report_round_trip() {
    let control = InputControlReply {
        size: InputControlReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: InputError::NotSupported,
        state: InputPowerState::Active,
    };
    let mut bytes = [0u8; InputControlReply::WIRE_SIZE];
    encode(&control, &mut bytes).expect("encode");
    assert_eq!(
        decode::<InputControlReply>(&bytes).expect("decode"),
        control
    );

    let request = InputReportRequest {
        size: InputReportRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        report_id: 0,
        length: 1,
        report: [0u8; 64],
    };
    let mut bytes = [0u8; InputReportRequest::WIRE_SIZE];
    encode(&request, &mut bytes).expect("encode");
    assert_eq!(
        decode::<InputReportRequest>(&bytes).expect("decode"),
        request
    );
}

#[test]
fn the_trace_points_are_stable_values() {
    assert_eq!(InputTracePoint::ReportReceived as u32, 1);
    assert_eq!(InputTracePoint::ReportSent as u32, 2);
    assert_eq!(InputTracePoint::DeviceReset as u32, 3);
    assert_eq!(InputTracePoint::PowerChanged as u32, 4);
}
