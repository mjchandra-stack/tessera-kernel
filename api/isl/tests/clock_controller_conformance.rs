// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the clock controller class contract's ABI structs.
//!
//! As with the other two classes, this is the ABI test and deliberately not the
//! class-conformance suite: what is checked here is that the bytes are what the
//! schema says. Whether a *driver* honours the contract lives in
//! `//api/class-conformance`.
//!
//! Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
//! ("Clock Controller"), docs/api/03-interface-schema-language.md

use clock_controller::{
    ClockError, ClockFeature, ClockPowerState, ClockRateReply, ClockRateRequest, ClockRequest,
    ClockTracePoint,
};
use tessera_isl_runtime::{decode, encode};

/// **The error set is numbered to the framework's discipline, not to this
/// class's convenience.** `NOT_SUPPORTED` at 5, `PROTOCOL` at 6, `DEGRADED` at
/// 7 and `REMOVED` at 8 on every class, so the rules that read those values
/// read them the same way wherever they run — which is what lets one
/// conformance suite judge three contracts. What differs is 1 through 4, and
/// that difference is what a class *is*.
#[test]
fn the_error_set_shares_the_frameworks_numbering() {
    assert_eq!(ClockError::Ok as u32, 0);
    assert_eq!(ClockError::BadRate as u32, 1);
    assert_eq!(ClockError::NoSuchClock as u32, 2);
    assert_eq!(ClockError::Critical as u32, 3);
    assert_eq!(ClockError::Busy as u32, 4);
    // The four the framework reads identically on every class.
    assert_eq!(ClockError::NotSupported as u32, 5);
    assert_eq!(ClockError::Protocol as u32, 6);
    assert_eq!(ClockError::Degraded as u32, 7);
    assert_eq!(ClockError::Removed as u32, 8);
}

/// The same four power-state names as the block and network classes. A power
/// manager arbitrates across every device on the machine and cannot do that
/// against a per-class vocabulary.
#[test]
fn the_power_states_share_the_other_classes_vocabulary() {
    assert_eq!(ClockPowerState::Active as u32, 1);
    assert_eq!(ClockPowerState::Idle as u32, 2);
    assert_eq!(ClockPowerState::Standby as u32, 3);
    assert_eq!(ClockPowerState::Off as u32, 4);
}

/// **What a consumer needs before it asks, rather than by being told no.** The
/// reply carries the range, whether the clock is critical, and how many
/// consumers hold it on — so a consumer can tell "my disable will not stop this
/// clock" from "my request failed", which are different facts with different
/// responses.
#[test]
fn a_rate_reply_says_what_may_be_asked_and_who_is_holding() {
    let value = ClockRateReply {
        size: ClockRateReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: ClockError::Ok as u32,
        critical: 0,
        rate_hz: 400_000,
        min_hz: 400_000,
        max_hz: 50_000_000,
        holders: 2,
        reserved: 0,
    };
    let mut buf = [0u8; ClockRateReply::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    let decoded: ClockRateReply = decode(&buf).unwrap();
    assert_eq!(decoded, value);
    assert_eq!(decoded.holders, 2, "somebody else wants this clock too");
}

#[test]
fn a_rate_request_round_trips() {
    let value = ClockRateRequest {
        size: ClockRateRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        clock: 3,
        reserved: 0,
        rate_hz: 25_000_000,
    };
    let mut buf = [0u8; ClockRateRequest::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    assert_eq!(decode::<ClockRateRequest>(&buf).unwrap(), value);
}

/// The optional methods are gated by bits, and the bits are ABI. A fixed clock
/// implements no `SetRate`; a controller whose every clock is critical
/// implements no `Disable` — and saying so once beats answering `CRITICAL` to
/// each in turn.
#[test]
fn the_feature_bits_are_stable() {
    assert_eq!(ClockFeature::SET_RATE.bits(), 0x1);
    assert_eq!(ClockFeature::DISABLE.bits(), 0x2);
    assert_eq!(ClockFeature::MUX.bits(), 0x4);
}

/// The trace points a conformant driver emits, including the refusal: a rate
/// this controller would not produce is the event somebody debugging a device
/// running at the wrong speed needs, and it is the one a driver is most likely
/// to leave unrecorded.
#[test]
fn the_trace_points_are_stable() {
    assert_eq!(ClockTracePoint::Enabled as u32, 1);
    assert_eq!(ClockTracePoint::Disabled as u32, 2);
    assert_eq!(ClockTracePoint::RateChanged as u32, 3);
    assert_eq!(ClockTracePoint::RateRefused as u32, 4);
    assert_eq!(ClockTracePoint::ControllerReset as u32, 6);
}

/// A clock id the schema carries is a plain number and a request naming one is
/// well-formed whatever it says — the contract answers `NO_SUCH_CLOCK` rather
/// than refusing to decode. That is deliberate: a controller's clock count is
/// discovered, so a consumer walking past the end is an ordinary outcome and
/// not a protocol violation.
#[test]
fn a_request_for_a_clock_that_may_not_exist_still_decodes() {
    let value = ClockRequest {
        size: ClockRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        clock: u32::MAX,
        parent: 0,
    };
    let mut buf = [0u8; ClockRequest::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    assert_eq!(decode::<ClockRequest>(&buf).unwrap(), value);
}
