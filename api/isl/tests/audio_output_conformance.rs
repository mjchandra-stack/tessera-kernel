// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the audio output class contract's ABI structs.
//!
//! As with the other five classes, this is the ABI test and deliberately not
//! the class-conformance suite: what is checked here is that the bytes are what
//! the schema says. Whether a *driver* honours the contract lives in
//! `//api/class-conformance`.
//!
//! Normative: docs/drivers/03-graphics-display-media-sensors-ai.md ("Audio"),
//! docs/api/03-interface-schema-language.md

use audio_output::{
    AudioConfigRequest, AudioControlReply, AudioControlRequest, AudioDescribeReply, AudioError,
    AudioEvent, AudioFeature, AudioFormat, AudioOutput, AudioPowerState, AudioStatusReply,
    AudioTracePoint, AudioVolumeRequest, AudioWriteReply, AudioWriteRequest,
};
use tessera_isl_runtime::{decode, encode};

/// **The error set is numbered to the framework's discipline.** `NOT_SUPPORTED`
/// at 5, `PROTOCOL` at 6, `DEGRADED` at 7 and `REMOVED` at 8 on every class, so
/// the rules that read those values read them the same way wherever they run.
/// What differs is 1 through 4, and that difference is what a class *is*.
#[test]
fn the_error_set_shares_the_frameworks_numbering() {
    assert_eq!(AudioError::Ok as u32, 0);
    assert_eq!(AudioError::Underrun as u32, 1);
    assert_eq!(AudioError::BadFormat as u32, 2);
    assert_eq!(AudioError::NoStream as u32, 3);
    assert_eq!(AudioError::Busy as u32, 4);
    assert_eq!(AudioError::NotSupported as u32, 5);
    assert_eq!(AudioError::Protocol as u32, 6);
    assert_eq!(AudioError::Degraded as u32, 7);
    assert_eq!(AudioError::Removed as u32, 8);
}

/// The same four power-state names as the other five classes. A power manager
/// arbitrates across every device on the machine and cannot do that against a
/// per-class vocabulary.
#[test]
fn the_power_states_share_the_other_classes_vocabulary() {
    assert_eq!(AudioPowerState::Active as u32, 1);
    assert_eq!(AudioPowerState::Idle as u32, 2);
    assert_eq!(AudioPowerState::Standby as u32, 3);
    assert_eq!(AudioPowerState::Off as u32, 4);
}

/// **A stream that ran dry is still running.** `UNDERRUN` travels as the reply's
/// status on a write that succeeded in every other sense: a client told `OK`
/// would not know a gap was heard, and one told a hard error would tear down a
/// stream that is playing perfectly well now.
#[test]
fn an_underrun_is_a_status_on_a_write_that_otherwise_worked() {
    let value = AudioWriteReply {
        size: AudioWriteReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: AudioError::Underrun,
        // The samples were taken. What is being reported is what happened
        // *before* they arrived.
        accepted: 64,
        outstanding: 1,
        reserved: 0,
    };
    let mut bytes = [0u8; AudioWriteReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<AudioWriteReply>(&bytes).expect("decode");
    assert_eq!(back, value);
    assert_eq!(back.accepted, 64, "and the write still landed");
    assert_ne!(
        back.status,
        AudioError::Degraded,
        "the stream is not unwell"
    );
}

/// **`accepted` is authoritative.** A client that assumed the whole write
/// landed would drift a little further ahead of the device on every call, and
/// would discover it as audio arriving late rather than as an error.
#[test]
fn a_partial_write_says_how_much_it_took() {
    let mut request = AudioWriteRequest {
        size: AudioWriteRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        stream: 0,
        length: 64,
        samples: [0u8; 64],
    };
    request.samples[0] = 0x5a;
    let mut bytes = [0u8; AudioWriteRequest::WIRE_SIZE];
    encode(&request, &mut bytes).expect("encode");
    assert_eq!(
        decode::<AudioWriteRequest>(&bytes).expect("decode"),
        request
    );

    let reply = AudioWriteReply {
        size: AudioWriteReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: AudioError::Busy,
        // The device is full, so none of it was taken — which is the stream
        // working rather than an error to recover from.
        accepted: 0,
        outstanding: 4,
        reserved: 0,
    };
    let mut bytes = [0u8; AudioWriteReply::WIRE_SIZE];
    encode(&reply, &mut bytes).expect("encode");
    let back = decode::<AudioWriteReply>(&bytes).expect("decode");
    assert_eq!(back.accepted, 0);
    assert_eq!(back.status, AudioError::Busy);
}

/// `Describe` says what a client needs before it can keep up: the unit the
/// device consumes and how many of them it will hold. A client that guessed
/// would either starve the device or sit further ahead of it than anybody asked
/// for, and latency nobody chose is what this field prevents.
#[test]
fn describe_says_what_it_takes_to_keep_up() {
    let value = AudioDescribeReply {
        size: AudioDescribeReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        contract_version: 1,
        status: AudioError::Ok,
        // It pauses, it has no mixer, and it does not capture.
        features: AudioFeature::PAUSE.0,
        streams: 1,
        period_bytes: 1024,
        periods: 4,
        channels_max: 2,
        power_states: (1 << AudioPowerState::Active as u32) | (1 << AudioPowerState::Idle as u32),
        resume_latency_us: 1000,
        vendor: 0,
        vendor_namespace: 0,
        vendor_extension_version: 0,
        reserved: 0,
    };
    let mut bytes = [0u8; AudioDescribeReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<AudioDescribeReply>(&bytes).expect("decode");
    assert_eq!(back, value);
    assert_eq!(back.features & AudioFeature::CAPTURE.0, 0);
    assert_eq!(back.features & AudioFeature::VOLUME.0, 0);
}

/// **Zero underruns is a claim, not an absence.** A client is told the count
/// either way, so "it played cleanly" and "nobody was counting" are different
/// answers — which is the whole reason `Status` is a required method.
#[test]
fn a_status_reports_the_gaps_as_a_number_including_none() {
    let clean = AudioStatusReply {
        size: AudioStatusReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: AudioError::Ok,
        stream: 0,
        played: 16,
        underruns: 0,
        outstanding: 4,
        reserved: 0,
    };
    let mut bytes = [0u8; AudioStatusReply::WIRE_SIZE];
    encode(&clean, &mut bytes).expect("encode");
    assert_eq!(decode::<AudioStatusReply>(&bytes).expect("decode"), clean);

    let starved = AudioStatusReply {
        played: 4,
        underruns: 4,
        outstanding: 0,
        ..clean
    };
    let mut bytes = [0u8; AudioStatusReply::WIRE_SIZE];
    encode(&starved, &mut bytes).expect("encode");
    let back = decode::<AudioStatusReply>(&bytes).expect("decode");
    assert_eq!(back.underruns, 4);
    assert_eq!(
        back.status,
        AudioError::Ok,
        "reporting a gap is not failing"
    );
}

/// A rate is a number and a format is an enum, because a device's list of rates
/// is its own and `Describe` is not the place to enumerate every one a codec
/// might have.
#[test]
fn a_configuration_names_a_format_and_a_rate() {
    let value = AudioConfigRequest {
        size: AudioConfigRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        stream: 0,
        channels: 2,
        format: AudioFormat::S16,
        rate: 44100,
    };
    let mut bytes = [0u8; AudioConfigRequest::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    assert_eq!(decode::<AudioConfigRequest>(&bytes).expect("decode"), value);
    assert_eq!(AudioFormat::S16 as u32, 0);
}

#[test]
fn the_ordinals_and_the_remaining_payloads_are_stable() {
    assert_eq!(AudioOutput::DESCRIBE, 1);
    assert_eq!(AudioOutput::CONFIGURE, 2);
    assert_eq!(AudioOutput::START, 3);
    assert_eq!(AudioOutput::WRITE, 4);
    assert_eq!(AudioOutput::RESET, 5);
    assert_eq!(AudioOutput::SET_POWER, 6);
    assert_eq!(AudioOutput::STOP, 7);
    assert_eq!(AudioOutput::STATUS, 8);
    assert_eq!(AudioOutput::SET_VOLUME, 9);
    assert_eq!(AudioOutput::ON_UNDERRUN, 20);
    assert_eq!(AudioOutput::ON_DEVICE_GONE, 22);

    let request = AudioControlRequest {
        size: AudioControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        stream: 0,
        state: AudioPowerState::Active,
    };
    let mut bytes = [0u8; AudioControlRequest::WIRE_SIZE];
    encode(&request, &mut bytes).expect("encode");
    assert_eq!(
        decode::<AudioControlRequest>(&bytes).expect("decode"),
        request
    );

    let reply = AudioControlReply {
        size: AudioControlReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: AudioError::NotSupported,
        state: AudioPowerState::Active,
    };
    let mut bytes = [0u8; AudioControlReply::WIRE_SIZE];
    encode(&reply, &mut bytes).expect("encode");
    assert_eq!(decode::<AudioControlReply>(&bytes).expect("decode"), reply);

    // Attenuation rather than gain, so full scale is zero and the field has no
    // sign to get wrong.
    let volume = AudioVolumeRequest {
        size: AudioVolumeRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        stream: 0,
        attenuation_centibels: 600,
    };
    let mut bytes = [0u8; AudioVolumeRequest::WIRE_SIZE];
    encode(&volume, &mut bytes).expect("encode");
    assert_eq!(
        decode::<AudioVolumeRequest>(&bytes).expect("decode"),
        volume
    );

    let event = AudioEvent {
        size: AudioEvent::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        // The only event here invisible to everything except the driver that
        // saw it.
        trace_point: AudioTracePoint::UnderrunObserved,
        status: AudioError::Underrun,
        stream: 0,
        reserved: 0,
    };
    let mut bytes = [0u8; AudioEvent::WIRE_SIZE];
    encode(&event, &mut bytes).expect("encode");
    assert_eq!(decode::<AudioEvent>(&bytes).expect("decode"), event);
    assert_eq!(AudioTracePoint::StreamConfigured as u32, 1);
    assert_eq!(AudioTracePoint::PowerChanged as u32, 5);
}
