// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wire conformance for the crypto service class contract's ABI structs.
//!
//! The ABI test, and deliberately not the class-conformance suite: what is
//! checked here is that the bytes are what the schema says.
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Crypto Agility"), docs/api/03-interface-schema-language.md

use crypto_service::{
    CryptoAlgorithm, CryptoControlReply, CryptoControlRequest, CryptoDataReply, CryptoDataRequest,
    CryptoDescribeReply, CryptoError, CryptoEvent, CryptoFeature, CryptoPowerState, CryptoService,
    CryptoSessionReply, CryptoSessionRequest, CryptoTracePoint,
};
use tessera_isl_runtime::{decode, encode};

/// **The error set is numbered to the framework's discipline.** `NOT_SUPPORTED`
/// at 5, `PROTOCOL` at 6, `DEGRADED` at 7 and `REMOVED` at 8 on every class.
/// What differs is 1 through 4, and that difference is what a class *is*.
#[test]
fn the_error_set_shares_the_frameworks_numbering() {
    assert_eq!(CryptoError::Ok as u32, 0);
    assert_eq!(CryptoError::NoSession as u32, 1);
    assert_eq!(CryptoError::BadKeyLength as u32, 2);
    assert_eq!(CryptoError::BadDataLength as u32, 3);
    assert_eq!(CryptoError::KeyRejected as u32, 4);
    assert_eq!(CryptoError::NotSupported as u32, 5);
    assert_eq!(CryptoError::Protocol as u32, 6);
    assert_eq!(CryptoError::Degraded as u32, 7);
    assert_eq!(CryptoError::Removed as u32, 8);
}

/// The same four power-state names as the seven classes before it.
#[test]
fn the_power_states_share_the_other_classes_vocabulary() {
    assert_eq!(CryptoPowerState::Active as u32, 1);
    assert_eq!(CryptoPowerState::Idle as u32, 2);
    assert_eq!(CryptoPowerState::Standby as u32, 3);
    assert_eq!(CryptoPowerState::Off as u32, 4);
}

/// **Zero names no algorithm.** A request that arrived zeroed, or a field a
/// client forgot to fill, must not be the first algorithm in the list by
/// accident — which is precisely how an algorithm gets implied by position.
#[test]
fn a_zeroed_request_names_no_algorithm() {
    assert_eq!(CryptoAlgorithm::None as u32, 0);
    let blank = [0u8; CryptoDataRequest::WIRE_SIZE];
    let request = decode::<CryptoDataRequest>(&blank).expect("a zeroed request decodes");
    assert_eq!(
        request.algorithm,
        CryptoAlgorithm::None,
        "no cipher is the default cipher"
    );
}

/// `Describe` reports the algorithms there **are**, so a client learns what this
/// machine can do before it holds a key rather than by being refused.
#[test]
fn describe_reports_the_algorithms_that_exist() {
    let value = CryptoDescribeReply {
        size: CryptoDescribeReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        contract_version: 1,
        status: CryptoError::Ok,
        // It decrypts as well as encrypting, and holds one session at a time.
        features: CryptoFeature::DECRYPT.0,
        algorithms: 1 << (CryptoAlgorithm::Aes128Cbc as u32),
        max_key_bytes: 32,
        max_data_bytes: 64,
        max_sessions: 1,
        power_states: 0b1111,
        resume_latency_us: 0,
        vendor: 0,
        vendor_namespace: 0,
        vendor_extension_version: 0,
        reserved: 0,
    };
    let mut bytes = [0u8; CryptoDescribeReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<CryptoDescribeReply>(&bytes).expect("decode");
    assert_eq!(back, value);
    assert_eq!(
        back.features & CryptoFeature::MULTIPLE_SESSIONS.0,
        0,
        "one session at a time is a real shape and the bit says so"
    );
}

/// **A key length is a field, not a delimiter**, and so is an IV's. A key is
/// arbitrary bytes and may contain any value, zero included; a driver that
/// stopped at the first zero would install a shorter key than the client gave
/// it and encrypt successfully with the wrong one.
#[test]
fn the_key_and_iv_lengths_are_fields() {
    let mut key = [0u8; 32];
    key[0] = 0x2b;
    // A zero in the middle of a 16-byte key, deliberately.
    key[5] = 0x00;
    key[15] = 0x3c;
    let value = CryptoSessionRequest {
        size: CryptoSessionRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        algorithm: CryptoAlgorithm::Aes128Cbc,
        encrypt: 1,
        key_len: 16,
        iv_len: 16,
        key,
        iv: [0x0fu8; 16],
    };
    let mut bytes = [0u8; CryptoSessionRequest::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<CryptoSessionRequest>(&bytes).expect("decode");
    assert_eq!(back, value);
    assert_eq!(back.key_len, 16, "sixteen bytes, one of which is zero");
    assert_eq!(back.key[5], 0, "and it survived the round trip");
}

/// The session id is the only thing that names a key after `CreateSession`, and
/// **no reply carries key material**. Checked by construction: there is nowhere
/// in the reply to put any.
#[test]
fn a_session_reply_names_a_key_without_carrying_one() {
    let value = CryptoSessionReply {
        size: CryptoSessionReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: CryptoError::Ok,
        reserved: 0,
        session: 0x1234_5678_9abc_def0,
    };
    let mut bytes = [0u8; CryptoSessionReply::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    assert_eq!(decode::<CryptoSessionReply>(&bytes).expect("decode"), value);
    assert_eq!(
        CryptoSessionReply::WIRE_SIZE,
        32,
        "a header, a status and an id — and no room for a key"
    );
}

/// **Every operation names its algorithm**, redundantly with the session's, so
/// that a substitution is detectable instead of silent.
#[test]
fn every_operation_names_its_algorithm() {
    let value = CryptoDataRequest {
        size: CryptoDataRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        session: 9,
        algorithm: CryptoAlgorithm::Aes128Cbc,
        len: 32,
        data: [0x6bu8; 64],
    };
    let mut bytes = [0u8; CryptoDataRequest::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    let back = decode::<CryptoDataRequest>(&bytes).expect("decode");
    assert_eq!(back, value);
    assert_eq!(back.algorithm, CryptoAlgorithm::Aes128Cbc);

    // A cipher's output is exactly as long as its input, and the reply says how
    // long it was rather than leaving the client to assume.
    let reply = CryptoDataReply {
        size: CryptoDataReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: CryptoError::Ok,
        len: 32,
        data: [0x76u8; 64],
    };
    let mut bytes = [0u8; CryptoDataReply::WIRE_SIZE];
    encode(&reply, &mut bytes).expect("encode");
    assert_eq!(decode::<CryptoDataReply>(&bytes).expect("decode"), reply);
}

/// A trace carries the session, the algorithm and the status — and **nothing
/// that was protected**. There is no field here for a key or for plaintext, and
/// that is the check.
#[test]
fn a_trace_event_carries_no_secret() {
    let value = CryptoEvent {
        size: CryptoEvent::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        trace_point: CryptoTracePoint::AlgorithmRefused,
        status: CryptoError::NotSupported,
        algorithm: CryptoAlgorithm::Aes256Cbc,
        session: 0,
    };
    let mut bytes = [0u8; CryptoEvent::WIRE_SIZE];
    encode(&value, &mut bytes).expect("encode");
    assert_eq!(decode::<CryptoEvent>(&bytes).expect("decode"), value);
    assert_eq!(
        CryptoEvent::WIRE_SIZE,
        40,
        "a header, three enums and an id — and no room for anything protected"
    );
}

/// The ordinals, and the reserved gap before the events.
#[test]
fn the_protocol_ordinals_are_where_the_framework_puts_them() {
    assert_eq!(CryptoService::DESCRIBE, 1);
    assert_eq!(CryptoService::CREATE_SESSION, 2);
    assert_eq!(CryptoService::ENCRYPT, 3);
    assert_eq!(CryptoService::DECRYPT, 4);
    assert_eq!(CryptoService::RESET, 5);
    assert_eq!(CryptoService::SET_POWER, 6);
    assert_eq!(CryptoService::DESTROY_SESSION, 7);
    assert_eq!(CryptoService::SET_IV, 8);
    assert_eq!(CryptoService::ON_SESSION_LOST, 20);
    assert_eq!(CryptoService::ON_ERROR, 21);
    assert_eq!(CryptoService::ON_DEVICE_GONE, 22);
}

/// Control requests and replies are the shape the other seven classes use.
#[test]
fn the_control_pair_matches_the_other_classes() {
    let request = CryptoControlRequest {
        size: CryptoControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: CryptoPowerState::Idle,
        reserved: 0,
    };
    let mut bytes = [0u8; CryptoControlRequest::WIRE_SIZE];
    encode(&request, &mut bytes).expect("encode");
    assert_eq!(
        decode::<CryptoControlRequest>(&bytes).expect("decode"),
        request
    );

    let reply = CryptoControlReply {
        size: CryptoControlReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: CryptoError::Ok,
        state: CryptoPowerState::Active,
    };
    let mut bytes = [0u8; CryptoControlReply::WIRE_SIZE];
    encode(&reply, &mut bytes).expect("encode");
    assert_eq!(decode::<CryptoControlReply>(&bytes).expect("decode"), reply);
}
