// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Golden vectors for the diagnostic contract.
//!
//! Hand-spelled bytes rather than a round trip through the codec. A round trip
//! proves the encoder and the decoder agree with each other, which they would
//! even if both moved a field; these bytes are what the collector on the other
//! end of the channel will actually be handed.

use diagnostic::{Diagnostic, DiagnosticIncoming, DiagnosticRecord, Severity};
use tessera_isl_runtime::{Reader, WireDecode, WireEncode, WireError, Writer};

/// `Report(ERROR, "no")` — the smallest record that carries anything.
const REPORT: [u8; DiagnosticRecord::WIRE_SIZE] = {
    let mut bytes = [0u8; DiagnosticRecord::WIRE_SIZE];
    bytes[0] = DiagnosticRecord::WIRE_SIZE as u8;
    bytes[1] = (DiagnosticRecord::WIRE_SIZE >> 8) as u8;
    bytes[4] = 1; // version
    // flags: 8 bytes of zero at 8..16
    bytes[16] = 1; // severity: ERROR
    bytes[20] = 2; // len
    // truncated at 24..28, reserved at 28..32, both zero
    bytes[32] = b'n';
    bytes[33] = b'o';
    bytes
};

#[test]
fn a_record_encodes_to_its_golden_bytes() {
    let mut text = [0u8; 192];
    text[..2].copy_from_slice(b"no");
    let record = DiagnosticRecord {
        size: DiagnosticRecord::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        severity: Severity::Error,
        len: 2,
        truncated: 0,
        reserved: 0,
        text,
    };
    let mut out = [0u8; DiagnosticRecord::WIRE_SIZE];
    record
        .encode(&mut Writer::new(&mut out))
        .expect("encodes into its own width");
    assert_eq!(out, REPORT);
}

#[test]
fn the_golden_bytes_decode_to_the_record() {
    let record = DiagnosticRecord::decode(&mut Reader::new(&REPORT)).expect("decodes");
    assert_eq!(record.severity, Severity::Error);
    assert_eq!(record.len, 2);
    assert_eq!(record.truncated, 0);
    assert_eq!(&record.text[..2], b"no");
}

/// The width is ABI. 224 bytes: a 16-byte envelope, four words of severity,
/// length, truncation and reserve, and 192 bytes of text.
#[test]
fn the_record_is_the_width_the_contract_declares() {
    assert_eq!(DiagnosticRecord::WIRE_SIZE, 224);
}

/// Ordinals are ABI. A renumbering is a different contract wearing this one's
/// name, so they are spelled out rather than derived.
#[test]
fn the_ordinals_are_what_they_were() {
    assert_eq!(Diagnostic::REPORT, 1);
    assert_eq!(Diagnostic::CLOSE, 2);
}

/// The severities are a closed set and their values are the wire.
#[test]
fn the_severities_are_what_they_were() {
    assert_eq!(Severity::Error as u32, 1);
    assert_eq!(Severity::Warning as u32, 2);
    assert_eq!(Severity::Info as u32, 3);
}

/// A severity the sender invented is refused rather than mapped onto one this
/// reader happens to know. A collector that silently read an unknown level as
/// `INFO` would drop exactly the records that mattered.
#[test]
fn an_unknown_severity_is_refused() {
    let mut bytes = REPORT;
    bytes[16] = 9;
    let err = DiagnosticRecord::decode(&mut Reader::new(&bytes)).expect_err("unknown severity");
    assert_eq!(err, WireError::BadEnum);
}

/// `Close` carries no payload, which is what lets a sender spell it with a zero
/// length and no buffer at all.
#[test]
fn close_decodes_from_an_empty_payload() {
    let incoming =
        DiagnosticIncoming::decode(Diagnostic::CLOSE, &mut Reader::new(&[])).expect("close");
    assert_eq!(incoming, DiagnosticIncoming::Close);
}

/// A method neither side implements is `UnknownMethod`, not a guess at the
/// nearest one.
#[test]
fn an_unknown_method_is_refused() {
    let err = DiagnosticIncoming::decode(7, &mut Reader::new(&REPORT)).expect_err("unknown method");
    assert_eq!(err, WireError::UnknownMethod);
}

#[test]
fn a_truncated_record_is_short_buffer_rather_than_a_guess() {
    let err = DiagnosticRecord::decode(&mut Reader::new(&REPORT[..16])).expect_err("short");
    assert_eq!(err, WireError::ShortBuffer);
}
