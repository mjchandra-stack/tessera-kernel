// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated firmware-loading ABI (built by the
//! codegen genrule from `examples/firmware.isl`, never committed). Proves
//! `FirmwareLoadArgs` and `FirmwareReport` encode to fixed golden layouts and
//! decode back.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format"),
//! docs/drivers/01-driver-framework.md ("Firmware Loading")

use firmware_abi::{FirmwareLoadArgs, FirmwareRefusal, FirmwareReport};
use tessera_isl_runtime::{HandleRef, WireError, decode, encode};

/// Golden encoding of the request below: 64 bytes, LE.
const ARGS_GOLDEN: [u8; 64] = [
    0x40, 0, 0, 0, // size = 64
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x03, 0, 0, 0, // device = handle 3
    0x02, 0, 0, 0, // min_image_version = 2
    // name = "firmware.bin", NUL-padded to 24
    0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x2e, 0x62, 0x69, 0x6e, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, //
    0, 0, 0, 0, // reserved = 0
    0, 0, 0, 0, // padding to the report pointer's 8-byte alignment
    0x00, 0x10, 0, 0, 0, 0, 0, 0, // report_ptr = 0x1000
];

/// Golden encoding of the report below: 72 bytes, LE.
///
/// A **refused** report, deliberately: the kernel writes one on both paths, and
/// the fields a refusal fills in are the ones somebody needs to explain it. The
/// svn is present and below a floor of 5, which is the number that has to be
/// comparable against the floor for the refusal to mean anything.
const REPORT_GOLDEN: [u8; 72] = [
    0x48, 0, 0, 0, // size = 72
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x01, 0, 0, 0, // refusal = RollbackBlocked
    0x02, 0, 0, 0, // svn = 2
    0x03, 0, 0, 0, // image_version = 3
    0, 0, 0, 0, // reserved = 0
    0x00, 0x04, 0, 0, 0, 0, 0, 0, // length = 1024
    // digest = 0x20, 0x21, ... 0x3f
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

fn golden_args() -> FirmwareLoadArgs {
    let mut name = [0u8; 24];
    name[..12].copy_from_slice(b"firmware.bin");
    FirmwareLoadArgs {
        size: 64,
        version: 1,
        flags: 0,
        device: HandleRef::new(3),
        min_image_version: 2,
        name,
        reserved: 0,
        report_ptr: 0x1000,
    }
}

fn golden_report() -> FirmwareReport {
    let mut digest = [0u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = 0x20 + i as u8;
    }
    FirmwareReport {
        size: 72,
        version: 1,
        flags: 0,
        refusal: FirmwareRefusal::RollbackBlocked,
        svn: 2,
        image_version: 3,
        reserved: 0,
        length: 1024,
        digest,
    }
}

#[test]
fn args_match_golden_and_round_trip() {
    assert_eq!(FirmwareLoadArgs::WIRE_SIZE, 64);
    let mut bytes = [0u8; 64];
    assert_eq!(encode(&golden_args(), &mut bytes).expect("encode"), 64);
    assert_eq!(bytes, ARGS_GOLDEN);
    assert_eq!(
        decode::<FirmwareLoadArgs>(&ARGS_GOLDEN).expect("decode"),
        golden_args()
    );
}

#[test]
fn report_matches_golden_and_round_trips() {
    assert_eq!(FirmwareReport::WIRE_SIZE, 72);
    let mut bytes = [0u8; 72];
    assert_eq!(encode(&golden_report(), &mut bytes).expect("encode"), 72);
    assert_eq!(bytes, REPORT_GOLDEN);
    assert_eq!(
        decode::<FirmwareReport>(&REPORT_GOLDEN).expect("decode"),
        golden_report()
    );
}

/// A refusal value outside the schema is refused rather than decoded into one
/// that exists. The two refusals mean different conversations, and a third
/// silently becoming one of them would send somebody to the wrong one.
#[test]
fn an_unknown_refusal_is_refused() {
    let mut bytes = REPORT_GOLDEN;
    bytes[16] = 0x09;
    assert_eq!(decode::<FirmwareReport>(&bytes), Err(WireError::BadEnum));
}

/// `None` is a legal value and means the load succeeded — a report is readable
/// without also holding the syscall's return value.
#[test]
fn a_successful_report_carries_no_refusal() {
    let mut bytes = REPORT_GOLDEN;
    bytes[16] = 0x00;
    let report = decode::<FirmwareReport>(&bytes).expect("decode");
    assert_eq!(report.refusal, FirmwareRefusal::None);
}
