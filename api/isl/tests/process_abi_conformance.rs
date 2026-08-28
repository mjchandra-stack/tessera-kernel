// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated process-lifecycle ABI bindings (built
//! by the codegen genrule from `examples/process_abi.isl`, never committed).
//! Proves each three-phase argument struct round-trips through the canonical
//! wire codec at its fixed size — the ABI a user-space loader / component
//! manager will call (docs/api/01-system-call-interface.md, "Process And
//! Thread"; the in-kernel loader exercises the same path today, D42).
//!
//! Normative: docs/api/01-system-call-interface.md,
//! docs/api/03-interface-schema-language.md ("Wire Format")

use process_abi::{
    AddressSpaceMapArgs, ProcessCreateArgs, ProcessStartArgs, Rights, StartupHandles,
};
use tessera_isl_runtime::{HandleRef, decode, encode};

#[test]
fn wire_sizes_are_stable() {
    assert_eq!(ProcessCreateArgs::WIRE_SIZE, 24);
    assert_eq!(AddressSpaceMapArgs::WIRE_SIZE, 56);
    // 48 before v2 added the startup message's three fields (D261). A wire
    // size is ABI: this number moving is a change every decoder has to know
    // about, which is why the version moved with it and the decoder refuses a
    // v1 struct rather than reading its `arg` as a pointer.
    assert_eq!(ProcessStartArgs::WIRE_SIZE, 72);
    assert_eq!(StartupHandles::WIRE_SIZE, 24);
}

/// The first startup-message payload round-trips.
///
/// **Named slots and no count**, which is the property worth pinning: a count
/// and an array would be a hand-decoded vector, and the count is the only guard
/// against a misparse in one (D101). Two named handle fields cannot be
/// miscounted.
#[test]
fn startup_handles_round_trips() {
    let value = StartupHandles {
        size: StartupHandles::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        endpoint: HandleRef::new(0),
        port: HandleRef::new(1),
    };
    let mut buf = [0u8; StartupHandles::WIRE_SIZE];
    assert_eq!(encode(&value, &mut buf).unwrap(), StartupHandles::WIRE_SIZE);
    assert_eq!(decode::<StartupHandles>(&buf).unwrap(), value);
}

#[test]
fn process_create_round_trips() {
    let value = ProcessCreateArgs {
        size: ProcessCreateArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        job: HandleRef::new(7),
        reserved: 0,
    };
    let mut buf = [0u8; ProcessCreateArgs::WIRE_SIZE];
    assert_eq!(
        encode(&value, &mut buf).unwrap(),
        ProcessCreateArgs::WIRE_SIZE
    );
    assert_eq!(decode::<ProcessCreateArgs>(&buf).unwrap(), value);
}

#[test]
fn address_space_map_round_trips() {
    // A loader placing an executable segment (read + execute, W^X honoured).
    let value = AddressSpaceMapArgs {
        size: AddressSpaceMapArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        process: HandleRef::new(3),
        reserved: 0,
        vaddr: 0x40_0000,
        length: 0x1000,
        rights: Rights(Rights::READ.bits() | Rights::EXECUTE.bits()),
        src: 0x1000_2000,
    };
    let mut buf = [0u8; AddressSpaceMapArgs::WIRE_SIZE];
    assert_eq!(
        encode(&value, &mut buf).unwrap(),
        AddressSpaceMapArgs::WIRE_SIZE
    );
    assert_eq!(decode::<AddressSpaceMapArgs>(&buf).unwrap(), value);
}

#[test]
fn process_start_round_trips() {
    let value = ProcessStartArgs {
        size: ProcessStartArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        process: HandleRef::new(3),
        reserved: 0,
        entry: 0x40_0000,
        stack: 0x7000_0000,
        arg: 0x6000_0000,
        // The startup message: a parent's buffer, its length, and where the
        // child finds it. Non-zero here so the round trip covers the three
        // fields v2 added rather than only their absence.
        message_ptr: 0x5000_0000,
        message_len: 16,
        message_va: 0x6000_0000,
    };
    let mut buf = [0u8; ProcessStartArgs::WIRE_SIZE];
    assert_eq!(
        encode(&value, &mut buf).unwrap(),
        ProcessStartArgs::WIRE_SIZE
    );
    assert_eq!(decode::<ProcessStartArgs>(&buf).unwrap(), value);
}
