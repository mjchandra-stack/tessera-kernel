// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated memory-object syscall bindings.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Memory Objects"),
//! docs/api/03-interface-schema-language.md ("Wire Format")

use memory_abi::{DmaAttachArgs, DmaRenewArgs, MapRights, MemoryCreateArgs, MemoryMapArgs};
use tessera_isl_runtime::{HandleRef, decode, encode};

#[test]
fn memory_create_args_round_trip() {
    assert_eq!(MemoryCreateArgs::WIRE_SIZE, 24);
    let value = MemoryCreateArgs {
        size: 24,
        version: 1,
        flags: 0,
        bytes: 4096,
    };
    let mut buf = [0u8; 24];
    assert_eq!(encode(&value, &mut buf).unwrap(), 24);
    assert_eq!(&buf[0..4], &24u32.to_le_bytes());
    assert_eq!(&buf[16..24], &4096u64.to_le_bytes());
    assert_eq!(decode::<MemoryCreateArgs>(&buf).unwrap(), value);
}

#[test]
fn memory_map_args_round_trip() {
    let value = MemoryMapArgs {
        size: MemoryMapArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        memory: HandleRef::new(3),
        rights: MapRights(MapRights::READ.bits() | MapRights::WRITE.bits()),
        vaddr: 0x1000_0000,
    };
    let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    assert_eq!(decode::<MemoryMapArgs>(&buf).unwrap(), value);
}

/// Mapping rights are a distinct, narrow set — only three things mean anything
/// to a page table, and naming them apart from the full Rights catalog is what
/// keeps a caller from asking for TRANSFER on a mapping.
#[test]
fn map_rights_are_the_three_a_page_table_understands() {
    assert_eq!(MapRights::READ.bits(), 0x1);
    assert_eq!(MapRights::WRITE.bits(), 0x2);
    assert_eq!(MapRights::EXECUTE.bits(), 0x4);
}

/// Golden encoding of the renewal request: 32 bytes, LE.
const RENEW_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x03, 0, 0, 0, // device = handle 3
    0, 0, 0, 0, // reserved
    0x64, 0, 0, 0, 0, 0, 0, 0, // ticks = 100
];

#[test]
fn the_renewal_request_matches_its_golden_and_round_trips() {
    assert_eq!(DmaRenewArgs::WIRE_SIZE, 32);
    let value = DmaRenewArgs {
        size: 32,
        version: 1,
        flags: 0,
        device: tessera_isl_runtime::HandleRef::new(3),
        reserved: 0,
        ticks: 100,
    };
    let mut buf = [0u8; 32];
    assert_eq!(encode(&value, &mut buf).unwrap(), 32);
    assert_eq!(buf, RENEW_GOLDEN);
    assert_eq!(decode::<DmaRenewArgs>(&RENEW_GOLDEN).unwrap(), value);
}

/// **Zero ticks is "no deadline", not "expire now".** Every lease taken before
/// expiry existed has one, and reading zero as an immediate deadline would
/// have the mechanism tear down its own users the moment it arrived.
#[test]
fn a_renewal_of_zero_ticks_is_the_absence_of_a_deadline() {
    let mut bytes = RENEW_GOLDEN;
    bytes[24..32].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(decode::<DmaRenewArgs>(&bytes).unwrap().ticks, 0);
}

/// The declared rights on both handle fields are the authority the syscalls
/// check, carried by the contract rather than restated by each caller.
#[test]
fn the_dma_handles_declare_the_authority_they_need() {
    // `MAP` in the kernel's rights catalog, which is what the schema's
    // `handle<Object, {MAP}>` resolves to.
    const MAP: u64 = 0x4;
    assert_eq!(DmaRenewArgs::DEVICE_RIGHTS, MAP);
    assert_eq!(DmaAttachArgs::DEVICE_RIGHTS, MAP);
    assert_eq!(DmaAttachArgs::MEMORY_RIGHTS, MAP);
}
