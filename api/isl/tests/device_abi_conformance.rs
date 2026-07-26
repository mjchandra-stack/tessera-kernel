// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated device syscall ABI bindings (built by
//! the codegen genrule from `examples/device_abi.isl`, never committed). Proves
//! `MapDeviceArgs`/`DmaAllocArgs` encode to a fixed golden layout and decode
//! back — the ring-3 driver-host arguments are ISL-expressible and wire-stable,
//! and the offsets the kernel's `decode_map_device_args`/`decode_dma_alloc_args`
//! read (16/20/24) are pinned.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format"),
//! docs/api/01-system-call-interface.md

use device_abi::{DmaAllocArgs, IrqCompleteArgs, MapDeviceArgs};
use tessera_isl_runtime::{HandleRef, WireError, decode, encode};

/// Golden encoding of the `MapDeviceArgs` value below: 32 bytes, LE, no
/// implicit padding (`device` u32 + explicit `reserved` u32 fill the 8-byte
/// slot before `vaddr`). Handle and VA are deliberately non-zero so the golden
/// covers them rather than agreeing with unset fields.
const MAP_DEVICE_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x05, 0, 0, 0, // device = handle index 5
    0, 0, 0, 0, // reserved = 0
    0x00, 0x00, 0x40, 0x00, 0x00, 0x10, 0x00, 0x00, // vaddr = 0x0000_1000_0040_0000
];

#[test]
fn map_device_args_matches_golden_and_round_trips() {
    assert_eq!(MapDeviceArgs::WIRE_SIZE, 32);
    let value = MapDeviceArgs {
        size: 32,
        version: 1,
        flags: 0,
        device: HandleRef::new(5),
        reserved: 0,
        vaddr: 0x0000_1000_0040_0000,
    };
    let mut buf = [0u8; 32];
    assert_eq!(encode(&value, &mut buf).unwrap(), 32);
    assert_eq!(buf, MAP_DEVICE_GOLDEN);
    assert_eq!(decode::<MapDeviceArgs>(&MAP_DEVICE_GOLDEN).unwrap(), value);
}

/// Golden encoding of the `DmaAllocArgs` value below: same 32-byte shape, with
/// the DMA-buffer VA the AArch64 boot check actually uses.
const DMA_ALLOC_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x00, 0, 0, 0, // device = handle index 0
    0, 0, 0, 0, // reserved = 0
    0x00, 0x00, 0x50, 0x00, 0x00, 0x10, 0x00, 0x00, // vaddr = 0x0000_1000_0050_0000
];

#[test]
fn dma_alloc_args_matches_golden_and_round_trips() {
    assert_eq!(DmaAllocArgs::WIRE_SIZE, 32);
    let value = DmaAllocArgs {
        size: 32,
        version: 1,
        flags: 0,
        device: HandleRef::new(0),
        reserved: 0,
        vaddr: 0x0000_1000_0050_0000,
    };
    let mut buf = [0u8; 32];
    assert_eq!(encode(&value, &mut buf).unwrap(), 32);
    assert_eq!(buf, DMA_ALLOC_GOLDEN);
    assert_eq!(decode::<DmaAllocArgs>(&DMA_ALLOC_GOLDEN).unwrap(), value);
}

/// Golden encoding of the `IrqCompleteArgs` value below: 24 bytes, LE.
const IRQ_COMPLETE_GOLDEN: [u8; 24] = [
    0x18, 0, 0, 0, // size = 24
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x00, 0, 0, 0, // device = handle index 0
    0, 0, 0, 0, // reserved = 0
];

#[test]
fn irq_complete_args_matches_golden_and_round_trips() {
    assert_eq!(IrqCompleteArgs::WIRE_SIZE, 24);
    let value = IrqCompleteArgs {
        size: 24,
        version: 1,
        flags: 0,
        device: HandleRef::new(0),
        reserved: 0,
    };
    let mut buf = [0u8; 24];
    assert_eq!(encode(&value, &mut buf).unwrap(), 24);
    assert_eq!(buf, IRQ_COMPLETE_GOLDEN);
    assert_eq!(
        decode::<IrqCompleteArgs>(&IRQ_COMPLETE_GOLDEN).unwrap(),
        value
    );
}

#[test]
fn a_truncated_buffer_is_rejected() {
    assert_eq!(
        decode::<MapDeviceArgs>(&MAP_DEVICE_GOLDEN[..24]),
        Err(WireError::ShortBuffer)
    );
}
