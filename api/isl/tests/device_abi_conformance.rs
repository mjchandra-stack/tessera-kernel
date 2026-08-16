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

/// The record a driver learns **where its device's structures are** from —
/// D126's open item, closed.
///
/// A virtio-pci function does not say where its controls are in any register
/// it exposes: it says so in config space, one vendor capability per
/// structure, and config space is not per-device, so no capability to it can
/// be handed out. Until this record carried the offsets, a driver holding the
/// right window still had no way to find anything in it.
#[test]
fn a_device_info_record_says_where_the_structures_are() {
    use device_abi::{DeviceBusKind, DeviceInfoKind, DeviceInfoRecord};
    assert_eq!(DeviceInfoRecord::WIRE_SIZE, 72);
    let value = DeviceInfoRecord {
        size: DeviceInfoRecord::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        kind: DeviceInfoKind::Pci,
        class_code: 0x01_00_00,
        vendor: 0x1af4,
        device: 0x1042,
        bdf: 0x08,
        revision: 1,
        bus: DeviceBusKind::Pci,
        layout_valid: 1,
        common_offset: 0,
        notify_offset: 0x3000,
        notify_multiplier: 4,
        isr_offset: 0x1000,
        device_config_offset: 0x2000,
        reserved: 0,
    };
    let mut buf = [0u8; DeviceInfoRecord::WIRE_SIZE];
    encode(&value, &mut buf).unwrap();
    assert_eq!(decode::<DeviceInfoRecord>(&buf).unwrap(), value);
}

/// **`layout_valid` is reported, not inferred from a zero offset.** Offset
/// zero is a legitimate place for a structure to be — it is where the common
/// configuration structure actually sits on the machines this boots — so a
/// driver that treated zero as "absent" would refuse to drive exactly the
/// devices that work.
#[test]
fn an_offset_of_zero_is_a_real_offset() {
    use device_abi::{DeviceBusKind, DeviceInfoKind, DeviceInfoRecord};
    let resolved = DeviceInfoRecord {
        size: DeviceInfoRecord::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        kind: DeviceInfoKind::Pci,
        class_code: 0,
        vendor: 0,
        device: 0,
        bdf: 0,
        revision: 0,
        bus: DeviceBusKind::Pci,
        layout_valid: 1,
        common_offset: 0,
        notify_offset: 0,
        notify_multiplier: 0,
        isr_offset: 0,
        device_config_offset: 0,
        reserved: 0,
    };
    let unresolved = DeviceInfoRecord {
        layout_valid: 0,
        ..resolved
    };
    // Byte for byte the offsets are identical; only the flag distinguishes a
    // device whose structures start at zero from one whose structures the
    // kernel did not resolve.
    let mut a = [0u8; DeviceInfoRecord::WIRE_SIZE];
    let mut b = [0u8; DeviceInfoRecord::WIRE_SIZE];
    encode(&resolved, &mut a).unwrap();
    encode(&unresolved, &mut b).unwrap();
    assert_ne!(a, b);
    // `layout_valid` sits at 44 and the offsets follow it.
    assert_eq!(a[48..], b[48..], "the offsets themselves are the same");
    assert_ne!(a[44..48], b[44..48], "only the flag differs");
}

/// The bus a device was found on is a binding input, and an unknown bus is a
/// value rather than an absence — a rule that named a bus must be able to
/// refuse it.
#[test]
fn the_bus_kinds_are_stable() {
    use device_abi::DeviceBusKind;
    assert_eq!(DeviceBusKind::Unknown as u32, 0);
    assert_eq!(DeviceBusKind::Pci as u32, 1);
    assert_eq!(DeviceBusKind::VirtioMmio as u32, 2);
    assert_eq!(DeviceBusKind::Platform as u32, 3);
}
