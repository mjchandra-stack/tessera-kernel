// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **platform bus controller**: a `no_std` Rust program that reads
//! the machine's description and puts what it finds in the resource graph.
//!
//! **The device tree is this bus's configuration space.** That is not an
//! analogy — it is the same relationship `pci-bus` has to ECAM. A PCI
//! controller maps the window that says what is on its bus and walks it; this
//! one maps the blob that says what is on its bus and walks that. Boot grants
//! it as the bus capability's own window, and it is mapped with the same
//! `MapDevice` call, because from the kernel's side there is no difference
//! between a window that describes devices and a window that is one.
//!
//! **Which is also why it is not believed.** A device tree is firmware's word
//! about a machine, so it is parsed by `tessera-devicetree` — `no_std`,
//! `forbid(unsafe_code)`, host-tested, and already carrying a test that feeds
//! it arbitrary bytes and requires it not to panic. Nothing in this program
//! indexes into the blob.
//!
//! **What it declares is bounded twice, and neither bound is its own.** A
//! device whose window lies outside what this bus forwards is not this bus's to
//! declare, and neither is one whose interrupt lies outside the lines it was
//! given — the kernel would refuse both, and asking first means the refusals
//! are something this program can report rather than something it discovers one
//! device at a time. It learns both ranges from `DeviceInfo`.
//!
//! **And one device is withheld on purpose.** The kernel is printing on the
//! console UART; handing it to a driver mid-boot would stop the verdict lines
//! arriving. It is skipped *and counted*, because a silent omission would be
//! indistinguishable from a machine with no console.
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md,
//! docs/drivers/01-driver-framework.md ("Bus Topology And Data Paths")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use device_abi::{
    DeviceDeclareArgs, DeviceDeclareRecord, DeviceInfoArgs, DeviceInfoRecord, MapDeviceArgs,
};
use tessera_devicetree::{DeviceTree, MmioDevice};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_SEND: u64 = 12;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DEVICE_INFO: u64 = 28;
const SYS_DEVICE_DECLARE: u64 = 41;

/// The capabilities boot installs, in order.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const BUS_HANDLE: u32 = 1;

/// Where this program asks for the blob.
const BLOB_VA: u64 = 0x0000_1000_0060_0000;

/// Devices of one kind this program will hold at a time.
const MAX_OF_A_KIND: usize = 8;

/// What a device found in the tree is declared as.
///
/// **Compiled in, for the reason the device manager's manifest is.** Which
/// compatible string means which kind of device is policy about a machine, not
/// a fact this program can derive — and where it should come from is a
/// configuration service reading a signed package, which is one substitution
/// away.
struct Known {
    compatible: &'static [u8],
    /// The class code the device is declared with, which is how a manager
    /// classifies it without knowing what a device tree is.
    class_code: u32,
    vendor: u32,
    device_id: u32,
    /// Whether this program declares it at all. The console is described here
    /// so that skipping it is a decision in the table rather than an absence
    /// somewhere in the code.
    declare: bool,
}

/// ARM, as a PrimeCell's identification registers give the designer. The same
/// value the manager reads off the part, so a manifest matching on it matches
/// whichever route classified the device.
const ARM_DESIGNER: u32 = 0x41;
/// Red Hat, which is virtio's vendor.
const VIRTIO_VENDOR: u32 = 0x1af4;

/// A GPIO controller: base system peripheral, subclass "other".
///
/// PCI has no class for a GPIO block, and the codes here are the vocabulary
/// the device manager already reads. "Other system peripheral" is the honest
/// place for a device the taxonomy does not name — and it is matched on both
/// bytes, because the base byte alone is a category shared with timers and
/// interrupt controllers.
const CLASS_GPIO: u32 = 0x08_8000;
/// A real-time clock, which PCI does name: base system peripheral, subclass 3.
const CLASS_RTC: u32 = 0x08_0300;
/// A device this program declares and does not classify. Real, in the graph,
/// and matched by nothing — which is the honest record of a device found and
/// not understood.
const CLASS_UNCLASSIFIED: u32 = 0;

const KNOWN: [Known; 4] = [
    Known {
        compatible: b"arm,pl061",
        class_code: CLASS_GPIO,
        vendor: ARM_DESIGNER,
        device_id: 0x061,
        declare: true,
    },
    Known {
        compatible: b"arm,pl031",
        class_code: CLASS_RTC,
        vendor: ARM_DESIGNER,
        device_id: 0x031,
        declare: true,
    },
    // **The console, withheld.** The kernel is printing on it, and a driver
    // that took it would take the verdict lines with it. Listed rather than
    // omitted so that the decision is visible where the others are made.
    Known {
        compatible: b"arm,pl011",
        class_code: CLASS_UNCLASSIFIED,
        vendor: ARM_DESIGNER,
        device_id: 0x011,
        declare: false,
    },
    Known {
        compatible: b"virtio,mmio",
        class_code: CLASS_UNCLASSIFIED,
        vendor: VIRTIO_VENDOR,
        device_id: 0,
        declare: true,
    },
];

/// What a declared device is offered with: read, map and the ability to be
/// handed on. Not `DERIVE` — a platform device is a leaf, and a driver that
/// could populate a bus it does not own would be inventing hardware.
const OFFERED_RIGHTS: u64 = 0x1 | 0x4 | 0x80;

/// What this program reports: a tag, and the three counts that describe what it
/// did with the machine it read.
const REPORT_TAG: u64 = 0x70 << 56;

/// Reads back a u32 the kernel wrote into one of this program's buffers.
fn kernel_u32(bytes: &[u8], at: usize) -> u32 {
    let mut out = [0u8; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        if at + i >= bytes.len() {
            return 0;
        }
        // SAFETY: a bounds-checked byte of this program's own stack buffer;
        // volatile because the kernel wrote it.
        *slot = unsafe { core::ptr::read_volatile(&bytes[at + i]) };
    }
    u32::from_le_bytes(out)
}

/// Asks the kernel what this bus is, and what it may hand out.
fn bus_info() -> Result<DeviceInfoRecord, u64> {
    let record = [0u8; DeviceInfoRecord::WIRE_SIZE];
    let args = DeviceInfoArgs {
        size: DeviceInfoArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(BUS_HANDLE),
        reserved: 0,
        record_ptr: record.as_ptr() as u64,
    };
    let mut buf = [0u8; DeviceInfoArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x60, 0xe));
    }
    let answered = syscall2(SYS_DEVICE_INFO, buf.as_ptr() as u64, 0);
    if answered < 0 {
        return Err(fail(0x60, (-answered) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceInfoRecord::WIRE_SIZE }>(&record);
    match decode::<DeviceInfoRecord>(&bytes) {
        Ok(info) => Ok(info),
        Err(_) => Err(fail(0x60, 0xd)),
    }
}

/// Maps the blob this bus is described by.
fn map_blob(vaddr: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(BUS_HANDLE),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x61, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x61, (-base) as u64));
    }
    Ok(base as u64)
}

/// Puts one device in the resource graph.
fn declare(known: &Known, device: &MmioDevice, index: u32) -> Result<u32, u64> {
    let record = [0u8; DeviceDeclareRecord::WIRE_SIZE];
    let args = DeviceDeclareArgs {
        size: DeviceDeclareArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        bus: HandleRef::new(BUS_HANDLE),
        // A platform device has no slot number. Its index in the walk is what
        // distinguishes one from the next, which is what a BDF does on PCI —
        // a name for a position on the bus and not an address.
        bdf: index,
        register_base: device.base,
        register_len: device.size,
        class_code: known.class_code,
        vendor: known.vendor,
        device_id: known.device_id,
        revision: 0,
        record_ptr: record.as_ptr() as u64,
        // **The wire, if it has one.** Zero is a real answer and the common
        // one; a device tree that names no interrupt for a node and one that
        // names none because the node has none are the same, and both mean
        // there is nothing to route.
        intid: device.intid.unwrap_or(0),
        trigger: match device.trigger {
            Some(tessera_devicetree::IrqTrigger::Edge) => 1,
            Some(tessera_devicetree::IrqTrigger::Level) => 2,
            // The binding did not say, which is its own fact.
            None => 0,
        },
    };
    let mut buf = [0u8; DeviceDeclareArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x62, 0xe));
    }
    let declared = syscall2(SYS_DEVICE_DECLARE, buf.as_ptr() as u64, 0);
    if declared < 0 {
        return Err(fail(0x62, (-declared) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceDeclareRecord::WIRE_SIZE }>(&record);
    let handle = kernel_u32(&bytes, 16);
    if handle == u32::MAX {
        return Err(fail(0x62, 0x100));
    }
    Ok(handle)
}

/// Offers a declared device to the device manager.
///
/// One-way, because an offer is a notification: nobody is waiting on an answer,
/// and the manager reads the arriving capability rather than the body — a body
/// can be forged by any sender and a transferred capability cannot.
fn offer(handle: u32) -> Result<(), u64> {
    let descriptor = HandleTransfer {
        mode: TransferMode::Transfer,
        rights: OFFERED_RIGHTS,
        handle,
    };
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    if encode(&descriptor, &mut transfer).is_err() {
        return Err(fail(0x63, 0xe));
    }
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr: transfer.as_ptr() as u64,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x63, 1));
    }
    let sent = syscall2(
        SYS_CHANNEL_SEND,
        buf.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if sent < 0 {
        return Err(fail(0x63, (-sent) as u64));
    }
    Ok(())
}

/// What this walk did with the machine it read.
#[derive(Default)]
struct Outcome {
    /// Devices declared and offered.
    declared: u32,
    /// Devices found and deliberately not declared — the console, so far.
    withheld: u32,
    /// Devices found whose window or interrupt this bus does not carry. **Not
    /// a failure and not silence**: a device outside what a bus forwards is
    /// simply not that bus's to declare, and a walk that dropped it without
    /// counting would look like a machine that does not have it.
    beyond: u32,
}

/// Whether this bus may declare a device at all: its window inside what the
/// bus forwards, and its line inside the lines it was given.
///
/// Asked before declaring rather than learned by being refused. The kernel
/// enforces both — this is a bus controller knowing what it holds, which is
/// what lets the refusals be reported instead of discovered.
fn within(info: &DeviceInfoRecord, device: &MmioDevice) -> bool {
    let Some(end) = device.base.checked_add(device.size) else {
        return false;
    };
    let Some(forward_end) = info.forward_cpu_base.checked_add(info.forward_len) else {
        return false;
    };
    if device.base < info.forward_cpu_base || end > forward_end {
        return false;
    }
    match device.intid {
        None => true,
        Some(intid) => {
            let past = info.first_intid.saturating_add(info.intid_count);
            info.intid_count != 0 && intid >= info.first_intid && intid < past
        }
    }
}

/// The whole program.
fn run() -> u64 {
    let info = match bus_info() {
        Ok(info) => info,
        Err(code) => return code,
    };
    // A bus that forwards nothing describes nothing, and saying so beats
    // walking a tree whose every device would be refused.
    if info.bus_valid == 0 || info.forward_len == 0 {
        return fail(0x64, 0);
    }
    let base = match map_blob(BLOB_VA) {
        Ok(base) => base,
        Err(code) => return code,
    };
    // The blob, as bytes. Its length is what the bus capability's window
    // covers, which boot set from the header the firmware wrote.
    let len = match usize::try_from(info.config_len) {
        Ok(len) if len > 0 => len,
        _ => return fail(0x64, 1),
    };
    // SAFETY: `MapDevice` installed exactly `config_len` readable bytes at
    // `base` in this address space, and the slice is never held across a call
    // that could unmap it. The bytes are firmware's word and are handed
    // straight to a parser that forbids `unsafe` and bounds every read.
    let blob = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
    let Ok(tree) = DeviceTree::parse(blob) else {
        return fail(0x64, 2);
    };

    let mut outcome = Outcome::default();
    let mut found = [MmioDevice {
        base: 0,
        size: 0,
        intid: None,
        trigger: None,
    }; MAX_OF_A_KIND];
    let mut index = 0u32;
    for known in &KNOWN {
        let Ok(count) = tree.mmio_devices(known.compatible, &mut found) else {
            return fail(0x65, 0);
        };
        if !known.declare {
            outcome.withheld += count as u32;
            continue;
        }
        // Past what this program can hold is counted as beyond its reach, for
        // the reason the walker reports the number found rather than the
        // number it wrote: a machine with more devices than room must not look
        // like a smaller machine.
        let held = count.min(MAX_OF_A_KIND);
        outcome.beyond += (count - held) as u32;
        for device in &found[..held] {
            if !within(&info, device) {
                outcome.beyond += 1;
                continue;
            }
            let handle = match declare(known, device, index) {
                Ok(handle) => handle,
                Err(code) => return code,
            };
            index += 1;
            if let Err(code) = offer(handle) {
                return code;
            }
            outcome.declared += 1;
        }
    }

    // The three counts, so a checker outside this program can compare them
    // against what the kernel independently read. A walk that reported only
    // its successes would be one nobody could tell from a walk that found less.
    REPORT_TAG
        | (u64::from(outcome.declared) << 32)
        | (u64::from(outcome.withheld) << 16)
        | u64::from(outcome.beyond)
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, value, 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    exit_reporting(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
