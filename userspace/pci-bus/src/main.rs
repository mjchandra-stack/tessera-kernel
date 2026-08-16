// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **PCI bus driver**: the program that walks the bus so the kernel
//! does not have to.
//!
//! Until now the kernel read ECAM at boot, descended through bridges, handed
//! out bus numbers, sized and placed every BAR, and wrote what it found into
//! the resource graph. Everything downstream — bind-by-class, `DeviceInfo`, the
//! device manager — rested on a table built by touching hardware in the most
//! privileged code on the machine. This program is what retires that.
//!
//! It holds two capabilities: a channel to the device manager, and the **host
//! bridge**. From the second it learns how far its configuration window
//! reaches, which memory the bridge forwards, and which bus numbers it covers —
//! and nothing else about the machine.
//!
//! **The walk itself is not written here.** `tessera_pci` is the same crate the
//! kernel was calling a moment before: `no_std`, `forbid(unsafe_code)`, with
//! config access behind a `read32`/`write32` trait. What this file adds is the
//! part that genuinely cannot be shared — a volatile accessor over a window the
//! kernel mapped, and the syscalls. The bridge descent, the multi-function
//! rules, the read-modify-restore that sizes a BAR: all unchanged, and all now
//! running unprivileged.
//!
//! What comes back is declared with `DeviceDeclare`, one call per function. The
//! kernel checks containment and nothing else: a declared function's config
//! slot must lie inside this driver's own window and its registers inside what
//! the bridge forwards. It does **not** check the identity, because the
//! identity came out of configuration space and there is nowhere else to read
//! it — which is exactly why the capability handed back carries `CONFIGURE`, so
//! a driver that cares can look for itself.
//!
//! Each declared function is then **offered** to the device manager with
//! `ChannelSend`. An offer is a notification and not a request: the manager
//! reads an arriving capability as authoritative because a message body can be
//! forged by any sender and a transferred capability cannot.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Bus Topology And Data
//! Paths"), docs/hardware/02-hardware-description-and-discovery.md ("PCIe")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use device_abi::{
    DeviceDeclareArgs, DeviceDeclareRecord, DeviceInfoArgs, DeviceInfoRecord, MapDeviceArgs,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_pci::{ConfigSpace, Function, Host, Window};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_SEND: u64 = 12;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DEVICE_INFO: u64 = 28;
const SYS_DEVICE_DECLARE: u64 = 41;

/// The two capabilities boot grants, in install order — this program's whole
/// bootstrap contract.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const BUS_HANDLE: u32 = 1;

/// Where this program asks for the configuration window. Its choice; what it
/// cannot choose is the physical window behind it, which is what makes the
/// capability worth holding.
const ECAM_VA: u64 = 0x0000_1000_0100_0000;

/// Functions one walk will record. Bounded like every buffer in these programs;
/// a bus with more is reported rather than silently truncated.
const MAX_FUNCTIONS: usize = 8;

/// The rights a declared function is offered to the manager with.
///
/// `CONFIGURE` travels, because the manager's whole job is to hand the function
/// to a driver and the driver is who needs to read its own configuration space.
/// `DERIVE` does not: a function is not a bus, and a driver that could derive
/// from one would be asking the graph for children it has no business having.
const OFFERED_RIGHTS: u64 = 0x1 | 0x2 | 0x4 | 0x80 | 0x100;

/// What this program reports: a tag, how many functions it walked, and how many
/// it successfully declared and handed on.
const REPORT_TAG: u64 = 0x50 << 56;

/// Reads back a u32 the kernel wrote into one of this program's buffers.
///
/// Volatile because the compiler has no idea a syscall wrote here and would
/// otherwise reuse whatever this program last put there.
fn kernel_u32(bytes: &[u8], at: usize) -> u32 {
    let mut out = [0u8; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        if at + i >= bytes.len() {
            return 0;
        }
        // SAFETY: a bounds-checked byte of this program's own stack buffer.
        *slot = unsafe { core::ptr::read_volatile(&bytes[at + i]) };
    }
    u32::from_le_bytes(out)
}

/// Configuration space, as this program reaches it: the window the kernel
/// mapped, addressed by offset.
struct EcamWindow {
    base: usize,
    len: u64,
}

impl ConfigSpace for EcamWindow {
    fn read32(&self, offset: u64) -> u32 {
        if offset + 4 > self.len {
            // Outside the window this program was granted. `tessera_pci` bounds
            // its own walk against the same length, so reaching here means the
            // two disagree — answered with the all-ones a missing function
            // reads as, rather than by touching memory nobody granted.
            return u32::MAX;
        }
        // SAFETY: `base` is the window `MapDevice` installed in this address
        // space, and the bound above keeps `offset` inside it. Volatile because
        // configuration space is device memory whose reads have effects the
        // compiler cannot model.
        unsafe { ((self.base + offset as usize) as *const u32).read_volatile() }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        if offset + 4 > self.len {
            return;
        }
        // SAFETY: as `read32`. This driver exclusively owns the bridge, which
        // is a property of the capability being conserved rather than shared.
        unsafe { ((self.base + offset as usize) as *mut u32).write_volatile(value) }
    }
}

/// Asks the kernel what this bus is and what it forwards.
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
        return Err(fail(0x80, 0xe));
    }
    let answered = syscall2(SYS_DEVICE_INFO, buf.as_ptr() as u64, 0);
    if answered < 0 {
        return Err(fail(0x80, (-answered) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceInfoRecord::WIRE_SIZE }>(&record);
    match decode::<DeviceInfoRecord>(&bytes) {
        Ok(record) if record.bus_valid != 0 => Ok(record),
        // A capability that is not a bus. Reported rather than worked around:
        // there is nothing to enumerate and no window to place BARs in.
        Ok(_) => Err(fail(0x80, 0x100)),
        Err(_) => Err(fail(0x80, 0xd)),
    }
}

/// Maps the configuration window and returns its base.
fn map_ecam() -> Result<usize, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(BUS_HANDLE),
        reserved: 0,
        vaddr: ECAM_VA,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x81, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x81, (-base) as u64));
    }
    Ok(base as usize)
}

/// Declares one function to the kernel and returns the handle it installed.
fn declare(function: &Function) -> Result<u32, u64> {
    let (base, len) = function.first_bar().unwrap_or((0, 0));
    let record = [0u8; DeviceDeclareRecord::WIRE_SIZE];
    let args = DeviceDeclareArgs {
        size: DeviceDeclareArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        bus: HandleRef::new(BUS_HANDLE),
        bdf: u32::from(function.bdf.bus) << 8
            | u32::from(function.bdf.device) << 3
            | u32::from(function.bdf.function),
        register_base: base,
        register_len: len,
        class_code: function.class_code,
        vendor: u32::from(function.vendor),
        device_id: u32::from(function.device),
        revision: u32::from(function.revision),
        record_ptr: record.as_ptr() as u64,
        // **No wire, and this bus has none to give.** A PCI function's
        // interrupts are message-signalled and arrive through a different door
        // entirely, so this bridge forwards memory and no lines — and a
        // declaration naming one would be refused for exactly that reason.
        intid: 0,
        trigger: 0,
    };
    let mut buf = [0u8; DeviceDeclareArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x82, 0xe));
    }
    let declared = syscall2(SYS_DEVICE_DECLARE, buf.as_ptr() as u64, 0);
    if declared < 0 {
        return Err(fail(0x82, (-declared) as u64));
    }
    // The handle is read out of the record the kernel filled, not inferred: a
    // table with no room is reported as NOT_INSTALLED, and zero is a legitimate
    // handle number.
    let bytes = read_kernel_filled::<{ DeviceDeclareRecord::WIRE_SIZE }>(&record);
    let handle = kernel_u32(&bytes, 16);
    if handle == u32::MAX {
        return Err(fail(0x82, 0x100));
    }
    Ok(handle)
}

/// Offers a declared function to the device manager.
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
        return Err(fail(0x83, 0xe));
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
        return Err(fail(0x83, 1));
    }
    let sent = syscall2(
        SYS_CHANNEL_SEND,
        buf.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if sent < 0 {
        return Err(fail(0x83, (-sent) as u64));
    }
    Ok(())
}

/// The whole program.
fn run() -> u64 {
    let info = match bus_info() {
        Ok(info) => info,
        Err(code) => return code,
    };
    let base = match map_ecam() {
        Ok(base) => base,
        Err(code) => return code,
    };

    // The window as this program addresses it. `ecam_base` is zero because the
    // accessor below works in offsets from the mapping the kernel gave it —
    // where configuration space sits in physical memory is a fact about the
    // machine that this program is deliberately not told.
    let host = Host {
        ecam_base: 0,
        ecam_len: info.config_len,
        first_bus: info.first_bus as u8,
        last_bus: info.last_bus as u8,
    };
    let window = Window {
        cpu_base: info.forward_cpu_base,
        bus_base: info.forward_bus_base,
        len: info.forward_len,
        // The forwarded window is where 32-bit BARs must land; a bridge
        // advertising a 64-bit-only window is a machine this driver has not
        // met, and would place nothing rather than place it wrongly.
        is_32bit: true,
    };
    let mut config = EcamWindow {
        base,
        len: info.config_len,
    };
    let mut functions = [Function {
        bdf: match tessera_pci::Bdf::new(0, 0, 0) {
            Some(bdf) => bdf,
            None => return fail(0x84, 0),
        },
        vendor: 0,
        device: 0,
        class_code: 0,
        revision: 0,
        header_type: 0,
        bars: [None; tessera_pci::MAX_BARS],
        parent: None,
    }; MAX_FUNCTIONS];
    // **The walk, in ring 3, on the kernel's own code.** Bridge descent, bus
    // numbering and BAR placement all happen here now; the only privileged
    // thing left in the path is the page table entry that made the window
    // reachable.
    let found = match tessera_pci::enumerate(&host, &mut config, window, &mut functions) {
        Ok(found) => found,
        Err(e) => return fail(0x85, e as u64),
    };

    let mut declared = 0u64;
    for function in &functions[..found] {
        let handle = match declare(function) {
            Ok(handle) => handle,
            Err(code) => return code,
        };
        if let Err(code) = offer(handle) {
            return code;
        }
        declared += 1;
    }
    REPORT_TAG | (found as u64) << 8 | declared
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
