// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **USB host driver**: a `no_std` Rust program that brings an xHCI
//! controller up, walks the tree of devices attached to it, decides which of
//! them this system will drive, puts every one of them in the resource graph,
//! and then moves bytes on behalf of the class drivers that cannot reach them.
//!
//! Four things here that no driver in this tree has done before.
//!
//! **Its devices have no registers.** Every driver so far maps a window and
//! writes to it. A USB device has nothing to map — there is no window a
//! capability could name — so a class driver reaches its device by asking this
//! program to move bytes for it. That is `docs/drivers/01`'s **relaying** bus
//! host, and this is the first one here: `Hop::Relay` has been in the binding
//! rules since D124 with nothing real to count, because PCIe gives every
//! function its own queues and every device in this tree has been `Separated`.
//!
//! **The tree is deep.** A hub is a device this program enumerated *and* a bus
//! it declares devices behind, so the resource graph gets three levels where it
//! has only ever had two — and a device two levels down pays the relay twice,
//! which is what makes the accumulated cost in `BindReply` a measurement.
//!
//! **The devices describe themselves, and are not believed.** Descriptors are
//! bytes a device chose, sent after being plugged into a running machine by
//! whoever was standing next to it. They are parsed by `tessera_usb`, which is
//! host-tested against byte strings that are wrong on purpose; nothing here
//! indexes into a descriptor.
//!
//! **A device can enumerate perfectly and still not be driven.** The class
//! allowlist is the first policy in this tree that refuses something that
//! works. A refused device is still declared — a refusal nobody can see is not
//! a control — but with a class code no manifest entry claims, so nothing binds
//! to it, and every transfer naming it is answered `UNAUTHORIZED`.
//!
//! The transport is `tessera-xhci`, host-tested against a mock whose event ring
//! wraps. What this file adds is the syscalls, the volatile access to a window
//! the kernel mapped, and the pages the controller reads.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("USB"),
//! docs/drivers/01-driver-framework.md ("Bus Topology And Data Paths")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use device_abi::{DeviceDeclareArgs, DeviceDeclareRecord, DmaAllocArgs, MapDeviceArgs};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{HandleRef, Reader, WireError, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};
use tessera_usb::{
    Configuration, Endpoint, HubDescriptor, Interface, Policy, TransferType, class, descriptor,
    hid, hub_port, request, storage,
};
use tessera_xhci::{
    Controller, EventRing, Registers, Ring, TRB_LEN, Trb, command, command_with_context, context,
    control_transfer, normal, port, trb,
};
use usb_host::{
    UsbDeviceReply, UsbError, UsbHostIncoming, UsbTransferKind, UsbTransferReply,
    UsbTransferRequest,
};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_SEND: u64 = 12;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DMA_ALLOC: u64 = 24;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_DEVICE_DECLARE: u64 = 41;

/// The capabilities boot installs, in order.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const CLIENT_ENDPOINT_HANDLE: u64 = 1;
/// Where the bound controller lands: two handles are installed above it.
const CONTROLLER_HANDLE: u32 = 2;

/// Where this program asks for the controller's registers, and where the pages
/// the controller reads begin. One page apiece and page-aligned, because a
/// controller reads its own structures at their physical addresses and packing
/// two into one page is how the NVMe queues were found to fail.
const MMIO_VA: u64 = 0x0000_1000_0040_0000;
const DMA_VA_BASE: u64 = 0x0000_1000_0050_0000;
const PAGE: u64 = 0x1000;

/// Pages this program will ask the kernel for. Bounded like every pool here; a
/// controller needing more is reported rather than partly set up.
const MAX_PAGES: usize = 24;

/// Devices this host will hold at once, across the whole tree.
const MAX_DEVICES: usize = 4;

/// Scratchpad pages this host will provide. A controller wanting more is
/// refused with a code of its own rather than run with a short array — the
/// controller writes into that memory, and a short array is memory corruption
/// rather than a missing feature.
const MAX_SCRATCHPAD: u32 = 4;

/// Entries in each ring. Small, because nothing here pipelines: a transfer is
/// issued and waited for, so the ring never holds more than the three TRBs of a
/// control transfer.
const RING_ENTRIES: u16 = 16;
/// Entries in the event ring, which must be able to hold what a burst of
/// completions and port changes produces before the driver reads any.
const EVENT_ENTRIES: u16 = 32;

/// How many times a completion is polled for before the transfer is called
/// dead. A count and not a duration: this program has no clock, and what the
/// bound buys is that a device which never answers produces an error.
const POLL_LIMIT: u32 = 4_000_000;

/// The bound a **brief** transfer waits under (`flags` bit 0).
///
/// Short because the caller is asking whether something has already happened
/// rather than waiting for it to. An interrupt endpoint on an idle device never
/// completes at all, and a class driver polling one would otherwise spend the
/// full bound per question.
const BRIEF_POLL_LIMIT: u32 = 4_000;

/// `UsbTransferRequest.flags` bit 0.
const TRANSFER_BRIEF: u64 = 0x1;

/// The most one relayed transfer carries, which is the class contract's inline
/// payload.
const MAX_PAYLOAD: usize = 64;

/// The bytes of a configuration this host will read. Larger than any device
/// here presents and smaller than a page; a configuration past it is refused
/// rather than truncated, because a truncated configuration is a device
/// described by half its own description.
const CONFIG_BUF_LEN: usize = 192;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// Field offsets in an encoded `ChannelMsgArgs` (`channel_msg.isl`).
const ARGS_METHOD_ID: usize = 32;
const ARGS_INLINE_LEN: usize = 48;

/// The PCI class code a USB host controller carries, and which this host
/// declares its hubs with — a hub is a bus of the same kind one level down, and
/// the manager's manifest matches both with one entry.
const CLASS_CODE_USB: u32 = 0x0c_0300;
/// The class code a mass-storage device is declared with, so a manager
/// classifies it as a block device without knowing what USB is.
const CLASS_CODE_MASS_STORAGE: u32 = 0x01_0000;
/// The class code a human interface device is declared with.
const CLASS_CODE_INPUT: u32 = 0x09_0000;
/// **What a refused device is declared with: nothing.** A class no manifest
/// entry claims, so the device is in the graph and visible and no driver is
/// offered it. Zero is the honest value — this system has decided it is not
/// going to say what the device is.
const CLASS_CODE_REFUSED: u32 = 0;

/// One page, under both names.
///
/// The two names for one page is the whole point of `DmaAlloc`: this program
/// writes through `va`, the controller fetches from `phys`, and nothing this
/// program could compute would relate them.
#[derive(Clone, Copy, Default)]
struct Page {
    va: u64,
    phys: u64,
}

/// The controller's register window, at the address the kernel mapped it to.
struct UserRegisters {
    base: usize,
}

impl Registers for UserRegisters {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the window `MapDevice` installed in this address
        // space, and every offset the transport core uses is a defined register
        // inside it.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }

    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as `read32`; this driver exclusively owns the controller,
        // which is a property of the capability being conserved rather than
        // shared.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// Reads one byte of a DMA page.
///
/// Volatile because the controller writes this memory: a compiler that cached a
/// read would hand back the value from before the device answered, which is
/// indistinguishable from a device that never did.
fn dma_read(page: &Page, at: usize, out: &mut [u8]) {
    for (index, slot) in out.iter_mut().enumerate() {
        // SAFETY: `at + index` is inside the page `DmaAlloc` mapped, bounded by
        // the caller against `PAGE`.
        *slot = unsafe { ((page.va as usize + at + index) as *const u8).read_volatile() };
    }
}

/// Writes into a DMA page.
fn dma_write(page: &Page, at: usize, data: &[u8]) {
    for (index, byte) in data.iter().enumerate() {
        // SAFETY: as `dma_read`; the page is this program's own mapping and the
        // caller bounds `at + data.len()` by `PAGE`.
        unsafe { ((page.va as usize + at + index) as *mut u8).write_volatile(*byte) };
    }
}

/// Zero-fills a span of a DMA page.
fn dma_zero(page: &Page, at: usize, len: usize) {
    for index in 0..len {
        // SAFETY: as `dma_write`.
        unsafe { ((page.va as usize + at + index) as *mut u8).write_volatile(0) };
    }
}

/// Writes a 64-bit value into a DMA page, little-endian.
fn dma_put64(page: &Page, at: usize, value: u64) {
    dma_write(page, at, &value.to_le_bytes());
}

/// Hands the transport core a slice over a DMA page.
///
/// **Only for pages the controller reads**: the command ring, the transfer
/// rings. Their contents are written by this program and fetched by the
/// controller, so a plain slice is honest. The event ring is the other way
/// round — the controller writes it while this program looks — and is read one
/// entry at a time through [`dma_read`] instead, because a compiler allowed to
/// cache a slice would answer with what was there before the device replied.
///
/// Scoped rather than returned, so no two references to a page exist at once.
fn with_page<R>(page: &Page, f: impl FnOnce(&mut [u8]) -> R) -> R {
    // SAFETY: `DmaAlloc` mapped exactly one readable and writable page at
    // `page.va` for this process; nothing else in this program forms a
    // reference to it while `f` runs, and the mapping outlives the call.
    let slice = unsafe { core::slice::from_raw_parts_mut(page.va as *mut u8, PAGE as usize) };
    f(slice)
}

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

/// Writes a u64 into an encoded descriptor between messages.
fn patch_args(args: &mut [u8; ChannelMsgArgs::WIRE_SIZE], at: usize, value: u64) {
    for (i, byte) in value.to_le_bytes().iter().enumerate() {
        // SAFETY: `at` is a field offset inside this program's own stack
        // buffer, and the widest field written is 8 bytes inside 88.
        unsafe { core::ptr::write_volatile(&mut args[at + i], *byte) };
    }
}

/// Encodes a `ChannelMsgArgs` over the symmetric message buffer.
fn channel_args(buf_ptr: u64, buf_len: u64) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: buf_len,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0xc0, 0xe)),
    }
}

/// Acquires the USB host controller from the device manager.
fn bind() -> Result<(), u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Usb,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0xc1, 0xe));
    }
    let args = channel_args(message.as_ptr() as u64, message.len() as u64)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xc1, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0xc1, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0xc1, 0x100 | u64::from(reply.status)));
    }
    // A driver handed a class it did not ask for has been mis-bound, and
    // checking beats trusting.
    if reply.class != DeviceClass::Usb {
        return Err(fail(0xc1, 0x200));
    }
    Ok(())
}

/// Maps the controller's registers, returning the base.
fn map_device(vaddr: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(CONTROLLER_HANDLE),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0xc2, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0xc2, (-base) as u64));
    }
    Ok(base as u64)
}

/// Hands out the next DMA page, under both its names.
struct Pages {
    next: usize,
}

impl Pages {
    fn take(&mut self) -> Result<Page, u64> {
        if self.next >= MAX_PAGES {
            return Err(fail(0xc3, 0x100));
        }
        let vaddr = DMA_VA_BASE + (self.next as u64) * PAGE;
        let args = DmaAllocArgs {
            size: DmaAllocArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            device: HandleRef::new(CONTROLLER_HANDLE),
            reserved: 0,
            vaddr,
        };
        let mut buf = [0u8; DmaAllocArgs::WIRE_SIZE];
        if encode(&args, &mut buf).is_err() {
            return Err(fail(0xc3, 0xe));
        }
        let phys = syscall2(SYS_DMA_ALLOC, buf.as_ptr() as u64, 0);
        if phys < 0 {
            return Err(fail(0xc3, (-phys) as u64));
        }
        self.next += 1;
        Ok(Page {
            va: vaddr,
            phys: phys as u64,
        })
    }
}

/// Puts a device in the resource graph behind `bus`.
///
/// **A device the kernel has never seen, on a bus it does not know**, and this
/// time the bus may itself be one of these. A hub is declared behind the
/// controller and its devices behind the hub, so the graph gets the shape the
/// machine has — which is what makes the relay cost on a device two levels down
/// a sum of two rather than a guess.
fn declare(bus: u32, address: u8, class_code: u32, vendor: u16, product: u16) -> Result<u32, u64> {
    let record = [0u8; DeviceDeclareRecord::WIRE_SIZE];
    let args = DeviceDeclareArgs {
        size: DeviceDeclareArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        bus: HandleRef::new(bus),
        // The address this host assigned, which is what identifies a device on
        // this bus the way a BDF does on PCI: unique among the devices one
        // controller holds, and assigned by the thing that enumerated them.
        bdf: u32::from(address),
        // No window: a USB device has no registers to map.
        register_base: 0,
        register_len: 0,
        class_code,
        vendor: u32::from(vendor),
        device_id: u32::from(product),
        revision: 0,
        record_ptr: record.as_ptr() as u64,
        // A USB device has no wire, for the same reason it has no registers:
        // everything it does reaches the machine through this controller.
        intid: 0,
        trigger: 0,
    };
    let mut buf = [0u8; DeviceDeclareArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0xc4, 0xe));
    }
    let declared = syscall2(SYS_DEVICE_DECLARE, buf.as_ptr() as u64, 0);
    if declared < 0 {
        return Err(fail(0xc4, (-declared) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceDeclareRecord::WIRE_SIZE }>(&record);
    let handle = kernel_u32(&bytes, 16);
    if handle == u32::MAX {
        return Err(fail(0xc4, 0x100));
    }
    Ok(handle)
}

/// What a declared device is offered to the manager with.
///
/// READ, MAP and TRANSFER — and **not** `WRITE` and not `DERIVE`. Rights only
/// narrow, so this set is bounded above by what the controller's own capability
/// carries; and neither of the two left out has a use here. A class driver has
/// no children to declare, and a USB device has no window to write.
const OFFERED_RIGHTS: u64 = 0x1 | 0x4 | 0x80;

/// Offers a declared device to the device manager.
///
/// One-way, because an offer is a notification: nobody is waiting on an answer,
/// and the manager reads the arriving capability rather than the body — a body
/// can be forged by any sender and a transferred capability cannot.
///
/// **This is what makes a USB device bindable.** Declaring it puts it in the
/// graph; offering it is what puts it in the hands of something that can hand
/// it to a driver. A device declared and not offered is visible and unusable,
/// which is exactly what a refused device should be and exactly what an
/// admitted one should not.
fn offer(handle: u32) -> Result<(), u64> {
    let descriptor = HandleTransfer {
        mode: TransferMode::Transfer,
        rights: OFFERED_RIGHTS,
        handle,
    };
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    if encode(&descriptor, &mut transfer).is_err() {
        return Err(fail(0xcd, 0xe));
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
        return Err(fail(0xcd, 1));
    }
    let sent = syscall2(
        SYS_CHANNEL_SEND,
        buf.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if sent < 0 {
        return Err(fail(0xcd, (-sent) as u64));
    }
    Ok(())
}

/// One device this host has addressed.
#[derive(Clone, Copy)]
struct Device {
    /// The address the controller assigned, which is also its slot.
    address: u8,
    /// How many hubs it is behind. Zero is a root port.
    depth: u32,
    vendor: u16,
    product: u16,
    /// The first interface's identity — what a class driver matches on.
    class: u8,
    subclass: u8,
    protocol: u8,
    interface: u8,
    /// Whether the policy admitted it. A refused device keeps its address and
    /// its place in the graph and is never configured.
    authorized: bool,
    /// Its data endpoints, as its own descriptors gave them.
    endpoint_in: Option<Endpoint>,
    endpoint_out: Option<Endpoint>,
    /// Its declared capability, and — if it is a hub — the handle its own
    /// devices are declared behind.
    handle: u32,
    /// Context and ring pages.
    contexts: Page,
    rings: Page,
    ep0: Ring,
    data_in: Ring,
    data_out: Ring,
}

/// Where the two contexts sit inside a device's context page. Two per page
/// rather than two pages, because both are 64-byte aligned structures well
/// under half a page and the kernel hands out whole pages.
const INPUT_CONTEXT_AT: usize = 0;
const DEVICE_CONTEXT_AT: usize = 2048;
/// And where the rings sit inside a device's ring page.
///
/// **One ring per endpoint, not one per device.** An endpoint's transfer ring
/// is named in its own context and rung by its own doorbell; two endpoints
/// pointed at one ring share an enqueue pointer and a cycle bit, so a transfer
/// pushed for the IN endpoint is work the OUT endpoint's doorbell also
/// announces — and the controller consumes it once, from whichever side it
/// looked at first.
const EP0_RING_AT: usize = 0;
const IN_RING_AT: usize = 1024;
const OUT_RING_AT: usize = 2048;
/// How much of the page each ring may use.
const RING_WINDOW: usize = 1024;

/// Everything the host carries.
struct Host<'r> {
    controller: Controller<'r, UserRegisters>,
    context_len: usize,
    /// Device context base address array, and the event ring segment table,
    /// which share a page for the reason the two contexts do.
    dcbaa: Page,
    command: Page,
    command_ring: Ring,
    events: Page,
    event_ring: EventRing,
    /// One page for every relayed transfer's data.
    buffer: Page,
    devices: [Option<Device>; MAX_DEVICES],
}

const ERST_AT: usize = 2048;

impl Host<'_> {
    /// Rings the command doorbell and waits for the completion this ring's TRB
    /// produced, returning the event.
    ///
    /// Matched **by the address the command was written at**, which the
    /// completion event carries in its parameter. Taking the next completion
    /// instead would work exactly until two commands were outstanding, and then
    /// silently attribute one command's answer to another.
    fn command(&mut self, entry: Trb) -> Result<Trb, UsbError> {
        let page = self.command;
        let mut ring = self.command_ring;
        let at =
            with_page(&page, |memory| ring.push(entry, memory)).map_err(|_| UsbError::Protocol)?;
        self.command_ring = ring;
        self.controller.doorbell(0, 0);
        self.wait_event(trb::COMMAND_COMPLETION, at, POLL_LIMIT)
    }

    /// Waits for an event of `kind` naming `parameter`.
    ///
    /// Every other event seen on the way is **consumed and dropped**, which is
    /// correct here and would not be in a host that pipelined: this program
    /// issues one thing at a time, so the only events it can pass over are port
    /// changes it will re-read from `PORTSC` anyway.
    fn wait_event(&mut self, kind: u32, parameter: u64, limit: u32) -> Result<Trb, UsbError> {
        let mut bytes = [0u8; TRB_LEN];
        for _ in 0..limit {
            // One entry, read volatilely at the offset the ring is waiting on.
            // The controller writes this memory while this loop runs.
            dma_read(&self.events, self.event_ring.dequeue_offset(), &mut bytes);
            let Ok(raw) = Trb::read(&bytes) else {
                return Err(UsbError::Protocol);
            };
            let Some(event) = self.event_ring.accept(raw) else {
                continue;
            };
            self.controller.set_event_dequeue(&self.event_ring);
            if event.kind() == kind && event.parameter == parameter {
                return if event.is_success() {
                    Ok(event)
                } else if event.completion_code() == COMPLETION_STALL {
                    Err(UsbError::Stall)
                } else {
                    Err(UsbError::TransferError)
                };
            }
        }
        // A controller that never answers is a controller, not a hang.
        Err(UsbError::TransferError)
    }

    /// Pushes TRBs onto a device's ring and waits for the transfer event.
    fn transfer(
        &mut self,
        device_index: usize,
        endpoint_index: u8,
        ring_at: usize,
        entries: &[Trb],
        limit: u32,
    ) -> Result<Trb, UsbError> {
        let Some(device) = self.devices[device_index] else {
            return Err(UsbError::NoDevice);
        };
        let mut ring = match ring_at {
            EP0_RING_AT => device.ep0,
            IN_RING_AT => device.data_in,
            _ => device.data_out,
        };
        let pushed = with_page(&device.rings, |memory| {
            let window = &mut memory[ring_at..ring_at + RING_WINDOW];
            let mut last = 0;
            for entry in entries {
                last = ring.push(*entry, window)?;
            }
            Ok::<u64, tessera_xhci::Error>(last)
        });
        let last = pushed.map_err(|_| UsbError::Protocol)?;
        if let Some(slot) = self.devices[device_index].as_mut() {
            match ring_at {
                EP0_RING_AT => slot.ep0 = ring,
                IN_RING_AT => slot.data_in = ring,
                _ => slot.data_out = ring,
            }
        }
        self.controller
            .doorbell(device.address, u32::from(endpoint_index));
        self.wait_event(trb::TRANSFER_EVENT, last, limit)
    }

    /// One control transfer on a device's endpoint zero.
    ///
    /// Returns how many bytes came back, which for a read is authoritative: a
    /// device is allowed to send less than was asked for, and the completion
    /// event's residual is the only place that shows.
    fn control(
        &mut self,
        device_index: usize,
        setup: [u8; 8],
        length: u16,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        if usize::from(length) > data.len() || usize::from(length) > PAGE as usize {
            return Err(UsbError::Protocol);
        }
        let device_to_host = setup[0] & 0x80 != 0;
        if !device_to_host && length > 0 {
            dma_write(&self.buffer, 0, &data[..usize::from(length)]);
        } else {
            dma_zero(&self.buffer, 0, usize::from(length));
        }
        let stages = control_transfer(setup, self.buffer.phys, u32::from(length), device_to_host);
        // A control transfer with no data stage is two TRBs, not three with an
        // empty one: a data stage of zero length is a transfer the controller
        // will try to make.
        let event = if length == 0 {
            self.transfer(
                device_index,
                1,
                EP0_RING_AT,
                &[stages[0], stages[2]],
                POLL_LIMIT,
            )?
        } else {
            self.transfer(device_index, 1, EP0_RING_AT, &stages, POLL_LIMIT)?
        };
        let moved = usize::from(length).saturating_sub(event.residual() as usize);
        if device_to_host && moved > 0 {
            dma_read(&self.buffer, 0, &mut data[..moved]);
        }
        Ok(moved)
    }

    /// A bulk or interrupt transfer on one of a device's data endpoints.
    fn data_transfer(
        &mut self,
        device_index: usize,
        endpoint: &Endpoint,
        length: u16,
        data: &mut [u8],
        brief: bool,
    ) -> Result<usize, UsbError> {
        if usize::from(length) > data.len() || usize::from(length) > PAGE as usize {
            return Err(UsbError::Protocol);
        }
        if !endpoint.device_to_host() {
            dma_write(&self.buffer, 0, &data[..usize::from(length)]);
        } else {
            dma_zero(&self.buffer, 0, usize::from(length));
        }
        let event = self.transfer(
            device_index,
            endpoint.context_index(),
            if endpoint.device_to_host() {
                IN_RING_AT
            } else {
                OUT_RING_AT
            },
            &[normal(self.buffer.phys, u32::from(length))],
            if brief { BRIEF_POLL_LIMIT } else { POLL_LIMIT },
        );
        let event = match event {
            Ok(event) => event,
            // **Nothing had happened, which is not an error.** A brief transfer
            // asks whether the device has already answered; zero bytes moved
            // and no failure is the honest report, and it is the same shape a
            // short transfer has.
            Err(UsbError::TransferError) if brief => return Ok(0),
            Err(e) => return Err(e),
        };
        let moved = usize::from(length).saturating_sub(event.residual() as usize);
        if endpoint.device_to_host() && moved > 0 {
            dma_read(&self.buffer, 0, &mut data[..moved]);
        }
        Ok(moved)
    }
}

/// The completion code a controller reports for a halted endpoint.
const COMPLETION_STALL: u8 = 6;

/// The device this host will drive, and nothing else.
///
/// **Compiled in, like the device manager's manifest and for the same reason.**
/// A policy is data, and what should deliver it is a configuration service
/// reading a signed package. An array here is the honest interim: the host
/// consults a policy rather than deciding for itself, and where the policy
/// comes from is one substitution away.
fn policy() -> Result<Policy, u64> {
    let mut policy = Policy::new();
    // Hubs, because the tree cannot be walked without them.
    if policy.allow_class(class::HUB).is_err() {
        return Err(fail(0xc5, 0));
    }
    // Bulk-only SCSI storage, narrowed to the protocol rather than the class: a
    // storage device speaking something else is a device this system has no
    // driver for, and admitting it would put an unbound device in a driver's
    // hands.
    if policy
        .allow(tessera_usb::Allowed {
            class: class::MASS_STORAGE,
            subclass: Some(storage::SUBCLASS_SCSI),
            protocol: Some(storage::PROTOCOL_BULK_ONLY),
        })
        .is_err()
    {
        return Err(fail(0xc5, 1));
    }
    // Boot-protocol human interface devices.
    if policy
        .allow(tessera_usb::Allowed {
            class: class::HID,
            subclass: Some(hid::SUBCLASS_BOOT),
            protocol: None,
        })
        .is_err()
    {
        return Err(fail(0xc5, 2));
    }
    Ok(policy)
}

/// Which class code a device is declared with, given what it turned out to be.
fn class_code_for(device: &Device) -> u32 {
    if !device.authorized {
        return CLASS_CODE_REFUSED;
    }
    match device.class {
        class::HUB => CLASS_CODE_USB,
        class::MASS_STORAGE => CLASS_CODE_MASS_STORAGE,
        class::HID => CLASS_CODE_INPUT,
        _ => CLASS_CODE_REFUSED,
    }
}

/// Brings a device up: a slot, a context, an address, and its descriptors.
///
/// `route` is the path through the hubs and `parent` the hub's slot and port
/// for a device that needs a transaction translator. Both are zero for a device
/// on a root port, which is the case that works whatever they are — and that is
/// exactly why they are arguments rather than something worked out here.
#[allow(clippy::too_many_arguments)]
fn enumerate(
    host: &mut Host<'_>,
    pages: &mut Pages,
    policy: &Policy,
    root_port: u8,
    speed: u8,
    route: u32,
    depth: u32,
    parent_tt: Option<(u8, u8)>,
) -> Result<Option<usize>, u64> {
    let Some(index) = host.devices.iter().position(Option::is_none) else {
        // Bounded, and reported: a device this host cannot hold is one it says
        // it cannot hold rather than one it silently skips.
        return Err(fail(0xc6, 0x100));
    };
    let contexts = pages.take()?;
    let rings = pages.take()?;
    dma_zero(&contexts, 0, PAGE as usize);
    dma_zero(&rings, 0, PAGE as usize);

    // Ask for a slot, which is the controller's name for the device.
    let event = match host.command(command(trb::ENABLE_SLOT, 0)) {
        Ok(event) => event,
        Err(_) => return Err(fail(0xc6, 1)),
    };
    let slot = event.slot();
    if slot == 0 || usize::from(slot) > MAX_DEVICES * 4 {
        return Err(fail(0xc6, 2));
    }

    let built = with_page(&rings, |memory| {
        let ep0 = Ring::new(
            rings.phys + EP0_RING_AT as u64,
            RING_ENTRIES,
            &mut memory[EP0_RING_AT..EP0_RING_AT + RING_WINDOW],
        )?;
        let data_in = Ring::new(
            rings.phys + IN_RING_AT as u64,
            RING_ENTRIES,
            &mut memory[IN_RING_AT..IN_RING_AT + RING_WINDOW],
        )?;
        let data_out = Ring::new(
            rings.phys + OUT_RING_AT as u64,
            RING_ENTRIES,
            &mut memory[OUT_RING_AT..OUT_RING_AT + RING_WINDOW],
        )?;
        Ok::<(Ring, Ring, Ring), tessera_xhci::Error>((ep0, data_in, data_out))
    });
    let Ok((ep0, data_in, data_out)) = built else {
        return Err(fail(0xc6, 3));
    };

    // The input context: what the controller should read, the slot, and
    // endpoint zero.
    let mut input = [0u8; 1024];
    if context::write_input_control(&mut input, 0b11, 0, 0).is_err() {
        return Err(fail(0xc6, 5));
    }
    let slot_at = context::at(1, host.context_len);
    if context::write_slot(&mut input, slot_at, route, speed, 1, root_port, parent_tt).is_err() {
        return Err(fail(0xc6, 6));
    }
    let ep0_at = context::at(2, host.context_len);
    if context::write_endpoint(
        &mut input,
        ep0_at,
        context::CONTROL,
        context::default_packet_size(speed),
        rings.phys + EP0_RING_AT as u64,
        ep0.cycle(),
        0,
    )
    .is_err()
    {
        return Err(fail(0xc6, 7));
    }
    dma_write(&contexts, INPUT_CONTEXT_AT, &input[..host.context_len * 3]);

    // The controller writes the device's own context here, and finds it through
    // the device context base address array.
    dma_put64(
        &host.dcbaa,
        usize::from(slot) * 8,
        contexts.phys + DEVICE_CONTEXT_AT as u64,
    );

    host.devices[index] = Some(Device {
        address: slot,
        depth,
        vendor: 0,
        product: 0,
        class: 0,
        subclass: 0,
        protocol: 0,
        interface: 0,
        authorized: false,
        endpoint_in: None,
        endpoint_out: None,
        handle: 0,
        contexts,
        rings,
        ep0,
        data_in,
        data_out,
    });

    if host
        .command(command_with_context(
            trb::ADDRESS_DEVICE,
            slot,
            contexts.phys + INPUT_CONTEXT_AT as u64,
        ))
        .is_err()
    {
        host.devices[index] = None;
        return Err(fail(0xc6, 8));
    }

    // Now it can be asked what it is. Everything below is the device's word and
    // is parsed rather than indexed.
    let mut buffer = [0u8; CONFIG_BUF_LEN];
    let read = host.control(
        index,
        request::get_descriptor(descriptor::DEVICE, 0, 18),
        18,
        &mut buffer,
    );
    let Ok(read) = read else {
        return Err(fail(0xc6, 9));
    };
    let Ok(identity) = tessera_usb::DeviceDescriptor::parse(&buffer[..read]) else {
        return Err(fail(0xc6, 0xa));
    };

    // The configuration, in two transfers: nine bytes to learn how long it is,
    // then the whole of it. Reading a fixed size and hoping would either
    // truncate a large configuration or read a device's descriptors into the
    // tail of the previous device's.
    let mut header = [0u8; 9];
    if host
        .control(
            index,
            request::get_descriptor(descriptor::CONFIGURATION, 0, 9),
            9,
            &mut header,
        )
        .is_err()
    {
        return Err(fail(0xc6, 0xb));
    }
    let total = usize::from(u16::from_le_bytes([header[2], header[3]]));
    if total < 9 || total > CONFIG_BUF_LEN {
        // Refused rather than truncated: a configuration read in part describes
        // a device that is not the one attached.
        return Err(fail(0xc6, 0xc));
    }
    buffer = [0u8; CONFIG_BUF_LEN];
    let read = host.control(
        index,
        request::get_descriptor(descriptor::CONFIGURATION, 0, total as u16),
        total as u16,
        &mut buffer,
    );
    let Ok(read) = read else {
        return Err(fail(0xc6, 0xd));
    };
    let Ok(configuration) = Configuration::parse(&buffer[..read]) else {
        return Err(fail(0xc6, 0xe));
    };
    let Some(interface) = configuration.interfaces().first().copied() else {
        return Err(fail(0xc6, 0xf));
    };

    // **The policy, and the only place it is applied.** A device it refuses is
    // left exactly here: addressed, in the graph, and never configured.
    let authorized = policy.authorize_device(&configuration) == tessera_usb::Authorization::Allowed;

    let endpoint_in = interface
        .find_endpoint(TransferType::Bulk, true)
        .or_else(|| interface.find_endpoint(TransferType::Interrupt, true));
    let endpoint_out = interface
        .find_endpoint(TransferType::Bulk, false)
        .or_else(|| interface.find_endpoint(TransferType::Interrupt, false));

    if let Some(device) = host.devices[index].as_mut() {
        device.vendor = identity.vendor;
        device.product = identity.product;
        device.class = interface.class;
        device.subclass = interface.subclass;
        device.protocol = interface.protocol;
        device.interface = interface.number;
        device.authorized = authorized;
        device.endpoint_in = endpoint_in;
        device.endpoint_out = endpoint_out;
    }

    if authorized {
        configure(host, index, &configuration, &interface)?;
    }
    Ok(Some(index))
}

/// Gives an admitted device its endpoints and selects its configuration.
fn configure(
    host: &mut Host<'_>,
    index: usize,
    configuration: &Configuration,
    interface: &Interface,
) -> Result<(), u64> {
    let Some(device) = host.devices[index] else {
        return Err(fail(0xc7, 0));
    };
    // One input context adding every endpoint at once, because `Configure
    // Endpoint` is one command: adding them one at a time would work and would
    // ask the controller to re-plan the bus schedule once per endpoint.
    let mut input = [0u8; 1024];
    let mut add = 0b1u32;
    let mut highest = 1u8;
    for endpoint in interface.endpoints() {
        let index_of = endpoint.context_index();
        // Isochronous endpoints are declared by devices this host admits and
        // are not configured: there is no periodic schedule here, and a pipe
        // opened without one would accept transfers it could not keep.
        if endpoint.transfer_type() == TransferType::Isochronous {
            continue;
        }
        let kind = match (endpoint.transfer_type(), endpoint.device_to_host()) {
            (TransferType::Bulk, true) => context::BULK_IN,
            (TransferType::Bulk, false) => context::BULK_OUT,
            (TransferType::Interrupt, true) => context::INTERRUPT_IN,
            (TransferType::Interrupt, false) => context::INTERRUPT_OUT,
            _ => continue,
        };
        add |= 1 << index_of;
        highest = highest.max(index_of);
        // Its own ring, named in its own context.
        let (ring_at, cycle) = if endpoint.device_to_host() {
            (IN_RING_AT, device.data_in.cycle())
        } else {
            (OUT_RING_AT, device.data_out.cycle())
        };
        if context::write_endpoint(
            &mut input,
            context::at(usize::from(index_of) + 1, host.context_len),
            kind,
            endpoint.max_packet_size,
            device.rings.phys + ring_at as u64,
            cycle,
            endpoint.interval,
        )
        .is_err()
        {
            return Err(fail(0xc7, 1));
        }
    }
    if context::write_input_control(&mut input, add, 0, configuration.value).is_err() {
        return Err(fail(0xc7, 2));
    }
    // The slot context is re-stated with the new highest endpoint, because the
    // controller reads how many contexts follow from it and a stale one would
    // stop it reading the endpoints just added.
    let mut existing = [0u8; 64];
    dma_read(
        &device.contexts,
        INPUT_CONTEXT_AT + context::at(1, host.context_len),
        &mut existing[..host.context_len],
    );
    existing[3] = (existing[3] & 0x07) | (highest << 3);
    let slot_at = context::at(1, host.context_len);
    input[slot_at..slot_at + host.context_len].copy_from_slice(&existing[..host.context_len]);
    dma_write(&device.contexts, INPUT_CONTEXT_AT, &input[..1024]);

    if host
        .command(command_with_context(
            trb::CONFIGURE_ENDPOINT,
            device.address,
            device.contexts.phys + INPUT_CONTEXT_AT as u64,
        ))
        .is_err()
    {
        return Err(fail(0xc7, 3));
    }
    let mut nothing = [0u8; 1];
    if host
        .control(
            index,
            request::set_configuration(configuration.value),
            0,
            &mut nothing,
        )
        .is_err()
    {
        return Err(fail(0xc7, 4));
    }
    Ok(())
}

/// Walks a hub's ports and enumerates whatever is behind them.
///
/// The hub is driven through its own control endpoint, with class requests
/// rather than registers — a hub has no more registers than the devices on it.
/// Its change bits are acknowledged one feature at a time, which is the same
/// discipline a root port's write-one-to-clear bits need and the only form a
/// hub offers.
fn walk_hub(
    host: &mut Host<'_>,
    pages: &mut Pages,
    policy: &Policy,
    hub_index: usize,
    root_port: u8,
) -> Result<(), u64> {
    let Some(hub) = host.devices[hub_index] else {
        return Err(fail(0xc8, 0));
    };
    let mut buffer = [0u8; 16];
    let read = host.control(
        hub_index,
        request::get_hub_descriptor(u16::try_from(buffer.len()).unwrap_or(9)),
        buffer.len() as u16,
        &mut buffer,
    );
    let Ok(read) = read else {
        return Err(fail(0xc8, 1));
    };
    let Ok(descriptor) = HubDescriptor::parse(&buffer[..read]) else {
        return Err(fail(0xc8, 2));
    };

    for hub_port_number in 1..=descriptor.ports {
        // Power the port, then look at it. A port nobody powered reports
        // nothing connected however full it is.
        let mut nothing = [0u8; 1];
        if host
            .control(
                hub_index,
                request::set_port_feature(hub_port_number, hub_port::FEATURE_POWER),
                0,
                &mut nothing,
            )
            .is_err()
        {
            continue;
        }
        let mut status = [0u8; 4];
        if host
            .control(
                hub_index,
                request::get_port_status(hub_port_number),
                4,
                &mut status,
            )
            .is_err()
        {
            continue;
        }
        let bits = u16::from_le_bytes([status[0], status[1]]);
        if bits & hub_port::CONNECTED == 0 {
            continue;
        }
        // Acknowledge the connection this walk is acting on, and only that: a
        // hub's change bits are cleared one feature at a time.
        let _ = host.control(
            hub_index,
            request::clear_port_feature(hub_port_number, hub_port::FEATURE_C_CONNECTION),
            0,
            &mut nothing,
        );
        if host
            .control(
                hub_index,
                request::set_port_feature(hub_port_number, hub_port::FEATURE_RESET),
                0,
                &mut nothing,
            )
            .is_err()
        {
            continue;
        }
        // Wait for the reset to finish, and read the speed it settled at — a
        // device behind a hub can be slower than the hub, and addressing it at
        // the hub's speed would address something that is not there.
        let mut speed = context::SPEED_FULL;
        let mut reset_done = false;
        for _ in 0..POLL_LIMIT / 1024 {
            if host
                .control(
                    hub_index,
                    request::get_port_status(hub_port_number),
                    4,
                    &mut status,
                )
                .is_err()
            {
                break;
            }
            let bits = u16::from_le_bytes([status[0], status[1]]);
            if bits & hub_port::RESET == 0 && bits & hub_port::ENABLED != 0 {
                speed = if bits & hub_port::LOW_SPEED != 0 {
                    context::SPEED_LOW
                } else if bits & hub_port::HIGH_SPEED != 0 {
                    context::SPEED_HIGH
                } else {
                    context::SPEED_FULL
                };
                reset_done = true;
                break;
            }
        }
        if !reset_done {
            continue;
        }
        let _ = host.control(
            hub_index,
            request::clear_port_feature(hub_port_number, hub_port::FEATURE_C_RESET),
            0,
            &mut nothing,
        );

        // The route string gains a tier: four bits per hub, the first tier in
        // the low nibble.
        let route = u32::from(hub_port_number & 0xf);
        // A low or full speed device behind a hub needs the hub named as its
        // transaction translator; the hub is what speaks to it at its speed.
        let translator = if speed == context::SPEED_HIGH {
            None
        } else {
            Some((hub.address, hub_port_number))
        };
        let Some(child) = enumerate(
            host,
            pages,
            policy,
            root_port,
            speed,
            route,
            hub.depth + 1,
            translator,
        )?
        else {
            continue;
        };
        // Declared **behind the hub**, so the graph has the shape the machine
        // has and the cost of reaching it is the sum of two relays.
        let Some(device) = host.devices[child] else {
            continue;
        };
        let handle = declare(
            hub.handle,
            device.address,
            class_code_for(&device),
            device.vendor,
            device.product,
        )?;
        if let Some(slot) = host.devices[child].as_mut() {
            slot.handle = handle;
        }
        if device.authorized {
            offer(handle)?;
        }
    }
    Ok(())
}

/// Finds the device at an address a class driver named.
fn device_at(host: &Host<'_>, address: u32) -> Option<usize> {
    host.devices
        .iter()
        .position(|slot| slot.is_some_and(|d| u32::from(d.address) == address))
}

/// The reply a request about a device gets: what it is, or why not.
fn describe(host: &Host<'_>, address: u32) -> UsbDeviceReply {
    let mut reply = UsbDeviceReply {
        size: UsbDeviceReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: UsbError::NoDevice,
        address,
        vendor: 0,
        product: 0,
        class: 0,
        subclass: 0,
        protocol: 0,
        interface: 0,
        depth: 0,
        reserved: 0,
    };
    if let Some(index) = device_at(host, address)
        && let Some(device) = host.devices[index]
    {
        reply.status = if device.authorized {
            UsbError::Ok
        } else {
            UsbError::Unauthorized
        };
        reply.vendor = u32::from(device.vendor);
        reply.product = u32::from(device.product);
        reply.class = u32::from(device.class);
        reply.subclass = u32::from(device.subclass);
        reply.protocol = u32::from(device.protocol);
        reply.interface = u32::from(device.interface);
        reply.depth = device.depth;
    }
    reply
}

/// Answers one class driver's request. Returns the reply's encoded length.
fn serve(
    host: &mut Host<'_>,
    method: u32,
    request: Result<UsbHostIncoming, WireError>,
    msg_buf: &mut [u8; MSG_BUF_LEN],
) -> Result<usize, u64> {
    let transfer_reply =
        |status: UsbError, moved: u32, data: [u8; 64], buf: &mut [u8; MSG_BUF_LEN]| {
            let reply = UsbTransferReply {
                size: UsbTransferReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                transferred: moved,
                data,
            };
            match encode(&reply, &mut buf[..UsbTransferReply::WIRE_SIZE]) {
                Ok(_) => Ok(UsbTransferReply::WIRE_SIZE),
                Err(_) => Err(fail(0xc9, 0xe)),
            }
        };

    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return transfer_reply(UsbError::Protocol, 0, [0u8; 64], msg_buf);
        }
        Err(_) => return Err(fail(0xc9, u64::from(method))),
    };

    match request {
        UsbHostIncoming::Describe(ask) => {
            let reply = describe(host, ask.address);
            match encode(&reply, &mut msg_buf[..UsbDeviceReply::WIRE_SIZE]) {
                Ok(_) => Ok(UsbDeviceReply::WIRE_SIZE),
                Err(_) => Err(fail(0xc9, 0xe)),
            }
        }
        UsbHostIncoming::Control(ask) => {
            let (status, moved, data) = relay_control(host, &ask);
            transfer_reply(status, moved, data, msg_buf)
        }
        UsbHostIncoming::Transfer(ask) => {
            let (status, moved, data) = relay_transfer(host, &ask);
            transfer_reply(status, moved, data, msg_buf)
        }
    }
}

/// A control transfer a class driver asked for.
fn relay_control(
    host: &mut Host<'_>,
    ask: &usb_host::UsbControlRequest,
) -> (UsbError, u32, [u8; 64]) {
    let mut data = [0u8; 64];
    let Some(index) = device_at(host, ask.address) else {
        return (UsbError::NoDevice, 0, data);
    };
    // **The refusal, enforced rather than recorded.** A device the policy
    // turned away is in the graph and answers nothing.
    if !host.devices[index].is_some_and(|d| d.authorized) {
        return (UsbError::Unauthorized, 0, data);
    }
    if ask.length as usize > MAX_PAYLOAD {
        return (UsbError::Protocol, 0, data);
    }
    data.copy_from_slice(&ask.data);
    match host.control(index, ask.setup, ask.length as u16, &mut data) {
        Ok(moved) => (UsbError::Ok, moved as u32, data),
        Err(e) => (e, 0, [0u8; 64]),
    }
}

/// A bulk or interrupt transfer a class driver asked for.
fn relay_transfer(host: &mut Host<'_>, ask: &UsbTransferRequest) -> (UsbError, u32, [u8; 64]) {
    let mut data = [0u8; 64];
    let Some(index) = device_at(host, ask.address) else {
        return (UsbError::NoDevice, 0, data);
    };
    let Some(device) = host.devices[index] else {
        return (UsbError::NoDevice, 0, data);
    };
    if !device.authorized {
        return (UsbError::Unauthorized, 0, data);
    }
    // Isochronous is declared in this protocol and refused here, so a class
    // driver is told "this host will not" rather than left to infer it.
    if ask.kind == UsbTransferKind::Isochronous {
        return (UsbError::NotSupported, 0, data);
    }
    if ask.length as usize > MAX_PAYLOAD {
        return (UsbError::Protocol, 0, data);
    }
    // The endpoint has to be one the *device* described. A host that opened a
    // pipe on whatever number arrived would let a class driver address an
    // endpoint its device never mentioned.
    let endpoint = match (device.endpoint_in, device.endpoint_out) {
        (Some(input), _) if u32::from(input.address) == ask.endpoint => input,
        (_, Some(output)) if u32::from(output.address) == ask.endpoint => output,
        _ => return (UsbError::Protocol, 0, data),
    };
    data.copy_from_slice(&ask.data);
    match host.data_transfer(
        index,
        &endpoint,
        ask.length as u16,
        &mut data,
        ask.flags & TRANSFER_BRIEF != 0,
    ) {
        Ok(moved) => (UsbError::Ok, moved as u32, data),
        Err(e) => (e, 0, [0u8; 64]),
    }
}

/// The whole program.
fn run() -> u64 {
    if let Err(code) = bind() {
        return code;
    }
    let base = match map_device(MMIO_VA) {
        Ok(base) => base,
        Err(code) => return code,
    };
    let registers = UserRegisters {
        base: base as usize,
    };
    let controller = match Controller::discover(&registers) {
        Ok(controller) => controller,
        Err(_) => return fail(0xca, 0),
    };
    let context_len = context::size_of(&registers);

    let mut pages = Pages { next: 0 };
    let dcbaa = match pages.take() {
        Ok(page) => page,
        Err(code) => return code,
    };
    let command = match pages.take() {
        Ok(page) => page,
        Err(code) => return code,
    };
    let events = match pages.take() {
        Ok(page) => page,
        Err(code) => return code,
    };
    let buffer = match pages.take() {
        Ok(page) => page,
        Err(code) => return code,
    };
    dma_zero(&dcbaa, 0, PAGE as usize);
    dma_zero(&events, 0, PAGE as usize);

    // **Memory the controller owns and this program never reads.** A controller
    // asking for scratchpad pages and not given them writes where the first
    // entry of the device context array points, which is nowhere.
    let wanted = controller.scratchpad_count();
    if wanted > MAX_SCRATCHPAD {
        return fail(0xca, 0x100 | u64::from(wanted));
    }
    if wanted > 0 {
        let array = match pages.take() {
            Ok(page) => page,
            Err(code) => return code,
        };
        dma_zero(&array, 0, PAGE as usize);
        for index in 0..wanted {
            let scratch = match pages.take() {
                Ok(page) => page,
                Err(code) => return code,
            };
            dma_zero(&scratch, 0, PAGE as usize);
            dma_put64(&array, index as usize * 8, scratch.phys);
        }
        dma_put64(&dcbaa, 0, array.phys);
    }

    let command_ring = match with_page(&command, |memory| {
        Ring::new(command.phys, RING_ENTRIES, memory)
    }) {
        Ok(ring) => ring,
        Err(_) => return fail(0xca, 1),
    };
    let event_ring = match EventRing::new(events.phys, EVENT_ENTRIES) {
        Ok(ring) => ring,
        Err(_) => return fail(0xca, 2),
    };
    // The event ring segment table: one segment, its base and its size.
    dma_put64(&dcbaa, ERST_AT, events.phys);
    dma_write(
        &dcbaa,
        ERST_AT + 8,
        &(u32::from(EVENT_ENTRIES)).to_le_bytes(),
    );

    if controller
        .reset_and_run(
            dcbaa.phys,
            &command_ring,
            dcbaa.phys + ERST_AT as u64,
            &event_ring,
        )
        .is_err()
    {
        return fail(0xca, 3);
    }

    let mut host = Host {
        controller,
        context_len,
        dcbaa,
        command,
        command_ring,
        events,
        event_ring,
        buffer,
        devices: [None; MAX_DEVICES],
    };
    let policy = match policy() {
        Ok(policy) => policy,
        Err(code) => return code,
    };

    // Every root port, then every hub found on one. Two passes rather than
    // recursion: the tree this host walks is two deep by construction, and a
    // recursive walk would need a stack this program has no allocator for.
    let ports = host.controller.max_ports();
    let mut hubs = [None; MAX_DEVICES];
    let mut hub_count = 0;
    for root in 1..=ports {
        let Ok(status) = host.controller.port_status(root) else {
            continue;
        };
        if status & port::CONNECTED == 0 {
            continue;
        }
        if host.controller.reset_port(root).is_err() {
            continue;
        }
        let speed = host
            .controller
            .port_speed(root)
            .unwrap_or(context::SPEED_HIGH);
        let found = match enumerate(&mut host, &mut pages, &policy, root, speed, 0, 0, None) {
            Ok(Some(index)) => index,
            Ok(None) => continue,
            Err(code) => return code,
        };
        let Some(device) = host.devices[found] else {
            continue;
        };
        let handle = match declare(
            CONTROLLER_HANDLE,
            device.address,
            class_code_for(&device),
            device.vendor,
            device.product,
        ) {
            Ok(handle) => handle,
            Err(code) => return code,
        };
        if let Some(slot) = host.devices[found].as_mut() {
            slot.handle = handle;
        }
        // **Only an admitted device is offered.** A refused one stays declared
        // and unoffered: visible in the graph, and in nobody's hands.
        if device.authorized
            && device.class != class::HUB
            && let Err(code) = offer(handle)
        {
            return code;
        }
        if device.authorized && device.class == class::HUB && hub_count < MAX_DEVICES {
            hubs[hub_count] = Some((found, root));
            hub_count += 1;
        }
    }
    for hub in hubs.iter().flatten() {
        if let Err(code) = walk_hub(&mut host, &mut pages, &policy, hub.0, hub.1) {
            return code;
        }
    }

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64) {
        Ok(args) => args,
        Err(code) => return code,
    };
    loop {
        let n = syscall2(
            SYS_CHANNEL_RECV,
            args.as_ptr() as u64,
            CLIENT_ENDPOINT_HANDLE,
        );
        if n < 0 {
            return fail(0xcb, (-n) as u64);
        }
        let method = kernel_u32(&args, ARGS_METHOD_ID);
        let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
        let request = UsbHostIncoming::decode(method, &mut Reader::in_message(&bytes, 0));
        let reply_len = match serve(&mut host, method, request, &mut msg_buf) {
            Ok(len) => len,
            Err(code) => return code,
        };
        patch_args(&mut args, ARGS_INLINE_LEN, reply_len as u64);
        let replied = syscall2(
            SYS_CHANNEL_REPLY_CONTINUE,
            args.as_ptr() as u64,
            CLIENT_ENDPOINT_HANDLE,
        );
        patch_args(&mut args, ARGS_INLINE_LEN, MSG_BUF_LEN as u64);
        if replied < 0 {
            return fail(0xcc, (-replied) as u64);
        }
    }
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
