// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **network class driver**: a `no_std` Rust user program that binds
//! a NIC by class and serves `tessera.driver.network` to a client over channel
//! IPC.
//!
//! The block class was proven by a driver that answered questions. This one
//! cannot be, and that is the whole reason the network class went first in the
//! rollout: **a frame arrives because a machine on the other side of the wire
//! sent one**, and no client asked for it. So this driver speaks first —
//! `ChannelSend`, with no request outstanding and nothing to reply to — which
//! is a direction the system did not have until now.
//!
//! Two consequences the block driver never met, both visible in this file:
//!
//! - **A received frame is given away.** `NetFrameEvent.buffer` is declared
//!   `transfer`, so the memory object holding the frame travels with the event
//!   and this driver holds nothing afterwards. It replenishes its receive pool
//!   with a fresh object. A client that is slow to consume frames therefore
//!   spends its own memory rather than stalling this driver — the asymmetry the
//!   contract calls `TRANSFERRED` ownership.
//! - **This driver never maps a received frame.** The buffer is created,
//!   attached to the device, written by the device, detached and handed on. The
//!   only thing that touches those bytes is the NIC and, afterwards, the
//!   client. The transport header goes somewhere else entirely — a page of this
//!   driver's own, on the other half of a two-descriptor chain — so the buffer
//!   the client receives holds the frame at its first byte and no virtio.
//!
//! The serve loop is one `PortWait` over a port carrying **both** the device's
//! interrupt and the client endpoint's message arrivals. That is what makes the
//! push unsolicited rather than merely asynchronous: the driver is not waiting
//! for the client when it decides to send.
//!
//! Link state is the second kind of event. `SetPower(STANDBY)` is, on this
//! class, the link going down — the contract says so — and this driver takes
//! the device to reset, answers `LINK_DOWN` to anything asked of it after, and
//! says so with `OnLinkChanged`. `ACTIVE` brings it back through the whole
//! handshake, which is what an autonegotiation costs here.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts"),
//! docs/drivers/02-storage-networking-usb-pcie.md,
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use device_abi::{DmaAllocArgs, IrqCompleteArgs, MapDeviceArgs};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use memory_abi::{DmaAttachArgs, DmaDetachArgs, MemoryConstraint, MemoryCreateArgs};
use network_driver::{
    NetControlReply, NetDescribeReply, NetError, NetFrameEvent, NetLinkEvent, NetPowerState,
    NetTransmitReply, NetworkDevice, NetworkDeviceIncoming,
};
use port_event::PortEventRecord;
use tessera_isl_runtime::{HandleRef, Ownership, Reader, WireError, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};
use tessera_virtio::{Layout, Mmio, NET_HDR_LEN, Net, QueueAddrs};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_SEND: u64 = 12;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_PORT_WAIT: u64 = 18;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_IRQ_COMPLETE: u64 = 26;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_DMA_ALLOC: u64 = 24;
const SYS_MEMORY_CREATE: u64 = 30;
const SYS_DMA_ATTACH: u64 = 32;
const SYS_DMA_DETACH: u64 = 33;

/// Port signals, as `kcore::ipc` numbers them: a device interrupt, a message
/// arriving on a bound endpoint, and a device that has left the machine.
///
/// This driver waits on ONE port carrying all three, so the number is the only
/// thing distinguishing "the NIC has a frame" from "the client asked for
/// something" — and a driver that confused them would service a completion
/// nobody reported.
const SIGNAL_INTERRUPT: u32 = 1;
const SIGNAL_MESSAGE: u32 = 2;
const SIGNAL_DEVICE_REMOVED: u32 = 3;

/// The capabilities boot installs, in order. The bind channel is the only
/// inbound authority at startup; the device arrives by asking for a class.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const SERVICE_PORT_HANDLE: u64 = 1;
const CLIENT_ENDPOINT_HANDLE: u64 = 2;
/// The **event** channel, and the reason it is a second channel rather than a
/// second use of the first: a pushed event and a reply share a queue, and a
/// client's `ChannelCall` would happily dequeue an event as its answer. Two
/// channels make that impossible rather than merely unlikely.
const EVENT_ENDPOINT_HANDLE: u64 = 3;
/// Where the bound device capability lands — four handles are installed above
/// it, so the kernel puts the first transferred one here.
const NET_DEVICE_HANDLE: u32 = 4;

/// Where this program asks for things in its own space.
const MMIO_VA: u64 = 0x0000_1000_0040_0000;
const DMA_VA: u64 = 0x0000_1000_0050_0000;

/// Virtqueue size, and the DMA page layout: the two ring blocks, the receive
/// chain's transport header, and the transmit frame. Every one of these is
/// memory this driver keeps; the received frame's buffer is not here at all.
const QUEUE_SIZE: u16 = 8;
const RX_RINGS_OFF: usize = 0x000;
const TX_RINGS_OFF: usize = 0x100;
const RX_HDR_OFF: usize = 0x200;
const TX_FRAME_OFF: usize = 0x400;
const DESC_OFF: usize = 0;
const AVAIL_OFF: usize = 128;
const USED_OFF: usize = 152;
const RINGS_TOTAL: usize = 222;
const PAGE: usize = 4096;

/// How much of a received frame this driver will accept, and the size of the
/// object it grants per frame. One page, because that is the allocation unit
/// and an MTU-sized frame fits inside it with room to spare.
const RX_FRAME_LEN: u32 = 2048;
const RX_OBJECT_BYTES: u64 = 4096;

/// What `Describe` answers.
///
/// `TRANSMIT`, and `LINK_EVENTS` only when the device actually reports link
/// state — advertising it off a config field that was never negotiated would
/// make the feature bit a lie. `PROMISCUOUS` is deliberately absent: a driver
/// advertising everything makes the conformance suite's unimplemented-optional
/// rule unreachable, and an optionality nobody exercises is one nobody checked.
const FEATURE_TRANSMIT: u64 = 0x1;
const FEATURE_LINK_EVENTS: u64 = 0x8;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace
/// (`tessera_class_conformance::VENDOR_ORDINAL_BASE`). This driver declares
/// none, so every one of them is refused.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// The interface's MTU, as this driver reports it.
const MTU: u32 = 1500;

/// What coming back from `STANDBY` costs, reported rather than named by the
/// contract: on this class the deepest state is a link that is down, and
/// bringing it up is the whole virtio handshake again.
const RESUME_LATENCY_US: u64 = 2000;

/// Bound on a completion poll: no timer exists at EL0, so a transmit's wait is
/// a bounded spin. Only the transmit path spins — receives are woken by the
/// device interrupt, which is the point of the whole loop.
const POLL_LIMIT: u32 = 50_000_000;

/// The symmetric request/reply buffer: the largest struct in either direction
/// is a `NetTransmitRequest` at 88 bytes.
const MSG_BUF_LEN: usize = 128;

/// Field offsets in an encoded `ChannelMsgArgs` (`channel_msg.isl`).
const ARGS_METHOD_ID: usize = 32;
const ARGS_INLINE_LEN: usize = 48;
const ARGS_HANDLES_PTR: usize = 56;
const ARGS_HANDLE_COUNT: usize = 64;

/// Publish stores before a doorbell; `dsb ish` is unprivileged.
fn barrier() {
    // SAFETY: a data synchronization barrier has no operands and no side
    // effect beyond ordering.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
}

/// The `Mmio` impl over the register window `MapDevice` granted.
struct UserMmio {
    base: usize,
}

impl Mmio for UserMmio {
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the window the device capability granted, and every
        // `reg::` offset the transport core uses stays inside that page.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }

    fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read`; this driver exclusively owns the transport, which
        // the capability being conserved rather than shared is what guarantees.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// Reads back a u32 the kernel wrote into a buffer of this program's.
///
/// Volatile because the compiler has no idea a syscall wrote here and would
/// otherwise be entitled to reuse whatever this program last put there.
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

/// Writes a u64 into an encoded descriptor between messages.
///
/// Volatile for the mirror reason: the kernel reads this buffer, so a store the
/// compiler judged dead would leave it acting on the previous message's
/// descriptor.
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
        Err(_) => Err(fail(0x50, 0xe)),
    }
}

/// Acquires a device of `class` from the device manager. The capability lands
/// at [`NET_DEVICE_HANDLE`]; which device answers to "Network" is the manager's
/// finding, and the class in the reply is checked so a mis-bind is caught here
/// rather than as a driver talking to the wrong hardware.
fn bind(class: DeviceClass) -> Result<u32, u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0x51, 0xe));
    }
    let args = channel_args(message.as_ptr() as u64, message.len() as u64)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0x51, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x51, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0x51, 0x100 | u64::from(reply.status)));
    }
    if reply.class != class {
        return Err(fail(0x51, 0x200));
    }
    Ok(NET_DEVICE_HANDLE)
}

/// Maps the device's registers at `vaddr`, returning the register base.
fn map_device(vaddr: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(NET_DEVICE_HANDLE),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x52, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x52, (-base) as u64));
    }
    Ok(base as u64)
}

/// Allocates the driver's own DMA page — rings, receive header, transmit frame
/// — and returns its physical address.
fn dma_alloc(vaddr: u64) -> Result<u64, u64> {
    let args = DmaAllocArgs {
        size: DmaAllocArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(NET_DEVICE_HANDLE),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; DmaAllocArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x53, 0xe));
    }
    let phys = syscall2(SYS_DMA_ALLOC, buf.as_ptr() as u64, 0);
    if phys < 0 {
        return Err(fail(0x53, (-phys) as u64));
    }
    Ok(phys as u64)
}

/// Re-arms the device's interrupt line after the device itself has been acked
/// — the `IrqComplete` half of the mask-on-deliver protocol.
fn irq_complete() -> Result<(), u64> {
    let args = IrqCompleteArgs {
        size: IrqCompleteArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(NET_DEVICE_HANDLE),
        reserved: 0,
    };
    let mut buf = [0u8; IrqCompleteArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x54, 0xe));
    }
    let r = syscall2(SYS_IRQ_COMPLETE, buf.as_ptr() as u64, 0);
    if r < 0 {
        return Err(fail(0x54, (-r) as u64));
    }
    Ok(())
}

/// A receive buffer: a memory object this driver created and made reachable by
/// the device, and the address the device writes to.
///
/// **Never mapped here.** Nothing in this program forms a reference to those
/// bytes, which is what makes "the driver did not copy the frame" a property of
/// the code rather than a claim about it.
#[derive(Clone, Copy)]
struct RxBuffer {
    handle: u32,
    iova: u64,
}

/// Creates one receive buffer and attaches it to the device.
fn new_rx_buffer() -> Result<RxBuffer, u64> {
    let create = MemoryCreateArgs {
        size: MemoryCreateArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        bytes: RX_OBJECT_BYTES,
        // **Device-visible contiguity**, which is what a receive buffer needs
        // and all it needs: the NIC reaches this through an attachment, so the
        // broker lays whatever pages it drew out at consecutive device
        // addresses. Asking for physical contiguity would spend a run of memory
        // nothing can defragment on hardware that does not need one.
        constraints: MemoryConstraint(MemoryConstraint::DEVICE_CONTIGUOUS.bits()),
        alignment: 0,
        address_limit: 0,
    };
    let mut buf = [0u8; MemoryCreateArgs::WIRE_SIZE];
    if encode(&create, &mut buf).is_err() {
        return Err(fail(0x55, 0xe));
    }
    let handle = syscall2(SYS_MEMORY_CREATE, buf.as_ptr() as u64, 0);
    if handle < 0 {
        return Err(fail(0x55, (-handle) as u64));
    }
    let handle = handle as u32;

    let attach = DmaAttachArgs {
        size: DmaAttachArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(NET_DEVICE_HANDLE),
        memory: HandleRef::new(handle),
    };
    let mut buf = [0u8; DmaAttachArgs::WIRE_SIZE];
    if encode(&attach, &mut buf).is_err() {
        return Err(fail(0x56, 0xe));
    }
    let iova = syscall2(SYS_DMA_ATTACH, buf.as_ptr() as u64, 0);
    if iova < 0 {
        return Err(fail(0x56, (-iova) as u64));
    }
    Ok(RxBuffer {
        handle,
        iova: iova as u64,
    })
}

/// Stops the device reaching a buffer, which must happen before it is given
/// away: an object still attached is one the NIC can write into after somebody
/// else owns it.
fn detach(handle: u32) -> Result<(), u64> {
    let args = DmaDetachArgs {
        size: DmaDetachArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        memory: HandleRef::new(handle),
        reserved: 0,
    };
    let mut buf = [0u8; DmaDetachArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x57, 0xe));
    }
    let r = syscall2(SYS_DMA_DETACH, buf.as_ptr() as u64, 0);
    if r < 0 {
        return Err(fail(0x57, (-r) as u64));
    }
    Ok(())
}

/// Bounded poll until the used-ring index at `idx_addr` reaches `expected`.
fn poll_used_at(idx_addr: usize, expected: u16) -> bool {
    let idx = idx_addr as *const u16;
    let mut spins = 0u32;
    while spins < POLL_LIMIT {
        barrier();
        // SAFETY: an aligned volatile read inside a DMA page this program
        // owns; the device updates the index concurrently.
        if unsafe { idx.read_volatile() } == expected {
            return true;
        }
        spins += 1;
    }
    false
}

/// What this driver has been asked to be. `Standby` is a link that is down —
/// the contract's own reading of the state on this class — and everything the
/// data path is asked for while it holds answers `LINK_DOWN`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Power {
    Active,
    Idle,
    Standby,
}

impl Power {
    fn state(self) -> NetPowerState {
        match self {
            Power::Active => NetPowerState::Active,
            Power::Idle => NetPowerState::Idle,
            Power::Standby => NetPowerState::Standby,
        }
    }

    /// Whether frames move. `IDLE` on this class is a link that is up and not
    /// serving, so it does; `STANDBY` is the link itself being down.
    fn link_up(self) -> bool {
        self != Power::Standby
    }
}

/// Everything the serve loop carries between messages.
struct Driver {
    dma_phys: u64,
    power: Power,
    /// The buffer the device is currently able to write a frame into.
    rx: RxBuffer,
    /// How many receive buffers have been posted, and how many completions
    /// consumed — the avail-ring slot and the used-ring cursor.
    rx_posted: u16,
    rx_seen: u16,
    tx_posted: u16,
    /// Whether the device reports link state, and so whether this driver may
    /// honestly advertise `LINK_EVENTS`.
    reports_link: bool,
    mac: [u8; 6],
}

impl Driver {
    /// The rings' physical addresses, which do not change across a re-init.
    fn queues(&self) -> (QueueAddrs, QueueAddrs) {
        let rx = QueueAddrs {
            desc: self.dma_phys + RX_RINGS_OFF as u64 + DESC_OFF as u64,
            avail: self.dma_phys + RX_RINGS_OFF as u64 + AVAIL_OFF as u64,
            used: self.dma_phys + RX_RINGS_OFF as u64 + USED_OFF as u64,
        };
        let tx = QueueAddrs {
            desc: self.dma_phys + TX_RINGS_OFF as u64 + DESC_OFF as u64,
            avail: self.dma_phys + TX_RINGS_OFF as u64 + AVAIL_OFF as u64,
            used: self.dma_phys + TX_RINGS_OFF as u64 + USED_OFF as u64,
        };
        (rx, tx)
    }

    /// Brings the transport up and returns the live handle. Called at startup
    /// and again whenever the link comes back, because coming back from
    /// `STANDBY` is the whole handshake and not a resumption.
    fn bring_up<'m>(&mut self, mmio: &'m UserMmio) -> Result<Net<'m, UserMmio>, u64> {
        let (rx, tx) = self.queues();
        let net = match Net::init(mmio, rx, tx, QUEUE_SIZE) {
            Ok(net) => net,
            Err(e) => return Err(fail(0x58, e as u64)),
        };
        self.mac = net.mac();
        self.reports_link = net.reports_link();
        // The rings are fresh after a reset, so the cursors start over.
        self.rx_posted = 0;
        self.rx_seen = 0;
        self.tx_posted = 0;
        Ok(net)
    }
}

/// The one DMA page, as this program's view of what the device reads and
/// writes by physical address.
///
/// Called **once**, from `run`, and threaded from there: a second call would
/// hand out a second mutable reference to the same bytes, which is a thing the
/// language does not allow anyone to hold even when the addresses are known to
/// be fine.
fn dma_page() -> &'static mut [u8] {
    // SAFETY: `DmaAlloc` mapped exactly one zero-filled page read+write at
    // `DMA_VA` in this process's space, and every offset this program uses
    // stays inside it. This is the only reference formed.
    unsafe { core::slice::from_raw_parts_mut(DMA_VA as *mut u8, PAGE) }
}

/// Posts the current receive buffer as a two-descriptor chain: the transport
/// header into this driver's own page, the frame into the object it will give
/// away.
fn post_receive(dma: &mut [u8], driver: &mut Driver, net: &Net<'_, UserMmio>) {
    let idx = driver.rx_posted;
    {
        let (rings, _) = dma[RX_RINGS_OFF..].split_at_mut(RINGS_TOTAL);
        let (desc, avail) = rings.split_at_mut(AVAIL_OFF);
        net.post_rx_split(
            desc,
            avail,
            driver.dma_phys + RX_HDR_OFF as u64,
            driver.rx.iova,
            RX_FRAME_LEN,
            idx,
        );
    }
    driver.rx_posted = idx.wrapping_add(1);
    barrier();
    net.notify_rx();
}

/// Hands a received frame to the client and replenishes the pool.
///
/// **The whole of `TRANSFERRED` ownership, in the order it has to happen in.**
/// Detach first — an object the device can still reach is one it may write into
/// after somebody else owns it. Then send, which takes this driver's handle
/// with it. Only then is there a replacement to make, and the driver is
/// genuinely without a receive buffer in between: that is the cost the mode
/// names, and pretending otherwise would mean holding a copy.
fn hand_over_frame(
    dma: &mut [u8],
    driver: &mut Driver,
    net: &Net<'_, UserMmio>,
    frame_len: u32,
) -> Result<(), u64> {
    detach(driver.rx.handle)?;

    let event = NetFrameEvent {
        size: NetFrameEvent::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        length: frame_len,
        reserved: 0,
        // The frame is in the object, not here. The inline array is what a
        // driver with nothing to grant would use instead.
        frame: [0u8; 64],
        // An *index* into this message's transfers, not a handle number: the
        // number the client ends up holding is the kernel's to choose.
        buffer: HandleRef::new(0),
    };
    let mut message = [0u8; NetFrameEvent::WIRE_SIZE];
    if encode(&event, &mut message).is_err() {
        return Err(fail(0x59, 0xe));
    }
    let descriptor = HandleTransfer {
        // Both from the contract rather than from constants typed to match it:
        // the schema declares `buffer: transfer handle<Object, {READ, MAP}>`,
        // and that declaration is what the client was compiled against.
        mode: match NetFrameEvent::BUFFER_OWNERSHIP {
            Ownership::Transfer => TransferMode::Transfer,
            _ => return Err(fail(0x59, 4)),
        },
        rights: NetFrameEvent::BUFFER_RIGHTS,
        handle: driver.rx.handle,
    };
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    if encode(&descriptor, &mut transfer).is_err() {
        return Err(fail(0x59, 2));
    }
    let mut args = channel_args(message.as_ptr() as u64, message.len() as u64)?;
    patch_args(
        &mut args,
        ARGS_METHOD_ID,
        NetworkDevice::ON_FRAME_RECEIVED.into(),
    );
    patch_args(&mut args, ARGS_HANDLES_PTR, transfer.as_ptr() as u64);
    patch_args(&mut args, ARGS_HANDLE_COUNT, 1);
    let sent = syscall2(
        SYS_CHANNEL_SEND,
        args.as_ptr() as u64,
        EVENT_ENDPOINT_HANDLE,
    );
    if sent < 0 {
        // The client is not keeping up and the frame is gone with the message.
        // Reported, never quietly retried: a receive path that held frames for
        // a slow client would stall on it, which is exactly what `TRANSFERRED`
        // exists to prevent.
        return Err(fail(0x5a, (-sent) as u64));
    }

    driver.rx = new_rx_buffer()?;
    post_receive(dma, driver, net);
    Ok(())
}

/// Tells the client the link changed. One-way, like a frame: there is nothing
/// to reply to and nobody asked.
fn announce_link(link_up: bool) -> Result<(), u64> {
    let event = NetLinkEvent {
        size: NetLinkEvent::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        link_up: u32::from(link_up),
        reserved: 0,
    };
    let mut message = [0u8; NetLinkEvent::WIRE_SIZE];
    if encode(&event, &mut message).is_err() {
        return Err(fail(0x5b, 0xe));
    }
    let mut args = channel_args(message.as_ptr() as u64, message.len() as u64)?;
    patch_args(
        &mut args,
        ARGS_METHOD_ID,
        NetworkDevice::ON_LINK_CHANGED.into(),
    );
    let sent = syscall2(
        SYS_CHANNEL_SEND,
        args.as_ptr() as u64,
        EVENT_ENDPOINT_HANDLE,
    );
    if sent < 0 {
        return Err(fail(0x5b, (-sent) as u64));
    }
    Ok(())
}

/// Drains whatever the device has completed and pushes every frame it left.
fn on_interrupt(dma: &mut [u8], driver: &mut Driver, net: &Net<'_, UserMmio>) -> Result<(), u64> {
    net.ack_interrupt();
    loop {
        let used = &dma[RX_RINGS_OFF + USED_OFF..RX_RINGS_OFF + RINGS_TOTAL];
        let completion = match net.rx_completion(used, driver.rx_seen) {
            Ok(Some(completion)) => completion,
            Ok(None) => break,
            Err(e) => return Err(fail(0x5c, e as u64)),
        };
        driver.rx_seen = driver.rx_seen.wrapping_add(1);
        // The used ring counts the header the device wrote into this driver's
        // page as well as the frame; the frame is what is left.
        let total = completion.1 as usize;
        let frame_len = total.saturating_sub(NET_HDR_LEN) as u32;
        hand_over_frame(dma, driver, net, frame_len)?;
    }
    irq_complete()
}

/// Sends one frame and waits for the device to take it.
fn transmit(
    dma: &mut [u8],
    driver: &mut Driver,
    net: &Net<'_, UserMmio>,
    frame: &[u8],
) -> (NetError, u32) {
    if frame.is_empty() || frame.len() > MTU as usize {
        return (NetError::BadLength, 0);
    }
    let total = NET_HDR_LEN + frame.len();
    dma[TX_FRAME_OFF..TX_FRAME_OFF + NET_HDR_LEN].fill(0);
    dma[TX_FRAME_OFF + NET_HDR_LEN..TX_FRAME_OFF + total].copy_from_slice(frame);
    let idx = driver.tx_posted;
    {
        let (rings, _) = dma[TX_RINGS_OFF..].split_at_mut(RINGS_TOTAL);
        let (desc, avail) = rings.split_at_mut(AVAIL_OFF);
        net.post_tx(
            desc,
            avail,
            driver.dma_phys + TX_FRAME_OFF as u64,
            total as u32,
            idx,
        );
    }
    barrier();
    net.notify_tx();
    driver.tx_posted = idx.wrapping_add(1);
    if !poll_used_at(
        DMA_VA as usize + TX_RINGS_OFF + USED_OFF + 2,
        driver.tx_posted,
    ) {
        return (NetError::IoError, 0);
    }
    (NetError::Ok, frame.len() as u32)
}

/// Answers one client request. Returns the reply's encoded length.
fn serve<'m>(
    dma: &mut [u8],
    mmio: &'m UserMmio,
    driver: &mut Driver,
    net: &mut Net<'m, UserMmio>,
    method: u32,
    request: Result<NetworkDeviceIncoming, WireError>,
    msg_buf: &mut [u8; MSG_BUF_LEN],
) -> Result<usize, u64> {
    // A control reply, which most arms answer with. Built here so each arm
    // says only what it changes.
    let control = |status: NetError, state: NetPowerState, buf: &mut [u8; MSG_BUF_LEN]| {
        let reply = NetControlReply {
            size: NetControlReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status: status as u32,
            state,
        };
        match encode(&reply, &mut buf[..NetControlReply::WIRE_SIZE]) {
            Ok(_) => Ok(NetControlReply::WIRE_SIZE),
            Err(_) => Err(fail(0x5d, 0xe)),
        }
    };

    // An ordinal this contract does not define, one in the vendor range with
    // nothing negotiated, or a payload naming a capability that did not arrive:
    // three refusals the client should hear rather than three ways for this
    // driver to die holding a request.
    if method >= VENDOR_ORDINAL_BASE {
        return control(NetError::Protocol, driver.power.state(), msg_buf);
    }
    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return control(NetError::Protocol, driver.power.state(), msg_buf);
        }
        // A defined ordinal whose bytes do not decode is a different fact and a
        // fatal one: the client and this driver disagree about a type they both
        // compile from the same schema.
        Err(_) => return Err(fail(0x5e, 0)),
    };

    match request {
        NetworkDeviceIncoming::Describe(_) => {
            let mut features = FEATURE_TRANSMIT;
            if driver.reports_link {
                features |= FEATURE_LINK_EVENTS;
            }
            let mac = driver.mac;
            let reply = NetDescribeReply {
                size: NetDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                status: NetError::Ok,
                features,
                mtu: MTU,
                link_up: u32::from(driver.power.link_up() && net.link_up()),
                mac_low: u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
                mac_high: u32::from_le_bytes([mac[4], mac[5], 0, 0]),
                // What a client must respect about this device's DMA, reported
                // rather than assumed: descriptor alignment, the largest frame
                // a granted buffer holds, and that buffers are reachable only
                // through an attachment scoped to this device.
                dma_alignment: 16,
                dma_max_frame: RX_FRAME_LEN,
                dma_scoped: 1,
                power_states: (1 << NetPowerState::Active as u32)
                    | (1 << NetPowerState::Idle as u32)
                    | (1 << NetPowerState::Standby as u32),
                resume_latency_us: RESUME_LATENCY_US,
                vendor: 0,
                vendor_namespace: 0,
                vendor_extension_version: 0,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..NetDescribeReply::WIRE_SIZE]) {
                Ok(_) => Ok(NetDescribeReply::WIRE_SIZE),
                Err(_) => Err(fail(0x5d, 0xe)),
            }
        }
        NetworkDeviceIncoming::Transmit(request) => {
            let (status, sent) = if !driver.power.link_up() {
                // The device is present and configurable and the link is not
                // there — which is the distinction this class draws that the
                // block class's `NO_MEDIUM` does not.
                (NetError::LinkDown, 0)
            } else {
                let length = request.length as usize;
                if length > request.frame.len() {
                    (NetError::BadLength, 0)
                } else {
                    transmit(dma, driver, net, &request.frame[..length])
                }
            };
            let reply = NetTransmitReply {
                size: NetTransmitReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status: status as u32,
                sent,
            };
            match encode(&reply, &mut msg_buf[..NetTransmitReply::WIRE_SIZE]) {
                Ok(_) => Ok(NetTransmitReply::WIRE_SIZE),
                Err(_) => Err(fail(0x5d, 0xe)),
            }
        }
        NetworkDeviceIncoming::Reset(_) => {
            // What the contract defines a reset to leave: ACTIVE, features
            // re-negotiated, the MAC unchanged, promiscuous off (this driver
            // has no such mode to leave on), and every posted receive buffer
            // accounted for — here, replaced, because the device is going
            // through its own reset and the old one is unreachable after it.
            *net = driver.bring_up(mmio)?;
            driver.power = Power::Active;
            driver.rx = new_rx_buffer()?;
            post_receive(dma, driver, net);
            control(NetError::Ok, NetPowerState::Active, msg_buf)
        }
        NetworkDeviceIncoming::SetPower(request) => match request.state {
            NetPowerState::Off => {
                // A state this driver did not report is `NOT_SUPPORTED`, which
                // is what makes the `power_states` mask worth reading.
                control(NetError::NotSupported, driver.power.state(), msg_buf)
            }
            NetPowerState::Standby => {
                if driver.power != Power::Standby {
                    net.shutdown();
                    driver.power = Power::Standby;
                    announce_link(false)?;
                }
                control(NetError::Ok, NetPowerState::Standby, msg_buf)
            }
            NetPowerState::Active => {
                if driver.power == Power::Standby {
                    *net = driver.bring_up(mmio)?;
                    driver.rx = new_rx_buffer()?;
                    post_receive(dma, driver, net);
                    driver.power = Power::Active;
                    announce_link(true)?;
                }
                driver.power = Power::Active;
                control(NetError::Ok, NetPowerState::Active, msg_buf)
            }
            NetPowerState::Idle => {
                // The link stays up; the device simply is not being asked for
                // anything. Nothing to announce.
                if driver.power != Power::Standby {
                    driver.power = Power::Idle;
                }
                control(NetError::Ok, driver.power.state(), msg_buf)
            }
        },
        NetworkDeviceIncoming::SetPromiscuous(_) => {
            // Not advertised, so this is the one answer the contract permits.
            control(NetError::NotSupported, driver.power.state(), msg_buf)
        }
    }
}

/// The whole program: bind, bring the NIC up, and then serve until the device
/// leaves or something fails.
fn run() -> u64 {
    if let Err(code) = bind(DeviceClass::Network) {
        return code;
    }
    let reg_base = match map_device(MMIO_VA) {
        Ok(base) => base,
        Err(code) => return code,
    };
    let dma_phys = match dma_alloc(DMA_VA) {
        Ok(phys) => phys,
        Err(code) => return code,
    };

    // The ring offsets this page uses are exactly the transport core's layout;
    // a mismatch means the constants above and the core disagree, which would
    // show up as a device reading somebody else's memory.
    let layout = Layout::for_size(QUEUE_SIZE);
    if layout.desc_offset != DESC_OFF
        || layout.avail_offset != AVAIL_OFF
        || layout.used_offset != USED_OFF
        || layout.total != RINGS_TOTAL
    {
        return fail(0x58, 0xa);
    }

    let rx = match new_rx_buffer() {
        Ok(rx) => rx,
        Err(code) => return code,
    };
    let mmio = UserMmio {
        base: reg_base as usize,
    };
    let dma = dma_page();
    let mut driver = Driver {
        dma_phys,
        power: Power::Active,
        rx,
        rx_posted: 0,
        rx_seen: 0,
        tx_posted: 0,
        reports_link: false,
        mac: [0; 6],
    };
    let mut net = match driver.bring_up(&mmio) {
        Ok(net) => net,
        Err(code) => return code,
    };
    post_receive(dma, &mut driver, &net);

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64) {
        Ok(args) => args,
        Err(code) => return code,
    };
    let mut event_buf = [0u8; PortEventRecord::WIRE_SIZE];

    loop {
        let waited = syscall2(
            SYS_PORT_WAIT,
            SERVICE_PORT_HANDLE,
            event_buf.as_ptr() as u64,
        );
        if waited < 0 {
            return fail(0x5f, (-waited) as u64);
        }
        let bytes = read_kernel_filled::<{ PortEventRecord::WIRE_SIZE }>(&event_buf);
        let event = match decode::<PortEventRecord>(&bytes) {
            Ok(event) => event,
            Err(_) => return fail(0x5f, 1),
        };

        match event.signal {
            SIGNAL_INTERRUPT => {
                if let Err(code) = on_interrupt(dma, &mut driver, &net) {
                    return code;
                }
            }
            SIGNAL_DEVICE_REMOVED => {
                // Nothing left to drive. The client is told on the same
                // channel its frames arrive on, because it may be waiting
                // there and a wait that never ends is the failure this path
                // exists to prevent.
                let gone = NetLinkEvent {
                    size: NetLinkEvent::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    link_up: 0,
                    reserved: 0,
                };
                let mut message = [0u8; NetLinkEvent::WIRE_SIZE];
                if encode(&gone, &mut message).is_err() {
                    return fail(0x5b, 0xe);
                }
                let mut out = match channel_args(message.as_ptr() as u64, message.len() as u64) {
                    Ok(out) => out,
                    Err(code) => return code,
                };
                patch_args(
                    &mut out,
                    ARGS_METHOD_ID,
                    NetworkDevice::ON_DEVICE_GONE.into(),
                );
                let _ = syscall2(SYS_CHANNEL_SEND, out.as_ptr() as u64, EVENT_ENDPOINT_HANDLE);
                return DEVICE_GONE_REPORT;
            }
            SIGNAL_MESSAGE => {
                let n = syscall2(
                    SYS_CHANNEL_RECV,
                    args.as_ptr() as u64,
                    CLIENT_ENDPOINT_HANDLE,
                );
                if n < 0 {
                    return fail(0x60, (-n) as u64);
                }
                let method = kernel_u32(&args, ARGS_METHOD_ID);
                let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
                let request =
                    NetworkDeviceIncoming::decode(method, &mut Reader::in_message(&bytes, 0));
                let reply_len = match serve(
                    dma,
                    &mmio,
                    &mut driver,
                    &mut net,
                    method,
                    request,
                    &mut msg_buf,
                ) {
                    Ok(len) => len,
                    Err(code) => return code,
                };
                // Reply-and-CONTINUE, never a plain reply: a plain one hands
                // off to the caller and blocks the replier, which is right for
                // a server woken by the next call on that endpoint and fatal
                // for one woken by a port — nothing would ever hand back.
                patch_args(&mut args, ARGS_INLINE_LEN, reply_len as u64);
                let replied = syscall2(
                    SYS_CHANNEL_REPLY_CONTINUE,
                    args.as_ptr() as u64,
                    CLIENT_ENDPOINT_HANDLE,
                );
                patch_args(&mut args, ARGS_INLINE_LEN, MSG_BUF_LEN as u64);
                if replied < 0 {
                    return fail(0x61, (-replied) as u64);
                }
            }
            other => return fail(0x5f, u64::from(other)),
        }
    }
}

/// What this driver reports when its device left rather than when it failed.
const DEVICE_GONE_REPORT: u64 = 0x00d0_0000_0000_60e1;

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
