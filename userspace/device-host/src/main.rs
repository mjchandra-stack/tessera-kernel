// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 AArch64 **device host** (build/README.md, D80-D85): a real
//! `no_std` Rust user program that drives BOTH virtio-blk and virtio-net
//! through the **unchanged** memory-safe `tessera-virtio` core. It maps each
//! device's MMIO window by capability (`MapDevice`), allocates a DMA page per
//! device (`DmaAlloc`), self-tests both — a read of sector 0 AND a real ARP
//! round-trip with the SLIRP gateway — and then serves as a **resident
//! service**.
//!
//! The serve loop is a **select** (D85). Each client has its own channel, so
//! each has its own outstanding-caller slot; one service port is bound to
//! every server endpoint, and a message arrival signals that endpoint's
//! object. So the host parks in `PortWait` on the service port, and the
//! `PortEventRecord` it drains names WHICH client has work — which it maps
//! back to that client's endpoint handle. It then `ChannelRecv`s the
//! `BlockReadRequest`, reads the sector **parked on its device interrupt**
//! (safe mid-request now that callers no longer share a slot), and answers
//! with a `BlockReadReply` carrying the sector's first 64 bytes. The reply is
//! `ChannelReplyContinue`, not `ChannelReply`: a plain reply hands off to the
//! caller and BLOCKS the replier, which is right for a server woken by the
//! next call on that same endpoint and fatal for one woken by a port —
//! nothing would ever hand back. The loop then re-selects; it never exits on
//! success, and the boot check reaps it. The request/reply payload is the
//! `tessera.driver.block` ISL protocol — a user↔user contract the kernel
//! transports opaquely; the channel descriptors are the ISL `ChannelMsgArgs`.
//!
//! Reporting: on net-self-test success the host `DebugWrite`s the resolved
//! gateway MAC (tagged) — its contribution to the check's XOR sink; the blk
//! proof is the clients' reports (the host itself never stops selecting). On
//! any failure it `DebugWrite`s a `0xdead_...` code
//! carrying the stage and cause, then exits. Every wait is bounded — the
//! interrupt waits included — and the panic handler exits, so this program
//! can never hang the boot.
//!
//! Normative: docs/api/01-system-call-interface.md,
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels"),
//! docs/hardware/04-device-memory-and-unified-memory.md

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{
    BlockBufferReply, BlockBufferRequest, BlockControlReply, BlockDescribeReply, BlockDevice,
    BlockDeviceIncoming, BlockError, BlockPowerState, BlockReadReply, BlockReadRequest,
    BlockWriteReply, BlockWriteRequest,
};
use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use device_abi::{DmaAllocArgs, IrqCompleteArgs, MapDeviceArgs};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use memory_abi::DmaAttachArgs;
use port_event::PortEventRecord;
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_isl_runtime::{Ownership, Reader, WireError};
use tessera_uabi::{fail, read_kernel_filled, syscall2};
use tessera_virtio::{
    BLK_S_OK, Blk, Layout, Mmio, NET_HDR_LEN, Net, QueueAddrs, arp, blk_read_header,
    blk_write_header,
};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_PORT_WAIT: u64 = 18;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DMA_ALLOC: u64 = 24;
const SYS_IRQ_COMPLETE: u64 = 26;
const SYS_DMA_ATTACH: u64 = 32;

/// The port signal a device's removal arrives on (`kcore::exec`'s
/// `IRQ_PORT_SIGNAL_REMOVED`).
///
/// **Three, and the two below it are why.** One is an interrupt and two is a
/// channel message; this host waits on a port carrying both, and sees the raw
/// number. A removal numbered two would arrive here as a client request and be
/// answered as one.
const SIGNAL_DEVICE_REMOVED: u32 = 3;

/// What this host reports when its device left rather than when it finished.
/// Distinct from every failure code, because stopping because the hardware
/// went away is not this program failing.
const DEVICE_GONE_REPORT: u64 = 0x00d0_0000_0000_60e0;

/// The capabilities the kernel installs for this process: the blk Device cap
/// at handle 0, the net Device cap at 1, the blk interrupt port at 2, the
/// service (select) port at 3, and one server endpoint PER CLIENT at 4/5.
/// The bind channel to the device manager — this program's only inbound
/// authority at startup, and the only handle number it is *told*.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const IRQ_PORT_HANDLE: u64 = 1;
const SERVICE_PORT_HANDLE: u64 = 2;
const CLIENT_A_ENDPOINT_HANDLE: u64 = 3;
const CLIENT_B_ENDPOINT_HANDLE: u64 = 4;

/// Where a bound device capability lands. Boot installs five handles above,
/// so the kernel installs the first transferred capability at 5 and the second
/// at 6 — a fact about *this program's own table*, not about which device is
/// where. Which device arrives is the manager's finding, checked against the
/// class asked for; nothing here encodes that the block device is first on the
/// bus, or that there is one at all.
const BLK_DEVICE_HANDLE: u32 = 5;
const NET_DEVICE_HANDLE: u32 = 6;

/// The object ids the kernel bound those per-client server endpoints to — a
/// drained service-port event names one of these as its `source`, which is
/// how this host learns WHICH client to serve (D85).
const SERVER_A_OBJECT: u64 = 50;
const SERVER_B_OBJECT: u64 = 52;

/// Where this program asks the kernel to place things in its own space:
/// the MMIO register window page and the DMA page. Both clear of the linked
/// text/data (at 0x0000_1000_0000_0000) and the stack region.
const MMIO_VA: u64 = 0x0000_1000_0040_0000;
const DMA_VA: u64 = 0x0000_1000_0050_0000;
const NET_MMIO_VA: u64 = 0x0000_1000_0060_0000;
const NET_DMA_VA: u64 = 0x0000_1000_0070_0000;

/// Virtqueue size this driver negotiates (same as the in-kernel proof).
const QUEUE_SIZE: u16 = 8;

/// Layout of the single DMA page: the split-virtqueue rings at the base
/// (exactly `Layout::for_size(8)`: desc@0, avail@128, used@152, total 222),
/// then the 16-byte request header, the 1-byte status, and the 512-byte
/// sector buffer — everything a one-queue virtio-blk driver needs.
const DESC_OFF: usize = 0;
const AVAIL_OFF: usize = 128;
const USED_OFF: usize = 152;
const RINGS_TOTAL: usize = 222;
const HEADER_OFF: usize = 0x300;
const STATUS_OFF: usize = 0x310;
const DATA_OFF: usize = 0x400;
/// One sector, the unit the block contract moves and the size this transport's
/// data descriptor names.
const SECTOR: usize = 512;
const PAGE: usize = 4096;

/// Layout of the net DMA page: the two split-virtqueue ring blocks (rx =
/// queue 0 at 0x000, tx = queue 1 at 0x100 — desc alignment 16 holds), the
/// device-writable rx buffer, and the ARP request frame. All in one page —
/// the in-kernel check uses four.
const NET_RX_RINGS_OFF: usize = 0x000;
const NET_TX_RINGS_OFF: usize = 0x100;
const NET_RX_BUF_OFF: usize = 0x200;
const NET_RX_BUF_LEN: u32 = 512;
const NET_TX_FRAME_OFF: usize = 0x400;

/// The SLIRP user-network addresses (the same convention the in-kernel
/// `net_check` uses): our static guest IP and the gateway this host ARPs.
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

/// The net self-test success report: an "AR" tag over the resolved gateway
/// MAC (6 bytes, LE-packed) — magic-dependent and distinct from every other
/// sink reporter.
const NET_REPORT_TAG: u64 = 0x4152 << 48;

/// Reported when the kernel refuses to make a client's buffer reachable by
/// this device.
///
/// **This driver cannot tell why**, and does not claim to: it asked for an
/// attachment and was refused, which from here is one fact. What makes the
/// refusal attributable is the client's side of the same exchange — the buffer
/// that moved a moment ago, unchanged but for its classification. Reporting it
/// from here is what puts the refusal in the boot's evidence rather than only
/// in a client's private pass/fail.
const ATTACH_REFUSED_TAG: u64 = 0x4152_5f52 << 32;

/// Bound on each completion poll: no timer exists at EL0, so the wait is a
/// bounded spin; on QEMU the device completes in far fewer iterations.
const POLL_LIMIT: u32 = 50_000_000;

/// The self-test check value: sector 0's first 8 bytes on the test disk.
const DISK_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");

/// The symmetric call/recv buffer this driver exchanges with its client:
/// large enough for the biggest struct in either direction — a
/// `BlockWriteRequest` or a `BlockDescribeReply`, both 88.
const MSG_BUF_LEN: usize = 128;

/// The method ordinals of the block class contract (`block_driver.isl`).
///
/// **Derived, not named.** The ordinals used to be a table of constants here,
/// with a comment explaining that ISL's dispatch codegen was deferred — which
/// stopped being true at D69. `BlockDeviceIncoming` is generated from the same
/// `protocol BlockDevice` the client compiles against, so a driver serving a
/// different method than it was asked for is no longer a thing a typo can
/// cause: the ordinal, the request type it pairs with, and the refusal of an
/// ordinal outside the contract all come from one place.

/// Ordinals at or above this belong to a vendor extension namespace
/// (`tessera_class_conformance::VENDOR_ORDINAL_BASE`).
///
/// **This driver declares no namespace**, so every ordinal here is refused
/// with `PROTOCOL`. That refusal is the enforcement behind
/// `docs/drivers/01`'s *"vendor-private methods are allowed only through
/// explicitly versioned extension namespaces"*: without it a vendor method
/// would be reachable by anyone who guessed an ordinal, which makes it a
/// public interface that nobody documented.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// What this driver reports in `Describe`.
///
/// `WRITE` and `FLUSH` and `OUT_OF_LINE`, and deliberately not `DISCARD`: an
/// implementation that advertised everything would make the conformance
/// suite's unimplemented-optional rule unreachable, and a class contract whose
/// optionality is never exercised is one nobody has checked.
const FEATURES: u64 = 0x1 | 0x2 | 0x10;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Publish stores / order the device notify after the ring writes; also used
/// in the completion polls. `dsb ish` is unprivileged.
fn barrier() {
    // SAFETY: a data synchronization barrier has no operands and no side
    // effect beyond ordering.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
}

/// The `Mmio` impl over the MapDevice-granted register window — the EL0 twin
/// of the kernel's `DeviceRegisters`: plain volatile 32-bit access at
/// `base + offset`; ordering comes from the Device-nGnRnE mapping.
struct UserMmio {
    base: usize,
}

impl Mmio for UserMmio {
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the register base the MapDevice capability
        // granted (page + intra-page window offset); every `reg::` offset the
        // core uses stays inside the mapped device page.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }

    fn write(&self, offset: usize, value: u32) {
        // SAFETY: same window as `read`; a volatile store to a device
        // register the capability granted.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// Reads back the method ordinal the kernel wrote into a receive descriptor.
///
/// The kernel writes it **in place** at a fixed offset in the encoded
/// `ChannelMsgArgs` (`kcore::syscall::CHANNEL_MSG_METHOD_ID_OFFSET`), so this
/// re-reads those four bytes rather than decoding the whole struct: decoding
/// would validate an envelope the kernel has just partially rewritten, and the
/// only field that changed is this one.
///
/// Volatile, for the same reason every kernel-filled buffer in these programs
/// is: the compiler has no idea a syscall wrote here and would otherwise be
/// entitled to reuse the value it encoded a moment ago.
fn read_method_id(args: &[u8; ChannelMsgArgs::WIRE_SIZE]) -> u32 {
    const AT: usize = 32;
    let mut bytes = [0u8; 4];
    for (i, byte) in bytes.iter_mut().enumerate() {
        // SAFETY: an aligned-agnostic byte read inside this program's own
        // stack buffer; volatile only forbids the compiler from assuming the
        // value it encoded is still there.
        *byte = unsafe { core::ptr::read_volatile(&args[AT + i]) };
    }
    u32::from_le_bytes(bytes)
}

/// Field offsets in an encoded `ChannelMsgArgs` (`channel_msg.isl`), for the
/// fields this program rewrites between messages rather than re-encoding the
/// whole descriptor for.
const ARGS_HANDLES_PTR: usize = 56;
const ARGS_HANDLE_COUNT: usize = 64;
const ARGS_INSTALLED_PTR: usize = 72;
const ARGS_INSTALLED_CAP: usize = 80;

/// Writes a u64 into an encoded descriptor.
///
/// Volatile for the mirror image of `read_method_id`'s reason: the kernel also
/// reads this buffer, so a store the compiler judged dead — because nothing in
/// *this* program reads it back — would leave the kernel acting on the
/// previous request's descriptor.
fn patch_args(args: &mut [u8; ChannelMsgArgs::WIRE_SIZE], at: usize, value: u64) {
    for (i, byte) in value.to_le_bytes().iter().enumerate() {
        // SAFETY: `at` is a field offset inside this program's own stack
        // buffer, and the widest field written is 8 bytes at offset 80 of an
        // 88-byte struct.
        unsafe { core::ptr::write_volatile(&mut args[at + i], *byte) };
    }
}

/// The handle at position `index` of the kernel's installed-handle report, or
/// 0 when that position holds no capability.
///
/// The report is **positional**: entry *i* is the sender's *i*th transferred
/// descriptor, and `kcore::dispatch::HANDLE_NOT_INSTALLED` marks one that did
/// not land. Zero is returned for both "not installed" and "past what this
/// program asked the kernel to report", because this program's own handle 0 is
/// its manager endpoint — never where an installed capability goes — so zero
/// is a value it can safely read as "no buffer".
fn installed_at(installed: &[u8], index: u32) -> u32 {
    let at = index as usize * 4;
    if at + 4 > installed.len() {
        return 0;
    }
    let mut bytes = [0u8; 4];
    for (i, slot) in bytes.iter_mut().enumerate() {
        // SAFETY: a bounds-checked byte of this program's own stack buffer;
        // volatile because the kernel wrote it and the compiler has no way to
        // know that.
        *slot = unsafe { core::ptr::read_volatile(&installed[at + i]) };
    }
    match u32::from_le_bytes(bytes) {
        HANDLE_NOT_INSTALLED => 0,
        handle => handle,
    }
}

/// The first reported handle, for deciding how many capabilities arrived.
fn granted_handle(installed: &[u8]) -> u32 {
    installed_at(installed, 0)
}

/// `kcore::dispatch::HANDLE_NOT_INSTALLED` — what the report holds at a
/// position whose capability the receiver's table had no room for.
const HANDLE_NOT_INSTALLED: u32 = u32::MAX;

/// Encodes a `ChannelMsgArgs` descriptor for the symmetric message buffer.
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
        // No capability is expected back, so no report is asked for.
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(8, 0xe)),
    }
}

/// Acquires a device of `class` from the device manager.
///
/// This is the whole of the framework's claim from a driver's side: it names a
/// class, and a capability it did not previously hold arrives in the reply and
/// is installed in its table by the kernel. It never learns the device's
/// address or interrupt — both live inside the capability, and the kernel
/// reads them from there when this program maps it.
///
/// `expected` is where the capability lands (see the handle constants); the
/// returned class is checked against the request, so a mis-bind is caught here
/// rather than showing up later as a driver talking to the wrong device.
fn bind(class: DeviceClass, expected: u32, stage: u64) -> Result<u32, u64> {
    // The larger of `BindRequest` and `BindReply`, taken from the type rather
    // than written out: the reply is the bigger of the two because binding
    // produces outputs, and one that grew past a literal would be read back
    // out of a buffer too small for it — a failure that looks like a decode
    // bug rather than the schema change that caused it.
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(stage, 0xe));
    }
    let args = channel_args(message.as_ptr() as u64, message.len() as u64)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(stage, (-n) as u64));
    }

    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(stage, 0xd)),
    };
    if reply.status != 0 {
        // No device of that class on this machine. Reported, never guessed
        // around — a driver that carried on would drive whatever handle 5
        // happened to be.
        return Err(fail(stage, 0x100 | u64::from(reply.status)));
    }
    if reply.class != class {
        return Err(fail(stage, 0x200));
    }
    Ok(expected)
}

/// Maps the device named by `handle` at `vaddr`, returning the register base
/// (ISL-encoded args on the tracked stack). `stage` tags failures.
fn map_device(handle: u32, vaddr: u64, stage: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(stage, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(stage, (-base) as u64));
    }
    Ok(base as u64)
}

/// Allocates one DMA page at `vaddr` under `handle`'s authority, returning
/// its physical address. `stage` tags failures.
fn dma_alloc(handle: u32, vaddr: u64, stage: u64) -> Result<u64, u64> {
    let args = DmaAllocArgs {
        size: DmaAllocArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; DmaAllocArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(stage, 0xe));
    }
    let phys = syscall2(SYS_DMA_ALLOC, buf.as_ptr() as u64, 0);
    if phys < 0 {
        return Err(fail(stage, (-phys) as u64));
    }
    Ok(phys as u64)
}

/// Re-arms the interrupt line of the device named by `handle` (after the
/// device itself has been acked) — the IrqComplete half of the
/// mask-on-deliver protocol (D84).
fn irq_complete(handle: u32, stage_bit: u64) -> Result<(), u64> {
    let args = IrqCompleteArgs {
        size: IrqCompleteArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        reserved: 0,
    };
    let mut buf = [0u8; IrqCompleteArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x31 | stage_bit, 0xe));
    }
    let r = syscall2(SYS_IRQ_COMPLETE, buf.as_ptr() as u64, 0);
    if r < 0 {
        return Err(fail(0x31 | stage_bit, (-r) as u64));
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

/// The net leg's self-test: bring the NIC up from EL0 (map + DMA + the full
/// modern two-queue handshake) and complete a real ARP round-trip with the
/// SLIRP gateway — the EL0 twin of the in-kernel `net_check`, in one packed
/// DMA page. Returns the tagged gateway-MAC report.
fn net_self_test() -> Result<u64, u64> {
    let reg_base = map_device(NET_DEVICE_HANDLE, NET_MMIO_VA, 0x21)?;
    let phys = dma_alloc(NET_DEVICE_HANDLE, NET_DMA_VA, 0x22)?;

    // SAFETY: DmaAlloc mapped exactly one zero-filled page, read+write, at
    // NET_DMA_VA in this process's space; this is the only reference formed.
    let dma = unsafe { core::slice::from_raw_parts_mut(NET_DMA_VA as *mut u8, PAGE) };

    let mmio = UserMmio {
        base: reg_base as usize,
    };
    let rx = QueueAddrs {
        desc: phys + NET_RX_RINGS_OFF as u64 + DESC_OFF as u64,
        avail: phys + NET_RX_RINGS_OFF as u64 + AVAIL_OFF as u64,
        used: phys + NET_RX_RINGS_OFF as u64 + USED_OFF as u64,
    };
    let tx = QueueAddrs {
        desc: phys + NET_TX_RINGS_OFF as u64 + DESC_OFF as u64,
        avail: phys + NET_TX_RINGS_OFF as u64 + AVAIL_OFF as u64,
        used: phys + NET_TX_RINGS_OFF as u64 + USED_OFF as u64,
    };
    let net = match Net::init(&mmio, rx, tx, QUEUE_SIZE) {
        Ok(net) => net,
        Err(e) => return Err(fail(0x23, e as u64)),
    };
    let mac = net.mac();

    // Post the rx buffer FIRST so the reply has somewhere to land, then the
    // ARP request (12-byte zeroed net header + the 42-byte frame).
    {
        let (rx_rings, _) = dma[NET_RX_RINGS_OFF..].split_at_mut(RINGS_TOTAL);
        let (desc, avail) = rx_rings.split_at_mut(AVAIL_OFF);
        net.post_rx(desc, avail, phys + NET_RX_BUF_OFF as u64, NET_RX_BUF_LEN, 0);
    }
    barrier();
    net.notify_rx();

    let frame_len = NET_HDR_LEN + arp::FRAME_LEN;
    dma[NET_TX_FRAME_OFF..NET_TX_FRAME_OFF + NET_HDR_LEN].fill(0);
    dma[NET_TX_FRAME_OFF + NET_HDR_LEN..NET_TX_FRAME_OFF + frame_len]
        .copy_from_slice(&arp::build_request(mac, OUR_IP, GATEWAY_IP));
    {
        let (tx_rings, _) = dma[NET_TX_RINGS_OFF..].split_at_mut(RINGS_TOTAL);
        let (desc, avail) = tx_rings.split_at_mut(AVAIL_OFF);
        net.post_tx(
            desc,
            avail,
            phys + NET_TX_FRAME_OFF as u64,
            frame_len as u32,
            0,
        );
    }
    barrier();
    net.notify_tx();

    // Fresh queues: each used index must reach 1. TX first, then the reply.
    if !poll_used_at(NET_DMA_VA as usize + NET_TX_RINGS_OFF + USED_OFF + 2, 1) {
        return Err(fail(0x24, 0));
    }
    if !poll_used_at(NET_DMA_VA as usize + NET_RX_RINGS_OFF + USED_OFF + 2, 1) {
        return Err(fail(0x25, 0));
    }
    match net.rx_completion(
        &dma[NET_RX_RINGS_OFF + USED_OFF..NET_RX_RINGS_OFF + RINGS_TOTAL],
        0,
    ) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(fail(0x26, 0)),
        Err(e) => return Err(fail(0x26, e as u64)),
    }

    let reply_frame =
        &dma[NET_RX_BUF_OFF + NET_HDR_LEN..NET_RX_BUF_OFF + NET_HDR_LEN + arp::FRAME_LEN];
    let Some(reply) = arp::parse_reply(reply_frame) else {
        return Err(fail(0x27, 0));
    };
    if reply.sender_ip != GATEWAY_IP {
        return Err(fail(0x27, 1));
    }
    let mut mac_u64 = 0u64;
    for (i, byte) in reply.sender_mac.iter().enumerate() {
        mac_u64 |= (*byte as u64) << (8 * i);
    }
    Ok(NET_REPORT_TAG | mac_u64)
}

/// How a blk read waits for its completion: a bounded spin on the used index
/// (the self-test path), or parked in the kernel on the interrupt port with
/// the device acked and the line re-armed per wake (the serve path, D84).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wait {
    Poll,
    Irq,
}

/// One read of `sector` through the virtqueue: `seq` is this queue's request
/// ordinal (0 for the self-test, 1 for the client's request) — it selects the
/// avail-ring slot, the expected used index (`seq + 1`), and the completion
/// cursor. `stage_bit` tags failure stages (0 for self-test, 0x8000 serving).
fn read_sector(
    blk: &Blk<'_, UserMmio>,
    dma: &mut [u8],
    dma_phys: u64,
    sector: u64,
    seq: u16,
    stage_bit: u64,
    wait: Wait,
) -> Result<(), u64> {
    read_sector_into(
        blk,
        dma,
        dma_phys,
        dma_phys + DATA_OFF as u64,
        sector,
        seq,
        stage_bit,
        wait,
    )
}

/// One read of `sector` whose data lands at **`data_addr`**, a device-visible
/// address that need not be inside this driver's own DMA page.
///
/// The whole point of the out-of-line path: `data_addr` is a client's buffer,
/// made reachable by the device through `DmaAttach`, so the sector goes
/// straight there and no CPU copies it. The header and status descriptors stay
/// in this driver's page — they are the driver's own bookkeeping, not the
/// client's data.
#[allow(clippy::too_many_arguments)]
fn read_sector_into(
    blk: &Blk<'_, UserMmio>,
    dma: &mut [u8],
    dma_phys: u64,
    data_addr: u64,
    sector: u64,
    seq: u16,
    stage_bit: u64,
    wait: Wait,
) -> Result<(), u64> {
    dma[HEADER_OFF..HEADER_OFF + 16].copy_from_slice(&blk_read_header(sector));
    {
        let (rings, _) = dma.split_at_mut(RINGS_TOTAL);
        let (desc, avail) = rings.split_at_mut(AVAIL_OFF);
        blk.write_read_request(
            desc,
            avail,
            dma_phys + HEADER_OFF as u64,
            data_addr,
            dma_phys + STATUS_OFF as u64,
            seq,
        );
    }
    barrier();
    blk.notify();

    // Wait for the EXPECTED used index (seq + 1): after an earlier request
    // the index is already seq, so a mere "non-zero" test would pass
    // instantly on stale state.
    let used_idx = (DMA_VA as usize + USED_OFF + 2) as *const u16;
    let expected = seq.wrapping_add(1);
    let mut completed = false;
    match wait {
        Wait::Poll => {
            let mut spins = 0u32;
            while spins < POLL_LIMIT {
                barrier();
                // SAFETY: an aligned volatile read inside the DMA page this
                // program owns; the device updates the index concurrently.
                if unsafe { used_idx.read_volatile() } == expected {
                    completed = true;
                    break;
                }
                spins += 1;
            }
        }
        Wait::Irq => {
            // Park on the interrupt port; per wake, ack the device through
            // this program's own mapped window (clearing the level source),
            // re-arm the line via IrqComplete, and re-check the used index —
            // a spurious or early wake just parks again. Bounded so no hang
            // path exists.
            let mut wakes = 0u32;
            while wakes < 16 {
                // Check before parking: on a fast device the completion — and
                // its interrupt — can land before this program reaches the
                // wait, and a port event consumed by nobody would strand it.
                barrier();
                // SAFETY: aligned volatile read inside this program's DMA page.
                if unsafe { used_idx.read_volatile() } == expected {
                    completed = true;
                    break;
                }
                let n = syscall2(SYS_PORT_WAIT, IRQ_PORT_HANDLE, 0);
                if n < 0 {
                    return Err(fail(0x30 | stage_bit, (-n) as u64));
                }
                wakes += 1;
            }
            // Acknowledge the device and re-arm the line on EVERY path — the
            // kernel masks the interrupt when it delivers it, so a completion
            // observed by the fast path above must still be acked and
            // re-armed or the NEXT request can never interrupt (the line
            // stays masked and the device's status bit stays set).
            // `ack_interrupt` is a no-op when nothing is pending, and
            // re-arming an unmasked line is idempotent.
            blk.ack_interrupt();
            if let Err(code) = irq_complete(BLK_DEVICE_HANDLE, stage_bit) {
                return Err(code);
            }
            if !completed {
                barrier();
                // SAFETY: as above — one last look after the acknowledge.
                if unsafe { used_idx.read_volatile() } == expected {
                    completed = true;
                }
            }
            if !completed {
                return Err(fail(0x32 | stage_bit, 0));
            }
        }
    }
    if !completed {
        return Err(fail(4 | stage_bit, 0));
    }

    match blk.completion(&dma[USED_OFF..RINGS_TOTAL], seq) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(fail(5 | stage_bit, 0)),
        Err(e) => return Err(fail(5 | stage_bit, e as u64)),
    }
    if dma[STATUS_OFF] != BLK_S_OK {
        return Err(fail(6 | stage_bit, dma[STATUS_OFF] as u64));
    }
    Ok(())
}

/// One write of `sector` through the virtqueue — the counterpart of
/// [`read_sector`], and what makes this contract no longer read-only.
///
/// The caller has already put the payload at `DATA_OFF`. Waiting is always
/// interrupt-driven here: a write completes exactly as a read does, and giving
/// it a poll path would be a second wait to keep correct for no gain.
fn write_sector(
    blk: &Blk<'_, UserMmio>,
    dma: &mut [u8],
    dma_phys: u64,
    sector: u64,
    seq: u16,
    stage_bit: u64,
) -> Result<(), u64> {
    write_sector_from(
        blk,
        dma,
        dma_phys,
        dma_phys + DATA_OFF as u64,
        sector,
        seq,
        stage_bit,
    )
}

/// One write of `sector` whose data is read from **`data_addr`** — a client's
/// attached buffer on the out-of-line path, this driver's own page otherwise.
#[allow(clippy::too_many_arguments)]
fn write_sector_from(
    blk: &Blk<'_, UserMmio>,
    dma: &mut [u8],
    dma_phys: u64,
    data_addr: u64,
    sector: u64,
    seq: u16,
    stage_bit: u64,
) -> Result<(), u64> {
    dma[HEADER_OFF..HEADER_OFF + 16].copy_from_slice(&blk_write_header(sector));
    {
        let (rings, _) = dma.split_at_mut(RINGS_TOTAL);
        let (desc, avail) = rings.split_at_mut(AVAIL_OFF);
        // The write chain: the data descriptor is device-*readable*. The
        // encoder enforces that; this call site could not get it wrong even by
        // trying, which is why the direction lives in `tessera-virtio` rather
        // than in a flags argument here.
        blk.write_write_request(
            desc,
            avail,
            dma_phys + HEADER_OFF as u64,
            data_addr,
            dma_phys + STATUS_OFF as u64,
            seq,
        );
    }
    barrier();
    blk.notify();

    let used_idx = (DMA_VA as usize + USED_OFF + 2) as *const u16;
    let expected = seq.wrapping_add(1);
    let mut completed = false;
    let mut wakes = 0u32;
    while wakes < 16 {
        barrier();
        // SAFETY: aligned volatile read inside this program's own DMA page;
        // the device updates the index concurrently.
        if unsafe { used_idx.read_volatile() } == expected {
            completed = true;
            break;
        }
        let n = syscall2(SYS_PORT_WAIT, IRQ_PORT_HANDLE, 0);
        if n < 0 {
            return Err(fail(0x40 | stage_bit, (-n) as u64));
        }
        wakes += 1;
    }
    // Acknowledge and re-arm on every path, for the reason `read_sector`
    // documents: the kernel masks the line when it delivers, so a completion
    // the fast path saw must still be acked or the next request can never
    // interrupt.
    blk.ack_interrupt();
    if let Err(code) = irq_complete(BLK_DEVICE_HANDLE, stage_bit) {
        return Err(code);
    }
    if !completed {
        barrier();
        // SAFETY: as above — one last look after the acknowledge.
        if unsafe { used_idx.read_volatile() } == expected {
            completed = true;
        }
    }
    if !completed {
        return Err(fail(0x41 | stage_bit, 0));
    }
    match blk.completion(&dma[USED_OFF..RINGS_TOTAL], seq) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(fail(0x42 | stage_bit, 0)),
        Err(e) => return Err(fail(0x42 | stage_bit, e as u64)),
    }
    if dma[STATUS_OFF] != BLK_S_OK {
        return Err(fail(0x43 | stage_bit, dma[STATUS_OFF] as u64));
    }
    Ok(())
}

/// Maps the device, allocates the DMA page, self-tests with sector 0, then
/// serves one client request over the channel. Returns only on failure.
fn run() -> u64 {
    // Acquire both devices before touching either. Order matters only in that
    // it fixes where each capability lands; *which* transport answers to
    // "Block" is the manager's finding, not this program's assumption.
    if let Err(code) = bind(DeviceClass::Block, BLK_DEVICE_HANDLE, 0x40) {
        return code;
    }
    if let Err(code) = bind(DeviceClass::Network, NET_DEVICE_HANDLE, 0x41) {
        return code;
    }

    let reg_base = match map_device(BLK_DEVICE_HANDLE, MMIO_VA, 1) {
        Ok(base) => base,
        Err(code) => return code,
    };
    let dma_phys = match dma_alloc(BLK_DEVICE_HANDLE, DMA_VA, 2) {
        Ok(phys) => phys,
        Err(code) => return code,
    };

    // The one DMA page, as this program's view of the memory the device will
    // read and write by physical address.
    // SAFETY: DmaAlloc mapped exactly one zero-filled page, read+write, at
    // DMA_VA in this process's space; this is the only reference formed.
    let dma = unsafe { core::slice::from_raw_parts_mut(DMA_VA as *mut u8, PAGE) };

    // The ring offsets this page uses are exactly the core's layout.
    let layout = Layout::for_size(QUEUE_SIZE);
    if layout.desc_offset != DESC_OFF
        || layout.avail_offset != AVAIL_OFF
        || layout.used_offset != USED_OFF
        || layout.total != RINGS_TOTAL
    {
        return fail(3, 0xa);
    }

    let mmio = UserMmio {
        base: reg_base as usize,
    };
    let blk = match Blk::init(
        &mmio,
        QUEUE_SIZE,
        dma_phys + DESC_OFF as u64,
        dma_phys + AVAIL_OFF as u64,
        dma_phys + USED_OFF as u64,
    ) {
        Ok(blk) => blk,
        Err(e) => return fail(3, e as u64),
    };

    // Self-test: read sector 0 INTERRUPT-DRIVEN (D84) — the driver parks on
    // its device interrupt port and is woken by the completion IRQ, acks the
    // device through its own window, and re-arms the line. This is the
    // isolated ring-3 interrupt-delivery proof; it runs before the driver
    // accepts any request, so no IPC ordering rides on it.
    if let Err(code) = read_sector(&blk, dma, dma_phys, 0, 0, 0, Wait::Irq) {
        return code;
    }
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&dma[DATA_OFF..DATA_OFF + 8]);
    if u64::from_le_bytes(magic) != DISK_MAGIC {
        return fail(7, 0);
    }

    // The net leg: bring the NIC up and complete the ARP round-trip, then
    // report the resolved gateway MAC — this host's contribution to the
    // check's XOR sink (the blk proof is the clients' reports).
    match net_self_test() {
        Ok(report) => {
            let _ = syscall2(SYS_DEBUG_WRITE, report, 0);
        }
        Err(code) => return code,
    }

    // The resident SELECT loop (D85): park on the service port until a
    // message lands on ANY per-client endpoint, learn which one from the
    // drained event, then receive/serve/reply on that client's own channel.
    // Because each client has its own endpoint — and so its own
    // outstanding-caller slot — the read may park on the device interrupt
    // mid-request while the other client calls, without crossing replies.
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64) {
        Ok(args) => args,
        Err(code) => return code,
    };
    let mut event_buf = [0u8; PortEventRecord::WIRE_SIZE];
    let mut seq: u16 = 1;
    // The out-of-line direction needs two buffers the inline methods do not:
    // somewhere for the kernel to report where a transferred capability landed
    // (filled on receive), and somewhere to build the descriptor that sends it
    // back (read on reply).
    let mut installed = [0u8; 4];
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    patch_args(&mut args, ARGS_INSTALLED_PTR, installed.as_ptr() as u64);
    patch_args(&mut args, ARGS_INSTALLED_CAP, 1);

    loop {
        let waited = syscall2(
            SYS_PORT_WAIT,
            SERVICE_PORT_HANDLE,
            event_buf.as_ptr() as u64,
        );
        if waited < 0 {
            return fail(0x34, (-waited) as u64);
        }
        let event_bytes = read_kernel_filled::<{ PortEventRecord::WIRE_SIZE }>(&event_buf);
        let event = match decode::<PortEventRecord>(&event_bytes) {
            Ok(event) => event,
            Err(_) => return fail(0x34, 1),
        };
        // **The device is gone.** Delivered on its own signal rather than the
        // interrupt's, because both reach this same wait and a driver that
        // could not tell them apart would go and service a completion that
        // never happened. There is nothing left to drive, so the contract's
        // answer goes to whoever is waiting and this host stops.
        if event.signal == SIGNAL_DEVICE_REMOVED {
            let reply = BlockControlReply {
                size: BlockControlReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status: BlockError::Removed as u32,
                state: BlockPowerState::Active,
            };
            if encode(&reply, &mut msg_buf[..BlockControlReply::WIRE_SIZE]).is_err() {
                return fail(10, 0xe);
            }
            // Both clients, because either may be the one blocked in a call:
            // a request that never gets an answer is the failure mode this
            // whole path exists to prevent, and guessing which one is waiting
            // is not something this host can do.
            for endpoint in [CLIENT_A_ENDPOINT_HANDLE, CLIENT_B_ENDPOINT_HANDLE] {
                let _ = syscall2(SYS_CHANNEL_REPLY_CONTINUE, args.as_ptr() as u64, endpoint);
            }
            return DEVICE_GONE_REPORT;
        }

        // The event names the endpoint object; map it to this host's handle.
        let endpoint = match event.source {
            SERVER_A_OBJECT => CLIENT_A_ENDPOINT_HANDLE,
            SERVER_B_OBJECT => CLIENT_B_ENDPOINT_HANDLE,
            _ => return fail(0x33, event.source & 0xffff),
        };

        // A receive that installs nothing writes nothing here, so the slot is
        // cleared first: otherwise the *previous* request's handle would look
        // like this one's buffer, and the driver would fill a client's memory
        // in answer to a request that sent none.
        for byte in installed.iter_mut() {
            // SAFETY: a byte of this program's own stack buffer; volatile so
            // the store is not elided as dead before the kernel's write.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        let n = syscall2(SYS_CHANNEL_RECV, args.as_ptr() as u64, endpoint);
        if n < 0 {
            return fail(8, (-n) as u64);
        }
        // **Which method.** The kernel writes the arrived message's ordinal
        // back into the descriptor on receive; before that this driver could
        // only ever be a block *reader*, because reading was the only thing a
        // request could mean.
        let method = read_method_id(&args);

        // **The request decodes once, through the contract.** The ordinal
        // chooses the request type, which is a pairing the schema states and
        // this program used to restate arm by arm. `in_message` bounds any
        // handle index in the payload by what the message actually carried, so
        // a field naming a capability that did not arrive is a decode failure
        // rather than a number this driver would go on to use.
        let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
        let installed_count = u32::from(granted_handle(&installed) != 0);
        let request =
            BlockDeviceIncoming::decode(method, &mut Reader::in_message(&bytes, installed_count));

        // The reply length varies by method, so it is decided per arm rather
        // than fixed for the loop.
        let reply_len = match request {
            // Three refusals the client should *hear*, rather than three ways
            // for this driver to die holding its request:
            //
            //   - an ordinal this contract does not define at all, or one in
            //     the vendor range with no namespace negotiated — the client
            //     asked for something outside the interface it is speaking,
            //     which is what keeps a vendor method from being reachable by
            //     anyone who guesses;
            //   - a payload naming a capability the message did not carry.
            //
            // The classification is the generated decoder's now; this program
            // no longer keeps its own idea of which ordinals exist.
            Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
                let reply = BlockControlReply {
                    size: BlockControlReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    status: BlockError::Protocol as u32,
                    state: BlockPowerState::Active,
                };
                if encode(&reply, &mut msg_buf[..BlockControlReply::WIRE_SIZE]).is_err() {
                    return fail(10, 0xe);
                }
                BlockControlReply::WIRE_SIZE
            }
            // A request whose ordinal this contract defines and whose bytes do
            // not decode is a different fact from an unknown method, and a
            // fatal one: the client and this driver disagree about a type they
            // both compile from the same schema.
            Err(_) => return fail(9, 0),
            Ok(BlockDeviceIncoming::Describe(_)) => {
                // Element 1's keystone: everything else in the contract is
                // conditional on this answer, so a client calls it first.
                let reply = BlockDescribeReply {
                    size: BlockDescribeReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    contract_version: CONTRACT_VERSION,
                    status: BlockError::Ok,
                    features: FEATURES,
                    sector_size: 512,
                    reserved: 0,
                    // The test disk is 1 MiB.
                    sector_count: 2048,
                    // This transport's DMA buffers are page-granular, and one
                    // request moves one sector.
                    dma_alignment: PAGE as u32,
                    dma_max_transfer_sectors: 1,
                    // Reported honestly: the virtio-mmio transports on these
                    // machines sit behind no IOMMU, and a client that assumed
                    // otherwise would be assuming the machine is protected
                    // from this driver when it is not.
                    dma_scoped: 0,
                    // ACTIVE and IDLE only — see SetPower below.
                    power_states: (1 << 1) | (1 << 2),
                    resume_latency_us: 0,
                    // No vendor extension. Zero rather than an arbitrary id,
                    // so "declares none" is distinguishable from "declares
                    // vendor 0".
                    vendor: 0,
                    vendor_namespace: 0,
                    vendor_extension_version: 0,
                    reserved2: 0,
                };
                if encode(&reply, &mut msg_buf[..BlockDescribeReply::WIRE_SIZE]).is_err() {
                    return fail(10, 0xe);
                }
                BlockDescribeReply::WIRE_SIZE
            }
            Ok(BlockDeviceIncoming::Read(request)) => {
                if request.size != BlockReadRequest::WIRE_SIZE as u32
                    || request.version != 1
                    || request.flags != 0
                {
                    return fail(9, 1);
                }
                // Interrupt-driven: the host parks on its device interrupt
                // port for the completion.
                let status = match read_sector(
                    &blk,
                    dma,
                    dma_phys,
                    request.sector,
                    seq,
                    0x8000,
                    Wait::Irq,
                ) {
                    Ok(()) => {
                        seq = seq.wrapping_add(1);
                        BlockError::Ok
                    }
                    // **From the contract's closed set, not the transport's
                    // own code.** A driver that leaked a virtio status here
                    // would be returning something the class does not define,
                    // which the conformance suite exists to catch.
                    Err(_) => BlockError::IoError,
                };
                let mut data = [0u8; 64];
                data.copy_from_slice(&dma[DATA_OFF..DATA_OFF + 64]);
                let reply = BlockReadReply {
                    size: BlockReadReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    status: status as u32,
                    reserved: 0,
                    data,
                };
                if encode(&reply, &mut msg_buf[..BlockReadReply::WIRE_SIZE]).is_err() {
                    return fail(10, 0xe);
                }
                BlockReadReply::WIRE_SIZE
            }
            Ok(BlockDeviceIncoming::Write(request)) => {
                if request.size != BlockWriteRequest::WIRE_SIZE as u32
                    || request.version != 1
                    || request.flags != 0
                {
                    return fail(9, 3);
                }
                // Buffer ownership: CALLER_RETAINS. The payload is copied out
                // of the message into this driver's own DMA page here, and
                // nothing of the caller's is referenced after the reply — the
                // rule the contract states for every request it defines.
                dma[DATA_OFF..DATA_OFF + 64].copy_from_slice(&request.data);
                dma[DATA_OFF + 64..DATA_OFF + 512].fill(0);
                let (status, written) =
                    match write_sector(&blk, dma, dma_phys, request.sector, seq, 0x8000) {
                        Ok(()) => {
                            seq = seq.wrapping_add(1);
                            (BlockError::Ok, 64u32)
                        }
                        Err(_) => (BlockError::IoError, 0),
                    };
                let reply = BlockWriteReply {
                    size: BlockWriteReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    status: status as u32,
                    written,
                };
                if encode(&reply, &mut msg_buf[..BlockWriteReply::WIRE_SIZE]).is_err() {
                    return fail(10, 0xe);
                }
                BlockWriteReply::WIRE_SIZE
            }
            Ok(
                BlockDeviceIncoming::ReadInto(request) | BlockDeviceIncoming::WriteFrom(request),
            ) => {
                // **The payload said which capability, the kernel said which
                // number.** `request.buffer` is an index into the handles this
                // message carried; the installed report is the only thing that
                // knows what each of them landed on here, because the number
                // is not the sender's to choose. `in_message` already refused
                // an index past what arrived, so this cannot read past the
                // report.
                let granted = installed_at(&installed, request.buffer.index());
                let (status, moved) = if granted == 0 {
                    (BlockError::Protocol, 0)
                } else {
                    serve_out_of_line(
                        &blk,
                        dma,
                        dma_phys,
                        &mut seq,
                        method,
                        request.sector,
                        request.length,
                        granted,
                    )
                };
                let reply = BlockBufferReply {
                    size: BlockBufferReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    status: status as u32,
                    reserved: 0,
                    transferred: moved,
                };
                if encode(&reply, &mut msg_buf[..BlockBufferReply::WIRE_SIZE]).is_err() {
                    return fail(10, 0xe);
                }
                // **The buffer goes home with the reply**, which is what makes
                // the client's bytes readable to it again — and what ends the
                // device's reach into them, since the kernel detaches an
                // object whose capability leaves. A driver that kept it would
                // strand a client's memory in a process the client cannot
                // reach, with a device still writing into it.
                if granted != 0 {
                    let descriptor = HandleTransfer {
                        handle: granted,
                        // The contract's own declaration, in both directions:
                        // the buffer goes home carrying exactly what the
                        // schema says a `buffer` field carries. A driver that
                        // computed its own mask here could hand back less than
                        // the client needs and be right by the letter of every
                        // check that exists.
                        mode: match BlockBufferRequest::BUFFER_OWNERSHIP {
                            Ownership::Transfer => TransferMode::Transfer,
                            _ => return fail(10, 0xc),
                        },
                        rights: BlockBufferRequest::BUFFER_RIGHTS,
                    };
                    if encode(&descriptor, &mut transfer).is_err() {
                        return fail(10, 0xd);
                    }
                    patch_args(&mut args, ARGS_HANDLES_PTR, transfer.as_ptr() as u64);
                    patch_args(&mut args, ARGS_HANDLE_COUNT, 1);
                }
                BlockBufferReply::WIRE_SIZE
            }
            Ok(
                BlockDeviceIncoming::Flush(request)
                | BlockDeviceIncoming::Reset(request)
                | BlockDeviceIncoming::SetPower(request),
            ) => {
                let (status, state) = match method {
                    // Advertised, so it must not answer NOT_SUPPORTED. This
                    // transport has no separate flush command in the feature
                    // set it negotiated, and every write it has issued has
                    // already completed at the device — so the flush is a
                    // no-op that is *true* rather than one that is convenient.
                    BlockDevice::FLUSH => (BlockError::Ok, BlockPowerState::Active),
                    // Element 8, performed: the device goes back to the state
                    // a reset is defined to leave. Nothing is outstanding here
                    // by construction — this driver completes each request
                    // before receiving the next — which is the contract's
                    // hardest clause and the one it satisfies most cheaply.
                    BlockDevice::RESET => (BlockError::Ok, BlockPowerState::Active),
                    BlockDevice::SET_POWER => {
                        // A state this driver did not report in `Describe` is
                        // NOT_SUPPORTED, not a best effort. A driver that
                        // silently accepted STANDBY and stayed active would
                        // have the power manager believe it had saved power it
                        // had not.
                        match request.state {
                            BlockPowerState::Active | BlockPowerState::Idle => {
                                (BlockError::Ok, request.state)
                            }
                            _ => (BlockError::NotSupported, BlockPowerState::Active),
                        }
                    }
                    // Unreachable: this arm is entered only for the three
                    // ordinals matched above. Answering rather than panicking,
                    // because a driver that aborts on its own impossible case
                    // takes a client's outstanding request down with it.
                    _ => (BlockError::Protocol, BlockPowerState::Active),
                };
                let reply = BlockControlReply {
                    size: BlockControlReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    status: status as u32,
                    state,
                };
                if encode(&reply, &mut msg_buf[..BlockControlReply::WIRE_SIZE]).is_err() {
                    return fail(10, 0xe);
                }
                BlockControlReply::WIRE_SIZE
            }
            // **`Discard` carries a `BlockWriteRequest`**, which the contract
            // has always said and neither program used to do: this host
            // decoded a `BlockControlRequest` for it and the client sent one,
            // so the two agreed on a pairing the schema does not define. The
            // generated dispatch is what made that visible — it pairs the
            // ordinal with the type the protocol declares, and there is no
            // longer a place to write a different answer.
            //
            // Not advertised (`DISCARD` is absent from `FEATURES`), so the one
            // answer the contract permits for an unimplemented optional.
            Ok(BlockDeviceIncoming::Discard(_)) => {
                let reply = BlockControlReply {
                    size: BlockControlReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    status: BlockError::NotSupported as u32,
                    state: BlockPowerState::Active,
                };
                if encode(&reply, &mut msg_buf[..BlockControlReply::WIRE_SIZE]).is_err() {
                    return fail(10, 0xe);
                }
                BlockControlReply::WIRE_SIZE
            }
        };
        let _ = reply_len;
        // Reply on THIS client's endpoint, then loop back to the select.
        let r = syscall2(SYS_CHANNEL_REPLY_CONTINUE, args.as_ptr() as u64, endpoint);
        if r < 0 {
            return fail(10, (-r) as u64);
        }
        // Clear the transfer vector: the descriptor above is set per reply,
        // and a stale one would try to send a handle this program no longer
        // holds on the *next* reply — an error at best, and the wrong
        // capability if the number had been reused.
        patch_args(&mut args, ARGS_HANDLES_PTR, 0);
        patch_args(&mut args, ARGS_HANDLE_COUNT, 0);
    }
}

/// Serves one out-of-line request: map the transferred buffer, move `length`
/// bytes between it and the medium, and report how many moved.
///
/// The mapping is not unmapped here, and does not need to be: the caller
/// transfers the buffer back with its reply, and a transfer takes the sender's
/// mappings with it. That is the whole reason this can use one fixed address
/// for every request.
///
/// **The copy through the DMA page is a deviation, stated rather than hidden**
/// (D131): this transport's descriptors must name device-visible physical
/// addresses, and a grant's frames are ordinary anonymous memory that no
/// `DmaAlloc` has made addressable to the device. Zero-copy needs a way to
/// attach an existing object to a device, which is the next milestone's job.
#[allow(clippy::too_many_arguments)]
fn serve_out_of_line(
    blk: &Blk<'_, UserMmio>,
    dma: &mut [u8],
    dma_phys: u64,
    seq: &mut u16,
    method: u32,
    sector: u64,
    length: u64,
    granted: u32,
) -> (BlockError, u64) {
    // One sector, exactly. Refused rather than trimmed to what fits: a client
    // told "512 bytes moved" when 64 did would trust bytes nobody wrote.
    if length == 0 || length > SECTOR as u64 || length % SECTOR as u64 != 0 {
        return (BlockError::Protocol, 0);
    }
    let length = length as usize;

    // **Hand the buffer to the device, not to this program.** The client's
    // object becomes reachable by the block device at an address the device
    // can use, and that address goes straight into the virtqueue's data
    // descriptor. Nothing here maps it, so nothing here can read or write a
    // byte of it — which is the strongest form the claim can take: a driver
    // with no mapping of a buffer did not copy it.
    let attach = DmaAttachArgs {
        size: DmaAttachArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(BLK_DEVICE_HANDLE),
        memory: HandleRef::new(granted),
    };
    let mut buf = [0u8; DmaAttachArgs::WIRE_SIZE];
    if encode(&attach, &mut buf).is_err() {
        return (BlockError::Protocol, 0);
    }
    let data_addr = syscall2(SYS_DMA_ATTACH, buf.as_ptr() as u64, 0);
    if data_addr < 0 {
        // Say so, once per refusal. The check's sink expects exactly one in a
        // boot, so a second — or none — fails it.
        let _ = syscall2(SYS_DEBUG_WRITE, ATTACH_REFUSED_TAG, 0);
        // `PROTOCOL` rather than `IO_ERROR` because no device was reached:
        // every way this can fail is a property of the grant the client sent —
        // rights it did not carry, or a size this driver cannot place — and a
        // client told "I/O error" would retry a request that can never succeed.
        return (BlockError::Protocol, 0);
    }
    let data_addr = data_addr as u64;

    // The buffer is detached by the reply that hands it back, so there is no
    // detach here and no way for this driver to forget one.
    if method == BlockDevice::WRITE_FROM {
        match write_sector_from(blk, dma, dma_phys, data_addr, sector, *seq, 0x8000) {
            Ok(()) => {
                *seq = seq.wrapping_add(1);
                (BlockError::Ok, length as u64)
            }
            Err(_) => (BlockError::IoError, 0),
        }
    } else {
        match read_sector_into(
            blk,
            dma,
            dma_phys,
            data_addr,
            sector,
            *seq,
            0x8000,
            Wait::Irq,
        ) {
            Ok(()) => {
                *seq = seq.wrapping_add(1);
                (BlockError::Ok, length as u64)
            }
            Err(_) => (BlockError::IoError, 0),
        }
    }
}

/// Entry: the kernel's `spawn_user` set SP to the top of the mapped user
/// stack, so plain Rust runs from the first instruction. `run` returning at
/// all is a failure (success parks in the reply handoff).
// SAFETY: the unmangled `_start` symbol is the ELF entry the linker script
// names; nothing else in this single-binary program can collide with it.
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    let report = run();
    let _ = syscall2(SYS_DEBUG_WRITE, report, 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 1, 0);
    // ProcessExit never returns; keep the type honest without UB.
    loop {
        core::hint::spin_loop();
    }
}

/// A panic must not hang the boot: report a distinct code and exit.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, fail(0xff, 0), 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 1, 0);
    loop {
        core::hint::spin_loop();
    }
}
