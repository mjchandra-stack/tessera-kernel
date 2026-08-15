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

use block_driver_abi::{BlockReadReply, BlockReadRequest};
use channel_msg::ChannelMsgArgs;
use driver_bind::{BindReply, BindRequest, DeviceClass};
use device_abi::{DmaAllocArgs, IrqCompleteArgs, MapDeviceArgs};
use port_event::PortEventRecord;
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_virtio::{
    BLK_S_OK, Blk, Layout, Mmio, NET_HDR_LEN, Net, QueueAddrs, arp, blk_read_header,
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

/// Bound on each completion poll: no timer exists at EL0, so the wait is a
/// bounded spin; on QEMU the device completes in far fewer iterations.
const POLL_LIMIT: u32 = 50_000_000;

/// The self-test check value: sector 0's first 8 bytes on the test disk.
const DISK_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");

/// The symmetric call/recv buffer this driver exchanges with its client:
/// large enough for the bigger of `BlockReadRequest` (24) and
/// `BlockReadReply` (88).
const MSG_BUF_LEN: usize = 96;

/// A failure report: `0xdead << 48 | stage << 16 | cause`. Stages: 1
/// map_device, 2 dma_alloc, 3 device init, 4 poll timeout, 5 completion,
/// 6 request status, 7 self-test magic, 8 recv (or a short next request),
/// 9 request decode, 10 reply error, 0x33 unknown select source, 0x34
/// select-event decode; IRQ stages: 0x30 port wait,
/// 0x31 irq_complete, 0x32 wake budget exhausted; net self-test stages: 0x21 net
/// map_device, 0x22 net dma_alloc, 0x23 net init, 0x24 tx-poll timeout,
/// 0x25 rx-poll timeout, 0x26 rx completion, 0x27 ARP reply mismatch;
/// 0xff panic. The virtio stages carry bit 15 of the stage set when they
/// happen while serving the client's request (second read) rather than the
/// self-test.
const fn fail(stage: u64, cause: u64) -> u64 {
    0xdead_0000_0000_0000 | (stage << 16) | (cause & 0xffff)
}

/// One syscall: `x8` = number, `x0`/`x1` = args, result in `x0`.
fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    // SAFETY: the svc traps to the kernel dispatcher, which restores every
    // GPR except x0 (the trap frame is saved/restored whole); only x0 is
    // written back, declared via inout. No memory is touched by the
    // instruction itself.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inout("x0") arg0 => ret,
            in("x1") arg1,
            options(nostack),
        );
    }
    ret
}

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

/// Reads the first `N` bytes of a buffer the **kernel** filled during a
/// preceding syscall, via volatile loads — making the cross-boundary write
/// visible to the compiler regardless of its alias analysis of this
/// never-Rust-mutated local.
fn read_kernel_filled<const N: usize>(buf: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: `&buf[i]` is a bounds-checked, initialized byte; volatile
        // only forbids the compiler from assuming a cached value.
        unsafe { *slot = core::ptr::read_volatile(&buf[i]) };
    }
    out
}

/// Encodes a `ChannelMsgArgs` descriptor for the symmetric message buffer.
fn channel_args(buf_ptr: u64, buf_len: u64) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 2,
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
    let mut message = [0u8; 32];
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
    let n = syscall2(SYS_CHANNEL_CALL, args.as_ptr() as u64, MANAGER_ENDPOINT_HANDLE);
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
    dma[HEADER_OFF..HEADER_OFF + 16].copy_from_slice(&blk_read_header(sector));
    {
        let (rings, _) = dma.split_at_mut(RINGS_TOTAL);
        let (desc, avail) = rings.split_at_mut(AVAIL_OFF);
        blk.write_read_request(
            desc,
            avail,
            dma_phys + HEADER_OFF as u64,
            dma_phys + DATA_OFF as u64,
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
    let args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64) {
        Ok(args) => args,
        Err(code) => return code,
    };
    let mut event_buf = [0u8; PortEventRecord::WIRE_SIZE];
    let mut seq: u16 = 1;
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
        // The event names the endpoint object; map it to this host's handle.
        let endpoint = match event.source {
            SERVER_A_OBJECT => CLIENT_A_ENDPOINT_HANDLE,
            SERVER_B_OBJECT => CLIENT_B_ENDPOINT_HANDLE,
            _ => return fail(0x33, event.source & 0xffff),
        };

        let n = syscall2(SYS_CHANNEL_RECV, args.as_ptr() as u64, endpoint);
        if n < 0 {
            return fail(8, (-n) as u64);
        }
        if (n as usize) < BlockReadRequest::WIRE_SIZE {
            return fail(8, n as u64);
        }
        let request_bytes = read_kernel_filled::<{ BlockReadRequest::WIRE_SIZE }>(&msg_buf);
        let request = match decode::<BlockReadRequest>(&request_bytes) {
            Ok(request) => request,
            Err(_) => return fail(9, 0),
        };
        if request.size != BlockReadRequest::WIRE_SIZE as u32
            || request.version != 1
            || request.flags != 0
        {
            return fail(9, 1);
        }

        // Interrupt-driven: the host parks on its device interrupt port for
        // the completion. Safe to do mid-request now — see the loop note.
        if let Err(code) = read_sector(&blk, dma, dma_phys, request.sector, seq, 0x8000, Wait::Irq)
        {
            return code;
        }
        seq = seq.wrapping_add(1);

        let mut data = [0u8; 64];
        data.copy_from_slice(&dma[DATA_OFF..DATA_OFF + 64]);
        let reply = BlockReadReply {
            size: BlockReadReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status: 0,
            reserved: 0,
            data,
        };
        if encode(&reply, &mut msg_buf[..BlockReadReply::WIRE_SIZE]).is_err() {
            return fail(10, 0xe);
        }
        // Reply on THIS client's endpoint, then loop back to the select.
        let r = syscall2(SYS_CHANNEL_REPLY_CONTINUE, args.as_ptr() as u64, endpoint);
        if r < 0 {
            return fail(10, (-r) as u64);
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
