// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! In-kernel virtio-blk bring-up for the `virt` machine: the arch glue that
//! backs the memory-safe [`tessera_virtio`] transport core with real hardware.
//!
//! The transport logic — the handshake ordering and the descriptor/available/
//! used ring layout — lives in `tessera_virtio` and is host-tested against a
//! mock device. This module supplies the parts that genuinely need `unsafe`:
//! the volatile MMIO register access, the DMA memory (frames reached through
//! the direct map at their physical addresses, which the device reads by
//! physical address), and the barriered completion poll. It reads sector 0 of
//! a qemu-attached disk and checks a magic — a first real block read proving
//! the transport end to end.
//!
//! This is an **in-kernel proof**, not the final arrangement: a real driver is
//! a ring-3 service on the device-host substrate (D46/D47), which this
//! architecture does not yet carry. We poll rather than take the device's
//! interrupt (interrupt objects are deferred, D36).
//!
//! Normative: docs/hardware/04-device-memory-and-unified-memory.md
//! Budget: none (boot/driver path)

use core::arch::asm;
use tessera_devicetree::{DeviceTree, HEADER_LEN, MmioDevice};
use tessera_karch::{FRAME_SIZE, PhysAddr};
use tessera_karch_aarch64::{
    DIRECT_MAP_BASE, counter_frequency, mmio_read32, mmio_write32, read_counter,
};
use tessera_kcore::pmem::BumpFrameAllocator;
use tessera_virtio::{self as virtio, Blk, Layout, Mmio, Net, QueueAddrs, arp};

/// Descriptors in a virtqueue. Eight is far more than the one or three a single
/// request needs, and stays a power of two within the device's `QueueNumMax`.
const QUEUE_SIZE: u16 = 8;

/// The magic the test disk carries in the first bytes of sector 0.
const DISK_MAGIC: &[u8] = b"TESSERAV";

/// Our address in QEMU's SLIRP virtual network, and the gateway we ARP for.
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

/// Receive buffer size — a whole Ethernet frame plus the virtio-net header,
/// generously rounded.
const RX_BUF_LEN: u32 = 2048;

/// One device's MMIO register block, at its device-mapped base. The `unsafe`
/// volatile access `tessera_virtio` cannot express is confined here.
struct DeviceRegisters {
    base: usize,
}

impl Mmio for DeviceRegisters {
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `base` is a virtio-mmio transport reported by the device
        // tree, identity-mapped Device memory in TTBR0; `offset` is a defined
        // 4-byte-aligned register within the 0x200 window.
        unsafe { mmio_read32(self.base + offset) }
    }

    fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read`, and this driver exclusively owns the transport
        // during bring-up.
        unsafe { mmio_write32(self.base + offset, value) }
    }
}

/// Fills `out` with the machine's virtio-mmio transport windows from the device
/// tree, returning how many were found. Best-effort: virtio is optional, so any
/// tree error yields zero rather than failing the boot. Must run **before** the
/// high-half switch, while the blob is reachable at its physical address.
///
/// # Safety
///
/// `dtb` must be the firmware device-tree pointer, readable at its physical
/// address (the boot identity map, before the table switch).
pub unsafe fn discover(dtb: u64, out: &mut [MmioDevice]) -> usize {
    // SAFETY: forwarded — `dtb` points at a device-tree blob the boot identity
    // maps; `total_size` validates the magic and length before the full slice
    // is formed, and the reader bounds-checks every access.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let Ok(total) = tessera_devicetree::total_size(header) else {
        return 0;
    };
    // SAFETY: `total` is the blob's own validated length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };
    let Ok(tree) = DeviceTree::parse(blob) else {
        return 0;
    };
    tree.virtio_mmio_regions(out).unwrap_or(0)
}

/// Probes the discovered transports for a block device, reads sector 0, and
/// verifies its magic. `Ok(true)` = a device was found and the read verified;
/// `Ok(false)` = no block device is attached (a clean skip, not a failure);
/// `Err(code)` = a device was present but bring-up or the read failed.
pub fn check(regions: &[MmioDevice], frames: &mut BumpFrameAllocator<'_>) -> Result<bool, u32> {
    let Some(base) = find_device(regions, virtio::DEVICE_ID_BLOCK) else {
        return Ok(false);
    };

    // DMA memory: one frame for the whole queue (desc + avail + used fit in a
    // page for this size) and one each for the request header, the sector data,
    // and the status byte. The device addresses these by physical address; the
    // kernel reaches the same bytes through the direct map.
    let queue = frames.alloc().ok_or(1u32)?.base();
    let header = frames.alloc().ok_or(2u32)?.base();
    let data = frames.alloc().ok_or(3u32)?.base();
    let status = frames.alloc().ok_or(4u32)?.base();

    let layout = Layout::for_size(QUEUE_SIZE);
    let desc_phys = queue.as_u64();
    let avail_phys = desc_phys + layout.avail_offset as u64;
    let used_phys = desc_phys + layout.used_offset as u64;

    // The ring indices must start at zero; a fresh frame is not guaranteed to
    // be. Zero the whole queue region before the device reads it.
    zero(queue, layout.total);

    let mmio = DeviceRegisters {
        base: base as usize,
    };
    let blk = Blk::init(&mmio, QUEUE_SIZE, desc_phys, avail_phys, used_phys)
        .map_err(|error| 100 + error as u32)?;

    // Write the request header, then the descriptor/available rings, into the
    // direct-mapped DMA memory. Descriptor and available rings share the queue
    // frame, so one mutable view is split rather than aliased.
    write_bytes(header, &virtio::blk_read_header(0));
    {
        let region = dm_mut(queue, layout.used_offset);
        let (desc, avail) = region.split_at_mut(layout.avail_offset);
        blk.write_read_request(
            desc,
            avail,
            header.as_u64(),
            data.as_u64(),
            status.as_u64(),
            0,
        );
    }

    // Publish the ring writes to the device, ring the doorbell, and poll the
    // used ring for the completion, bounded by a real time limit.
    barrier();
    blk.notify();
    if !poll_used(used_phys) {
        return Err(20); // no completion within the deadline
    }

    let used = dm_ref(PhysAddr::new(used_phys), layout.total - layout.used_offset);
    let (_head, _len) = blk
        .completion(used, 0)
        .map_err(|error| 200 + error as u32)?
        .ok_or(21u32)?;

    // SAFETY: `status` is the one-byte status frame the device wrote, reachable
    // through the direct map.
    let status_byte = unsafe { *((DIRECT_MAP_BASE + status.as_u64()) as *const u8) };
    if status_byte != virtio::BLK_S_OK {
        return Err(22);
    }

    let sector = dm_ref(data, virtio::SECTOR_LEN);
    if &sector[..DISK_MAGIC.len()] != DISK_MAGIC {
        return Err(23); // the device returned bytes, but not our disk's
    }

    Ok(true)
}

/// Brings up a virtio-net device and proves the datapath with a real ARP
/// round-trip: it transmits an ARP request for QEMU's SLIRP gateway and
/// receives and verifies the reply, exercising both virtqueues. `Ok(Some(mac))`
/// = a device was found and the round-trip verified (its MAC returned);
/// `Ok(None)` = no network device is attached (a clean skip); `Err(code)` = a
/// device was present but bring-up or the exchange failed.
pub fn net_check(
    regions: &[MmioDevice],
    frames: &mut BumpFrameAllocator<'_>,
) -> Result<Option<[u8; 6]>, u32> {
    let Some(base) = find_device(regions, virtio::DEVICE_ID_NET) else {
        return Ok(None);
    };

    // One frame per queue (receive, transmit) and one buffer each. The device
    // DMAs all four by physical address; the kernel reaches them via the direct
    // map.
    let rx_queue = frames.alloc().ok_or(1u32)?.base();
    let tx_queue = frames.alloc().ok_or(2u32)?.base();
    let rx_buf = frames.alloc().ok_or(3u32)?.base();
    let tx_buf = frames.alloc().ok_or(4u32)?.base();

    let layout = Layout::for_size(QUEUE_SIZE);
    zero(rx_queue, layout.total);
    zero(tx_queue, layout.total);
    let rx = queue_addrs(rx_queue, layout);
    let tx = queue_addrs(tx_queue, layout);

    let mmio = DeviceRegisters {
        base: base as usize,
    };
    let net = Net::init(&mmio, rx, tx, QUEUE_SIZE).map_err(|error| 100 + error as u32)?;
    let mac = net.mac();

    // Post a receive buffer first, so the device has somewhere to deliver the
    // reply before we ask for it.
    {
        let region = dm_mut(rx_queue, layout.used_offset);
        let (desc, avail) = region.split_at_mut(layout.avail_offset);
        net.post_rx(desc, avail, rx_buf.as_u64(), RX_BUF_LEN, 0);
    }
    barrier();
    net.notify_rx();

    // Build the ARP request into [net header (zeroed) | frame] and transmit it.
    let frame_len = (virtio::NET_HDR_LEN + arp::FRAME_LEN) as u32;
    {
        let buffer = dm_mut(tx_buf, virtio::NET_HDR_LEN + arp::FRAME_LEN);
        for byte in &mut buffer[..virtio::NET_HDR_LEN] {
            *byte = 0;
        }
        buffer[virtio::NET_HDR_LEN..].copy_from_slice(&arp::build_request(mac, OUR_IP, GATEWAY_IP));

        let region = dm_mut(tx_queue, layout.used_offset);
        let (desc, avail) = region.split_at_mut(layout.avail_offset);
        net.post_tx(desc, avail, tx_buf.as_u64(), frame_len, 0);
    }
    barrier();
    net.notify_tx();

    // The transmit must complete, then the reply must arrive on the receive
    // queue, each within a real time limit.
    if !poll_used(tx.used) {
        return Err(20); // transmit never completed
    }
    if !poll_used(rx.used) {
        return Err(21); // no reply within the deadline
    }
    let rx_used = dm_ref(PhysAddr::new(rx.used), layout.total - layout.used_offset);
    net.rx_completion(rx_used, 0)
        .map_err(|error| 200 + error as u32)?
        .ok_or(22u32)?;

    // Parse the received frame past the net header and require an ARP reply
    // from the gateway.
    let received = dm_ref(
        PhysAddr::new(rx_buf.as_u64() + virtio::NET_HDR_LEN as u64),
        arp::FRAME_LEN,
    );
    match arp::parse_reply(received) {
        Some(reply) if reply.sender_ip == GATEWAY_IP => Ok(Some(mac)),
        _ => Err(23), // a frame arrived, but not the gateway's ARP reply
    }
}

/// The three ring physical addresses for a queue placed at `base`.
fn queue_addrs(base: PhysAddr, layout: Layout) -> QueueAddrs {
    QueueAddrs {
        desc: base.as_u64(),
        avail: base.as_u64() + layout.avail_offset as u64,
        used: base.as_u64() + layout.used_offset as u64,
    }
}

/// The MMIO base of the attached virtio-block transport, or `None` if none is
/// present — the physical window a ring-3 driver's `map_device` capability names
/// (D77). Discovery (a read-only probe of `MAGIC`/`DEVICE_ID`) does not disturb
/// device state, so the in-kernel `check` still runs afterward.
pub fn block_device_base(regions: &[MmioDevice]) -> Option<u64> {
    find_device(regions, virtio::DEVICE_ID_BLOCK)
}

/// The first virtio-mmio window holding a network device, if any (the ring-3
/// device host's second capability, D83).
pub fn net_device_base(regions: &[MmioDevice]) -> Option<u64> {
    find_device(regions, virtio::DEVICE_ID_NET)
}

/// The base of the first attached transport whose `DeviceID` is `device_id`,
/// or `None` if none is.
fn find_device(regions: &[MmioDevice], device_id: u32) -> Option<u64> {
    for region in regions {
        let mmio = DeviceRegisters {
            base: region.base as usize,
        };
        if mmio.read(virtio::reg::MAGIC_VALUE) == virtio::MAGIC
            && mmio.read(virtio::reg::DEVICE_ID) == device_id
        {
            return Some(region.base);
        }
    }
    None
}

/// Polls a used ring's producer index (offset 2) until it advances past zero or
/// a real time limit expires, returning whether a completion appeared. A fresh
/// volatile read each iteration (a plain load could be hoisted and spin
/// forever), with a barrier so the device's write is observed.
fn poll_used(used_phys: u64) -> bool {
    let deadline = read_counter() + counter_frequency() * 2;
    loop {
        barrier();
        // SAFETY: `used_phys + 2` is the used ring's index field, inside the
        // zeroed, mapped queue frame; a `u16` read is aligned and in bounds.
        let idx =
            unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + used_phys + 2) as *const u16) };
        if idx != 0 {
            return true;
        }
        if read_counter() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// A full data-synchronisation barrier, so ring writes are visible to the
/// device before the doorbell and the device's completion is visible to us.
fn barrier() {
    // SAFETY: `dsb` only orders memory accesses; it touches nothing and is
    // permitted at EL1.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
}

/// Zeroes `len` bytes of the frame at `phys` through the direct map.
fn zero(phys: PhysAddr, len: usize) {
    // SAFETY: `phys` is a freshly allocated frame this driver owns, reachable
    // at `DIRECT_MAP_BASE + phys`; `len` stays within the frame.
    unsafe { core::ptr::write_bytes((DIRECT_MAP_BASE + phys.as_u64()) as *mut u8, 0, len) };
}

/// Copies `bytes` into the frame at `phys` through the direct map.
fn write_bytes(phys: PhysAddr, bytes: &[u8]) {
    let dst = dm_mut(phys, bytes.len());
    dst.copy_from_slice(bytes);
}

/// A mutable view of `len` bytes at physical `phys` through the direct map.
fn dm_mut(phys: PhysAddr, len: usize) -> &'static mut [u8] {
    // SAFETY: `phys` names a frame this driver owns; the direct map makes it
    // readable and writable at `DIRECT_MAP_BASE + phys`, and `len` is bounded
    // by the caller to stay within the frame. Single-threaded boot: no aliasing
    // borrow of the same bytes is live.
    unsafe { core::slice::from_raw_parts_mut((DIRECT_MAP_BASE + phys.as_u64()) as *mut u8, len) }
}

/// A shared view of `len` bytes at physical `phys` through the direct map.
fn dm_ref(phys: PhysAddr, len: usize) -> &'static [u8] {
    // SAFETY: as `dm_mut`, read-only.
    unsafe { core::slice::from_raw_parts((DIRECT_MAP_BASE + phys.as_u64()) as *const u8, len) }
}

/// Padding assertion: the whole queue must fit the single frame we allocate.
const _: () = assert!(Layout::for_size(QUEUE_SIZE).total <= FRAME_SIZE as usize);
