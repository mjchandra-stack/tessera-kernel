// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The virtio transport core: the modern (v2) virtio-mmio device handshake,
//! the split-virtqueue layout and encoding, and the virtio-blk request codec.
//!
//! It is deliberately **architecture-neutral and `unsafe`-free**. All device
//! register access goes through the [`Mmio`] trait, and all queue and buffer
//! memory is passed in as byte slices, so the fragile parts — the handshake
//! ordering and the descriptor/available/used ring layout the device reads by
//! DMA — are ordinary logic that a mock device exercises on the host. The
//! caller (an arch boot glue or, later, a ring-3 driver host) supplies the
//! real volatile MMIO, allocates the DMA memory, and owns the barriers and the
//! completion poll — the operations that genuinely need `unsafe`.
//!
//! The used ring is **device-controlled external input**: every field the
//! device fills is read back through bounds-checked slice access, and a
//! malformed completion is a typed [`Error`], never a panic.
//!
//! Normative: docs/hardware/04-device-memory-and-unified-memory.md
//! ("Device Memory"), docs/hardware/02-hardware-description-and-discovery.md
//! Budget: none (driver path)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// Access to one device's MMIO register block, offset from its base. The only
/// device-touching surface: an implementation performs the actual volatile
/// load/store (and is where the `unsafe` lives); this crate only ever calls
/// these two methods, which keeps the handshake host-testable.
pub trait Mmio {
    /// Reads the 32-bit register at `offset` from the device base.
    fn read(&self, offset: usize) -> u32;
    /// Writes the 32-bit register at `offset` from the device base.
    fn write(&self, offset: usize, value: u32);
}

/// virtio-mmio register offsets (interface version 2).
pub mod reg {
    pub const MAGIC_VALUE: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const DEVICE_FEATURES: usize = 0x010;
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    pub const DRIVER_FEATURES: usize = 0x020;
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
    pub const QUEUE_DESC_LOW: usize = 0x080;
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    pub const QUEUE_DRIVER_LOW: usize = 0x090;
    pub const QUEUE_DRIVER_HIGH: usize = 0x094;
    pub const QUEUE_DEVICE_LOW: usize = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: usize = 0x0a4;
    /// Device-specific configuration space (the virtio-net MAC lives here).
    pub const CONFIG: usize = 0x100;
}

/// `"virt"` little-endian — the value the `MagicValue` register must hold.
pub const MAGIC: u32 = 0x7472_6976;
/// Interface version this driver speaks (modern virtio).
pub const VERSION: u32 = 2;
/// `DeviceID` for a block device.
pub const DEVICE_ID_BLOCK: u32 = 2;
/// `DeviceID` for a network device.
pub const DEVICE_ID_NET: u32 = 1;

/// `Status` register bits, set in the order the specification prescribes.
pub mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
    pub const FAILED: u32 = 0x80;
}

/// `VIRTIO_F_VERSION_1` (feature bit 32) — mandatory for a modern device; it
/// lives in the high 32-bit feature word (selector 1), at bit 0.
const FEATURE_VERSION_1_BIT: u32 = 1; // bit 0 of selector-1 word

/// Descriptor flags.
const DESC_F_NEXT: u16 = 1;
/// Marks a buffer the device writes into (driver-readable output).
const DESC_F_WRITE: u16 = 2;

/// virtio-blk request type: read from the device into the data buffer.
pub const BLK_T_IN: u32 = 0;
/// virtio-blk status: success.
pub const BLK_S_OK: u8 = 0;
/// Bytes in a virtio-blk request header (`type`, `reserved`, `sector`).
pub const BLK_HEADER_LEN: usize = 16;
/// Bytes in one disk sector.
pub const SECTOR_LEN: usize = 512;

/// `VIRTIO_NET_F_MAC` (feature bit 5, low word): the device exposes its MAC in
/// config space. Accepted so the config-space MAC is defined.
pub const NET_F_MAC: u32 = 1 << 5;
/// Bytes in the modern virtio-net header prepended to every buffer.
pub const NET_HDR_LEN: usize = 12;

pub mod arp;

/// Why a virtio operation could not complete. Stable ordering; a boot verdict
/// or log reports the value rather than a string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Error {
    /// `MagicValue` was not `"virt"`.
    BadMagic = 1,
    /// The interface version is not the modern version this driver speaks.
    BadVersion = 2,
    /// The transport is present but is not a block device.
    NotBlockDevice = 3,
    /// The device does not offer `VIRTIO_F_VERSION_1`.
    NoModernFeature = 4,
    /// The device cleared `FEATURES_OK` — it rejected the negotiated set.
    FeaturesRejected = 5,
    /// The requested queue size is zero, not a power of two, or larger than
    /// the device's `QueueNumMax`.
    QueueSize = 6,
    /// The device set `FAILED` during bring-up.
    DeviceFailed = 7,
    /// A used-ring element referenced a descriptor index outside the queue.
    BadUsedElement = 8,
    /// The transport is present but is not a network device.
    NotNetDevice = 9,
}

/// Byte layout of a split virtqueue of `size` descriptors packed into one
/// contiguous region: the descriptor table, then the available ring, then the
/// used ring, each at the alignment the specification requires (16 / 2 / 4).
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub size: u16,
    pub desc_offset: usize,
    pub avail_offset: usize,
    pub used_offset: usize,
    pub total: usize,
}

impl Layout {
    /// Descriptor is 16 bytes; the available ring is `6 + 2*size`; the used
    /// ring is `6 + 8*size`.
    pub const fn for_size(size: u16) -> Layout {
        let n = size as usize;
        let desc_offset = 0;
        let desc_len = 16 * n;
        let avail_offset = desc_len; // 16*n is 16-aligned, so 2-aligned
        let avail_len = 6 + 2 * n;
        let used_offset = align_up(avail_offset + avail_len, 4);
        let used_len = 6 + 8 * n;
        Layout {
            size,
            desc_offset,
            avail_offset,
            used_offset,
            total: used_offset + used_len,
        }
    }
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// A ready-to-use block transport: a live reference to the device's MMIO and
/// the negotiated queue size. Built by [`Blk::init`], which runs the whole
/// handshake; the caller then drives one request at a time with
/// [`write_read_request`](Blk::write_read_request) / [`notify`](Blk::notify) /
/// [`completion`](Blk::completion).
pub struct Blk<'m, M: Mmio> {
    mmio: &'m M,
    queue_size: u16,
}

impl<'m, M: Mmio> Blk<'m, M> {
    /// Runs the modern virtio-mmio bring-up against a block device and leaves
    /// it in the `DRIVER_OK` state with queue 0 configured at the given
    /// **physical** addresses.
    ///
    /// `queue_size` must be a power of two no larger than the device's
    /// `QueueNumMax`. `desc_phys`/`avail_phys`/`used_phys` are the physical
    /// addresses of the three ring regions the device will DMA — the caller
    /// carves them out of one contiguous region per [`Layout`].
    pub fn init(
        mmio: &'m M,
        queue_size: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> Result<Self, Error> {
        probe(mmio, DEVICE_ID_BLOCK, Error::NotBlockDevice)?;
        begin(mmio);
        // A block device needs no optional feature; accept only VERSION_1.
        negotiate(mmio, 0, FEATURE_VERSION_1_BIT)?;
        let state = set_features_ok(mmio)?;
        let queue_size = configure_queue(mmio, 0, queue_size, desc_phys, avail_phys, used_phys)?;
        driver_ok(mmio, state)?;
        Ok(Blk { mmio, queue_size })
    }

    /// The negotiated queue size.
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// Writes a three-descriptor read chain into the caller's `desc` and
    /// `avail` ring slices and publishes it: descriptor 0 the request header
    /// (device-readable), descriptor 1 the data buffer (device-writable),
    /// descriptor 2 the status byte (device-writable). The three `*_phys`
    /// arguments are the buffers' physical addresses. `avail_idx` is the
    /// current producer index (0 for the first request).
    ///
    /// The caller must have written [`blk_read_header`] into the header buffer
    /// first, and must publish the descriptor and available writes to the
    /// device (a barrier) before calling [`notify`](Self::notify).
    pub fn write_read_request(
        &self,
        desc: &mut [u8],
        avail: &mut [u8],
        header_phys: u64,
        data_phys: u64,
        status_phys: u64,
        avail_idx: u16,
    ) {
        write_desc(desc, 0, header_phys, BLK_HEADER_LEN as u32, DESC_F_NEXT, 1);
        write_desc(
            desc,
            1,
            data_phys,
            SECTOR_LEN as u32,
            DESC_F_NEXT | DESC_F_WRITE,
            2,
        );
        write_desc(desc, 2, status_phys, 1, DESC_F_WRITE, 0);

        // Available ring: ring[idx % size] = head descriptor (0), then bump
        // the producer index so the device sees the new entry.
        let slot = (avail_idx as usize) % (self.queue_size as usize);
        put_u16(avail, 4 + slot * 2, 0);
        put_u16(avail, 2, avail_idx.wrapping_add(1));
    }

    /// Rings the doorbell for queue 0. The caller must have made the
    /// descriptor/available writes visible first.
    pub fn notify(&self) {
        self.mmio.write(reg::QUEUE_NOTIFY, 0);
    }

    /// Whether the device has produced a completion, given the current used
    /// ring bytes (which the caller must read fresh from device memory, with a
    /// barrier). `seen` is the producer index the driver has already consumed
    /// (0 before the first request). Returns the completed head descriptor
    /// index and the byte count the device reported written, or `None` if the
    /// device has not advanced.
    pub fn completion(&self, used: &[u8], seen: u16) -> Result<Option<(u16, u32)>, Error> {
        completion_for(used, seen, self.queue_size)
    }

    /// Acknowledges a used-buffer interrupt, if the caller polls
    /// `InterruptStatus` (not required for the pure-poll path).
    pub fn ack_interrupt(&self) {
        let pending = self.mmio.read(reg::INTERRUPT_STATUS);
        if pending != 0 {
            self.mmio.write(reg::INTERRUPT_ACK, pending);
        }
    }
}

/// The physical addresses of one queue's three ring regions.
#[derive(Clone, Copy)]
pub struct QueueAddrs {
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
}

/// A virtio-net device with a receive queue (0) and a transmit queue (1).
/// Built by [`Net::init`]; the caller posts single-descriptor buffers with
/// [`post_rx`](Net::post_rx)/[`post_tx`](Net::post_tx), rings the matching
/// doorbell, and reads completions off each used ring.
pub struct Net<'m, M: Mmio> {
    mmio: &'m M,
    rx_size: u16,
    tx_size: u16,
    mac: [u8; 6],
}

impl<'m, M: Mmio> Net<'m, M> {
    /// Runs the modern virtio-mmio bring-up against a network device, leaving
    /// it in `DRIVER_OK` with the receive queue (0) and transmit queue (1)
    /// configured at the given physical ring addresses, and reads the MAC from
    /// config space.
    pub fn init(
        mmio: &'m M,
        rx: QueueAddrs,
        tx: QueueAddrs,
        queue_size: u16,
    ) -> Result<Self, Error> {
        probe(mmio, DEVICE_ID_NET, Error::NotNetDevice)?;
        begin(mmio);
        // Accept the MAC feature when offered, so config-space MAC is defined.
        let mac_feature = device_features_low(mmio) & NET_F_MAC;
        negotiate(mmio, mac_feature, FEATURE_VERSION_1_BIT)?;
        let state = set_features_ok(mmio)?;
        let rx_size = configure_queue(mmio, 0, queue_size, rx.desc, rx.avail, rx.used)?;
        let tx_size = configure_queue(mmio, 1, queue_size, tx.desc, tx.avail, tx.used)?;
        driver_ok(mmio, state)?;

        let low = read_config_u32(mmio, 0);
        let high = read_config_u32(mmio, 4);
        let mut mac = [0u8; 6];
        mac[0..4].copy_from_slice(&low.to_le_bytes());
        mac[4..6].copy_from_slice(&high.to_le_bytes()[0..2]);
        Ok(Net {
            mmio,
            rx_size,
            tx_size,
            mac,
        })
    }

    /// The device's MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Posts a single device-writable buffer on the receive queue for the
    /// device to deliver an incoming frame into.
    pub fn post_rx(
        &self,
        desc: &mut [u8],
        avail: &mut [u8],
        buf_phys: u64,
        buf_len: u32,
        idx: u16,
    ) {
        post_single(
            desc,
            avail,
            buf_phys,
            buf_len,
            DESC_F_WRITE,
            idx,
            self.rx_size,
        );
    }

    /// Posts a single device-readable buffer (`[net header | frame]`) on the
    /// transmit queue.
    pub fn post_tx(
        &self,
        desc: &mut [u8],
        avail: &mut [u8],
        frame_phys: u64,
        frame_len: u32,
        idx: u16,
    ) {
        post_single(desc, avail, frame_phys, frame_len, 0, idx, self.tx_size);
    }

    /// Rings the receive doorbell (queue 0).
    pub fn notify_rx(&self) {
        self.mmio.write(reg::QUEUE_NOTIFY, 0);
    }

    /// Rings the transmit doorbell (queue 1).
    pub fn notify_tx(&self) {
        self.mmio.write(reg::QUEUE_NOTIFY, 1);
    }

    /// A completion off the receive used ring, if the device has advanced.
    pub fn rx_completion(&self, used: &[u8], seen: u16) -> Result<Option<(u16, u32)>, Error> {
        completion_for(used, seen, self.rx_size)
    }

    /// A completion off the transmit used ring, if the device has advanced.
    pub fn tx_completion(&self, used: &[u8], seen: u16) -> Result<Option<(u16, u32)>, Error> {
        completion_for(used, seen, self.tx_size)
    }
}

/// Checks the transport is present, modern, and the expected device kind,
/// returning `wrong` if the `DeviceID` does not match.
fn probe<M: Mmio>(mmio: &M, device_id: u32, wrong: Error) -> Result<(), Error> {
    if mmio.read(reg::MAGIC_VALUE) != MAGIC {
        return Err(Error::BadMagic);
    }
    if mmio.read(reg::VERSION) != VERSION {
        return Err(Error::BadVersion);
    }
    if mmio.read(reg::DEVICE_ID) != device_id {
        return Err(wrong);
    }
    Ok(())
}

/// Resets the device and acknowledges it, up to the `DRIVER` state.
fn begin<M: Mmio>(mmio: &M) {
    mmio.write(reg::STATUS, 0);
    mmio.write(reg::STATUS, status::ACKNOWLEDGE);
    mmio.write(reg::STATUS, status::ACKNOWLEDGE | status::DRIVER);
}

/// The device's offered low-word (selector 0) feature bits.
fn device_features_low<M: Mmio>(mmio: &M) -> u32 {
    mmio.write(reg::DEVICE_FEATURES_SEL, 0);
    mmio.read(reg::DEVICE_FEATURES)
}

/// Requires the device to offer `VIRTIO_F_VERSION_1`, then writes the driver's
/// accepted features — `features_high` (which must include `VERSION_1`) in the
/// high word, `features_low` in the low word.
fn negotiate<M: Mmio>(mmio: &M, features_low: u32, features_high: u32) -> Result<(), Error> {
    mmio.write(reg::DEVICE_FEATURES_SEL, 1);
    if mmio.read(reg::DEVICE_FEATURES) & FEATURE_VERSION_1_BIT == 0 {
        return Err(Error::NoModernFeature);
    }
    mmio.write(reg::DRIVER_FEATURES_SEL, 1);
    mmio.write(reg::DRIVER_FEATURES, features_high);
    mmio.write(reg::DRIVER_FEATURES_SEL, 0);
    mmio.write(reg::DRIVER_FEATURES, features_low);
    Ok(())
}

/// Sets `FEATURES_OK` and confirms the device did not clear it. Returns the
/// running status word so the caller can add `DRIVER_OK` after queue setup.
fn set_features_ok<M: Mmio>(mmio: &M) -> Result<u32, Error> {
    let state = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK;
    mmio.write(reg::STATUS, state);
    if mmio.read(reg::STATUS) & status::FEATURES_OK == 0 {
        mmio.write(reg::STATUS, state | status::FAILED);
        return Err(Error::FeaturesRejected);
    }
    Ok(state)
}

/// Marks the driver ready and checks the device did not set `FAILED`.
fn driver_ok<M: Mmio>(mmio: &M, state: u32) -> Result<(), Error> {
    let state = state | status::DRIVER_OK;
    mmio.write(reg::STATUS, state);
    if mmio.read(reg::STATUS) & status::FAILED != 0 {
        return Err(Error::DeviceFailed);
    }
    Ok(())
}

/// Reads a 32-bit word from device-specific config space at `offset`.
fn read_config_u32<M: Mmio>(mmio: &M, offset: usize) -> u32 {
    mmio.read(reg::CONFIG + offset)
}

/// Posts one descriptor over `buf_phys` (writable if `flags` has `DESC_F_WRITE`)
/// and publishes it on the available ring.
fn post_single(
    desc: &mut [u8],
    avail: &mut [u8],
    buf_phys: u64,
    len: u32,
    flags: u16,
    avail_idx: u16,
    queue_size: u16,
) {
    write_desc(desc, 0, buf_phys, len, flags, 0);
    let slot = (avail_idx as usize) % (queue_size as usize);
    put_u16(avail, 4 + slot * 2, 0);
    put_u16(avail, 2, avail_idx.wrapping_add(1));
}

/// Reads a completion off a used ring: the head descriptor index and byte
/// count the device wrote, or `None` if it has not advanced past `seen`.
fn completion_for(used: &[u8], seen: u16, queue_size: u16) -> Result<Option<(u16, u32)>, Error> {
    if used_index(used) == seen {
        return Ok(None);
    }
    let slot = (seen as usize) % (queue_size as usize);
    let (id, len) = used_element(used, slot);
    if id >= queue_size as u32 {
        return Err(Error::BadUsedElement);
    }
    Ok(Some((id as u16, len)))
}

/// Selects queue `index`, checks it fits the device's maximum, programs the
/// three ring physical addresses, and marks it ready. Returns the size used.
fn configure_queue<M: Mmio>(
    mmio: &M,
    index: u32,
    size: u16,
    desc_phys: u64,
    avail_phys: u64,
    used_phys: u64,
) -> Result<u16, Error> {
    if size == 0 || !size.is_power_of_two() {
        return Err(Error::QueueSize);
    }
    mmio.write(reg::QUEUE_SEL, index);
    let max = mmio.read(reg::QUEUE_NUM_MAX);
    if max == 0 || u32::from(size) > max {
        return Err(Error::QueueSize);
    }
    mmio.write(reg::QUEUE_NUM, u32::from(size));
    write_phys(mmio, reg::QUEUE_DESC_LOW, reg::QUEUE_DESC_HIGH, desc_phys);
    write_phys(
        mmio,
        reg::QUEUE_DRIVER_LOW,
        reg::QUEUE_DRIVER_HIGH,
        avail_phys,
    );
    write_phys(
        mmio,
        reg::QUEUE_DEVICE_LOW,
        reg::QUEUE_DEVICE_HIGH,
        used_phys,
    );
    mmio.write(reg::QUEUE_READY, 1);
    Ok(size)
}

fn write_phys<M: Mmio>(mmio: &M, low: usize, high: usize, phys: u64) {
    mmio.write(low, phys as u32);
    mmio.write(high, (phys >> 32) as u32);
}

/// Encodes a virtio-blk read-request header for `sector`.
pub fn blk_read_header(sector: u64) -> [u8; BLK_HEADER_LEN] {
    let mut header = [0u8; BLK_HEADER_LEN];
    header[0..4].copy_from_slice(&BLK_T_IN.to_le_bytes());
    // header[4..8] is the reserved word, left zero.
    header[8..16].copy_from_slice(&sector.to_le_bytes());
    header
}

/// Writes one 16-byte descriptor at `index` into a descriptor-table slice.
fn write_desc(desc: &mut [u8], index: usize, addr: u64, len: u32, flags: u16, next: u16) {
    let at = index * 16;
    put_u64(desc, at, addr);
    put_u32(desc, at + 8, len);
    put_u16(desc, at + 12, flags);
    put_u16(desc, at + 14, next);
}

/// The producer index the device has reached in the used ring (offset 2).
fn used_index(used: &[u8]) -> u16 {
    get_u16(used, 2)
}

/// The used-ring element at `slot`: `(descriptor id, bytes written)`.
fn used_element(used: &[u8], slot: usize) -> (u32, u32) {
    let at = 4 + slot * 8;
    (get_u32(used, at), get_u32(used, at + 4))
}

// Little-endian slice accessors. Out-of-range writes are silently skipped and
// out-of-range reads return zero: callers size the ring slices from `Layout`,
// so an index past the end is a caller bug the tests catch, never a live
// out-of-bounds — but these never panic on device-controlled input.
fn put_u16(buffer: &mut [u8], at: usize, value: u16) {
    if let Some(slot) = buffer.get_mut(at..at + 2) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

fn put_u32(buffer: &mut [u8], at: usize, value: u32) {
    if let Some(slot) = buffer.get_mut(at..at + 4) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

fn put_u64(buffer: &mut [u8], at: usize, value: u64) {
    if let Some(slot) = buffer.get_mut(at..at + 8) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

fn get_u16(buffer: &[u8], at: usize) -> u16 {
    match buffer.get(at..at + 2) {
        Some(bytes) => u16::from_le_bytes([bytes[0], bytes[1]]),
        None => 0,
    }
}

fn get_u32(buffer: &[u8], at: usize) -> u32 {
    match buffer.get(at..at + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

#[cfg(test)]
mod tests;
