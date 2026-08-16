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

/// What a virtio *transport* must be able to do, stated as operations rather
/// than as registers.
///
/// virtio has more than one transport, and they do not differ in what the
/// bring-up *means* — reset, acknowledge, agree features, configure a queue,
/// go — only in where those live. On virtio-mmio they are 32-bit registers at
/// fixed offsets in one block; on virtio-pci they are fields of several widths
/// in a structure found through PCI capabilities, with the doorbell in a
/// different region again. Everything above this line — the split-virtqueue
/// layout, descriptor chains, used-ring polling, the block request codec — is
/// the same either way, and is where the bugs live, so it is written once.
///
/// [`Mmio`] implementors get this for free through a blanket implementation,
/// so a driver that already speaks virtio-mmio needs no change at all.
pub trait Transport {
    /// Checks the transport is present, modern, and the expected device kind.
    fn probe(&self, device_id: u32, wrong: Error) -> Result<(), Error>;
    /// Puts the device back in its reset state and leaves it there.
    ///
    /// The half of [`begin`](Self::begin) that stops rather than starts, and
    /// separate from it because a driver taking an interface out of service
    /// has nothing to start: after this the queues are gone and the device
    /// moves nothing, which is what a network link being down *is* on a
    /// transport with no cable to unplug.
    fn reset(&self);
    /// Resets the device and acknowledges it, up to the `DRIVER` state.
    fn begin(&self);
    /// The device's offered low-word (selector 0) feature bits.
    fn device_features_low(&self) -> u32;
    /// Requires `VIRTIO_F_VERSION_1` and writes the driver's accepted features.
    fn negotiate(&self, features_low: u32, features_high: u32) -> Result<(), Error>;
    /// Sets `FEATURES_OK` and confirms the device did not clear it, returning
    /// the running status word.
    fn set_features_ok(&self) -> Result<u32, Error>;
    /// Marks the driver ready and checks the device did not set `FAILED`.
    fn driver_ok(&self, state: u32) -> Result<(), Error>;
    /// Programs one queue's size and ring addresses and enables it, returning
    /// the size actually used.
    fn configure_queue(
        &self,
        index: u32,
        size: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> Result<u16, Error>;
    /// Rings `queue`'s doorbell.
    fn notify(&self, queue: u16);
    /// Acknowledges a used-buffer interrupt.
    fn ack_interrupt(&self);
    /// Reads a 32-bit word from device-specific configuration space.
    fn config_u32(&self, offset: usize) -> u32;
}

/// Every virtio-mmio register block is a transport, which is what keeps this
/// seam from being a rewrite: the in-kernel drivers and the ring-3 ones pass
/// their register shim exactly as they did before.
impl<M: Mmio> Transport for M {
    fn probe(&self, device_id: u32, wrong: Error) -> Result<(), Error> {
        mmio_probe(self, device_id, wrong)
    }
    fn reset(&self) {
        mmio_reset(self);
    }
    fn begin(&self) {
        mmio_begin(self);
    }
    fn device_features_low(&self) -> u32 {
        mmio_device_features_low(self)
    }
    fn negotiate(&self, features_low: u32, features_high: u32) -> Result<(), Error> {
        mmio_negotiate(self, features_low, features_high)
    }
    fn set_features_ok(&self) -> Result<u32, Error> {
        mmio_set_features_ok(self)
    }
    fn driver_ok(&self, state: u32) -> Result<(), Error> {
        mmio_driver_ok(self, state)
    }
    fn configure_queue(
        &self,
        index: u32,
        size: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> Result<u16, Error> {
        mmio_configure_queue(self, index, size, desc_phys, avail_phys, used_phys)
    }
    fn notify(&self, queue: u16) {
        self.write(reg::QUEUE_NOTIFY, u32::from(queue));
    }
    fn ack_interrupt(&self) {
        let pending = self.read(reg::INTERRUPT_STATUS);
        if pending != 0 {
            self.write(reg::INTERRUPT_ACK, pending);
        }
    }
    fn config_u32(&self, offset: usize) -> u32 {
        self.read(reg::CONFIG + offset)
    }
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
/// Request type: the driver hands the device data to put on the medium.
pub const BLK_T_OUT: u32 = 1;
/// Request type: make everything already written durable.
pub const BLK_T_FLUSH: u32 = 4;
/// virtio-blk status: success.
pub const BLK_S_OK: u8 = 0;
/// Bytes in a virtio-blk request header (`type`, `reserved`, `sector`).
pub const BLK_HEADER_LEN: usize = 16;
/// Bytes in one disk sector.
pub const SECTOR_LEN: usize = 512;

/// `VIRTIO_NET_F_MAC` (feature bit 5, low word): the device exposes its MAC in
/// config space. Accepted so the config-space MAC is defined.
pub const NET_F_MAC: u32 = 1 << 5;
/// `VIRTIO_NET_F_STATUS` (feature bit 16, low word): the device reports link
/// state in config space.
///
/// Accepted when offered, because **the status field does not exist unless it
/// is**: a driver that read config offset 6 without negotiating this would be
/// reading whatever the device leaves there, and calling it a link state. A
/// device that does not offer it has a link that is up by definition — there
/// is nothing else it could mean, and a driver reporting "down" for want of a
/// feature bit would take an interface out of service over a device's silence.
pub const NET_F_STATUS: u32 = 1 << 16;
/// `VIRTIO_NET_S_LINK_UP`, bit 0 of the config-space status field at offset 6.
pub const NET_S_LINK_UP: u16 = 1;
/// Bytes in the modern virtio-net header prepended to every buffer.
pub const NET_HDR_LEN: usize = 12;

/// `VIRTIO_BLK_F_MQ` (feature bit 12): the device has more than one request
/// queue.
///
/// The feature that makes per-child queue separation possible at all
/// (`docs/drivers/01`, "Bus Topology And Data Paths"): where the controller
/// hardware provides it, a child's queue is mapped directly to the child and a
/// transfer crosses no extra process.
pub const BLK_F_MQ: u32 = 1 << 12;

/// The 32-bit word of virtio-blk's device configuration holding `num_queues`.
///
/// `num_queues` is a 16-bit field at byte 34, so it is the **high half** of the
/// aligned word at 32 — see [`blk_num_queues`], which is where that is done
/// once rather than at every call site.
pub const BLK_CFG_NUM_QUEUES_WORD: usize = 32;

/// Extracts `num_queues` from the configuration word at
/// [`BLK_CFG_NUM_QUEUES_WORD`].
///
/// A function rather than an offset constant because the field is not word
/// aligned: `writeback` and one unused byte sit below it, and a driver reading
/// a whole word at 34 would be issuing an unaligned access to device memory for
/// a value that is already in the word below.
pub const fn blk_num_queues(config_word: u32) -> u16 {
    ((config_word >> 16) & 0xffff) as u16
}

pub mod arp;
pub mod crypto;
pub mod gpu;
pub mod pci;
pub mod snd;

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
    /// The transport is present but is not a sound device, or describes no
    /// streams — which is the same thing to a driver that has to name one in
    /// every request it makes.
    NotSoundDevice = 10,
    /// A stream's parameters cannot describe something playable: a period that
    /// does not divide the buffer, or a count of zero where there must be one.
    BadStreamParams = 11,
    /// A device's answer is shorter than the structure it must contain.
    ShortResponse = 12,
    /// The device is already holding every period it can. Refused rather than
    /// queued: a driver that let the queue grow would be adding latency the
    /// stream's parameters said it would not have.
    StreamFull = 13,
    /// A rectangle that does not lie inside the resource it names, or a
    /// command whose buffer is too small for it. Refused here rather than sent:
    /// a device handed a rectangle past a resource's edge reads whatever
    /// follows the backing and puts it on the screen.
    BadRect = 14,
    /// The transport is present but is not a crypto device, or offers no
    /// cipher service — which is the same thing to a driver that has nothing
    /// else to ask it for.
    NotCryptoDevice = 15,
    /// The device does not offer the algorithm that was asked for. **Refused,
    /// never substituted**: a caller handed a different cipher than the one it
    /// named would get back bytes indistinguishable from the right ones.
    AlgorithmNotOffered = 16,
    /// A key length the algorithm does not have, or one longer than the device
    /// will take.
    BadKeyLength = 17,
    /// A data length that is not a whole number of blocks where the mode needs
    /// them, an IV that is not the length the mode takes, or more data than the
    /// device accepts in one request.
    BadDataLength = 18,
    /// An operation asked of a session created for the other direction.
    SessionMismatch = 19,
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
pub struct Blk<'m, T: Transport> {
    transport: &'m T,
    queue_size: u16,
}

impl<'m, T: Transport> Blk<'m, T> {
    /// Runs the modern virtio-mmio bring-up against a block device and leaves
    /// it in the `DRIVER_OK` state with queue 0 configured at the given
    /// **physical** addresses.
    ///
    /// `queue_size` must be a power of two no larger than the device's
    /// `QueueNumMax`. `desc_phys`/`avail_phys`/`used_phys` are the physical
    /// addresses of the three ring regions the device will DMA — the caller
    /// carves them out of one contiguous region per [`Layout`].
    pub fn init(
        transport: &'m T,
        queue_size: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> Result<Self, Error> {
        transport.probe(DEVICE_ID_BLOCK, Error::NotBlockDevice)?;
        transport.begin();
        // A block device needs no optional feature; accept only VERSION_1.
        transport.negotiate(0, FEATURE_VERSION_1_BIT)?;
        let state = transport.set_features_ok()?;
        let queue_size =
            transport.configure_queue(0, queue_size, desc_phys, avail_phys, used_phys)?;
        transport.driver_ok(state)?;
        Ok(Blk {
            transport,
            queue_size,
        })
    }

    /// Brings the device up with **more than one request queue**, leaving it in
    /// `DRIVER_OK` with one queue configured per entry in `queues`.
    ///
    /// Returns the driver and the device's own `num_queues`, which is a fact
    /// about the hardware rather than a request: a caller asking for more
    /// queues than the device has is refused, because configuring a queue index
    /// the device does not implement writes a selector it will not honour and
    /// leaves a ring nothing ever reads.
    ///
    /// **Every queue is independent, and that is the whole point.** A request
    /// posted on queue *n* is completed on queue *n*'s used ring and needs
    /// queue *n*'s doorbell — so a queue can be driven by a process that has
    /// nothing but that queue's rings and that queue's doorbell page, which is
    /// what makes per-child queue mapping possible
    /// (`docs/drivers/01`, "Bus Topology And Data Paths").
    pub fn init_multiqueue(
        transport: &'m T,
        queues: &[QueueAddrs],
        queue_size: u16,
    ) -> Result<(Self, u16), Error> {
        if queues.is_empty() {
            return Err(Error::QueueSize);
        }
        transport.probe(DEVICE_ID_BLOCK, Error::NotBlockDevice)?;
        transport.begin();
        if transport.device_features_low() & BLK_F_MQ == 0 {
            // Falling back to one queue here would hand a child driver the
            // controller's own queue under the name of its own.
            return Err(Error::NotBlockDevice);
        }
        transport.negotiate(BLK_F_MQ, FEATURE_VERSION_1_BIT)?;
        let state = transport.set_features_ok()?;

        let num_queues = blk_num_queues(transport.config_u32(BLK_CFG_NUM_QUEUES_WORD));
        if (num_queues as usize) < queues.len() {
            return Err(Error::QueueSize);
        }
        let mut negotiated = 0u16;
        for (index, queue) in queues.iter().enumerate() {
            negotiated = transport.configure_queue(
                index as u32,
                queue_size,
                queue.desc,
                queue.avail,
                queue.used,
            )?;
        }
        transport.driver_ok(state)?;
        Ok((
            Blk {
                transport,
                queue_size: negotiated,
            },
            num_queues,
        ))
    }

    /// Rings the doorbell of an arbitrary request queue.
    ///
    /// **The one register write a transfer needs.** On a device whose notify
    /// structure gives each queue its own page, this is all a child driver
    /// touches on the data path — which is what lets the queue belong to a
    /// different process from the one that brought the device up.
    pub fn notify_queue(&self, queue: u16) {
        self.transport.notify(queue);
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

    /// The write counterpart of [`write_read_request`](Self::write_read_request):
    /// descriptor 0 the request header, descriptor 1 the data buffer, and
    /// descriptor 2 the status byte.
    ///
    /// **The one difference is the direction of descriptor 1, and it is the
    /// whole thing.** A read marks the data buffer device-*writable*, because
    /// the device fills it; a write must not, because the device reads it. A
    /// buffer marked writable on a write is a buffer the device is entitled to
    /// scribble on — the transfer may appear to succeed while the data that
    /// came back is whatever the device felt like leaving there, which is the
    /// failure this method exists to make unwritable.
    ///
    /// The caller must have written [`blk_write_header`] into the header
    /// buffer and the payload into the data buffer first, and must publish
    /// both to the device before calling [`notify`](Self::notify).
    pub fn write_write_request(
        &self,
        desc: &mut [u8],
        avail: &mut [u8],
        header_phys: u64,
        data_phys: u64,
        status_phys: u64,
        avail_idx: u16,
    ) {
        write_desc(desc, 0, header_phys, BLK_HEADER_LEN as u32, DESC_F_NEXT, 1);
        // Device-readable: no DESC_F_WRITE. See the note above.
        write_desc(desc, 1, data_phys, SECTOR_LEN as u32, DESC_F_NEXT, 2);
        write_desc(desc, 2, status_phys, 1, DESC_F_WRITE, 0);

        let slot = (avail_idx as usize) % (self.queue_size as usize);
        put_u16(avail, 4 + slot * 2, 0);
        put_u16(avail, 2, avail_idx.wrapping_add(1));
    }

    /// Rings the doorbell for queue 0. The caller must have made the
    /// descriptor/available writes visible first.
    pub fn notify(&self) {
        self.transport.notify(0);
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
        self.transport.ack_interrupt();
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
pub struct Net<'m, T: Transport> {
    transport: &'m T,
    rx_size: u16,
    tx_size: u16,
    mac: [u8; 6],
    /// Whether `VIRTIO_NET_F_STATUS` was negotiated — i.e. whether the config
    /// space link-state field exists to be read at all.
    reports_link: bool,
}

impl<'m, T: Transport> Net<'m, T> {
    /// Runs the modern virtio-mmio bring-up against a network device, leaving
    /// it in `DRIVER_OK` with the receive queue (0) and transmit queue (1)
    /// configured at the given physical ring addresses, and reads the MAC from
    /// config space.
    pub fn init(
        transport: &'m T,
        rx: QueueAddrs,
        tx: QueueAddrs,
        queue_size: u16,
    ) -> Result<Self, Error> {
        transport.probe(DEVICE_ID_NET, Error::NotNetDevice)?;
        transport.begin();
        // Accept the MAC feature when offered, so config-space MAC is defined,
        // and the status feature for the same reason: both are fields that
        // exist only because they were negotiated.
        let offered = transport.device_features_low() & (NET_F_MAC | NET_F_STATUS);
        transport.negotiate(offered, FEATURE_VERSION_1_BIT)?;
        let state = transport.set_features_ok()?;
        let rx_size = transport.configure_queue(0, queue_size, rx.desc, rx.avail, rx.used)?;
        let tx_size = transport.configure_queue(1, queue_size, tx.desc, tx.avail, tx.used)?;
        transport.driver_ok(state)?;

        let low = transport.config_u32(0);
        let high = transport.config_u32(4);
        let mut mac = [0u8; 6];
        mac[0..4].copy_from_slice(&low.to_le_bytes());
        mac[4..6].copy_from_slice(&high.to_le_bytes()[0..2]);
        Ok(Net {
            transport,
            rx_size,
            tx_size,
            mac,
            reports_link: offered & NET_F_STATUS != 0,
        })
    }

    /// The device's MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Whether this device reports link state — i.e. whether
    /// [`link_up`](Self::link_up) is reading the device or answering from the
    /// spec's default.
    ///
    /// A driver needs the difference to say honestly which of its class
    /// features it has: reporting link events off a field that does not exist
    /// is worse than not reporting them.
    pub fn reports_link(&self) -> bool {
        self.reports_link
    }

    /// Whether the link is up.
    ///
    /// The status field shares the 32-bit config word with the MAC's last two
    /// bytes — offset 6 in a structure whose second word starts at 4 — so this
    /// is the same read `init` makes for the MAC, taken from the other half.
    /// A device that never offered `VIRTIO_NET_F_STATUS` has no such field,
    /// and its link is up by definition.
    pub fn link_up(&self) -> bool {
        if !self.reports_link {
            return true;
        }
        let status = (self.transport.config_u32(4) >> 16) as u16;
        status & NET_S_LINK_UP != 0
    }

    /// Acknowledges a used-buffer interrupt.
    pub fn ack_interrupt(&self) {
        self.transport.ack_interrupt();
    }

    /// Takes the device out of service: back to reset, queues gone, nothing
    /// moving. What a driver does to bring its own link down, and the state
    /// [`init`](Self::init) starts from — so coming back up is the full
    /// handshake and not a resumption.
    pub fn shutdown(&self) {
        self.transport.reset();
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

    /// Posts a receive buffer as **two chained descriptors**: the transport's
    /// header into `hdr_phys`, and the frame itself into `buf_phys` starting at
    /// its first byte.
    ///
    /// The reason to split what [`post_rx`](Self::post_rx) keeps together is
    /// ownership. A driver that hands a received frame to a client wants to
    /// hand over *the frame*, and with one descriptor the client's buffer
    /// begins with twelve bytes of virtio — so either the driver copies, or
    /// the class contract grows a transport detail every client has to know.
    /// Splitting the chain puts the header in memory the driver keeps and the
    /// frame in memory it gives away.
    ///
    /// The used ring still reports the total the device wrote, header
    /// included; the frame is that minus [`NET_HDR_LEN`].
    pub fn post_rx_split(
        &self,
        desc: &mut [u8],
        avail: &mut [u8],
        hdr_phys: u64,
        buf_phys: u64,
        buf_len: u32,
        idx: u16,
    ) {
        write_desc(
            desc,
            0,
            hdr_phys,
            NET_HDR_LEN as u32,
            DESC_F_NEXT | DESC_F_WRITE,
            1,
        );
        write_desc(desc, 1, buf_phys, buf_len, DESC_F_WRITE, 0);
        let slot = (idx as usize) % (self.rx_size as usize);
        put_u16(avail, 4 + slot * 2, 0);
        put_u16(avail, 2, idx.wrapping_add(1));
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
        self.transport.notify(0);
    }

    /// Rings the transmit doorbell (queue 1).
    pub fn notify_tx(&self) {
        self.transport.notify(1);
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
fn mmio_probe<M: Mmio>(mmio: &M, device_id: u32, wrong: Error) -> Result<(), Error> {
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
fn mmio_reset<M: Mmio>(mmio: &M) {
    mmio.write(reg::STATUS, 0);
}

fn mmio_begin<M: Mmio>(mmio: &M) {
    mmio_reset(mmio);
    mmio.write(reg::STATUS, status::ACKNOWLEDGE);
    mmio.write(reg::STATUS, status::ACKNOWLEDGE | status::DRIVER);
}

/// The device's offered low-word (selector 0) feature bits.
fn mmio_device_features_low<M: Mmio>(mmio: &M) -> u32 {
    mmio.write(reg::DEVICE_FEATURES_SEL, 0);
    mmio.read(reg::DEVICE_FEATURES)
}

/// Requires the device to offer `VIRTIO_F_VERSION_1`, then writes the driver's
/// accepted features — `features_high` (which must include `VERSION_1`) in the
/// high word, `features_low` in the low word.
fn mmio_negotiate<M: Mmio>(mmio: &M, features_low: u32, features_high: u32) -> Result<(), Error> {
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
fn mmio_set_features_ok<M: Mmio>(mmio: &M) -> Result<u32, Error> {
    let state = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK;
    mmio.write(reg::STATUS, state);
    if mmio.read(reg::STATUS) & status::FEATURES_OK == 0 {
        mmio.write(reg::STATUS, state | status::FAILED);
        return Err(Error::FeaturesRejected);
    }
    Ok(state)
}

/// Marks the driver ready and checks the device did not set `FAILED`.
fn mmio_driver_ok<M: Mmio>(mmio: &M, state: u32) -> Result<(), Error> {
    let state = state | status::DRIVER_OK;
    mmio.write(reg::STATUS, state);
    if mmio.read(reg::STATUS) & status::FAILED != 0 {
        return Err(Error::DeviceFailed);
    }
    Ok(())
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
fn mmio_configure_queue<M: Mmio>(
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

/// Encodes a virtio-blk write-request header for `sector`.
///
/// Identical to [`blk_read_header`] but for the type word, which is the only
/// thing that tells the device which way the data is going. Written as its own
/// function rather than a parameter so that a caller cannot pass the wrong
/// direction by passing the wrong integer.
pub fn blk_write_header(sector: u64) -> [u8; BLK_HEADER_LEN] {
    let mut header = [0u8; BLK_HEADER_LEN];
    header[0..4].copy_from_slice(&BLK_T_OUT.to_le_bytes());
    header[8..16].copy_from_slice(&sector.to_le_bytes());
    header
}

/// Encodes a virtio-blk flush header.
///
/// The sector field is unused by a flush and is written as zero rather than
/// left as whatever the caller's buffer held: the device is entitled to read
/// the whole header, and a stale sector number in it is a value nobody
/// intended.
pub fn blk_flush_header() -> [u8; BLK_HEADER_LEN] {
    let mut header = [0u8; BLK_HEADER_LEN];
    header[0..4].copy_from_slice(&BLK_T_FLUSH.to_le_bytes());
    header
}

/// Forms a block read's three-descriptor chain at head 0 — header, data,
/// status — **without touching the available ring**.
///
/// The split matters when the two halves belong to different processes. Forming
/// a chain names buffers by their device-visible addresses, which is knowledge
/// about the machine that only whoever allocated them has; *publishing* it is
/// the available-ring index and the doorbell, and needs no address at all. A
/// controller can therefore form a chain for a child that could not have formed
/// it, and the child still decides when it becomes a request
/// (`docs/drivers/01`, "Bus Topology And Data Paths").
pub fn write_read_chain(desc: &mut [u8], header_phys: u64, data_phys: u64, status_phys: u64) {
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
