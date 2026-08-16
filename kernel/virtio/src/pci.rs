// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The virtio-pci transport: the same bring-up as virtio-mmio, against a device
//! that keeps its controls somewhere else entirely.
//!
//! A virtio-mmio device is one register block at a base the firmware names, and
//! every control in it is a 32-bit register at a fixed offset. A virtio-pci
//! device has **no such block**. Its controls live in up to five structures,
//! each described by a vendor-specific PCI capability that says which BAR the
//! structure is in and at what offset — so finding them is a walk of config
//! space, and reaching them is a different region per structure.
//!
//! Two consequences shape everything here. The **common configuration**
//! structure is a packed record of mixed widths, not an array of registers:
//! `device_status` is one byte at +0x14, and `queue_select`, `queue_size` and
//! `queue_enable` are 16-bit fields packed three to a pair of words. And the
//! **doorbell is not a register** — it is an address computed per queue from
//! the notify structure's base, the queue's own `queue_notify_off`, and a
//! multiplier the device reports.
//!
//! This module is `unsafe`-free like the rest of the crate: it reaches devices
//! only through [`Regs`], and the caller supplies one per structure.
//!
//! Normative: Virtual I/O Device (VIRTIO) Version 1.x, "Virtio Over PCI Bus"

use crate::{Error, FEATURE_VERSION_1_BIT, Transport, status};

/// Byte-addressed access to one device region, at natural widths.
///
/// **Natural widths are not a convenience.** The common configuration
/// structure packs fields of different sizes into adjacent bytes, so writing
/// `device_status` (one byte at +0x14) with a 32-bit access would also rewrite
/// `config_generation` at +0x15 and `queue_select` at +0x16 — the first of
/// which is read-only and the second of which decides which queue every
/// following access means. An implementation must issue accesses of exactly
/// the width asked for.
pub trait Regs {
    fn read8(&self, offset: usize) -> u8;
    fn read16(&self, offset: usize) -> u16;
    fn read32(&self, offset: usize) -> u32;
    fn write8(&self, offset: usize, value: u8);
    fn write16(&self, offset: usize, value: u16);
    fn write32(&self, offset: usize, value: u32);
}

/// Field offsets in the virtio-pci common configuration structure.
pub mod common {
    pub const DEVICE_FEATURE_SELECT: usize = 0x00; // u32
    pub const DEVICE_FEATURE: usize = 0x04; // u32
    pub const DRIVER_FEATURE_SELECT: usize = 0x08; // u32
    pub const DRIVER_FEATURE: usize = 0x0c; // u32
    pub const CONFIG_MSIX_VECTOR: usize = 0x10; // u16
    pub const NUM_QUEUES: usize = 0x12; // u16
    pub const DEVICE_STATUS: usize = 0x14; // u8
    pub const CONFIG_GENERATION: usize = 0x15; // u8
    pub const QUEUE_SELECT: usize = 0x16; // u16
    pub const QUEUE_SIZE: usize = 0x18; // u16
    pub const QUEUE_MSIX_VECTOR: usize = 0x1a; // u16
    pub const QUEUE_ENABLE: usize = 0x1c; // u16
    pub const QUEUE_NOTIFY_OFF: usize = 0x1e; // u16
    pub const QUEUE_DESC: usize = 0x20; // u64
    pub const QUEUE_DRIVER: usize = 0x28; // u64
    pub const QUEUE_DEVICE: usize = 0x30; // u64
}

/// `cfg_type` values naming what a vendor capability describes.
pub mod cfg_type {
    pub const COMMON: u8 = 1;
    pub const NOTIFY: u8 = 2;
    pub const ISR: u8 = 3;
    pub const DEVICE: u8 = 4;
    pub const PCI: u8 = 5;
}

/// The PCI vendor id every virtio device carries.
pub const VENDOR_ID: u16 = 0x1af4;

/// The virtio device type a PCI device id names, or `None` if it is not a
/// virtio device id at all.
///
/// There are two encodings and a driver must read both. A **modern** device is
/// `0x1040 + type`, which is the arithmetic everyone remembers. A
/// **transitional** device — which is what QEMU presents by default, and what
/// this tree's `virtio-blk-pci` reports as `1af4:1001` — uses the legacy ids
/// from before that rule existed, where block is `0x1001` and network is
/// `0x1000`. Subtracting `0x1040` from a transitional id gives an enormous
/// number that matches nothing, so a driver that knows only the modern rule
/// decides a perfectly good disk is not a disk.
pub const fn device_type(pci_device_id: u16) -> Option<u32> {
    match pci_device_id {
        // Transitional: the legacy id space, which is not contiguous with the
        // modern one and is enumerated rather than computed.
        0x1000 => Some(1), // network
        0x1001 => Some(2), // block
        0x1040..=0x107f => Some((pci_device_id - 0x1040) as u32),
        _ => None,
    }
}

/// One decoded `virtio_pci_cap`: which structure it describes and where.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cap {
    /// Which structure this is — one of [`cfg_type`].
    pub cfg_type: u8,
    /// The BAR index the structure lives in.
    pub bar: u8,
    /// Its offset within that BAR.
    pub offset: u32,
    /// Its length in bytes.
    pub length: u32,
}

/// Decodes a `virtio_pci_cap` from the four config-space dwords at the
/// capability's offset.
///
/// Takes raw words rather than reading config space itself, so this crate needs
/// no dependency on the PCI crate and the decode stays host-testable — the same
/// split that put the SMMU's encodings in a crate a mock could check.
///
/// Layout: `cap_vndr` at +0, `cap_next` at +1, `cap_len` at +2, `cfg_type` at
/// +3, `bar` at +4, then `offset` and `length` as whole dwords at +8 and +12.
pub const fn decode_cap(words: [u32; 4]) -> Cap {
    Cap {
        cfg_type: ((words[0] >> 24) & 0xff) as u8,
        bar: (words[1] & 0xff) as u8,
        offset: words[2],
        length: words[3],
    }
}

/// The notify structure's multiplier, which follows the standard capability at
/// +16 and is present only on a `NOTIFY` capability.
pub const fn decode_notify_multiplier(word: u32) -> u32 {
    word
}

/// A virtio device reached over PCI.
///
/// Borrows one accessor per structure. `isr` is optional because a driver that
/// takes completions by MSI-X never reads it, and the ISR structure is the
/// legacy-interrupt path; a driver that polls needs neither.
pub struct PciTransport<'r, R: Regs> {
    common: &'r R,
    notify: &'r R,
    /// Multiplied by a queue's `queue_notify_off` to find its doorbell.
    notify_multiplier: u32,
    isr: Option<&'r R>,
    /// The device id from PCI config space. virtio-pci has no `DeviceID`
    /// register: what a device *is* is a fact about the function, read during
    /// enumeration, and passed in here.
    device_id: u32,
    /// Where the device-specific configuration structure is, if the device has
    /// one — the virtio-net MAC lives there.
    device_cfg: Option<&'r R>,
}

impl<'r, R: Regs> PciTransport<'r, R> {
    /// Builds a transport over the structures a driver found through the
    /// device's vendor capabilities.
    pub fn new(
        common: &'r R,
        notify: &'r R,
        notify_multiplier: u32,
        isr: Option<&'r R>,
        device_cfg: Option<&'r R>,
        device_id: u32,
    ) -> Self {
        Self {
            common,
            notify,
            notify_multiplier,
            isr,
            device_id,
            device_cfg,
        }
    }

    /// Writes a 64-bit field as two 32-bit halves, low first.
    ///
    /// The specification permits this explicitly, and it keeps [`Regs`] free of
    /// a 64-bit accessor that some buses cannot issue anyway.
    fn write64(&self, offset: usize, value: u64) {
        self.common.write32(offset, value as u32);
        self.common.write32(offset + 4, (value >> 32) as u32);
    }

    /// The doorbell offset for `queue` within the notify structure, exposed so
    /// a caller can see **whether two queues have distinct doorbells**.
    ///
    /// That is not a curiosity: page granularity is the unit of granting, so
    /// two queues sharing a page cannot be handed to different processes
    /// however separate their rings are. A multiplier large enough to give each
    /// queue its own page is what makes a queue a thing that can be delegated,
    /// and a caller intending to delegate one has to be able to check rather
    /// than assume.
    pub fn notify_offset_of(&self, queue: u16) -> usize {
        self.notify_offset(queue)
    }

    /// The doorbell address for `queue`, within the notify structure.
    fn notify_offset(&self, queue: u16) -> usize {
        self.common.write16(common::QUEUE_SELECT, queue);
        let off = self.common.read16(common::QUEUE_NOTIFY_OFF);
        // A multiplier of zero is legal and means every queue shares one
        // address — so this must be a multiply, never an assumption that
        // distinct queues have distinct doorbells.
        (u32::from(off) * self.notify_multiplier) as usize
    }
}

impl<R: Regs> Transport for PciTransport<'_, R> {
    fn probe(&self, device_id: u32, wrong: Error) -> Result<(), Error> {
        // There is nothing to check for presence or version: a virtio-pci
        // device is one the *bus* enumerated, and finding a common
        // configuration structure at all is what "present" means here. The
        // modern/legacy question is settled by VERSION_1 in `negotiate`, not by
        // a version register — there isn't one.
        if self.device_id != device_id {
            return Err(wrong);
        }
        Ok(())
    }

    fn begin(&self) {
        self.common.write8(common::DEVICE_STATUS, 0);
        // The reset is not complete until the device says so by reading back
        // zero. virtio-mmio has the same rule and gets away without it because
        // its reset is a posted write to a device that answers immediately.
        while self.common.read8(common::DEVICE_STATUS) != 0 {
            core::hint::spin_loop();
        }
        self.common
            .write8(common::DEVICE_STATUS, status::ACKNOWLEDGE as u8);
        self.common.write8(
            common::DEVICE_STATUS,
            (status::ACKNOWLEDGE | status::DRIVER) as u8,
        );
    }

    fn device_features_low(&self) -> u32 {
        self.common.write32(common::DEVICE_FEATURE_SELECT, 0);
        self.common.read32(common::DEVICE_FEATURE)
    }

    fn negotiate(&self, features_low: u32, features_high: u32) -> Result<(), Error> {
        self.common.write32(common::DEVICE_FEATURE_SELECT, 1);
        if self.common.read32(common::DEVICE_FEATURE) & FEATURE_VERSION_1_BIT == 0 {
            return Err(Error::NoModernFeature);
        }
        self.common.write32(common::DRIVER_FEATURE_SELECT, 1);
        self.common.write32(common::DRIVER_FEATURE, features_high);
        self.common.write32(common::DRIVER_FEATURE_SELECT, 0);
        self.common.write32(common::DRIVER_FEATURE, features_low);
        Ok(())
    }

    fn set_features_ok(&self) -> Result<u32, Error> {
        let state = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK;
        self.common.write8(common::DEVICE_STATUS, state as u8);
        if u32::from(self.common.read8(common::DEVICE_STATUS)) & status::FEATURES_OK == 0 {
            self.common
                .write8(common::DEVICE_STATUS, (state | status::FAILED) as u8);
            return Err(Error::FeaturesRejected);
        }
        Ok(state)
    }

    fn driver_ok(&self, state: u32) -> Result<(), Error> {
        let state = state | status::DRIVER_OK;
        self.common.write8(common::DEVICE_STATUS, state as u8);
        if u32::from(self.common.read8(common::DEVICE_STATUS)) & status::FAILED != 0 {
            return Err(Error::DeviceFailed);
        }
        Ok(())
    }

    fn configure_queue(
        &self,
        index: u32,
        size: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> Result<u16, Error> {
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::QueueSize);
        }
        let Ok(index) = u16::try_from(index) else {
            return Err(Error::QueueSize);
        };
        self.common.write16(common::QUEUE_SELECT, index);
        // Unlike virtio-mmio there is no separate maximum register: the size
        // field reads back the device's maximum before the driver writes it.
        let max = self.common.read16(common::QUEUE_SIZE);
        if max == 0 || size > max {
            return Err(Error::QueueSize);
        }
        self.common.write16(common::QUEUE_SIZE, size);
        self.write64(common::QUEUE_DESC, desc_phys);
        self.write64(common::QUEUE_DRIVER, avail_phys);
        self.write64(common::QUEUE_DEVICE, used_phys);
        self.common.write16(common::QUEUE_ENABLE, 1);
        Ok(size)
    }

    fn notify(&self, queue: u16) {
        let at = self.notify_offset(queue);
        self.notify.write16(at, queue);
    }

    fn ack_interrupt(&self) {
        // The ISR status register is read-to-clear, so the read *is* the
        // acknowledgement and the value is discarded. A driver taking
        // completions by MSI-X has no ISR structure and nothing to do.
        if let Some(isr) = self.isr {
            let _ = isr.read8(0);
        }
    }

    fn config_u32(&self, offset: usize) -> u32 {
        match self.device_cfg {
            Some(cfg) => cfg.read32(offset),
            // A device with no device-specific configuration structure has no
            // such field; zero is what a driver reading an absent optional
            // field should see, and it cannot be mistaken for a MAC.
            None => 0,
        }
    }
}
