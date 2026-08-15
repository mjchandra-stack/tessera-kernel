// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The device resource graph: the kernel's normalized record of which physical
//! I/O resources back each `ObjectType::Device` capability. In v0 a node carries
//! a device's I/O port range and its interrupt line — the minimal
//! `docs/hardware/02-hardware-description-and-discovery.md` "Normalized Resource
//! Graph" (a Device node with a memory/port region and an interrupt route).
//!
//! This closes the ObjectTable-payload deferral for devices (D42/D45/D46): the
//! object table stays a pure typed-refcount registry, and a Device object's
//! authority-scoping payload — its `(base, len)` range — lives here, keyed by the
//! object id and reached by a linear-scan bridge, exactly as `PortTable` and
//! `ChannelTable` key their state to an object id. A ring-3 `DeviceIo` syscall
//! resolves the caller's handle to an `ObjectId`, then reads+enforces the range
//! from this table — no compile-time device constant on the generic path.
//!
//! The device manager (a ring-3 service) brokers *binding* — granting a Device
//! capability to a driver host — on top of these nodes; discovery sources
//! (ACPI/DT/PCI) and the fuller graph (buses, clocks, power domains, DMA
//! apertures) are deferred (build/README.md, D47).
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md
//! ("Normalized Resource Graph"), docs/hardware/01-platform-and-cpu-support.md
//! Budget: none (capability resolution; register access is the driver's path)

use crate::object::ObjectId;
use tessera_karch::KError;

/// Device nodes the resource graph holds.
pub const MAX_DEVICES: usize = 8;

/// One resource-graph device node: the object it backs, its I/O port range
/// (`base`, `len` registers), and its interrupt line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DeviceNode {
    object: ObjectId,
    base: u16,
    len: u16,
    /// The device's interrupt line (recorded for the node; the IRQ→port bridge
    /// is still a kernel constant in v0 — D47).
    irq: u8,
    /// The device's memory-mapped register window `(phys_base, len)`, for devices
    /// reached by MMIO rather than I/O ports (D77). `None` for a port-only node.
    /// A `MapDevice` syscall reads this to map the window into a ring-3 driver's
    /// address space; the physical base is the capability's authority, never the
    /// caller's to choose.
    mmio: Option<(u64, u64)>,
    /// The MMIO device's interrupt-controller INTID (e.g. a GIC SPI's, parsed
    /// from the device tree), for wiring the IRQ→port bridge and gating a
    /// ring-3 `IrqComplete` (D84). `None` for port-I/O nodes (whose narrow
    /// `irq` line field predates this) and for MMIO devices with no interrupt
    /// wired.
    intid: Option<u32>,
}

/// A fixed pool of device nodes — the normalized resource graph.
pub struct DeviceTable {
    nodes: [Option<DeviceNode>; MAX_DEVICES],
}

impl DeviceTable {
    pub const fn new() -> Self {
        Self {
            nodes: [const { None }; MAX_DEVICES],
        }
    }

    /// Registers a device node backing `object` with the I/O range `[base,
    /// base+len)` and interrupt line `irq`, or [`KError::OutOfMemory`] if the
    /// graph is full. The manager/boot populates the graph before granting.
    pub fn register(
        &mut self,
        object: ObjectId,
        base: u16,
        len: u16,
        irq: u8,
    ) -> Result<(), KError> {
        let slot = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.nodes[slot] = Some(DeviceNode {
            object,
            base,
            len,
            irq,
            mmio: None,
            intid: None,
        });
        Ok(())
    }

    /// Registers a device node backing `object` with the MMIO register window
    /// `[base, base+len)` (physical), or [`KError::OutOfMemory`] if the graph is
    /// full. The port fields are left empty — this is an MMIO-only node, the shape
    /// a memory-mapped device (e.g. virtio-mmio) grants to a ring-3 driver (D77).
    pub fn register_mmio(&mut self, object: ObjectId, base: u64, len: u64) -> Result<(), KError> {
        let slot = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.nodes[slot] = Some(DeviceNode {
            object,
            base: 0,
            len: 0,
            irq: 0,
            mmio: Some((base, len)),
            intid: None,
        });
        Ok(())
    }

    /// Records the interrupt-controller INTID of an already-registered MMIO
    /// device (the IRQ half of its resource-graph payload, D84).
    pub fn set_mmio_irq(&mut self, object: ObjectId, intid: u32) -> Result<(), KError> {
        for node in self.nodes.iter_mut().flatten() {
            if node.object == object {
                node.intid = Some(intid);
                return Ok(());
            }
        }
        Err(KError::BadHandle)
    }

    /// Resolves a Device object id to its interrupt INTID, if one is wired —
    /// the gate a ring-3 `IrqComplete` resolves through.
    /// Every object this graph backs, so a caller can ask "is this handle a
    /// device?" without knowing how the graph is stored. Returns how many were
    /// written; `out` shorter than the graph truncates, which is why callers
    /// size it at [`MAX_DEVICES`].
    pub fn objects(&self, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for node in self.nodes.iter().flatten() {
            if n == out.len() {
                break;
            }
            out[n] = node.object;
            n += 1;
        }
        n
    }

    pub fn intid_of_object(&self, id: ObjectId) -> Option<u32> {
        for node in self.nodes.iter().flatten() {
            if node.object == id {
                return node.intid;
            }
        }
        None
    }

    /// Resolves an object id to its device node's I/O range — the handle→range
    /// bridge a `DeviceIo` syscall uses after looking the handle up in the
    /// caller's table (a linear scan, the `ProcessTable::process_of_id` pattern).
    pub fn device_of_object(&self, id: ObjectId) -> Option<(u16, u16)> {
        for node in self.nodes.iter().flatten() {
            if node.object == id {
                return Some((node.base, node.len));
            }
        }
        None
    }

    /// Resolves a Device object id to its MMIO register window `(phys_base, len)` —
    /// the handle→window bridge a `MapDevice` syscall uses to map the granted
    /// window into a ring-3 driver's address space. `None` for a port-only node.
    pub fn mmio_of_object(&self, id: ObjectId) -> Option<(u64, u64)> {
        for node in self.nodes.iter().flatten() {
            if node.object == id {
                return node.mmio;
            }
        }
        None
    }

    /// The interrupt line recorded for the device backing `object`, if any.
    pub fn irq_of_object(&self, id: ObjectId) -> Option<u8> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .map(|node| node.irq)
    }
}

impl Default for DeviceTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_and_resolves_independent_nodes() {
        let mut table = DeviceTable::new();
        let com2 = ObjectId::from_raw(0x11);
        let other = ObjectId::from_raw(0x22);
        table.register(com2, 0x2f8, 8, 3).unwrap();
        table.register(other, 0x3e8, 4, 5).unwrap();
        // The graph holds N nodes, each resolving independently.
        assert_eq!(table.device_of_object(com2), Some((0x2f8, 8)));
        assert_eq!(table.device_of_object(other), Some((0x3e8, 4)));
        assert_eq!(table.irq_of_object(com2), Some(3));
        assert_eq!(table.irq_of_object(other), Some(5));
    }

    #[test]
    fn unregistered_object_resolves_to_none() {
        let mut table = DeviceTable::new();
        table
            .register(ObjectId::from_raw(0x11), 0x2f8, 8, 3)
            .unwrap();
        assert_eq!(table.device_of_object(ObjectId::from_raw(0x99)), None);
        assert_eq!(table.irq_of_object(ObjectId::from_raw(0x99)), None);
    }

    #[test]
    fn registers_and_resolves_an_mmio_window() {
        let mut table = DeviceTable::new();
        let virtio = ObjectId::from_raw(0x33);
        table.register_mmio(virtio, 0x0a00_0000, 0x200).unwrap();
        // The MMIO window resolves; the object carries no I/O-port range.
        assert_eq!(table.mmio_of_object(virtio), Some((0x0a00_0000, 0x200)));
        assert_eq!(table.device_of_object(virtio), Some((0, 0)));
    }

    #[test]
    fn records_and_resolves_an_mmio_intid() {
        let mut devices = DeviceTable::new();
        let id = ObjectId::from_raw(9);
        devices.register_mmio(id, 0x0a00_3e00, 0x200).expect("mmio");
        assert_eq!(devices.intid_of_object(id), None);
        devices.set_mmio_irq(id, 79).expect("set irq");
        assert_eq!(devices.intid_of_object(id), Some(79));
        // An unknown object neither sets nor resolves.
        assert!(devices.set_mmio_irq(ObjectId::from_raw(99), 50).is_err());
        assert_eq!(devices.intid_of_object(ObjectId::from_raw(99)), None);
    }

    #[test]
    fn a_port_node_has_no_mmio_window() {
        let mut table = DeviceTable::new();
        let com2 = ObjectId::from_raw(0x11);
        table.register(com2, 0x2f8, 8, 3).unwrap();
        // A port-only node resolves its ports but reports no MMIO window.
        assert_eq!(table.device_of_object(com2), Some((0x2f8, 8)));
        assert_eq!(table.mmio_of_object(com2), None);
        // An unregistered object has neither.
        assert_eq!(table.mmio_of_object(ObjectId::from_raw(0x99)), None);
    }

    #[test]
    fn a_full_graph_rejects_further_registration() {
        let mut table = DeviceTable::new();
        for i in 0..MAX_DEVICES {
            table
                .register(ObjectId::from_raw(i as u32 + 1), 0x100 + i as u16, 1, 0)
                .unwrap();
        }
        assert_eq!(
            table.register(ObjectId::from_raw(0xfff), 0x200, 1, 0),
            Err(KError::OutOfMemory)
        );
    }
}
