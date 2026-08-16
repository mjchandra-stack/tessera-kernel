// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Flattened Device Tree reader: the discovery front end for platforms that
//! describe themselves with a device tree rather than ACPI tables.
//!
//! This is deliberately **not** an AArch64 crate.
//! docs/hardware/02-hardware-description-and-discovery.md accepts Device
//! Tree "for embedded, Arm, RISC-V, and development-board platforms", so the
//! reader is shared vocabulary that the AArch64 boot glue consumes today and
//! a RISC-V port consumes unchanged later. It normalizes into
//! `tessera-karch` boot types, exactly as the x86-64 glue's Limine module
//! normalizes its own protocol, so the kernel core never sees a device tree.
//!
//! Scope is the boot-time memory map — the RAM banks, the firmware
//! reservation block, and `/reserved-memory`. The full normalized resource
//! graph, schema-validated bindings and driver binding
//! (docs/hardware/02, "Binding Process") belong to the device manager in
//! user space and are not this crate's business.
//!
//! **This parses untrusted external input.** Every read is bounds-checked
//! against the blob, every structural assumption returns an error instead of
//! assuming, and the crate forbids `unsafe` outright: the caller hands in a
//! `&[u8]` it has already established is readable, so nothing here needs to
//! dereference a raw pointer. Malformed input is a normal result.
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md
//! ("Device Tree"), docs/hardware/01-platform-and-cpu-support.md ("Platform
//! Support Package")
//! Budget: none (boot path)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use tessera_karch::{MemoryKind, MemoryRegion, PhysAddr};

/// Bytes of header that must be readable before the blob's real length is
/// known. A caller reads exactly this much, asks [`total_size`] how long the
/// blob is, and only then forms the full slice.
pub const HEADER_LEN: usize = 40;

const MAGIC: u32 = 0xd00d_feed;

/// Highest structure version whose layout this reader implements. A blob is
/// accepted when its `last_comp_version` is at most this, which is the
/// compatibility rule the specification defines.
const SUPPORTED_VERSION: u32 = 17;

// Header field offsets.
const OFF_MAGIC: usize = 0;
const OFF_TOTALSIZE: usize = 4;
const OFF_DT_STRUCT: usize = 8;
const OFF_DT_STRINGS: usize = 12;
const OFF_MEM_RSVMAP: usize = 16;
const OFF_LAST_COMP_VERSION: usize = 24;
const OFF_SIZE_DT_STRINGS: usize = 32;
const OFF_SIZE_DT_STRUCT: usize = 36;

// Structure block tokens.
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// Deepest node nesting the reader will follow. Real trees are a handful of
/// levels; a blob claiming more is malformed or hostile, and bounding the
/// depth is what lets the walk carry per-level state without an allocator.
const MAX_DEPTH: usize = 24;

/// Address/size cell counts default to these when a parent does not say,
/// per the specification.
const DEFAULT_ADDRESS_CELLS: u32 = 2;
const DEFAULT_SIZE_CELLS: u32 = 1;

/// Why a device tree could not be read. Stable numeric values; append new
/// variants, never renumber existing ones.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum FdtError {
    /// The blob does not begin with the device-tree magic.
    BadMagic = 1,
    /// The blob's structure version is newer than this reader implements.
    UnsupportedVersion = 2,
    /// A field, string, or block extends past the end of the blob.
    Truncated = 3,
    /// The structure block violates the format: an unknown token, an
    /// unterminated string, a mismatched node end, or nesting past
    /// [`MAX_DEPTH`].
    Malformed = 4,
    /// A `reg` entry uses more address or size cells than fit in 64 bits.
    UnsupportedCellCount = 5,
    /// The caller's output slice cannot hold every region found. Never
    /// truncated silently (docs/lifecycle/04, "No Silent Fallback").
    TooManyRegions = 6,
}

/// Reads the blob's total length from its first [`HEADER_LEN`] bytes, so a
/// caller can bound the mapping before reading the rest.
pub fn total_size(header: &[u8]) -> Result<usize, FdtError> {
    if be_u32(header, OFF_MAGIC)? != MAGIC {
        return Err(FdtError::BadMagic);
    }
    let size = be_u32(header, OFF_TOTALSIZE)? as usize;
    if size < HEADER_LEN {
        return Err(FdtError::Truncated);
    }
    Ok(size)
}

/// A validated device tree blob.
pub struct DeviceTree<'a> {
    blob: &'a [u8],
    structure: &'a [u8],
    strings: &'a [u8],
    reservations: &'a [u8],
}

impl<'a> DeviceTree<'a> {
    /// Validates `blob`'s header and locates its blocks. Every later
    /// operation reads only inside the slices resolved here.
    pub fn parse(blob: &'a [u8]) -> Result<Self, FdtError> {
        let total = total_size(blob)?;
        if blob.len() < total {
            return Err(FdtError::Truncated);
        }
        // Trailing bytes are not this reader's to interpret; the header's
        // own length is authoritative.
        let blob = &blob[..total];

        if be_u32(blob, OFF_LAST_COMP_VERSION)? > SUPPORTED_VERSION {
            return Err(FdtError::UnsupportedVersion);
        }

        let structure = block(blob, OFF_DT_STRUCT, OFF_SIZE_DT_STRUCT)?;
        let strings = block(blob, OFF_DT_STRINGS, OFF_SIZE_DT_STRINGS)?;

        // The reservation block has no length field: it runs to a
        // terminating all-zero entry, which `reserved_regions` finds.
        let reservations_at = be_u32(blob, OFF_MEM_RSVMAP)? as usize;
        let reservations = blob.get(reservations_at..).ok_or(FdtError::Truncated)?;

        Ok(Self {
            blob,
            structure,
            strings,
            reservations,
        })
    }

    /// Total length of the blob, so the caller can reserve the memory it
    /// occupies.
    pub fn len(&self) -> usize {
        self.blob.len()
    }

    /// A device tree is never empty; provided because `len` alone trips the
    /// usual lint.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Appends the firmware's memory reservation entries to `out` as
    /// [`MemoryKind::Reserved`], returning how many were written.
    ///
    /// These are ranges the firmware requires the OS to leave alone. They
    /// live in their own block rather than in the tree, and they routinely
    /// overlap the RAM banks — resolving that overlap is
    /// [`tessera_karch::normalize_memory_map`]'s job, not this reader's.
    pub fn reserved_regions(&self, out: &mut [MemoryRegion]) -> Result<usize, FdtError> {
        let mut filled = 0usize;
        let mut at = 0usize;
        loop {
            let base = be_u64(self.reservations, at)?;
            let len = be_u64(self.reservations, at + 8)?;
            at += 16;
            if base == 0 && len == 0 {
                return Ok(filled); // terminator
            }
            push(out, &mut filled, base, len, MemoryKind::Reserved)?;
        }
    }

    /// Appends every RAM bank the tree describes to `out` as
    /// [`MemoryKind::Usable`], and every `/reserved-memory` child as
    /// [`MemoryKind::Reserved`]. Returns how many were written.
    ///
    /// A bank is a node whose `device_type` is `"memory"`, and its extent is
    /// its `reg` property read with the *parent's* address and size cell
    /// counts. Properties may appear in any order within a node, so the
    /// `reg` bytes are held until the node closes and only then interpreted
    /// — by which time `device_type` has certainly been seen if it is there
    /// at all.
    pub fn memory_regions(&self, out: &mut [MemoryRegion]) -> Result<usize, FdtError> {
        let mut filled = 0usize;
        self.walk_nodes(|level, address_cells, size_cells, structure| {
            if let Some(kind) = level.contributes()
                && let Some(reg) = level.reg(structure)
            {
                read_reg(reg, address_cells, size_cells, out, &mut filled, kind)?;
            }
            Ok(())
        })?;
        Ok(filled)
    }

    /// Fills `out` with every `compatible = "virtio,mmio"` node's `reg`
    /// (base, size) window, returning how many were written.
    ///
    /// The `virt` machine lays out 32 such transport slots; each is a real
    /// device only if its `DeviceID` register is non-zero, which is the
    /// consumer's runtime check, not the tree's. This only reports where the
    /// transports live — where a driver looks — the same division of labour as
    /// [`memory_regions`], which reports RAM without deciding what uses it.
    pub fn virtio_mmio_regions(&self, out: &mut [MmioDevice]) -> Result<usize, FdtError> {
        let mut filled = 0usize;
        self.walk_nodes(|level, address_cells, size_cells, structure| {
            if level.is_virtio_mmio
                && let Some(reg) = level.reg(structure)
            {
                let interrupt = level.interrupt_line(structure);
                read_mmio_reg(reg, address_cells, size_cells, interrupt, out, &mut filled)?;
            }
            Ok(())
        })?;
        Ok(filled)
    }

    /// **Every** MMIO device whose `compatible` list names `compatible`.
    ///
    /// The many-device form of [`first_mmio_device`](Self::first_mmio_device),
    /// which [`virtio_mmio_regions`](Self::virtio_mmio_regions) has been a
    /// hand-written special case of. A bus controller enumerating a machine
    /// needs it: "the real-time clock" is a question with one answer and "the
    /// transports" is not, and a walker that could only ask the first would
    /// describe a fraction of the bus it just walked.
    ///
    /// Returns how many were written. **A device past the end of `out` is
    /// dropped and the count says so** — the caller is told the number found
    /// rather than the number it could hold, so a buffer too small is
    /// something the caller can report rather than something that looks like a
    /// smaller machine.
    pub fn mmio_devices(
        &self,
        compatible: &[u8],
        out: &mut [MmioDevice],
    ) -> Result<usize, FdtError> {
        let mut found = 0usize;
        self.walk_nodes(|level, address_cells, size_cells, structure| {
            let Some((at, len)) = level.compatible else {
                return Ok(());
            };
            let Some(value) = structure.get(at..at + len) else {
                return Ok(());
            };
            if !compatible_lists(value, compatible) {
                return Ok(());
            }
            if let Some(reg) = level.reg(structure) {
                let interrupt = level.interrupt_line(structure);
                let entries = mmio_reg_entries(reg, address_cells, size_cells)?;
                // **Counted either way, written only when there is room.** A
                // count clamped to the buffer would make a machine with more
                // devices than room indistinguishable from a smaller machine,
                // and the caller would have nothing to report.
                if found + entries <= out.len() {
                    let mut filled = found;
                    read_mmio_reg(reg, address_cells, size_cells, interrupt, out, &mut filled)?;
                    found = filled;
                } else {
                    found += entries;
                }
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// The first MMIO device whose `compatible` list names `compatible`.
    ///
    /// The generic form of [`virtio_mmio_regions`](Self::virtio_mmio_regions),
    /// for the devices a machine has exactly one of and this crate has no
    /// business knowing about — a real-time clock, say. It reports *where* the
    /// device is and which line it interrupts on; what the device is for is
    /// the caller's business, the same division of labour as
    /// [`memory_regions`](Self::memory_regions).
    pub fn first_mmio_device(&self, compatible: &[u8]) -> Result<Option<MmioDevice>, FdtError> {
        let mut found: Option<MmioDevice> = None;
        self.walk_nodes(|level, address_cells, size_cells, structure| {
            if found.is_some() {
                return Ok(());
            }
            let Some((at, len)) = level.compatible else {
                return Ok(());
            };
            let Some(value) = structure.get(at..at + len) else {
                return Ok(());
            };
            if !compatible_lists(value, compatible) {
                return Ok(());
            }
            if let Some(reg) = level.reg(structure) {
                let interrupt = level.interrupt_line(structure);
                let mut one = [MmioDevice {
                    base: 0,
                    size: 0,
                    intid: None,
                    trigger: None,
                }];
                let mut filled = 0usize;
                read_mmio_reg(
                    reg,
                    address_cells,
                    size_cells,
                    interrupt,
                    &mut one,
                    &mut filled,
                )?;
                if filled == 1 {
                    found = Some(one[0]);
                }
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// The PCI host bridge, if the machine has one: its ECAM window, the bus
    /// numbers that window covers, and the memory windows it forwards.
    ///
    /// Three properties, and each answers a question enumeration cannot ask
    /// the hardware. `reg` gives the ECAM window — config space is not
    /// self-describing, so without it there is nowhere to start. `bus-range`
    /// bounds the walk, and the first bus in it sits at offset 0 of the
    /// window rather than at `bus << 20`. `ranges` gives the address windows
    /// the bridge forwards, which is where BARs must be placed: the reference
    /// machines leave BARs unassigned and expect the OS to place them, so a
    /// walk that ignored `ranges` would have nowhere to put them
    /// (docs/hardware/02, "PCIe").
    ///
    /// Only the **32-bit non-prefetchable memory** window is reported. A
    /// `ranges` entry's first cell carries the space code in bits 25:24 (1 =
    /// I/O, 2 = 32-bit memory, 3 = 64-bit memory); I/O is a different
    /// transport and 64-bit windows are not needed until a device asks for
    /// one, so both are skipped rather than reported as something they are
    /// not.
    pub fn pci_host(&self) -> Result<Option<PciHost>, FdtError> {
        let mut found: Option<PciHost> = None;
        self.walk_nodes(|level, address_cells, size_cells, structure| {
            if found.is_some() || !level.is_pci_host {
                return Ok(());
            }
            let Some(reg) = level.reg(structure) else {
                return Ok(());
            };
            let mut window = [MmioDevice {
                base: 0,
                size: 0,
                intid: None,
                trigger: None,
            }];
            let mut filled = 0usize;
            read_mmio_reg(
                reg,
                address_cells,
                size_cells,
                None,
                &mut window,
                &mut filled,
            )?;
            if filled != 1 {
                return Ok(());
            }
            let (first_bus, last_bus) = match level
                .bus_range
                .and_then(|(at, len)| structure.get(at..at + len))
            {
                Some(value) if value.len() >= 8 => {
                    (be_u32(value, 0)? as u8, be_u32(value, 4)? as u8)
                }
                // A bridge that does not say defaults to the whole range its
                // ECAM window can express, which the walk then bounds anyway.
                _ => (0, 255),
            };
            let memory = level
                .ranges
                .and_then(|(at, len)| structure.get(at..at + len))
                .map(pci_memory_window)
                .transpose()?
                .flatten();
            found = Some(PciHost {
                ecam_base: window[0].base,
                ecam_len: window[0].size,
                first_bus,
                last_bus,
                memory,
            });
            Ok(())
        })?;
        Ok(found)
    }

    /// Streams the structure block once, invoking `on_leave` as each node
    /// closes with its `Level`, the address/size cell counts its `reg` is
    /// expressed in, and the structure block. The single walk both
    /// [`memory_regions`] and [`virtio_mmio_regions`] are expressed on, so the
    /// bounded node-stack traversal and its error handling live in one place.
    fn walk_nodes<F>(&self, mut on_leave: F) -> Result<(), FdtError>
    where
        F: FnMut(&Level, u32, u32, &[u8]) -> Result<(), FdtError>,
    {
        let mut walk = Walk::new();
        let mut at = 0usize;

        loop {
            let token = be_u32(self.structure, at)?;
            at += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let name = cstr(self.structure, at)?;
                    at = align4(at + name.len() + 1)?;
                    walk.enter(name)?;
                }
                FDT_END_NODE => {
                    let level = walk.leave()?;
                    let (address_cells, size_cells) = walk.cells();
                    on_leave(&level, address_cells, size_cells, self.structure)?;
                }
                FDT_PROP => {
                    let len = be_u32(self.structure, at)? as usize;
                    let name_at = be_u32(self.structure, at + 4)? as usize;
                    at += 8;
                    let value = self
                        .structure
                        .get(at..at.checked_add(len).ok_or(FdtError::Truncated)?)
                        .ok_or(FdtError::Truncated)?;
                    walk.property(cstr(self.strings, name_at)?, value, at, len)?;
                    at = align4(at + len)?;
                }
                FDT_NOP => {}
                FDT_END => return walk.finish(),
                _ => return Err(FdtError::Malformed),
            }
        }
    }
}

/// One memory-mapped device window from the device tree: the base and length
/// of its register block, and the line it interrupts on as its controller
/// numbers it (see [`Level::interrupt_line`]), so a driver host can be wired
/// to a device's real interrupt without any platform constant (D84).
///
/// Nothing about it was ever virtio-specific — the name it used to carry said
/// otherwise, and the RISC-V port needed the same three facts about a
/// real-time clock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MmioDevice {
    pub base: u64,
    pub size: u64,
    pub intid: Option<u32>,
    /// How that line signals, where the controller's binding encodes it.
    ///
    /// `None` means the binding does not say — a PLIC `interrupts` value is a
    /// bare source number and carries no trigger — and a consumer must then
    /// use whatever its controller defaults to. It is deliberately not
    /// defaulted to `Level` here: a device tree that does not describe the
    /// trigger and one that describes a level-triggered line are different
    /// facts, and folding them together is how a kernel ends up configuring an
    /// edge-triggered source as level and never seeing its interrupt.
    pub trigger: Option<IrqTrigger>,
}

/// How an interrupt line signals.
///
/// The distinction is not cosmetic on a GIC: a source the controller is
/// configured to treat as level-sensitive latches nothing from a pulse, so a
/// device that asserts and immediately deasserts — which is exactly what an
/// edge-triggered source does — is silently never delivered. There is no error
/// anywhere; the interrupt simply does not arrive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrqTrigger {
    /// Delivered on a transition; the source need not stay asserted.
    Edge,
    /// Delivered while asserted, and re-delivered until the device is
    /// acknowledged.
    Level,
}

/// One memory window a PCI host bridge forwards: where it is as the CPU sees
/// it, where it is as a device behind the bridge sees it, and how long. The
/// two addresses are usually equal on the reference machines and are kept
/// apart because nothing guarantees it — a BAR holds the *bus* address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PciWindow {
    pub cpu_base: u64,
    pub bus_base: u64,
    pub len: u64,
}

/// A PCI host bridge as the device tree describes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PciHost {
    /// The ECAM window: config space for every bus in `first_bus..=last_bus`.
    pub ecam_base: u64,
    pub ecam_len: u64,
    pub first_bus: u8,
    pub last_bus: u8,
    /// The 32-bit non-prefetchable memory window BARs are placed in, if the
    /// bridge forwards one.
    pub memory: Option<PciWindow>,
}

/// PCI address-space codes, in bits 25:24 of a `ranges` entry's first cell.
const PCI_SPACE_MEMORY_32: u32 = 0x02;
/// A `ranges` entry: 3 child cells (PCI address), 2 parent cells (CPU
/// address), 2 size cells — 7 cells of 4 bytes.
const PCI_RANGE_CELLS: usize = 7;

/// Finds the 32-bit non-prefetchable memory window in a `ranges` value.
///
/// The child address is three cells because a PCI address is: the first
/// carries flags (space code in 25:24, prefetchable in bit 30), the next two
/// are the 64-bit address. A malformed `ranges` — one whose length is not a
/// whole number of entries — is [`FdtError::Malformed`] rather than a
/// truncated read of the last partial entry.
fn pci_memory_window(ranges: &[u8]) -> Result<Option<PciWindow>, FdtError> {
    if !ranges.len().is_multiple_of(PCI_RANGE_CELLS * 4) {
        return Err(FdtError::Malformed);
    }
    for entry in ranges.chunks_exact(PCI_RANGE_CELLS * 4) {
        let flags = be_u32(entry, 0)?;
        let space = (flags >> 24) & 0x3;
        // Prefetchable memory (bit 30) is still memory, but this reader
        // reports one window and the non-prefetchable one is what a register
        // block belongs in.
        if space != PCI_SPACE_MEMORY_32 || (flags & (1 << 30)) != 0 {
            continue;
        }
        let bus_base = (u64::from(be_u32(entry, 4)?) << 32) | u64::from(be_u32(entry, 8)?);
        let cpu_base = (u64::from(be_u32(entry, 12)?) << 32) | u64::from(be_u32(entry, 16)?);
        let len = (u64::from(be_u32(entry, 20)?) << 32) | u64::from(be_u32(entry, 24)?);
        if len == 0 {
            continue;
        }
        return Ok(Some(PciWindow {
            cpu_base,
            bus_base,
            len,
        }));
    }
    Ok(None)
}

/// Per-node state gathered while its properties stream past.
#[derive(Clone, Copy)]
struct Level {
    /// `#address-cells`/`#size-cells` this node declares for its children.
    address_cells: u32,
    size_cells: u32,
    /// Set by `device_type = "memory"`.
    is_memory: bool,
    /// Set for the `/reserved-memory` node itself.
    is_reserved_memory_root: bool,
    /// Set for any node inside a `/reserved-memory` subtree.
    in_reserved_memory: bool,
    /// Set by `compatible` listing `"virtio,mmio"`.
    is_virtio_mmio: bool,
    /// Where this node's `compatible` value lives in the structure block, so a
    /// caller can match a string this crate does not know about.
    compatible: Option<(usize, usize)>,
    /// Where this node's `reg` value lives in the structure block.
    reg: Option<(usize, usize)>,
    /// Where this node's `interrupts` value lives in the structure block.
    interrupts: Option<(usize, usize)>,
    /// Set by `compatible` listing `"pci-host-ecam-generic"`.
    is_pci_host: bool,
    /// Where this node's `bus-range` value lives in the structure block.
    bus_range: Option<(usize, usize)>,
    /// Where this node's `ranges` value lives in the structure block — the
    /// windows the bridge forwards, which is where BARs are placed.
    ranges: Option<(usize, usize)>,
}

impl Level {
    const fn root() -> Self {
        Self {
            address_cells: DEFAULT_ADDRESS_CELLS,
            size_cells: DEFAULT_SIZE_CELLS,
            is_memory: false,
            is_reserved_memory_root: false,
            in_reserved_memory: false,
            is_virtio_mmio: false,
            is_pci_host: false,
            bus_range: None,
            ranges: None,
            compatible: None,
            reg: None,
            interrupts: None,
        }
    }

    /// What kind of region this node's `reg` describes, if any.
    const fn contributes(&self) -> Option<MemoryKind> {
        if self.is_memory {
            Some(MemoryKind::Usable)
        } else if self.in_reserved_memory && !self.is_reserved_memory_root {
            Some(MemoryKind::Reserved)
        } else {
            None
        }
    }

    fn reg<'a>(&self, structure: &'a [u8]) -> Option<&'a [u8]> {
        let (at, len) = self.reg?;
        structure.get(at..at + len)
    }

    /// This node's interrupt line, as the machine's interrupt controller
    /// numbers it.
    ///
    /// An `interrupts` value means whatever its controller's
    /// `#interrupt-cells` says, and the two machines this kernel targets
    /// disagree:
    ///
    /// * **One cell** — a RISC-V PLIC source number, which *is* the line.
    /// * **Three cells** — a GIC `<type number flags>` descriptor; type 0
    ///   (SPI) gives INTID = number + 32.
    ///
    /// They are told apart by the property's length, which is what the tree
    /// makes available without resolving `interrupt-parent` phandles to find
    /// the controller's declared `#interrupt-cells`. That resolution is the
    /// correct general answer and is not done here; the shapes of the two
    /// supported controllers do not collide, and a wrong reading cannot pass
    /// silently — a consumer that wires a device to the wrong line simply
    /// never sees its interrupt, which is what the ports' boot checks assert.
    ///
    /// Any other shape yields `None`; the consumer decides whether an absent
    /// interrupt is an error.
    fn interrupt_line(&self, structure: &[u8]) -> Option<(u32, Option<IrqTrigger>)> {
        const GIC_TYPE_SPI: u32 = 0;
        const SPI_INTID_BASE: u32 = 32;
        // The low nibble of a GIC descriptor's flags cell, from the generic
        // interrupt-controller binding: 1 rising edge, 2 falling edge, 4 high
        // level, 8 low level. A value naming both, or neither, is left
        // unclassified rather than guessed at.
        const SENSE_MASK: u32 = 0xf;
        const EDGE: u32 = 0b0011;
        const LEVEL: u32 = 0b1100;
        let (at, len) = self.interrupts?;
        if len == 4 {
            let cells = structure.get(at..at + 4)?;
            // A PLIC source number and nothing else — no trigger to report.
            return Some((
                u32::from_be_bytes([cells[0], cells[1], cells[2], cells[3]]),
                None,
            ));
        }
        if len < 12 {
            return None;
        }
        let cells = structure.get(at..at + 12)?;
        let kind = u32::from_be_bytes([cells[0], cells[1], cells[2], cells[3]]);
        if kind != GIC_TYPE_SPI {
            return None;
        }
        let number = u32::from_be_bytes([cells[4], cells[5], cells[6], cells[7]]);
        let flags = u32::from_be_bytes([cells[8], cells[9], cells[10], cells[11]]) & SENSE_MASK;
        let trigger = match (flags & EDGE != 0, flags & LEVEL != 0) {
            (true, false) => Some(IrqTrigger::Edge),
            (false, true) => Some(IrqTrigger::Level),
            // Both bits, or none: the tree is describing something this reader
            // does not understand, and reporting a trigger it invented would
            // be worse than reporting none.
            _ => None,
        };
        Some((SPI_INTID_BASE + number, trigger))
    }
}

/// Bounded, allocation-free node stack for the structure-block walk.
struct Walk {
    levels: [Level; MAX_DEPTH],
    depth: usize,
}

impl Walk {
    fn new() -> Self {
        Self {
            levels: [Level::root(); MAX_DEPTH],
            depth: 0,
        }
    }

    /// Cell counts in force for the node currently being closed — i.e. its
    /// parent's, which is what `reg` is expressed in.
    fn cells(&self) -> (u32, u32) {
        let parent = self.depth.checked_sub(1).map(|i| self.levels[i]);
        match parent {
            Some(level) => (level.address_cells, level.size_cells),
            None => (DEFAULT_ADDRESS_CELLS, DEFAULT_SIZE_CELLS),
        }
    }

    fn enter(&mut self, name: &[u8]) -> Result<(), FdtError> {
        if self.depth == MAX_DEPTH {
            return Err(FdtError::Malformed);
        }
        let parent = self.depth.checked_sub(1).map(|i| self.levels[i]);
        let mut level = Level::root();
        if let Some(parent) = parent {
            // Cell counts are inherited until a node overrides them.
            level.address_cells = parent.address_cells;
            level.size_cells = parent.size_cells;
            level.in_reserved_memory = parent.in_reserved_memory;
        }
        if name == b"reserved-memory" {
            level.is_reserved_memory_root = true;
            level.in_reserved_memory = true;
        }
        self.levels[self.depth] = level;
        self.depth += 1;
        Ok(())
    }

    fn leave(&mut self) -> Result<Level, FdtError> {
        self.depth = self.depth.checked_sub(1).ok_or(FdtError::Malformed)?;
        Ok(self.levels[self.depth])
    }

    fn property(
        &mut self,
        name: &[u8],
        value: &[u8],
        at: usize,
        len: usize,
    ) -> Result<(), FdtError> {
        let level = self
            .depth
            .checked_sub(1)
            .and_then(|i| self.levels.get_mut(i))
            .ok_or(FdtError::Malformed)?; // a property outside any node
        match name {
            b"#address-cells" => level.address_cells = be_u32(value, 0)?,
            b"#size-cells" => level.size_cells = be_u32(value, 0)?,
            b"device_type" => level.is_memory = value == b"memory\0",
            b"compatible" => {
                level.is_virtio_mmio = compatible_lists(value, b"virtio,mmio");
                level.is_pci_host = compatible_lists(value, b"pci-host-ecam-generic");
                level.compatible = Some((at, len));
            }
            b"reg" => level.reg = Some((at, len)),
            b"interrupts" => level.interrupts = Some((at, len)),
            b"bus-range" => level.bus_range = Some((at, len)),
            b"ranges" => level.ranges = Some((at, len)),
            _ => {}
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), FdtError> {
        if self.depth == 0 {
            Ok(())
        } else {
            Err(FdtError::Malformed) // FDT_END inside an unclosed node
        }
    }
}

/// Splits a `reg` value into (address, length) pairs and appends them.
fn read_reg(
    reg: &[u8],
    address_cells: u32,
    size_cells: u32,
    out: &mut [MemoryRegion],
    filled: &mut usize,
    kind: MemoryKind,
) -> Result<(), FdtError> {
    // One cell is 32 bits, so anything past two cells cannot be represented
    // in the 64-bit physical address these types use. Refusing is right:
    // silently keeping the low 64 bits would produce a plausible, wrong map.
    if address_cells == 0 || address_cells > 2 || size_cells == 0 || size_cells > 2 {
        return Err(FdtError::UnsupportedCellCount);
    }
    let stride = ((address_cells + size_cells) * 4) as usize;
    if !reg.len().is_multiple_of(stride) {
        return Err(FdtError::Malformed);
    }

    for entry in reg.chunks_exact(stride) {
        let base = read_cells(entry, 0, address_cells)?;
        let len = read_cells(entry, (address_cells * 4) as usize, size_cells)?;
        push(out, filled, base, len, kind)?;
    }
    Ok(())
}

/// How many devices one `reg` describes, and whether it is describable at all.
///
/// Split out of [`read_mmio_reg`] so a walk can count what it has no room to
/// write without either losing the malformed cases or pretending the node was
/// not there.
fn mmio_reg_entries(reg: &[u8], address_cells: u32, size_cells: u32) -> Result<usize, FdtError> {
    if address_cells == 0 || address_cells > 2 || size_cells == 0 || size_cells > 2 {
        return Err(FdtError::UnsupportedCellCount);
    }
    let stride = ((address_cells + size_cells) * 4) as usize;
    if !reg.len().is_multiple_of(stride) {
        return Err(FdtError::Malformed);
    }
    Ok(reg.len() / stride)
}

/// Splits a `reg` value into (base, size) windows and appends them, the
/// [`MmioDevice`] counterpart of [`read_reg`].
fn read_mmio_reg(
    reg: &[u8],
    address_cells: u32,
    size_cells: u32,
    interrupt: Option<(u32, Option<IrqTrigger>)>,
    out: &mut [MmioDevice],
    filled: &mut usize,
) -> Result<(), FdtError> {
    if address_cells == 0 || address_cells > 2 || size_cells == 0 || size_cells > 2 {
        return Err(FdtError::UnsupportedCellCount);
    }
    let stride = ((address_cells + size_cells) * 4) as usize;
    if !reg.len().is_multiple_of(stride) {
        return Err(FdtError::Malformed);
    }

    for entry in reg.chunks_exact(stride) {
        let base = read_cells(entry, 0, address_cells)?;
        let size = read_cells(entry, (address_cells * 4) as usize, size_cells)?;
        let slot = out.get_mut(*filled).ok_or(FdtError::TooManyRegions)?;
        *slot = MmioDevice {
            base,
            size,
            intid: interrupt.map(|(intid, _)| intid),
            trigger: interrupt.and_then(|(_, trigger)| trigger),
        };
        *filled += 1;
    }
    Ok(())
}

/// Whether a `compatible` property value — a list of NUL-terminated strings —
/// lists `target` as one of its entries.
fn compatible_lists(value: &[u8], target: &[u8]) -> bool {
    value.split(|&byte| byte == 0).any(|entry| entry == target)
}

fn read_cells(bytes: &[u8], at: usize, cells: u32) -> Result<u64, FdtError> {
    match cells {
        1 => Ok(u64::from(be_u32(bytes, at)?)),
        _ => be_u64(bytes, at),
    }
}

fn push(
    out: &mut [MemoryRegion],
    filled: &mut usize,
    base: u64,
    len: u64,
    kind: MemoryKind,
) -> Result<(), FdtError> {
    let slot = out.get_mut(*filled).ok_or(FdtError::TooManyRegions)?;
    *slot = MemoryRegion {
        base: PhysAddr::new(base),
        len,
        kind,
    };
    *filled += 1;
    Ok(())
}

/// Resolves one of the header's (offset, size) block descriptors.
fn block(blob: &[u8], offset_at: usize, size_at: usize) -> Result<&[u8], FdtError> {
    let start = be_u32(blob, offset_at)? as usize;
    let len = be_u32(blob, size_at)? as usize;
    let end = start.checked_add(len).ok_or(FdtError::Truncated)?;
    blob.get(start..end).ok_or(FdtError::Truncated)
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32, FdtError> {
    let end = at.checked_add(4).ok_or(FdtError::Truncated)?;
    let field = bytes.get(at..end).ok_or(FdtError::Truncated)?;
    let mut buffer = [0u8; 4];
    buffer.copy_from_slice(field);
    Ok(u32::from_be_bytes(buffer))
}

fn be_u64(bytes: &[u8], at: usize) -> Result<u64, FdtError> {
    let end = at.checked_add(8).ok_or(FdtError::Truncated)?;
    let field = bytes.get(at..end).ok_or(FdtError::Truncated)?;
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(field);
    Ok(u64::from_be_bytes(buffer))
}

/// The NUL-terminated string starting at `at`, without its terminator.
fn cstr(bytes: &[u8], at: usize) -> Result<&[u8], FdtError> {
    let tail = bytes.get(at..).ok_or(FdtError::Truncated)?;
    let len = tail
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(FdtError::Malformed)?;
    Ok(&tail[..len])
}

fn align4(value: usize) -> Result<usize, FdtError> {
    value
        .checked_add(3)
        .ok_or(FdtError::Truncated)
        .map(|v| v & !3)
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
