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
    pub fn virtio_mmio_regions(&self, out: &mut [VirtioMmioRegion]) -> Result<usize, FdtError> {
        let mut filled = 0usize;
        self.walk_nodes(|level, address_cells, size_cells, structure| {
            if level.is_virtio_mmio
                && let Some(reg) = level.reg(structure)
            {
                let intid = level.gic_spi_intid(structure);
                read_mmio_reg(reg, address_cells, size_cells, intid, out, &mut filled)?;
            }
            Ok(())
        })?;
        Ok(filled)
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

/// One `compatible = "virtio,mmio"` transport window from the device tree: the
/// base and length of its MMIO register block, and — when the node carries a
/// GIC SPI `interrupts` descriptor — the interrupt's GIC INTID (SPI number +
/// 32), so a driver host can be wired to the device's real interrupt line
/// without any platform constant (D84).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VirtioMmioRegion {
    pub base: u64,
    pub size: u64,
    pub intid: Option<u32>,
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
    /// Where this node's `reg` value lives in the structure block.
    reg: Option<(usize, usize)>,
    /// Where this node's `interrupts` value lives in the structure block.
    interrupts: Option<(usize, usize)>,
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

    /// The GIC INTID of this node's interrupt, when its `interrupts` value is
    /// a GIC three-cell `<type number flags>` descriptor with type 0 (SPI):
    /// INTID = SPI number + 32. Other types or shapes yield `None` — the
    /// consumer decides whether an absent interrupt is an error.
    fn gic_spi_intid(&self, structure: &[u8]) -> Option<u32> {
        const GIC_TYPE_SPI: u32 = 0;
        const SPI_INTID_BASE: u32 = 32;
        let (at, len) = self.interrupts?;
        if len < 12 {
            return None;
        }
        let cells = structure.get(at..at + 12)?;
        let kind = u32::from_be_bytes([cells[0], cells[1], cells[2], cells[3]]);
        if kind != GIC_TYPE_SPI {
            return None;
        }
        let number = u32::from_be_bytes([cells[4], cells[5], cells[6], cells[7]]);
        Some(SPI_INTID_BASE + number)
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
            b"compatible" => level.is_virtio_mmio = compatible_lists(value, b"virtio,mmio"),
            b"reg" => level.reg = Some((at, len)),
            b"interrupts" => level.interrupts = Some((at, len)),
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

/// Splits a `reg` value into (base, size) windows and appends them, the
/// [`VirtioMmioRegion`] counterpart of [`read_reg`].
fn read_mmio_reg(
    reg: &[u8],
    address_cells: u32,
    size_cells: u32,
    intid: Option<u32>,
    out: &mut [VirtioMmioRegion],
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
        *slot = VirtioMmioRegion { base, size, intid };
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
mod tests {
    use super::*;

    // Property name offsets into `STRINGS` below. New names append at the end
    // so existing offsets stay put.
    const NAME_ADDRESS_CELLS: u32 = 0;
    const NAME_SIZE_CELLS: u32 = 15;
    const NAME_DEVICE_TYPE: u32 = 27;
    const NAME_REG: u32 = 39;
    const NAME_COMPATIBLE: u32 = 43;
    const NAME_INTERRUPTS: u32 = 54;
    const STRINGS: &[u8] =
        b"#address-cells\0#size-cells\0device_type\0reg\0compatible\0interrupts\0";

    /// Minimal big-endian blob writer, so the fixtures are the real wire
    /// format rather than a mock of it.
    struct Writer {
        buffer: [u8; 1024],
        len: usize,
    }

    impl Writer {
        fn new() -> Self {
            Self {
                buffer: [0; 1024],
                len: 0,
            }
        }

        fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
            self.buffer[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            self
        }

        fn u32(&mut self, value: u32) -> &mut Self {
            self.bytes(&value.to_be_bytes())
        }

        fn u64(&mut self, value: u64) -> &mut Self {
            self.bytes(&value.to_be_bytes())
        }

        fn pad4(&mut self) -> &mut Self {
            while !self.len.is_multiple_of(4) {
                self.len += 1;
            }
            self
        }

        fn begin_node(&mut self, name: &[u8]) -> &mut Self {
            self.u32(FDT_BEGIN_NODE).bytes(name).bytes(b"\0").pad4()
        }

        fn end_node(&mut self) -> &mut Self {
            self.u32(FDT_END_NODE)
        }

        fn prop(&mut self, name_at: u32, value: &[u8]) -> &mut Self {
            self.u32(FDT_PROP)
                .u32(value.len() as u32)
                .u32(name_at)
                .bytes(value)
                .pad4()
        }

        fn prop_u32(&mut self, name_at: u32, value: u32) -> &mut Self {
            self.prop(name_at, &value.to_be_bytes())
        }

        fn reg(&mut self, base: u64, len: u64) -> &mut Self {
            let mut value = [0u8; 16];
            value[..8].copy_from_slice(&base.to_be_bytes());
            value[8..].copy_from_slice(&len.to_be_bytes());
            self.prop(NAME_REG, &value)
        }

        fn as_slice(&self) -> &[u8] {
            &self.buffer[..self.len]
        }
    }

    /// Assembles a complete blob around a structure block.
    fn blob_from(structure: &[u8], reservations: &[(u64, u64)]) -> ([u8; 2048], usize) {
        let mut reservation_bytes = Writer::new();
        for &(base, len) in reservations {
            reservation_bytes.u64(base).u64(len);
        }
        reservation_bytes.u64(0).u64(0); // terminator

        let rsvmap_at = HEADER_LEN;
        let struct_at = rsvmap_at + reservation_bytes.len;
        let strings_at = struct_at + structure.len();
        let total = strings_at + STRINGS.len();

        let mut header = Writer::new();
        header
            .u32(MAGIC)
            .u32(total as u32)
            .u32(struct_at as u32)
            .u32(strings_at as u32)
            .u32(rsvmap_at as u32)
            .u32(SUPPORTED_VERSION)
            .u32(16) // last_comp_version
            .u32(0) // boot_cpuid_phys
            .u32(STRINGS.len() as u32)
            .u32(structure.len() as u32);

        let mut blob = [0u8; 2048];
        blob[..HEADER_LEN].copy_from_slice(header.as_slice());
        blob[rsvmap_at..struct_at].copy_from_slice(reservation_bytes.as_slice());
        blob[struct_at..strings_at].copy_from_slice(structure);
        blob[strings_at..total].copy_from_slice(STRINGS);
        (blob, total)
    }

    /// A tree shaped like the QEMU `virt` machine's: 2/2 cells at the root,
    /// one RAM bank, and a `/reserved-memory` carve-out inside it.
    fn virt_like() -> ([u8; 2048], usize) {
        let mut structure = Writer::new();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 2)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"memory@40000000")
            .prop(NAME_DEVICE_TYPE, b"memory\0")
            .reg(0x4000_0000, 0x2000_0000)
            .end_node()
            .begin_node(b"reserved-memory")
            .prop_u32(NAME_ADDRESS_CELLS, 2)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"framebuffer@4fff0000")
            .reg(0x4fff_0000, 0x1_0000)
            .end_node()
            .end_node()
            .end_node()
            .u32(FDT_END);
        blob_from(structure.as_slice(), &[(0x4700_0000, 0x1000)])
    }

    fn empty_regions() -> [MemoryRegion; 8] {
        [MemoryRegion {
            base: PhysAddr::new(0),
            len: 0,
            kind: MemoryKind::Reserved,
        }; 8]
    }

    #[test]
    fn a_virt_like_tree_yields_its_ram_bank_and_carve_out() {
        let (blob, total) = virt_like();
        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        assert_eq!(tree.len(), total);

        let mut regions = empty_regions();
        let found = tree.memory_regions(&mut regions).expect("readable tree");
        assert_eq!(found, 2);
        assert_eq!(
            (regions[0].base.as_u64(), regions[0].len, regions[0].kind),
            (0x4000_0000, 0x2000_0000, MemoryKind::Usable)
        );
        assert_eq!(
            (regions[1].base.as_u64(), regions[1].len, regions[1].kind),
            (0x4fff_0000, 0x1_0000, MemoryKind::Reserved)
        );
    }

    #[test]
    fn virtio_mmio_nodes_are_discovered_by_compatible() {
        // Two virtio-mmio transport slots (the `virt` layout: stride 0x200)
        // plus a non-virtio device that must not be reported. The compatible
        // value carries a second string to prove the list is scanned, not just
        // its first entry compared.
        let mut structure = Writer::new();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 2)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"virtio_mmio@a000000")
            .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
            .reg(0x0a00_0000, 0x200)
            .end_node()
            .begin_node(b"pl011@9000000")
            .prop(NAME_COMPATIBLE, b"arm,pl011\0arm,primecell\0")
            .reg(0x0900_0000, 0x1000)
            .end_node()
            .begin_node(b"virtio_mmio@a000200")
            .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
            .reg(0x0a00_0200, 0x200)
            .end_node()
            .end_node()
            .u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = [VirtioMmioRegion {
            base: 0,
            size: 0,
            intid: None,
        }; 8];
        let found = tree
            .virtio_mmio_regions(&mut regions)
            .expect("readable tree");
        assert_eq!(found, 2);
        assert_eq!(
            regions[0],
            VirtioMmioRegion {
                base: 0x0a00_0000,
                size: 0x200,
                intid: None
            }
        );
        assert_eq!(
            regions[1],
            VirtioMmioRegion {
                base: 0x0a00_0200,
                size: 0x200,
                intid: None
            }
        );
    }

    #[test]
    fn a_virtio_node_with_a_gic_spi_interrupt_reports_its_intid() {
        // The `virt` layout: `interrupts = <GIC_SPI n flags>` — three
        // big-endian cells; SPI 16 maps to GIC INTID 48. A second node with a
        // PPI-type descriptor (type 1) must yield None, not a wrong INTID.
        let mut structure = Writer::new();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 2)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"virtio_mmio@a000000")
            .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
            .prop(
                NAME_INTERRUPTS,
                &[0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 1], // <SPI 16 edge>
            )
            .reg(0x0a00_0000, 0x200)
            .end_node()
            .begin_node(b"virtio_mmio@a000200")
            .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
            .prop(
                NAME_INTERRUPTS,
                &[0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 4], // <PPI 9 level>
            )
            .reg(0x0a00_0200, 0x200)
            .end_node()
            .end_node()
            .u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = [VirtioMmioRegion {
            base: 0,
            size: 0,
            intid: None,
        }; 8];
        let found = tree
            .virtio_mmio_regions(&mut regions)
            .expect("readable tree");
        assert_eq!(found, 2);
        assert_eq!(regions[0].intid, Some(48));
        assert_eq!(regions[1].intid, None);
    }

    #[test]
    fn the_reservation_block_is_read_up_to_its_terminator() {
        let (blob, total) = virt_like();
        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");

        let mut regions = empty_regions();
        let found = tree.reserved_regions(&mut regions).expect("readable block");
        assert_eq!(found, 1);
        assert_eq!(
            (regions[0].base.as_u64(), regions[0].len, regions[0].kind),
            (0x4700_0000, 0x1000, MemoryKind::Reserved)
        );
    }

    #[test]
    fn the_reserved_memory_node_itself_is_not_a_region() {
        // `/reserved-memory` may carry its own `reg`; only its children
        // describe actual carve-outs.
        let mut structure = Writer::new();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 2)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"reserved-memory")
            .reg(0x1000, 0x1000)
            .end_node()
            .end_node()
            .u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = empty_regions();
        assert_eq!(tree.memory_regions(&mut regions), Ok(0));
    }

    #[test]
    fn reg_is_read_with_the_parents_cell_counts() {
        // Root declares 1/1, so each `reg` cell pair is 32-bit.
        let mut structure = Writer::new();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 1)
            .prop_u32(NAME_SIZE_CELLS, 1)
            .begin_node(b"memory@80000000")
            .prop(NAME_DEVICE_TYPE, b"memory\0")
            .prop(NAME_REG, &[0x80, 0, 0, 0, 0x10, 0, 0, 0])
            .end_node()
            .end_node()
            .u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = empty_regions();
        assert_eq!(tree.memory_regions(&mut regions), Ok(1));
        assert_eq!(
            (regions[0].base.as_u64(), regions[0].len),
            (0x8000_0000, 0x1000_0000)
        );
    }

    #[test]
    fn multiple_banks_in_one_reg_are_all_reported() {
        let mut value = [0u8; 32];
        value[..8].copy_from_slice(&0x4000_0000u64.to_be_bytes());
        value[8..16].copy_from_slice(&0x1000_0000u64.to_be_bytes());
        value[16..24].copy_from_slice(&0x8000_0000u64.to_be_bytes());
        value[24..].copy_from_slice(&0x1000_0000u64.to_be_bytes());

        let mut structure = Writer::new();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 2)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"memory@40000000")
            .prop(NAME_DEVICE_TYPE, b"memory\0")
            .prop(NAME_REG, &value)
            .end_node()
            .end_node()
            .u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = empty_regions();
        assert_eq!(tree.memory_regions(&mut regions), Ok(2));
        assert_eq!(regions[1].base.as_u64(), 0x8000_0000);
    }

    #[test]
    fn properties_may_precede_the_device_type_that_qualifies_them() {
        // `reg` before `device_type` must still be recognized — the reason
        // the walk defers interpretation to the node's close.
        let mut structure = Writer::new();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 2)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"memory@40000000")
            .reg(0x4000_0000, 0x1000)
            .prop(NAME_DEVICE_TYPE, b"memory\0")
            .end_node()
            .end_node()
            .u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = empty_regions();
        assert_eq!(tree.memory_regions(&mut regions), Ok(1));
    }

    #[test]
    fn a_bad_magic_is_rejected_before_anything_else_is_read() {
        let (mut blob, total) = virt_like();
        blob[0] ^= 0xff;
        assert_eq!(
            DeviceTree::parse(&blob[..total]).err(),
            Some(FdtError::BadMagic)
        );
    }

    #[test]
    fn a_future_structure_version_is_rejected() {
        let (mut blob, total) = virt_like();
        blob[OFF_LAST_COMP_VERSION..OFF_LAST_COMP_VERSION + 4]
            .copy_from_slice(&(SUPPORTED_VERSION + 1).to_be_bytes());
        assert_eq!(
            DeviceTree::parse(&blob[..total]).err(),
            Some(FdtError::UnsupportedVersion)
        );
    }

    #[test]
    fn a_blob_shorter_than_its_own_totalsize_is_truncated() {
        let (blob, total) = virt_like();
        assert_eq!(
            DeviceTree::parse(&blob[..total - 1]).err(),
            Some(FdtError::Truncated)
        );
    }

    #[test]
    fn an_output_slice_too_small_reports_rather_than_truncating() {
        let (blob, total) = virt_like();
        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = [MemoryRegion {
            base: PhysAddr::new(0),
            len: 0,
            kind: MemoryKind::Reserved,
        }; 1];
        assert_eq!(
            tree.memory_regions(&mut regions),
            Err(FdtError::TooManyRegions)
        );
    }

    #[test]
    fn a_reg_needing_more_than_64_bits_is_refused_not_silently_narrowed() {
        let mut structure = Writer::new();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 3)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"memory@0")
            .prop(NAME_DEVICE_TYPE, b"memory\0")
            .prop(NAME_REG, &[0u8; 20])
            .end_node()
            .end_node()
            .u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = empty_regions();
        assert_eq!(
            tree.memory_regions(&mut regions),
            Err(FdtError::UnsupportedCellCount)
        );
    }

    #[test]
    fn an_unterminated_node_is_malformed() {
        let mut structure = Writer::new();
        structure.begin_node(b"").u32(FDT_END); // never closed
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = empty_regions();
        assert_eq!(tree.memory_regions(&mut regions), Err(FdtError::Malformed));
    }

    #[test]
    fn an_unknown_token_is_malformed() {
        let mut structure = Writer::new();
        structure.u32(0xdead);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = empty_regions();
        assert_eq!(tree.memory_regions(&mut regions), Err(FdtError::Malformed));
    }

    #[test]
    fn nesting_past_the_depth_bound_is_malformed() {
        let mut structure = Writer::new();
        for _ in 0..=MAX_DEPTH {
            structure.begin_node(b"n");
        }
        structure.u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);

        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = empty_regions();
        assert_eq!(tree.memory_regions(&mut regions), Err(FdtError::Malformed));
    }

    #[test]
    fn the_reader_never_panics_on_arbitrary_input() {
        // A seeded LCG producing both random soup and single-byte mutations
        // of a valid blob; every path must return an error, never panic
        // (docs/lifecycle/04, fuzz target for parsers of external input; a
        // libfuzzer target is deferred, D12).
        let (valid, total) = virt_like();
        let mut state: u64 = 0x0f1e_2d3c_4b5a_6978;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 33
        };

        let mut regions = empty_regions();
        for round in 0..20_000u32 {
            let mut blob = valid;
            let len = if round % 2 == 0 {
                // Mutate a valid blob: keeps the walk reaching deep code.
                for _ in 0..1 + next() % 4 {
                    let at = (next() as usize) % total;
                    blob[at] ^= (next() as u8) | 1;
                }
                total
            } else {
                // Arbitrary bytes, arbitrary length.
                let len = (next() as usize) % blob.len();
                for byte in blob.iter_mut().take(len) {
                    *byte = next() as u8;
                }
                len
            };

            let _ = total_size(&blob[..len.min(HEADER_LEN)]);
            if let Ok(tree) = DeviceTree::parse(&blob[..len]) {
                let _ = tree.memory_regions(&mut regions);
                let _ = tree.reserved_regions(&mut regions);
            }
        }
    }
}
