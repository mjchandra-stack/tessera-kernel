// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What the firmware says this machine has: the ACPI tables, and the one
//! structure in them that names a DMA remapping unit.
//!
//! **This is the device tree's counterpart.** Every other port learns where its
//! IOMMU registers are by reading a node out of a blob the firmware handed it;
//! on an IA-PC there is no blob, and the same question is answered by a
//! signature scan through low memory followed by two table walks. The mechanism
//! is different and the standing is identical — neither is a constant this
//! kernel chose, and a machine that describes a remapping unit somewhere else
//! is followed rather than second-guessed.
//!
//! **Why the scan rather than the bootloader.** ACPI 6.5 §5.2.5.1 defines
//! exactly this search for IA-PC systems — the two-kilobyte EBDA named by the
//! word at `0x40e`, then `0xe0000..0x100000`, sixteen-byte aligned, checksummed
//! — and it is the method that holds whether this kernel was started by
//! Limine, by another loader, or by something that answers no request at all.
//! Depending on a boot protocol's optional response would make a hardware fact
//! contingent on who launched us.
//!
//! Nothing here interprets more than it must: the tables are read, the DMAR's
//! first remapping hardware unit is returned, and everything else in ACPI is
//! left alone, because a parser that reads fields nobody uses is a parser with
//! bugs nobody would notice.
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md,
//! docs/hardware/04-dma-and-memory-management.md
//! Budget: none (boot path)

/// The signature the root pointer carries, as eight bytes rather than a string:
/// what is being matched is a fixed byte pattern at a sixteen-byte boundary.
const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";

/// Where the search looks. The first is the word at `0x40e` — the BIOS data
/// area's pointer to the extended BIOS data area, in paragraphs — and the
/// second is the fixed window every IA-PC firmware places tables in.
const EBDA_POINTER: u64 = 0x40e;
const EBDA_SEARCH_LEN: u64 = 1024;
const BIOS_SEARCH_START: u64 = 0x000e_0000;
const BIOS_SEARCH_END: u64 = 0x0010_0000;

/// A table's signature, checked before anything in it is believed.
const DMAR_SIGNATURE: [u8; 4] = *b"DMAR";

/// The fixed part of every ACPI table: signature, length, revision, checksum,
/// and six fields naming who wrote it.
const TABLE_HEADER_LEN: u64 = 36;

/// A remapping hardware unit definition — the DMAR structure naming one unit's
/// register block. Type 0; the only type this kernel reads.
const DMAR_TYPE_DRHD: u16 = 0;

/// `DRHD.flags` bit 0: this unit covers every PCI device in its segment that
/// no other unit claims. QEMU's `intel-iommu` sets it, and a unit that did not
/// would have to be matched against a device scope this kernel does not read —
/// so a clear bit is reported rather than assumed away.
const DRHD_INCLUDE_PCI_ALL: u8 = 1;

/// One remapping unit, as the firmware describes it.
#[derive(Clone, Copy)]
pub(crate) struct RemappingUnit {
    /// Physical base of the unit's register block.
    pub(crate) register_base: u64,
    /// The PCI segment it covers.
    pub(crate) segment: u16,
    /// Whether it covers every function in that segment.
    pub(crate) include_all: bool,
}

/// Reads `len` bytes of physical memory through the direct map.
///
/// # Safety
///
/// `phys..phys + len` must be inside the direct map — that is, below the
/// machine's top of RAM — and must not be concurrently written.
unsafe fn phys_bytes<'a>(direct_map_base: u64, phys: u64, len: u64) -> &'a [u8] {
    // SAFETY: the caller's contract, restated: the range is mapped read-write
    // at `direct_map_base` for the life of the kernel, and firmware tables are
    // not written by anything on this machine.
    unsafe {
        core::slice::from_raw_parts(
            (direct_map_base + phys) as *const u8,
            usize::try_from(len).unwrap_or(0),
        )
    }
}

/// The little-endian integers a table is made of, read out of a byte slice.
///
/// Bounds-checked and answering `None` past the end rather than panicking: a
/// table whose length field disagrees with its contents is a machine
/// description this kernel declines to follow, not a reason to stop the boot.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Whether a run of bytes sums to zero in eight bits, which is how every ACPI
/// structure says it is intact.
///
/// **Checked rather than skipped.** The scan below matches an eight-byte
/// pattern in a megabyte of memory somebody else's firmware wrote; without the
/// checksum, a stale copy of that pattern in a data area is a pointer this
/// kernel would follow.
fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}

/// Finds the root system description pointer.
///
/// Returns its physical address. The two search areas are ACPI 6.5 §5.2.5.1's,
/// in its order: a firmware that placed the pointer in the EBDA is answered
/// from there, and one that did not is answered from the BIOS window.
///
/// # Safety
///
/// The direct map must cover low physical memory, which it does from the moment
/// the kernel's own tables are active.
unsafe fn find_rsdp(direct_map_base: u64) -> Option<u64> {
    // SAFETY: the caller's contract; two bytes of the BIOS data area.
    let ebda_paragraph = unsafe { phys_bytes(direct_map_base, EBDA_POINTER, 2) };
    let ebda = u64::from(u16_at(ebda_paragraph, 0)?) << 4;
    let areas = [
        (ebda, ebda + EBDA_SEARCH_LEN),
        (BIOS_SEARCH_START, BIOS_SEARCH_END),
    ];
    for (start, end) in areas {
        // A zero or absurd EBDA pointer is a firmware that did not set one;
        // searching from it would read whatever happens to be at that address.
        if start < 0x400 || end <= start {
            continue;
        }
        let mut at = start;
        while at + 20 <= end {
            // SAFETY: as above; the window is inside the direct map.
            let candidate = unsafe { phys_bytes(direct_map_base, at, 20) };
            if candidate[..8] == RSDP_SIGNATURE && checksum_ok(candidate) {
                return Some(at);
            }
            at += 16;
        }
    }
    None
}

/// The address and entry width of the description table this pointer names.
///
/// Revision 2 and later carry an XSDT with 64-bit entries; earlier ones carry
/// an RSDT with 32-bit entries. Both are followed, because which one a machine
/// offers is the machine's business.
///
/// # Safety
///
/// As [`find_rsdp`].
unsafe fn description_table(direct_map_base: u64, rsdp: u64) -> Option<(u64, usize)> {
    // SAFETY: the caller's contract; the pointer was checksummed as 20 bytes,
    // and its own length field says whether there are more.
    let short = unsafe { phys_bytes(direct_map_base, rsdp, 20) };
    if short[15] >= 2 {
        // SAFETY: as above.
        let long = unsafe { phys_bytes(direct_map_base, rsdp, 36) };
        // The extended checksum covers the whole structure, and a revision-2
        // pointer whose second checksum fails is one whose 64-bit fields were
        // never written.
        if checksum_ok(long) {
            let xsdt = u64_at(long, 24)?;
            if xsdt != 0 {
                return Some((xsdt, 8));
            }
        }
    }
    Some((u64::from(u32_at(short, 16)?), 4))
}

/// Walks the description table for a signature and answers where that table is.
///
/// # Safety
///
/// As [`find_rsdp`].
unsafe fn table_with(
    direct_map_base: u64,
    root: u64,
    entry_width: usize,
    signature: [u8; 4],
) -> Option<u64> {
    // SAFETY: the caller's contract; the header says how long the rest is.
    let header = unsafe { phys_bytes(direct_map_base, root, TABLE_HEADER_LEN) };
    let length = u64::from(u32_at(header, 4)?);
    if length < TABLE_HEADER_LEN {
        return None;
    }
    // SAFETY: as above, now the whole table.
    let table = unsafe { phys_bytes(direct_map_base, root, length) };
    if !checksum_ok(table) {
        return None;
    }
    let entries = &table[TABLE_HEADER_LEN as usize..];
    for entry in entries.chunks_exact(entry_width) {
        let phys = match entry_width {
            8 => u64_at(entry, 0)?,
            _ => u64::from(u32_at(entry, 0)?),
        };
        if phys == 0 {
            continue;
        }
        // SAFETY: as above; a candidate's own header, before it is believed.
        let candidate = unsafe { phys_bytes(direct_map_base, phys, TABLE_HEADER_LEN) };
        if candidate[..4] == signature {
            return Some(phys);
        }
    }
    None
}

/// The first DMA remapping unit this machine describes, or `None` on a machine
/// that describes none.
///
/// **`None` is an answer, not a failure.** A machine without an IOMMU is a
/// machine where a device's DMA is not scoped, and the check above this reports
/// that rather than treating it as a fault — which is the same shape the other
/// port's device-tree lookup has.
///
/// # Safety
///
/// The kernel's own page tables must be active, so the direct map covers low
/// memory and the ACPI reclaimable regions.
pub(crate) unsafe fn remapping_unit(direct_map_base: u64) -> Option<RemappingUnit> {
    // SAFETY: the caller's contract, carried down each step.
    unsafe {
        let rsdp = find_rsdp(direct_map_base)?;
        let (root, entry_width) = description_table(direct_map_base, rsdp)?;
        let dmar = table_with(direct_map_base, root, entry_width, DMAR_SIGNATURE)?;
        let header = phys_bytes(direct_map_base, dmar, TABLE_HEADER_LEN);
        let length = u64::from(u32_at(header, 4)?);
        let table = phys_bytes(direct_map_base, dmar, length);
        if !checksum_ok(table) {
            return None;
        }
        // The DMAR's own fixed part is twelve bytes past the common header:
        // the host address width, the flags, and ten reserved bytes. The
        // remapping structures follow, each with a type and a length of its
        // own.
        let mut at = TABLE_HEADER_LEN as usize + 12;
        while at + 4 <= table.len() {
            let kind = u16_at(table, at)?;
            let len = usize::from(u16_at(table, at + 2)?);
            // A zero-length structure would make this loop never end, and a
            // table that produced one is not a table to keep reading.
            if len < 4 || at + len > table.len() {
                return None;
            }
            if kind == DMAR_TYPE_DRHD && len >= 16 {
                return Some(RemappingUnit {
                    register_base: u64_at(table, at + 8)?,
                    segment: u16_at(table, at + 6)?,
                    include_all: table[at + 4] & DRHD_INCLUDE_PCI_ALL != 0,
                });
            }
            at += len;
        }
        None
    }
}
