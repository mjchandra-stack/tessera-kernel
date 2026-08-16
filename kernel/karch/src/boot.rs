// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Boot-protocol-independent boot information. Boot glue (the only code
//! that knows which bootloader ran) normalizes its protocol into these
//! types before the kernel core sees anything.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Platform
//! Support Packages")

use crate::addr::PhysAddr;
use crate::error::KError;

/// What a physical memory region may be used for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoryKind {
    /// Free RAM the kernel may allocate.
    Usable,
    /// Holds boot-protocol data; reclaimable once the kernel stops
    /// referencing boot structures.
    BootloaderReclaimable,
    /// The kernel image and boot modules themselves.
    KernelAndModules,
    /// Framebuffer or other device-backed ranges.
    Framebuffer,
    /// ACPI tables, reclaimable after parsing.
    AcpiReclaimable,
    /// ACPI non-volatile storage; never reclaimable.
    AcpiNvs,
    /// Firmware-reserved; never touched.
    Reserved,
    /// Known-faulty memory; never touched.
    Bad,
}

/// One contiguous physical region. Regions never overlap; the boot glue is
/// responsible for delivering them sorted by base address.
#[derive(Clone, Copy, Debug)]
pub struct MemoryRegion {
    pub base: PhysAddr,
    pub len: u64,
    pub kind: MemoryKind,
}

impl MemoryKind {
    /// Which kind wins where two regions overlap. Higher wins.
    ///
    /// The one load-bearing rule is that **`Usable` is weakest**: a firmware
    /// map that says "this whole bank is RAM" overlaps the kernel image, the
    /// boot data, and every firmware carve-out inside it, and handing any of
    /// those to the frame allocator would let the kernel allocate over
    /// itself. Everything else outranks it. The ordering *among* the
    /// non-usable kinds is a documented tie-break for maps that should not
    /// have produced an overlap at all; more-restrictive wins, so a
    /// disagreement can only ever cost memory, never safety.
    const fn precedence(self) -> u8 {
        match self {
            Self::Usable => 0,
            Self::BootloaderReclaimable => 1,
            Self::AcpiReclaimable => 2,
            Self::Framebuffer => 3,
            Self::KernelAndModules => 4,
            Self::AcpiNvs => 5,
            Self::Reserved => 6,
            Self::Bad => 7,
        }
    }
}

impl MemoryRegion {
    /// Exclusive end of the region, or `None` if the region wraps the
    /// address space (a malformed map the caller must reject).
    pub const fn end(&self) -> Option<PhysAddr> {
        self.base.checked_add(self.len)
    }
}

/// Turns an unordered, possibly overlapping set of regions into the sorted,
/// non-overlapping map [`BootInfo`] requires.
///
/// Boot glue assembles its map from several sources that legitimately
/// describe the same addresses — the firmware's RAM banks, the kernel image,
/// the boot data, firmware reservations — so overlap is the normal case, not
/// a malformed input. This resolves it by [precedence](MemoryKind::precedence)
/// rather than by trusting an ordering the sources never agreed on.
///
/// The method is a sweep over region boundaries: every base and end becomes
/// an edge, and each elementary interval between adjacent edges takes the
/// strongest kind covering it. That is quadratic in the region count, which
/// is the right trade at boot-map sizes (tens of regions) for an algorithm
/// whose correctness is evident by inspection.
///
/// `edges` is caller-supplied scratch and must hold `2 * input.len()`
/// entries. Neither buffer is ever silently outgrown: too small returns
/// [`KError::LimitExceeded`] so the caller reports a truncated map instead of
/// booting on one (docs/lifecycle/04, "No Silent Fallback").
///
/// Zero-length regions are dropped. A region whose end overflows the address
/// space is rejected with [`KError::InvalidMapping`].
pub fn normalize_memory_map(
    input: &[MemoryRegion],
    edges: &mut [u64],
    out: &mut [MemoryRegion],
) -> Result<usize, KError> {
    let mut edge_count = 0usize;
    for region in input {
        if region.len == 0 {
            continue;
        }
        let end = region.end().ok_or(KError::InvalidMapping)?;
        for value in [region.base.as_u64(), end.as_u64()] {
            if edge_count == edges.len() {
                return Err(KError::LimitExceeded);
            }
            edges[edge_count] = value;
            edge_count += 1;
        }
    }

    let edges = &mut edges[..edge_count];
    // Insertion sort: no allocator, and the input is small and often nearly
    // sorted already.
    for i in 1..edges.len() {
        let mut j = i;
        while j > 0 && edges[j - 1] > edges[j] {
            edges.swap(j - 1, j);
            j -= 1;
        }
    }

    let mut filled = 0usize;
    for window in edges.windows(2) {
        let (start, end) = (window[0], window[1]);
        if start == end {
            continue; // duplicate edge
        }

        // Strongest kind covering this elementary interval, if any. The
        // interval lies entirely inside or entirely outside each region, so
        // testing the start point alone is sufficient.
        let mut kind: Option<MemoryKind> = None;
        for region in input {
            if region.len == 0 {
                continue;
            }
            let region_end = region.base.as_u64().wrapping_add(region.len);
            if start < region.base.as_u64() || start >= region_end {
                continue;
            }
            if kind.is_none_or(|held| region.kind.precedence() > held.precedence()) {
                kind = Some(region.kind);
            }
        }
        let Some(kind) = kind else {
            continue; // a hole between regions
        };

        // Coalesce with the previous interval when it is the same kind and
        // physically adjacent, so the output is the coarsest correct map.
        if let Some(last) = filled.checked_sub(1).and_then(|i| out.get_mut(i))
            && last.kind == kind
            && last.base.as_u64() + last.len == start
        {
            last.len += end - start;
            continue;
        }

        if filled == out.len() {
            return Err(KError::LimitExceeded);
        }
        out[filled] = MemoryRegion {
            base: PhysAddr::new(start),
            len: end - start,
            kind,
        };
        filled += 1;
    }

    Ok(filled)
}

/// Everything the kernel core needs from boot, already normalized.
#[derive(Debug)]
pub struct BootInfo<'a> {
    /// Offset of the higher-half direct map: physical address `p` is
    /// mapped at virtual `hhdm_offset + p`.
    pub hhdm_offset: u64,
    /// The physical memory map, sorted by base, non-overlapping.
    pub memory_map: &'a [MemoryRegion],
}

#[cfg(test)]
#[path = "tests/boot.rs"]
mod tests;
