// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What this machine finds at boot: the PCIe functions behind the host
//! bridge, and the memory map the firmware handed over.
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

/// Enumerates the PCI bus. See the RISC-V port's twin for why the **kernel**
/// walks config space rather than the device manager (D114): config space is
/// not per-device, so a capability to it would be authority over every
/// function behind the bridge at once.
pub(crate) fn pcie_enumerate(
    host: &tessera_devicetree::PciHost,
    out: &mut [tessera_pci::Function],
) -> Result<usize, tessera_pci::Error> {
    let Some(memory) = host.memory else {
        return Err(tessera_pci::Error::WindowExhausted);
    };
    let window = tessera_pci::Window {
        cpu_base: memory.cpu_base,
        bus_base: memory.bus_base,
        len: memory.len,
        is_32bit: true,
    };
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    tessera_pci::enumerate(&bridge, &mut config, window, out)
}

/// Reads the firmware's device tree and returns the sorted, non-overlapping
/// physical memory map [`BootInfo`] requires.
///
/// Four sources contribute, and they overlap by nature: the tree's RAM banks
/// cover everything, while the kernel image, the device tree blob itself,
/// the firmware reservation block, and `/reserved-memory` all sit inside
/// them. They are gathered unresolved and handed to
/// [`normalize_memory_map`], which settles the overlaps by precedence — so
/// no caller has to reason about the order they were collected in.
pub(crate) fn boot_memory_map(
    dtb: u64,
    storage: &mut [MemoryRegion],
) -> Result<&[MemoryRegion], FdtError> {
    // The blob's own length lives inside it, so the header is read first and
    // the rest only once its extent is known.
    //
    // SAFETY: `dtb` is the firmware handoff address. The Image boot protocol
    // guarantees it points at a device tree blob in memory the kernel owns,
    // and with the MMU off every physical address is readable. Nothing is
    // trusted about the *contents*: `total_size` validates the magic and
    // rejects an implausible length before the larger slice is formed, and
    // the reader bounds-checks every access inside it.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header)?;
    // SAFETY: as above, now bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };

    let tree = DeviceTree::parse(blob)?;

    let mut gathered = [EMPTY_REGION; MAX_MEMORY_REGIONS];
    let mut count = tree.memory_regions(&mut gathered)?;
    count += tree.reserved_regions(&mut gathered[count..])?;

    for region in [
        // The image the firmware just loaded us from. Its symbols are linked
        // in the high half now, so the physical extent — what the memory map
        // must carve out of RAM — is the low 48 bits of those addresses.
        MemoryRegion {
            base: PhysAddr::new(&raw const __kernel_start as u64 & PHYS_MASK),
            len: &raw const __kernel_end as u64 - &raw const __kernel_start as u64,
            kind: MemoryKind::KernelAndModules,
        },
        // The device tree itself, reclaimable once discovery has consumed
        // it — which has not happened yet, so it stays reserved for now.
        MemoryRegion {
            base: PhysAddr::new(dtb),
            len: tree.len() as u64,
            kind: MemoryKind::BootloaderReclaimable,
        },
    ] {
        *gathered.get_mut(count).ok_or(FdtError::TooManyRegions)? = region;
        count += 1;
    }

    let mut edges = [0u64; MAX_MEMORY_REGIONS * 2];
    let filled = normalize_memory_map(&gathered[..count], &mut edges, storage)
        .map_err(|_| FdtError::TooManyRegions)?;
    Ok(&storage[..filled])
}

/// How many CPUs the firmware's device tree describes.
///
/// Read here rather than folded into [`boot_memory_map`] because it answers a
/// different question about the same blob, and because it must be read at the
/// same moment: before the high-half switch drops the boot identity mapping
/// that makes the blob reachable at all.
///
/// `None` is a tree that could not be read or that describes no CPUs — the
/// second being impossible on a machine that is running this code, and so
/// worth reporting as "did not say" rather than as zero.
pub(crate) fn boot_cpu_count(dtb: u64) -> Option<usize> {
    // SAFETY: identical to `boot_memory_map`'s — `dtb` is the firmware handoff
    // address, the Image boot protocol guarantees a blob there in memory the
    // kernel owns, the MMU is off so every physical address is readable, and
    // `total_size` validates the magic and length before the larger slice is
    // formed. Nothing here trusts the contents.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above, now bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };

    match DeviceTree::parse(blob).ok()?.cpu_count() {
        Ok(0) | Err(_) => None,
        Ok(found) => Some(found),
    }
}

/// How many CPU identifiers the boot path will collect out of the device tree.
///
/// Deliberately the *configuration's* ceiling on `MAX_CPUS` rather than
/// `MAX_CPUS` itself: what this kernel can use is kcore's decision to make and
/// report, and a buffer that truncated first would take that decision here,
/// silently, where nothing counts what it dropped.
const MAX_LISTED_CPUS: usize = 64;

/// What the device tree says about the machine's CPUs and about how to start
/// one.
///
/// Read in one pass and carried by value because both facts must be taken at
/// the same moment as the memory map — while the blob is still reachable at its
/// physical address, before the high-half switch drops the boot identity of low
/// RAM — and are wanted afterwards.
pub(crate) struct BootCpus {
    /// Each CPU's hardware identifier, in the order the tree listed them.
    pub(crate) ids: [u64; MAX_LISTED_CPUS],
    /// How many of `ids` are filled.
    pub(crate) count: usize,
    /// How to reach firmware to start one, and the identifier of the call, or
    /// `None` where the tree describes no interface this kernel can use.
    pub(crate) psci: Option<(PsciConduit, u32)>,
}

impl BootCpus {
    /// The identifiers the tree listed.
    pub(crate) fn ids(&self) -> &[u64] {
        &self.ids[..self.count]
    }

    const NONE: Self = Self {
        ids: [0; MAX_LISTED_CPUS],
        count: 0,
        psci: None,
    };
}

/// Reads the CPU list and the power-control interface from the firmware's
/// device tree.
///
/// An unreadable tree yields no CPUs and no interface, which the caller reports
/// as a machine it cannot start anything on — the same shape as
/// [`boot_cpu_count`]'s `None` and for the same reason.
pub(crate) fn boot_cpus(dtb: u64) -> BootCpus {
    // SAFETY: identical to `boot_memory_map`'s — `dtb` is the firmware handoff
    // address, the boot protocol guarantees a blob there, the MMU is off so
    // every physical address is readable, and `total_size` validates the magic
    // and length before the larger slice is formed.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let Ok(total) = tessera_devicetree::total_size(header) else {
        return BootCpus::NONE;
    };
    // SAFETY: as above, now bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };
    let Ok(tree) = DeviceTree::parse(blob) else {
        return BootCpus::NONE;
    };

    let mut found = BootCpus::NONE;
    found.count = tree.cpus(&mut found.ids).unwrap_or(0);
    // The tree's conduit becomes the port's: two two-variant enums, because the
    // porting layer depends on no discovery crate (see `karch-aarch64`'s psci).
    found.psci = match tree.psci() {
        Ok(Some(psci)) => Some((
            match psci.conduit {
                tessera_devicetree::PsciConduit::Hvc => PsciConduit::Hvc,
                tessera_devicetree::PsciConduit::Smc => PsciConduit::Smc,
            },
            psci.cpu_on,
        )),
        _ => None,
    };
    found
}

/// Boot timer rate; matches the x86-64 harness so the two are comparable.
pub(crate) const TICK_HZ: u32 = 100;

/// Samples for the context-switch benchmark.
pub(crate) const PERF_SAMPLES: usize = 200;
pub(crate) static mut PERF_BUF: [u64; PERF_SAMPLES] = [0; PERF_SAMPLES];

/// The two ends of the ping-pong the benchmark switches between.
pub(crate) static mut PERF_MAIN_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> =
    None;
pub(crate) static mut PERF_PONG_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> =
    None;
