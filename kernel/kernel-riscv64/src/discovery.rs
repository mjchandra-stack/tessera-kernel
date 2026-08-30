// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What the firmware says this machine is.
//!
//! The device tree, read for the things the boot needs and nothing else: the
//! memory map, the virtio-MMIO windows, the PCIe host and its ECAM, and the RTC.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

/// Short label for a memory kind, for the boot map dump.
pub(crate) const fn kind_name(kind: MemoryKind) -> &'static str {
    match kind {
        MemoryKind::Usable => "usable",
        MemoryKind::BootloaderReclaimable => "boot-reclaimable",
        MemoryKind::KernelAndModules => "kernel",
        MemoryKind::Framebuffer => "framebuffer",
        MemoryKind::AcpiReclaimable => "acpi-reclaimable",
        MemoryKind::AcpiNvs => "acpi-nvs",
        MemoryKind::Reserved => "reserved",
        MemoryKind::Bad => "bad",
    }
}

pub(crate) const EMPTY_REGION: MemoryRegion = MemoryRegion {
    base: PhysAddr::new(0),
    len: 0,
    kind: MemoryKind::Reserved,
};

/// Capacity of the virtio-mmio window table. The `virt` machine presents a
/// fixed bank of transport slots whether or not anything is attached to them.
pub(crate) const MAX_MMIO_DEVICES: usize = 32;

/// Fills `out` with the machine's virtio-mmio register windows, returning how
/// many were found.
///
/// Best-effort: virtio is optional on a machine, so a tree this cannot read
/// yields zero windows rather than failing the boot — the caller states that
/// it found none instead of passing quietly.
///
/// Unlike the AArch64 twin this needs no "before the table switch" caveat: the
/// entry stub's direct map covers the blob for the kernel's whole life, so
/// `dtb` here is the same already-offset address the memory map was read from.
pub(crate) fn virtio_mmio_windows(dtb: u64, out: &mut [MmioDevice]) -> usize {
    // SAFETY: as `boot_memory_map` — `dtb` is the firmware handoff address
    // reached through the direct map; `total_size` validates the magic and
    // length before the larger slice is formed, and the reader bounds-checks
    // every access within it.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let Ok(total) = tessera_devicetree::total_size(header) else {
        return 0;
    };
    // SAFETY: as above, bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };
    let Ok(tree) = DeviceTree::parse(blob) else {
        return 0;
    };
    tree.virtio_mmio_regions(out).unwrap_or(0)
}

/// Reads a virtio-mmio transport's identity registers through the kernel's
/// direct map, returning `(magic, device_id)`.
///
/// The kernel reads them for two reasons: to refuse to hand out a capability
/// to a window that is not a virtio transport at all, and so that what a
/// ring-3 program later reports through its *own* mapping can be compared
/// against what the kernel saw through a completely different path.
pub(crate) fn virtio_identity(base: u64) -> (u32, u32) {
    let window = DIRECT_MAP_BASE as usize + base as usize;
    // SAFETY: `base` is a virtio-mmio window the device tree reported, which
    // lies inside `DEVICE_RANGE` and is therefore mapped read-write at
    // `DIRECT_MAP_BASE + base` by `build_kernel_space`. Both offsets are
    // defined 4-byte-aligned registers within the transport's 0x200 slot, and
    // reading either has no device-side effect.
    unsafe {
        (
            tessera_karch_riscv64::mmio_read32(window + tessera_virtio::reg::MAGIC_VALUE),
            tessera_karch_riscv64::mmio_read32(window + tessera_virtio::reg::DEVICE_ID),
        )
    }
}

/// The machine's PCI host bridge, if it has one.
pub(crate) fn pci_host(dtb: u64) -> Option<tessera_devicetree::PciHost> {
    // SAFETY: as `boot_memory_map` — `dtb` is the firmware handoff address
    // reached through the direct map, and `total_size` validates the blob's
    // magic and length before the larger slice is formed.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above, bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };
    DeviceTree::parse(blob).ok()?.pci_host().ok()?
}

/// Config space reached through the kernel's direct map.
///
/// The `unsafe` the `tessera-pci` crate forbids lives here, and it rests on
/// two facts checked before this is built: the ECAM window the device tree
/// reported lies inside `DEVICE_RANGE`, so it is mapped read-write at
/// `DIRECT_MAP_BASE + phys`; and the crate bounds every offset it passes
/// against the window length it was given, so an offset can never leave it.
pub(crate) struct EcamWindow {
    pub(crate) base: u64,
}

impl tessera_pci::ConfigSpace for EcamWindow {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: `base + offset` is inside the ECAM window (the caller bounds
        // the offset) and therefore inside the direct-mapped device range. A
        // config-space read has no device-side effect.
        unsafe {
            tessera_karch_riscv64::mmio_read32(
                DIRECT_MAP_BASE as usize + self.base as usize + offset as usize,
            )
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read32`. Writes here program BARs and the command
        // register of a device the kernel is enumerating before anything else
        // can hold a capability to it.
        unsafe {
            tessera_karch_riscv64::mmio_write32(
                DIRECT_MAP_BASE as usize + self.base as usize + offset as usize,
                value,
            );
        }
    }
}

/// Functions one walk may report — the `virt` machine's bus is sparse, and a
/// bound that is too small is an error rather than a short answer.
pub(crate) const MAX_PCI_FUNCTIONS: usize = 16;

/// Enumerates the PCI bus and reports what it found.
///
/// **The kernel walks config space, and that is a departure worth naming.**
/// The framework's rule is that enumeration needs access, which is why the
/// device manager is a program rather than a table (D91). PCI is the case
/// where that cannot hold: config space is not per-device, so a capability to
/// it would be authority over every function behind the bridge at once, and
/// `MapDevice` grants a single page against a window of megabytes. The kernel
/// therefore reads it and normalizes what it finds into the resource graph —
/// which is what `docs/architecture/02` already says the device manager
/// How far into a device's window the ring-3 driver reads to show it was
/// granted the whole thing. Must match `FAR_OFFSET` in `userspace/blk-probe`.
pub(crate) const FAR_WINDOW_OFFSET: u64 = 0x2000;

/// The BAR a virtio-pci function keeps its configuration structures in, and
/// its extent.
///
/// **Not `first_bar`.** That is the lowest-indexed assigned BAR, which on a
/// virtio-pci function is the MSI-X table; the structures a driver needs live
/// in whichever BAR the device's own vendor capabilities name. Granting a
/// driver the first one hands it the wrong region however completely it is
/// mapped. `None` for a function that publishes no virtio capabilities, whose
/// caller then falls back to the first BAR.
pub(crate) fn virtio_pci_bar(dtb: u64, function: &tessera_pci::Function) -> Option<(u64, u64)> {
    let host = pci_host(dtb)?;
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let cfg = EcamWindow {
        base: host.ecam_base,
    };
    let mut at = None;
    while let Ok(Some(offset)) =
        tessera_pci::find_capability_from(&bridge, &cfg, function.bdf, tessera_pci::CAP_VENDOR, at)
    {
        at = Some(offset);
        let word = |i: u16| bridge.read(&cfg, function.bdf, offset + i * 4).unwrap_or(0);
        let cap = tessera_virtio::pci::decode_cap([word(0), word(1), word(2), word(3)]);
        if cap.cfg_type != tessera_virtio::pci::cfg_type::COMMON {
            continue;
        }
        let (base, len) = function.bars.get(cap.bar as usize).copied().flatten()?;
        // The device's own numbers, checked before they are trusted.
        if u64::from(cap.offset) + u64::from(cap.length) > len {
            return None;
        }
        return Some((base, len));
    }
    None
}

/// consumes ("It receives facts from ... PCIe enumeration").
///
/// Returns the functions found, or `None` when the machine has no bridge.
pub(crate) fn pcie_enumerate(
    dtb: u64,
    out: &mut [tessera_pci::Function],
) -> Option<Result<usize, tessera_pci::Error>> {
    let host = pci_host(dtb)?;
    // The window must be inside the range the kernel direct-maps as device
    // memory, or `EcamWindow`'s safety argument does not hold. Refusing beats
    // reading whatever is mapped there instead.
    if host.ecam_base < DEVICE_RANGE.0
        || host
            .ecam_base
            .saturating_add(host.ecam_len)
            .saturating_sub(1)
            >= DEVICE_RANGE.1
    {
        return Some(Err(tessera_pci::Error::OutsideEcam));
    }
    let memory = host.memory?;
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
    Some(tessera_pci::enumerate(&bridge, &mut config, window, out))
}

/// The machine's real-time clock, if it has one.
pub(crate) fn rtc_device(dtb: u64) -> Option<tessera_devicetree::MmioDevice> {
    // SAFETY: as `boot_memory_map` — `dtb` is the firmware handoff address
    // reached through the direct map, and `total_size` validates the blob's
    // magic and length before the larger slice is formed.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above, bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };
    DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(RTC_COMPATIBLE)
        .ok()
        .flatten()
}

/// Reads the firmware's device tree and returns the sorted, non-overlapping
/// physical memory map [`BootInfo`] requires.
///
/// Four sources contribute, and they overlap by nature: the tree's RAM banks
/// cover everything, while the kernel image, the device tree blob itself, and
/// the firmware's own reservations sit inside them. On this machine that last
/// source is not a formality — OpenSBI is resident in the first 2 MiB of RAM
/// and stays there, so a map that missed its reservation would hand the frame
/// allocator the firmware the kernel is still calling into. They are gathered
/// unresolved and handed to [`normalize_memory_map`], which settles the
/// overlaps by precedence.
pub(crate) fn boot_memory_map(
    dtb: u64,
    storage: &mut [MemoryRegion],
) -> Result<&[MemoryRegion], FdtError> {
    // The blob's own length lives inside it, so the header is read first and
    // the rest only once its extent is known.
    //
    // SAFETY: `dtb` is the firmware handoff address. The SBI boot convention
    // guarantees it points at a device tree blob in memory the kernel owns,
    // and with translation off every physical address is readable. Nothing is
    // trusted about the *contents*: `total_size` validates the magic and
    // rejects an implausible length before the larger slice is formed, and
    // the reader bounds-checks every access inside it.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header)?;
    // SAFETY: as above, now bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };

    let tree = DeviceTree::parse(blob)?;

    // The tree reports what firmware said, in its own vocabulary: a base, a
    // length, and usable-or-not. Widening that into the kernel's kinds is this
    // port's job, the same job the x86-64 glue does for Limine's map — the
    // reader has no dependency on the kernel to do it for us (D295).
    let mut described = [tessera_devicetree::Region::EMPTY; MAX_MEMORY_REGIONS];
    let mut count = tree.memory_regions(&mut described)?;
    count += tree.reserved_regions(&mut described[count..])?;

    let mut gathered = [EMPTY_REGION; MAX_MEMORY_REGIONS];
    for (slot, region) in gathered.iter_mut().zip(&described[..count]) {
        *slot = MemoryRegion::described(
            region.base,
            region.len,
            region.kind == tessera_devicetree::RegionKind::Usable,
        );
    }

    for region in [
        // The image the firmware loaded. Its symbols are **virtual** now that
        // the kernel is linked in the upper half, and a memory map describes
        // physical memory — so each is converted back. Recording a virtual
        // address here hands the frame allocator a region that is not memory,
        // which is how this was caught.
        MemoryRegion {
            base: PhysAddr::new(&raw const __kernel_start as u64 - DIRECT_MAP_BASE),
            len: &raw const __kernel_end as u64 - &raw const __kernel_start as u64,
            kind: MemoryKind::KernelAndModules,
        },
        // The device tree itself, reclaimable once discovery has consumed
        // it — which has not happened yet, so it stays reserved for now.
        MemoryRegion {
            base: PhysAddr::new(dtb - DIRECT_MAP_BASE),
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
