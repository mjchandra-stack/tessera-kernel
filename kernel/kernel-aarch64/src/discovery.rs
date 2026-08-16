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
pub(crate) fn boot_memory_map(dtb: u64, storage: &mut [MemoryRegion]) -> Result<&[MemoryRegion], FdtError> {
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

/// Boot timer rate; matches the x86-64 harness so the two are comparable.
pub(crate) const TICK_HZ: u32 = 100;

/// Samples for the context-switch benchmark.
pub(crate) const PERF_SAMPLES: usize = 200;
pub(crate) static mut PERF_BUF: [u64; PERF_SAMPLES] = [0; PERF_SAMPLES];

/// The two ends of the ping-pong the benchmark switches between.
pub(crate) static mut PERF_MAIN_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> = None;
pub(crate) static mut PERF_PONG_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> = None;

