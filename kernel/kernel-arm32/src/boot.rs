// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The parts of the boot path that are about *this machine* rather than about
//! the kernel: reading the firmware's device tree into a normalized memory
//! map, and the tick check.
//!
//! Split out of `main.rs` only to keep the composition root readable; there is
//! no interface here, and nothing outside the crate uses it.
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md
//! Budget: none (init path)

use crate::{__kernel_end, __kernel_start, MAX_MEMORY_REGIONS, OBSERVED_TICKS, TICK_HZ, on_tick};
use core::sync::atomic::Ordering;
use tessera_devicetree::{DeviceTree, FdtError, HEADER_LEN};
use tessera_karch::{MemoryKind, MemoryRegion, PhysAddr, normalize_memory_map};

pub const EMPTY_REGION: MemoryRegion = MemoryRegion {
    base: PhysAddr::new(0),
    len: 0,
    kind: MemoryKind::Reserved,
};

/// Short label for a memory kind, for the boot map dump.
pub const fn kind_name(kind: MemoryKind) -> &'static str {
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

/// True when the device tree lies inside the kernel image's extent — in which
/// case the entry stub's `.bss` zeroing pass has already destroyed it.
///
/// Nothing on this platform places it there today (QEMU puts the tree 128 MiB
/// into RAM, far above the image), and no other port needs this check because
/// no other port's loader is free to choose. Here the tree's address is
/// whatever a stub QEMU wrote decided, and the failure mode if it ever
/// overlapped would be a *corrupt* tree read as a valid one, so it is worth a
/// line of arithmetic to turn into a named error.
pub fn tree_overlaps_image(dtb: usize, len: usize) -> bool {
    let image_start = &raw const __kernel_start as usize;
    let image_end = &raw const __kernel_end as usize;
    dtb < image_end && dtb.saturating_add(len) > image_start
}

/// Reads the firmware's device tree and returns the sorted, non-overlapping
/// physical memory map `BootInfo` requires.
///
/// Three sources contribute and they overlap by nature: the tree's RAM banks
/// cover everything, while the kernel image and the tree itself sit inside
/// them. They are gathered unresolved and handed to `normalize_memory_map`,
/// which settles the overlaps by precedence.
pub fn memory_map(dtb: usize, storage: &mut [MemoryRegion]) -> Result<&[MemoryRegion], FdtError> {
    // The blob's own length lives inside it, so the header is read first and
    // the rest only once its extent is known.
    //
    // SAFETY: `dtb` is the firmware handoff address, which the boot protocol
    // guarantees points at a device tree in memory the kernel owns; with the
    // MMU off every physical address is readable. Nothing is trusted about the
    // *contents*: `total_size` validates the magic and rejects an implausible
    // length before the larger slice is formed, and the reader bounds-checks
    // every access inside it.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header)?;
    // SAFETY: as above, now bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };

    let tree = DeviceTree::parse(blob)?;

    let mut gathered = [EMPTY_REGION; MAX_MEMORY_REGIONS];
    let mut count = tree.memory_regions(&mut gathered)?;
    count += tree.reserved_regions(&mut gathered[count..])?;

    for region in [
        // The image the loader just placed. It is linked at its physical
        // address, so the symbols are the physical extent.
        MemoryRegion {
            base: PhysAddr::new(&raw const __kernel_start as usize as u64),
            len: (&raw const __kernel_end as usize - &raw const __kernel_start as usize) as u64,
            kind: MemoryKind::KernelAndModules,
        },
        // The device tree itself, reclaimable once discovery has consumed it —
        // which has not happened yet, so it stays reserved for now.
        MemoryRegion {
            base: PhysAddr::new(dtb as u64),
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

/// Starts the tick, waits for interrupts to actually arrive, and stops it.
///
/// Programming a timer proves nothing on its own: the interrupt has to make
/// it through the GIC's distributor and CPU interface, the vector table, the
/// IRQ mode switch and the acknowledge before the hook runs. This waits on
/// the hook's own count, so only end-to-end delivery satisfies it.
pub fn timer_check() -> Result<u64, u32> {
    use tessera_karch::{InterruptControl, TimerControl};
    use tessera_karch_arm32::{Cpu, GenericTimer};

    tessera_karch_arm32::set_tick_hook(on_tick);
    GenericTimer::start_periodic(TICK_HZ);
    Cpu::enable();

    // Bounded wait: spin on the counter rather than trusting the timer, so a
    // controller that never delivers fails the check instead of hanging the
    // boot. The bound is counter ticks, read from the same counter the timer
    // compares against, so it is a real time limit and not a spin count.
    const WANTED: u64 = 3;
    let deadline = tessera_karch_arm32::read_counter()
        + u64::from(tessera_karch_arm32::counter_frequency()) * 2;
    while OBSERVED_TICKS.load(Ordering::Relaxed) < WANTED {
        if tessera_karch_arm32::read_counter() > deadline {
            Cpu::disable();
            tessera_karch_arm32::stop_timer();
            return Err(1);
        }
        core::hint::spin_loop();
    }

    Cpu::disable();
    tessera_karch_arm32::stop_timer();

    // The architecture's own tick count and the hook's must agree; a mismatch
    // means ticks were delivered that the hook never saw.
    let counted = GenericTimer::ticks();
    let observed = OBSERVED_TICKS.load(Ordering::Relaxed);
    if counted != observed {
        return Err(2);
    }
    if tessera_karch_arm32::unexpected_irqs() != 0 {
        return Err(3);
    }
    Ok(observed)
}
