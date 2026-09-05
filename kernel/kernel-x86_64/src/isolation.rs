// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Checks that this machine cannot be made to read memory it was not given.
//!
//! **This is the DMA-scoping claim on x86-64.** Until now a driver on this port
//! programmed a device with a physical address and the device was obeyed; the
//! only thing keeping a device out of memory it had no business in was the
//! driver choosing not to. Here one PCI function is put behind an address space
//! — a root entry for its bus, a context entry for its function, and a
//! second-level table with a single page in it — and the hardware refuses
//! everything else.
//!
//! **The proof needs both halves.** A transfer *inside* the aperture must land,
//! or a unit that aborts everything would pass for one that scopes; a transfer
//! *outside* must not, and the fault record must say so, or "nothing arrived"
//! is indistinguishable from a misconfiguration. `edu` is the device for the
//! reason the other port picked it: its DMA engine is four register writes, so
//! nothing has to be brought up first.
//!
//! **Translation is on for exactly this check.** Enabling it globally makes
//! every function's transactions pass through tables that describe one of them,
//! so it is switched on around the two transfers and off again before anything
//! else on this machine moves data. Nothing is in flight while it is on: the
//! checks run one after another on the boot CPU and no device has been told to
//! do anything.
//!
//! Normative: docs/hardware/04-dma-and-memory-management.md,
//! docs/drivers/01-driver-framework.md ("DMA Safety")

use crate::*;

/// Where the unit's register block and the device's BAR are mapped.
///
/// Pages of their own beside the interrupt controller's, and for `msi`'s
/// reason: the direct map reaches physical memory as cacheable 2 MiB pages, and
/// a device register written through a cacheable mapping works under an
/// emulator and is a fault on hardware.
const VTD_VA: u64 = crate::INTERRUPT_MMIO_BASE + 3 * FRAME_SIZE;
const EDU_BAR_VA: u64 = crate::INTERRUPT_MMIO_BASE + 4 * FRAME_SIZE;

/// The `edu` device, which exists to be driven by exactly this kind of check.
const EDU_VENDOR: u16 = 0x1234;
const EDU_DEVICE: u16 = 0x11e8;

/// Its DMA engine: a source, a destination, a count and a command.
const EDU_DMA_SRC: u64 = 0x80;
const EDU_DMA_DST: u64 = 0x88;
const EDU_DMA_COUNT: u64 = 0x90;
const EDU_DMA_CMD: u64 = 0x98;
/// The device-side address of its own buffer, which is not an address the
/// remapping unit ever sees: a transfer between the buffer and itself never
/// leaves the device.
const EDU_BUFFER: u64 = 0x4_0000;
const EDU_DMA_START: u64 = 1 << 0;
/// Clear means memory to device, set means device to memory.
const EDU_DMA_TO_MEMORY: u64 = 1 << 1;

/// The one page the device is given, and a page it is not.
///
/// **Adjacent on purpose.** The refused address is the next page along, inside
/// the same leaf table as the one that works — so what refuses it is the entry
/// being absent rather than the walk failing higher up, which a distant address
/// could not distinguish.
const APERTURE_IOVA: u64 = 0x4000;
const OUTSIDE_IOVA: u64 = APERTURE_IOVA + FRAME_SIZE;

/// What the device moves. Recognisable rather than zero: a page that was never
/// written and a page written with zeroes are the same page.
const DMA_PATTERN: u64 = 0x5654_4400_5544_3322;

/// The domain the one function is put in. Any number the unit's `CAP.ND`
/// allows; one is the first that is not the reserved zero some units use for
/// pass-through.
const DOMAIN_ID: u16 = 1;

/// How long a register poll waits before giving up. Bounded, because a unit
/// that never reports a command took is one this check must report rather than
/// hang on.
const REGISTER_POLL: u32 = 1_000_000;

/// The unit's register block, as [`tessera_vtd::Registers`].
struct VtdWindow {
    base: u64,
}

impl tessera_vtd::Registers for VtdWindow {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is a device mapping of the unit's register page, made
        // by `isolation_check` and live for the whole of its call.
        unsafe { ((self.base + offset as u64) as *const u32).read_volatile() }
    }

    fn write32(&mut self, offset: usize, value: u32) {
        // SAFETY: as `read32`.
        unsafe { ((self.base + offset as u64) as *mut u32).write_volatile(value) }
    }

    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: as `read32`.
        unsafe { ((self.base + offset as u64) as *const u64).read_volatile() }
    }

    fn write64(&mut self, offset: usize, value: u64) {
        // SAFETY: as `read32`.
        unsafe { ((self.base + offset as u64) as *mut u64).write_volatile(value) }
    }
}

/// Reads and writes a physical address through the direct map.
///
/// The tables this check builds are ordinary memory the unit walks, so they are
/// written the way any other kernel structure is.
fn direct_write64(direct_map_base: u64, phys: u64, offset: u64, value: u64) {
    // SAFETY: `phys` is a frame this check allocated, and the direct map covers
    // all of physical memory for the life of the kernel.
    unsafe { ((direct_map_base + phys + offset) as *mut u64).write_volatile(value) }
}

fn direct_read64(direct_map_base: u64, phys: u64, offset: u64) -> u64 {
    // SAFETY: as `direct_write64`.
    unsafe { ((direct_map_base + phys + offset) as *const u64).read_volatile() }
}

fn zero_frame(direct_map_base: u64, phys: u64) {
    for offset in (0..FRAME_SIZE).step_by(8) {
        direct_write64(direct_map_base, phys, offset, 0);
    }
}

/// Writes one 32-bit word of the device's BAR.
fn edu_write64(base: u64, offset: u64, value: u64) {
    // SAFETY: `base` is a device mapping of the function's BAR page, made by
    // `isolation_check` and live for the whole of its call.
    unsafe { ((base + offset) as *mut u64).write_volatile(value) }
}

fn edu_read64(base: u64, offset: u64) -> u64 {
    // SAFETY: as `edu_write64`.
    unsafe { ((base + offset) as *const u64).read_volatile() }
}

/// Starts one transfer and waits for the device to say it is done.
///
/// Answers whether it finished. A transfer the unit refuses still completes as
/// far as the device is concerned — it asked, it was told no, and it stops —
/// so this returning `true` is not evidence the data moved, which is why the
/// memory is read afterwards.
fn edu_dma(base: u64, src: u64, dst: u64, count: u64, cmd: u64) -> bool {
    edu_write64(base, EDU_DMA_SRC, src);
    edu_write64(base, EDU_DMA_DST, dst);
    edu_write64(base, EDU_DMA_COUNT, count);
    edu_write64(base, EDU_DMA_CMD, cmd);
    for _ in 0..REGISTER_POLL {
        if edu_read64(base, EDU_DMA_CMD) & EDU_DMA_START == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// What the run established.
pub(crate) struct IsolationOutcome {
    /// The unit's version register, as read.
    pub(crate) version: u32,
    /// The function that was scoped.
    pub(crate) source: u16,
    /// What came back through the aperture.
    pub(crate) inside: u64,
    /// The record the refused transfer left.
    pub(crate) fault: tessera_vtd::Fault,
}

/// Waits for a global-status bit to take the value a command asked for.
fn wait_status(unit: &VtdWindow, bit: u32, set: bool) -> bool {
    use tessera_vtd::Registers as _;
    for _ in 0..REGISTER_POLL {
        if (unit.read32(tessera_vtd::reg::GSTS) & bit != 0) == set {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Puts one PCI function behind a one-page aperture and proves the boundary in
/// both directions.
pub(crate) fn isolation_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    direct_map_base: u64,
) -> Result<Option<IsolationOutcome>, u32> {
    use tessera_vtd::Registers as _;

    // SAFETY: the kernel's own tables are active, so the direct map covers the
    // firmware's description of itself.
    let Some(remapping) = (unsafe { crate::acpi::remapping_unit(direct_map_base) }) else {
        return Ok(None);
    };

    let host = tessera_pci::Host {
        ecam_base: 0,
        ecam_len: 0x1000_0000,
        first_bus: 0,
        last_bus: 0,
    };
    let mut config = PortConfigSpace;
    let window = tessera_pci::Window {
        cpu_base: PCI_WINDOW_BASE,
        bus_base: PCI_WINDOW_BASE,
        len: PCI_WINDOW_LEN,
        is_32bit: true,
    };
    let mut functions = [PCI_BLANK_FUNCTION; MAX_PCI_FUNCTIONS];
    let found =
        tessera_pci::enumerate(&host, &mut config, window, &mut functions).map_err(|_| 1u32)?;
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.vendor == EDU_VENDOR && f.device == EDU_DEVICE)
    else {
        return Ok(None);
    };
    let (bar_base, _) = function.bars.iter().flatten().copied().next().ok_or(2u32)?;
    let source =
        tessera_vtd::SourceId::new(function.bdf.bus, function.bdf.device, function.bdf.function);

    // Both register blocks, each as its own uncached page.
    for (virt, phys) in [(VTD_VA, remapping.register_base), (EDU_BAR_VA, bar_base)] {
        let frame = PhysFrame::from_base(PhysAddr::new(phys)).ok_or(3u32)?;
        let _ = kernel_vm.unmap_device_page(VirtAddr::new(virt));
        kernel_vm
            .map_device_page(
                VirtAddr::new(virt),
                frame,
                kcore::vm::DeviceReach::Kernel,
                frames,
            )
            .map_err(|_| 4u32)?;
    }
    let mut unit = VtdWindow { base: VTD_VA };
    let version = unit.read32(tessera_vtd::reg::VER);
    let cap = unit.read64(tessera_vtd::reg::CAP);
    let ecap = unit.read64(tessera_vtd::reg::ECAP);
    let width = tessera_vtd::address_width(cap).map_err(|_| 5u32)?;

    // **The tables, built from the leaf up.** Each level's frame is zeroed
    // before anything points at it: a table the unit walks into that still
    // holds whatever the last owner left is a set of translations nobody wrote.
    let mut below = None;
    for level in 1..=width.levels {
        let table = frames.alloc().ok_or(6u32)?.base().as_u64();
        zero_frame(direct_map_base, table);
        if let Some(next) = below {
            // **The index is this table's level, not the one below it.** An
            // entry in a level-`n` table is selected by the address bits that
            // level owns; using the lower level's bits builds a chain that
            // walks somewhere else and looks exactly like an aperture that
            // refuses everything.
            let index = tessera_vtd::level_index(APERTURE_IOVA, level) as u64;
            let entry = tessera_vtd::table_entry(next).map_err(|_| 7u32)?;
            direct_write64(direct_map_base, table, index * 8, entry);
        }
        below = Some(table);
    }
    let second_level = below.ok_or(8u32)?;
    let leaf = {
        // Walk back down to the leaf, which is where the one page goes. The
        // loop above built the chain; this reads it back rather than
        // remembering it, so what is written is reached the same way the unit
        // will reach it.
        let mut table = second_level;
        for level in (2..=width.levels).rev() {
            let index = tessera_vtd::level_index(APERTURE_IOVA, level) as u64;
            let entry = direct_read64(direct_map_base, table, index * 8);
            table = entry & 0x000f_ffff_ffff_f000;
        }
        table
    };
    let target = frames.alloc().ok_or(9u32)?.base().as_u64();
    zero_frame(direct_map_base, target);
    direct_write64(
        direct_map_base,
        leaf,
        tessera_vtd::level_index(APERTURE_IOVA, 1) as u64 * 8,
        tessera_vtd::page_entry(target).map_err(|_| 10u32)?,
    );

    // The context table for this bus, and the root table above it.
    let context_table = frames.alloc().ok_or(11u32)?.base().as_u64();
    zero_frame(direct_map_base, context_table);
    let context = tessera_vtd::context_entry(second_level, width, DOMAIN_ID).map_err(|_| 12u32)?;
    let context_offset = source.context_index() as u64 * 16;
    direct_write64(direct_map_base, context_table, context_offset, context[0]);
    direct_write64(
        direct_map_base,
        context_table,
        context_offset + 8,
        context[1],
    );

    let root_table = frames.alloc().ok_or(13u32)?.base().as_u64();
    zero_frame(direct_map_base, root_table);
    let root = tessera_vtd::root_entry(context_table).map_err(|_| 14u32)?;
    let root_offset = source.bus() as u64 * 16;
    direct_write64(direct_map_base, root_table, root_offset, root[0]);
    direct_write64(direct_map_base, root_table, root_offset + 8, root[1]);

    // **Point the unit at the tables, then turn translation on**, each command
    // waited for: the register is write-to-set and a second command written
    // before the first is acknowledged is a request the hardware is not defined
    // to answer.
    unit.write64(tessera_vtd::reg::RTADDR, root_table);
    unit.write32(tessera_vtd::reg::GCMD, tessera_vtd::gcmd::SRTP);
    if !wait_status(&unit, tessera_vtd::gsts::RTPS, true) {
        return Err(15);
    }
    // Nothing is cached yet on a unit that has never translated, and it is
    // invalidated anyway: what this costs is two register writes, and what it
    // buys is that the check does not depend on that being true.
    unit.write64(
        tessera_vtd::reg::CCMD,
        tessera_vtd::CCMD_ICC | tessera_vtd::CCMD_CIRG_GLOBAL,
    );
    let iotlb = tessera_vtd::iotlb_invalidate_offset(ecap);
    unit.write64(
        iotlb,
        tessera_vtd::IOTLB_IVT | tessera_vtd::IOTLB_IIRG_GLOBAL,
    );
    // Any fault the machine had recorded before now is not this check's, and a
    // stale record would answer the question below without the device asking.
    unit.write32(tessera_vtd::reg::FSTS, unit.read32(tessera_vtd::reg::FSTS));
    let recording = tessera_vtd::fault_recording(cap);
    for record in 0..recording.count {
        unit.write64(
            recording.offset + record * 16 + 8,
            tessera_vtd::FAULT_CLEAR_HIGH,
        );
    }
    unit.write32(tessera_vtd::reg::GCMD, tessera_vtd::gcmd::TE);
    if !wait_status(&unit, tessera_vtd::gsts::TES, true) {
        return Err(16);
    }

    // **Inside the aperture.** The pattern goes into the page the device was
    // given, the device reads it into its own buffer through the aperture, the
    // page is cleared, and the device writes it back. Reading it out of the
    // page afterwards is what says the transfer happened — a transfer that was
    // refused leaves the cleared page cleared.
    direct_write64(direct_map_base, target, 0, DMA_PATTERN);
    let read_done = edu_dma(EDU_BAR_VA, APERTURE_IOVA, EDU_BUFFER, 8, EDU_DMA_START);
    direct_write64(direct_map_base, target, 0, 0);
    let write_done = edu_dma(
        EDU_BAR_VA,
        EDU_BUFFER,
        APERTURE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    let inside = direct_read64(direct_map_base, target, 0);

    // **Outside it.** The next page along, which no entry describes. The device
    // is told to write there and the unit refuses; what the check reads is the
    // record it left.
    let _ = edu_dma(
        EDU_BAR_VA,
        EDU_BUFFER,
        OUTSIDE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    let mut fault = tessera_vtd::Fault {
        valid: false,
        source: tessera_vtd::SourceId(0),
        address: 0,
        reason: tessera_vtd::FaultReason::Other(0),
        read: false,
    };
    for _ in 0..REGISTER_POLL {
        if unit.read32(tessera_vtd::reg::FSTS) & tessera_vtd::fsts::PPF != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    for record in 0..recording.count {
        let low = unit.read64(recording.offset + record * 16);
        let high = unit.read64(recording.offset + record * 16 + 8);
        let decoded = tessera_vtd::decode_fault(low, high);
        if decoded.valid {
            fault = decoded;
            unit.write64(
                recording.offset + record * 16 + 8,
                tessera_vtd::FAULT_CLEAR_HIGH,
            );
        }
    }
    unit.write32(tessera_vtd::reg::FSTS, unit.read32(tessera_vtd::reg::FSTS));

    // **Translation back off before anything else on this machine moves data.**
    // The tables describe one function; leaving them in front of every other
    // one would abort the next transfer any of them made.
    unit.write32(tessera_vtd::reg::GCMD, 0);
    if !wait_status(&unit, tessera_vtd::gsts::TES, false) {
        return Err(17);
    }
    let _ = kernel_vm.unmap_device_page(VirtAddr::new(EDU_BAR_VA));
    let _ = kernel_vm.unmap_device_page(VirtAddr::new(VTD_VA));

    if !read_done || !write_done {
        return Err(18);
    }
    // The half that says this is scoping rather than aborting.
    if inside != DMA_PATTERN {
        return Err(19);
    }
    // And the half that says it is scoping rather than passing everything
    // through. A missing record is the failure this check exists for: "the DMA
    // did not arrive" is what a misconfiguration produces too.
    if !fault.valid {
        return Err(20);
    }
    if fault.source != source {
        return Err(21);
    }
    if fault.address != OUTSIDE_IOVA {
        return Err(22);
    }
    if fault.reason == tessera_vtd::FaultReason::RootNotPresent
        || fault.reason == tessera_vtd::FaultReason::ContextNotPresent
    {
        // The function reached the unit but never reached its own tables, which
        // means the root or context entry is wrong rather than the aperture
        // being enforced — a refusal for the wrong reason.
        return Err(23);
    }

    Ok(Some(IsolationOutcome {
        version,
        source: source.0,
        inside,
        fault,
    }))
}
