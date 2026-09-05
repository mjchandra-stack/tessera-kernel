// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Checks that this machine cannot be made to read memory it was not given,
//! and that taking it away works.
//!
//! **The DMA-scoping claim on x86-64.** Until D338 a driver on this port
//! programmed a device with a physical address and the device was obeyed; the
//! only thing keeping a device out of memory it had no business in was the
//! driver choosing not to. Now one PCI function sits behind an address space
//! and the hardware refuses everything else.
//!
//! **What this file no longer does is program the unit.** [`crate::vtd`] brings
//! it up for the whole boot and implements [`kcore::devmgr::DmaMapper`], so the
//! aperture below is installed through the graph — a lease the graph records
//! and translations the graph asks for — rather than by this check writing
//! tables of its own. That is the difference between an IOMMU the machine has
//! and an IOMMU one check has.
//!
//! **Three things, in the order they can fail.** The device reaches the page it
//! was given, or a unit that aborts everything would pass for one that scopes.
//! It is refused one page along, **and the refusal is recorded**, or "nothing
//! arrived" is what a misconfiguration produces too. And when the lease ends it
//! stops reaching the address it *was* entitled to — which is the difference
//! between revocation being enforced and the kernel merely having forgotten.
//!
//! `edu` is the device for the reason the other port picked it: its DMA engine
//! is four register writes, so nothing has to be brought up first.
//!
//! Normative: docs/hardware/04-dma-and-memory-management.md,
//! docs/drivers/01-driver-framework.md ("DMA Safety")

use crate::*;

/// Where the device's BAR is mapped, beside the unit's own register page and
/// for the same reason.
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

/// The device in the graph, and who holds its lease.
///
/// A holder is named because the graph is what isolation consults to find one,
/// and a lease installed only in the hardware would be torn down with nobody
/// named.
pub(crate) const ISOLATION_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x220);
pub(crate) const ISOLATION_HOLDER_OBJ: ObjectId = ObjectId::from_raw(0x221);

/// What the device moves. Recognisable rather than zero: a page that was never
/// written and a page written with zeroes are the same page.
const DMA_PATTERN: u64 = 0x5654_4400_5544_3322;

/// How long the device is given to finish one transfer.
const DMA_POLL: u32 = 1_000_000;

/// Writes and reads the device's BAR.
fn edu_write64(offset: u64, value: u64) {
    // SAFETY: `EDU_BAR_VA` is a device mapping of the function's BAR page, made
    // by `isolation_check` and live for the whole of its call.
    unsafe { ((EDU_BAR_VA + offset) as *mut u64).write_volatile(value) }
}

fn edu_read64(offset: u64) -> u64 {
    // SAFETY: as `edu_write64`.
    unsafe { ((EDU_BAR_VA + offset) as *const u64).read_volatile() }
}

/// Starts one transfer and waits for the device to say it is done.
///
/// A transfer the unit refuses still completes as far as the device is
/// concerned — it asked, it was told no, and it stops — so this returning
/// `true` is not evidence the data moved, which is why memory is read
/// afterwards and the fault ring is read too.
fn edu_dma(src: u64, dst: u64, count: u64, cmd: u64) -> bool {
    edu_write64(EDU_DMA_SRC, src);
    edu_write64(EDU_DMA_DST, dst);
    edu_write64(EDU_DMA_COUNT, count);
    edu_write64(EDU_DMA_CMD, cmd);
    for _ in 0..DMA_POLL {
        if edu_read64(EDU_DMA_CMD) & EDU_DMA_START == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// How long a forged interrupt is given to arrive, or to be refused.
///
/// **Bounded and spent in full for the refusals**, which is what the halves
/// below cost: a blocked interrupt is a thing that does not happen, so the only
/// way to say it did not happen is to wait long enough that it would have.
const DELIVERY_POLL: u32 = 2_000_000;

/// The registers that make the device raise and drop an interrupt on demand.
const EDU_IRQ_RAISE: u64 = 0x60;
const EDU_IRQ_ACK: u64 = 0x64;

/// The same device under the interrupt check's own name.
///
/// Its own id because [`crate::vtd::Vtd::scope`] keys tables by **function**:
/// naming it twice is two checks pointing at one device, which is what
/// re-keying is for.
const INTERRUPT_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x222);

/// What the interrupt half of the boundary established.
pub(crate) struct InterruptOutcome {
    /// The handle this device was issued, and the vector its entry names.
    pub(crate) handle: u16,
    pub(crate) vector: u8,
    /// The function a handle was issued to that is not this one. The handle
    /// itself is not kept: the record of its refusal carries it, which is the
    /// copy worth reporting.
    pub(crate) foreign_source: u16,
    /// Interrupts that arrived on this device's vector, and on the one beside
    /// it — the one the message it wrote would have named if the message were
    /// still the interrupt.
    pub(crate) delivered: u64,
    pub(crate) elsewhere: u64,
    /// The record left by another function's handle, by a handle past the end
    /// of the table, by one inside it that was never issued, and by this
    /// device's own once it was taken back.
    pub(crate) refused_foreign: tessera_vtd::Fault,
    pub(crate) refused_beyond: tessera_vtd::Fault,
    pub(crate) refused_unissued: tessera_vtd::Fault,
    pub(crate) refused_revoked: tessera_vtd::Fault,
}

/// Writes one of the device's 32-bit registers.
fn edu_write32(offset: u64, value: u32) {
    // SAFETY: `EDU_BAR_VA` is a device mapping of the function's BAR page, made
    // by the check below and live for the whole of its call.
    unsafe { ((EDU_BAR_VA + offset) as *mut u32).write_volatile(value) }
}

/// Programs the device's interrupt message, makes it raise one, and answers
/// whether anything arrived.
///
/// **The message is the device's own field, which is what makes this a
/// forgery.** A function keeps the address and data it signals with in its
/// configuration space; boot writes them because boot is what knows where
/// interrupts go, but nothing about the hardware makes them boot's — a device
/// whose firmware chose its own would signal exactly the same way, and there is
/// no third party to notice. So programming a message that names a handle this
/// device was not issued *is* a device sending one, faithfully, and the only
/// thing that can refuse it is the unit.
///
/// **Unmasked around the raise and nowhere else.** Boot runs masked, so an
/// interrupt raised here would otherwise sit pending until some later check
/// enabled them and be counted against that one instead.
fn edu_raises(
    host: &tessera_pci::Host,
    config: &mut PortConfigSpace,
    bdf: tessera_pci::Bdf,
    capability: u16,
    address: u64,
    data: u32,
) -> Result<(), u32> {
    use tessera_karch::InterruptControl as _;
    tessera_pci::msi_program(host, config, bdf, capability, address, data).map_err(|_| 53u32)?;
    let before = crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst);
    Cpu::enable();
    edu_write32(EDU_IRQ_RAISE, 1);
    for _ in 0..DELIVERY_POLL {
        if crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst) != before {
            break;
        }
        core::hint::spin_loop();
    }
    Cpu::disable();
    // Dropped again, so the next raise is a fresh edge rather than a level the
    // device is still holding.
    edu_write32(EDU_IRQ_ACK, 1);
    Ok(())
}

/// Proves that an interrupt a device raises is one this kernel gave it, and
/// nothing else.
///
/// **This is the half of the boundary that DMA scoping cannot reach.** A
/// message-signalled interrupt is a write into a window the translation tables
/// never see: it is recognised by its address and turned into an interrupt
/// before any of the work D338 to D342 did applies. The device below is behind
/// an address space of its own for the whole of this check — it can reach no
/// memory at all — and it raises interrupts throughout, which is the fact that
/// makes this a separate mechanism rather than a corollary of the last one.
///
/// **Five things, in the order they can fail.** The device raises the interrupt
/// it was given. The vector that arrives is **the table's and not the
/// message's**, which is the whole mechanism in one measurement: the message
/// named no vector and one this kernel chose is what turned up. A handle
/// *another function* was issued is refused, which is the interrupt-side
/// counterpart of an out-of-aperture DMA and the reason an entry carries a
/// source id at all. A handle past the table and one inside it that was never
/// issued are refused too, each for its own recorded reason. And the device's
/// own handle stops working the moment it is taken back.
pub(crate) fn interrupt_isolation_check(
    unit: &mut crate::vtd::Vtd,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<InterruptOutcome>, u32> {
    if !unit.remaps_interrupts() || !pci_window_is_clear(memory_map) {
        return Ok(None);
    }
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
        tessera_pci::enumerate(&host, &mut config, window, &mut functions).map_err(|_| 30u32)?;
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.vendor == EDU_VENDOR && f.device == EDU_DEVICE)
    else {
        return Ok(None);
    };
    // Somebody else on this machine, so a handle can be issued to a function
    // that is not this one. Which function does not matter and is reported
    // rather than chosen: what the check needs is a source id that differs.
    let Some(other) = functions[..found]
        .iter()
        .find(|f| f.bdf != function.bdf)
        .map(|f| tessera_vtd::SourceId::new(f.bdf.bus, f.bdf.device, f.bdf.function))
    else {
        return Ok(None);
    };
    // MSI rather than MSI-X, because its message lives in configuration space:
    // there is no table to map and no transport to bring up, so the device can
    // be made to signal with four register writes.
    let capability =
        tessera_pci::find_capability(&host, &config, function.bdf, tessera_pci::CAP_MSI)
            .map_err(|_| 31u32)?
            .ok_or(32u32)?;
    let (bar_base, _) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .next()
        .ok_or(33u32)?;
    let frame = PhysFrame::from_base(PhysAddr::new(bar_base)).ok_or(34u32)?;
    let _ = kernel_vm.unmap_device_page(VirtAddr::new(EDU_BAR_VA));
    kernel_vm
        .map_device_page(
            VirtAddr::new(EDU_BAR_VA),
            frame,
            kcore::vm::DeviceReach::Kernel,
            frames,
        )
        .map_err(|_| 35u32)?;

    // **Behind an aperture for the whole of what follows, and it changes
    // nothing.** The check above left this device scoped and holding no lease,
    // and re-scoping it here under this check's own name empties its tables
    // again: every address it could name for memory is refused from here. It
    // goes on raising interrupts throughout, because an interrupt request is
    // not a memory access — which is the fact this check exists for, stated as
    // a step rather than a sentence.
    unit.scope(INTERRUPT_DEVICE_OBJ, function, frames)
        .map_err(|which| 70 + which)?;
    let source =
        tessera_vtd::SourceId::new(function.bdf.bus, function.bdf.device, function.bdf.function);

    // **The second message vector, not the first.** A remappable message names
    // no vector at all — its data word is zero, which in the format this kernel
    // used to program would have been vector zero. So a delivery on a vector
    // this check chose, and *not* on the one beside it, is the table having
    // chosen it rather than the device.
    let vector = tessera_karch_x86_64::MSI_VECTOR_BASE + 1;
    let handle = unit
        .issue_handle(source, vector)
        .map_err(|which| 60 + which)?;
    let foreign = unit
        .issue_handle(other, vector)
        .map_err(|which| 60 + which)?;

    // A fresh executive, and the bridge every device driver on this port is
    // woken through — so what counts a delivery here is what counts one there.
    // SAFETY: the boot CPU alone; no thread of any earlier check is live.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    tessera_karch_x86_64::set_device_irq_hook(crate::msi::msi_bridge_hook);
    crate::msi::forget_deliveries();
    unit.clear_faults();

    let slot = usize::from(vector - tessera_karch_x86_64::MSI_VECTOR_BASE);

    // **The handle it was given.**
    let (address, data) = tessera_vtd::remappable_message(handle);
    edu_raises(&host, &mut config, function.bdf, capability, address, data)?;
    let delivered = crate::msi::MSI_BY_VECTOR[slot].load(Ordering::SeqCst);
    let elsewhere = crate::msi::MSI_BY_VECTOR[0].load(Ordering::SeqCst);
    let issued_fault = unit.take_fault();

    // **A handle somebody else was given.** The entry is present and names this
    // same vector; the only thing wrong with it is who is asking.
    let (address, data) = tessera_vtd::remappable_message(foreign);
    edu_raises(&host, &mut config, function.bdf, capability, address, data)?;
    let refused_foreign = unit.wait_for_fault();
    let after_foreign = crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst);

    // **A handle past the end of the table.** The crudest forgery there is, and
    // the one a bounds check must catch.
    let beyond = crate::vtd::Vtd::handles_end();
    let (address, data) = tessera_vtd::remappable_message(beyond);
    edu_raises(&host, &mut config, function.bdf, capability, address, data)?;
    let refused_beyond = unit.wait_for_fault();
    let after_beyond = crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst);

    // **And one inside it that nobody was issued**, which is what every handle
    // this kernel has not handed out looks like.
    let unissued = crate::vtd::Vtd::handles_end() - 1;
    let (address, data) = tessera_vtd::remappable_message(unissued);
    edu_raises(&host, &mut config, function.bdf, capability, address, data)?;
    let refused_unissued = unit.wait_for_fault();
    let after_unissued = crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst);

    // **And away.** The handle it raised an interrupt through a moment ago is
    // taken back, and the same message stops working. Same device, same
    // message, same vector: the only thing that changed is that the handle is
    // no longer issued.
    unit.withdraw_handle(handle);
    let (address, data) = tessera_vtd::remappable_message(handle);
    edu_raises(&host, &mut config, function.bdf, capability, address, data)?;
    let refused_revoked = unit.wait_for_fault();
    let after_revoked = crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst);

    unit.withdraw_handle(foreign);
    let _ = kernel_vm.unmap_device_page(VirtAddr::new(EDU_BAR_VA));

    // The half that says this remaps rather than blocks.
    if delivered != 1 {
        return Err(36);
    }
    // **And that the table chose the vector.** The message named none.
    if elsewhere != 0 {
        return Err(37);
    }
    if issued_fault.is_some() {
        return Err(38);
    }
    // Each refusal: recorded, for its own reason, naming this device and the
    // handle it asked for — because "no interrupt arrived" is what a
    // misprogrammed unit produces too, and only the record separates them.
    let refused_foreign = refused_foreign.ok_or(39u32)?;
    if refused_foreign.reason != tessera_vtd::FaultReason::InterruptSourceMismatch {
        return Err(40);
    }
    if refused_foreign.source != source || refused_foreign.interrupt_handle() != foreign {
        return Err(41);
    }
    if after_foreign != delivered {
        return Err(42);
    }
    let refused_beyond = refused_beyond.ok_or(43u32)?;
    if refused_beyond.reason != tessera_vtd::FaultReason::InterruptIndexOutOfRange {
        return Err(44);
    }
    if after_beyond != delivered {
        return Err(45);
    }
    let refused_unissued = refused_unissued.ok_or(46u32)?;
    if refused_unissued.reason != tessera_vtd::FaultReason::InterruptEntryNotPresent {
        return Err(47);
    }
    if refused_unissued.interrupt_handle() != unissued {
        return Err(48);
    }
    if after_unissued != delivered {
        return Err(49);
    }
    let refused_revoked = refused_revoked.ok_or(50u32)?;
    if refused_revoked.reason != tessera_vtd::FaultReason::InterruptEntryNotPresent {
        return Err(51);
    }
    if refused_revoked.interrupt_handle() != handle {
        return Err(52);
    }
    if after_revoked != delivered {
        return Err(54);
    }

    Ok(Some(InterruptOutcome {
        handle,
        vector,
        foreign_source: other.0,
        delivered,
        elsewhere,
        refused_foreign,
        refused_beyond,
        refused_unissued,
        refused_revoked,
    }))
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
    pub(crate) outside: tessera_vtd::Fault,
    /// And the one the revoked address left.
    pub(crate) revoked: tessera_vtd::Fault,
}

/// Puts one PCI function behind a leased aperture and proves the boundary in
/// three directions: in, out, and away.
pub(crate) fn isolation_check(
    unit: &mut crate::vtd::Vtd,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    direct_map_base: u64,
) -> Result<Option<IsolationOutcome>, u32> {
    use kcore::devmgr::{DeviceAperture, DmaMapper as _};

    if !pci_window_is_clear(memory_map) {
        return Err(1);
    }
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
        tessera_pci::enumerate(&host, &mut config, window, &mut functions).map_err(|_| 2u32)?;
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.vendor == EDU_VENDOR && f.device == EDU_DEVICE)
    else {
        return Ok(None);
    };
    let (bar_base, bar_len) = function.bars.iter().flatten().copied().next().ok_or(3u32)?;

    // The device's registers, as their own uncached page.
    let frame = PhysFrame::from_base(PhysAddr::new(bar_base)).ok_or(4u32)?;
    let _ = kernel_vm.unmap_device_page(VirtAddr::new(EDU_BAR_VA));
    kernel_vm
        .map_device_page(
            VirtAddr::new(EDU_BAR_VA),
            frame,
            kcore::vm::DeviceReach::Kernel,
            frames,
        )
        .map_err(|_| 5u32)?;

    // **First, that pass-through is real.** Translation has been on since this
    // boot's devices were enumerated, and every function the kernel has nothing
    // to say about was given an entry that passes its addresses through. This
    // device still has one, so a transfer naming a *physical* address must
    // land — and if the entry were missing it would be aborted instead. It is
    // checked here rather than assumed because `edu` is the only function on
    // this machine whose transactions reach the unit at all: QEMU's virtio
    // devices bypass a vIOMMU unless they negotiate `VIRTIO_F_ACCESS_PLATFORM`,
    // which this tree's virtio core does not, so nothing else on the boot could
    // tell a working pass-through entry from an absent one.
    let scratch = frames.alloc().ok_or(6u32)?.base().as_u64();
    crate::vtd::zero_frame(direct_map_base, scratch);
    unit.clear_faults();
    crate::vtd::direct_write64(direct_map_base, scratch, 0, DMA_PATTERN);
    let _ = edu_dma(scratch, EDU_BUFFER, 8, EDU_DMA_START);
    crate::vtd::direct_write64(direct_map_base, scratch, 0, 0);
    let _ = edu_dma(EDU_BUFFER, scratch, 8, EDU_DMA_START | EDU_DMA_TO_MEMORY);
    let passed_through = crate::vtd::direct_read64(direct_map_base, scratch, 0);
    let passthrough_fault = unit.take_fault();

    // **Out of pass-through and into an address space of its own.** Every other
    // function on this machine keeps passing its addresses through, which is
    // what lets translation stay on for the whole boot.
    unit.scope(ISOLATION_DEVICE_OBJ, function, frames)
        .map_err(|which| 100 + which)?;
    let source = unit.source_of(ISOLATION_DEVICE_OBJ).ok_or(23u32)?;

    // A fresh executive holding this device and nothing else, so the graph
    // state read below is this check's.
    // SAFETY: the boot CPU alone; no thread of any earlier check is live.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    exec_ref()
        .device_register_mmio(
            ISOLATION_DEVICE_OBJ,
            bar_base,
            bar_len,
            kcore::rights::Rights::READ,
        )
        .map_err(|_| 7u32)?;

    // **The lease is the graph's, and the translations are the mapper's.** A
    // lease recorded only in the hardware would be one nothing could revoke on
    // a holder's behalf; an aperture recorded only in the graph would be one
    // the device never notices.
    let (base, len) = unit.begin_lease(ISOLATION_DEVICE_OBJ).map_err(|_| 8u32)?;
    exec_ref()
        .device_set_aperture(
            ISOLATION_DEVICE_OBJ,
            ISOLATION_HOLDER_OBJ,
            DeviceAperture::new(base, len.min(FRAME_SIZE)),
            // No deadline: this lease exists for the length of one check.
            None,
        )
        .map_err(|_| 9u32)?;

    let target = frames.alloc().ok_or(10u32)?.base().as_u64();
    crate::vtd::zero_frame(direct_map_base, target);
    unit.map(ISOLATION_DEVICE_OBJ, base, target, FRAME_SIZE)
        .map_err(|_| 11u32)?;
    unit.clear_faults();

    // **Inside the aperture.** The pattern goes into the page the device was
    // given, the device reads it into its own buffer, the page is cleared, and
    // the device writes it back. Reading it out afterwards is what says the
    // transfer happened: a transfer that was refused leaves the cleared page
    // cleared.
    crate::vtd::direct_write64(direct_map_base, target, 0, DMA_PATTERN);
    let read_done = edu_dma(base, EDU_BUFFER, 8, EDU_DMA_START);
    crate::vtd::direct_write64(direct_map_base, target, 0, 0);
    let write_done = edu_dma(EDU_BUFFER, base, 8, EDU_DMA_START | EDU_DMA_TO_MEMORY);
    let inside = crate::vtd::direct_read64(direct_map_base, target, 0);

    // **Outside it.** The next page along, inside the same leaf table as the
    // one that works — so what refuses it is the entry being absent rather than
    // the walk failing higher up, which a distant address could not
    // distinguish.
    let outside_iova = base + FRAME_SIZE;
    let _ = edu_dma(
        EDU_BUFFER,
        outside_iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    let outside = unit.wait_for_fault();

    // **And away.** The lease ends, and the address the device was reaching a
    // moment ago through an address the graph issued is refused. Same address,
    // same device, same transfer: the only thing that changed is that the lease
    // is over.
    unit.end_lease(ISOLATION_DEVICE_OBJ);
    crate::vtd::direct_write64(direct_map_base, target, 0, 0);
    let _ = edu_dma(EDU_BUFFER, base, 8, EDU_DMA_START | EDU_DMA_TO_MEMORY);
    let after = crate::vtd::direct_read64(direct_map_base, target, 0);
    let revoked = unit.wait_for_fault();

    let _ = kernel_vm.unmap_device_page(VirtAddr::new(EDU_BAR_VA));

    if !read_done || !write_done {
        return Err(12);
    }
    // The pass-through half, judged here with the rest. Both halves: the data
    // moved, and the unit recorded nothing — a transfer that was refused and
    // one that was never attempted leave the same cleared page, and the fault
    // ring is what separates them.
    if passed_through != DMA_PATTERN {
        return Err(24);
    }
    if passthrough_fault.is_some() {
        return Err(25);
    }
    // The half that says this is scoping rather than aborting.
    if inside != DMA_PATTERN {
        return Err(13);
    }
    let outside = outside.ok_or(14u32)?;
    if outside.source != source {
        return Err(15);
    }
    if outside.address != outside_iova {
        return Err(16);
    }
    // A refusal for the wrong reason: the function reached the unit but never
    // reached its own tables, which means the root or context entry is wrong
    // rather than the aperture being enforced.
    if outside.reason == tessera_vtd::FaultReason::RootNotPresent
        || outside.reason == tessera_vtd::FaultReason::ContextNotPresent
    {
        return Err(17);
    }
    // And the half about taking it away. **The page is checked first**: a
    // revocation that left the translation live would move the pattern, and a
    // fault ring nobody looked at would not say so.
    if after != 0 {
        return Err(18);
    }
    let revoked = revoked.ok_or(19u32)?;
    if revoked.source != source {
        return Err(20);
    }
    if revoked.address != base {
        return Err(21);
    }
    if revoked.reason == tessera_vtd::FaultReason::RootNotPresent
        || revoked.reason == tessera_vtd::FaultReason::ContextNotPresent
    {
        return Err(22);
    }

    Ok(Some(IsolationOutcome {
        version: unit.version(),
        source: source.0,
        inside,
        outside,
        revoked,
    }))
}
