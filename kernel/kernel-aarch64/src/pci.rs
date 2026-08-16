// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! PCIe on this machine: the host bridge, its ECAM and BAR windows, MSI and
//! MSI-X, and the device-tree lookups that find them.
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

/// Programs a PCI device's message-signalled interrupt and makes it send one.
///
/// This is the claim the milestone rests on: **a PCI device raised a
/// message-signalled interrupt.** `edu` is used because it can be made to
/// send one from a single register write — every other endpoint on this
/// machine needs its transport brought up first, which is a different
/// milestone. It carries MSI rather than MSI-X, and that is why both are
/// implemented: MSI keeps its address and data in config space, so nothing
/// has to be mapped before the device can be armed.
///
/// The address programmed is the v2m doorbell and the data is an SPI from the
/// frame's own range, so what the device sends arrives as an ordinary wired
/// interrupt — which is why nothing downstream of the GIC had to change.
///
/// Returns `(spi, deliveries)`.
pub(crate) fn msi_check(
    host: &tessera_devicetree::PciHost,
    frame: &mut V2mFrame,
    function: &tessera_pci::Function,
) -> Result<(u32, u32), u32> {
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    let capability =
        tessera_pci::find_capability(&bridge, &config, function.bdf, tessera_pci::CAP_MSI)
            .map_err(|_| 1u32)?
            .ok_or(2u32)?;
    let spi = frame.allocate().ok_or(3u32)?;
    let (bar, _) = function.first_bar().ok_or(4u32)?;

    MSI_SPI.store(spi, Ordering::SeqCst);
    MSI_DELIVERED.store(0, Ordering::SeqCst);

    tessera_pci::msi_program(
        &bridge,
        &mut config,
        function.bdf,
        capability,
        frame.doorbell(),
        spi,
    )
    .map_err(|_| 5u32)?;
    // SAFETY: both are interrupt-controller register writes. The edge
    // configuration must come first: the doorbell raises and drops the SPI in
    // one action, and a level-triggered input has nothing left to latch.
    unsafe {
        tessera_karch_aarch64::set_irq_edge_triggered(spi);
        tessera_karch_aarch64::enable_irq(spi);
    }

    // Make the device send. The write is to its own BAR, which this kernel
    // placed and mapped; everything after it is the machine's doing.
    let mut window = BarWindow { base: bar };
    {
        use tessera_pci::ConfigSpace;
        window.write32(EDU_RAISE, 1);
    }

    // Wait for it, bounded. An interrupt that never arrives must fail the
    // check rather than hang the boot — the trap this port has hit before
    // (D85) is a wait with nothing to end it.
    //
    // **Spinning, deliberately not `wfi`.** This check runs before the
    // periodic tick is started, so `wfi` would have nothing but this very
    // interrupt to wake it — and if the message never arrives it blocks for
    // ever, turning a failing check into a hung boot. That is the trap this
    // port has hit before (D85, D104); a spin makes the budget mean something.
    let mut budget = 2_000_000u32;
    while MSI_DELIVERED.load(Ordering::SeqCst) == 0 && budget > 0 {
        // SAFETY: unmasking is re-done every iteration because returning from
        // an exception restores the boot context with IRQs masked again.
        unsafe {
            core::arch::asm!(
                "msr daifclr, #2",
                "nop",
                "msr daifset, #2",
                options(nomem, nostack)
            );
        }
        budget -= 1;
    }

    // Read the device's own interrupt status *before* acknowledging: the ack
    // clears it, so measuring afterwards says nothing about whether the raise
    // ever landed.
    // The device's own view, read *before* acknowledging — the ack clears it,
    // so measuring afterwards says nothing about whether the raise landed.
    // Checking it separates "the device never asked" from "the message never
    // arrived", which is the split that found the bug behind this check.
    let raised = {
        use tessera_pci::ConfigSpace;
        let raised = window.read32(EDU_IRQ_STATUS);
        window.write32(EDU_ACK, 1);
        raised
    };
    if raised == 0 {
        return Err(7);
    }
    let delivered = MSI_DELIVERED.load(Ordering::SeqCst);
    if delivered == 0 {
        return Err(6);
    }
    Ok((spi, delivered))
}

/// Configures MSI-X on a function that has it, and reports **only that**.
///
/// What is proven here is narrow and the verdict says so: the capability was
/// found, its table located in a BAR this kernel placed, an entry programmed
/// with the same doorbell `edu` uses, and MSI-X enabled — read back from the
/// device. What is **not** proven is the device choosing to send one, because
/// making a virtio endpoint raise MSI-X means feature negotiation, queue
/// setup and vector assignment: the transport, which is the next milestone.
/// Reporting this as "MSI-X works" would be the dishonest version.
pub(crate) fn msix_configure_check(
    host: &tessera_devicetree::PciHost,
    frame: &mut V2mFrame,
    functions: &[tessera_pci::Function],
) {
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    for function in functions {
        let Ok(Some(capability)) =
            tessera_pci::find_capability(&bridge, &config, function.bdf, tessera_pci::CAP_MSIX)
        else {
            continue;
        };
        let Ok(table) =
            tessera_pci::msix_table(&bridge, &config, function.bdf, capability, function)
        else {
            continue;
        };
        let Some((bar, _)) = function.bars[table.bar] else {
            continue;
        };
        let Some(spi) = frame.allocate() else {
            kprintln!("msix: FATAL: the v2m frame has no SPI left to assign");
            SemihostingExit::exit(ExitCode::Failure)
        };
        let mut window = BarWindow {
            base: bar + u64::from(table.offset),
        };
        if tessera_pci::program_msix_entry(&mut window, 0, frame.doorbell(), spi).is_err()
            || tessera_pci::msix_enable(&bridge, &mut config, function.bdf, capability).is_err()
        {
            kprintln!("msix: FATAL: entry not programmed");
            SemihostingExit::exit(ExitCode::Failure)
        }
        // Read the entry back from the device rather than trusting the write.
        let (address, data, control) = {
            use tessera_pci::ConfigSpace;
            (
                u64::from(window.read32(0)) | (u64::from(window.read32(4)) << 32),
                window.read32(8),
                window.read32(12),
            )
        };
        if address != frame.doorbell()
            || data != spi
            || control & tessera_pci::MSIX_VECTOR_MASKED != 0
        {
            kprintln!(
                "msix: FATAL: read back address {address:#x} data {data} control {control:#x}"
            );
            SemihostingExit::exit(ExitCode::Failure)
        }
        // msix: OK — {:04x}:{:04x} has MSI-X with {} vector(s); vector 0 is
        // programmed to the v2m doorbell at {address:#x} with SPI {data} and
        // unmasked, read back from the device. NOT proven: the device sending
        // one, which needs its transport
        kprintln!(
            "msix: OK — vendor={:04x}, device={:04x}, entries={}, address={address:#x}, data={data}",
            function.vendor,
            function.device,
            table.entries
        );
        return;
    }
    kprintln!("msix: skipped — no function on this bus offers MSI-X");
}

/// The machine's PCI host bridge, if it has one.
///
/// **Read through the direct map, not at `dtb` itself.** `dtb` is the physical
/// address the firmware handed over, and every other reader on this port uses
/// it *before* the MMU switch, while the boot stub's identity map still
/// covers RAM. Afterwards the low half maps only `DEVICE_RANGE` — one
/// gigabyte of device registers — and the blob, which lives in RAM above
/// that, is no longer at its physical address. Reading it there is a data
/// abort, which is how this was found.
pub(crate) fn pci_host(dtb: u64) -> Option<tessera_devicetree::PciHost> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: the blob lies in RAM, which the high half direct-maps, so
    // `DIRECT_MAP_BASE + dtb` is readable. Nothing is trusted about the
    // contents: `total_size` validates the magic and rejects an implausible
    // length before the larger slice is formed, and the reader bounds-checks
    // every access inside it.
    let header = unsafe { core::slice::from_raw_parts(at, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above, bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    DeviceTree::parse(blob).ok()?.pci_host().ok()?
}

/// Maps a PCI host bridge's windows into the **high half**, and says why they
/// cannot simply be reached the way every other device on this port is.
///
/// Every device here is reached at its physical address through the low-half
/// identity map of `DEVICE_RANGE` — which is 1 GiB, and this machine puts ECAM
/// at 0x40_1000_0000. Widening the blanket range to reach it would identity-map
/// 256 GiB of nothing. Worse, the low half is `TTBR0`, which a per-process
/// address space *replaces* (D76): a mapping made there stops existing the
/// moment a driver runs. So the windows are mapped where the kernel's own
/// mappings live, at `DIRECT_MAP_BASE + phys`, which survives every process
/// switch — the same place the RISC-V port reaches devices from.
///
/// Both windows are needed and for different reasons: config space is how the
/// bus is enumerated, and the memory window is where the BARs this kernel
/// places actually answer.
pub(crate) fn map_pci_windows(
    space: &mut KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    host: &tessera_devicetree::PciHost,
) -> Result<(), tessera_karch::KError> {
    let device = PageFlags::rw().global().device();
    space.map_block_range(
        DIRECT_MAP_BASE + host.ecam_base,
        host.ecam_base,
        host.ecam_len,
        device,
        frames,
    )?;
    if let Some(window) = host.memory {
        // The bridge's window need not be a whole number of 2 MiB blocks —
        // this machine forwards 0x2eff_0000 — and the block mapper refuses a
        // partial one. Rounding **up** maps a little more device space than
        // the bridge forwards, which reads as nothing; rounding down would
        // leave the last BAR placed in the window unmapped, which reads as a
        // fault the first time a driver touches it.
        let len = window.len.next_multiple_of(2 * 1024 * 1024);
        space.map_block_range(
            DIRECT_MAP_BASE + window.cpu_base,
            window.cpu_base,
            len,
            device,
            frames,
        )?;
    }
    Ok(())
}

/// Config space reached through the high-half mapping `map_pci_windows` made.
///
/// The `unsafe` the `tessera-pci` crate forbids lives here, and it rests on
/// two facts: the ECAM window is mapped read-write at `DIRECT_MAP_BASE + phys`
/// before this is built, and the crate bounds every offset it passes against
/// the window length it was given.
pub(crate) struct EcamWindow {
    pub(crate) base: u64,
}

impl tessera_pci::ConfigSpace for EcamWindow {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: `base + offset` is inside the mapped ECAM window (the caller
        // bounds the offset). A config-space read has no device-side effect.
        unsafe {
            tessera_karch_aarch64::mmio_read32((DIRECT_MAP_BASE + self.base + offset) as usize)
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read32`. Writes here program BARs and the command
        // register of a device the kernel is enumerating, before anything else
        // can hold a capability to it.
        unsafe {
            tessera_karch_aarch64::mmio_write32(
                (DIRECT_MAP_BASE + self.base + offset) as usize,
                value,
            );
        }
    }
}

/// The GICv2m frame: where a message-signalled interrupt is *sent*.
///
/// GICv2m is why message-signalled interrupts are cheap on this port. The
/// frame is a doorbell: a device writes an SPI number to `SETSPI` and the GIC
/// raises that SPI. So an MSI becomes an **ordinary wired interrupt** the
/// moment it lands, and everything downstream — `enable_irq`, the IRQ→port
/// bridge, the EL0 driver waiting on its port (D84) — is reused unchanged.
/// Nothing here knows it is handling a message.
pub(crate) struct V2mFrame {
    pub(crate) base: u64,
    pub(crate) first_spi: u32,
    pub(crate) spi_count: u32,
    /// SPIs handed out so far, from the low end of the frame's range.
    pub(crate) allocated: u32,
}

/// `SETSPI_NSR`: writing an SPI number here raises it. This is the address a
/// device's MSI message is programmed with.
pub(crate) const V2M_SETSPI: u64 = 0x040;
/// `TYPER`: base SPI in bits 25:16, count in bits 9:0.
pub(crate) const V2M_TYPER: u64 = 0x008;

impl V2mFrame {
    /// Reads the frame's own description of the SPI range it owns.
    ///
    /// Taken from `TYPER` rather than the device tree's `arm,msi-base-spi` and
    /// `arm,msi-num-spis`: both describe the same thing, and the one the
    /// hardware answers with cannot disagree with the hardware.
    fn probe(base: u64) -> Self {
        // SAFETY: `base` is the v2m frame the device tree reported, inside
        // `DEVICE_RANGE` and therefore identity-mapped in the low half; TYPER
        // is a defined read-only register and reading it has no side effect.
        let typer = unsafe { tessera_karch_aarch64::mmio_read32((base + V2M_TYPER) as usize) };
        Self {
            base,
            first_spi: (typer >> 16) & 0x3ff,
            spi_count: typer & 0x3ff,
            allocated: 0,
        }
    }

    /// Takes the next SPI from the frame's range.
    ///
    /// An SPI outside the range belongs to some other device on the machine —
    /// handing one out would arm an interrupt this frame never raises, and the
    /// driver would wait for something that cannot arrive.
    pub(crate) fn allocate(&mut self) -> Option<u32> {
        if self.allocated >= self.spi_count {
            return None;
        }
        let spi = self.first_spi + self.allocated;
        self.allocated += 1;
        Some(spi)
    }

    /// The address a device writes to raise an SPI.
    pub(crate) const fn doorbell(&self) -> u64 {
        self.base + V2M_SETSPI
    }
}

/// The machine's SMMUv3, if it has one.
pub(crate) fn smmu_device(dtb: u64) -> Option<MmioDevice> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM and the reader
    // bounds-checks every access inside its self-declared length.
    let header = unsafe { core::slice::from_raw_parts(at, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(b"arm,smmu-v3")
        .ok()?
}

/// The machine's real-time clock, if it has one — this port's wakeup source.
pub(crate) fn rtc_device(dtb: u64) -> Option<MmioDevice> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM, and the reader
    // bounds-checks every access inside its self-declared length.
    let header = unsafe { core::slice::from_raw_parts(at, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(PL031_COMPATIBLE)
        .ok()?
}

/// How long the machine's description is, out of its own header.
///
/// The length a bus controller is granted, and taken from the blob rather than
/// assumed: a header says how much of it there is, and a window sized by
/// anything else would either hide part of the machine or hand out memory the
/// firmware never wrote.
pub(crate) fn dtb_total_size(dtb: u64) -> Option<u64> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM, and the header
    // is read before the body to learn how much of it there is.
    let total =
        unsafe { tessera_devicetree::total_size(core::slice::from_raw_parts(at, 64)) }.ok()?;
    Some(total as u64)
}

/// The machine's PL061 GPIO controller, if it has one.
///
/// Found by compatible string, which is all the device tree is asked for: the
/// window and the interrupt. **What the part is is not taken from here** — the
/// tree is a description somebody wrote, and the manager reads the answer out
/// of the device's own identification registers.
pub(crate) fn pl061_device(dtb: u64) -> Option<MmioDevice> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM, and the header
    // is read before the body to learn how much of it there is.
    let total =
        unsafe { tessera_devicetree::total_size(core::slice::from_raw_parts(at, 64)) }.ok()?;
    // SAFETY: as above, now for the length the header declared.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(b"arm,pl061")
        .ok()?
}

/// The machine's GICv2m frame, if it has one.
pub(crate) fn v2m_frame(dtb: u64) -> Option<V2mFrame> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM, and the
    // reader bounds-checks every access inside its self-declared length.
    let header = unsafe { core::slice::from_raw_parts(at, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    let node = DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(b"arm,gic-v2m-frame")
        .ok()??;
    Some(V2mFrame::probe(node.base))
}

/// A register window over a BAR the kernel placed, for reaching an MSI-X table
/// or a device's own registers.
///
/// The `ConfigSpace` trait is a 32-bit register window; `tessera-pci` uses it
/// for config space and for an MSI-X table alike, because the two differ in
/// where they are and not in how they are touched.
pub(crate) struct BarWindow {
    pub(crate) base: u64,
}

impl BarWindow {
    /// A 64-bit register write.
    ///
    /// Needed because a device's registers are not all 32 bits wide: `edu`'s
    /// DMA source, destination and count are `dma_addr_t`, and its register
    /// decode has no case for the upper half's offset — so two 32-bit writes
    /// set the low word and drop the high one on the floor, leaving the device
    /// with an address it never agreed to and no complaint about it.
    pub(crate) fn write64(&mut self, offset: u64, value: u64) {
        // SAFETY: as the 32-bit accessor below — a BAR this kernel placed
        // inside the bridge's mapped memory window.
        unsafe {
            ((DIRECT_MAP_BASE + self.base + offset) as *mut u64).write_volatile(value);
        }
    }

    /// A 64-bit register read.
    pub(crate) fn read64(&self, offset: u64) -> u64 {
        // SAFETY: as `write64`.
        unsafe { ((DIRECT_MAP_BASE + self.base + offset) as *const u64).read_volatile() }
    }
}

impl tessera_pci::ConfigSpace for BarWindow {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: `base` is a BAR this kernel placed inside the bridge's
        // memory window, which `map_pci_windows` mapped at
        // `DIRECT_MAP_BASE + phys`; `offset` stays inside that BAR.
        unsafe {
            tessera_karch_aarch64::mmio_read32((DIRECT_MAP_BASE + self.base + offset) as usize)
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read32`.
        unsafe {
            tessera_karch_aarch64::mmio_write32(
                (DIRECT_MAP_BASE + self.base + offset) as usize,
                value,
            );
        }
    }
}

/// Set by the MSI hook when the SPI this check armed is taken.
pub(crate) static MSI_SPI: AtomicU32 = AtomicU32::new(0);
pub(crate) static MSI_DELIVERED: AtomicU32 = AtomicU32::new(0);

/// The `edu` device: QEMU's minimal PCI endpoint. Writing `RAISE` makes it
/// send its interrupt; writing `ACK` clears it.
pub(crate) const EDU_VENDOR: u16 = 0x1234;
pub(crate) const EDU_DEVICE: u16 = 0x11e8;
pub(crate) const EDU_RAISE: u64 = 0x60;
pub(crate) const EDU_ACK: u64 = 0x64;
/// The device's own record that it raised — set by `RAISE`, cleared by `ACK`.
pub(crate) const EDU_IRQ_STATUS: u64 = 0x24;

/// The IRQ hook for the SPI a message-signalled interrupt was programmed to
/// raise. Counts it and acknowledges nothing else: this proves the message
/// arrived, and the device's own acknowledgement is the caller's business.
pub(crate) fn msi_irq_hook(id: u32) -> bool {
    if id != MSI_SPI.load(Ordering::SeqCst) || id == 0 {
        return false;
    }
    // SAFETY: masking a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(id) };
    MSI_DELIVERED.fetch_add(1, Ordering::SeqCst);
    true
}

