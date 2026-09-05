// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The remapping unit this machine describes, brought up for the whole boot.
//!
//! **Translation is a property of the machine, not of one check.** Enabling it
//! makes every PCI function's transactions pass through the tables at once, and
//! a function with no entry is aborted rather than let by — so a kernel that
//! scoped one device by switching translation on would be stopping every other
//! device on the machine. D338 got away with that by turning it off again
//! immediately; this brings the unit up once, gives every function the kernel
//! has nothing to say about an entry that passes its addresses through
//! unchanged, and leaves translation on.
//!
//! **What that buys is the seam.** [`Vtd`] implements
//! [`kcore::devmgr::DmaMapper`], which is how the graph installs and revokes a
//! device's translations without kcore knowing what a VT-d unit is — the same
//! trait the other port's SMMU implements. A device the graph scopes has its
//! context entry rewritten from pass-through to a second-level table, and from
//! then on it reaches what a lease says and nothing else.
//!
//! **A scoped device starts reaching nothing.** The tables are built empty:
//! registering a device is a fact about how the machine is wired and happens at
//! enumeration, while leasing is a fact about a driver and happens when one
//! asks.
//!
//! **What this machine can and cannot show about pass-through.** On the boot
//! that carries a unit, `edu` is the only function whose transactions reach it
//! at all: QEMU's virtio devices address memory directly unless they negotiate
//! `VIRTIO_F_ACCESS_PLATFORM`, which this tree's virtio core does not offer. So
//! the disk going on working with translation enabled says the boot survived,
//! not that these entries are right — and the entry that *is* checked is
//! `edu`'s own, exercised before it is scoped (`crate::isolation`). Removing
//! the loop below fails that check and nothing else, which is the measurement
//! rather than the expectation.
//!
//! Normative: docs/hardware/04-dma-and-memory-management.md,
//! docs/drivers/01-driver-framework.md ("DMA Safety")

use crate::*;

/// Where the unit's register block is mapped.
///
/// A page of its own beside the interrupt controller's, and for `msi`'s reason:
/// the direct map reaches physical memory as cacheable 2 MiB pages, and a
/// device register written through a cacheable mapping works under an emulator
/// and is a fault on hardware.
pub(crate) const VTD_VA: u64 = crate::INTERRUPT_MMIO_BASE + 3 * FRAME_SIZE;

/// Buses this unit holds a context table for. One is what a q35 machine needs;
/// a function on a bus past this is left untranslated, which is reported rather
/// than silently allowed.
const MAX_BUSES: usize = 4;

/// Devices that can be scoped at once, counted by **function** rather than by
/// check: a function three checks bind under three object ids takes one slot,
/// because the tables belong to the function.
///
/// **Measured, then over-provisioned.** The class boot is the widest — a disk,
/// a display, a sound card, an SD host and an encryption device, five distinct
/// functions — so this is eight rather than five: a boot that adds one device
/// should not also have to change a budget, and the cost of a slot is one
/// `Option` in a static.
const MAX_SCOPED: usize = 8;

/// Where a lease begins, and how far it reaches.
///
/// **One leaf table's worth**, which is what makes [`Vtd::begin_lease`] and
/// [`Vtd::map`] allocation-free: the whole chain down to the leaf is built when
/// the device is scoped, so leasing writes entries into a table that already
/// exists. A lease cannot exceed it, and the graph is told so.
pub(crate) const LEASE_BASE: u64 = 0x1_0000;
pub(crate) const LEAF_SPAN: u64 = 512 * FRAME_SIZE;

/// The domain every pass-through function shares, and the first domain a scoped
/// device gets.
///
/// **Shared for the ones that pass through, separate for the ones that do
/// not.** A domain is what the unit tags its cached translations with; two
/// devices in one domain share those and each other's invalidations. Functions
/// passing addresses through have no translations to share, so one domain for
/// all of them is honest; a scoped device gets its own, so emptying its tables
/// cannot leave another device's entries behind.
const PASSTHROUGH_DOMAIN: u16 = 0;
const FIRST_SCOPED_DOMAIN: u16 = 1;

/// How long a register poll waits before giving up. Bounded, because a unit
/// that never reports a command took is one to report rather than hang on.
const REGISTER_POLL: u32 = 1_000_000;

/// Entries in the interrupt-remapping table: one 4 KiB frame of 16-byte
/// entries.
///
/// **Sixteen for the I/O interrupt controller's lines and the rest for
/// messages**, which is more than this machine can use: the widest boot
/// enumerates six functions, and a function may raise
/// [`tessera_karch_x86_64::MSI_VECTOR_COUNT`] messages. The size is a page
/// because a page is the smallest thing to allocate, not because 256 was
/// fitted to anything.
const IRT_ENTRIES: u32 = 256;

/// Handles 0..16 are the I/O interrupt controller's lines, indexed **by line**
/// so a handle is not a thing anybody has to look up: line `n` is handle `n`.
const IOAPIC_LINES: u16 = 16;
/// Message-signalled interrupts take handles from here up, one per function and
/// vector, issued when a function's table is programmed.
const FIRST_MSI_HANDLE: u16 = IOAPIC_LINES;

/// How many message handles can be live at once. A function takes one per
/// vector it is armed with; measured at four on the NVMe boot, over-provisioned
/// to four functions' worth so a boot that arms another device does not also
/// have to change a budget.
const MAX_MSI_HANDLES: usize = 16;

/// The unit's register block, as [`tessera_vtd::Registers`].
pub(crate) struct VtdWindow {
    base: u64,
}

impl tessera_vtd::Registers for VtdWindow {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is a device mapping of the unit's register page, made
        // by `Vtd::bring_up` and live for the rest of the boot.
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

/// Reads and writes physical memory through the direct map. The tables the unit
/// walks are ordinary memory, written the way any other kernel structure is.
pub(crate) fn direct_write64(direct_map_base: u64, phys: u64, offset: u64, value: u64) {
    // SAFETY: `phys` is a frame this kernel allocated, and the direct map
    // covers all of physical memory for the life of the kernel.
    unsafe { ((direct_map_base + phys + offset) as *mut u64).write_volatile(value) }
}

pub(crate) fn direct_read64(direct_map_base: u64, phys: u64, offset: u64) -> u64 {
    // SAFETY: as `direct_write64`.
    unsafe { ((direct_map_base + phys + offset) as *const u64).read_volatile() }
}

pub(crate) fn zero_frame(direct_map_base: u64, phys: u64) {
    for offset in (0..FRAME_SIZE).step_by(8) {
        direct_write64(direct_map_base, phys, offset, 0);
    }
}

/// One device the graph has put behind an address space.
struct ScopedDevice {
    object: ObjectId,
    source: tessera_vtd::SourceId,
    /// The leaf table describing `[LEASE_BASE, LEASE_BASE + LEAF_SPAN)` — the
    /// only addresses this device can be given, and the reason a lease is
    /// bounded.
    leaf: u64,
    /// The live lease, if a driver holds one. `None` means the device is
    /// configured and translates nothing: every address it tries faults, which
    /// is both what "no lease" ought to mean and what makes the refusal
    /// observable in a fault record.
    lease: Option<(u64, u64)>,
}

/// One message handle this kernel has issued, and to whom.
#[derive(Clone, Copy)]
struct IssuedHandle {
    source: tessera_vtd::SourceId,
    vector: u8,
    handle: u16,
}

/// The unit, and what this kernel has told it.
pub(crate) struct Vtd {
    regs: VtdWindow,
    direct_map_base: u64,
    cap: u64,
    ecap: u64,
    width: tessera_vtd::AddressWidth,
    root_table: u64,
    /// One context table per bus that has a function on it.
    context: [Option<(u8, u64)>; MAX_BUSES],
    devices: [Option<ScopedDevice>; MAX_SCOPED],
    next_domain: u16,
    /// **The global command register is write-only and not one bit at a
    /// time.** Every write says what the whole register is to become, so the
    /// state of the bits that stay on has to be remembered here — a command
    /// issued by writing its bit alone turns off everything already enabled,
    /// which for `TE` means a machine whose DMA stops being translated at the
    /// moment interrupt remapping is switched on.
    gcmd: u32,
    /// The invalidation queue, once it exists: its page, the word a wait
    /// descriptor writes into, the next index to fill and the value the last
    /// wait asked for.
    queue: Option<u64>,
    queue_status: u64,
    queue_tail: u64,
    queue_sequence: u32,
    /// The interrupt-remapping table, once translation of interrupts is on.
    irt: Option<u64>,
    /// Whether its entries name a CPU with the whole 32-bit identifier.
    extended: bool,
    handles: [Option<IssuedHandle>; MAX_MSI_HANDLES],
}

impl Vtd {
    /// Brings the unit up with every enumerated function passing its addresses
    /// through, and turns translation on.
    ///
    /// **Pass-through before enable, never after.** Between the two the unit is
    /// translating with tables that describe nobody, and every transaction on
    /// the machine is aborted; the entries are written first so that window
    /// does not exist.
    pub(crate) fn bring_up(
        register_base: u64,
        functions: &[tessera_pci::Function],
        kernel_vm: &mut AddressSpace<KernelAddressSpace>,
        frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
        direct_map_base: u64,
    ) -> Result<Self, u32> {
        use tessera_vtd::Registers as _;

        let frame = PhysFrame::from_base(PhysAddr::new(register_base)).ok_or(1u32)?;
        let _ = kernel_vm.unmap_device_page(VirtAddr::new(VTD_VA));
        kernel_vm
            .map_device_page(
                VirtAddr::new(VTD_VA),
                frame,
                kcore::vm::DeviceReach::Kernel,
                frames,
            )
            .map_err(|_| 2u32)?;
        let regs = VtdWindow { base: VTD_VA };
        let cap = regs.read64(tessera_vtd::reg::CAP);
        let ecap = regs.read64(tessera_vtd::reg::ECAP);
        // **A unit that cannot pass a transaction through is one this kernel
        // must not leave enabled.** Every function it says nothing about would
        // be aborted, which is a machine that no longer works rather than one
        // that is safer.
        if !tessera_vtd::passthrough_supported(ecap) {
            return Err(3);
        }
        let width = tessera_vtd::address_width(cap).map_err(|_| 4u32)?;

        let root_table = frames.alloc().ok_or(5u32)?.base().as_u64();
        zero_frame(direct_map_base, root_table);
        let mut unit = Self {
            regs,
            direct_map_base,
            cap,
            ecap,
            width,
            root_table,
            context: [None; MAX_BUSES],
            devices: [const { None }; MAX_SCOPED],
            next_domain: FIRST_SCOPED_DOMAIN,
            gcmd: 0,
            queue: None,
            queue_status: 0,
            queue_tail: 0,
            queue_sequence: 0,
            irt: None,
            extended: false,
            handles: [None; MAX_MSI_HANDLES],
        };

        for function in functions {
            let source = tessera_vtd::SourceId::new(
                function.bdf.bus,
                function.bdf.device,
                function.bdf.function,
            );
            let entry = tessera_vtd::context_entry_passthrough(width, PASSTHROUGH_DOMAIN);
            unit.write_context(source, entry, frames)?;
        }

        unit.regs.write64(tessera_vtd::reg::RTADDR, unit.root_table);
        unit.command(tessera_vtd::gcmd::SRTP, tessera_vtd::gsts::RTPS)
            .map_err(|_| 6u32)?;
        unit.invalidate();
        unit.clear_faults();
        unit.enable(tessera_vtd::gcmd::TE, tessera_vtd::gsts::TES)
            .map_err(|_| 7u32)?;
        // **And the queue, once translation is on.** From here every
        // invalidation goes through it: the register interface below may not be
        // used while it is enabled, and it could not invalidate what the unit
        // caches about interrupt remapping in any case.
        unit.enable_queued_invalidation(frames)?;
        Ok(unit)
    }

    /// Enables the queued-invalidation interface.
    ///
    /// **A queue rather than two registers, and not for speed.** The register
    /// interface can invalidate the context cache and the IOTLB; there is no
    /// register that invalidates what the unit caches about the
    /// interrupt-remapping table, so a kernel that withdraws a handle through
    /// it has no way to make the withdrawal take effect. That is why the
    /// specification requires this before interrupt remapping, and why a unit
    /// without it gets no interrupt remapping here rather than an unenforceable
    /// version of it.
    fn enable_queued_invalidation(
        &mut self,
        frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    ) -> Result<(), u32> {
        use tessera_vtd::Registers as _;
        if !tessera_vtd::queued_invalidation_supported(self.ecap) {
            return Ok(());
        }
        let queue = frames.alloc().ok_or(30u32)?.base().as_u64();
        zero_frame(self.direct_map_base, queue);
        // The status word gets a frame of its own: the queue register describes
        // the whole page as descriptors, so there is nowhere inside it a wait
        // descriptor could write without the unit reading that write back as a
        // command.
        let status = frames.alloc().ok_or(31u32)?.base().as_u64();
        zero_frame(self.direct_map_base, status);
        self.regs.write64(
            tessera_vtd::reg::IQA,
            tessera_vtd::queue_address(queue).map_err(|_| 32u32)?,
        );
        self.regs.write64(tessera_vtd::reg::IQT, 0);
        self.queue = Some(queue);
        self.queue_status = status;
        self.queue_tail = 0;
        self.enable(tessera_vtd::gcmd::QIE, tessera_vtd::gsts::QIES)
            .map_err(|_| {
                // Left off rather than half on: a queue the unit is not draining
                // would make every later invalidation time out.
                self.queue = None;
                33u32
            })
    }

    /// Turns interrupt remapping on, and puts this machine's interrupts behind
    /// it.
    ///
    /// **What changes is who names the vector.** Until now a device signalled
    /// by writing an address naming a CPU and a data word naming a vector, both
    /// of them fields the device supplies — so a device that could write to the
    /// interrupt window could raise any vector on any CPU, which no amount of
    /// DMA scoping touches, because a write into that window is not a memory
    /// access at all and never reaches the tables the last four increments
    /// built. Now it writes a **handle**, and which vector and which CPU that
    /// stands for is an entry in a table only this kernel writes — with the
    /// requester's own source id in it, so a handle issued to one function is
    /// not one another function can use.
    ///
    /// Returns whether it was enabled: a unit that does not offer it, or offers
    /// it without the queue it needs, is reported rather than driven half-way.
    pub(crate) fn enable_interrupt_remapping(
        &mut self,
        ioapic_source: Option<u16>,
        frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    ) -> Result<bool, u32> {
        use tessera_vtd::Registers as _;
        if !tessera_vtd::interrupt_remapping_supported(self.ecap) || self.queue.is_none() {
            return Ok(false);
        }
        let table = frames.alloc().ok_or(40u32)?.base().as_u64();
        zero_frame(self.direct_map_base, table);
        self.extended = tessera_vtd::extended_interrupt_mode_supported(self.ecap);
        self.irt = Some(table);

        // **The lines first, then the switch.** Every entry the controller
        // could deliver through exists before remapping is enabled, because
        // between the two an unmasked line is one the unit has no entry for and
        // would block. Nothing is unmasked here — boot masked them all — and
        // this ordering is what keeps that from being load-bearing.
        let destination = tessera_karch_x86_64::local_apic_id();
        // **The controller's own source id, when the firmware states it.** Its
        // interrupt requests carry one like any other requester's, and without
        // it every one of its entries would have to be issued with no
        // verification — which is a vector any device that can write to the
        // interrupt window may raise as if it were the controller.
        //
        // **Programmed, and not measured on this machine.** Giving these
        // entries a deliberately wrong source id changes nothing here: the
        // emulated controller's writes arrive with no requester id at all, so
        // the unit has nothing to compare and skips the check. The same
        // inversion on a *message* is caught immediately (`crate::isolation`),
        // which is how the two are told apart — the field is right, and this
        // machine cannot see whether it is.
        let source = ioapic_source.map(tessera_vtd::SourceId);
        for line in 0..IOAPIC_LINES {
            let vector = tessera_karch_x86_64::IRQ_BASE_LINE + line as u8;
            let entry = match source {
                Some(source) => {
                    tessera_vtd::interrupt_entry(vector, destination, self.extended, source)
                }
                None => tessera_vtd::interrupt_entry_unverified(vector, destination, self.extended),
            };
            self.write_interrupt_entry(line, entry);
        }

        self.regs.write64(
            tessera_vtd::reg::IRTA,
            tessera_vtd::interrupt_table_address(table, IRT_ENTRIES, self.extended)
                .map_err(|_| 41u32)?,
        );
        self.command(tessera_vtd::gcmd::SIRTP, tessera_vtd::gsts::IRTPS)
            .map_err(|_| 42u32)?;
        self.invalidate_interrupts();
        self.enable(tessera_vtd::gcmd::IRE, tessera_vtd::gsts::IRES)
            .map_err(|_| 43u32)?;
        // **And the old format is shut.** `GCMD.CFI` is never written, so a
        // request that still carries its own vector and destination is blocked;
        // this reads the status bit back rather than trusting that, because a
        // unit that came up with it set would remap the interrupts this kernel
        // asked it to and let every forged one past — which is the one failure
        // that leaves nothing to see.
        if self.regs.read32(tessera_vtd::reg::GSTS) & tessera_vtd::gsts::CFIS != 0 {
            return Err(44);
        }
        // The controller's lines change format only now, so a line unmasked
        // before this point was delivered the old way and correctly.
        for line in 0..IOAPIC_LINES {
            tessera_karch_x86_64::remap_irq_line(line as u8, line);
        }
        Ok(true)
    }

    /// Whether this unit is remapping interrupts, which is what decides the
    /// format the MSI-X arming path writes.
    pub(crate) fn remaps_interrupts(&self) -> bool {
        self.irt.is_some()
    }

    /// Issues `source` a handle standing for `vector` on this CPU, or answers
    /// the one it already holds for that vector.
    ///
    /// **Re-issued rather than duplicated**, for [`Vtd::scope`]'s reason: a
    /// function armed twice across two checks is one function, and a second
    /// entry for it would leave the first live — a handle nothing points at
    /// that still raises an interrupt.
    pub(crate) fn issue_handle(
        &mut self,
        source: tessera_vtd::SourceId,
        vector: u8,
    ) -> Result<u16, u32> {
        if self.irt.is_none() {
            return Err(50);
        }
        if let Some(held) = self
            .handles
            .iter()
            .flatten()
            .find(|held| held.source == source && held.vector == vector)
        {
            return Ok(held.handle);
        }
        let slot = self.handles.iter().position(Option::is_none).ok_or(51u32)?;
        let handle = FIRST_MSI_HANDLE + slot as u16;
        let entry = tessera_vtd::interrupt_entry(
            vector,
            tessera_karch_x86_64::local_apic_id(),
            self.extended,
            source,
        );
        self.write_interrupt_entry(handle, entry);
        self.invalidate_interrupts();
        self.handles[slot] = Some(IssuedHandle {
            source,
            vector,
            handle,
        });
        Ok(handle)
    }

    /// Takes a handle back: the entry stops being present, so the next
    /// interrupt naming it is blocked and recorded.
    ///
    /// **The invalidation is the withdrawal**, exactly as it is for an unmap.
    /// Clearing the entry without telling the unit leaves whatever it cached
    /// live for as long as it cares to keep it, and the bookkeeping would say
    /// withdrawn while the interrupt still arrived.
    ///
    /// Not measured on this machine, and said rather than assumed: dropping the
    /// invalidation leaves the check below passing, because the emulated unit
    /// re-reads the entry for every interrupt and caches nothing. It is here
    /// because a unit that does cache is the one this has to be right for, and
    /// there is nothing in a passing boot that would say otherwise.
    pub(crate) fn withdraw_handle(&mut self, handle: u16) {
        if self.irt.is_none() {
            return;
        }
        self.write_interrupt_entry(handle, tessera_vtd::INTERRUPT_ENTRY_ABSENT);
        self.invalidate_interrupts();
        for held in self.handles.iter_mut() {
            if held.is_some_and(|held| held.handle == handle) {
                *held = None;
            }
        }
    }

    /// The first handle past the ones any device holds, for a check that needs
    /// an index the table does not cover.
    pub(crate) const fn handles_end() -> u16 {
        IRT_ENTRIES as u16
    }

    fn write_interrupt_entry(&mut self, handle: u16, entry: [u64; 2]) {
        let Some(table) = self.irt else {
            return;
        };
        if u32::from(handle) >= IRT_ENTRIES {
            return;
        }
        let at = u64::from(handle) * tessera_vtd::IRT_ENTRY_BYTES;
        // The high word first, as for a context entry: the low word carries the
        // present bit, and a unit reading the entry between the two writes would
        // pair a live vector with whatever source id the last owner left.
        direct_write64(self.direct_map_base, table, at + 8, entry[1]);
        direct_write64(self.direct_map_base, table, at, entry[0]);
    }

    /// The version register, for the boot to say what it found.
    pub(crate) fn version(&self) -> u32 {
        use tessera_vtd::Registers as _;
        self.regs.read32(tessera_vtd::reg::VER)
    }

    /// Puts `object`'s function behind an address space of its own, replacing
    /// the pass-through entry it was brought up with.
    ///
    /// The whole chain down to the leaf is built here, once, which is what lets
    /// [`kcore::devmgr::DmaMapper::begin_lease`] and
    /// [`kcore::devmgr::DmaMapper::map`] be allocation-free — and is why a
    /// lease cannot exceed [`LEAF_SPAN`].
    pub(crate) fn scope(
        &mut self,
        object: ObjectId,
        function: &tessera_pci::Function,
        frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    ) -> Result<(), u32> {
        let source = tessera_vtd::SourceId::new(
            function.bdf.bus,
            function.bdf.device,
            function.bdf.function,
        );
        // **A function already behind tables is re-keyed, not given a second
        // set.** The tables belong to the function; the object id is whichever
        // executive is naming it now, and successive checks on this machine
        // name one NIC three times. A second chain would leak the first and
        // leave the context entry pointing at whichever was written last —
        // which is a device translating through tables nothing else can reach.
        let direct_map_base = self.direct_map_base;
        if let Some(existing) = self
            .devices
            .iter_mut()
            .flatten()
            .find(|device| device.source == source)
        {
            existing.object = object;
            existing.lease = None;
            let leaf = existing.leaf;
            zero_frame(direct_map_base, leaf);
            self.invalidate();
            return Ok(());
        }
        let slot = self.devices.iter().position(Option::is_none).ok_or(10u32)?;

        // Built from the leaf up, each level zeroed before anything points at
        // it: a table the unit walks into that still holds what the last owner
        // left is a set of translations nobody wrote.
        let mut below = None;
        for level in 1..=self.width.levels {
            let table = frames.alloc().ok_or(11u32)?.base().as_u64();
            zero_frame(self.direct_map_base, table);
            if let Some(next) = below {
                // **This table's level, not the one below it.** An entry in a
                // level-`n` table is selected by the address bits that level
                // owns; using the lower level's builds a chain that walks
                // somewhere else and looks exactly like an aperture that
                // refuses everything.
                let index = tessera_vtd::level_index(LEASE_BASE, level) as u64;
                let entry = tessera_vtd::table_entry(next).map_err(|_| 12u32)?;
                direct_write64(self.direct_map_base, table, index * 8, entry);
            }
            below = Some(table);
        }
        let root = below.ok_or(13u32)?;
        let leaf = {
            // Read the chain back rather than remembering it, so what is
            // written is reached the same way the unit will reach it.
            let mut table = root;
            for level in (2..=self.width.levels).rev() {
                let index = tessera_vtd::level_index(LEASE_BASE, level) as u64;
                let entry = direct_read64(self.direct_map_base, table, index * 8);
                table = entry & 0x000f_ffff_ffff_f000;
            }
            table
        };

        let domain = self.next_domain;
        self.next_domain += 1;
        let entry = tessera_vtd::context_entry(root, self.width, domain).map_err(|_| 14u32)?;
        self.write_context(source, entry, frames)?;
        self.invalidate();

        self.devices[slot] = Some(ScopedDevice {
            object,
            source,
            leaf,
            lease: None,
        });
        Ok(())
    }

    /// The source id a scoped device's transactions arrive with, for a check
    /// that has to recognise its fault records.
    pub(crate) fn source_of(&self, object: ObjectId) -> Option<tessera_vtd::SourceId> {
        self.devices
            .iter()
            .flatten()
            .find(|d| d.object == object)
            .map(|d| d.source)
    }

    /// Takes the next fault the unit has recorded, if it has recorded one.
    ///
    /// **Read-and-clear**, because a record left in the ring is one the next
    /// reader would find and mistake for its own.
    pub(crate) fn take_fault(&mut self) -> Option<tessera_vtd::Fault> {
        use tessera_vtd::Registers as _;
        let recording = tessera_vtd::fault_recording(self.cap);
        let mut found = None;
        for record in 0..recording.count {
            let low = self.regs.read64(recording.offset + record * 16);
            let high = self.regs.read64(recording.offset + record * 16 + 8);
            let decoded = tessera_vtd::decode_fault(low, high);
            if decoded.valid {
                found = Some(decoded);
                self.regs.write64(
                    recording.offset + record * 16 + 8,
                    tessera_vtd::FAULT_CLEAR_HIGH,
                );
            }
        }
        let status = self.regs.read32(tessera_vtd::reg::FSTS);
        self.regs.write32(tessera_vtd::reg::FSTS, status);
        found
    }

    /// Waits, bounded, for a fault to arrive. A unit records one within a few
    /// cycles of refusing a transaction, so this is a settle rather than a
    /// timeout: what it protects against is reading the ring before the write
    /// lands, which would report "no fault" for one that happened.
    pub(crate) fn wait_for_fault(&mut self) -> Option<tessera_vtd::Fault> {
        use tessera_vtd::Registers as _;
        for _ in 0..REGISTER_POLL {
            if self.regs.read32(tessera_vtd::reg::FSTS) & tessera_vtd::fsts::PPF != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        self.take_fault()
    }

    /// Discards whatever the unit had recorded before now.
    pub(crate) fn clear_faults(&mut self) {
        while self.take_fault().is_some() {}
    }

    /// Writes one context entry, making the bus's context table if this is the
    /// first function on it.
    fn write_context(
        &mut self,
        source: tessera_vtd::SourceId,
        entry: [u64; 2],
        frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    ) -> Result<(), u32> {
        let bus = source.bus() as u8;
        let table = match self.context.iter().flatten().find(|(b, _)| *b == bus) {
            Some((_, table)) => *table,
            None => {
                let slot = self.context.iter().position(Option::is_none).ok_or(20u32)?;
                let table = frames.alloc().ok_or(21u32)?.base().as_u64();
                zero_frame(self.direct_map_base, table);
                let root = tessera_vtd::root_entry(table).map_err(|_| 22u32)?;
                let at = u64::from(bus) * 16;
                direct_write64(self.direct_map_base, self.root_table, at, root[0]);
                direct_write64(self.direct_map_base, self.root_table, at + 8, root[1]);
                self.context[slot] = Some((bus, table));
                table
            }
        };
        let at = source.context_index() as u64 * 16;
        // **The high word first.** The low word carries the present bit, and a
        // unit that read the entry between the two writes would walk a table
        // pointer paired with whatever width the last entry left.
        direct_write64(self.direct_map_base, table, at + 8, entry[1]);
        direct_write64(self.direct_map_base, table, at, entry[0]);
        Ok(())
    }

    /// Turns on a global command bit and waits for the status bit that mirrors
    /// it, remembering that the bit is now on.
    fn enable(&mut self, command: u32, status: u32) -> Result<(), tessera_vtd::Error> {
        use tessera_vtd::Registers as _;
        self.gcmd |= command;
        self.regs.write32(tessera_vtd::reg::GCMD, self.gcmd);
        if self.wait_status(status, true) {
            Ok(())
        } else {
            self.gcmd &= !command;
            Err(tessera_vtd::Error::Timeout)
        }
    }

    /// Issues a one-shot command — "the pointer I just wrote is the one to
    /// use" — without disturbing what is already enabled, and waits for it.
    ///
    /// The bit is **not** remembered: it is a command rather than a state, and
    /// a kernel that left it in the shadow would re-issue it with every later
    /// write.
    fn command(&mut self, command: u32, status: u32) -> Result<(), tessera_vtd::Error> {
        use tessera_vtd::Registers as _;
        self.regs
            .write32(tessera_vtd::reg::GCMD, self.gcmd | command);
        if self.wait_status(status, true) {
            Ok(())
        } else {
            Err(tessera_vtd::Error::Timeout)
        }
    }

    /// Puts descriptors on the invalidation queue and waits for the unit to
    /// finish them.
    ///
    /// **Submitting is not completing.** The unit advances the head as it
    /// *fetches*, so a kernel polling the head would take "read" for "done" and
    /// go on to reuse a translation the device can still see. The wait
    /// descriptor appended here writes a value of this call's own into a word in
    /// memory once everything before it has completed, and that write is the
    /// only signal that means what it says.
    fn submit(&mut self, descriptors: &[[u64; 2]]) -> bool {
        use tessera_vtd::Registers as _;
        let Some(queue) = self.queue else {
            return false;
        };
        // Never zero, because zero is what the status word is cleared to: a
        // sequence that wrapped onto it would read as complete before the unit
        // had done anything.
        self.queue_sequence = self.queue_sequence.wrapping_add(1).max(1);
        let sequence = self.queue_sequence;
        let status = self.queue_status;
        direct_write64(self.direct_map_base, status, 0, 0);
        let Ok(wait) = tessera_vtd::invalidate_wait_descriptor(status, sequence) else {
            return false;
        };
        let mut tail = self.queue_tail;
        for descriptor in descriptors.iter().chain(core::iter::once(&wait)) {
            let at = tail * tessera_vtd::DESCRIPTOR_BYTES;
            direct_write64(self.direct_map_base, queue, at, descriptor[0]);
            direct_write64(self.direct_map_base, queue, at + 8, descriptor[1]);
            tail = (tail + 1) % tessera_vtd::QUEUE_DESCRIPTORS;
        }
        self.queue_tail = tail;
        self.regs.write64(
            tessera_vtd::reg::IQT,
            tail << tessera_vtd::QUEUE_INDEX_SHIFT,
        );
        for _ in 0..REGISTER_POLL {
            if direct_read64(self.direct_map_base, status, 0) as u32 == sequence {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Invalidates everything the unit may have cached about the tables.
    ///
    /// **Through whichever interface is live.** The two are mutually exclusive
    /// — the context and IOTLB registers may not be used once the queue is
    /// enabled — so this is one decision made in one place rather than a caller
    /// having to know which era of the boot it is in.
    fn invalidate(&mut self) {
        use tessera_vtd::Registers as _;
        if self.queue.is_some() {
            self.submit(&[
                tessera_vtd::context_invalidate_descriptor(),
                tessera_vtd::iotlb_invalidate_descriptor(),
            ]);
            return;
        }
        self.regs.write64(
            tessera_vtd::reg::CCMD,
            tessera_vtd::CCMD_ICC | tessera_vtd::CCMD_CIRG_GLOBAL,
        );
        let iotlb = tessera_vtd::iotlb_invalidate_offset(self.ecap);
        self.regs.write64(
            iotlb,
            tessera_vtd::IOTLB_IVT | tessera_vtd::IOTLB_IIRG_GLOBAL,
        );
    }

    /// The same for the interrupt-remapping table, which only the queue can
    /// reach. Kept apart from [`Vtd::invalidate`] because the two answer
    /// different questions and a mapping change has nothing to say about
    /// interrupts.
    fn invalidate_interrupts(&mut self) {
        self.submit(&[tessera_vtd::interrupt_entry_invalidate_descriptor()]);
    }

    fn wait_status(&self, bit: u32, set: bool) -> bool {
        use tessera_vtd::Registers as _;
        for _ in 0..REGISTER_POLL {
            if (self.regs.read32(tessera_vtd::reg::GSTS) & bit != 0) == set {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    fn device(&self, object: ObjectId) -> Option<&ScopedDevice> {
        self.devices.iter().flatten().find(|d| d.object == object)
    }

    /// The checks `map` and `unmap` share: a mapper whose only correctness
    /// argument is "my caller checks" is one refactor away from being wrong.
    fn bounded(
        &self,
        object: ObjectId,
        iova: u64,
        len: u64,
    ) -> Result<(u64, u64), tessera_karch::KError> {
        use tessera_karch::KError;
        let device = self.device(object).ok_or(KError::InvalidMapping)?;
        let (base, span) = device.lease.ok_or(KError::InvalidMapping)?;
        if len == 0 || !len.is_multiple_of(FRAME_SIZE) || !iova.is_multiple_of(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        let end = iova.checked_add(len).ok_or(KError::InvalidMapping)?;
        if iova < base || end > base + span {
            return Err(KError::InvalidMapping);
        }
        Ok((device.leaf, end))
    }
}

impl kcore::devmgr::DmaMapper for Vtd {
    fn translates(&self, device: ObjectId) -> bool {
        self.device(device).is_some()
    }

    fn begin_lease(&mut self, device: ObjectId) -> Result<(u64, u64), tessera_karch::KError> {
        use tessera_karch::KError;
        let direct_map_base = self.direct_map_base;
        let leaf = {
            let scoped = self
                .devices
                .iter_mut()
                .flatten()
                .find(|d| d.object == device)
                .ok_or(KError::InvalidMapping)?;
            scoped.lease = Some((LEASE_BASE, LEAF_SPAN));
            scoped.leaf
        };
        // **Start from nothing, always.** The previous lease's teardown already
        // cleared this table, so this is redundant on the happy path — and that
        // is the point: reissuing a device-visible address is only safe if the
        // new lease cannot inherit a translation, and doing it here is cheaper
        // than trusting that every teardown ran.
        zero_frame(direct_map_base, leaf);
        self.invalidate();
        Ok((LEASE_BASE, LEAF_SPAN))
    }

    fn end_lease(&mut self, device: ObjectId) {
        let direct_map_base = self.direct_map_base;
        let Some(leaf) = self
            .devices
            .iter_mut()
            .flatten()
            .find(|d| d.object == device)
            .map(|scoped| {
                scoped.lease = None;
                scoped.leaf
            })
        else {
            return;
        };
        // **Empty the table; leave the context entry pointing at it.** Putting
        // the entry back to not-present would also stop the device, but it
        // would stop it as a context fault — the refusal for a function that
        // was never configured — which reads exactly like a misconfiguration.
        // An empty translation table is what "reaches nothing" should mean, and
        // a device that tries anyway takes an ordinary translation fault naming
        // the address it wanted. That is the difference between revocation
        // being enforced and revocation being observable.
        zero_frame(direct_map_base, leaf);
        self.invalidate();
    }

    fn map(
        &mut self,
        device: ObjectId,
        iova: u64,
        phys: u64,
        len: u64,
    ) -> Result<(), tessera_karch::KError> {
        use tessera_karch::KError;
        if !phys.is_multiple_of(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        let (leaf, _) = self.bounded(device, iova, len)?;
        for page in 0..len / FRAME_SIZE {
            let at = iova + page * FRAME_SIZE;
            let entry =
                tessera_vtd::page_entry(phys + page * FRAME_SIZE).map_err(|_| KError::Unaligned)?;
            direct_write64(
                self.direct_map_base,
                leaf,
                tessera_vtd::level_index(at, 1) as u64 * 8,
                entry,
            );
        }
        // The address was never mapped before — an aperture does not reuse —
        // but the unit may hold a *negative* translation for it from a fault,
        // so the entry only becomes visible once the cache is told.
        self.invalidate();
        Ok(())
    }

    fn unmap(
        &mut self,
        device: ObjectId,
        iova: u64,
        len: u64,
    ) -> Result<(), tessera_karch::KError> {
        let (leaf, _) = self.bounded(device, iova, len)?;
        for page in 0..len / FRAME_SIZE {
            let at = iova + page * FRAME_SIZE;
            // Entry zero has neither read nor write, so the device's next
            // transaction to this address faults — which is what "the device
            // can no longer reach it" has to mean.
            direct_write64(
                self.direct_map_base,
                leaf,
                tessera_vtd::level_index(at, 1) as u64 * 8,
                0,
            );
        }
        // **The invalidation is the unmap.** Clearing the entry without telling
        // the unit leaves the old translation live in it for as long as it
        // cares to keep it: the bookkeeping would say detached and the device
        // would still be reading.
        self.invalidate();
        Ok(())
    }
}
