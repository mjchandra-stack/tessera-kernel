// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The SMMUv3 device model: registers, stream table, and the fault log.
//!
//! Normative: docs/hardware/04-dma-and-memory-management.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

/// The SMMU's registers, reached at their physical address through the
/// low-half identity map — the same way the GIC and the v2m frame are, and
/// unlike ECAM, which sits above `DEVICE_RANGE` and needed its own mapping.
pub(crate) struct SmmuRegisters {
    base: usize,
}

impl tessera_smmu::Registers for SmmuRegisters {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: the SMMU's register page is inside `DEVICE_RANGE` and so is
        // identity-mapped device memory; every offset comes from the register
        // map in `tessera_smmu::reg`.
        unsafe { tessera_karch_aarch64::mmio_read32(self.base + offset) }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        // SAFETY: as `read32`.
        unsafe { tessera_karch_aarch64::mmio_write32(self.base + offset, value) }
    }
    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: as `read32`; the SMMU's 64-bit registers are naturally
        // aligned within the page.
        unsafe { ((self.base + offset) as *const u64).read_volatile() }
    }
    fn write64(&mut self, offset: usize, value: u64) {
        // SAFETY: as `read64`.
        unsafe { ((self.base + offset) as *mut u64).write_volatile(value) }
    }
}

/// A word written through the direct map, for the structures the SMMU walks:
/// stream table, queues, and stage-2 tables all live in frames the boot
/// allocator handed out, and the hardware reads them at their physical
/// addresses while the kernel writes them at their direct-map aliases.
pub(crate) fn direct_write64(phys: u64, offset: u64, value: u64) {
    // SAFETY: `phys` is a frame the boot allocator handed out and `offset`
    // stays inside it, so the direct-map alias is mapped writable RAM.
    unsafe { ((DIRECT_MAP_BASE + phys + offset) as *mut u64).write_volatile(value) }
}

/// The counterpart read. See [`direct_write64`].
pub(crate) fn direct_read64(phys: u64, offset: u64) -> u64 {
    // SAFETY: as `direct_write64`.
    unsafe { ((DIRECT_MAP_BASE + phys + offset) as *const u64).read_volatile() }
}

/// Zeroes a whole frame the hardware is about to walk. An uninitialised
/// structure is a structure of undefined entries, not an empty one.
pub(crate) fn zero_frame(phys: u64) {
    for offset in (0..FRAME_SIZE).step_by(8) {
        direct_write64(phys, offset, 0);
    }
}

/// Streams this SMMU can hold an aperture for at once. One per device behind
/// it; this machine puts one device behind it.
pub(crate) const MAX_SMMU_STREAMS: usize = 4;

/// What one level-3 table describes: 512 entries of one page.
pub(crate) const LEAF_SPAN: u64 = 512 * FRAME_SIZE;

/// A stream's translation, and the device capability it belongs to.
///
/// `object` is what makes this reachable from the kernel core: `dma_alloc`
/// knows the device object a driver named, and knows nothing about stream ids.
pub(crate) struct SmmuStream {
    object: kcore::object::ObjectId,
    stream: u32,
    /// The level-3 table describing `[0, LEAF_SPAN)` for this stream — the
    /// only addresses it can be given, and the reason a lease is bounded.
    leaf: u64,
    /// The live lease's `(base, len)`, if a driver holds one. `None` means the
    /// stream is configured and translates nothing: every address it tries
    /// takes a stage-2 fault, which is both what "no lease" ought to mean and
    /// what makes the refusal observable in the event queue.
    lease: Option<(u64, u64)>,
}

/// What the fault harvest has seen, and how it found out.
///
/// The log exists because there are now **two** readers of one queue — the
/// unit's interrupt and a boot check that polls — and a queue read by two
/// consumers is a race in which either can swallow the other's record. Making
/// the harvest the only consumer and the log the only reader removes the race
/// rather than timing around it: whichever path drains first, both see the
/// same answer.
#[derive(Clone, Copy, Default)]
pub(crate) struct FaultLog {
    /// The most recent fault, taken by the next reader.
    ///
    /// Written by the interrupt bridge and read by boot code, which is safe to
    /// do as a plain field **only** because every reader synchronises on
    /// [`SMMU_FAULTS_SEEN`] first: the harvest stores that counter after
    /// writing this, so a reader that has observed the counter move has
    /// observed the record too.
    last: Option<tessera_smmu::Event>,
}

/// Faults harvested since boot.
///
/// An atomic, and a static rather than a field, because the writer is an
/// interrupt handler and the readers are boot code spinning on it. A plain
/// counter would be hoisted out of any wait loop that watched it — the loop
/// would read one cached value forever and time out on a fault that had
/// already arrived, which is a false negative that looks exactly like the
/// interrupt never firing.
pub(crate) static SMMU_FAULTS_SEEN: AtomicU32 = AtomicU32::new(0);

/// How many of those arrived because the unit *told* the kernel, rather than
/// because something happened to look.
///
/// Counted apart because it is the whole claim of the runtime harvest. A boot
/// check that polls proves the queue works; only this proves a fault on a
/// system nobody is watching would be seen.
pub(crate) static SMMU_FAULTS_BY_INTERRUPT: AtomicU32 = AtomicU32::new(0);

/// The SMMU, brought up once and left running for the life of the boot.
///
/// This is the hardware behind [`kcore::devmgr::DmaMapper`]: the graph records
/// which addresses belong to a device, and this installs them. It is boot glue
/// rather than a crate because everything here is *poking* — the encoding it
/// writes all comes from `tessera_smmu`, which is `forbid(unsafe_code)` and
/// host-tested, and that split is what caught three encoding bugs before
/// hardware saw them (D119).
pub(crate) struct Smmu {
    regs: SmmuRegisters,
    /// The linear stream table: one entry per stream id, all aborting except
    /// those an aperture has been installed for.
    strtab: u64,
    cmdq: u64,
    eventq: u64,
    /// The command queue's producer index, advanced by every command issued.
    prod: tessera_smmu::QueueIndex,
    /// The event queue's consumer index. Kept here rather than re-read per
    /// check, so successive readers each see the *next* fault rather than all
    /// re-reading the first one.
    cons: tessera_smmu::QueueIndex,
    streams: [Option<SmmuStream>; MAX_SMMU_STREAMS],
    /// What the harvest has seen. See [`FaultLog`].
    faults: FaultLog,
}

impl Smmu {
    /// Brings the SMMU up with every stream aborting, and nothing translating.
    ///
    /// Aborting is the safe starting state and the deliberate one: a stream
    /// with no entry must not bypass, or an SMMU with an empty table behaves
    /// exactly like no SMMU at all.
    pub(crate) fn bring_up(base: u64, frames: &mut kcore::pmem::BumpFrameAllocator<'_>) -> Result<Self, u32> {
        use tessera_smmu::Registers as _;

        // Contiguous **and aligned to its own size**, which is what the
        // architecture requires of a linear stream table and what the frame
        // allocator does not promise: `alloc_contiguous` guarantees the run is
        // unbroken and nothing about where it starts. A misaligned base has the
        // unit read the table from a lower address, find no valid entry for any
        // stream, and abort every transaction — which presents as DMA that
        // silently does not land, with the stream table looking perfectly well
        // formed in memory. Twice the frames are taken so an aligned run of the
        // right length is certain to be inside; this is boot-time and the waste
        // is one table.
        let table_bytes = STREAM_TABLE_FRAMES * FRAME_SIZE;
        let run = frames
            .alloc_contiguous(STREAM_TABLE_FRAMES * 2)
            .ok_or(2u32)?
            .as_u64();
        let strtab = run.next_multiple_of(table_bytes);
        let cmdq = frames.alloc().ok_or(2u32)?.base().as_u64();
        let eventq = frames.alloc().ok_or(2u32)?.base().as_u64();
        for frame in 0..STREAM_TABLE_FRAMES {
            zero_frame(strtab + frame * FRAME_SIZE);
        }
        for frame in [cmdq, eventq] {
            zero_frame(frame);
        }
        for entry in 0..(1u64 << STREAM_TABLE_LOG2) {
            let at = entry * tessera_smmu::STE_SIZE as u64;
            for (word, value) in tessera_smmu::stream_table_entry_abort().iter().enumerate() {
                direct_write64(strtab, at + (word as u64) * 8, *value);
            }
        }

        let mut smmu = Self {
            regs: SmmuRegisters {
                base: base as usize,
            },
            strtab,
            cmdq,
            eventq,
            prod: tessera_smmu::QueueIndex::new(QUEUE_LOG2, 0),
            cons: tessera_smmu::QueueIndex::new(QUEUE_LOG2, 0),
            streams: [const { None }; MAX_SMMU_STREAMS],
            faults: FaultLog::default(),
        };

        // Queues and the table go in **before** the SMMU is enabled: between
        // enabling and having a valid table every stream aborts, including any
        // the machine is already using.
        smmu.regs
            .write64(tessera_smmu::reg::CMDQ_BASE, cmdq | u64::from(QUEUE_LOG2));
        smmu.regs.write32(tessera_smmu::reg::CMDQ_PROD, 0);
        smmu.regs.write32(tessera_smmu::reg::CMDQ_CONS, 0);
        smmu.regs.write64(
            tessera_smmu::reg::EVENTQ_BASE,
            eventq | u64::from(QUEUE_LOG2),
        );
        smmu.regs.write32(tessera_smmu::reg::EVENTQ_PROD, 0);
        smmu.regs.write32(tessera_smmu::reg::EVENTQ_CONS, 0);
        smmu.regs.write64(tessera_smmu::reg::STRTAB_BASE, strtab);
        // Linear format, sized to the table just built.
        smmu.regs
            .write32(tessera_smmu::reg::STRTAB_BASE_CFG, STREAM_TABLE_LOG2);
        // A stream with no entry aborts rather than bypassing.
        smmu.regs.write32(
            tessera_smmu::reg::GBPA,
            tessera_smmu::gbpa::UPDATE | tessera_smmu::gbpa::ABORT,
        );
        smmu.regs.write32(
            tessera_smmu::reg::CR0,
            tessera_smmu::cr0::CMDQEN | tessera_smmu::cr0::EVENTQEN,
        );
        // **Ask the unit to speak up.** `EVENTQEN` makes it write records;
        // this makes it raise its own interrupt when it does. Without it the
        // queue still fills and nothing says so, which is a fault harvest that
        // works exactly when someone happens to look — during a boot check,
        // and never afterwards.
        //
        // Only the event queue: the PRI queue and the global-error line have
        // no consumer here, and enabling an interrupt nothing handles would
        // give this machine a line that asserts forever.
        smmu.regs
            .write32(tessera_smmu::reg::IRQ_CTRL, tessera_smmu::irq_ctrl::EVENTQ);

        smmu.issue(tessera_smmu::cmd_cfgi_all());
        smmu.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        smmu.issue(tessera_smmu::cmd_sync());

        smmu.regs.write32(
            tessera_smmu::reg::CR0,
            tessera_smmu::cr0::CMDQEN | tessera_smmu::cr0::EVENTQEN | tessera_smmu::cr0::SMMUEN,
        );
        // The hardware says when an enable took effect; assuming it did is how
        // a configuration race becomes an unexplainable fault later.
        let mut budget = 100_000u32;
        while smmu.regs.read32(tessera_smmu::reg::CR0ACK) & tessera_smmu::cr0::SMMUEN == 0
            && budget > 0
        {
            budget -= 1;
        }
        if budget == 0 {
            return Err(4);
        }
        // The unit acknowledges its interrupt-enable separately from `CR0`,
        // and a unit that never does is one whose faults would be harvested
        // only by polling — a degradation that must be reported rather than
        // discovered later as silence.
        let mut budget = 100_000u32;
        while smmu.regs.read32(tessera_smmu::reg::IRQ_CTRLACK) & tessera_smmu::irq_ctrl::EVENTQ == 0
            && budget > 0
        {
            budget -= 1;
        }
        if budget == 0 {
            return Err(5);
        }
        Ok(smmu)
    }

    /// Records that `object`'s DMA arrives on `stream` and builds the
    /// translation structures it will use, with **nothing mapped in them** —
    /// the device can reach exactly nothing until a lease says otherwise.
    ///
    /// Both levels of the table are allocated **here**, once, which is what
    /// lets [`Smmu::begin_lease`] and [`Smmu::map`] be allocation-free (see
    /// [`kcore::devmgr::DmaMapper`]) — and is why a lease cannot exceed
    /// [`LEAF_SPAN`]. Registering a stream is a fact about the machine's
    /// wiring, so it happens at enumeration; leasing is a fact about a driver,
    /// so it happens when one asks.
    pub(crate) fn register_stream(
        &mut self,
        object: kcore::object::ObjectId,
        stream: u32,
        frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    ) -> Result<(), u32> {
        if stream >= (1 << STREAM_TABLE_LOG2) {
            return Err(1);
        }
        let slot = self.streams.iter().position(Option::is_none).ok_or(8u32)?;
        let root = frames.alloc().ok_or(2u32)?.base().as_u64();
        let leaf = frames.alloc().ok_or(2u32)?.base().as_u64();
        zero_frame(root);
        zero_frame(leaf);

        let (t0sz, start_level) =
            tessera_smmu::t0sz_and_start_level(APERTURE_BITS).map_err(|_| 3u32)?;
        // The root is the level-2 table for a 30-bit address; its first entry
        // covers `[0, LEAF_SPAN)`, which is the whole of this stream's world.
        direct_write64(
            root,
            (tessera_smmu::level_index(0, 2) * 8) as u64,
            tessera_smmu::stage2_table_descriptor(leaf),
        );

        // A VMID per stream, so one stream's TLB entries are not another's.
        let ste = tessera_smmu::stream_table_entry_s2(
            root,
            (slot + 1) as u16,
            t0sz,
            tessera_smmu::start_level_to_sl0(start_level),
        );
        let at = u64::from(stream) * tessera_smmu::STE_SIZE as u64;
        for (word, value) in ste.iter().enumerate() {
            direct_write64(self.strtab, at + (word as u64) * 8, *value);
        }
        self.issue(tessera_smmu::cmd_cfgi_ste(stream));
        self.issue(tessera_smmu::cmd_sync());

        self.streams[slot] = Some(SmmuStream {
            object,
            stream,
            leaf,
            lease: None,
        });
        Ok(())
    }

    /// The stream registered for `object`, if it has one.
    fn stream_mut(&mut self, object: kcore::object::ObjectId) -> Option<&mut SmmuStream> {
        self.streams
            .iter_mut()
            .flatten()
            .find(|s| s.object == object)
    }

    /// The stream id an aperture was installed under for `object`.
    pub(crate) fn stream_of(&self, object: kcore::object::ObjectId) -> Option<u32> {
        self.streams
            .iter()
            .flatten()
            .find(|s| s.object == object)
            .map(|s| s.stream)
    }

    /// Pushes one command and rings the doorbell.
    fn issue(&mut self, command: tessera_smmu::Command) {
        use tessera_smmu::Registers as _;
        let at = u64::from(self.prod.index()) * tessera_smmu::CMD_SIZE as u64;
        direct_write64(self.cmdq, at, command[0]);
        direct_write64(self.cmdq, at + 8, command[1]);
        self.prod = self.prod.next();
        self.regs
            .write32(tessera_smmu::reg::CMDQ_PROD, self.prod.raw);
    }

    /// Consumes every fault the SMMU has logged since the last harvest,
    /// records each into `kcore::event`, applies the standing isolation
    /// policy, and remembers the **last** one for a polling reader.
    ///
    /// Draining rather than stepping one record at a time, because **one
    /// refused transfer does not produce one record**: an 8-byte DMA to an
    /// unmapped address logged three on this machine, so a consumer that
    /// advanced by one per harvest would read the previous transfer's refusal
    /// and call it the current one — which is exactly the false pass this
    /// diagnosed.
    ///
    /// `by_interrupt` says which of the two callers this is. Both exist and
    /// neither is redundant: the interrupt is what makes a fault on a running
    /// system visible, and the polled call is what keeps a boot check working
    /// in the windows where the line is masked. They cannot race for records
    /// because neither reads the queue — the log does, once, here.
    ///
    /// Returns how many records were consumed.
    pub(crate) fn harvest(&mut self, by_interrupt: bool) -> u32 {
        use tessera_smmu::Registers as _;
        // The producer index is readable at a page-0 offset and a page-1 alias
        // depending on the implementation; take whichever moved rather than
        // guessing which one this SMMU answers on.
        let page0 = self.regs.read32(0xa8);
        let page1 = self.regs.read32(tessera_smmu::reg::EVENTQ_PROD);
        let prod =
            tessera_smmu::QueueIndex::new(QUEUE_LOG2, if page0 != 0 { page0 } else { page1 });
        let mut consumed = 0u32;
        while !self.cons.is_empty(prod) {
            let at = u64::from(self.cons.index()) * tessera_smmu::EVENT_SIZE as u64;
            let record = tessera_smmu::decode_event([
                direct_read64(self.eventq, at),
                direct_read64(self.eventq, at + 8),
                direct_read64(self.eventq, at + 16),
                direct_read64(self.eventq, at + 24),
            ]);
            self.cons = self.cons.next();
            consumed += 1;
            self.faults.last = Some(record);
            // The record first, then the counters. A reader that has seen
            // `SMMU_FAULTS_SEEN` move has, by this ordering, also seen the
            // record it counts — which is what makes `last` safe to keep as a
            // plain field across an interrupt.
            if by_interrupt {
                SMMU_FAULTS_BY_INTERRUPT.fetch_add(1, Ordering::SeqCst);
            }
            SMMU_FAULTS_SEEN.fetch_add(1, Ordering::SeqCst);
            self.report(record);
        }
        // Told once, after the loop: `EVENTQ_CONS` is how the unit learns the
        // queue has room again, and writing it per record would be a register
        // access per fault on a path a storm can drive.
        self.regs
            .write32(tessera_smmu::reg::EVENTQ_CONS, self.cons.raw);
        consumed
    }

    /// Hands one decoded record to the kernel core: the log first, then the
    /// standing policy.
    ///
    /// The two are separate calls because they have different preconditions.
    /// Recording needs nothing and therefore always happens — `docs/drivers/01`
    /// says faults "are logged", with no qualifier, and a harvest that skipped
    /// the record when no executive was in scope would lose exactly the faults
    /// that happen between checks. Isolation needs the resource graph, so it
    /// happens when there is one and the absence is a fact about this moment
    /// in boot rather than a silent downgrade.
    fn report(&mut self, record: tessera_smmu::Event) {
        use kcore::devmgr::{DmaFault, DmaFaultKind, IsolationPolicy};
        use tessera_smmu::FaultClass;

        let kind = match record.class() {
            FaultClass::Unmapped => DmaFaultKind::Unmapped,
            FaultClass::Permission => DmaFaultKind::Permission,
            FaultClass::UnknownStream => DmaFaultKind::UnknownStream,
            FaultClass::BadConfiguration => DmaFaultKind::BadConfiguration,
            FaultClass::Other => DmaFaultKind::Unclassified,
        };
        let fault = DmaFault {
            // A stream with no registered device is not a lookup failure to
            // paper over — it is this kernel's own stream table describing
            // something no capability backs, and the record says so.
            device: self
                .streams
                .iter()
                .flatten()
                .find(|s| s.stream == record.stream)
                .map(|s| s.object),
            stream: record.stream,
            address: record.address,
            kind,
        };
        kcore::devmgr::record_dma_fault(&fault);

        let policy = match SMMU_FAULT_POLICY.load(Ordering::SeqCst) {
            p if p == IsolationPolicy::EndLease as u32 => IsolationPolicy::EndLease,
            p if p == IsolationPolicy::EndLeaseAndStop as u32 => IsolationPolicy::EndLeaseAndStop,
            _ => IsolationPolicy::Report,
        };
        if matches!(policy, IsolationPolicy::Report) {
            return;
        }
        // SAFETY: transient raw access to the static executive. This runs
        // either from boot code between scheduler runs, or from the interrupt
        // bridge — which can only preempt EL0 execution or boot code outside
        // an enable window, never a live Executive borrow (the same argument
        // `virtio_irq_hook` rests on). Nothing here blocks or schedules.
        let outcome = unsafe {
            match (*(&raw mut KCORE_EXEC)).as_mut() {
                Some(exec) => exec.isolate_dma_fault(fault, policy, Some(self)),
                // No executive: the fault is recorded and nothing is isolated,
                // because there is no graph saying who holds what. Boot before
                // the first check is genuinely in this state.
                None => return,
            }
        };
        if let Some(holder) = outcome.stop {
            // The policy asked for the holder to be stopped and this port has
            // no supervisor in scope to do it, so the request is published for
            // one rather than dropped: a policy that reports acting without
            // acting is the silent degradation docs/lifecycle/04 forbids.
            SMMU_ISOLATION_STOP.store(holder.raw(), Ordering::SeqCst);
        }
    }

    /// Consumes anything outstanding and returns the most recent fault, or
    /// `None` when none has been harvested since the last reader took one.
    ///
    /// **Takes rather than peeks**, which is what preserves the semantics
    /// every existing caller was written against: drain before a transfer to
    /// clear, drain after it to read that transfer's refusal. It also makes
    /// the polled reader immune to the interrupt beating it to the queue — a
    /// fault harvested by the bridge a moment earlier is still waiting here.
    pub(crate) fn drain_events(&mut self) -> Option<tessera_smmu::Event> {
        self.harvest(false);
        self.faults.last.take()
    }
}

/// The kernel core's DMA seam, implemented by real hardware.
///
/// Everything this refuses is a refusal the caller sees rather than a
/// translation quietly not installed: an unknown device, an unaligned range,
/// or a range past what this stream's one table can describe.
impl kcore::devmgr::DmaMapper for Smmu {
    fn translates(&self, device: kcore::object::ObjectId) -> bool {
        self.streams.iter().flatten().any(|s| s.object == device)
    }

    fn begin_lease(
        &mut self,
        device: kcore::object::ObjectId,
    ) -> Result<(u64, u64), tessera_karch::KError> {
        use tessera_karch::KError;
        let stream = self.stream_mut(device).ok_or(KError::InvalidMapping)?;
        let leaf = stream.leaf;
        stream.lease = Some((LEASE_BASE, LEASE_LEN));
        // **Start from nothing, always.** The previous lease's teardown already
        // cleared this table, so this is redundant on the happy path — and that
        // is the point: reissuing a device-visible address is only safe if the
        // new lease cannot inherit a translation, and belt-and-braces here is
        // cheaper than trusting that every teardown ran.
        zero_frame(leaf);
        self.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        self.issue(tessera_smmu::cmd_sync());
        Ok((LEASE_BASE, LEASE_LEN))
    }

    fn end_lease(&mut self, device: kcore::object::ObjectId) {
        let Some(stream) = self.stream_mut(device) else {
            return;
        };
        let leaf = stream.leaf;
        stream.lease = None;
        // **Empty the table; leave the stream table entry valid.** Setting the
        // entry back to abort would also stop the device, but it would stop it
        // as `C_BAD_STREAMID` — the fault for a stream that was never
        // configured — which reports no address and reads exactly like a
        // misconfiguration. An empty translation table is what "reaches
        // nothing" should mean, and a device that tries anyway takes an
        // ordinary stage-2 translation fault naming the address it wanted.
        // That is the difference between revocation being enforced and
        // revocation being observable, and `docs/drivers/01` asks for both.
        //
        // Setting the entry to abort belongs to *device removal*, which is a
        // different sentence in the same paragraph and not this milestone.
        zero_frame(leaf);
        self.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        self.issue(tessera_smmu::cmd_sync());
    }

    fn map(
        &mut self,
        device: kcore::object::ObjectId,
        iova: u64,
        phys: u64,
        len: u64,
    ) -> Result<(), tessera_karch::KError> {
        use tessera_karch::KError;
        let stream = self
            .streams
            .iter()
            .flatten()
            .find(|s| s.object == device)
            .ok_or(KError::InvalidMapping)?;
        let leaf = stream.leaf;
        // A mapper whose only correctness argument is "my caller checks" is one
        // refactor away from being wrong.
        let (base, span) = stream.lease.ok_or(KError::InvalidMapping)?;
        if len == 0 || len % FRAME_SIZE != 0 || iova % FRAME_SIZE != 0 || phys % FRAME_SIZE != 0 {
            return Err(KError::Unaligned);
        }
        let end = iova.checked_add(len).ok_or(KError::InvalidMapping)?;
        if iova < base || end > base + span || end > LEAF_SPAN {
            return Err(KError::InvalidMapping);
        }
        for page in 0..len / FRAME_SIZE {
            let at = iova + page * FRAME_SIZE;
            direct_write64(
                leaf,
                (tessera_smmu::level_index(at, 3) * 8) as u64,
                tessera_smmu::stage2_page_descriptor(phys + page * FRAME_SIZE),
            );
        }
        // The address was never mapped before — an aperture does not reuse —
        // but the hardware may hold a *negative* translation for it from a
        // fault, so the entry only becomes visible once the TLB is told.
        self.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        self.issue(tessera_smmu::cmd_sync());
        Ok(())
    }

    fn unmap(
        &mut self,
        device: kcore::object::ObjectId,
        iova: u64,
        len: u64,
    ) -> Result<(), tessera_karch::KError> {
        use tessera_karch::KError;
        let stream = self
            .streams
            .iter()
            .flatten()
            .find(|s| s.object == device)
            .ok_or(KError::InvalidMapping)?;
        let leaf = stream.leaf;
        // The same checks as `map`, and for the same reason: a mapper whose
        // only correctness argument is "my caller checks" is one refactor away
        // from being wrong. Here the stakes are the other way round — a range
        // this refuses to clear is one the device can still reach.
        let (base, span) = stream.lease.ok_or(KError::InvalidMapping)?;
        if len == 0 || len % FRAME_SIZE != 0 || iova % FRAME_SIZE != 0 {
            return Err(KError::Unaligned);
        }
        let end = iova.checked_add(len).ok_or(KError::InvalidMapping)?;
        if iova < base || end > base + span || end > LEAF_SPAN {
            return Err(KError::InvalidMapping);
        }
        for page in 0..len / FRAME_SIZE {
            let at = iova + page * FRAME_SIZE;
            // Descriptor zero is invalid — bit 0 clear. The device's next
            // transaction to this address raises a translation fault, which is
            // what "the device can no longer reach it" has to mean.
            direct_write64(leaf, (tessera_smmu::level_index(at, 3) * 8) as u64, 0);
        }
        // **The invalidation is the unmap.** Clearing the descriptor without
        // telling the TLB leaves the old translation live in the hardware for
        // as long as it cares to keep it — the bookkeeping would say detached
        // and the device would still be writing.
        self.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        self.issue(tessera_smmu::cmd_sync());
        Ok(())
    }
}

/// How the aperture is sized. A 30-bit input address makes the stage-2 root a
/// single 512-entry level-2 table — one frame — and puts everything at or
/// above 2 MiB outside the one level-3 table below it, which is what makes
/// "outside the aperture" unambiguous rather than a matter of degree.
pub(crate) const APERTURE_BITS: u32 = 30;
/// Where a lease starts in a device's address space, and how wide it is.
///
/// Not zero, because a device-visible address of 0 is handed to ring 3 as a
/// syscall return value, where every driver in this tree reads 0 as failure.
/// Two pages, so a second allocation has somewhere to go and a third proves
/// exhaustion refuses.
pub(crate) const LEASE_BASE: u64 = 0x1_0000;
pub(crate) const LEASE_LEN: u64 = 2 * FRAME_SIZE;
/// Where the device is told to write, inside the lease.
pub(crate) const APERTURE_IOVA: u64 = LEASE_BASE;
/// An address with no translation: the second 2 MiB, which the root table
/// does not describe at all.
pub(crate) const OUTSIDE_IOVA: u64 = 0x20_0000;
/// Log2 of the linear stream table's entry count — enough entries to cover the
/// stream ids this machine's PCI functions get, and few enough to fit one frame.
///
/// **Sized by the bus numbers, not by the device count.** A PCIe stream id is
/// the requester id — `bus << 8 | device << 3 | function` — because that is what
/// the hardware puts on the bus, not something this kernel gets to choose. So
/// the moment a function sits behind a bridge its stream id is at least 256, and
/// a table sized for the devices on bus 0 refuses it: `register_stream` returns
/// "outside the table", and the failure surfaces as a driver that cannot be
/// given DMA rather than as anything mentioning buses.
///
/// Ten covers buses 0 through 3, which is every machine here — 1024 entries at
/// 64 bytes each, sixteen contiguous frames. A machine deeper than that needs
/// the two-level table the architecture provides, which is the right answer for
/// a real range of bus numbers and more mechanism than any check here would
/// exercise.
pub(crate) const STREAM_TABLE_LOG2: u32 = 10;

/// Frames the stream table occupies, which must be contiguous: the unit indexes
/// it as one array from a single base register.
pub(crate) const STREAM_TABLE_FRAMES: u64 =
    ((1u64 << STREAM_TABLE_LOG2) * tessera_smmu::STE_SIZE as u64).div_ceil(FRAME_SIZE);
/// Entries in each queue.
pub(crate) const QUEUE_LOG2: u32 = 3;
/// The pattern the device is made to move, chosen to be recognisable in a
/// page that is otherwise zero.
pub(crate) const DMA_PATTERN: u64 = 0x5344_4d4d_5556_3300;

/// edu's DMA registers (QEMU `hw/misc/edu.c`).
pub(crate) const EDU_DMA_SRC: u64 = 0x80;
pub(crate) const EDU_DMA_DST: u64 = 0x88;
pub(crate) const EDU_DMA_COUNT: u64 = 0x90;
pub(crate) const EDU_DMA_CMD: u64 = 0x98;
/// The address of edu's own buffer, in its private address space — not
/// something the SMMU translates.
pub(crate) const EDU_BUFFER: u64 = 0x4_0000;
pub(crate) const EDU_DMA_START: u64 = 1 << 0;
/// Direction bit: set means edu's buffer to memory, which is the direction
/// that lets the kernel *observe* whether a transfer landed.
pub(crate) const EDU_DMA_TO_MEMORY: u64 = 1 << 1;

/// Functions one walk may report.
pub(crate) const MAX_PCI_FUNCTIONS: usize = 16;

