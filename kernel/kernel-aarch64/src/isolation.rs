// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Checks that the machine cannot be made to read memory it was not given.
//!
//! The SMMU's fault isolation, and DMA confined to what a driver was
//! granted. Both answer the same question from opposite sides: what a device
//! reaches when it asks for something nobody gave it.
//!
//! Normative: docs/hardware/04-dma-and-memory-management.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

/// Puts one PCI device behind a stream table with a one-page aperture, and
/// proves the boundary in both directions.
///
/// **This is the DMA-scoping claim.** Until now a driver programmed a device
/// with a physical address and the device was obeyed; the only thing keeping
/// a device out of memory it had no business in was the driver choosing not
/// to. Here the device is given an address space: one page is mapped, and the
/// hardware refuses everything else.
///
/// The proof needs both halves. A transfer *inside* the aperture must land,
/// or an SMMU that aborts everything would pass for one that scopes; a
/// transfer *outside* must not, and the event queue must say so, or "nothing
/// arrived" is indistinguishable from a misconfiguration. `edu` is the device
/// because its DMA engine is four register writes, so nothing has to be
/// brought up first.
///
/// Returns `(stream, inside, outside_event)`.
pub(crate) fn smmu_check(
    smmu: &mut Smmu,
    device: kcore::object::ObjectId,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<(u32, u64, tessera_smmu::Event), u32> {
    use kcore::devmgr::DmaMapper as _;

    let stream = smmu.stream_of(device).ok_or(1u32)?;

    // A lease, then one page of memory for the device to reach inside it —
    // through the same seam `dma_alloc` uses, so this proves the *mechanism*
    // rather than a second one built beside it.
    smmu.begin_lease(device).map_err(|_| 3u32)?;
    let target = frames.alloc().ok_or(2u32)?.base().as_u64();
    zero_frame(target);
    smmu.map(device, APERTURE_IOVA, target, FRAME_SIZE)
        .map_err(|_| 3u32)?;

    let (bar, _) = function.first_bar().ok_or(5u32)?;
    let mut edu = BarWindow { base: bar };

    // Give the device something recognisable to move: put the pattern in the
    // target page and have the device read it into its own buffer, through the
    // aperture. Then clear the page and have it write the pattern back.
    direct_write64(target, 0, DMA_PATTERN);
    edu_dma(&mut edu, APERTURE_IOVA, EDU_BUFFER, 8, EDU_DMA_START);
    direct_write64(target, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        APERTURE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    let inside = direct_read64(target, 0);

    // The same transfer to an address the table does not describe.
    direct_write64(target, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        OUTSIDE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(target, 0) != 0 {
        // It reached the page it must not have reached.
        return Err(6);
    }

    // The SMMU's own account of the refusal. Without it, "nothing arrived" is
    // what a misconfiguration produces too.
    let record = smmu.drain_events().ok_or(7u32)?;

    // Give the lease back. The next one — the ring-3 driver's — then starts
    // from an empty table, which is what makes it a *second* lease rather than
    // a continuation of this one.
    smmu.end_lease(device);
    Ok((stream, inside, record))
}

/// What [`dma_fault_isolation_check`] observed.
pub(crate) struct FaultIsolation {
    /// The stream the refusal named.
    pub(crate) stream: u32,
    /// The address the device was refused.
    pub(crate) refused_at: u64,
    /// How many of this check's faults the **unit's own interrupt** delivered.
    /// Zero would mean the harvest works only when something looks.
    pub(crate) by_interrupt: u32,
    /// The process whose lease the policy ended.
    pub(crate) stopped: u32,
}

/// A blank crash dump, for supervisors to fill.
///
/// A `const` rather than a `Default` because `KernelEvent` is generated code
/// and giving generated types trait impls in a boot glue is how a schema
/// change becomes a compile error in the wrong file.
pub(crate) const CRASH_DUMP_TEMPLATE: kcore::supervise::CrashDump = kcore::supervise::CrashDump {
    process: kcore::object::ObjectId::from_raw(0),
    cause: 0,
    address: 0,
    correlation: 0,
    captured: 0,
    trace: [kcore::event::KernelEvent {
        size: 0,
        version: 0,
        flags: 0,
        kind: kcore::event::EventKind::EventsDropped,
        severity: kcore::event::Severity::Info,
        component: kcore::event::Component::Driver,
        classification: kcore::event::Classification::Public,
        timestamp: 0,
        thread_id: 0,
        process_id: 0,
        correlation_lo: 0,
        correlation_hi: 0,
        arg0: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
    }; kcore::supervise::CRASH_TRACE_TAIL],
};

/// How many trace records the last crash dump captured — read by the boot
/// check, because a dump that collected nothing is the failure worth seeing
/// and is invisible from outside the dump itself.
pub(crate) static CRASH_DUMP_RECORDS: AtomicU32 = AtomicU32::new(0);

/// A stand-in driver process for the isolation check.
///
/// The check needs a lease *holder* and deliberately not a running driver: the
/// claim is about what the kernel does when a device misbehaves, and putting
/// an EL0 program behind it would add a second thing that could be wrong
/// without making the claim stronger. `scoped_dma_check` already proves a real
/// ring-3 driver takes a real lease.
pub(crate) const ISOLATION_HOLDER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x51);

/// Proves the second clause of `docs/drivers/01` "DMA Safety": faults *are
/// logged and can trigger driver isolation*.
///
/// Everything before this milestone stopped at the hardware's refusal — the
/// SMMU declined one transaction and the system carried on, none the wiser. A
/// device that keeps asking is a device nobody has taken away anything from.
/// Here the fault reaches the kernel **through the unit's own interrupt**, is
/// recorded as a structured event, and ends the device's lease: it stops
/// reaching the address it was refused *and* the one it was entitled to.
///
/// The three things checked, in the order they can fail:
///
/// 1. The interrupt delivered it. Without this the harvest is a polling loop
///    with extra steps, and a fault between two checks would be invisible.
/// 2. The lease ended. The device was reaching a page a moment earlier through
///    an address the graph had issued; it is not now.
/// 3. The device agrees. The in-aperture address that worked is refused, which
///    is the difference between the translations being torn down and the
///    kernel merely having forgotten them.
pub(crate) fn dma_fault_isolation_check(
    smmu: &mut Smmu,
    device: kcore::object::ObjectId,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<FaultIsolation, u32> {
    use kcore::devmgr::{DeviceAperture, DmaMapper as _, IsolationPolicy};

    let stream = smmu.stream_of(device).ok_or(170u32)?;
    let (bar, bar_len) = function.first_bar().ok_or(171u32)?;

    // A fresh executive holding this device and nothing else, so the events
    // read below are this check's.
    // SAFETY: single-threaded boot; no thread of any earlier check is live.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }

    // A lease, recorded in the graph as a driver's would be. The graph is what
    // isolation consults to find a holder, so a lease installed only in the
    // hardware would be torn down with nobody named — which is precisely the
    // case the `device: None` fault arm reports rather than acts on.
    let (base, len) = smmu.begin_lease(device).map_err(|_| 172u32)?;
    let target = frames.alloc().ok_or(173u32)?.base().as_u64();
    zero_frame(target);
    smmu.map(device, base, target, FRAME_SIZE)
        .map_err(|_| 174u32)?;
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(175u32)?;
        exec.device_register_mmio(device, bar, bar_len, kcore::rights::Rights::READ)
            .map_err(|_| 176u32)?;
        exec.device_set_aperture(
            device,
            ISOLATION_HOLDER_OBJ,
            DeviceAperture::new(base, len.min(FRAME_SIZE)),
            // No deadline: this lease exists for the length of one check.
            None,
        )
        .map_err(|_| 177u32)?;
    }

    let mut edu = BarWindow { base: bar };

    // The device reaches its page, so that losing it later means something.
    direct_write64(target, 0, DMA_PATTERN);
    edu_dma(&mut edu, base, EDU_BUFFER, 8, EDU_DMA_START);
    direct_write64(target, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        base,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(target, 0) != DMA_PATTERN {
        return Err(178);
    }

    // Empty the log, so what is counted below is this check's, and arm the
    // policy. Both are deliberate acts: the harvest has been recording faults
    // since bring-up and isolating none of them, which is the conservative
    // default a machine still coming up wants.
    smmu.drain_events();
    let before = SMMU_FAULTS_BY_INTERRUPT.load(Ordering::SeqCst);
    SMMU_ISOLATION_STOP.store(0, Ordering::SeqCst);
    SMMU_FAULT_POLICY.store(IsolationPolicy::EndLeaseAndStop as u32, Ordering::SeqCst);

    // The misbehaviour, and the window in which the unit can report it. The
    // boot context has masked interrupts since reset, so without unmasking
    // here the record would sit in the queue and only the polled reader would
    // ever find it — which is the state this milestone exists to leave behind.
    //
    // Nothing else is enabled on this path but the periodic tick and the
    // SMMU's own line, and neither handler touches the borrow held here:
    // the tick counts, and the fault bridge reaches this same unit through
    // `BOOT_IOMMU` between — never during — the accesses below.
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        OUTSIDE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: unmasking and re-masking at EL1 is a PSTATE write on the boot
    // CPU, which owns the machine here.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
    }
    let mut settle = 200_000u32;
    while SMMU_FAULTS_BY_INTERRUPT.load(Ordering::SeqCst) == before && settle > 0 {
        settle -= 1;
        core::hint::spin_loop();
    }
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack));
    }
    SMMU_FAULT_POLICY.store(IsolationPolicy::Report as u32, Ordering::SeqCst);

    let by_interrupt = SMMU_FAULTS_BY_INTERRUPT
        .load(Ordering::SeqCst)
        .saturating_sub(before);
    if by_interrupt == 0 {
        // The unit refused the transaction — every earlier check proves that
        // much — and did not tell anyone. That is the failure this milestone
        // is about, so it is a failure here rather than a fallback to polling.
        return Err(179);
    }

    // The policy acted: the graph no longer names a holder for this device.
    // SAFETY: transient raw access to the static executive.
    if unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
        .ok_or(180u32)?
        .lease_holder_of_object(device)
        .is_some()
    {
        return Err(181);
    }
    let stopped = SMMU_ISOLATION_STOP.load(Ordering::SeqCst);
    if stopped != ISOLATION_HOLDER_OBJ.raw() {
        return Err(182);
    }

    // And the hardware agrees. The address the device was *entitled* to a
    // moment ago is refused now — which is what distinguishes translations
    // torn down from a graph that merely forgot them.
    direct_write64(target, 0, 0);
    smmu.drain_events();
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        base,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(target, 0) != 0 {
        return Err(183);
    }
    let record = smmu.drain_events().ok_or(184u32)?;
    if record.kind != tessera_smmu::event::F_TRANSLATION || record.stream != stream {
        return Err(185);
    }

    Ok(FaultIsolation {
        stream,
        refused_at: record.address,
        by_interrupt,
        stopped,
    })
}

/// Who holds the lease the protected-memory check takes.
///
/// The *device* is `SMMU_DEVICE_OBJ`, as in every other check here: a stream id
/// belongs to the hardware the unit was told about, and a fresh object id would
/// name a device the SMMU has never heard of.
pub(crate) const PROTECTED_HOLDER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x61);

/// What the protected-memory check produced.
pub(crate) struct ProtectedDma {
    /// The stream the refusal named.
    pub(crate) stream: u32,
    /// The address the device was refused — inside its own aperture.
    pub(crate) refused_at: u64,
    /// The aperture the device holds, so the verdict can say the refused
    /// address was inside it rather than merely somewhere.
    pub(crate) aperture: (u64, u64),
    /// Faults the unit's own interrupt delivered for this check.
    pub(crate) by_interrupt: u32,
}

/// Proves the **second layer** of `docs/security/01`'s memory classification:
/// a device refused protected memory does not reach it, and the hardware is
/// what makes that true rather than the interface.
///
/// The first layer — the refusal itself — is proven by the syscall (host tests)
/// and in ring 3 (`blk-client` classifies the very buffer it just moved and the
/// same request comes back refused). What neither of those can show is what the
/// refusal *left behind*, and that is the question here: a policy that returned
/// an error while installing a translation anyway would pass both.
///
/// So the same rule runs — `kcore::memory::attach_permitted`, against the
/// rights the resource graph recorded for this device — and because it says no,
/// no translation is installed. The device is then driven at the address the
/// attach would have returned, which is **inside its own aperture**: an address
/// this device is entitled to use, unmapped because policy stopped the mapping
/// being made. That is what distinguishes this from D119, where the refused
/// address was outside the aperture and the SMMU was refusing a device reaching
/// somewhere it had no business at all.
pub(crate) fn protected_dma_check(
    smmu: &mut Smmu,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<ProtectedDma, u32> {
    use kcore::devmgr::{DeviceAperture, DmaMapper as _};
    use kcore::memory::{MemoryClass, attach_permitted};
    use kcore::rights::Rights;

    let stream = smmu.stream_of(SMMU_DEVICE_OBJ).ok_or(190u32)?;
    let (bar, bar_len) = function.first_bar().ok_or(191u32)?;

    // A fresh executive holding this device and nothing else, so what is
    // counted below is this check's.
    // SAFETY: single-threaded boot; no thread of any earlier check is live.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }

    let (base, len) = smmu.begin_lease(SMMU_DEVICE_OBJ).map_err(|_| 192u32)?;
    // **Two pages of aperture, and that is the point.** One page would leave
    // the refused attach's address outside the lease, which is the case D119
    // already covers; the refusal has to leave a hole *inside* the range this
    // device is entitled to.
    let aperture_len = len.min(2 * FRAME_SIZE);
    if aperture_len < 2 * FRAME_SIZE {
        return Err(193);
    }

    // The device this check registers is deliberately **not** authorized for
    // protected memory: `PROTECTED_DMA` is absent from the rights the graph
    // records, which is what the rule below reads.
    let device_rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(194u32)?;
        exec.device_register_mmio(SMMU_DEVICE_OBJ, bar, bar_len, device_rights)
            .map_err(|_| 194u32)?;
        exec.device_set_aperture(
            SMMU_DEVICE_OBJ,
            PROTECTED_HOLDER_OBJ,
            DeviceAperture::new(base, aperture_len),
            None,
        )
        .map_err(|_| 195u32)?;
    }

    let mut edu = BarWindow { base: bar };

    // --- An unclassified buffer, which reaches the device ---
    let open_frame = frames.alloc().ok_or(196u32)?.base().as_u64();
    zero_frame(open_frame);
    // SAFETY: transient raw access to the static executive; single-threaded
    // boot, and no thread of any earlier check is live.
    let open_iova = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(197u32)?;
        exec.device_allocate_in_aperture(SMMU_DEVICE_OBJ, FRAME_SIZE)
            .ok_or(197u32)?
    };
    smmu.map(SMMU_DEVICE_OBJ, open_iova, open_frame, FRAME_SIZE)
        .map_err(|_| 198u32)?;
    direct_write64(open_frame, 0, DMA_PATTERN);
    edu_dma(&mut edu, open_iova, EDU_BUFFER, 8, EDU_DMA_START);
    direct_write64(open_frame, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        open_iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(open_frame, 0) != DMA_PATTERN {
        return Err(199);
    }

    // --- And a protected one, which does not ---
    //
    // The rule is asked, and its answer is what stops the mapping. Nothing here
    // decides not to map: `attach_permitted` decides, and it is the same
    // function `DmaAttach` consults.
    if !attach_permitted(MemoryClass::Unclassified, device_rights) {
        // The unclassified case must be permitted, or the round trip above
        // proved nothing about classification.
        return Err(200);
    }
    if attach_permitted(MemoryClass::Protected, device_rights) {
        return Err(201);
    }
    // The address the refused attach would have returned. Taken from the
    // aperture, so it is an address this device is entitled to — and left
    // unmapped, because the rule said no.
    //
    // SAFETY: transient raw access to the static executive; single-threaded
    // boot with no other thread live, as everywhere else in this check.
    let sealed_iova = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(202u32)?;
        exec.device_allocate_in_aperture(SMMU_DEVICE_OBJ, FRAME_SIZE)
            .ok_or(202u32)?
    };
    if sealed_iova < base || sealed_iova >= base + aperture_len {
        return Err(203);
    }

    // --- The device tries anyway, and the hardware refuses it ---
    smmu.drain_events();
    let before = SMMU_FAULTS_BY_INTERRUPT.load(Ordering::SeqCst);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        sealed_iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: unmasking and re-masking at EL1 is a PSTATE write on the boot
    // CPU, which owns the machine here.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
    }
    let mut settle = 200_000u32;
    while SMMU_FAULTS_BY_INTERRUPT.load(Ordering::SeqCst) == before && settle > 0 {
        settle -= 1;
        core::hint::spin_loop();
    }
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack));
    }
    let by_interrupt = SMMU_FAULTS_BY_INTERRUPT
        .load(Ordering::SeqCst)
        .saturating_sub(before);
    if by_interrupt == 0 {
        return Err(204);
    }

    // And the buffer the device *was* entitled to still works, so the refusal
    // is scoped to the memory that was classified rather than having broken the
    // device's aperture. The device still holds the pattern in its own buffer —
    // the refused transfer read from there and wrote nowhere — so writing it
    // back is the same round trip that worked before.
    direct_write64(open_frame, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        open_iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(open_frame, 0) != DMA_PATTERN {
        return Err(205);
    }

    let record = smmu.drain_events().ok_or(206u32)?;
    if record.kind != tessera_smmu::event::F_TRANSLATION || record.stream != stream {
        return Err(207);
    }

    Ok(ProtectedDma {
        stream,
        refused_at: sealed_iova,
        aperture: (base, aperture_len),
        by_interrupt,
    })
}

/// Runs one `edu` DMA transfer and waits for it to finish.
///
/// **Waits in time, not in iterations.** This device runs its DMA off a timer
/// with a delay measured in milliseconds, and a spin counted in loop
/// iterations expires in whatever wall time those happen to take. That is what
/// made an earlier version conclude the SMMU was refusing transfers it had not
/// been given time to perform (D119).
pub(crate) fn edu_dma(edu: &mut BarWindow, src: u64, dst: u64, count: u64, cmd: u64) {
    // Whole 64-bit writes: the device decodes these registers at their own
    // offsets only, so a split access loses the upper half silently.
    edu.write64(EDU_DMA_SRC, src);
    edu.write64(EDU_DMA_DST, dst);
    edu.write64(EDU_DMA_COUNT, count);
    // The command register ignores a write without the start bit, so this is
    // what actually launches the transfer.
    edu.write64(EDU_DMA_CMD, cmd);
    let hz = <Cpu as tessera_karch::CpuOps>::counter_hz().unwrap_or(62_500_000);
    let deadline = <Cpu as tessera_karch::CpuOps>::counter_serialized() + hz; // one second
    while edu.read64(EDU_DMA_CMD) & EDU_DMA_START != 0
        && <Cpu as tessera_karch::CpuOps>::counter_serialized() < deadline
    {
        core::hint::spin_loop();
    }
}

