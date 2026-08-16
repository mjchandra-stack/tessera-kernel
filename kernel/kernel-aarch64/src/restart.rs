// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The restart ladder: one crash contained, the device given back, and the
//! replacement bound to it.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Runs one host that is asked to crash, contains it, records the ladder's
/// first and sixth steps, and reclaims the corpse.
///
/// Returns whether the host actually faulted. `false` means it exited or never
/// got there, which the caller must treat as a failure rather than as a
/// recovery — a supervisor that reports restarting a host that never crashed
/// is reporting work it did not do.
///
/// **The supervisor names no device.** It does not know what this driver held
/// and does not need to: `reclaim_devices` hands whatever it was holding back
/// to the manager, which is what makes forgetting impossible rather than
/// merely unlikely.
#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise_one_crash(
    supervisor: &mut kcore::supervise::RestartSupervisor,
    kstack: u64,
    proc_obj: kcore::object::ObjectId,
    device_obj: kcore::object::ObjectId,
    manager_client_obj: kcore::object::ObjectId,
    manager_client_ep: kcore::ipc::EndpointId,
    kernel_space: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    base_err: u32,
) -> Result<bool, u32> {
    use kcore::rights::Rights;

    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_SINK_FAULT_ADDR.store(0, Ordering::SeqCst);
    EL0_SINK_FAULT_CORRELATION.store(0, Ordering::SeqCst);

    let (idx, proc) = ring3_host_spawn(
        components::blk_probe(),
        kstack,
        BLK_PROBE_CRASH_AFTER_BIND as usize,
        proc_obj,
        kernel_space,
        frames,
        base_err,
    )?;
    // SAFETY: transient raw access to the static process table; the process
    // was just inserted and no thread of it has run.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(proc)
            .ok_or(base_err + 1)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| base_err + 1)?;
    }
    supervisor.launched();
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }

    let syndrome = EL0_SINK_FAULT.load(Ordering::SeqCst);
    if syndrome != 0 {
        let correlation = EL0_SINK_FAULT_CORRELATION.load(Ordering::SeqCst);
        let address = EL0_SINK_FAULT_ADDR.load(Ordering::SeqCst);
        // Ladder step 1. Adopt the dead host's cause before recording
        // anything: `run()` returned through a yield to boot, which left the
        // ambient context on boot's own id, and without this the ladder roots
        // a fresh trace and the restart cannot be joined to the crash.
        kcore::trace::set_current_correlation(correlation);
        supervisor.crashed(syndrome, address);

        // Ladder step 3: the dump, and the tail of the trace the dead host
        // left behind. Taken **before** the corpse is torn down and before the
        // ring fills with teardown records, because the trail this is for is
        // the one leading up to the fault.
        //
        // The dump is a kilobyte and lives here rather than in a static: it is
        // read by the check that follows and by nothing else, and a static
        // would outlive the crash it describes.
        let mut dump = CRASH_DUMP_TEMPLATE;
        kcore::supervise::capture_crash_dump(&mut dump, proc_obj, syndrome, address, correlation);
        CRASH_DUMP_RECORDS.store(dump.captured as u32, Ordering::SeqCst);

        // **Steps 4 and 5 need the binding, and this is where a supervisor
        // does know one.** It does not know everything the driver held — that
        // is reclaim's job below, and the whole reason reclaim names nothing —
        // but it was asked to supervise a (driver, device) pair, and steps 4
        // and 5 are about the device half of it.
        // SAFETY: transient raw access to the static executive; every thread
        // is off-CPU here.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                // Step 4: tell the services that depend on this device.
                exec.notify_dependents(
                    device_obj,
                    kcore::lifecycle::DriverState::Degraded,
                    kcore::lifecycle::TransitionReason::DriverCrashed,
                );
                // Step 5: attempt a reset, if policy allows. A device whose
                // driver died mid-flight has queues the kernel cannot reason
                // about; the next driver should not inherit them.
                //
                // A refusal is recorded and not fatal: a reset that cannot be
                // performed is a rung the ladder could not climb, and the
                // rungs below it still apply.
                let mut resetter = VirtioMmioResetter;
                let _ = exec.reset_device(
                    device_obj,
                    kcore::devmgr::ResetPolicy::OnDegraded,
                    Some(&mut resetter),
                );
            }
        }
    }

    // Reclaim, whether or not it crashed: a host that exited still has to be
    // taken down, and leaving one behind would corrupt the next launch's
    // scheduler slot.
    //
    // The free-list depth, not `handed_out`: the latter is cumulative and
    // never decreases, so a delta across a reclaim would always be zero.
    let free_before = frames.free_list_depth();
    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(idx);
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(proc) {
                let mapper = (!EL0_DISPATCH_IOMMU.is_null())
                    .then(|| &mut *EL0_DISPATCH_IOMMU as &mut dyn kcore::devmgr::DmaMapper);
                let mut router = GicRouter;
                exec.reclaim_devices(dead, manager_client_ep, mapper, Some(&mut router));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(idx);
        if let Some(mut dead) = processes.remove(proc) {
            dead.space_mut().teardown(frames);
        }
    }
    let _ = kernel_space.reclaim_range(
        VirtAddr::new(kstack),
        RING3_HOST_KSTACK_PAGES * FRAME_SIZE,
        frames,
    );

    if syndrome != 0 {
        supervisor.restarted(frames.free_list_depth().saturating_sub(free_before) as u64);
    }
    // The sinks are cleared so the checks after this one do not read a
    // deliberate crash as their own failure.
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_SINK_FAULT_ADDR.store(0, Ordering::SeqCst);
    Ok(syndrome != 0)
}

/// What each incarnation of the block driver reports: the virtio magic rotated
/// by its incarnation number, so two successful runs cannot look like one run
/// counted twice.
pub(crate) const REBIND_EXPECTED: u64 = 0x7472_6976u64.rotate_left(8) ^ 0x7472_6976u64.rotate_left(16);

/// A driver dies; the device it held is handed to its replacement.
///
/// This is deliberately the smallest arrangement that can show it: one device
/// manager, and one minimal block driver run twice. No clients, no interrupts,
/// no select loop — the earlier attempts bolted this onto the resident host's
/// check and the handover was never the only thing in the picture.
///
/// The device object the rebind check registers its block transport under.
/// Named because two checks depend on it being the same object: the rebind
/// grants it twice, and the event check asserts that the records say so.
pub(crate) const REBIND_DEVICE_OBJECT: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(26);

/// The bridge the bound device sits behind, when it sits behind one.
///
/// Registered only when the enumeration actually found a parent. A graph that
/// invented a bus for a function on the root complex would be describing a
/// machine that does not exist, and the manager would derive its device from
/// something that is not there.
pub(crate) const REBIND_BRIDGE_OBJECT: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(27);

/// Negative self-test: a host that keeps crashing is restarted only up to its
/// budget, and then the supervisor stops.
///
/// **The ladder's most important property is the one a healthy machine never
/// shows.** Every other check here watches recovery succeed; this watches it
/// give up, because a supervisor without a bound is not a recovery policy —
/// it is a machine that respawns a broken driver until something else breaks.
///
/// The budget is deliberately smaller than the number of crashes available, so
/// what stops the loop is the budget and not the driver running out of ways to
/// fail. Returns the launches made, or an error code.
pub(crate) fn driver_giveup_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blk_base: u64,
    blk_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if components::device_manager().is_empty() || components::blk_probe().is_empty() {
        return Ok(0);
    }

    // A fresh executive: this check shares nothing with the ones before it.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    let device_obj = kcore::object::ObjectId::from_raw(28);
    let manager_server_obj = kcore::object::ObjectId::from_raw(68);
    let manager_client_obj = kcore::object::ObjectId::from_raw(69);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(70);
    let crash_proc_obj = kcore::object::ObjectId::from_raw(71);

    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(260u32)?;
        exec.device_register_mmio(
            device_obj,
            blk_base,
            blk_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 261u32)?;
        let channel = exec.channel_create().map_err(|_| 262u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        exec.device_add_dependent(device_obj, channel.1)
            .map_err(|_| 262u32)?;
        channel.1
    };

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kernel stacks and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // Expose the boot allocator to the syscall hook for the run only.
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        REBIND_MANAGER_KSTACK_VA,
        1,
        manager_proc_obj,
        &mut kernel_space,
        frames,
        263,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(264u32)?;
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 264u32)?;
        manager
            .handles_mut()
            .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .map_err(|_| 264u32)?;
    }

    let mut supervisor = kcore::supervise::RestartSupervisor::new(tessera_boot_checks::DRIVER_RESTART_SELFTEST_BUDGET);
    // The loop the budget has to stop. Its own guard is deliberately generous:
    // if `may_restart` never went false, this would spin past the budget and
    // the count below would catch it — a test whose runaway guard is the
    // thing under test proves nothing.
    let mut guard = tessera_boot_checks::DRIVER_RESTART_SELFTEST_BUDGET * 4 + 4;
    while supervisor.may_restart() && guard > 0 {
        guard -= 1;
        if !supervise_one_crash(
            &mut supervisor,
            REBIND_CRASH_KSTACK_VA,
            crash_proc_obj,
            device_obj,
            manager_client_obj,
            manager_client_ep,
            &mut kernel_space,
            frames,
            265,
        )? {
            return Err(268);
        }
    }
    supervisor.give_up(DRIVER_RESTART_GIVEUP_CODE);
    let outcome = supervisor.outcome();

    // Step 7 — the policy the ladder ends on, applied and read back, in
    // `tessera_boot_checks`: none of it is architectural.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let quarantined = unsafe {
        match (*(&raw mut KCORE_EXEC)).as_mut() {
            Some(exec) => tessera_boot_checks::apply_giveup_policy(exec, device_obj, &outcome),
            None => return Err(268),
        }
    };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // SAFETY: transient raw access; every thread is off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(manager_idx);
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(manager_idx);
        if let Some(mut gone) = processes.remove(manager_proc) {
            gone.space_mut().teardown(frames);
        }
    }
    let _ = kernel_space.reclaim_range(
        VirtAddr::new(REBIND_MANAGER_KSTACK_VA),
        RING3_HOST_KSTACK_PAGES * FRAME_SIZE,
        frames,
    );

    // SAFETY: transient raw access; every thread is off-CPU.
    let exec = unsafe { (*(&raw const KCORE_EXEC)).as_ref() };
    tessera_boot_checks::driver_giveup_verdict(exec, device_obj, &outcome, quarantined, 269, 270)?;
    Ok(outcome.launches)
}


/// What one run of [`driver_rebind_check`] observed.
pub(crate) struct RebindReports {
    /// What each incarnation reported, kept apart rather than folded.
    pub(crate) first: u64,
    pub(crate) second: u64,
    /// The device-visible base each incarnation's lease started at, when the
    /// device was behind an IOMMU. Both incarnations see the same value —
    /// which is the claim, not a coincidence.
    pub(crate) leased_at: Option<u64>,
    /// Whether the manager reached its device by **deriving it from a bus**
    /// rather than by being handed it.
    ///
    /// Not a report from the manager, and it does not need to be. When the
    /// device sits behind a bridge the kernel installs the *bridge* in the
    /// manager's table and nothing else — so a driver that was bound to the
    /// device at all can only have been given a capability the manager obtained
    /// from `DeviceChild`. There is no other way for one to exist.
    pub(crate) derived_from_bus: bool,
}

/// Reads the live DMA lease for `device` and checks it belongs to `holder`.
///
/// `scoped` says whether there should be one at all: a device behind no IOMMU
/// takes no lease, and finding one would mean the graph recorded something the
/// hardware is not enforcing.
pub(crate) fn observe_lease(
    device: kcore::object::ObjectId,
    holder: kcore::object::ObjectId,
    scoped: bool,
    base_err: u32,
) -> Result<Option<u64>, u32> {
    // SAFETY: transient raw access to the static executive; single-threaded
    // boot, and every thread of this check is off-CPU when this runs.
    let exec = unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }.ok_or(base_err)?;
    let held = exec.lease_holder_of_object(device);
    if !scoped {
        // No IOMMU: no lease, and the grant said so when it was made.
        return if held.is_none() {
            Ok(None)
        } else {
            Err(base_err + 1)
        };
    }
    if held != Some(holder) {
        return Err(base_err + 2);
    }
    let aperture = exec.aperture_of_object(device).ok_or(base_err + 3)?;
    if aperture.base != LEASE_BASE {
        return Err(base_err + 4);
    }
    Ok(Some(aperture.base))
}

/// `identity` is what the kernel learned enumerating the device, when it
/// learned anything: `Some` registers a device the manager can **classify
/// without reading it**, which is the only way a PCI function can be bound
/// (config space is not per-device, so no capability to it can be handed out).
/// `None` is a transport that says what it is in its own registers, and the
/// manager maps it and asks.
///
/// `smmu` is the unit the bound device's DMA passes through, with the stream id
/// its transactions arrive on. `Some` puts the device behind a translation and
/// lets its driver take a **DMA lease**; `None` is a device no IOMMU sits in
/// front of, whose grants are unscoped and say so.
///
/// Returns what each incarnation reported, in order — not folded together. See
/// [`EL0_REPORTS`] for why that distinction is load-bearing here.
/// What the kernel enumerated about one PCI function, in the form the resource
/// graph records identities in.
pub(crate) fn pci_identity(f: &tessera_pci::Function) -> kcore::devmgr::DeviceIdentity {
    kcore::devmgr::DeviceIdentity {
        class_code: f.class_code,
        vendor: f.vendor,
        device: f.device,
        bdf: (u16::from(f.bdf.bus) << 8)
            | (u16::from(f.bdf.device) << 3)
            | u16::from(f.bdf.function),
        revision: f.revision,
        bus: kcore::devmgr::DeviceBus::Pci,
    }
}

/// The sequence a supervisor actually performs: run the driver, watch it go,
/// **tear it down completely**, give the device back, start the replacement.
/// The "tear it down completely" step is not bookkeeping — see
/// `Process::forget_thread` for what a half-torn-down process does to the next
/// one that reuses its scheduler slot.
pub(crate) fn driver_rebind_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blk_base: u64,
    blk_len: u64,
    identity: Option<kcore::devmgr::DeviceIdentity>,
    layout: Option<kcore::devmgr::DeviceLayout>,
    smmu: Option<(&mut Smmu, u32)>,
    bridge: Option<kcore::devmgr::DeviceIdentity>,
) -> Result<RebindReports, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if components::device_manager().is_empty() || components::blk_probe().is_empty() {
        return Ok(RebindReports {
            first: 0,
            second: 0,
            leased_at: None,
            derived_from_bus: false,
        });
    }

    // A fresh executive: this check shares nothing with the ones before it.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    let device_obj = REBIND_DEVICE_OBJECT;
    let manager_server_obj = kcore::object::ObjectId::from_raw(62);
    let manager_client_obj = kcore::object::ObjectId::from_raw(63);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(64);
    let driver1_proc_obj = kcore::object::ObjectId::from_raw(65);
    let driver2_proc_obj = kcore::object::ObjectId::from_raw(66);
    // The crashing incarnations get their own process objects. Reusing one
    // across launches would have a replacement inserted under an id the dead
    // process still claims, which is the `Process::forget_thread` failure in
    // its other form.
    let crash_proc_obj = kcore::object::ObjectId::from_raw(67);

    // The device this check binds, and — when the kernel enumerated one — the
    // identity that lets the manager classify it without reading a register.
    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(220u32)?;
        let rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
        match identity {
            Some(identity) => {
                exec.device_register_identified(device_obj, blk_base, blk_len, rights, identity)
            }
            None => exec.device_register_mmio(device_obj, blk_base, blk_len, rights),
        }
        .map_err(|_| 221u32)?;
        // **Where the device's structures are** — the thing a driver holding
        // only a window cannot discover, because a virtio-pci function says so
        // in config space and config space is not per-device (D126's open
        // item). The kernel read it while enumerating; this is where it
        // becomes something a capability holder can ask for.
        if let Some(layout) = layout {
            exec.device_set_layout(device_obj, layout)
                .map_err(|_| 221u32)?;
        }
        // **The bus, when there is one.** The manager is handed the bridge
        // rather than the device, and derives the device from it — which is
        // what makes it a bus controller's manager rather than one holding an
        // inventory somebody else assembled.
        //
        // The bridge's own rights carry no MAP: a root port's register window
        // is nothing any holder should reach, and the child does not inherit
        // these anyway — `DeviceChild` hands out the graph's record for the
        // child, which is why a bus can be granted less than the devices on it.
        if let Some(bridge) = bridge {
            // Identified, so the manager can classify the hub and ask the
            // manifest what passing through it costs. Windowless still: a root
            // port's registers are nothing any holder should reach.
            exec.device_register_identified(
                REBIND_BRIDGE_OBJECT,
                0,
                0,
                Rights::READ | Rights::DERIVE,
                bridge,
            )
            .map_err(|_| 240u32)?;
            exec.device_set_parent(device_obj, REBIND_BRIDGE_OBJECT)
                .map_err(|_| 240u32)?;
        }
        let channel = exec.channel_create().map_err(|_| 222u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        // The manager **depends on** this device — ladder step 4's edge in the
        // graph. It is a dependent in the ordinary sense: it holds the
        // inventory, it is what a failure invalidates, and it is the one thing
        // on this machine that has to hear about a device going wrong whether
        // or not the capability finds its way back.
        exec.device_add_dependent(device_obj, channel.1)
            .map_err(|_| 222u32)?;
        channel.1
    };

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kernel stacks and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // Put the device behind its stream before anything can ask for DMA, and
    // publish the unit to the syscall hook for the run — the same set-and-clear
    // discipline `scoped_dma_check` uses. Without this a bound device's
    // `dma_alloc` would find no mapper and hand back a physical address.
    let smmu = match smmu {
        Some((unit, stream)) => {
            unit.register_stream(device_obj, stream, frames)
                .map_err(|_| 234u32)?;
            // SAFETY: `unit` outlives the run below; cleared before returning.
            unsafe { EL0_DISPATCH_IOMMU = unit };
            Some(unit)
        }
        None => None,
    };

    // Expose the boot allocator to the syscall hook for the run only.
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    reset_el0_reports();

    // The manager, holding the machine's one device. TRANSFER is what makes it
    // a manager rather than a driver that happens to hold something.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        REBIND_MANAGER_KSTACK_VA,
        1,
        manager_proc_obj,
        &mut kernel_space,
        frames,
        223,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(224u32)?;
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 224u32)?;
        // Handle 1 is the manager's inventory root. Behind a bridge that is the
        // **bus**, which the manager walks with `DeviceChild`; on a machine
        // whose function sits on the root complex it is the device itself, and
        // the manager finds a count of zero children and treats it as a leaf.
        // One code path, two machines, and no flag telling it which it is on.
        if bridge.is_some() {
            manager
                .handles_mut()
                .install(REBIND_BRIDGE_OBJECT, Rights::READ | Rights::DERIVE)
                .map_err(|_| 224u32)?;
        } else {
            manager
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
                .map_err(|_| 224u32)?;
        }
    }

    // --- The crash-recovery ladder, before the rebind it makes possible ---
    //
    // Incarnation 0 binds the device and then **faults on purpose**, holding
    // it. Everything after this point in the check used to begin with a driver
    // that exited tidily, which exercises teardown and not recovery: a corpse
    // that asked to leave has already given back everything it held. A host
    // killed mid-flight has not, and whether the device comes back from it is
    // the whole question the ladder answers.
    //
    // The supervisor's policy and its three records are `kcore::supervise`,
    // shared with the x86-64 port that has run this ladder since D51. What is
    // local is the architecture work: spawning a host, containing its fault,
    // and reclaiming the corpse.
    let mut supervisor = kcore::supervise::RestartSupervisor::new(DRIVER_RESTART_BUDGET);
    let crashed_before = supervise_one_crash(
        &mut supervisor,
        REBIND_CRASH_KSTACK_VA,
        crash_proc_obj,
        device_obj,
        manager_client_obj,
        manager_client_ep,
        &mut kernel_space,
        frames,
        236,
    )?;
    if !crashed_before {
        // The driver was supposed to die and did not, so nothing below is
        // testing recovery. Failing here beats passing a rebind that never
        // recovered from anything.
        return Err(239);
    }

    // Incarnation 1: binds the device, reads its identifying register, exits.
    let (driver1_idx, driver1_proc) = ring3_host_spawn(
        components::blk_probe(),
        REBIND_DRIVER1_KSTACK_VA,
        1,
        driver1_proc_obj,
        &mut kernel_space,
        frames,
        225,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(driver1_proc)
            .ok_or(226u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 226u32)?;
    }

    // Everything here is cooperative — a call, a reply, an exit — so the
    // scheduler runs to quiescence without a tick to prod it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    let first = EL0_REPORTS[0].load(Ordering::SeqCst);
    // A transport that identifies itself is expected to have been *driven*, so
    // the magic is the proof. A device the kernel classified is not: this
    // driver speaks no virtio-pci transport, and the identity it echoes is
    // what the caller checks instead.
    if identity.is_none() && first != 0x7472_6976u64.rotate_left(8) {
        return Err(227);
    }

    // The lease incarnation 1 took, before anything tears it down.
    let leased_at = observe_lease(device_obj, driver1_proc_obj, smmu.is_some(), 235)?;

    // The driver is gone. Tear it down completely — and note what the
    // supervisor does *not* do here: it never mentions the block device. It
    // does not know which devices this driver held, and does not need to. The
    // kernel hands whatever it was holding back to the manager as part of
    // teardown, so a supervisor cannot cost the machine a device by forgetting.
    //
    // Reaping alone is not teardown: it frees the scheduler slot while leaving
    // the dead process claiming the thread index, and the next spawn reuses it
    // — see `Process::forget_thread`.
    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver1_idx);
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(driver1_proc) {
                // The device goes back to the manager **and** its DMA lease
                // ends here — the supervisor names neither. It does not know
                // what this driver held, which is the point; the kernel does.
                //
                // **Register windows are not revoked here, and do not need to
                // be.** A window lives in the address space torn down below and
                // dies with it (D93). A DMA lease does not — it lives in the
                // IOMMU and would outlive this process entirely — which is the
                // whole reason this call takes a mapper at all. Reading the
                // lease teardown as covering windows too would have the
                // asymmetry exactly backwards.
                //
                // An interrupt route is the *second* thing on the wrong side of
                // that asymmetry: it lives in the GIC and in the port table,
                // both of which survive this teardown, so it is handed a router
                // for the same reason and by the same argument.
                let mapper = (!EL0_DISPATCH_IOMMU.is_null())
                    .then(|| &mut *EL0_DISPATCH_IOMMU as &mut dyn kcore::devmgr::DmaMapper);
                let mut router = GicRouter;
                exec.reclaim_devices(dead, manager_client_ep, mapper, Some(&mut router));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(driver1_idx);
        if let Some(mut dead) = processes.remove(driver1_proc) {
            dead.space_mut().teardown(frames);
        }
    }

    // The lease went with the driver. Checking this *between* the incarnations
    // is what makes the next one's lease a second lease rather than the first
    // one still standing.
    if smmu.is_some() {
        // SAFETY: transient raw access; every thread of this check is off-CPU.
        let held = unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
            .ok_or(240u32)?
            .lease_holder_of_object(device_obj);
        if held.is_some() {
            return Err(241);
        }
    }

    // Incarnation 2: the same program, a fresh process, no memory of the first.
    let (driver2_idx, driver2_proc) = ring3_host_spawn(
        components::blk_probe(),
        REBIND_DRIVER2_KSTACK_VA,
        2,
        driver2_proc_obj,
        &mut kernel_space,
        frames,
        229,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(driver2_proc)
            .ok_or(230u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 230u32)?;
    }

    // SAFETY: as the first run.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }

    // The replacement's lease, taken before the space is torn down — and it
    // must start where the first one did. A second driver handed the *next*
    // addresses instead would mean the window is being spent one restart at a
    // time, which no long-running machine survives.
    let second_lease = observe_lease(device_obj, driver2_proc_obj, smmu.is_some(), 245)?;
    if second_lease != leased_at {
        return Err(250);
    }

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe {
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
        EL0_DISPATCH_IOMMU = core::ptr::null_mut();
    }

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(232);
    }
    let second = EL0_REPORTS[1].load(Ordering::SeqCst);
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        // Two drivers, two reports. More means someone else reported into this
        // check; fewer means an incarnation never got there.
        return Err(234);
    }
    if identity.is_none() && EL0_SINK_LOG.load(Ordering::SeqCst) != REBIND_EXPECTED {
        return Err(233);
    }

    // Teardown.
    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver2_idx);
            exec.scheduler().reap(manager_idx);
            // The replacement's lease ends before its frames go back to the
            // allocator, not after: in the gap the device would still name
            // memory the kernel had already handed to something else.
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(driver2_proc) {
                exec.end_device_leases(dead, smmu.map(|u| u as &mut dyn kcore::devmgr::DmaMapper));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(driver2_idx);
        processes.forget_thread(manager_idx);
        for idx in [driver2_proc, manager_proc] {
            if let Some(mut gone) = processes.remove(idx) {
                gone.space_mut().teardown(frames);
            }
        }
    }
    for kstack in [
        REBIND_MANAGER_KSTACK_VA,
        REBIND_DRIVER1_KSTACK_VA,
        REBIND_DRIVER2_KSTACK_VA,
    ] {
        let _ = kernel_space.reclaim_range(
            VirtAddr::new(kstack),
            RING3_HOST_KSTACK_PAGES * FRAME_SIZE,
            frames,
        );
    }
    Ok(RebindReports {
        first,
        second,
        leased_at,
        derived_from_bus: bridge.is_some(),
    })
}

