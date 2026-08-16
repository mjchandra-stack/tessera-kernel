// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A driver dies and the system recovers: the crash, the slot watch that
//! notices, and the switch that becomes pullable.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// **A client parked on a driver that dies.**
///
/// Its own run, and it has to be: a crash that leaves the certifier without an
/// answer destroys the transcript the other checks are built on, so this cannot
/// share the run that produces them. A fresh executive, a driver told to take
/// one request and never reply, and a client that calls it.
///
/// What is being asked is not whether the driver died — that is arranged — but
/// whether **the client came back**. Before `close_endpoints_of`, it did not:
/// the call parked awaiting a reply, the server stopped existing, and nothing
/// connected the two, so the thread stayed blocked and the run ended with it
/// still waiting. A client that never returns reports nothing at all, which is
/// exactly how this reads: the report count is the evidence.
pub(crate) fn crash_recovery_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
    layout: kcore::devmgr::DeviceLayout,
    bar_base: u64,
    bar_len: u64,
) -> Result<bool, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1501u32)?;
        exec.device_register_identified(
            CRASH_DEVICE_OBJ,
            bar_base,
            bar_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            kcore::devmgr::DeviceIdentity {
                class_code: function.class_code,
                vendor: function.vendor,
                device: function.device,
                bdf: (u16::from(function.bdf.bus) << 8)
                    | (u16::from(function.bdf.device) << 3)
                    | u16::from(function.bdf.function),
                revision: function.revision,
                bus: kcore::devmgr::DeviceBus::Pci,
            },
        )
        .map_err(|_| 1502u32)?;
        exec.device_set_layout(CRASH_DEVICE_OBJ, layout)
            .map_err(|_| 1503u32)?;
        let manager = exec.channel_create().map_err(|_| 1504u32)?;
        exec.bind_endpoint_object(manager.0, CRASH_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, CRASH_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 1505u32)?;
        exec.bind_endpoint_object(service.0, CRASH_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, CRASH_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        CRASH_MANAGER_KSTACK_VA,
        1,
        CRASH_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1510,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::crypto_driver(),
        CRASH_DRIVER_KSTACK_VA,
        CRASH_BEFORE_REPLYING,
        CRASH_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1520,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        components::certifier(),
        CRASH_CLIENT_KSTACK_VA,
        CERTIFIED_DRIVER_ID,
        CRASH_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        1530,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(1501u32)?;
            manager
                .handles_mut()
                .install(CRASH_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1511u32)?;
            manager
                .handles_mut()
                .install(
                    CRASH_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 1511u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(1521u32)?;
            driver
                .handles_mut()
                .install(CRASH_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 1521u32)?;
            driver
                .handles_mut()
                .install(CRASH_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1521u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(1531u32)?
            .handles_mut()
            .install(CRASH_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 1531u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable —
    // which, before this milestone, is precisely what a client left blocked
    // forever looked like.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    // The driver was supposed to die. If it did not, the run proved nothing
    // about recovery and must say so rather than passing on a crash that never
    // happened.
    let crashed = EL0_SINK_FAULT.load(Ordering::SeqCst) != 0;
    // And the client was supposed to come back. A client still parked reports
    // nothing at all, so the count is the whole evidence.
    let client_report = EL0_REPORTS[0].load(Ordering::SeqCst);
    let returned = EL0_REPORT_COUNT.load(Ordering::SeqCst) > 0;
    // With an error, and specifically the channel call's. A client that came
    // back claiming success would be worse than one that hung.
    let with_an_error = client_report & 0xffff_0000_0000_0000 == CLIENT_FAIL_TAG
        && (client_report >> 16) & 0xffff == CLIENT_CHANNEL_STAGE;

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        CRASH_CLIENT_KSTACK_VA,
        CRASH_DRIVER_KSTACK_VA,
        CRASH_MANAGER_KSTACK_VA,
    ] {
        for page in 0..RING3_HOST_KSTACK_PAGES {
            if let Ok(frame) = kernel_space
                .arch_mut()
                .unmap(VirtAddr::new(kstack + page * FRAME_SIZE))
            {
                frames.free_frame(frame);
            }
        }
    }
    // SAFETY: transient raw access; each process is removed and torn down once.
    unsafe {
        for proc_idx in [client_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }

    if !crashed {
        return Err(1540);
    }
    Ok(returned && with_an_error)
}

// --- Removal while ring 3 is running: the guest's half of hotplug, on the
// periodic tick ---

/// What the slot watch has seen so far.
///
/// Four states rather than a flag, because the two middle ones are different
/// facts and collapsing them would make the check unable to say which half
/// failed: a slot that never asked and a slot that asked and was never answered
/// are an absent request and a broken guest.
pub(crate) mod slot_watch {
    /// Nothing is being watched.
    pub const IDLE: u32 = 0;
    /// A port and the device below it are being watched, and no eject has been
    /// requested yet.
    pub const ARMED: u32 = 1;
    /// The eject was requested and this guest answered it. The device has not
    /// stopped answering config space yet.
    pub const ACKNOWLEDGED: u32 = 2;
    /// Config space stopped answering and the graph was told.
    pub const REMOVED: u32 = 3;
}

pub(crate) static SLOT_WATCH_STATE: AtomicU32 = AtomicU32::new(slot_watch::IDLE);
pub(crate) static SLOT_WATCH_ECAM: AtomicU64 = AtomicU64::new(0);
pub(crate) static SLOT_WATCH_ECAM_LEN: AtomicU64 = AtomicU64::new(0);
/// The host's bus range, `first << 8 | last`.
pub(crate) static SLOT_WATCH_BUSES: AtomicU32 = AtomicU32::new(0);
/// The port whose slot is watched, and the endpoint below it, each packed as
/// `bus << 16 | device << 8 | function`.
pub(crate) static SLOT_WATCH_PORT: AtomicU32 = AtomicU32::new(0);
pub(crate) static SLOT_WATCH_DEVICE: AtomicU32 = AtomicU32::new(0);
/// The graph node the endpoint is, so the removal can name it.
pub(crate) static SLOT_WATCH_OBJECT: AtomicU32 = AtomicU32::new(0);
/// How many ticks looked, so a run in which the hook never fired is
/// distinguishable from one in which it looked and saw nothing.
pub(crate) static SLOT_WATCH_POLLS: AtomicU64 = AtomicU64::new(0);
/// How many graph nodes the removal took.
pub(crate) static SLOT_WATCH_SUBTREE: AtomicU32 = AtomicU32::new(0);

pub(crate) fn pack_bdf(bdf: tessera_pci::Bdf) -> u32 {
    (u32::from(bdf.bus) << 16) | (u32::from(bdf.device) << 8) | u32::from(bdf.function)
}

pub(crate) fn unpack_bdf(packed: u32) -> Option<tessera_pci::Bdf> {
    tessera_pci::Bdf::new(
        ((packed >> 16) & 0xff) as u8,
        ((packed >> 8) & 0xff) as u8,
        (packed & 0xff) as u8,
    )
}

/// Starts watching `port`'s slot for an eject, and `device` for the moment it
/// stops answering.
///
/// Everything the watch needs is copied into integers rather than borrowed.
/// `tessera_pci::Host` and `EcamWindow` are four numbers and one number
/// respectively, so the tick hook rebuilds them instead of holding a reference
/// into a boot stack frame that a later check will reuse.
pub(crate) fn arm_slot_watch(
    host: &tessera_pci::Host,
    port: tessera_pci::Bdf,
    device: tessera_pci::Bdf,
    object: kcore::object::ObjectId,
) {
    SLOT_WATCH_ECAM.store(host.ecam_base, Ordering::SeqCst);
    SLOT_WATCH_ECAM_LEN.store(host.ecam_len, Ordering::SeqCst);
    SLOT_WATCH_BUSES.store(
        (u32::from(host.first_bus) << 8) | u32::from(host.last_bus),
        Ordering::SeqCst,
    );
    SLOT_WATCH_PORT.store(pack_bdf(port), Ordering::SeqCst);
    SLOT_WATCH_DEVICE.store(pack_bdf(device), Ordering::SeqCst);
    SLOT_WATCH_OBJECT.store(object.raw(), Ordering::SeqCst);
    SLOT_WATCH_POLLS.store(0, Ordering::SeqCst);
    SLOT_WATCH_SUBTREE.store(0, Ordering::SeqCst);
    SLOT_WATCH_STATE.store(slot_watch::ARMED, Ordering::SeqCst);
}

pub(crate) fn disarm_slot_watch() {
    SLOT_WATCH_STATE.store(slot_watch::IDLE, Ordering::SeqCst);
}

/// A tick that does nothing, for restoring the state this check found: no hook
/// at all. There is no way to unregister one, and a hook that counted would
/// perturb the check that owns the counter.
pub(crate) fn on_tick_idle() {}

/// The periodic tick, watching a hot-pluggable slot.
///
/// **This exists because a removal cannot happen while ring 3 is running
/// otherwise.** A hot-pluggable slot does not simply lose its device: the port
/// raises an eject request and waits for the guest to answer, because the
/// software using the device is the only thing that knows whether it is
/// mid-transfer. The existing removal check answers in a boot loop, with no
/// thread alive — which is exactly the situation a driver is never in. During
/// `Scheduler::run` the boot CPU is inside the scheduler and nothing polls, so
/// `device_del` on a running machine is a request nobody ever answers and the
/// device stays. That was measured, not assumed.
///
/// The tick is the one thing that already fires during a run, so the guest's
/// half lives here. It does the same two things the boot loop does, in the same
/// order and for the same reasons: answer the request once, then watch config
/// space, because acknowledging is a request to de-energize the slot and what
/// makes a device *gone* is that it stops answering.
pub(crate) fn on_tick_watching_a_slot() {
    // **Deliberately not `OBSERVED_TICKS`.** That counter belongs to
    // `timer_check`, which waits on it and then compares it against the
    // architecture's own tick count — and the architecture's is reset by
    // `start_periodic` while this one never is. A hook that incremented it here
    // would leave that check already past its threshold before its timer had
    // ticked once, so it would compare a fresh hardware count against a stale
    // software one and fail. Found by doing exactly that. This watch counts its
    // own looks, in `SLOT_WATCH_POLLS`.
    let state = SLOT_WATCH_STATE.load(Ordering::SeqCst);
    if state != slot_watch::ARMED && state != slot_watch::ACKNOWLEDGED {
        return;
    }
    let buses = SLOT_WATCH_BUSES.load(Ordering::SeqCst);
    let host = tessera_pci::Host {
        ecam_base: SLOT_WATCH_ECAM.load(Ordering::SeqCst),
        ecam_len: SLOT_WATCH_ECAM_LEN.load(Ordering::SeqCst),
        first_bus: ((buses >> 8) & 0xff) as u8,
        last_bus: (buses & 0xff) as u8,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    let (Some(port), Some(device)) = (
        unpack_bdf(SLOT_WATCH_PORT.load(Ordering::SeqCst)),
        unpack_bdf(SLOT_WATCH_DEVICE.load(Ordering::SeqCst)),
    ) else {
        return;
    };
    SLOT_WATCH_POLLS.fetch_add(1, Ordering::SeqCst);

    match host.read(&config, device, 0) {
        // Still there. Answer the eject if one has been raised and this guest
        // has not answered yet — once, because the acknowledgement clears the
        // status bits and a second request would be a different removal.
        Ok(vendor) if vendor != 0xffff_ffff => {
            if state == slot_watch::ARMED
                && tessera_pci::eject_requested(&host, &config, port).unwrap_or(false)
                && tessera_pci::acknowledge_eject(&host, &mut config, port).is_ok()
            {
                SLOT_WATCH_STATE.store(slot_watch::ACKNOWLEDGED, Ordering::SeqCst);
            }
        }
        // Gone. Tell the graph, which is what invalidates the capabilities
        // naming it and wakes whoever was parked on its interrupt.
        _ => {
            let object =
                kcore::object::ObjectId::from_raw(SLOT_WATCH_OBJECT.load(Ordering::SeqCst));
            // SAFETY: transient raw access to the statics. The tick is an IRQ
            // and AArch64 masks interrupts on exception entry, so this cannot
            // preempt `el0_dispatch_hook` — which is the only other holder of
            // these — and the two never overlap. The state is moved to
            // `REMOVED` first, so a tick that arrived during this one would
            // return at the top rather than remove twice.
            unsafe {
                SLOT_WATCH_STATE.store(slot_watch::REMOVED, Ordering::SeqCst);
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    let processes = &mut *(&raw mut KCORE_PROCESSES);
                    let report = exec.remove_device(
                        object,
                        kcore::lifecycle::TransitionReason::Removed,
                        processes,
                        None,
                        None,
                    );
                    SLOT_WATCH_SUBTREE.store(report.subtree as u32, Ordering::SeqCst);
                }
            }
        }
    }
}

// --- Certification: a run of the checks, and the refusal it produces (D161) ---

pub(crate) const CERT_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d0);
pub(crate) const CERT_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d1);
pub(crate) const CERT_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d2);
pub(crate) const CERT_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d3);
pub(crate) const CERT_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d4);
pub(crate) const CERT_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d5);
pub(crate) const CERT_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d6);
pub(crate) const CERT_CERTIFIER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d7);
/// The bridge this check holds only so that something can be pulled out from
/// under a running machine.
pub(crate) const CERT_VICTIM_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d8);

/// Ticks to wait for a pull that was asked for from outside.
///
/// Twenty seconds at `TICK_HZ`, which is generous for a request the driving
/// script makes within a second of the armed marker — and short enough that the
/// cases where the pull never lands *fail* rather than crawl. It was two
/// hundred seconds first, and the two inversions that prove this mechanism both
/// took that long to report what they knew in the first tick: a bound sized so
/// nothing could ever hit it makes every negative result expensive.
pub(crate) const SLOT_WATCH_SETTLE: u32 = 2_000;

/// The root port and the bridge below it, if this machine has that shape.
///
/// Read off the bus numbers rather than the parent edges: a root port is a
/// bridge on the host's own first bus, and the switch is a bridge on any bus
/// below it. That is enough here because the topology is one of each — a
/// machine with two would need the edges, and a check that guessed between them
/// would be watching the wrong slot.
pub(crate) fn pullable_switch<'a>(
    first_bus: u8,
    functions: &'a [tessera_pci::Function],
) -> Option<(&'a tessera_pci::Function, &'a tessera_pci::Function)> {
    let bridges = || {
        functions
            .iter()
            .filter(|f| f.class_code >> 8 == RELAY_CLASS_BRIDGE >> 8)
    };
    let port = bridges().find(|f| f.bdf.bus == first_bus)?;
    let switch = bridges().find(|f| f.bdf.bus != first_bus)?;
    Some((port, switch))
}

pub(crate) const CERT_MANAGER_KSTACK_VA: u64 = 0xffff_000d_a000_0000;
pub(crate) const CERT_DRIVER_KSTACK_VA: u64 = 0xffff_000d_b000_0000;
pub(crate) const CERT_CERTIFIER_KSTACK_VA: u64 = 0xffff_000d_c000_0000;

/// **What boot tells the certifier it is certifying.**
///
/// A client observes behaviour and cannot observe identity: whoever answers its
/// channel is "the driver" from the inside, whatever it is, so a certificate a
/// client filled in for itself would be a certificate about nothing in
/// particular. Boot spawned the process and is what knows.
///
/// The low half of the manifest's driver signature. The record's `driver` field
/// is 32 bits and a signature is 64, which is survivable exactly because this
/// field was never the identity — the artifact's measurement is, which is why
/// the record carries a digest at all (build/README.md, D161).
pub(crate) const CERTIFIED_DRIVER_ID: usize = 0x6572_6100;

/// The class and contract version the certificate is about — the crypto class,
/// and the version its `Describe` reply names.
pub(crate) const CERTIFIED_DEVICE_CLASS: u32 = 10;
pub(crate) const CERTIFIED_CONTRACT_VERSION: u32 = 1;

/// The five checks this machine can make: the certifier's two, the two only
/// boot can see, and the one that happened before the machine existed.
pub(crate) const CERTIFIED_CHECKS_RAN: u32 = tessera_certification::Check::AbiConformance.bit()
    | tessera_certification::Check::ClassConformance.bit()
    | tessera_certification::Check::TraceSchema.bit()
    | tessera_certification::Check::SecurityPolicy.bit()
    | tessera_certification::Check::DmaFault.bit()
    | tessera_certification::Check::Power.bit()
    | tessera_certification::Check::SuspendResume.bit()
    | tessera_certification::Check::CrashRecovery.bit()
    | tessera_certification::Check::Fuzz.bit();

/// The one check this machine runs and this driver does not pass.
///
/// **A failure, deliberately, and not a check left unrun.** This rig cannot
/// contain the device under test: QEMU's SMMU does not translate for a
/// virtio-crypto function, on bus zero or behind a root port, so the driver's
/// grants come back as physical addresses. The honest answer to "is this
/// driver's DMA contained" is therefore *no*, and recording it as such is the
/// difference the certificate exists to keep — a check that failed and said why
/// is worth more than a check nobody ran, and collapsing the two would lose the
/// only thing distinguishing an unfit driver from an absent rig
/// (build/README.md, D166).
pub(crate) const CERTIFIED_CHECKS_FAILED: u32 = tessera_certification::Check::DmaFault.bit();

