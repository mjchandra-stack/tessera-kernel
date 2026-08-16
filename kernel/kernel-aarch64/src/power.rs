// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Power: the transitions a machine makes, the RTC that wakes it, and suspend.
//!
//! Normative: docs/kernel/08-power-management.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// What the run must produce.
pub(crate) struct PowerOutcome {
    /// The three replies, as the voters saw them.
    pub(crate) replies: [u64; 3],
    /// The lifecycle state the kernel has recorded for the device afterwards.
    pub(crate) device_state: kcore::lifecycle::DriverState,
}

/// Proves the first thing in this system that **arbitrates**: three processes
/// vote on one power domain and a service weighs them.
///
/// Every contract here has declared power states and resume latencies since
/// D128, and nothing weighed one voter's requirement against another's — a
/// test client sent `SetPower(IDLE)` and then `SetPower(ACTIVE)` because the
/// two lines were next to each other in a transcript, which is a device
/// changing state rather than a system deciding it should.
///
/// The three voters run one at a time, and that is what makes the transcript a
/// sequence rather than a race: each is spawned, runs to its exit, and only
/// then is the next spawned. The manager stays parked on its port between
/// them, which is also the point — it is a resident service, not a script.
pub(crate) fn power_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<PowerOutcome, u32> {
    use kcore::lifecycle::{DriverState, TransitionReason};
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if components::power_manager().is_empty() {
        return Err(1);
    }

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // The device the manager arbitrates *about*, and a node with **no
        // register window at all** — base and length zero, the same shape the
        // queue-child check's controller has. Narrating a lifecycle requires
        // `Rights::MAP` (D128: the same authority `MapDevice` and
        // `IrqComplete` need, so a process that has merely heard of a device
        // cannot tell its story), so the manager is granted it — and there is
        // still nothing behind it to reach. What the manager can do to this
        // device is say what state it is in; what it cannot do is touch it.
        exec.device_register_mmio(POWER_DEVICE_OBJ, 0, 0, Rights::READ | Rights::MAP)
            .map_err(|_| 11u32)?;
        // Boot brings the device up to service the way a device manager would
        // have. Binding is not the power manager's business, and a lifecycle
        // that opened at `Suspending` would be a history nobody lived.
        for (from, to, reason) in [
            (
                DriverState::Discovered,
                DriverState::Matched,
                TransitionReason::Bound,
            ),
            (
                DriverState::Matched,
                DriverState::Starting,
                TransitionReason::Launched,
            ),
            (
                DriverState::Starting,
                DriverState::Probing,
                TransitionReason::Launched,
            ),
            (
                DriverState::Probing,
                DriverState::Active,
                TransitionReason::ProbeSucceeded,
            ),
        ] {
            exec.declare_lifecycle(POWER_DEVICE_OBJ, from, to, reason, 0)
                .map_err(|_| 12u32)?;
        }

        // One channel per voter, and one service port bound to every
        // server-side endpoint: a message on any of them raises
        // `SIGNAL_MESSAGE` on that endpoint's object, so the manager's single
        // `PortWait` is a select that names who spoke. A manager receiving on
        // one endpoint at a time would deadlock the moment a different voter
        // called first.
        let port = exec.port_create().map_err(|_| 13u32)?;
        exec.bind_port_object(port, POWER_SERVICE_PORT_OBJ);
        for index in 0..POWER_SERVER_OBJS.len() {
            let (server, client) = exec.channel_create().map_err(|_| 14u32)?;
            let server_obj = kcore::object::ObjectId::from_raw(POWER_SERVER_OBJS[index]);
            exec.bind_endpoint_object(server, server_obj);
            exec.bind_endpoint_object(
                client,
                kcore::object::ObjectId::from_raw(POWER_CLIENT_OBJS[index]),
            );
            exec.port_bind(
                port,
                u64::from(server_obj.raw()),
                kcore::ipc::SIGNAL_MESSAGE,
            )
            .map_err(|_| 15u32)?;
        }
    }

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();

    // The manager spawns first and parks on its port before anybody calls —
    // the server-first pattern every check here uses.
    let (_manager_idx, manager_proc) = ring3_host_spawn(
        components::power_manager(),
        POWER_MANAGER_KSTACK_VA,
        // Manager mode: the argument is how many requests to serve. A resident
        // service has no opinion about how long it should live, so the
        // stopping condition is boot's rather than the program's.
        POWER_SERVER_OBJS.len(),
        POWER_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        20,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(30u32)?;
        manager
            .handles_mut()
            .install(POWER_SERVICE_PORT_OBJ, Rights::READ)
            .map_err(|_| 31u32)?;
        for object in POWER_SERVER_OBJS {
            manager
                .handles_mut()
                .install(kcore::object::ObjectId::from_raw(object), Rights::READ)
                .map_err(|_| 32u32)?;
        }
        manager
            .handles_mut()
            .install(POWER_DEVICE_OBJ, Rights::READ | Rights::MAP)
            .map_err(|_| 33u32)?;
    }

    // The three voters: a driver asking for what it needs to serve, a user
    // asking for more, and a thermal zone taking it away. Levels and classes
    // are `power_manager.isl`'s.
    const DRIVER_VOTE: usize = power_voter_arg(2, 3, 1);
    const USER_VOTE: usize = power_voter_arg(4, 1, 2);
    const THERMAL_VOTE: usize = power_voter_arg(2, 4, 3);

    let mut voter_procs = [0usize; 3];
    for (index, arg) in [DRIVER_VOTE, USER_VOTE, THERMAL_VOTE]
        .into_iter()
        .enumerate()
    {
        let (_idx, proc_idx) = ring3_host_spawn(
            components::power_manager(),
            POWER_VOTER_KSTACK_VAS[index],
            arg,
            kcore::object::ObjectId::from_raw(POWER_VOTER_PROC_OBJS[index]),
            &mut kernel_space,
            frames,
            40 + 10 * index as u32,
        )?;
        voter_procs[index] = proc_idx;
        // SAFETY: transient raw access to the static process table.
        unsafe {
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            let voter = processes.get_mut(proc_idx).ok_or(80u32)?;
            voter
                .handles_mut()
                .install(
                    kcore::object::ObjectId::from_raw(POWER_CLIENT_OBJS[index]),
                    Rights::WRITE,
                )
                .map_err(|_| 81u32)?;
        }
        // Run to a standstill before the next voter is spawned. That is what
        // makes the transcript a sequence: three concurrent voters would
        // resolve to the same final level but in an order nobody could
        // predict, and the intermediate replies are exactly what is being
        // checked.
        // SAFETY: transient raw access; `run` returns when nothing is runnable.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
    }

    // **Put the boot low half back before anything else.** A run leaves
    // `TTBR0` holding the last process's space, and this check then frees that
    // space — after which the live translation tables are frames the allocator
    // has handed to somebody else. Nothing fails at the moment it happens;
    // what fails is the next thing to touch a low address, which on this port
    // is the interrupt controller, in a check further down the boot.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    // Four reports: one per voter, then the manager's when it stops.
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 4 {
        return Err(90);
    }
    let mut replies = [
        EL0_REPORTS[0].load(Ordering::SeqCst),
        EL0_REPORTS[1].load(Ordering::SeqCst),
        EL0_REPORTS[2].load(Ordering::SeqCst),
    ];
    if replies[0] != POWER_STEP_1 {
        return Err(91);
    }
    if replies[1] != POWER_STEP_2 {
        return Err(92);
    }
    // The third voter and the manager both become runnable on the same reply,
    // so which of them reports first is the scheduler's business and not this
    // check's. Both values are required, in either order — the alternative
    // would be a check that passes or fails on a detail neither program
    // controls. Matched as a pair rather than folded together, so that one
    // report cannot stand in for the other.
    let tail = [replies[2], EL0_REPORTS[3].load(Ordering::SeqCst)];
    let thermal_reply = if tail == [POWER_STEP_3, POWER_MANAGER_WORD] {
        tail[0]
    } else if tail == [POWER_MANAGER_WORD, POWER_STEP_3] {
        tail[1]
    } else {
        return Err(93);
    };

    replies[2] = thermal_reply;

    // **The resolution happened to a device.** The manager drove it through
    // the states a power transition is defined to pass through; the kernel
    // refused none of them and has the state to prove it.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let device_state = unsafe { (*(&raw const KCORE_EXEC)).as_ref() }
        .and_then(|exec| exec.lifecycle_of_object(POWER_DEVICE_OBJ))
        .ok_or(94u32)?;
    if device_state != DriverState::Suspended {
        return Err(95);
    }

    // **And it moved three times, not once.** The final state alone would not
    // say so — but the kernel's edge table does: had the manager failed to
    // resume the device after step 2, step 3's `Active -> Suspending` would
    // have been declared from `Suspended`, which is refused, and the manager
    // would have reported a failure instead of its summary. The transcript is
    // enforced rather than counted.

    // Tear every process down before returning. The process table is shared
    // across every check in this boot, and a leftover process still owns a
    // thread index and a handle table — which is how a later check ends up
    // counting the wrong incarnations (D139).
    // SAFETY: transient raw access; every thread is off-CPU.
    unsafe {
        for proc_idx in voter_procs
            .into_iter()
            .chain(core::iter::once(manager_proc))
        {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
    }
    // SAFETY: the run is over; clear what was published for it.
    unsafe {
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    Ok(PowerOutcome {
        replies,
        device_state,
    })
}

// --- Runtime idle and a real wake source: the PL031 RTC (D141) ---

/// The `virt` machine's real-time clock. Chosen as this port's wakeup source
/// for the reason D104 chose the goldfish RTC on RISC-V: it is **real, on its
/// own interrupt line, and owned by no driver**. A virtio device only
/// interrupts for a request somebody made, so using one would mean idling with
/// work outstanding — which is not what runtime idle is, and would make the
/// proof describe a situation the policy would never create.
pub(crate) const PL031_COMPATIBLE: &[u8] = b"arm,pl031";
/// Register offsets. The counter, the match register the alarm compares
/// against, the interrupt mask, the masked status, and the write-one-to-clear.
pub(crate) const PL031_DR: u64 = 0x00;
pub(crate) const PL031_MR: u64 = 0x04;
pub(crate) const PL031_IMSC: u64 = 0x10;
pub(crate) const PL031_MIS: u64 = 0x18;
pub(crate) const PL031_ICR: u64 = 0x1c;

/// The RTC's registers, through the high-half mapping [`map_wake_source`]
/// makes.
///
/// The high half rather than the low-half device identity map, and that is
/// forced: the low half is `TTBR0`, which a running EL0 process owns, so an
/// address that worked before a process ran would be that process's memory
/// afterwards. `map_pci_windows` maps its windows high for the same reason.
pub(crate) struct Pl031 {
    base: u64,
}

impl Pl031 {
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: `base` is the RTC's register page, mapped Device-nGnRnE at
        // `DIRECT_MAP_BASE + phys` before this is built, and `offset` is a
        // defined 4-byte-aligned register inside the first 0x20 bytes of it.
        unsafe { tessera_karch_aarch64::mmio_read32((self.base + offset) as usize) }
    }

    fn write(&self, offset: u64, value: u32) {
        // SAFETY: as `read`; nothing else on this machine touches the RTC.
        unsafe {
            tessera_karch_aarch64::mmio_write32((self.base + offset) as usize, value);
        }
    }

    /// Sets the alarm `seconds` from now and unmasks its interrupt.
    ///
    /// The PL031 counts at 1 Hz, so one second is the shortest alarm this
    /// device can express. That is slow for a boot check and it is the price
    /// of the source being real — a faster wake would have to come from a
    /// device somebody owns, which is the thing this deliberately avoids.
    fn arm_alarm(&self, seconds: u32) {
        self.write(PL031_ICR, 1);
        let now = self.read(PL031_DR);
        self.write(PL031_MR, now.wrapping_add(seconds));
        self.write(PL031_IMSC, 1);
    }

    /// Whether the alarm has fired and not yet been acknowledged.
    fn fired(&self) -> bool {
        self.read(PL031_MIS) & 1 != 0
    }

    /// Acknowledges the alarm and masks the line.
    fn disarm(&self) {
        self.write(PL031_IMSC, 0);
        self.write(PL031_ICR, 1);
    }
}

/// Maps the RTC's register page into the high half and answers its VA.
pub(crate) fn map_wake_source(
    space: &mut KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    phys: u64,
) -> Result<u64, tessera_karch::KError> {
    const BLOCK: u64 = 2 * 1024 * 1024;
    let block = phys & !(BLOCK - 1);
    space.map_block_range(
        DIRECT_MAP_BASE + block,
        block,
        BLOCK,
        PageFlags::rw().global().device(),
        frames,
    )?;
    Ok(DIRECT_MAP_BASE + phys)
}

/// The wakeup source's INTID while [`wake_check`] runs (0 = none), on the same
/// enable-only-around-the-run discipline every other bridge here uses.
pub(crate) static POWER_WAKE_INTID: AtomicU32 = AtomicU32::new(0);

/// The wakeup-source bridge: mask the line, **count the wake**, then signal
/// the port.
///
/// The order is the whole point. A wake that is delivered but not counted is
/// exactly the lost wakeup the counter exists to close — delivery can wake a
/// process which then races a suspend entry, while counting first means the
/// number has already moved by the time anything can observe the event at all.
///
/// Masking before either is the storm rule every level-triggered source here
/// obeys: the trap path EOIs unconditionally, and the PL031 keeps its line
/// asserted until its status register is cleared.
pub(crate) fn wake_irq_hook(id: u32) -> bool {
    let wired = POWER_WAKE_INTID.load(Ordering::SeqCst);
    if wired == 0 || id != wired {
        return false;
    }
    // SAFETY: masking a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(id) };
    // SAFETY: as `virtio_irq_hook` — exception entry sets PSTATE.I, so this
    // can only have preempted EL0 or boot code outside the enable window, and
    // never a live Executive borrow.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.record_wake(id);
            exec.port_signal(id as u64, 1, 1);
        }
    }
    true
}

/// Kernel objects [`wake_check`] creates.
pub(crate) const WAKE_RTC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa0);
pub(crate) const WAKE_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa1);
/// The capability the power manager holds to say the machine must not sleep.
///
/// **Not a device and not, yet, an object class of its own.** What the kernel
/// checks when a hold is taken is the *right*, and the hold is attributed to
/// the calling process — so this handle is the gate rather than the subject. A
/// Power object with a table entry would give the gate something to be about;
/// the suspend commit will need one, and inventing it before then would be an
/// object nobody reads.
pub(crate) const WAKE_POWER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa2);
pub(crate) const WAKE_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa3);
pub(crate) const WAKE_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa4);
pub(crate) const WAKE_MANAGER_KSTACK_VA: u64 = 0xffff_0003_4000_0000;

/// The startup argument that asks the power manager to run its idle-and-wake
/// mode. Must match `WAKE_MODE` there.
pub(crate) const POWER_MANAGER_WAKE_MODE: usize = 1 << 62;

/// What the manager must report: one wake counted, the grace hold seen, the
/// domain idled, the capability without `Rights::WAKE` refused, and the device
/// back in service. One byte each, so a failure names which of the five went
/// wrong rather than only that something did.
pub(crate) const WAKE_EXPECTED: u64 = 1 | (1 << 8) | (1 << 16) | (1 << 24) | (1 << 32);

/// What the run must produce.
pub(crate) struct WakeOutcome {
    /// The manager's packed report.
    pub(crate) reported: u64,
    /// The system wake-event counter afterwards.
    pub(crate) events: u64,
    /// The lifecycle state the kernel has recorded for the idled device.
    pub(crate) device_state: kcore::lifecycle::DriverState,
    /// Whether the RTC is still armed as a wakeup source.
    pub(crate) still_armed: bool,
}

/// Proves runtime idle and the wake capability: a domain nobody is using drops
/// out of service, and a **real interrupt the kernel counted** brings it back.
///
/// D140 built something that arbitrates. What it could not do is let a domain
/// that had fallen to the floor come back on its own — there was nothing that
/// could wake a machine which had stopped, and no way to say which things were
/// allowed to.
///
/// The power manager here touches no register. It holds three capabilities —
/// the RTC with `Rights::WAKE`, a port, and the device whose lifecycle it
/// narrates — and boot owns the RTC itself, arms its alarm, and clears it
/// afterwards. That split is the design rather than a convenience: registering
/// a wakeup source is the manager's business and driving a clock is not.
pub(crate) fn wake_check(
    rtc: &tessera_devicetree::MmioDevice,
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<WakeOutcome, u32> {
    use kcore::lifecycle::{DriverState, TransitionReason};
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    if components::power_manager().is_empty() {
        return Err(1);
    }
    // A wakeup source with no interrupt is not a wakeup source. The device
    // tree is where that is settled, and a missing line is a fatal
    // misconfiguration rather than a silent downgrade to polling (D84).
    let intid = rtc.intid.ok_or(2u32)?;

    // SAFETY: `high` is the active kernel high-half; the alias maps the RTC
    // page and the manager's kernel stack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let rtc_va = {
        // SAFETY: the same alias, used only to add a Device mapping for a page
        // nothing else in the high half covers.
        let mut arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
        map_wake_source(&mut arch, frames, rtc.base).map_err(|_| 3u32)?
    };
    let clock = Pl031 { base: rtc_va };

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // The RTC as a graph node. `WAKE` is on the node's own rights because
        // that is what a kernel-originated hand-out of it carries; a device
        // nobody said may wake this machine could not be armed however it were
        // granted.
        exec.device_register_mmio(
            WAKE_RTC_OBJ,
            rtc.base,
            FRAME_SIZE,
            Rights::READ | Rights::WAKE,
        )
        .map_err(|_| 11u32)?;
        exec.device_set_mmio_irq(WAKE_RTC_OBJ, intid)
            .map_err(|_| 12u32)?;
        // The device that idles: windowless, as in D140, so the capability
        // carries the authority to narrate a lifecycle and nothing else.
        exec.device_register_mmio(WAKE_DEVICE_OBJ, 0, 0, Rights::READ | Rights::MAP)
            .map_err(|_| 13u32)?;
        for (from, to, reason) in [
            (
                DriverState::Discovered,
                DriverState::Matched,
                TransitionReason::Bound,
            ),
            (
                DriverState::Matched,
                DriverState::Starting,
                TransitionReason::Launched,
            ),
            (
                DriverState::Starting,
                DriverState::Probing,
                TransitionReason::Launched,
            ),
            (
                DriverState::Probing,
                DriverState::Active,
                TransitionReason::ProbeSucceeded,
            ),
        ] {
            exec.declare_lifecycle(WAKE_DEVICE_OBJ, from, to, reason, 0)
                .map_err(|_| 14u32)?;
        }
        // The route: the RTC's line, delivered to a port the manager holds.
        // Through the graph rather than as a bare port binding, so the wake
        // capability follows the device the way a register window and a DMA
        // lease already do.
        let port = exec.port_create().map_err(|_| 15u32)?;
        exec.bind_port_object(port, WAKE_PORT_OBJ);
        exec.device_route_irq(WAKE_RTC_OBJ, port, WAKE_MANAGER_PROC_OBJ)
            .map_err(|_| 16u32)?;
    }

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);

    let (_manager_idx, manager_proc) = ring3_host_spawn(
        components::power_manager(),
        WAKE_MANAGER_KSTACK_VA,
        POWER_MANAGER_WAKE_MODE,
        WAKE_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        20,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(30u32)?;
        let mut install = |object, rights| {
            manager
                .handles_mut()
                .install(object, rights)
                .map(|_| ())
                .map_err(|_| 31u32)
        };
        install(WAKE_PORT_OBJ, Rights::READ)?;
        install(WAKE_RTC_OBJ, Rights::READ | Rights::WAKE)?;
        install(WAKE_POWER_OBJ, Rights::READ | Rights::WAKE)?;
        install(WAKE_DEVICE_OBJ, Rights::READ | Rights::MAP)?;
        // **The same device, without `WAKE`.** The negative check is a handle
        // rather than a second boot: one capability can arm this line and the
        // other cannot, and the only difference between them is the right.
        install(WAKE_RTC_OBJ, Rights::READ)?;
    }

    // Arm the alarm and let the line through, strictly around the run.
    clock.arm_alarm(1);
    POWER_WAKE_INTID.store(intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(intid) };
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);

    // The interrupt pump (D84/D85): the manager parks on its port with nothing
    // else runnable, so `run` returns and the wake would be orphaned without a
    // boot context that waits for it. Unmasking every iteration is required —
    // `wfi` returns from a pending-but-masked interrupt without ever taking
    // it, and returning from a thread switch restores the boot context with
    // IRQs masked again.
    let mut pump_budget = 600u32;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable
        // (a parked thread may become Ready from interrupt context).
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if EL0_SINK_EXITED.load(Ordering::SeqCst) || pump_budget == 0 {
            break;
        }
        pump_budget -= 1;
        // SAFETY: the boot context owns the CPU here; the only handler that can
        // run is the interrupt bridge, which touches the port facility and the
        // wake counter, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();
    // **Put the boot low half back before anything else.** A run that ends
    // with a thread merely *parked* rather than exited leaves `TTBR0` holding
    // that process's space, so the console's identity mapping — and every
    // other device register the low half carries — is simply not there. Every
    // check that can end that way does this; the ones that cannot get away
    // without it, which is why it is easy to forget and expensive to debug.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    POWER_WAKE_INTID.store(0, Ordering::SeqCst);
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(intid) };
    clock.disarm();

    let reported = EL0_REPORTS[0].load(Ordering::SeqCst);
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(40);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(41);
    }
    if reported != WAKE_EXPECTED {
        return Err(44);
    }

    // SAFETY: transient raw access; every thread is off-CPU by here.
    let (events, device_state, still_armed) = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(42u32)?;
        (
            exec.wake_events(),
            exec.lifecycle_of_object(WAKE_DEVICE_OBJ).ok_or(43u32)?,
            exec.is_wake_source(WAKE_RTC_OBJ),
        )
    };

    // Tear the manager down before returning: the process table is shared
    // across every check in this boot, and a leftover process still owns a
    // thread index and a handle table (D139).
    // SAFETY: transient raw access; every thread is off-CPU.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(manager_proc) {
            process.space_mut().teardown(frames);
        }
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    // The kernel's own answers, independent of what the manager said about
    // itself: exactly one wake was counted, the device is back in service, and
    // nothing is left able to wake this machine.
    if events != 1 {
        return Err(45);
    }
    if device_state != DriverState::Active {
        return Err(46);
    }
    if still_armed {
        return Err(47);
    }

    Ok(WakeOutcome {
        reported,
        events,
        device_state,
        still_armed,
    })
}

// --- System suspend and resume, ordered by the device tree (D142) ---

/// Kernel objects [`suspend_check`] creates. The bus and the device behind it
/// are graph nodes with a real parent edge — the same edge `pcie_enumerate`
/// records for a function behind a bridge — and the manager is handed only the
/// bus, so it has to walk the graph to find the rest.
pub(crate) const SUSPEND_BUS_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb0);
pub(crate) const SUSPEND_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb1);
pub(crate) const SUSPEND_RTC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb2);
pub(crate) const SUSPEND_POWER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb3);
pub(crate) const SUSPEND_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb4);
pub(crate) const SUSPEND_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb5);
pub(crate) const SUSPEND_MANAGER_KSTACK_VA: u64 = 0xffff_0003_5000_0000;

/// The startup argument that asks the power manager to suspend the machine.
/// Must match `SUSPEND_MODE` there.
pub(crate) const POWER_MANAGER_SUSPEND_MODE: usize = 1 << 61;

/// What the manager must report: the wrong-order suspend refused, the
/// wrong-order resume refused, the commit resumed (1) naming a source, the
/// stale snapshot aborted as a wake having arrived (2), the held machine
/// refusing to stop (3), and both devices back in service. One byte each, so a
/// failure names which of the seven went wrong.
pub(crate) const SUSPEND_EXPECTED: u64 =
    1 | (1 << 8) | (1 << 16) | (1 << 24) | (2u64 << 32) | (3u64 << 40) | (1u64 << 48);

/// What the run must produce.
pub(crate) struct SuspendOutcomeReport {
    /// The manager's packed report.
    pub(crate) reported: u64,
    /// The lifecycle states the kernel has recorded afterwards.
    pub(crate) bus_state: kcore::lifecycle::DriverState,
    pub(crate) device_state: kcore::lifecycle::DriverState,
    /// The system wake-event counter.
    pub(crate) events: u64,
}

/// Proves that the whole machine stops and starts again, ordered by Phase 2's
/// dependency graph and committed by the kernel.
///
/// Three things are being shown, and the first is the one that could not have
/// been shown before this phase. **The ordering is enforced**: the manager
/// asks to suspend the bus while the device behind it is still serving, and
/// the kernel refuses — so leaves-before-parents is a property of the machine
/// rather than of whichever loop happens to be walking the tree. The mirror is
/// asked too, because resume runs parent-first and that is the half a manager
/// is most likely to get wrong.
///
/// **The commit is the kernel's.** The manager snapshots the wake-event
/// counter, calls `SystemSuspend`, and does not run again until something
/// wakes the machine — which here is a real alarm on a device nobody owns.
/// Nothing else is runnable while it sleeps, so the CPU reaches its idle loop,
/// which *is* suspend-to-idle.
///
/// **And it refuses when it should.** The same snapshot presented a second
/// time no longer matches, because the wake that ended the sleep moved the
/// counter — a real stale snapshot rather than a fabricated number. A wake
/// hold then refuses a commit whose snapshot is perfectly fresh.
pub(crate) fn suspend_check(
    rtc: &tessera_devicetree::MmioDevice,
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<SuspendOutcomeReport, u32> {
    use kcore::lifecycle::{DriverState, TransitionReason};
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    if components::power_manager().is_empty() {
        return Err(1);
    }
    let intid = rtc.intid.ok_or(2u32)?;

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let rtc_va = {
        // SAFETY: the same alias, adding a Device mapping for the RTC page.
        // Idempotent: `wake_check` has already made it, and mapping the same
        // block again over the same output is not a change.
        let mut arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
        map_wake_source(&mut arch, frames, rtc.base).unwrap_or(DIRECT_MAP_BASE + rtc.base)
    };
    let clock = Pl031 { base: rtc_va };

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // The bus, and the device behind it. Windowless: what is being tested
        // is the tree, and giving these register windows would add a thing to
        // get wrong that has nothing to do with ordering. `DERIVE` on the bus
        // is what lets the manager find the device without being told.
        exec.device_register_mmio(
            SUSPEND_BUS_OBJ,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::DERIVE,
        )
        .map_err(|_| 11u32)?;
        exec.device_register_mmio(SUSPEND_DEVICE_OBJ, 0, 0, Rights::READ | Rights::MAP)
            .map_err(|_| 12u32)?;
        exec.device_set_parent(SUSPEND_DEVICE_OBJ, SUSPEND_BUS_OBJ)
            .map_err(|_| 13u32)?;
        exec.device_register_mmio(
            SUSPEND_RTC_OBJ,
            rtc.base,
            FRAME_SIZE,
            Rights::READ | Rights::WAKE,
        )
        .map_err(|_| 14u32)?;
        exec.device_set_mmio_irq(SUSPEND_RTC_OBJ, intid)
            .map_err(|_| 15u32)?;

        for device in [SUSPEND_BUS_OBJ, SUSPEND_DEVICE_OBJ] {
            for (from, to, reason) in [
                (
                    DriverState::Discovered,
                    DriverState::Matched,
                    TransitionReason::Bound,
                ),
                (
                    DriverState::Matched,
                    DriverState::Starting,
                    TransitionReason::Launched,
                ),
                (
                    DriverState::Starting,
                    DriverState::Probing,
                    TransitionReason::Launched,
                ),
                (
                    DriverState::Probing,
                    DriverState::Active,
                    TransitionReason::ProbeSucceeded,
                ),
            ] {
                exec.declare_lifecycle(device, from, to, reason, 0)
                    .map_err(|_| 16u32)?;
            }
        }

        let port = exec.port_create().map_err(|_| 17u32)?;
        exec.bind_port_object(port, SUSPEND_PORT_OBJ);
        exec.device_route_irq(SUSPEND_RTC_OBJ, port, SUSPEND_MANAGER_PROC_OBJ)
            .map_err(|_| 18u32)?;
    }

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);

    let (_manager_idx, manager_proc) = ring3_host_spawn(
        components::power_manager(),
        SUSPEND_MANAGER_KSTACK_VA,
        POWER_MANAGER_SUSPEND_MODE,
        SUSPEND_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        20,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(30u32)?;
        let mut install = |object, rights| {
            manager
                .handles_mut()
                .install(object, rights)
                .map(|_| ())
                .map_err(|_| 31u32)
        };
        install(SUSPEND_PORT_OBJ, Rights::READ)?;
        install(SUSPEND_RTC_OBJ, Rights::READ | Rights::WAKE)?;
        // Both power rights on one capability, which is a fact about this one
        // service rather than a property of the bits: saying what may wake the
        // machine and stopping it are separate authorities, and the kernel
        // checks them separately.
        install(
            SUSPEND_POWER_OBJ,
            Rights::READ | Rights::WAKE | Rights::SLEEP,
        )?;
        // **The bus, and nothing else.** What is behind it the manager finds
        // by asking the graph, which is the same graph the ordering is
        // enforced against.
        install(SUSPEND_BUS_OBJ, Rights::READ | Rights::MAP | Rights::DERIVE)?;
    }

    // The alarm has to fire *after* the manager reaches its commit, or the
    // wake it is waiting for will already have happened — which the snapshot
    // comparison would correctly refuse, proving the abort rather than the
    // sleep. One second is the shortest this device can express and the
    // manager reaches the commit in microseconds.
    clock.arm_alarm(1);
    POWER_WAKE_INTID.store(intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(intid) };
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);

    let mut pump_budget = 600u32;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable
        // — which during the commit is the machine being asleep.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if EL0_SINK_EXITED.load(Ordering::SeqCst) || pump_budget == 0 {
            break;
        }
        pump_budget -= 1;
        // SAFETY: the boot context owns the CPU here; the only handler that can
        // run is the interrupt bridge, which touches the port facility and the
        // wake counter, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    POWER_WAKE_INTID.store(0, Ordering::SeqCst);
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(intid) };
    clock.disarm();

    let reported = EL0_REPORTS[0].load(Ordering::SeqCst);
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(40);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(41);
    }
    if reported != SUSPEND_EXPECTED {
        return Err(42);
    }

    // SAFETY: transient raw access; every thread is off-CPU by here.
    let (bus_state, device_state, events) = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(43u32)?;
        (
            exec.lifecycle_of_object(SUSPEND_BUS_OBJ).ok_or(44u32)?,
            exec.lifecycle_of_object(SUSPEND_DEVICE_OBJ).ok_or(45u32)?,
            exec.wake_events(),
        )
    };
    // The kernel's own answers: both nodes back in service, and exactly one
    // wake — the one that ended the sleep. A second would mean the two aborts
    // had been ended by something rather than refused.
    if bus_state != DriverState::Active || device_state != DriverState::Active {
        return Err(46);
    }
    if events != 1 {
        return Err(47);
    }

    // SAFETY: transient raw access; every thread is off-CPU.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(manager_proc) {
            process.space_mut().teardown(frames);
        }
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    Ok(SuspendOutcomeReport {
        reported,
        bus_state,
        device_state,
        events,
    })
}

// --- The relay path, and what it costs (D143) ---

/// The chain [`relay_check`] builds. Two relaying hubs the manifest describes,
/// one it does not, and the devices behind each.
///
/// Graph nodes rather than enumerated hardware, and for the reason D142 built
/// its bus the same way: no reference machine has a relaying hub on it. What is
/// under test is the arithmetic over a parent chain, and these carry the same
/// parent edge `pcie_enumerate` records for a function behind a bridge — the
/// edge the manager walks is the real one either way.
pub(crate) const RELAY_HUB_NEAR_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc0);
pub(crate) const RELAY_NEAR_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc1);
pub(crate) const RELAY_HUB_FAR_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc2);
pub(crate) const RELAY_FAR_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc3);
pub(crate) const RELAY_FAR_NET_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc4);
pub(crate) const RELAY_HUB_UNKNOWN_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc5);
pub(crate) const RELAY_UNKNOWN_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc6);
pub(crate) const RELAY_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc7);
pub(crate) const RELAY_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc8);
pub(crate) const RELAY_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc9);
pub(crate) const RELAY_PROBE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xca);
pub(crate) const RELAY_SERVER_2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xcb);
pub(crate) const RELAY_CLIENT_2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xcc);
pub(crate) const RELAY_MANAGER_2_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xcd);
pub(crate) const RELAY_PROBE_2_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xce);

pub(crate) const RELAY_MANAGER_KSTACK_VA: u64 = 0xffff_0003_6000_0000;
pub(crate) const RELAY_PROBE_KSTACK_VA: u64 = 0xffff_0003_7000_0000;
pub(crate) const RELAY_MANAGER_2_KSTACK_VA: u64 = 0xffff_0003_8000_0000;
pub(crate) const RELAY_PROBE_2_KSTACK_VA: u64 = 0xffff_0003_9000_0000;

/// The startup argument asking `blk-probe` to report what its path costs over
/// three binds. Must match `RELAY_REPORT` there.
pub(crate) const BLK_PROBE_RELAY_REPORT: usize = 1 << 61;

/// PCI class codes, as the graph records them: class in bits 23:16.
pub(crate) const RELAY_CLASS_BRIDGE: u32 = 0x06_04_00;
pub(crate) const RELAY_CLASS_STORAGE: u32 = 0x01_08_00;
pub(crate) const RELAY_CLASS_NETWORK: u32 = 0x02_00_00;
pub(crate) const RELAY_VIRTIO_VENDOR: u16 = 0x1af4;
pub(crate) const RELAY_REDHAT_VENDOR: u16 = 0x1b36;

/// The costs `userspace/device-manager`'s manifest declares for these two hubs,
/// and the budget its block entry sets.
///
/// **Restated here, not shared.** The manifest is the manager's policy and this
/// is the check's expectation; a single constant would make the check agree
/// with the manager by construction and prove nothing about whether the
/// manager applied it.
pub(crate) const RELAY_NEAR_COST_US: u64 = 10;
pub(crate) const RELAY_NEAR_THROUGHPUT_MBPS: u64 = 1000;
pub(crate) const RELAY_FAR_COST_US: u64 = 25;
pub(crate) const BLOCK_PATH_BUDGET_US: u64 = 30;

/// What the three binds must answer.
///
/// The near device binds: status 0, one hop, its declared cost, its declared
/// throughput. The far one is refused `BudgetExceeded` (8) and the network
/// device `ThroughputTooLow` (9). Every number is one the manifest declared —
/// a hop count of two, or the far hub's cost showing up on the near device,
/// would mean the manager had accumulated something other than the path it
/// walked.
pub(crate) const RELAY_EXPECTED: u64 = (1 << 8)
    | (RELAY_NEAR_COST_US << 16)
    | (8u64 << 32)
    | (9u64 << 40)
    | (RELAY_NEAR_THROUGHPUT_MBPS << 48);

/// What the same three binds must answer behind the hub nothing describes.
///
/// The one device there is refused `PathUndeclared` (10) — twice, because a
/// refused device stays held and the second request is about the same one — and
/// there is no network device at all, which is `NoMatch` (1). No hops, no
/// latency and no throughput are reported, because nothing was bound.
///
/// It is deliberately the *same* probe mode as the described chain. A mode that
/// went on to drive whatever it was given would, if this hub ever became
/// declared, fail by wandering off into a windowless device rather than by
/// reporting a different number — and a negative check that fails for an
/// incidental reason is not evidence about the thing under test.
pub(crate) const RELAY_UNDECLARED_EXPECTED: u64 = 10 | (10u64 << 32) | (1u64 << 40);

