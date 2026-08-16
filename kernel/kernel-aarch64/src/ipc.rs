// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The executive substrate this machine runs ring 3 on: the syscall hook, the
//! interrupt hooks, and the channel IPC round trip.
//!
//! Normative: docs/kernel/04-synchronization-and-ipc-guarantees.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

/// A `&mut` to the IPC executive, via the raw static. Provably initialized
/// before any thread runs.
pub(crate) fn ipc_exec() -> &'static mut kcore::exec::Executive<ContextSwitch> {
    // SAFETY: single-core cooperative; `KCORE_EXEC` is set in `ipc_check` before
    // any thread runs, and each channel handoff switches control, so only one
    // borrow is ever actively in flight.
    unsafe {
        match (*(&raw mut KCORE_EXEC)).as_mut() {
            Some(exec) => exec,
            None => fatal_no_executive(),
        }
    }
}

#[inline(never)]
pub(crate) fn fatal_no_executive() -> ! {
    kprintln!("ipc: FATAL: executive uninitialized");
    SemihostingExit::exit(ExitCode::Failure)
}

/// The running thread's scheduler index.
pub(crate) fn ipc_current() -> Option<usize> {
    ipc_exec().scheduler().current()
}

/// Ends the running EL0 thread and switches to the next ready thread — or
/// the boot context only when nothing is runnable (`exit_current`, D82: the
/// old terminate-and-yield-to-boot ended the whole run at the FIRST exit,
/// abandoning a still-ready second client).
pub(crate) fn ipc_end_thread() {
    ipc_exec().scheduler().exit_current();
}

/// Closes every channel endpoint the running thread's process holds, waking
/// whoever was waiting on the other side.
///
/// **Only for a thread that died, never for one that finished.** Doing this on
/// every thread exit was tried and took eighteen of the twenty-four boot checks
/// down with it: a ring-3 program reaching the end of its work is the ordinary
/// case, its peers are still running and still using those channels, and
/// closing them is a teardown nobody asked for. A crash is the opposite — the
/// peers are waiting on a reply that will never come — and the difference
/// between the two is the whole reason this is called from the fault path
/// alone.
///
/// Read from the process's **own handle table** rather than from a list kept
/// alongside it: a channel it was given late, or one that arrived by transfer,
/// is exactly the one a separate list forgets.
pub(crate) fn close_endpoints_of_current() {
    let Some(thread) = ipc_current() else {
        return;
    };
    const SLOTS: usize = 32;
    let mut audit = [(
        kcore::object::ObjectId::from_raw(0),
        kcore::rights::Rights::none(),
    ); SLOTS];
    // SAFETY: transient raw access to the static process table; a read, and the
    // executive borrow below does not overlap it.
    let count = unsafe {
        (*(&raw mut KCORE_PROCESSES))
            .process_of_thread(thread)
            .map(|process| process.handles().audit(&mut audit))
            .unwrap_or(0)
    };
    let mut held = [kcore::object::ObjectId::from_raw(0); SLOTS];
    for (slot, (object, _)) in held.iter_mut().zip(audit.iter()).take(count) {
        *slot = *object;
    }
    ipc_exec().close_endpoints_of(&held[..count]);
}

/// The GIC INTID whose interrupts the ring-3 driver under test is currently
/// wired to (0 = none) — the block host's, or the network driver's, whichever
/// check is running. Set strictly around a ring-3 check's `run()` — the same
/// unmask-only-around-the-run window the x86 COM2 demo uses — so the bridge
/// below can never race boot-context Executive access.
pub(crate) static RING3_DRIVER_INTID: AtomicU32 = AtomicU32::new(0);

/// A second line the same driver is wired to (0 = none).
///
/// **Because a multi-queue controller has more than one.** Every check before
/// this one drove a device with a single interrupt, so one slot was the whole
/// need; an NVMe controller raises one per queue, and a bridge that claimed
/// only the first would leave the other queue's completions unclaimed and its
/// driver parked forever.
pub(crate) static RING3_DRIVER_INTID_ALT: AtomicU32 = AtomicU32::new(0);

/// The device-IRQ bridge (D84): claims the ring-3 host's device INTID,
/// masks the line (storm-safe for level-triggered sources — the trap path
/// EOIs unconditionally; the host re-arms via `IrqComplete` after acking the
/// device), and signals the host's port. Runs in interrupt context.
pub(crate) fn virtio_irq_hook(id: u32) -> bool {
    let wired = RING3_DRIVER_INTID.load(Ordering::SeqCst);
    let alt = RING3_DRIVER_INTID_ALT.load(Ordering::SeqCst);
    if (wired == 0 || id != wired) && (alt == 0 || id != alt) {
        return false;
    }
    // SAFETY: masking a GIC line is an interrupt-controller register write
    // with no memory-model footprint.
    unsafe { tessera_karch_aarch64::disable_irq(id) };
    // SAFETY: exception entry sets PSTATE.I, so this IRQ can only have
    // preempted EL0 execution or boot code outside the enable window — never
    // a live Executive borrow (kernel dispatch runs with IRQs masked from
    // entry to eret, and boot only enables the line for the duration of the
    // scheduler run it does not otherwise touch the Executive within).
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.port_signal(id as u64, 1, 1);
        }
    }
    true
}

/// The SMMU's event-queue INTID, once the device tree has been read (0 = the
/// machine has no SMMU, or its node declares no interrupt).
pub(crate) static SMMU_EVENTQ_INTID: AtomicU32 = AtomicU32::new(0);

/// The isolation policy the fault harvest applies, as an
/// `IsolationPolicy` discriminant.
///
/// A static rather than a constant because it *is* policy: a machine being
/// brought up wants every fault recorded and nothing torn down, and a machine
/// running drivers wants the opposite. Defaulting to `Report` is the
/// conservative end — a boot that never sets it degrades to logging, which is
/// the behaviour this port had before the harvest existed.
pub(crate) static SMMU_FAULT_POLICY: AtomicU32 = AtomicU32::new(kcore::devmgr::IsolationPolicy::Report as u32);

/// A holder the isolation policy asked to have stopped, published for a
/// supervisor to act on (0 = none outstanding). See [`Smmu::report`].
pub(crate) static SMMU_ISOLATION_STOP: AtomicU32 = AtomicU32::new(0);

/// The machine's SMMU, reachable from the interrupt bridge for the whole boot.
///
/// Distinct from [`EL0_DISPATCH_IOMMU`], which is set and cleared around each
/// check that needs a mapper in a syscall. A fault can land at any moment —
/// including between two checks, which is exactly the window a
/// check-scoped pointer would leave unharvested — so this one is set once
/// after bring-up and never cleared, matching the fact that the SMMU itself is
/// enabled once and never disabled.
pub(crate) static mut BOOT_IOMMU: *mut Smmu = core::ptr::null_mut();

/// The SMMU's own interrupt: a fault record has been written to the event
/// queue. Harvests it, which records it and applies the standing policy.
///
/// Runs in interrupt context. Unlike the device bridges below it does **not**
/// mask its line: the SMMU's event-queue interrupt is edge-triggered and
/// pulsed per record on this machine, and the harvest empties the queue, so
/// there is no level left asserting to storm on. Masking it would instead
/// silence every fault after the first.
pub(crate) fn smmu_irq_hook(id: u32) -> bool {
    let wired = SMMU_EVENTQ_INTID.load(Ordering::SeqCst);
    if wired == 0 || id != wired {
        return false;
    }
    // SAFETY: `BOOT_IOMMU` is set once after bring-up and names a slot nothing
    // moves out of. Single-core, and this interrupt can only preempt EL0
    // execution or boot code inside an enable window — kernel dispatch runs
    // with IRQs masked from entry to eret, so the raw access never overlaps a
    // use of the `&mut Smmu` a boot check holds. This is the same discipline
    // `EL0_DISPATCH_IOMMU` already rests on, reaching the same object.
    unsafe {
        if let Some(smmu) = BOOT_IOMMU.as_mut() {
            smmu.harvest(true);
        }
    }
    true
}

/// This port's one device-interrupt entry point.
///
/// A single hook, offered to each consumer in turn, because the IOMMU's
/// interrupt is not like the others: every other bridge here belongs to one
/// check and is disarmed by zeroing its own INTID when that check ends, while
/// the SMMU reports faults about *every* device on the machine and must stay
/// wired for the whole boot. With one hook slot in the arch layer, a check
/// installing its own bridge would have unwired the fault harvest for exactly
/// the window in which drivers are running.
///
/// Each consumer still guards on its own wired INTID, so the order below is
/// not a priority — no two of them can claim the same line.
pub(crate) fn device_irq_hook(id: u32) -> bool {
    smmu_irq_hook(id) || msi_irq_hook(id) || virtio_irq_hook(id) || wake_irq_hook(id)
}

/// virtio-mmio as the kernel core's device-reset seam
/// (`kcore::devmgr::DeviceResetter`) — ladder step 5.
///
/// **Per class, and this port knows exactly one.** A virtio transport is reset
/// by writing zero to its `Status` register: the specification defines that as
/// the device dropping every negotiated feature, every queue configuration and
/// every outstanding buffer, and re-reading the register as zero is the device
/// saying it has done so. That is the whole reset, and it is why virtio is the
/// class this can honestly implement today.
///
/// Anything else is a **refusal**. A PCI function-level reset is a different
/// mechanism entirely (a capability write and a mandated settling time), and
/// returning `Ok` for one would have the ladder record a successful reset of a
/// device nothing touched — the next rung would then be taken on a false
/// premise, which is worse than not resetting at all.
pub(crate) struct VirtioMmioResetter;

/// virtio-mmio register offsets used by the reset.
pub(crate) const VIRTIO_MMIO_MAGIC: u64 = 0x000;
pub(crate) const VIRTIO_MMIO_STATUS: u64 = 0x070;
pub(crate) const VIRTIO_MMIO_MAGIC_VALUE: u32 = 0x7472_6976;

impl kcore::devmgr::DeviceResetter for VirtioMmioResetter {
    fn reset(
        &mut self,
        _device: kcore::object::ObjectId,
        identity: Option<kcore::devmgr::DeviceIdentity>,
        window: Option<(u64, u64)>,
    ) -> Result<(), tessera_karch::KError> {
        use tessera_karch::KError;
        // A device the kernel enumerated from config space is a PCI function,
        // and this resetter does not speak function-level reset.
        if identity.is_some() {
            return Err(KError::NotSupported);
        }
        let (base, len) = window.ok_or(KError::NotSupported)?;
        if len <= VIRTIO_MMIO_STATUS {
            return Err(KError::InvalidMapping);
        }
        // Confirm it is a virtio transport before writing anything to it.
        // The register map below belongs to virtio and to nothing else, and a
        // zero written at offset 0x70 of some other device is not a reset —
        // it is a poke at a register whose meaning nobody here knows.
        //
        // SAFETY: the window comes from the resource graph, which holds the
        // physical base enumeration found; it is inside `DEVICE_RANGE` and so
        // identity-mapped device memory on this port, and both offsets are
        // inside the length the graph recorded (checked above).
        let magic =
            unsafe { tessera_karch_aarch64::mmio_read32((base + VIRTIO_MMIO_MAGIC) as usize) };
        if magic != VIRTIO_MMIO_MAGIC_VALUE {
            return Err(KError::NotSupported);
        }
        // SAFETY: as above.
        unsafe { tessera_karch_aarch64::mmio_write32((base + VIRTIO_MMIO_STATUS) as usize, 0) };
        // The device says whether it did it. Without reading back, a reset
        // that the hardware ignored would be recorded as one that worked.
        // SAFETY: as above.
        let status =
            unsafe { tessera_karch_aarch64::mmio_read32((base + VIRTIO_MMIO_STATUS) as usize) };
        if status != 0 {
            return Err(KError::InvalidMapping);
        }
        Ok(())
    }
}

/// The GIC as the kernel core's interrupt-revocation seam
/// (`kcore::devmgr::InterruptRouter`).
///
/// Zero-sized: the controller is a fixed set of registers this port already
/// knows how to reach, so there is nothing to carry. It exists as a type
/// solely because the kernel core must not name a GIC — the same reason
/// [`Smmu`] implements `DmaMapper` rather than kcore knowing what an SMMU is.
pub(crate) struct GicRouter;

impl kcore::devmgr::InterruptRouter for GicRouter {
    fn mask(&mut self, intid: u32) {
        // SAFETY: masking a GIC line is an interrupt-controller register write
        // with no memory-model footprint, valid from any context.
        unsafe { tessera_karch_aarch64::disable_irq(intid) };
    }
}

/// `IrqComplete` (D84): re-enable every line of the device the caller names.
///
/// Port-local for the controller write alone — the authority check and the
/// lines themselves are [`kcore::dispatch::resolve_irq_lines`], because which
/// lines a device has is the resource graph's answer and not this port's.
pub(crate) fn irq_complete(caller: usize, args_ptr: u64) -> i64 {
    use kcore::syscall::encode_result;

    let mut lines = [0u32; kcore::devmgr::MAX_IRQ_LINES];
    // SAFETY: transient raw access to the static process table and executive.
    let processes = unsafe { &mut *(&raw mut KCORE_PROCESSES) };
    // SAFETY: transient raw read of the static executive.
    let Some(exec) = (unsafe { (*(&raw const KCORE_EXEC)).as_ref() }) else {
        return encode_result(Err(tessera_karch::KError::AccessDenied));
    };
    let count = match kcore::dispatch::resolve_irq_lines(
        exec, processes, caller, args_ptr, &mut lines,
    ) {
        Ok(count) => count,
        Err(e) => return encode_result(Err(e)),
    };
    for intid in &lines[..count] {
        // SAFETY: enabling a GIC line is an interrupt-controller register
        // write; the caller proved authority over the device it belongs to.
        unsafe { tessera_karch_aarch64::enable_irq(*intid) };
    }
    encode_result(Ok(0))
}

/// The one EL0 syscall hook for every Executive-substrate check (D79):
/// normalizes the trap frame into a `SyscallRequest` (`x8` = number,
/// `x0..x5` = args), routes it through the shared kcore dispatcher, and keeps
/// only the port-divergent arms local — `DebugWrite` records the raw `x0`
/// value in [`EL0_SINK_LOG`], `ProcessExit` sets [`EL0_SINK_EXITED`] and ends
/// the thread. A covered arm's result lands back in `x0`. A channel op may
/// hand off inside `dispatch` and resume here later; a `ChannelReply` leaves
/// the server blocked and this frame parked, never resumed.
pub(crate) fn el0_dispatch_hook(frame: &mut tessera_karch_aarch64::TrapFrame) {
    use kcore::dispatch::{DispatchEnv, DispatchOutcome, SyscallRequest, dispatch};
    use kcore::syscall::{SyscallNumber, encode_result};
    if !tessera_karch_aarch64::is_svc(frame.esr) {
        EL0_SINK_FAULT_ADDR.store(frame.far, Ordering::SeqCst);
        EL0_SINK_FAULT_CORRELATION.store(kcore::trace::current().correlation, Ordering::SeqCst);
        EL0_SINK_FAULT.store(frame.esr, Ordering::SeqCst);
        // The thread is not going to reply to anybody. Release what it held
        // before it stops running, so a caller parked on it can discover that
        // rather than wait for an event that can no longer happen.
        close_endpoints_of_current();
        ipc_end_thread();
        return;
    }
    let Some(caller) = ipc_current() else {
        EL0_SINK_FAULT.store(0xbad0, Ordering::SeqCst);
        ipc_end_thread();
        return;
    };
    // SAFETY: transient raw read of the check-scoped allocator pointer.
    let frames = unsafe { *(&raw const EL0_DISPATCH_FRAMES) };
    if frames.is_null() {
        // A check forgot to expose the boot allocator — fail loudly (a
        // distinct fault sink), never by dereferencing null in a covered arm.
        EL0_SINK_FAULT.store(0xbad2, Ordering::SeqCst);
        ipc_end_thread();
        return;
    }
    let req = SyscallRequest {
        number: frame.x[8],
        args: [
            frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
        ],
    };
    // SAFETY: single-core cooperative boot. The statics are initialized by the
    // running check before `run()`; `EL0_DISPATCH_FRAMES` points at the boot
    // allocator for the check's duration (checked non-null above). A blocking
    // channel op parks this frame — env borrows included — on the blocked
    // thread's kernel stack; the parked borrows are never dereferenced until
    // the handoff returns here (the executive-substrate discipline).
    let mut router = GicRouter;
    let outcome = unsafe {
        let mut env = DispatchEnv {
            exec: match (*(&raw mut KCORE_EXEC)).as_mut() {
                Some(exec) => exec,
                None => fatal_no_executive(),
            },
            processes: &mut *(&raw mut KCORE_PROCESSES),
            caller,
            alloc: &mut *frames,
            // Always present, unlike the IOMMU: this machine's interrupt
            // controller is not optional, and a departing capability whose
            // route was dropped from the graph but left unmasked at the GIC is
            // the half-teardown the seam exists to prevent.
            irqs: Some(&mut router),
            iommu: {
                let unit = *(&raw const EL0_DISPATCH_IOMMU);
                // Null means no IOMMU on this boot, which is a fact about the
                // machine and reported as one — never a reason to hand a
                // device with an aperture a physical address instead.
                unit.as_mut()
                    .map(|u| u as &mut dyn kcore::devmgr::DmaMapper)
            },
        };
        dispatch(&mut env, &req)
    };
    match outcome {
        DispatchOutcome::Return(v) => frame.x[0] = v as u64,
        DispatchOutcome::Unhandled => match SyscallNumber::from_u64(frame.x[8]) {
            Some(SyscallNumber::IrqComplete) => {
                // Arch-coupled (a GIC enable), so port-local like
                // DebugWrite/ProcessExit (D79 class; D84).
                frame.x[0] = irq_complete(caller, frame.x[0]) as u64;
            }
            Some(SyscallNumber::DebugWrite) => {
                // XOR-accumulate so multiple reporters compose (two host
                // clients, D82); single-writer checks are value-identical
                // (each resets the sink to 0 and writes once).
                EL0_SINK_LOG.fetch_xor(frame.x[0], Ordering::SeqCst);
                // **And keep them apart, in order.** XOR composes reporters but
                // cannot distinguish them, and two reporters sending the *same*
                // value cancel to zero — which is not a hypothetical: a driver
                // bound to a PCI device reports the identity the kernel
                // enumerated, and its replacement reports the same identity.
                // A check reading only the sink would see 0 and could not tell
                // "ran twice, agreed" from "never ran". Keyed by order, which
                // is a property of the program rather than of the schedule.
                let slot = EL0_REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
                if slot < MAX_EL0_REPORTS {
                    EL0_REPORTS[slot].store(frame.x[0], Ordering::SeqCst);
                }
                // Overflow is not dropped silently: the count keeps rising past
                // the array, so a check expecting two reports and given three
                // sees three.
                frame.x[0] = encode_result(Ok(0)) as u64;
            }
            Some(SyscallNumber::ProcessExit) => {
                EL0_SINK_EXITED.store(true, Ordering::SeqCst);
                ipc_end_thread();
            }
            _ => {
                EL0_SINK_FAULT.store(0xbad1, Ordering::SeqCst);
                ipc_end_thread();
            }
        },
    }
}

/// Builds one IPC process: a fresh space with its program at `USER_CODE_VA`, a
/// user stack, a data buffer (seeded with `data`), and its endpoint installed
/// at handle 0. Returns `(thread_index, process_index)` — teardown needs the
/// process index to `remove` it from the table (else its stale thread index
/// collides with a later check's reused scheduler slot in `process_of_thread`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn ipc_spawn_process(
    high: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blob: &[u8],
    kstack_va: u64,
    endpoint_object: kcore::object::ObjectId,
    data: &[u8],
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| base_err)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    // Map through the kcore wrapper (not the arch directly) so the mappings are
    // tracked — `validate_user_range`/`rights_at` consult the wrapper's mapping
    // table, and a syscall reading these buffers must find them there. Then
    // write the program/data into the freshly allocated (zeroed) frames.
    user_space
        .map_anonymous(
            VirtAddr::new(USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| base_err + 1)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(USER_CODE_VA))
        .map(|(f, _)| f)
        .ok_or(base_err + 2)?;
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    user_space
        .map_anonymous(
            VirtAddr::new(USER_DATA_VA),
            FRAME_SIZE,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| base_err + 3)?;
    let data_frame = user_space
        .arch()
        .translate(VirtAddr::new(USER_DATA_VA))
        .map(|(f, _)| f)
        .ok_or(base_err + 4)?;
    user_space.arch().write_bytes_to_frame(data_frame, 0, data);

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kstack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(kstack_va),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(kstack_va),
        IPC_KSTACK_PAGES,
        endpoint_object,
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| base_err + 5)?;

    // SAFETY: transient raw access to the static executive and process table.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 6)?
            .add_thread(thread)
            .map_err(|_| base_err + 7)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(endpoint_object, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 8)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| base_err + 9)?;
            // The first install in each fresh handle table lands at handle 0,
            // which the programs name.
            p.handles_mut()
                .install(endpoint_object, Rights::READ | Rights::WRITE)
                .map_err(|_| base_err + 10)?;
        }
    }
    Ok((thread_idx, proc_idx))
}

/// Proves the kcore IPC substrate on AArch64: two EL0 processes exchange a
/// message over a channel — the client `call`s with a magic, the server
/// `receive`s it, logs it back, and `reply`s, exercising the scheduler's
/// blocking handoff between address spaces. Returns the magic the server saw.
pub(crate) fn ipc_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u64, u64), u32> {
    use tessera_karch::AddressSpaceOps;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let (server_ep, client_ep) = ipc_exec().channel_create().map_err(|_| 70u32)?;
    let server_obj = kcore::object::ObjectId::from_raw(10);
    let client_obj = kcore::object::ObjectId::from_raw(11);
    ipc_exec().bind_endpoint_object(server_ep, server_obj);
    ipc_exec().bind_endpoint_object(client_ep, client_obj);

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // The server is built first so it schedules first and parks on `receive`
    // before the client `call`s.
    let (server_idx, server_proc) = ipc_spawn_process(
        high,
        frames,
        IPC_SERVER_BLOB,
        IPC_SERVER_KSTACK_VA,
        server_obj,
        &[0u8; 8],
        71,
    )?;
    let (client_idx, client_proc) = ipc_spawn_process(
        high,
        frames,
        IPC_CLIENT_BLOB,
        IPC_CLIENT_KSTACK_VA,
        client_obj,
        &IPC_MAGIC.to_le_bytes(),
        80,
    )?;

    // Expose the boot allocator to the dispatch hook: the channel arms build
    // nothing today, but dispatch requires a live frame source (page tables
    // for a covered map arm; a null pointer is a distinct 0xbad2 fault).
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    let switches_before = ipc_exec().switch_count();
    // SAFETY: transient raw access; `run` returns when the last thread yields.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    let switches = ipc_exec().switch_count() - switches_before;
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(90);
    }
    let seen = EL0_SINK_LOG.load(Ordering::SeqCst);
    if seen != IPC_MAGIC {
        return Err(91);
    }

    // Teardown: reap both threads (both off-CPU — client Exited, server Blocked)
    // and remove each process, reclaiming its space. Removing (not just
    // tearing down in place) frees the table slots so a later check's threads do
    // not collide with these stale thread indices in `process_of_thread`.
    // SAFETY: transient raw access; both threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(server_idx);
        }
        for proc_idx in [client_proc, server_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
    }

    Ok((seen, switches))
}

// --- MapDevice: a ring-3 process maps and reads a device's MMIO registers (D77) ---

/// The user VA the ring-3 driver asks `map_device` to place the virtio window at.
/// A fresh high user address, distinct from the code/stack it already holds. The
/// value is also encoded in `MMIO_PROBE_BLOB` (the `movz`/`movk` of `x11`, the
/// args struct's `vaddr` field); this constant documents it and pins the
/// invariant the syscall enforces.
pub(crate) const USER_MMIO_VA: u64 = 0x0000_1000_0040_0000;
const _: () = assert!(
    USER_MMIO_VA < 0x0000_8000_0000_0000 && USER_MMIO_VA % FRAME_SIZE == 0,
    "USER_MMIO_VA must be a page-aligned user address",
);
/// The MMIO process's kernel stack, distinct from the other EL0 kstacks.
pub(crate) const MMIO_KSTACK_VA: u64 = 0xffff_0000_a000_0000;

/// A ring-3 driver program: build a `MapDeviceArgs` (32 bytes, the ISL struct —
/// D79: device handle 0, vaddr `USER_MMIO_VA`) on the tracked user stack page,
/// `MapDevice`(23), then read the identity registers directly from EL0 (through
/// the register base the syscall returns in x0 — the mapped page VA plus the
/// window's intra-page offset) and `DebugWrite`(1) the packed
/// `MAGIC | (DEVICE_ID << 32)`, then `ProcessExit`(5). Register ABI:
/// x0=args-struct ptr, x8=number; MapDevice returns the register base in x0.
pub(crate) const MMIO_PROBE_BLOB: &[u8] = &[
    0x09, 0x02, 0xa0, 0xd2, // movz x9, #0x10, lsl #16
    0x09, 0x00, 0xc2, 0xf2, // movk x9, #0x1000, lsl #32   (x9 = USER_STACK_VA)
    0x0a, 0x04, 0x80, 0xd2, // movz x10, #0x20        (size = 32)
    0x2a, 0x00, 0xc0, 0xf2, // movk x10, #0x1, lsl #32     (| version 1 << 32)
    0x2a, 0x01, 0x00, 0xf9, // str x10, [x9]          (size|version)
    0x3f, 0x05, 0x00, 0xf9, // str xzr, [x9, #8]      (flags = 0)
    0x3f, 0x09, 0x00, 0xf9, // str xzr, [x9, #16]     (device handle 0 | reserved)
    0x0b, 0x08, 0xa0, 0xd2, // movz x11, #0x40, lsl #16
    0x0b, 0x00, 0xc2, 0xf2, // movk x11, #0x1000, lsl #32  (x11 = USER_MMIO_VA)
    0x2b, 0x0d, 0x00, 0xf9, // str x11, [x9, #24]     (vaddr)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0xe8, 0x02, 0x80, 0xd2, // movz x8, #23           (MapDevice)
    0x01, 0x00, 0x00, 0xd4, // svc #0                 (x0 = register base VA)
    0x02, 0x00, 0x40, 0xb9, // ldr w2, [x0]           (MAGIC   @ +0x000)
    0x03, 0x08, 0x40, 0xb9, // ldr w3, [x0, #8]       (DEVICE_ID @ +0x008)
    0x40, 0x80, 0x03, 0xaa, // orr x0, x2, x3, lsl #32     (pack magic|id<<32)
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1            (DebugWrite)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0xa8, 0x00, 0x80, 0xd2, // movz x8, #5            (ProcessExit)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

// The `MapDevice` semantics (capability resolution, `Rights::MAP`,
// containing-page mapping of the unaligned window, untracked device page) live
// in the shared kcore dispatcher (`kcore::dispatch`, D79); this check only
// grants the capability and verifies what the ring-3 probe read.

