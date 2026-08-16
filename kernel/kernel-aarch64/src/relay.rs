// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The relay: a client, a server, and the pair of processes that carry a
//! message between them.
//!
//! Normative: docs/kernel/04-synchronization-and-ipc-guarantees.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// One spawned program: its scheduler thread and its process, both of which
/// have to be released and which are not the same index.
#[derive(Clone, Copy)]
pub(crate) struct RelaySpawn {
    pub(crate) thread: usize,
    pub(crate) process: usize,
}

/// What the run produced.
pub(crate) struct RelayReport {
    /// The three-bind report from the described chain.
    pub(crate) declared: u64,
    /// The single bind behind the hub nothing describes.
    pub(crate) undeclared: u64,
}

/// Proves that a device's **data path is a declared cost, checked at binding
/// time** — `docs/drivers/01`, "Bus Topology And Data Paths".
///
/// The claim being tested is the doc's last one: that a class "cannot meet its
/// budget on direct-attach and silently miss it behind two hubs without the
/// declaration making that arithmetic visible at binding time". So the same
/// manifest entry, with the same budget, is asked about two devices of the same
/// class that differ **only in depth** — and it binds the near one and refuses
/// the far one. Nothing else about the machine differs between those two
/// answers, which is what makes the refusal the topology's doing.
///
/// Throughput is a separate requirement with a separate refusal, because a
/// shorter path is the fix for one and no help at all for the other. The
/// network device sits at a depth its latency budget tolerates easily and
/// behind a hub too narrow for it.
///
/// And a hub the kernel cannot identify is **not free**. The second half hands
/// a manager a bus with no recorded identity; the manifest claims nothing, so
/// the device behind it is refused rather than bound as though it were
/// direct-attached. That is the case a system assuming zero would get wrong
/// while looking entirely healthy.
pub(crate) fn relay_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<RelayReport, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if components::device_manager().is_empty() || components::blk_probe().is_empty() {
        return Err(1);
    }

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    let identity = |class_code, vendor, device| kcore::devmgr::DeviceIdentity {
        class_code,
        vendor,
        device,
        bdf: 0,
        revision: 0,
        bus: kcore::devmgr::DeviceBus::Pci,
    };

    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // Devices carry TRANSFER because a manager hands them on; hubs do not,
        // and are windowless besides — a bus's registers are nothing a holder
        // should reach, and `DeviceChild` grants the graph's record for the
        // *child* rather than a narrowing of the parent's.
        let device_rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
        let hub_rights = Rights::READ | Rights::DERIVE;
        // **Registration order is child order, and it is load-bearing.**
        // `children_of` scans the node pool in slot order, the manager walks
        // depth-first, and it binds the first *held* device of a class — so the
        // near device has to be registered before the hub that leads away from
        // it. Registering both hubs first sends the walk down the far branch
        // and swaps which device each of the three answers is about.
        exec.device_register_identified(
            RELAY_HUB_NEAR_OBJ,
            0,
            0,
            hub_rights,
            identity(RELAY_CLASS_BRIDGE, RELAY_REDHAT_VENDOR, 0x0001),
        )
        .map_err(|_| 11u32)?;
        exec.device_register_identified(
            RELAY_NEAR_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 12u32)?;
        exec.device_set_parent(RELAY_NEAR_DEVICE_OBJ, RELAY_HUB_NEAR_OBJ)
            .map_err(|_| 12u32)?;

        exec.device_register_identified(
            RELAY_HUB_FAR_OBJ,
            0,
            0,
            hub_rights,
            identity(RELAY_CLASS_BRIDGE, RELAY_REDHAT_VENDOR, 0x0002),
        )
        .map_err(|_| 11u32)?;
        exec.device_set_parent(RELAY_HUB_FAR_OBJ, RELAY_HUB_NEAR_OBJ)
            .map_err(|_| 12u32)?;
        exec.device_register_identified(
            RELAY_FAR_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 13u32)?;
        exec.device_set_parent(RELAY_FAR_DEVICE_OBJ, RELAY_HUB_FAR_OBJ)
            .map_err(|_| 13u32)?;
        exec.device_register_identified(
            RELAY_FAR_NET_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_NETWORK, RELAY_VIRTIO_VENDOR, 0x1041),
        )
        .map_err(|_| 14u32)?;
        exec.device_set_parent(RELAY_FAR_NET_OBJ, RELAY_HUB_FAR_OBJ)
            .map_err(|_| 14u32)?;

        // **The hub with no identity.** Registered the way a device the kernel
        // could not enumerate is, which is the whole point: the manager can see
        // that something is there and cannot learn what, so the manifest has
        // nothing to say about what passing through it costs.
        exec.device_register_mmio(RELAY_HUB_UNKNOWN_OBJ, 0, 0, Rights::READ | Rights::DERIVE)
            .map_err(|_| 15u32)?;
        exec.device_register_identified(
            RELAY_UNKNOWN_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 15u32)?;
        exec.device_set_parent(RELAY_UNKNOWN_DEVICE_OBJ, RELAY_HUB_UNKNOWN_OBJ)
            .map_err(|_| 15u32)?;

        let channel = exec.channel_create().map_err(|_| 16u32)?;
        exec.bind_endpoint_object(channel.0, RELAY_SERVER_OBJ);
        exec.bind_endpoint_object(channel.1, RELAY_CLIENT_OBJ);
        let channel2 = exec.channel_create().map_err(|_| 16u32)?;
        exec.bind_endpoint_object(channel2.0, RELAY_SERVER_2_OBJ);
        exec.bind_endpoint_object(channel2.1, RELAY_CLIENT_2_OBJ);
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

    // --- The described chain: three binds, one manager, one entry ---
    let (relay_manager, relay_probe) = relay_pair(
        RELAY_HUB_NEAR_OBJ,
        Rights::READ | Rights::DERIVE,
        RELAY_SERVER_OBJ,
        RELAY_CLIENT_OBJ,
        RELAY_MANAGER_PROC_OBJ,
        RELAY_PROBE_PROC_OBJ,
        RELAY_MANAGER_KSTACK_VA,
        RELAY_PROBE_KSTACK_VA,
        1,
        BLK_PROBE_RELAY_REPORT,
        &mut kernel_space,
        frames,
        20,
    )?;

    // --- And the hub nothing describes ---
    //
    // A second manager rather than a fourth request on the first: a manager
    // hands out the first *held* device of a class, and a refused device stays
    // held — so every later request for that class answers about the same
    // device. Asking a different manager is what makes this a different
    // question.
    let (relay_manager_2, relay_probe_2) = relay_pair(
        RELAY_HUB_UNKNOWN_OBJ,
        Rights::READ | Rights::DERIVE,
        RELAY_SERVER_2_OBJ,
        RELAY_CLIENT_2_OBJ,
        RELAY_MANAGER_2_PROC_OBJ,
        RELAY_PROBE_2_PROC_OBJ,
        RELAY_MANAGER_2_KSTACK_VA,
        RELAY_PROBE_2_KSTACK_VA,
        1,
        BLK_PROBE_RELAY_REPORT,
        &mut kernel_space,
        frames,
        40,
    )?;

    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    // A run leaves TTBR0 holding the last process's space, and everything below
    // — including the console this reports through — is a low address.
    unsafe { boot_low.activate() };

    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        return Err(60);
    }
    let declared = EL0_REPORTS[0].load(Ordering::SeqCst);
    let undeclared = EL0_REPORTS[1].load(Ordering::SeqCst);
    if declared != RELAY_EXPECTED {
        return Err(61);
    }
    if undeclared != RELAY_UNDECLARED_EXPECTED {
        return Err(62);
    }

    // SAFETY: transient raw access; every thread is off-CPU by here, and each
    // thread and process is released once.
    //
    // **Reaping alone is not teardown.** It frees the scheduler slot while the
    // dead process still claims the thread index, and the next spawn reuses it
    // — so `forget_thread` follows every reap. The managers are still blocked
    // in `recv` when this runs: a resident server has no exit, and what ends
    // the run is the probe having reported.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            for thread in [
                relay_manager.thread,
                relay_probe.thread,
                relay_manager_2.thread,
                relay_probe_2.thread,
            ] {
                exec.scheduler().reap(thread);
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        for pair in [relay_manager, relay_probe, relay_manager_2, relay_probe_2] {
            processes.forget_thread(pair.thread);
            if let Some(mut process) = processes.remove(pair.process) {
                process.space_mut().teardown(frames);
            }
        }
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    Ok(RelayReport {
        declared,
        undeclared,
    })
}

/// Spawns one device manager over `root` and one `blk-probe` against it, and
/// runs until nothing is runnable.
///
/// The manager is a resident server, so it never exits; what ends the run is
/// the probe having reported. That is why each pair is run to quiescence before
/// the next is spawned — two managers racing would put their probes' reports in
/// the sink in whichever order the scheduler happened to produce, and the check
/// would be asserting on a coincidence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn relay_pair(
    root: kcore::object::ObjectId,
    root_rights: kcore::rights::Rights,
    server: kcore::object::ObjectId,
    client: kcore::object::ObjectId,
    manager_proc_obj: kcore::object::ObjectId,
    probe_proc_obj: kcore::object::ObjectId,
    manager_kstack: u64,
    probe_kstack: u64,
    manager_arg: usize,
    probe_arg: usize,
    kernel_space: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    base_err: u32,
) -> Result<(RelaySpawn, RelaySpawn), u32> {
    use kcore::rights::Rights;

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        manager_kstack,
        manager_arg,
        manager_proc_obj,
        kernel_space,
        frames,
        base_err,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(base_err + 10)?;
        manager
            .handles_mut()
            .install(server, Rights::READ)
            .map_err(|_| base_err + 10)?;
        // **What boot grants the framework, and nothing else.** For a bus that
        // is READ | DERIVE: everything behind it the manager gets from the
        // graph, so the topology it charges for is the topology it walked. For
        // a device it is the device's own rights, `FIRMWARE` included — the
        // authority to put code on hardware is boot's to grant and the
        // manager's to spend, and it does not travel on to a driver.
        manager
            .handles_mut()
            .install(root, root_rights)
            .map_err(|_| base_err + 10)?;
    }

    let (probe_idx, probe_proc) = ring3_host_spawn(
        components::blk_probe(),
        probe_kstack,
        probe_arg,
        probe_proc_obj,
        kernel_space,
        frames,
        base_err + 1,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(probe_proc)
            .ok_or(base_err + 11)?
            .handles_mut()
            .install(client, Rights::WRITE)
            .map_err(|_| base_err + 11)?;
    }

    // Everything here is cooperative — a call, a reply, an exit — so the
    // scheduler runs to quiescence without a tick to prod it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    Ok((
        RelaySpawn {
            thread: manager_idx,
            process: manager_proc,
        },
        RelaySpawn {
            thread: probe_idx,
            process: probe_proc,
        },
    ))
}

// --- Firmware loading (D148) ---------------------------------------------

pub(crate) const FIRMWARE_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd0);
pub(crate) const FIRMWARE_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd1);
pub(crate) const FIRMWARE_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd2);
pub(crate) const FIRMWARE_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd3);
pub(crate) const FIRMWARE_PROBE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd4);

/// The virtio product id the firmware-declaring manifest entry names. Restated
/// here rather than shared, like every other value this check expects of the
/// manager's policy.
pub(crate) const FIRMWARE_BLOCK_PRODUCT: u16 = 0x1052;

pub(crate) const FIRMWARE_MANAGER_KSTACK_VA: u64 = 0xffff_0003_a000_0000;
pub(crate) const FIRMWARE_PROBE_KSTACK_VA: u64 = 0xffff_0003_b000_0000;

/// The startup argument asking `device-manager` to report the two refusals
/// before it serves, over one device. Must match `FIRMWARE_PROBE` there.
pub(crate) const DEVICE_MANAGER_FIRMWARE_PROBE: usize = (1 << 60) | 1;
/// The startup argument asking `blk-probe` to report what firmware it was
/// handed. Must match `FIRMWARE_REPORT` there.
pub(crate) const BLK_PROBE_FIRMWARE_REPORT: usize = 1 << 60;

// What the store's images declare, restated here rather than shared.
//
// **Restated on purpose**, the way the relay costs are: these are what the
// build put in the container, and a check that read them from the same place
// the manager does would agree with it by construction.

/// The version the manifest entry requires, restated. Used here as the
/// *installed* driver set's requirement — what the machine is running today.
pub(crate) const BLOCK_FIRMWARE_MIN_VERSION: u32 = 2;
pub(crate) const FIRMWARE_GOOD_SVN: u64 = 7;
pub(crate) const FIRMWARE_GOOD_VERSION: u64 = 3;
pub(crate) const FIRMWARE_OLD_SVN: u64 = 2;
pub(crate) const FIRMWARE_V1_SVN: u64 = 7;

/// What the manager's two deliberate refusals must answer.
///
/// Low to high: `RollbackBlocked` (1) for the image below the floor,
/// `VersionTooOld` (2) for the one below what the entry needs, then the two
/// security versions the kernel reported for them. **Two different refusals is
/// the evidence** — one code for both would leave a system unable to say
/// whether an image was retired or merely old, and those have different fixes.
pub(crate) const FIRMWARE_REFUSALS_EXPECTED: u64 =
    1 | (2u64 << 4) | (FIRMWARE_OLD_SVN << 32) | (FIRMWARE_V1_SVN << 40);

