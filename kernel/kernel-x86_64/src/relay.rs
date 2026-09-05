// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A device's data path is a declared cost, and the budget refuses one that is
//! too far.
//!
//! The manager declares what a hop costs; a path over budget is refused rather
//! than taken slowly, which is the only form in which a budget is a decision.
//!
//! **Not one line of the mechanism is per-port.** The arbiter is `api/binding`,
//! the manifest and the accumulation are `userspace/device-manager`, and the
//! budget is checked by the same `blk-probe` — all already compiled for this
//! target and otherwise untouched. What is here is the boot glue that builds
//! the topology and grants the authority, and it builds it out of **devices
//! that do not exist**: every node below is registered with a base and a length
//! of zero, because what is being checked is what the graph says about a path
//! and not what is at the end of one.
//!
//! The claim is `docs/drivers/01`'s: one manifest entry with one budget, asked
//! about two devices of the same class differing **only in depth**, binds the
//! near one and refuses the far one. Throughput refuses separately, because a
//! shorter path is no help when the remaining hop is the narrow one. And a hub
//! the kernel cannot identify is refused rather than assumed free.
//!
//! Split out of `main.rs` by area (build/README.md, D265).
//!
//! Normative: docs/drivers/01-driver-framework.md ("Bus Topology And Data
//! Paths")

use crate::*;

/// This check's own topology, in a block of its own.
pub(crate) const RELAY_HUB_NEAR_OBJ: ObjectId = ObjectId::from_raw(0x190);
pub(crate) const RELAY_NEAR_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x191);
pub(crate) const RELAY_HUB_FAR_OBJ: ObjectId = ObjectId::from_raw(0x192);
pub(crate) const RELAY_FAR_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x193);
pub(crate) const RELAY_FAR_NET_OBJ: ObjectId = ObjectId::from_raw(0x194);
pub(crate) const RELAY_HUB_UNKNOWN_OBJ: ObjectId = ObjectId::from_raw(0x195);
pub(crate) const RELAY_UNKNOWN_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x196);
pub(crate) const RELAY_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x197);
pub(crate) const RELAY_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x198);
pub(crate) const RELAY_SERVER_2_OBJ: ObjectId = ObjectId::from_raw(0x199);
pub(crate) const RELAY_CLIENT_2_OBJ: ObjectId = ObjectId::from_raw(0x19a);
pub(crate) const RELAY_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x19b);
pub(crate) const RELAY_PROBE_PROC_OBJ: ObjectId = ObjectId::from_raw(0x19c);
pub(crate) const RELAY_MANAGER_2_PROC_OBJ: ObjectId = ObjectId::from_raw(0x19d);
pub(crate) const RELAY_PROBE_2_PROC_OBJ: ObjectId = ObjectId::from_raw(0x19e);

/// The startup argument asking `blk-probe` to report what its path costs over
/// three binds. Must match `RELAY_REPORT` there.
pub(crate) const BLK_PROBE_RELAY_REPORT: usize = 1 << 61;

/// PCI class codes, as the graph records them: class in bits 23:16.
pub(crate) const RELAY_CLASS_BRIDGE: u32 = 0x06_04_00;
pub(crate) const RELAY_CLASS_STORAGE: u32 = 0x01_08_00;
pub(crate) const RELAY_CLASS_NETWORK: u32 = 0x02_00_00;
pub(crate) const RELAY_VIRTIO_VENDOR: u16 = 0x1af4;
pub(crate) const RELAY_REDHAT_VENDOR: u16 = 0x1b36;

/// The costs `userspace/device-manager`'s manifest declares for these hubs, and
/// the budget its block entry sets. Restated rather than shared, so the check
/// does not agree with the manager by construction.
pub(crate) const RELAY_NEAR_COST_US: u64 = 10;
pub(crate) const RELAY_NEAR_THROUGHPUT_MBPS: u64 = 1000;
pub(crate) const RELAY_FAR_COST_US: u64 = 25;
pub(crate) const BLOCK_PATH_BUDGET_US: u64 = 30;

/// What the three binds must answer on the described chain, and on the one
/// nothing describes. Identical to the other ports' expectations, because the
/// manifest, the arbiter and the probe are the same sources — only the boot
/// glue here is per-port.
pub(crate) const RELAY_EXPECTED: u64 = (1 << 8)
    | (RELAY_NEAR_COST_US << 16)
    | (8u64 << 32)
    | (9u64 << 40)
    | (RELAY_NEAR_THROUGHPUT_MBPS << 48);
pub(crate) const RELAY_UNDECLARED_EXPECTED: u64 = 10 | (10u64 << 32) | (1u64 << 40);

/// The virtio product id the firmware-declaring manifest entry names. Restated
/// here rather than shared, like every other value these checks expect of the
/// manager's policy.
pub(crate) const FIRMWARE_BLOCK_PRODUCT: u16 = 0x1052;

/// The startup argument asking `device-manager` to report the two refusals
/// before it serves, over one device. Must match `FIRMWARE_PROBE` there.
pub(crate) const DEVICE_MANAGER_FIRMWARE_PROBE: usize = (1 << 60) | 1;
/// The startup argument asking `blk-probe` to report what firmware it was
/// handed. Must match `FIRMWARE_REPORT` there.
pub(crate) const BLK_PROBE_FIRMWARE_REPORT: usize = 1 << 60;

// What the store's images declare, restated here rather than shared — the way
// the relay costs are: these are what the build put in the container, and a
// check that read them from the same place the manager does would agree with it
// by construction.

/// The version the manifest entry requires. Used here as the *installed*
/// driver set's requirement — what the machine is running today.
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

/// Builds the topology, runs two manager/probe pairs over it, and returns what
/// each probe reported.
pub(crate) fn relay_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<Option<(u64, u64)>, u32> {
    use kcore::rights::Rights;

    if components::device_manager().is_empty() || components::blk_probe().is_empty() {
        return Ok(None);
    }

    // SAFETY: the boot CPU alone; a fresh table and executive for this check.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(4);
    }

    let identity = |class_code, vendor, device| kcore::devmgr::DeviceIdentity {
        class_code,
        vendor,
        device,
        bdf: 0,
        revision: 0,
        bus: kcore::devmgr::DeviceBus::Pci,
    };
    // Devices carry TRANSFER because a manager hands them on; hubs do not, and
    // are windowless besides — a bus's registers are nothing a holder should
    // reach.
    let device_rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
    let hub_rights = Rights::READ | Rights::DERIVE;

    // **Registration order is child order, and it is load-bearing.**
    // `children_of` scans the node pool in slot order, the manager walks
    // depth-first, and it binds the first *held* device of a class — so the
    // near device has to be registered before the hub that leads away from it,
    // or the three answers are about different devices.
    exec_ref()
        .device_register_identified(
            RELAY_HUB_NEAR_OBJ,
            0,
            0,
            hub_rights,
            identity(RELAY_CLASS_BRIDGE, RELAY_REDHAT_VENDOR, 0x0001),
        )
        .map_err(|_| 10u32)?;
    exec_ref()
        .device_register_identified(
            RELAY_NEAR_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 11u32)?;
    exec_ref()
        .device_set_parent(RELAY_NEAR_DEVICE_OBJ, RELAY_HUB_NEAR_OBJ)
        .map_err(|_| 11u32)?;

    exec_ref()
        .device_register_identified(
            RELAY_HUB_FAR_OBJ,
            0,
            0,
            hub_rights,
            identity(RELAY_CLASS_BRIDGE, RELAY_REDHAT_VENDOR, 0x0002),
        )
        .map_err(|_| 12u32)?;
    exec_ref()
        .device_set_parent(RELAY_HUB_FAR_OBJ, RELAY_HUB_NEAR_OBJ)
        .map_err(|_| 12u32)?;
    exec_ref()
        .device_register_identified(
            RELAY_FAR_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 13u32)?;
    exec_ref()
        .device_set_parent(RELAY_FAR_DEVICE_OBJ, RELAY_HUB_FAR_OBJ)
        .map_err(|_| 13u32)?;
    exec_ref()
        .device_register_identified(
            RELAY_FAR_NET_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_NETWORK, RELAY_VIRTIO_VENDOR, 0x1041),
        )
        .map_err(|_| 14u32)?;
    exec_ref()
        .device_set_parent(RELAY_FAR_NET_OBJ, RELAY_HUB_FAR_OBJ)
        .map_err(|_| 14u32)?;

    // **The hub with no identity**, registered the way a device the kernel
    // could not enumerate is: the manager can see something is there and cannot
    // learn what, so the manifest has nothing to say about what passing through
    // it costs.
    exec_ref()
        .device_register_mmio(RELAY_HUB_UNKNOWN_OBJ, 0, 0, hub_rights)
        .map_err(|_| 15u32)?;
    exec_ref()
        .device_register_identified(
            RELAY_UNKNOWN_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 15u32)?;
    exec_ref()
        .device_set_parent(RELAY_UNKNOWN_DEVICE_OBJ, RELAY_HUB_UNKNOWN_OBJ)
        .map_err(|_| 15u32)?;

    for (server, client, base) in [
        (RELAY_SERVER_OBJ, RELAY_CLIENT_OBJ, 16u32),
        (RELAY_SERVER_2_OBJ, RELAY_CLIENT_2_OBJ, 17),
    ] {
        let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| base)?;
        exec_ref().bind_endpoint_object(server_ep, server);
        exec_ref().bind_endpoint_object(client_ep, client);
    }

    let kstacks = kstack_mark();

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(bind_observer);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    crate::syscalls::publish_frames(frames);

    let first = relay_pair(
        RELAY_HUB_NEAR_OBJ,
        Rights::READ | Rights::DERIVE,
        RELAY_SERVER_OBJ,
        RELAY_CLIENT_OBJ,
        RELAY_MANAGER_PROC_OBJ,
        RELAY_PROBE_PROC_OBJ,
        1,
        BLK_PROBE_RELAY_REPORT,
        kernel_vm,
        frames,
        20,
    )?;
    // A second manager rather than a fourth request on the first: a manager
    // hands out the first *held* device of a class, and a refused device stays
    // held — so every later request for that class answers about the same
    // device. Asking a different manager is what makes this a different
    // question, and running the pairs one after the other is what keeps the two
    // reports in a known order.
    let second = relay_pair(
        RELAY_HUB_UNKNOWN_OBJ,
        Rights::READ | Rights::DERIVE,
        RELAY_SERVER_2_OBJ,
        RELAY_CLIENT_2_OBJ,
        RELAY_MANAGER_2_PROC_OBJ,
        RELAY_PROBE_2_PROC_OBJ,
        1,
        BLK_PROBE_RELAY_REPORT,
        kernel_vm,
        frames,
        40,
    )?;

    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    let outcome = judge_relay();

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once. Both managers are still blocked in `recv`: a resident
    // server has no exit, and what ended each run is its probe having reported.
    unsafe {
        for spawn in [first, second] {
            for thread in [spawn.0, spawn.2] {
                exec_ref().scheduler().reap(thread);
            }
        }
        let processes = &mut *&raw mut PROCESSES;
        for spawn in [first, second] {
            for process in [spawn.1, spawn.3] {
                if let Some(mut gone) = processes.remove(process) {
                    exec_ref().release_memory_of(gone.id(), frames, None);
                    gone.space_mut().teardown(frames);
                }
            }
        }
    }
    kstack_release(kernel_vm, kstacks, BIND_KSTACK_PAGES);
    outcome.map(Some)
}

/// Spawns one device manager over `root` and one `blk-probe` against it, and
/// runs until nothing is runnable.
///
/// The manager is a resident server and never exits, so what ends the run is
/// the probe having reported. Each pair is run to quiescence before the next is
/// spawned: two managers racing would put their probes' reports in the sink in
/// whichever order the scheduler happened to produce, and the check would be
/// asserting on a coincidence.
#[allow(clippy::too_many_arguments)]
fn relay_pair(
    root: ObjectId,
    root_rights: kcore::rights::Rights,
    server: ObjectId,
    client: ObjectId,
    manager_obj: ObjectId,
    probe_obj: ObjectId,
    manager_arg: usize,
    probe_arg: usize,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    base_err: u32,
) -> Result<(usize, usize, usize, usize), u32> {
    use kcore::rights::Rights;

    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        manager_arg,
        manager_obj,
        kernel_vm,
        frames,
        base_err,
    )?;
    // SAFETY: the boot CPU alone; the process table is quiescent between spawns.
    unsafe {
        let manager = (&mut *&raw mut PROCESSES)
            .get_mut(manager_proc)
            .ok_or(base_err + 10)?;
        manager
            .handles_mut()
            .install(server, Rights::READ)
            .map_err(|_| base_err + 10)?;
        // The root it walks, with DERIVE: the manager descends from where it
        // starts, so the topology it charges for is the topology it walked.
        manager
            .handles_mut()
            .install(root, root_rights)
            .map_err(|_| base_err + 10)?;
    }

    let (probe_thread, probe_proc) = spawn_elf_process(
        components::blk_probe(),
        probe_arg,
        probe_obj,
        kernel_vm,
        frames,
        base_err + 1,
    )?;
    // SAFETY: as above. The probe gets its endpoint and **no device**.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(probe_proc)
            .ok_or(base_err + 11)?
            .handles_mut()
            .install(client, Rights::WRITE)
            .map_err(|_| base_err + 11)?;
    }

    // Everything here is cooperative — a call, a reply, an exit — so the
    // scheduler runs to quiescence without a tick to prod it.
    exec_ref().run();
    Ok((manager_thread, manager_proc, probe_thread, probe_proc))
}

/// Reads what the two runs left and says what they establish.
fn judge_relay() -> Result<(u64, u64), u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(60);
    }
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        return Err(61);
    }
    let declared = BIND_REPORTS[0].load(Ordering::SeqCst);
    let undeclared = BIND_REPORTS[1].load(Ordering::SeqCst);
    if declared != RELAY_EXPECTED {
        return Err(62);
    }
    if undeclared != RELAY_UNDECLARED_EXPECTED {
        return Err(63);
    }
    Ok((declared, undeclared))
}

/// The firmware check's own objects.
pub(crate) const FIRMWARE_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x1a0);
pub(crate) const FIRMWARE_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x1a1);
pub(crate) const FIRMWARE_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x1a2);
pub(crate) const FIRMWARE_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x1a3);
pub(crate) const FIRMWARE_PROBE_PROC_OBJ: ObjectId = ObjectId::from_raw(0x1a4);

/// What the firmware run produced.
pub(crate) struct FirmwareReportPair {
    pub(crate) refusals: u64,
    pub(crate) driver: u64,
    /// Whether a stricter incoming driver set would strand an image already in
    /// the store — `docs/drivers/01`'s update-compatibility check.
    pub(crate) update_would_strand: bool,
}

/// What the driver must report: the digest it measured, and the version and
/// security version of what it was handed.
pub(crate) fn firmware_report_expected(digest_lead: u32) -> u64 {
    u64::from(digest_lead) | (FIRMWARE_GOOD_VERSION << 32) | (FIRMWARE_GOOD_SVN << 40)
}

/// Proves **firmware loading, mediated by the driver framework** —
/// `docs/drivers/01`, "Firmware Loading".
///
/// Five claims, and each is a different outcome from one code path:
///
/// 1. A manager holding `Rights::FIRMWARE` fetches a verified image and hands
///    it to a driver beside the device, as a second capability.
/// 2. The driver **measures what it received** and gets the digest the kernel
///    measured from the store — the only claim here that neither side can
///    satisfy by trusting the other.
/// 3. An image below the system's rollback floor is refused **while measuring
///    perfectly**: `docs/security/02`'s "rejected even if correctly signed".
/// 4. An image the floor accepts and the manifest entry does not is refused
///    *differently*, because those are two authorities and two fixes.
/// 5. The driver asks for firmware itself and is refused, because the manager
///    narrowed the right away when it handed the device on. Without this the
///    right would be a bit nobody had watched refuse anything.
pub(crate) fn firmware_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<Option<FirmwareReportPair>, u32> {
    use kcore::rights::Rights;

    if components::device_manager().is_empty()
        || components::blk_probe().is_empty()
        || kcore::firmware::system_store().is_empty()
    {
        return Ok(None);
    }

    // SAFETY: the boot CPU alone; a fresh table and executive for this check.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(4);
    }

    // **FIRMWARE is granted here and nowhere else.** Boot gives it to the
    // manager because the manager is the framework; the manager does not pass
    // it on, and the driver's refusal later is that decision working.
    let manager_rights = Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::FIRMWARE;
    exec_ref()
        .device_register_identified(
            FIRMWARE_DEVICE_OBJ,
            0,
            0,
            manager_rights,
            kcore::devmgr::DeviceIdentity {
                class_code: RELAY_CLASS_STORAGE,
                vendor: RELAY_VIRTIO_VENDOR,
                // The product id the one firmware-declaring manifest entry
                // names. Every other block device in this tree keeps binding
                // with no firmware at all, which is the normal case.
                device: FIRMWARE_BLOCK_PRODUCT,
                bdf: 0,
                revision: 0,
                bus: kcore::devmgr::DeviceBus::Pci,
            },
        )
        .map_err(|_| 10u32)?;
    let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| 11u32)?;
    exec_ref().bind_endpoint_object(server_ep, FIRMWARE_SERVER_OBJ);
    exec_ref().bind_endpoint_object(client_ep, FIRMWARE_CLIENT_OBJ);

    let kstacks = kstack_mark();

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(bind_observer);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    crate::syscalls::publish_frames(frames);

    let spawned = relay_pair(
        FIRMWARE_DEVICE_OBJ,
        // The device itself, with the authority to fetch its firmware. The
        // manager spends it and narrows it away on the transfer.
        manager_rights,
        FIRMWARE_SERVER_OBJ,
        FIRMWARE_CLIENT_OBJ,
        FIRMWARE_MANAGER_PROC_OBJ,
        FIRMWARE_PROBE_PROC_OBJ,
        DEVICE_MANAGER_FIRMWARE_PROBE,
        BLK_PROBE_FIRMWARE_REPORT,
        kernel_vm,
        frames,
        20,
    )?;

    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    let outcome = judge_firmware();

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [spawned.0, spawned.2] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in [spawned.1, spawned.3] {
            if let Some(mut gone) = processes.remove(process) {
                exec_ref().release_memory_of(gone.id(), frames, None);
                gone.space_mut().teardown(frames);
            }
        }
    }
    kstack_release(kernel_vm, kstacks, BIND_KSTACK_PAGES);
    outcome.map(Some)
}

/// Reads what the firmware run left.
fn judge_firmware() -> Result<FirmwareReportPair, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(60);
    }
    // Two reports: the manager's refusals first (it writes before it serves),
    // then the driver's.
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        return Err(61);
    }
    let refusals = BIND_REPORTS[0].load(Ordering::SeqCst);
    let driver = BIND_REPORTS[1].load(Ordering::SeqCst);
    if refusals != FIRMWARE_REFUSALS_EXPECTED {
        return Err(62);
    }
    Ok(FirmwareReportPair {
        refusals,
        driver,
        update_would_strand: firmware_update_would_strand(),
    })
}

/// Runs `docs/drivers/01`'s update-compatibility rule over the store's **real**
/// contents.
///
/// The question an update has to answer is whether the machine still works
/// afterwards, so it is asked of the images that are *in use*: an image today's
/// policy already refuses is not stranded by an update, because nothing is
/// running it. Filtering by the current rule first is what makes the answer
/// about the update rather than about the store's contents.
///
/// Two candidate driver sets against that set: the one installed, which still
/// admits everything, and a stricter one requiring a version above what is
/// there, which does not. Both are checked, because a rule that refused
/// everything would look correct with only the second.
pub(crate) fn firmware_update_would_strand() -> bool {
    let Ok(store) = kcore::store::mount(kcore::firmware::system_store()) else {
        return false;
    };
    let installed = tessera_firmware::Requirement {
        min_image_version: BLOCK_FIRMWARE_MIN_VERSION,
    };
    let incoming = tessera_firmware::Requirement {
        min_image_version: FIRMWARE_GOOD_VERSION as u32 + 1,
    };
    let policy = kcore::firmware::POLICY;

    let mut in_use = [tessera_firmware::Image {
        svn: 0,
        image_version: 0,
    }; 8];
    let mut count = 0;
    for index in 0..store.len().min(in_use.len()) {
        let Ok(entry) = store.entry(index) else {
            continue;
        };
        // Firmware only: the store carries other things, and an answer about a
        // blob no driver loads would be noise.
        if !entry.name().starts_with("firmware") {
            continue;
        }
        let image = tessera_firmware::Image {
            svn: entry.svn,
            image_version: entry.image_version,
        };
        if tessera_firmware::admit(&image, &installed, &policy).is_ok() {
            in_use[count] = image;
            count += 1;
        }
    }
    let in_use = &in_use[..count];
    if in_use.is_empty() {
        return false;
    }
    tessera_firmware::update_compatible(in_use, &installed, &policy).is_ok()
        && tessera_firmware::update_compatible(in_use, &incoming, &policy).is_err()
}
