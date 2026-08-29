// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A device's data path is a declared cost, and the budget refuses one that is too far.
//!
//! The manager declares what a hop costs; a path over budget is refused rather than
//! taken slowly, which is the only form in which a budget is a decision.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

/// The chain [`relay_check`] builds: two relaying hubs the manifest describes,
/// one it does not, and the devices behind each.
///
/// Graph nodes with real parent edges, as on AArch64 and for the same reason —
/// no reference machine has a relaying hub on it, and the edge the manager
/// walks is the one `pcie_enumerate` records either way.
pub(crate) const RELAY_HUB_NEAR_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc0);
pub(crate) const RELAY_NEAR_DEVICE_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc1);
pub(crate) const RELAY_HUB_FAR_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc2);
pub(crate) const RELAY_FAR_DEVICE_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc3);
pub(crate) const RELAY_FAR_NET_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc4);
pub(crate) const RELAY_HUB_UNKNOWN_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc5);
pub(crate) const RELAY_UNKNOWN_DEVICE_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc6);
pub(crate) const RELAY_SERVER_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc7);
pub(crate) const RELAY_CLIENT_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc8);
pub(crate) const RELAY_MANAGER_PROC_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xc9);
pub(crate) const RELAY_PROBE_PROC_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xca);
pub(crate) const RELAY_SERVER_2_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xcb);
pub(crate) const RELAY_CLIENT_2_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xcc);
pub(crate) const RELAY_MANAGER_2_PROC_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xcd);
pub(crate) const RELAY_PROBE_2_PROC_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xce);

/// Kernel stacks, in the direct map's gigabyte slot (the D100 constraint), and
/// the ASIDs that go with them.
pub(crate) const RELAY_MANAGER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb400_0000;
pub(crate) const RELAY_PROBE_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb500_0000;
pub(crate) const RELAY_MANAGER_2_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb600_0000;
pub(crate) const RELAY_PROBE_2_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb700_0000;
pub(crate) const RELAY_MANAGER_ASID: u16 = 21;
pub(crate) const RELAY_PROBE_ASID: u16 = 22;
pub(crate) const RELAY_MANAGER_2_ASID: u16 = 23;
pub(crate) const RELAY_PROBE_2_ASID: u16 = 24;

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
/// nothing describes. Identical to the AArch64 expectations, because the
/// manifest, the arbiter and the probe are the same sources — only the boot
/// glue below is per-port.
pub(crate) const RELAY_EXPECTED: u64 = (1 << 8)
    | (RELAY_NEAR_COST_US << 16)
    | (8u64 << 32)
    | (9u64 << 40)
    | (RELAY_NEAR_THROUGHPUT_MBPS << 48);
pub(crate) const RELAY_UNDECLARED_EXPECTED: u64 = 10 | (10u64 << 32) | (1u64 << 40);

/// One spawned program: its scheduler thread and its process, which are not the
/// same index and are both released at the end.
#[derive(Clone, Copy)]
pub(crate) struct RelaySpawn {
    pub(crate) thread: usize,
    pub(crate) process: usize,
}

/// Proves that a device's **data path is a declared cost, checked at binding
/// time**, on a second architecture — `docs/drivers/01`, "Bus Topology And Data
/// Paths".
///
/// **Not one line of the mechanism is per-port**, which is the same thing D111
/// showed for binding itself. The arbiter is `api/binding`, the manifest and
/// the accumulation are `userspace/device-manager`, and the budget is checked
/// by the same `blk-probe` — all compiled for a second target and otherwise
/// untouched. What is here is the boot glue that builds the topology and grants
/// the authority.
///
/// The claim is the doc's: one manifest entry with one budget, asked about two
/// devices of the same class differing **only in depth**, binds the near one
/// and refuses the far one. Throughput refuses separately, because a shorter
/// path is no help when the remaining hop is the narrow one. And a hub the
/// kernel cannot identify is refused rather than assumed free.
pub(crate) fn relay_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u64, u64), u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    if components::device_manager().is_empty() || components::blk_probe().is_empty() {
        return Err(1);
    }

    // SAFETY: the boot CPU alone; written before any thread runs.
    unsafe {
        kcore_exec_restart(4);
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
        // should reach.
        let device_rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
        let hub_rights = Rights::READ | Rights::DERIVE;

        // **Registration order is child order, and it is load-bearing.**
        // `children_of` scans the node pool in slot order, the manager walks
        // depth-first, and it binds the first *held* device of a class — so the
        // near device has to be registered before the hub that leads away from
        // it, or the three answers are about different devices.
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

        // **The hub with no identity**, registered the way a device the kernel
        // could not enumerate is: the manager can see something is there and
        // cannot learn what, so the manifest has nothing to say about what
        // passing through it costs.
        exec.device_register_mmio(RELAY_HUB_UNKNOWN_OBJ, 0, 0, hub_rights)
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

    REPORT_COUNT.store(0, Ordering::SeqCst);
    REPORTS_FROM_ANY_THREAD.store(true, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);

    let (manager, probe) = relay_pair(
        kernel_space,
        frames,
        RELAY_HUB_NEAR_OBJ,
        RELAY_SERVER_OBJ,
        RELAY_CLIENT_OBJ,
        RELAY_MANAGER_PROC_OBJ,
        RELAY_PROBE_PROC_OBJ,
        RELAY_MANAGER_KSTACK_VA,
        RELAY_PROBE_KSTACK_VA,
        RELAY_MANAGER_ASID,
        RELAY_PROBE_ASID,
        20,
    )?;

    // A second manager rather than a fourth request on the first: a manager
    // hands out the first *held* device of a class, and a refused device stays
    // held — so every later request for that class answers about the same
    // device. Asking a different manager is what makes this a different
    // question, and running the pairs one after the other is what keeps the two
    // reports in a known order.
    let (manager2, probe2) = relay_pair(
        kernel_space,
        frames,
        RELAY_HUB_UNKNOWN_OBJ,
        RELAY_SERVER_2_OBJ,
        RELAY_CLIENT_2_OBJ,
        RELAY_MANAGER_2_PROC_OBJ,
        RELAY_PROBE_2_PROC_OBJ,
        RELAY_MANAGER_2_KSTACK_VA,
        RELAY_PROBE_2_KSTACK_VA,
        RELAY_MANAGER_2_ASID,
        RELAY_PROBE_2_ASID,
        40,
    )?;

    // SAFETY: the teardown below frees tables that are otherwise still mapping
    // this kernel, so the kernel's own space is made current first.
    unsafe { kernel_space.activate() };
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(60);
    }
    if REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        return Err(61);
    }
    let declared = REPORTS[0].load(Ordering::SeqCst);
    let undeclared = REPORTS[1].load(Ordering::SeqCst);
    if declared != RELAY_EXPECTED {
        return Err(62);
    }
    if undeclared != RELAY_UNDECLARED_EXPECTED {
        return Err(63);
    }

    // SAFETY: transient raw access; all threads are off-CPU, each released
    // once. Reaping alone is not teardown — it frees the scheduler slot while
    // the dead process still claims the thread index, and the next spawn reuses
    // it, so `forget_thread` follows every reap. Both managers are still
    // blocked in `recv`: a resident server has no exit, and what ended each run
    // is its probe having reported.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            for spawn in [manager, probe, manager2, probe2] {
                exec.scheduler().reap(spawn.thread);
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        for spawn in [manager, probe, manager2, probe2] {
            if let Some(mut gone) = processes.remove(spawn.process) {
                gone.space_mut().teardown(frames);
            }
        }
    }

    use tessera_karch::FrameSource;
    // SAFETY: the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for base in [
        RELAY_MANAGER_KSTACK_VA,
        RELAY_PROBE_KSTACK_VA,
        RELAY_MANAGER_2_KSTACK_VA,
        RELAY_PROBE_2_KSTACK_VA,
    ] {
        for page in 0..REBIND_KSTACK_PAGES {
            if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(base + page * FRAME_SIZE)) {
                frames.free_frame(frame);
            }
        }
    }

    Ok((declared, undeclared))
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
pub(crate) fn relay_pair(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    root: kcore::object::ObjectId,
    server: kcore::object::ObjectId,
    client: kcore::object::ObjectId,
    manager_proc_obj: kcore::object::ObjectId,
    probe_proc_obj: kcore::object::ObjectId,
    manager_kstack: u64,
    probe_kstack: u64,
    manager_asid: u16,
    probe_asid: u16,
    base_err: u32,
) -> Result<(RelaySpawn, RelaySpawn), u32> {
    use kcore::rights::Rights;

    let (manager_idx, manager_proc) = spawn_elf_process(
        kernel_space,
        frames,
        components::device_manager(),
        manager_kstack,
        manager_asid,
        1,
        manager_proc_obj,
        base_err,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(base_err + 10)?;
        // Install order is the ABI: handle 0 is the service endpoint, then the
        // inventory roots from handle 1 up.
        manager
            .handles_mut()
            .install(server, Rights::READ)
            .map_err(|_| base_err + 10)?;
        // **The bus, and nothing else.** Everything behind it the manager gets
        // from the graph — which is also where the path it accumulates comes
        // from, so the topology it charges for is the topology it walked.
        manager
            .handles_mut()
            .install(root, Rights::READ | Rights::DERIVE)
            .map_err(|_| base_err + 10)?;
    }

    let (probe_idx, probe_proc) = spawn_elf_process(
        kernel_space,
        frames,
        components::blk_probe(),
        probe_kstack,
        probe_asid,
        BLK_PROBE_RELAY_REPORT,
        probe_proc_obj,
        base_err + 1,
    )?;
    // SAFETY: as above. The probe gets its endpoint and **no device**.
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
            exec.run();
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
