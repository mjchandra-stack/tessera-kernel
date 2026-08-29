// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A device outlives its driver: the window is revoked and the class re-bound.
//!
//! A departing driver's device window goes before its frames are reused, or the
//! device keeps writing into memory that belongs to something else.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

/// A driver binds a device by class, dies, and its replacement binds the same
/// physical device.
///
/// This is the driver framework, running on a second architecture with **not
/// one line of its mechanism changed**: the resource graph, the transfer, the
/// window revocation and the reclaim all live in `kcore`, and the manager and
/// the probe are the same sources AArch64 builds. What is new here is the
/// boot glue that grants the authority, and the fact that the programs now
/// compile for two targets.
///
/// Returns what each incarnation reported.
pub(crate) fn driver_rebind_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    device_base: u64,
    device_len: u64,
    identity: Option<kcore::devmgr::DeviceIdentity>,
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
    let device_obj = REBIND_DEVICE_OBJECT;
    let manager_server_obj = kcore::object::ObjectId::from_raw(71);
    let manager_client_obj = kcore::object::ObjectId::from_raw(72);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(73);
    let driver1_proc_obj = kcore::object::ObjectId::from_raw(74);
    let driver2_proc_obj = kcore::object::ObjectId::from_raw(75);

    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(2u32)?;
        // A device the kernel enumerated is registered *with what it is*, so
        // the manager can classify it without touching config space; a
        // virtio-mmio transport is registered without, and the manager falls
        // back to reading the transport's own registers.
        match identity {
            Some(identity) => exec.device_register_identified(
                device_obj,
                device_base,
                device_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
                identity,
            ),
            None => exec.device_register_mmio(
                device_obj,
                device_base,
                device_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            ),
        }
        .map_err(|_| 3u32)?;
        let channel = exec.channel_create().map_err(|_| 4u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        // The manager **depends on** this device — ladder step 4's edge in the
        // graph. It holds the inventory, and it is the one thing on this
        // machine that has to hear about a device going wrong whether or not
        // the capability finds its way back.
        exec.device_add_dependent(device_obj, channel.1)
            .map_err(|_| 4u32)?;
        channel.1
    };

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

    // The manager, holding the machine's one device. **TRANSFER** is what
    // makes it a manager rather than a driver that happens to hold something —
    // handing a capability on is itself a right, and D91 paid for learning it.
    let (manager_idx, manager_proc) = spawn_elf_process(
        kernel_space,
        frames,
        components::device_manager(),
        REBIND_MANAGER_KSTACK_VA,
        11,
        1,
        manager_proc_obj,
        20,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(40u32)?;
        // Install order is the ABI: handle 0 is the service endpoint, then the
        // devices from handle 1 up. The program names those numbers.
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 41u32)?;
        manager
            .handles_mut()
            .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .map_err(|_| 42u32)?;
    }

    // --- The crash-recovery ladder, before the rebind it makes possible ---
    //
    // Incarnation 0 binds the device and then **faults on purpose**, holding
    // it. A driver that exits tidily exercises teardown, not recovery: it has
    // already given back everything it held. A host killed mid-flight has not,
    // and whether the device comes back from it is the question the ladder
    // answers. The policy and the three records are `kcore::supervise`, shared
    // with the other ports; what is local is the architecture work.
    let mut supervisor = kcore::supervise::RestartSupervisor::new(DRIVER_RESTART_BUDGET);
    if !supervise_one_crash(
        &mut supervisor,
        kernel_space,
        frames,
        16,
        kcore::object::ObjectId::from_raw(76),
        device_obj,
        manager_client_obj,
        manager_client_ep,
        110,
    )? {
        // The driver was supposed to die and did not, so nothing below tests
        // recovery. Failing here beats passing a rebind that recovered from
        // nothing.
        return Err(119);
    }

    // Incarnation 1: binds by class, reads the transport's magic, exits.
    let (driver1_idx, driver1_proc) = spawn_elf_process(
        kernel_space,
        frames,
        components::blk_probe(),
        REBIND_DRIVER1_KSTACK_VA,
        12,
        1,
        driver1_proc_obj,
        50,
    )?;
    // SAFETY: as above. The driver gets its endpoint and **no device**.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(driver1_proc)
            .ok_or(70u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 70u32)?;
    }

    // Everything here is cooperative — a call, a reply, an exit — so the
    // scheduler runs to quiescence without a tick to prod it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.run();
        }
    }
    // Back to the kernel's own root **before touching a process's tables**.
    //
    // `run` returns with whatever root the last thread ran under still in
    // `satp`, and on a single-root architecture that root is also what maps
    // the kernel — `new_user` copied the kernel's entries into it. Freeing
    // that process's tables while it is active pulls the ground out from
    // under the running kernel: the next `.rodata` load faults, the fault
    // handler faults pushing its own frame, and the machine spirals silently.
    // AArch64 cannot have this bug, because there the kernel is in `TTBR1`
    // and tearing down a `TTBR0` cannot reach it.
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    // A driver that identified its device rather than driving it reports the
    // identity, not the transport's magic — the expectation belongs to the
    // caller, which knows which kind of device it registered.
    let expect_magic = identity.is_none();
    let first = REPORTS[0].load(Ordering::SeqCst);
    if expect_magic && first != REBIND_MAGIC.rotate_left(8) {
        kprintln!("driver-rebind: the first driver reported {}", first as i64);
        return Err(71);
    }

    // The driver is gone. Note what the supervisor does *not* do: it never
    // mentions the device. It does not know which devices this driver held and
    // does not need to — the kernel hands whatever it held back to the manager
    // as part of teardown, so a supervisor cannot cost the machine a device by
    // forgetting. Reaping alone is not teardown: it frees the scheduler slot
    // while the dead process still claims the thread index, and the next spawn
    // reuses it (`Process::forget_thread`).
    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver1_idx);
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(driver1_proc) {
                // No IOMMU in scope here: `driver_rebind_check` binds a
                // virtio-mmio device, which no IOMMU on this machine sits in
                // front of. The sweep still runs, so a lease taken by any
                // future device bound here would end with its holder.
                //
                // The PLIC is another matter — an interrupt route outlives
                // this teardown in the controller and in the port table, so
                // the router is real rather than absent.
                let mut router = PlicRouter;
                exec.reclaim_devices(dead, manager_client_ep, None, Some(&mut router));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        if let Some(mut dead) = processes.remove(driver1_proc) {
            dead.space_mut().teardown(frames);
        }
    }

    // Incarnation 2: the same program, a fresh process, no memory of the first.
    let (driver2_idx, driver2_proc) = spawn_elf_process(
        kernel_space,
        frames,
        components::blk_probe(),
        REBIND_DRIVER2_KSTACK_VA,
        13,
        2,
        driver2_proc_obj,
        80,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(driver2_proc)
            .ok_or(100u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 100u32)?;
    }
    // SAFETY: as the first run.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.run();
        }
    }
    // SAFETY: as after the first run, and for the same reason — the teardown
    // below frees the tables that are otherwise still mapping this kernel.
    unsafe { kernel_space.activate() };

    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(101);
    }
    let second = REPORTS[1].load(Ordering::SeqCst);
    if expect_magic && second != REBIND_MAGIC.rotate_left(16) {
        kprintln!(
            "driver-rebind: the second driver reported {}",
            second as i64
        );
        return Err(102);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver2_idx);
            exec.scheduler().reap(manager_idx);
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        for idx in [driver2_proc, manager_proc] {
            if let Some(mut gone) = processes.remove(idx) {
                gone.space_mut().teardown(frames);
            }
        }
    }
    use tessera_karch::FrameSource;
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for base in [
        REBIND_MANAGER_KSTACK_VA,
        REBIND_DRIVER1_KSTACK_VA,
        REBIND_DRIVER2_KSTACK_VA,
    ] {
        for page in 0..REBIND_KSTACK_PAGES {
            if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(base + page * FRAME_SIZE)) {
                frames.free_frame(frame);
            }
        }
    }

    Ok((first, second))
}
