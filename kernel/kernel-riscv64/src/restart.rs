// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A driver is supervised: restarted while there is budget, given up on after.
//!
//! The half that says no is the half worth checking — a supervisor that only ever
//! restarts is one that cannot report a service as lost.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

/// The user stack every framework program gets. Clear of its image at
/// 0x1000_0000 and of the probe windows `uabi::layout` puts at 0x3000_0000.
pub(crate) const REBIND_USER_STACK_VA: u64 = 0x2000_0000;
pub(crate) const REBIND_USER_STACK_PAGES: u64 = 4;
/// Kernel stacks, in the direct map's gigabyte slot (the D100 constraint).
/// Eight pages: a channel op parks a whole dispatch frame across the handoff.
pub(crate) const REBIND_MANAGER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb000_0000;
pub(crate) const REBIND_DRIVER1_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb100_0000;
pub(crate) const REBIND_DRIVER2_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb200_0000;
/// The crashing incarnations' window, **reused** across launches: supervision
/// here is synchronous, so one host is alive at a time and each crash's
/// reclaim frees the window before the next spawn takes it.
pub(crate) const REBIND_CRASH_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb300_0000;

/// How many times a persistently crashing host is brought back here, and the
/// deliberately smaller budget the give-up self-test runs against so that the
/// budget — not the driver running out of ways to fail — is what stops it.
pub(crate) const DRIVER_RESTART_BUDGET: u32 = kcore::supervise::DEFAULT_RESTART_BUDGET;
/// This supervisor's give-up identity, so two supervisors giving up in one
/// boot stay distinguishable in the record stream.
pub(crate) const DRIVER_RESTART_GIVEUP_CODE: u64 = 179;

/// The startup-argument bit that asks `blk-probe` to crash once it holds its
/// device (`userspace/blk-probe`'s `CRASH_AFTER_BIND`).
///
/// Duplicated here rather than shared through `uabi` because it is a fact
/// about **one program's** entry contract, not about the ABI.
pub(crate) const BLK_PROBE_CRASH_AFTER_BIND: usize = 1 << 63;

/// Runs one host that is asked to crash, contains it, records the ladder's
/// first and sixth steps, and reclaims the corpse.
///
/// Returns whether the host actually faulted. `false` means it exited or never
/// got there, which the caller must treat as a failure rather than a recovery
/// — a supervisor that reports restarting a host that never crashed is
/// reporting work it did not do.
///
/// **The supervisor names no device.** `reclaim_devices` hands whatever the
/// corpse held back to the manager, which is what makes forgetting impossible
/// rather than merely unlikely.
#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise_one_crash(
    supervisor: &mut kcore::supervise::RestartSupervisor,
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    asid: u16,
    proc_obj: kcore::object::ObjectId,
    device_obj: kcore::object::ObjectId,
    manager_client_obj: kcore::object::ObjectId,
    manager_client_ep: kcore::ipc::EndpointId,
    base_err: u32,
) -> Result<bool, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    USER_FAULT.store(0, Ordering::SeqCst);
    USER_FAULT_ADDR.store(0, Ordering::SeqCst);
    USER_FAULT_CORRELATION.store(0, Ordering::SeqCst);

    let (idx, proc) = spawn_elf_process(
        kernel_space,
        frames,
        components::blk_probe(),
        REBIND_CRASH_KSTACK_VA,
        asid,
        BLK_PROBE_CRASH_AFTER_BIND,
        proc_obj,
        base_err,
    )?;
    // SAFETY: transient raw access to the static process table; the process
    // was just inserted and no thread of it has run.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(proc)
            .ok_or(base_err + 20)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| base_err + 20)?;
    }
    supervisor.launched();
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.run();
        }
    }
    // Back to the kernel's own root before touching a process's tables — the
    // single-root hazard this file documents at every other `run` return.
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    let cause = USER_FAULT.load(Ordering::SeqCst);
    if cause != 0 {
        let correlation = USER_FAULT_CORRELATION.load(Ordering::SeqCst);
        let address = USER_FAULT_ADDR.load(Ordering::SeqCst);
        // Ladder step 1. Adopt the dead host's cause before recording
        // anything, or the ladder roots a fresh trace and the restart cannot
        // be joined to the crash that provoked it.
        kcore::trace::set_current_correlation(correlation);
        supervisor.crashed(cause, address);

        // Ladder step 3: the dump, taken before the corpse is torn down and
        // before the ring fills with teardown records — the trail this is for
        // is the one leading up to the fault.
        let mut dump = CRASH_DUMP_TEMPLATE;
        kcore::supervise::capture_crash_dump(&mut dump, proc_obj, cause, address, correlation);

        // Steps 4 and 5. The supervisor does not know everything the driver
        // held — that is reclaim's job below, and the reason reclaim names
        // nothing — but it was asked to supervise a (driver, device) pair, and
        // these two rungs are about the device half of it.
        // SAFETY: transient raw access to the static executive; every thread
        // is off-CPU here.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.notify_dependents(
                    device_obj,
                    kcore::lifecycle::DriverState::Degraded,
                    kcore::lifecycle::TransitionReason::DriverCrashed,
                );
                let mut resetter = VirtioMmioResetter;
                let _ = exec.reset_device(
                    device_obj,
                    kcore::devmgr::ResetPolicy::OnDegraded,
                    Some(&mut resetter),
                );
            }
        }
    }

    // The free-list depth, not `handed_out`: the latter is cumulative and
    // never decreases, so a delta across a reclaim would always be zero.
    let free_before = frames.free_list_depth();
    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(idx);
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(proc) {
                let mut router = PlicRouter;
                exec.reclaim_devices(dead, manager_client_ep, None, Some(&mut router));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        if let Some(mut dead) = processes.remove(proc) {
            dead.space_mut().teardown(frames);
        }
    }

    // The kernel stack the corpse used goes back too, before the next launch
    // asks for the same window. Without this the second crashing incarnation
    // would fail to map its stack over a live mapping — the reason
    // supervision here is synchronous and one window can serve every launch.
    // The frames are freed, not merely unmapped: a leak here would show up in
    // the restart record's reclaimed count, which is exactly what that field
    // exists to make visible.
    use tessera_karch::FrameSource;
    // SAFETY: the alias owns no tables and is used only to unmap; the kernel
    // space is active and every thread of the corpse is off-CPU.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for page in 0..REBIND_KSTACK_PAGES {
        if let Ok(frame) =
            kernel_alias.unmap(VirtAddr::new(REBIND_CRASH_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }

    if cause != 0 {
        supervisor.restarted(frames.free_list_depth().saturating_sub(free_before) as u64);
    }
    // Cleared so the checks after this one do not read a deliberate crash as
    // their own failure.
    USER_FAULT.store(0, Ordering::SeqCst);
    USER_FAULT_ADDR.store(0, Ordering::SeqCst);
    Ok(cause != 0)
}
pub(crate) const REBIND_KSTACK_PAGES: u64 = 8;

/// What each incarnation of the probe reports: the transport's magic, rotated
/// by its incarnation number so the two runs cannot be mistaken for one value
/// written twice.
pub(crate) const REBIND_MAGIC: u64 = 0x7472_6976;

/// Builds one framework process from its ELF: a fresh space, loaded segments,
/// user and kernel stacks, and a thread registered on the shared executive.
/// Installs **no** handles — the caller grants each process exactly its
/// authority, which is the whole point of the exercise.
/// Eight arguments, and each is one thing the caller alone knows: which space,
/// which allocator, which image, and the four identities the new process is
/// given. Bundling them into a struct would move the same list one line up.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_elf_process(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    image: &[u8],
    kstack_va: u64,
    asid: u16,
    arg: usize,
    process_obj: kcore::object::ObjectId,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    spawn_elf_process_with_stack(
        kernel_space,
        frames,
        image,
        kstack_va,
        REBIND_KSTACK_PAGES,
        REBIND_USER_STACK_VA,
        REBIND_USER_STACK_PAGES,
        asid,
        arg,
        process_obj,
        base_err,
    )
}

/// As [`spawn_elf_process`], with the two stacks named rather than assumed.
///
/// **Because one program on this port needs a bigger kernel stack than the
/// rest.** A `ProcessCreate` builds a 30 KB `Process` inside a syscall, and the
/// eight pages a channel operation needs are not enough for it; every other
/// U-mode program here is happy with the default, so the size is the caller's
/// to state rather than a number raised for everybody.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_elf_process_with_stack(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    image: &[u8],
    kstack_va: u64,
    kstack_pages: u64,
    user_stack_va: u64,
    user_stack_pages: u64,
    asid: u16,
    arg: usize,
    process_obj: kcore::object::ObjectId,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch = kernel_space.new_user(frames, asid).map_err(|_| base_err)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(asid), 0);
    let entry = kcore::elf::load_into(
        image,
        &mut user_space,
        frames,
        kcore::elf::Machine::RiscV64,
        base_err + 1,
    )?;

    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // the kernel stack and is never torn down.
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(entry),
        arg,
        VirtAddr::new(user_stack_va),
        user_stack_pages,
        VirtAddr::new(kstack_va),
        kstack_pages,
        process_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| base_err + 8)?;

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 9)?
            .add_thread(thread)
            .map_err(|_| base_err + 9)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(process_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 10)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process
                .add_thread(thread_id_of(thread_idx)?)
                .map_err(|_| base_err + 11)?;
        }
    }
    Ok((thread_idx, proc_idx))
}

/// The device object the rebind check registers its block transport under.
/// Named because two checks depend on it being the same object: the rebind
/// grants it twice, and the event check asserts that the records say so.
pub(crate) const REBIND_DEVICE_OBJECT: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(70);

/// Negative self-test: a host that keeps crashing is restarted only up to its
/// budget, and then the supervisor stops.
///
/// **The ladder's most important property is the one a healthy machine never
/// shows.** Every other check here watches recovery succeed; this watches it
/// give up, because a supervisor without a bound is not a recovery policy — it
/// is a machine that respawns a broken driver until something else breaks.
///
/// Returns the launches made.
pub(crate) fn driver_giveup_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    device_base: u64,
    device_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;

    if components::device_manager().is_empty() || components::blk_probe().is_empty() {
        return Ok(0);
    }

    // SAFETY: the boot CPU alone; written before any thread runs.
    unsafe {
        kcore_exec_restart(4);
    }
    let device_obj = kcore::object::ObjectId::from_raw(29);
    let manager_server_obj = kcore::object::ObjectId::from_raw(77);
    let manager_client_obj = kcore::object::ObjectId::from_raw(78);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(79);
    let crash_proc_obj = kcore::object::ObjectId::from_raw(80);

    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(130u32)?;
        exec.device_register_mmio(
            device_obj,
            device_base,
            device_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 131u32)?;
        let channel = exec.channel_create().map_err(|_| 132u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        exec.device_add_dependent(device_obj, channel.1)
            .map_err(|_| 132u32)?;
        channel.1
    };

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

    let (manager_idx, manager_proc) = spawn_elf_process(
        kernel_space,
        frames,
        components::device_manager(),
        REBIND_MANAGER_KSTACK_VA,
        17,
        1,
        manager_proc_obj,
        133,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(140u32)?;
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 141u32)?;
        manager
            .handles_mut()
            .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .map_err(|_| 142u32)?;
    }

    let mut supervisor = kcore::supervise::RestartSupervisor::new(
        tessera_boot_checks::DRIVER_RESTART_SELFTEST_BUDGET,
    );
    // The loop the budget has to stop. Its own guard is deliberately generous:
    // a test whose runaway guard is the thing under test proves nothing.
    let mut guard = tessera_boot_checks::DRIVER_RESTART_SELFTEST_BUDGET * 4 + 4;
    while supervisor.may_restart() && guard > 0 {
        guard -= 1;
        if !supervise_one_crash(
            &mut supervisor,
            kernel_space,
            frames,
            18,
            crash_proc_obj,
            device_obj,
            manager_client_obj,
            manager_client_ep,
            143,
        )? {
            return Err(148);
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
            None => return Err(148),
        }
    };

    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: transient raw access; every thread is off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(manager_idx);
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        if let Some(mut gone) = processes.remove(manager_proc) {
            gone.space_mut().teardown(frames);
        }
    }

    // SAFETY: transient raw access; every thread is off-CPU.
    let exec = unsafe { (*(&raw const KCORE_EXEC)).as_ref() };
    tessera_boot_checks::driver_giveup_verdict(exec, device_obj, &outcome, quarantined, 149, 150)?;
    Ok(outcome.launches)
}

// --- The relay path, and what it costs (D144) ---
