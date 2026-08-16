// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `crypto` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves **a device whose right answer was decided somewhere else**.
///
/// The display check had to go outside the machine to see whether the work was
/// done. This one does not have to, and for a better reason: the answer is
/// published. A ring-3 client encrypts NIST SP 800-38A's vector and compares
/// what comes back against the ciphertext the standard says it becomes — a
/// value no wrong implementation agrees with by accident, and one that nothing
/// in this machine could have produced without actually doing the work.
pub(crate) fn crypto_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
    layout: kcore::devmgr::DeviceLayout,
    bar_base: u64,
    bar_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1201u32)?;
        exec.device_register_identified(
            CRYPTO_DEVICE_OBJ,
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
        .map_err(|_| 1202u32)?;
        // Where its virtio structures are, read out of configuration space
        // during enumeration — a driver holding only a window has no way to
        // find them, because config space is not per-device and no capability
        // to it can be handed out.
        exec.device_set_layout(CRYPTO_DEVICE_OBJ, layout)
            .map_err(|_| 1203u32)?;

        let manager = exec.channel_create().map_err(|_| 1204u32)?;
        exec.bind_endpoint_object(manager.0, CRYPTO_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, CRYPTO_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 1205u32)?;
        exec.bind_endpoint_object(service.0, CRYPTO_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, CRYPTO_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        CRYPTO_MANAGER_KSTACK_VA,
        1,
        CRYPTO_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1210,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::crypto_driver(),
        CRYPTO_DRIVER_KSTACK_VA,
        0,
        CRYPTO_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1220,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        components::crypto_client(),
        CRYPTO_CLIENT_KSTACK_VA,
        0,
        CRYPTO_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        1230,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(1201u32)?;
            manager
                .handles_mut()
                .install(CRYPTO_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1211u32)?;
            manager
                .handles_mut()
                .install(
                    CRYPTO_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 1211u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(1221u32)?;
            driver
                .handles_mut()
                .install(CRYPTO_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 1221u32)?;
            driver
                .handles_mut()
                .install(CRYPTO_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1221u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(1231u32)?
            .handles_mut()
            .install(CRYPTO_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 1231u32)?;
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
    // The timer runs so a driver parked on a command the device has not yet
    // finished with is interrupted rather than spinning to its bound.
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
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

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(1240);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Eight separable claims, checked apart so a failure names which one.
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    for (bit, which) in [
        (32u32, 1241u32),
        (33, 1242),
        (34, 1243),
        (35, 1244),
        (36, 1245),
        (37, 1246),
        (38, 1247),
        (39, 1248),
        (40, 1250),
    ] {
        if report & (1 << bit) == 0 {
            return Err(which);
        }
    }
    // The low half carries the conformance rule bits, which the verdict does
    // not need and a failure does.
    if report >> 32 != CRYPTO_CLIENT_EXPECTED >> 32 {
        return Err(1249);
    }

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
        CRYPTO_CLIENT_KSTACK_VA,
        CRYPTO_DRIVER_KSTACK_VA,
        CRYPTO_MANAGER_KSTACK_VA,
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
    Ok(report)
}

// --- Crash recovery: a client parked on a driver that dies (D171) ---

pub(crate) const CRASH_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e0);
pub(crate) const CRASH_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e1);
pub(crate) const CRASH_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e2);
pub(crate) const CRASH_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e3);
pub(crate) const CRASH_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e4);
pub(crate) const CRASH_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e5);
pub(crate) const CRASH_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e6);
pub(crate) const CRASH_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e7);

pub(crate) const CRASH_MANAGER_KSTACK_VA: u64 = 0xffff_000e_a000_0000;
pub(crate) const CRASH_DRIVER_KSTACK_VA: u64 = 0xffff_000e_b000_0000;
pub(crate) const CRASH_CLIENT_KSTACK_VA: u64 = 0xffff_000e_c000_0000;

/// The startup bit that makes the driver take a request and never answer it.
pub(crate) const CRASH_BEFORE_REPLYING: usize = 1 << 63;

/// The stage a ring-3 program reports when a channel call fails, and the tag
/// every `uabi::fail` carries. Together they say the client came back from its
/// call with an error rather than with an answer.
pub(crate) const CLIENT_FAIL_TAG: u64 = 0xdead_0000_0000_0000;
pub(crate) const CLIENT_CHANNEL_STAGE: u64 = 0xc9;

