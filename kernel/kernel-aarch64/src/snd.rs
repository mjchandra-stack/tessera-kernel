// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `snd` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves **a device that is never finished**.
///
/// Everything else this kernel drives answers a request and stops. A playback
/// stream is a standing obligation: the device consumes periods at the rate of
/// the sound and plays silence the moment there is nothing to consume, and
/// nothing fails while it happens.
///
/// Which is why the check has two streams. One is kept fed and must have
/// consumed periods with no gap; the other is started, given one period and
/// abandoned, and must be **reported** as having gapped. Without the second, a
/// driver that dropped every period on the floor would pass — silence is what a
/// broken audio path produces too.
pub(crate) fn snd_check(
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
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(901u32)?;
        exec.device_register_identified(
            SND_DEVICE_OBJ,
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
        .map_err(|_| 902u32)?;
        // Where its virtio structures are, read out of configuration space
        // during enumeration — a driver holding only a window has no way to
        // find them, because config space is not per-device and no capability
        // to it can be handed out.
        exec.device_set_layout(SND_DEVICE_OBJ, layout)
            .map_err(|_| 903u32)?;

        let manager = exec.channel_create().map_err(|_| 904u32)?;
        exec.bind_endpoint_object(manager.0, SND_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, SND_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 905u32)?;
        exec.bind_endpoint_object(service.0, SND_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, SND_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        SND_MANAGER_KSTACK_VA,
        1,
        SND_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        910,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::snd_driver(),
        SND_DRIVER_KSTACK_VA,
        0,
        SND_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        920,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        components::snd_client(),
        SND_CLIENT_KSTACK_VA,
        0,
        SND_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        930,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(911u32)?;
            manager
                .handles_mut()
                .install(SND_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 911u32)?;
            manager
                .handles_mut()
                .install(
                    SND_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 911u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(921u32)?;
            driver
                .handles_mut()
                .install(SND_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 921u32)?;
            driver
                .handles_mut()
                .install(SND_SERVER_OBJ, Rights::READ)
                .map_err(|_| 921u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(931u32)?
            .handles_mut()
            .install(SND_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 931u32)?;
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
    // **The device consumes at the rate of the sound**, so the client's polling
    // has to be able to make progress while nothing else is runnable. The timer
    // runs so a stream waiting on a period the device has not finished with is
    // interrupted rather than spinning to its bound.
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
        return Err(940);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Three separable claims, checked apart: the suite came back complete, the
    // fed stream played without a gap, and the abandoned one gapped.
    if report & (1 << 32) == 0 {
        return Err(941);
    }
    if report & (1 << 33) == 0 {
        return Err(942);
    }
    if report & (1 << 34) == 0 {
        return Err(943);
    }
    // The low half carries the fed stream's own numbers, which the verdict
    // does not need and a failure does.
    if report >> 32 != SND_CLIENT_EXPECTED >> 32 {
        return Err(944);
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
        SND_CLIENT_KSTACK_VA,
        SND_DRIVER_KSTACK_VA,
        SND_MANAGER_KSTACK_VA,
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

// --- Display: the first device whose work is checked from outside the
// machine (D159) ---

pub(crate) const GPU_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a0);
pub(crate) const GPU_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a1);
pub(crate) const GPU_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a2);
pub(crate) const GPU_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a3);
pub(crate) const GPU_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a4);
pub(crate) const GPU_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a5);
pub(crate) const GPU_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a6);
pub(crate) const GPU_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a7);

pub(crate) const GPU_MANAGER_KSTACK_VA: u64 = 0xffff_000b_a000_0000;
pub(crate) const GPU_DRIVER_KSTACK_VA: u64 = 0xffff_000b_b000_0000;
pub(crate) const GPU_CLIENT_KSTACK_VA: u64 = 0xffff_000b_c000_0000;

/// A display controller. Matched on the base byte: every subclass of it is a
/// display of some kind, which is not true of the multimedia class beside it.
pub(crate) const PCI_CLASS_DISPLAY: u32 = 0x03;

/// What the client reports: the suite came back complete, every pixel was
/// written and shown, and a blit past the edge was refused rather than clipped.
pub(crate) const GPU_CLIENT_EXPECTED: u64 = (0xd0 << 56) | (1 << 34) | (1 << 33) | (1 << 32);

