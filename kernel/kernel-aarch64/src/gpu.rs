// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `gpu` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves **a device whose work is checked from outside the machine**.
///
/// Every other check here believes the guest, and is right to: the value a
/// driver reports could only have come from its device. A display is different.
/// A driver that created the resource, attached the backing, set the scanout
/// and drew nothing reports exactly what a working one does — so this check
/// asks the guest for very little, arms, and waits while the harness outside
/// asks QEMU for the framebuffer and looks at the pixels.
pub(crate) fn gpu_check(
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
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1001u32)?;
        exec.device_register_identified(
            GPU_DEVICE_OBJ,
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
        .map_err(|_| 1002u32)?;
        // Where its virtio structures are, read out of configuration space
        // during enumeration — a driver holding only a window has no way to
        // find them, because config space is not per-device and no capability
        // to it can be handed out.
        exec.device_set_layout(GPU_DEVICE_OBJ, layout)
            .map_err(|_| 1003u32)?;

        let manager = exec.channel_create().map_err(|_| 1004u32)?;
        exec.bind_endpoint_object(manager.0, GPU_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, GPU_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 1005u32)?;
        exec.bind_endpoint_object(service.0, GPU_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, GPU_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        GPU_MANAGER_KSTACK_VA,
        1,
        GPU_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1010,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::gpu_driver(),
        GPU_DRIVER_KSTACK_VA,
        0,
        GPU_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1020,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        components::gpu_client(),
        GPU_CLIENT_KSTACK_VA,
        0,
        GPU_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        1030,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(1011u32)?;
            manager
                .handles_mut()
                .install(GPU_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1011u32)?;
            manager
                .handles_mut()
                .install(
                    GPU_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 1011u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(1021u32)?;
            driver
                .handles_mut()
                .install(GPU_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 1021u32)?;
            driver
                .handles_mut()
                .install(GPU_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1021u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(1031u32)?
            .handles_mut()
            .install(GPU_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 1031u32)?;
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
    // The timer runs so the wait after the picture is drawn is a wait rather
    // than a spin, and so a driver parked on a command the device has not
    // finished with is interrupted.
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // **Armed, and then held.** The picture is on the glass now, and it stays
    // there only while this machine is running — so the check says so and waits
    // long enough for the harness outside to ask QEMU for the framebuffer. A
    // boot nobody is watching pays a few seconds; a boot that is watching gets
    // its screendump.
    kprintln!(
        "gpu: armed — a picture is on the glass, waiting for it to be looked at from outside"
    );
    kcore::verdict::claims(&["gpu.armed"]);
    {
        use tessera_karch::{CpuOps, InterruptControl};
        for _ in 0..500u32 {
            <Cpu as InterruptControl>::enable();
            Cpu::halt_until_interrupt();
            <Cpu as InterruptControl>::disable();
        }
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(1040);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Three separable claims, checked apart — and none of them is the one that
    // matters most, which is checked outside this machine entirely.
    if report & (1 << 32) == 0 {
        return Err(1041);
    }
    if report & (1 << 33) == 0 {
        return Err(1042);
    }
    if report & (1 << 34) == 0 {
        return Err(1043);
    }
    // The low half carries the pixel count, which the verdict does not need and
    // a failure does.
    if report >> 32 != GPU_CLIENT_EXPECTED >> 32 {
        return Err(1044);
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
        GPU_CLIENT_KSTACK_VA,
        GPU_DRIVER_KSTACK_VA,
        GPU_MANAGER_KSTACK_VA,
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

// --- Crypto: a device whose answer is fixed by a published standard
// (D160) ---

pub(crate) const CRYPTO_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c0);
pub(crate) const CRYPTO_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c1);
pub(crate) const CRYPTO_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c2);
pub(crate) const CRYPTO_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c3);
pub(crate) const CRYPTO_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c4);
pub(crate) const CRYPTO_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c5);
pub(crate) const CRYPTO_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c6);
pub(crate) const CRYPTO_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c7);

pub(crate) const CRYPTO_MANAGER_KSTACK_VA: u64 = 0xffff_000c_a000_0000;
pub(crate) const CRYPTO_DRIVER_KSTACK_VA: u64 = 0xffff_000c_b000_0000;
pub(crate) const CRYPTO_CLIENT_KSTACK_VA: u64 = 0xffff_000c_c000_0000;

/// What a virtio crypto device is, by vendor and device id.
///
/// **Not a PCI class.** This transport does not declare a useful one — the
/// class byte says "other", which a dozen unrelated devices also say — so it is
/// identified by what it *is* rather than by what kind of thing it claims to
/// be: 0x1040 plus the virtio device id, which is how a modern virtio function
/// names itself.
pub(crate) const VIRTIO_VENDOR_ID: u16 = 0x1af4;
pub(crate) const VIRTIO_CRYPTO_DEVICE_ID: u16 = 0x1040 + 20;

/// What the client reports: the suite came back complete, the ciphertext is the
/// one the standard publishes, it decrypts back, the key made a difference, and
/// four things that should have been refused were.
pub(crate) const CRYPTO_CLIENT_EXPECTED: u64 = (0xc0 << 56)
    | (1 << 40)
    | (1 << 39)
    | (1 << 38)
    | (1 << 37)
    | (1 << 36)
    | (1 << 35)
    | (1 << 34)
    | (1 << 33)
    | (1 << 32);

