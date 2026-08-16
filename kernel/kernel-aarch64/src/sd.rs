// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `sd` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves **a controller with card children, card-detect hotplug, and a clock
/// that is requested rather than written** — `docs/drivers/04` and the
/// removable half of the block class.
///
/// Runs in two acts, because the interesting one needs the first to have
/// finished:
///
/// 1. With a card in the slot, a ring-3 driver identifies it, **declares it
///    into the resource graph** — a device the kernel has never seen, on a bus
///    it does not know — and serves the block class over it. `blk-client`, the
///    same program that judges virtio and NVMe, reads and runs the conformance
///    suite.
/// 2. Then the check says it is armed and waits. The card is pulled from
///    outside the machine, and a second client loops on **the same request that
///    just succeeded** until the answer becomes `NO_MEDIUM` — a value the block
///    contract has carried since it was written and nothing could ever return,
///    because nothing here was removable.
pub(crate) fn sd_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
        return Err(600);
    };

    // **Whether there is a card, read here rather than inferred from what the
    // driver reports.** The two boots this check runs under differ in exactly
    // one thing — a card in the slot or not — and a check that learned which
    // from the driver would be asking the thing under test.
    //
    // SAFETY: the PCI memory windows are mapped in the kernel's low half by
    // `map_pci_windows`, and the present-state register is a defined 32-bit
    // register inside this function's BAR.
    let card_present = unsafe {
        ((bar_base + tessera_sdhci::reg::PRESENT_STATE as u64) as *const u32).read_volatile()
            & (1 << 16)
            != 0
    };

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(601u32)?;
        exec.device_register_identified(
            SD_DEVICE_OBJ,
            bar_base,
            bar_len,
            // DERIVE, because this controller's children are devices and its
            // driver is what puts them in the graph. The manager narrows what
            // it hands on; this is what boot gives the manager to spend.
            Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
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
        .map_err(|_| 602u32)?;
        // **A bus that forwards nothing and has no configuration window for its
        // children.** That is what makes a card declarable at all: the kernel
        // records the controller as a bus whose children own no memory, and a
        // declaration naming a register window is refused.
        exec.device_set_bus_window(SD_DEVICE_OBJ, kcore::devmgr::BusWindow::default())
            .map_err(|_| 603u32)?;

        let manager = exec.channel_create().map_err(|_| 604u32)?;
        exec.bind_endpoint_object(manager.0, SD_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, SD_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 605u32)?;
        exec.bind_endpoint_object(service.0, SD_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, SD_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        SD_MANAGER_KSTACK_VA,
        1,
        SD_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        610,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::sd_host(),
        SD_DRIVER_KSTACK_VA,
        0,
        SD_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        620,
    )?;
    // **The same client program either way**, and its argument is the only
    // difference: with a card it reads and runs the conformance suite, and
    // without one it asks for the same sector and requires the answer to be
    // `NO_MEDIUM`. One program, one contract, two machines.
    let (client_idx, client_proc) = ring3_host_spawn(
        components::blk_client(),
        SD_CLIENT_A_KSTACK_VA,
        if card_present {
            1
        } else {
            BLK_CLIENT_MEDIUM_GONE
        },
        SD_CLIENT_A_PROC_OBJ,
        &mut kernel_space,
        frames,
        630,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(611u32)?;
            manager
                .handles_mut()
                .install(SD_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 611u32)?;
            manager
                .handles_mut()
                .install(
                    SD_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
                )
                .map_err(|_| 611u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(621u32)?;
            driver
                .handles_mut()
                .install(SD_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 621u32)?;
            driver
                .handles_mut()
                .install(SD_SERVER_OBJ, Rights::READ)
                .map_err(|_| 621u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(631u32)?
            .handles_mut()
            .install(SD_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 631u32)?;
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
    // Cooperative throughout — calls, replies and an exit.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(640);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    let expected = if card_present {
        SD_CLIENT_EXPECTED
    } else {
        SD_GONE_EXPECTED
    };
    if report != expected {
        return Err(641);
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
        SD_CLIENT_A_KSTACK_VA,
        SD_DRIVER_KSTACK_VA,
        SD_MANAGER_KSTACK_VA,
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
    Ok(u64::from(card_present))
}

