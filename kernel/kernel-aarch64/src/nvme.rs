// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `nvme` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves the **block class contract over a second transport, with a vector per
/// queue** — `docs/drivers/02` ("Storage").
///
/// Three claims:
///
/// 1. An NVMe controller is brought up entirely from ring 3 and serves
///    `tessera.driver.block`. Nothing in the schema changed to accommodate it,
///    and the client that judges it is `blk-client` — the same program, byte for
///    byte, that judges the virtio driver. A class contract belongs to the class
///    and not to the transport under it, and this is what that sentence means.
/// 2. Each I/O queue's completions arrive on **its own MSI-X vector and its own
///    port**. The driver never demultiplexes: it submits on a queue and waits
///    where that queue's interrupts land.
/// 3. The block class's conformance suite comes back *complete* against it —
///    every rule reached and held, judged by the suite that judged virtio.
pub(crate) fn nvme_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    host: &tessera_devicetree::PciHost,
    v2m: &mut V2mFrame,
    function: &tessera_pci::Function,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    // The register window: the largest memory BAR, which on this controller is
    // BAR 0 — its registers and, past 0x1000, its doorbells.
    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
        return Err(500);
    };

    // **Two vectors, two SPIs, two ports.** Programming MSI-X is boot's because
    // the doorbell address is a platform fact a driver must not invent — the
    // same reason a driver is never told where its register window is in
    // physical memory.
    let capability =
        tessera_pci::find_capability(&bridge, &config, function.bdf, tessera_pci::CAP_MSIX)
            .map_err(|_| 501u32)?
            .ok_or(502u32)?;
    let table = tessera_pci::msix_table(&bridge, &config, function.bdf, capability, function)
        .map_err(|_| 503u32)?;
    if u32::from(table.entries) <= u32::from(NVME_VECTORS[1]) {
        // A controller with fewer vectors than queues cannot give each queue
        // its own, and a check that carried on would be proving something else.
        return Err(504);
    }
    let Some((msix_bar, _)) = function.bars[table.bar] else {
        return Err(505);
    };
    let mut msix = BarWindow {
        base: msix_bar + u64::from(table.offset),
    };
    let mut spis = [0u32; 2];
    for (slot, vector) in NVME_VECTORS.iter().enumerate() {
        let spi = v2m.allocate().ok_or(506u32)?;
        spis[slot] = spi;
        tessera_pci::program_msix_entry(&mut msix, usize::from(*vector), v2m.doorbell(), spi)
            .map_err(|_| 507u32)?;
    }
    tessera_pci::msix_enable(&bridge, &mut config, function.bdf, capability).map_err(|_| 508u32)?;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(510u32)?;
        // **Registered with its identity, not just its window.** A PCI
        // function says what it is in configuration space, which no capability
        // reaches, so the manager classifies it from what the graph recorded.
        // Without this it falls back to probing the device's own registers —
        // which works for a virtio transport that announces itself at offset
        // zero and finds an NVMe controller's capability register instead.
        exec.device_register_identified(
            NVME_DEVICE_OBJ,
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
        .map_err(|_| 511u32)?;
        // Both lines, and then a route each. A device with one line per queue
        // needs both recorded or the second is one nothing can re-arm — and a
        // route each is what makes the port the driver wakes on identify the
        // queue that finished.
        for spi in spis {
            exec.device_add_mmio_irq(NVME_DEVICE_OBJ, spi)
                .map_err(|_| 512u32)?;
        }
        for (slot, object) in [NVME_PORT1_OBJ, NVME_PORT2_OBJ].into_iter().enumerate() {
            let port = exec.port_create().map_err(|_| 513u32)?;
            exec.bind_port_object(port, object);
            exec.device_route_irq_line(NVME_DEVICE_OBJ, spis[slot], port, NVME_DRIVER_PROC_OBJ)
                .map_err(|_| 514u32)?;
        }
        let manager = exec.channel_create().map_err(|_| 515u32)?;
        exec.bind_endpoint_object(manager.0, NVME_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, NVME_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 516u32)?;
        exec.bind_endpoint_object(service.0, NVME_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, NVME_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        NVME_MANAGER_KSTACK_VA,
        1,
        NVME_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        520,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::nvme_driver(),
        NVME_DRIVER_KSTACK_VA,
        0,
        NVME_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        530,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        components::blk_client(),
        NVME_CLIENT_KSTACK_VA,
        1,
        NVME_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        540,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(521u32)?;
            manager
                .handles_mut()
                .install(NVME_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 521u32)?;
            manager
                .handles_mut()
                .install(
                    NVME_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 521u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(531u32)?;
            driver
                .handles_mut()
                .install(NVME_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 531u32)?;
            driver
                .handles_mut()
                .install(NVME_SERVER_OBJ, Rights::READ)
                .map_err(|_| 531u32)?;
            // A port per queue, in the order the driver's own constants name
            // them. This install order is the whole of its bootstrap contract.
            for object in [NVME_PORT1_OBJ, NVME_PORT2_OBJ] {
                driver
                    .handles_mut()
                    .install(object, Rights::READ)
                    .map_err(|_| 531u32)?;
            }
        }
        processes
            .get_mut(client_proc)
            .ok_or(541u32)?
            .handles_mut()
            .install(NVME_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 541u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

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
    RING3_DRIVER_INTID.store(spis[0], Ordering::SeqCst);
    RING3_DRIVER_INTID_ALT.store(spis[1], Ordering::SeqCst);
    for spi in spis {
        // SAFETY: enabling a GIC line is an interrupt-controller register
        // write. Edge-triggered, because a message-signalled interrupt raises
        // and drops the line in one action and a level input has nothing left
        // to latch.
        unsafe {
            tessera_karch_aarch64::set_irq_edge_triggered(spi);
            tessera_karch_aarch64::enable_irq(spi);
        }
    }
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    let done = || {
        EL0_SINK_EXITED.load(Ordering::SeqCst)
            && EL0_SINK_LOG.load(Ordering::SeqCst) == NVME_CLIENT_EXPECTED
    };
    let mut pump_budget = 2000u32;
    loop {
        // SAFETY: transient raw access; `run` returns when no thread is
        // runnable (parked threads may become Ready from interrupt context).
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if done() || pump_budget == 0 {
            break;
        }
        pump_budget -= 1;
        // SAFETY: the boot context owns the CPU here; the only handler that can
        // run is the interrupt bridge, which touches atomics and the port
        // facility, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();

    // The driver's routes end with the driver, and the kernel is what ends
    // them — both of them, which is what a device with a line per queue needs.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let routes_ended = unsafe {
        let mut router = GicRouter;
        match (
            (*(&raw mut KCORE_EXEC)).as_mut(),
            (*(&raw mut KCORE_PROCESSES)).get_mut(driver_proc),
        ) {
            (Some(exec), Some(driver)) => exec.end_device_irq_routes(driver, Some(&mut router)),
            _ => 0,
        }
    };
    for spi in spis {
        // SAFETY: disabling a GIC line is an interrupt-controller register
        // write.
        unsafe { tessera_karch_aarch64::disable_irq(spi) };
    }
    RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    RING3_DRIVER_INTID_ALT.store(0, Ordering::SeqCst);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if routes_ended != 1 {
        return Err(550);
    }
    // Neither line routes anywhere now. Checked rather than assumed, because
    // "the graph forgot" and "the graph was never told" look identical
    // afterwards — and a device with two lines is exactly where a sweep that
    // ended one and stopped would go unnoticed.
    // SAFETY: transient raw access; every thread is off-CPU.
    if unsafe { (*(&raw const KCORE_EXEC)).as_ref() }
        .and_then(|exec| exec.irq_route_of_object(NVME_DEVICE_OBJ))
        .is_some()
    {
        return Err(551);
    }
    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(552);
    }
    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    if report != NVME_CLIENT_EXPECTED {
        return Err(553);
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
        NVME_CLIENT_KSTACK_VA,
        NVME_DRIVER_KSTACK_VA,
        NVME_MANAGER_KSTACK_VA,
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

// --- Sound: a device that is never finished, and a stream deliberately
// starved (D158) ---

pub(crate) const SND_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x180);
pub(crate) const SND_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x181);
pub(crate) const SND_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x182);
pub(crate) const SND_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x183);
pub(crate) const SND_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x184);
pub(crate) const SND_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x185);
pub(crate) const SND_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x186);
pub(crate) const SND_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x187);

pub(crate) const SND_MANAGER_KSTACK_VA: u64 = 0xffff_000a_a000_0000;
pub(crate) const SND_DRIVER_KSTACK_VA: u64 = 0xffff_000a_b000_0000;
pub(crate) const SND_CLIENT_KSTACK_VA: u64 = 0xffff_000a_c000_0000;

/// A multimedia controller, subclass audio. Matched on both bytes: the base
/// byte covers video and telephony as well.
pub(crate) const PCI_CLASS_AUDIO: u32 = 0x0401;

/// What the client reports: the suite came back complete, the fed stream played
/// with no gap, and the abandoned one gapped.
pub(crate) const SND_CLIENT_EXPECTED: u64 = (0xa0 << 56) | (1 << 34) | (1 << 33) | (1 << 32);

