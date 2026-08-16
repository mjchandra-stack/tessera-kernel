// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `net` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves the **network device class, served by a ring-3 driver** — the first
/// class in the rollout, and the first thing on this system to speak without
/// being asked.
///
/// Four claims, and the first is the one the block class could never make:
///
/// 1. The driver sends the received frame with `ChannelSend` — no request
///    outstanding, nothing to reply to. It sends because the NIC interrupted
///    it; the client is parked on a channel it never called on.
/// 2. The frame travels **as a memory object the driver gives away**. It
///    created the buffer, attached it to the NIC, never mapped it, and holds no
///    handle to it afterwards — `TRANSFERRED` ownership, which the block class
///    had no use for.
/// 3. `SetPower(STANDBY)` takes the link down and says so; a transmit while it
///    is down answers `LINK_DOWN` rather than an I/O error, because the device
///    is present and configurable; `ACTIVE` brings it back and says so again.
/// 4. The same conformance suite the block class passes, against this one,
///    complete.
pub(crate) fn net_class_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    net_base: u64,
    net_intid: Option<u32>,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    // A receive path that is not interrupt-driven is not this class. A missing
    // interrupt is a fatal misconfiguration, never a silent downgrade to
    // polling — which would leave the unsolicited-send claim untested.
    let net_intid = net_intid.ok_or(420u32)?;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(421u32)?;
        exec.device_register_mmio(
            NET_CLASS_DEVICE_OBJ,
            net_base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 422u32)?;
        exec.device_set_mmio_irq(NET_CLASS_DEVICE_OBJ, net_intid)
            .map_err(|_| 423u32)?;

        // **One port carries both**, and that is what makes the push
        // unsolicited rather than merely asynchronous. The driver's single
        // `PortWait` is a select over "the NIC has a frame" and "the client
        // asked for something": when it sends, it is not sitting in anybody's
        // call. Two ports would have let it wait for the client and answer.
        let port = exec.port_create().map_err(|_| 424u32)?;
        exec.bind_port_object(port, NET_CLASS_PORT_OBJ);
        exec.device_route_irq(NET_CLASS_DEVICE_OBJ, port, NET_CLASS_DRIVER_PROC_OBJ)
            .map_err(|_| 425u32)?;

        let requests = exec.channel_create().map_err(|_| 426u32)?;
        exec.bind_endpoint_object(requests.0, NET_CLASS_SERVER_OBJ);
        exec.bind_endpoint_object(requests.1, NET_CLASS_CLIENT_OBJ);
        // **A second channel for events, and it is not an optimisation.** A
        // pushed event and a reply share one endpoint's queue, so a client's
        // `ChannelCall` would dequeue whichever came first and read an event as
        // its answer. Separate channels make that impossible rather than
        // unlikely.
        let events = exec.channel_create().map_err(|_| 427u32)?;
        exec.bind_endpoint_object(events.0, NET_CLASS_EVENT_DRIVER_OBJ);
        exec.bind_endpoint_object(events.1, NET_CLASS_EVENT_CLIENT_OBJ);
        // The bind channel. Not on the port: the driver calls the manager once
        // at startup and never hears from it again.
        let manager = exec.channel_create().map_err(|_| 428u32)?;
        exec.bind_endpoint_object(manager.0, NET_CLASS_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, NET_CLASS_MANAGER_CLIENT_OBJ);

        exec.port_bind(
            port,
            u64::from(NET_CLASS_SERVER_OBJ.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 429u32)?;
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // Server first, in both hops: the manager must be parked on `recv` before
    // the driver's bind call, and the driver on its port before the client's.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        NET_CLASS_MANAGER_KSTACK_VA,
        // One device capability, and no probe modes: this manager exists to
        // hand a NIC to whoever asks for the class.
        1,
        NET_CLASS_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        430,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::net_driver(),
        NET_CLASS_DRIVER_KSTACK_VA,
        0,
        NET_CLASS_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        440,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        components::net_client(),
        NET_CLASS_CLIENT_KSTACK_VA,
        0,
        NET_CLASS_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        450,
    )?;

    // Each process gets exactly its authority, in the install order each
    // program's bootstrap contract mirrors. The driver holds no device until it
    // asks for one by class; the client holds no device at all, ever.
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(431u32)?;
            manager
                .handles_mut()
                .install(NET_CLASS_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 431u32)?;
            manager
                .handles_mut()
                .install(
                    NET_CLASS_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 431u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(441u32)?;
            driver
                .handles_mut()
                .install(NET_CLASS_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 441u32)?;
            driver
                .handles_mut()
                .install(NET_CLASS_PORT_OBJ, Rights::READ)
                .map_err(|_| 441u32)?;
            driver
                .handles_mut()
                .install(NET_CLASS_SERVER_OBJ, Rights::READ)
                .map_err(|_| 441u32)?;
            // WRITE, because sending is putting a message in somebody else's
            // queue. The driver can never read this channel, which is the same
            // asymmetry that stops a client answering its own events.
            driver
                .handles_mut()
                .install(NET_CLASS_EVENT_DRIVER_OBJ, Rights::WRITE)
                .map_err(|_| 441u32)?;
        }
        {
            let client = processes.get_mut(client_proc).ok_or(451u32)?;
            client
                .handles_mut()
                .install(NET_CLASS_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 451u32)?;
            client
                .handles_mut()
                .install(NET_CLASS_EVENT_CLIENT_OBJ, Rights::READ)
                .map_err(|_| 451u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator to the hook for the run only.
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
    RING3_DRIVER_INTID.store(net_intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(net_intid) };
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // The interrupt pump (D84/D85), and this class needs it more than the
    // block one did: the frame that wakes the driver arrives long after every
    // thread has parked, and the boot context is the only thing left to take
    // the interrupt. Unmasked every iteration, because returning from a thread
    // switch restores the boot context with `DAIF.I` set again.
    let done = || {
        EL0_SINK_EXITED.load(Ordering::SeqCst)
            && EL0_SINK_LOG.load(Ordering::SeqCst) == NET_CLASS_EXPECTED
    };
    let mut pump_budget = 500u32;
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

    // The driver's interrupt route ends with the driver, and the kernel is what
    // ends it — the supervisor names no INTID and no port; the graph does.
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
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(net_intid) };
    RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if routes_ended != 1 {
        return Err(452);
    }
    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(453);
    }
    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    if report != NET_CLASS_EXPECTED {
        return Err(454);
    }

    // Teardown: the client Exited, the driver and manager parked. Reap, free
    // the kernel stacks, and remove the processes — which releases the receive
    // buffer the driver was holding when the run ended, along with everything
    // else it owned.
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
        NET_CLASS_CLIENT_KSTACK_VA,
        NET_CLASS_DRIVER_KSTACK_VA,
        NET_CLASS_MANAGER_KSTACK_VA,
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

// --- PCI as a bus driver: enumeration in ring 3 (D151) ----------------------

pub(crate) const PCI_BUS_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf0);
pub(crate) const PCI_BUS_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf1);
pub(crate) const PCI_BUS_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf2);
pub(crate) const PCI_BUS_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf3);
pub(crate) const PCI_BUS_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf4);
pub(crate) const PCI_BUS_PROBE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf5);

pub(crate) const PCI_BUS_MANAGER_KSTACK_VA: u64 = 0xffff_0005_a000_0000;
pub(crate) const PCI_BUS_DRIVER_KSTACK_VA: u64 = 0xffff_0005_b000_0000;
pub(crate) const PCI_BUS_PROBE_KSTACK_VA: u64 = 0xffff_0005_c000_0000;

/// How much configuration space the bus controller is granted: eight buses.
///
/// **A grant, not a limit it discovers.** The window covers whichever buses the
/// controller is handed, and a machine with more of them hands over more window
/// deliberately rather than a controller quietly reaching further. Eight is
/// what the deepest topology these boots build needs — a root port above an
/// upstream switch above a downstream port, with an endpoint under it — plus
/// room, and `MAX_BUS_WINDOW_BYTES` is the kernel's ceiling on the same number.
pub(crate) const PCI_BUS_CONFIG_LEN: u64 = 0x80_0000;

/// Buses that window covers, counting from the host bridge's first.
pub(crate) const PCI_BUS_COUNT: u8 = 8;

/// The startup argument asking `blk-probe` to report what its own configuration
/// space says it is. Must match `CONFIG_REPORT` there.
pub(crate) const BLK_PROBE_CONFIG_REPORT: usize = 1 << 59;

