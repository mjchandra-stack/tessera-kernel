// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// Normative: docs/network/01-network-stack.md ("Flow API And Port Authority")

//! The **flow service**: a program reaches the network by asking, and what it
//! holds is a channel.
//!
//! `docs/roadmap/03` Phase 3 is called "The Network Is A Service". This is the
//! check that makes that sentence mean something: four processes, and the one
//! that completes a DHCP exchange holds no device capability, no DMA, no NIC
//! and no Ethernet constant.
//!
//! **Separate from `net_class_check`, deliberately.** That check owns the
//! driver's client endpoint, and a driver serves one. Extending it would have
//! meant proxying the class-conformance legs through the stack instance, which
//! changes what `net-class.conformance-complete` asserts in order to test
//! something else. Two checks, two process sets, one NIC used twice — the same
//! argument D171 made for splitting the crash-recovery check out.

// The crate root holds this machine's statics, its layout constants and its
// object ids, and every check reaches for them.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves that **a program with no device capability sends and receives a
/// datagram**, by asking a stack instance for it.
///
/// The chain is four processes deep and each knows strictly less than the one
/// below it: `flow-client` knows DHCP and the flow contract; `net-stack` knows
/// Ethernet, IPv4 and UDP and not what they carry; `net-driver` knows virtio
/// and not what a datagram is; the manager knows only that something asked for
/// the network class.
///
/// Three claims:
///
/// 1. The client binds a port, sends a DHCP DISCOVER **as a payload**, and
///    reads the OFFER out of what comes back — never naming a MAC as a frame's
///    source, an ethertype, or a checksum. The stack instance builds all three.
/// 2. QEMU's DHCP server answers, which is what makes the headers the stack
///    built correct rather than merely well-formed. Nothing in this tree judges
///    them.
/// 3. A `Bind` carrying a port capability nobody can resolve is **refused**.
///    `flow_service.isl` reserves that field against a namespace broker that
///    does not exist yet, and a reserved field only stays reserved if
///    something enforces it.
pub(crate) fn flow_service_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    net_base: u64,
    net_intid: Option<u32>,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    // The receive path is interrupt-driven here exactly as it is for the class
    // check: the frame that answers the DISCOVER arrives long after every
    // thread has parked.
    let net_intid = net_intid.ok_or(460u32)?;

    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        crate::el0::kcore_exec_restart(1);
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(461u32)?;
        exec.device_register_mmio(
            FLOW_DEVICE_OBJ,
            net_base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 462u32)?;
        exec.device_set_mmio_irq(FLOW_DEVICE_OBJ, net_intid)
            .map_err(|_| 463u32)?;

        let port = exec.port_create().map_err(|_| 464u32)?;
        exec.bind_port_object(port, FLOW_PORT_OBJ);
        exec.device_route_irq(FLOW_DEVICE_OBJ, port, FLOW_DRIVER_PROC_OBJ)
            .map_err(|_| 465u32)?;

        // Driver requests: the stack instance calls, the driver serves.
        let requests = exec.channel_create().map_err(|_| 466u32)?;
        exec.bind_endpoint_object(requests.0, FLOW_DRIVER_SERVER_OBJ);
        exec.bind_endpoint_object(requests.1, FLOW_DRIVER_CLIENT_OBJ);
        // Driver events: frames the driver pushes with nothing outstanding.
        // Separate from requests for the reason the class check gives — a
        // pushed event and a reply sharing a queue lets a call read an event
        // as its answer.
        let events = exec.channel_create().map_err(|_| 467u32)?;
        exec.bind_endpoint_object(events.0, FLOW_EVENT_DRIVER_OBJ);
        exec.bind_endpoint_object(events.1, FLOW_EVENT_STACK_OBJ);
        // The bind channel, driver to manager, once at startup.
        let manager = exec.channel_create().map_err(|_| 468u32)?;
        exec.bind_endpoint_object(manager.0, FLOW_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, FLOW_MANAGER_CLIENT_OBJ);
        // **The flow channel, and it is the client's whole authority.**
        let flow = exec.channel_create().map_err(|_| 469u32)?;
        exec.bind_endpoint_object(flow.0, FLOW_SERVER_OBJ);
        exec.bind_endpoint_object(flow.1, FLOW_CLIENT_OBJ);

        exec.port_bind(
            port,
            u64::from(FLOW_DRIVER_SERVER_OBJ.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 470u32)?;
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // Servers before their clients, all the way down the chain: the manager
    // must be parked before the driver binds, the driver before the stack
    // instance describes it, and the stack instance before the client calls.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        FLOW_MANAGER_KSTACK_VA,
        1,
        FLOW_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        471,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::net_driver(),
        FLOW_DRIVER_KSTACK_VA,
        0,
        FLOW_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        472,
    )?;
    let (stack_idx, stack_proc) = ring3_host_spawn(
        components::net_stack(),
        FLOW_STACK_KSTACK_VA,
        0,
        FLOW_STACK_PROC_OBJ,
        &mut kernel_space,
        frames,
        473,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        components::flow_client(),
        FLOW_CLIENT_KSTACK_VA,
        0,
        FLOW_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        474,
    )?;

    // Each process gets exactly its authority, in the install order each
    // program's bootstrap contract mirrors.
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(475u32)?;
            manager
                .handles_mut()
                .install(FLOW_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 475u32)?;
            manager
                .handles_mut()
                .install(
                    FLOW_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 475u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(476u32)?;
            driver
                .handles_mut()
                .install(FLOW_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 476u32)?;
            driver
                .handles_mut()
                .install(FLOW_PORT_OBJ, Rights::READ)
                .map_err(|_| 476u32)?;
            driver
                .handles_mut()
                .install(FLOW_DRIVER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 476u32)?;
            driver
                .handles_mut()
                .install(FLOW_EVENT_DRIVER_OBJ, Rights::WRITE)
                .map_err(|_| 476u32)?;
        }
        {
            // **The stack instance's authority, and it is all channels.** It
            // serves one and calls on two. No device, no DMA, no port — a
            // stack instance is a component between two others, not a
            // privileged one.
            let stack = processes.get_mut(stack_proc).ok_or(477u32)?;
            stack
                .handles_mut()
                .install(FLOW_SERVER_OBJ, Rights::READ)
                .map_err(|_| 477u32)?;
            stack
                .handles_mut()
                .install(FLOW_DRIVER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 477u32)?;
            stack
                .handles_mut()
                .install(FLOW_EVENT_STACK_OBJ, Rights::READ)
                .map_err(|_| 477u32)?;
        }
        {
            // **One handle, and this is the claim.** Everything the client can
            // reach on the network, it reaches by asking through this.
            let client = processes.get_mut(client_proc).ok_or(478u32)?;
            client
                .handles_mut()
                .install(FLOW_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 478u32)?;
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
    tessera_karch_aarch64::GenericTimer::start_periodic_this_cpu(TICK_HZ);

    // The interrupt pump. **Both programs report**, into disjoint bytes of the
    // one sink, so the run is finished when their composition is the expected
    // word rather than when either of them alone has spoken.
    let done = || {
        EL0_SINK_EXITED.load(Ordering::SeqCst)
            && EL0_SINK_LOG.load(Ordering::SeqCst) == FLOW_SERVICE_EXPECTED
    };
    let mut pump_budget = 500u32;
    loop {
        // SAFETY: transient raw access; `run` returns when no thread is
        // runnable (parked threads may become Ready from interrupt context).
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.run();
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

    // The driver's interrupt route ends with the driver.
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
    // SAFETY: the boot CPU alone; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if routes_ended != 1 {
        return Err(479);
    }
    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(480);
    }
    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    if report != FLOW_SERVICE_EXPECTED {
        return Err(481);
    }

    // Teardown: the client and the stack instance Exited, the driver and
    // manager parked.
    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(stack_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        FLOW_CLIENT_KSTACK_VA,
        FLOW_STACK_KSTACK_VA,
        FLOW_DRIVER_KSTACK_VA,
        FLOW_MANAGER_KSTACK_VA,
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
        for proc_idx in [client_proc, stack_proc, driver_proc, manager_proc] {
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
