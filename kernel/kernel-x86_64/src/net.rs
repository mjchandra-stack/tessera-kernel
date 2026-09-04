// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `net` device class on this machine, driven from ring 3.
//!
//! **The block class was proved by a driver that answered questions. This one
//! cannot be.** A frame arrives because a machine on the other side of the wire
//! sent one, and no client asked for it — so the driver speaks first, with no
//! request outstanding and nothing to reply to. That is a direction this port
//! did not have, and it is the reason the network class is worth its own check
//! rather than being the block check with a different device.
//!
//! What is different here from the other machine that runs these programs is
//! one branch and one interrupt. The controls of a virtio-pci function live in
//! structures its own vendor capabilities describe rather than in one register
//! block, so the driver is told where they are as offsets into the window it
//! was granted (D322); and the function has no wire, so boot programs an MSI-X
//! entry and the driver parks on the port the graph routed it (D326). Neither
//! is visible in the programs' behaviour, which is the point — the same
//! `net-driver` source and the same `net-client` run on both.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts"),
//! docs/drivers/02-storage-networking-usb-pcie.md

use crate::*;

/// This check's own topology, in a block of its own.
pub(crate) const NET_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x110);
pub(crate) const NET_PORT_OBJ: ObjectId = ObjectId::from_raw(0x111);
pub(crate) const NET_MANAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x112);
pub(crate) const NET_MANAGER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x113);
/// The request channel: the client asks, the driver answers.
pub(crate) const NET_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x114);
pub(crate) const NET_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x115);
/// The **event** channel, and a second channel rather than a second use of the
/// first: a pushed event and a reply share a queue, so a client's call would
/// happily dequeue an event as its answer. Two channels make that impossible
/// rather than merely unlikely.
pub(crate) const NET_EVENT_DRIVER_OBJ: ObjectId = ObjectId::from_raw(0x116);
pub(crate) const NET_EVENT_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x117);
pub(crate) const NET_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x118);
pub(crate) const NET_DRIVER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x119);
pub(crate) const NET_CLIENT_PROC_OBJ: ObjectId = ObjectId::from_raw(0x11a);

/// PCI class 0x02: a network controller.
pub(crate) const PCI_CLASS_NETWORK: u32 = 0x02;

/// What `net-client` reports when every leg of its run held, and every bit of
/// it is load-bearing.
///
/// Low 48 bits: the gateway's MAC as the ARP resolved it (`52:55:0a:00:02:02`,
/// which is what QEMU's user-mode backend answers with), and only a completed
/// round trip produces it. Then, in order: the frame arrived **in a memory
/// object** rather than copied inline; both link transitions were announced; a
/// transmit while the link was down answered `LINK_DOWN`; the class conformance
/// suite came back *complete* — every rule reached and held, not merely nothing
/// failed — and a DHCP server answered a datagram the client built out of three
/// headers of its own and handed over in a buffer. The top byte tags the
/// reporter.
///
/// Stated here as well as in the program, because a single shared definition
/// would make agreement automatic rather than checked. It is the same value the
/// other port expects, which is what says the two machines run the same check.
pub(crate) const NET_CLIENT_EXPECTED: u64 = 0x4e7f_0202_000a_5552;

/// What the network check produced.
pub(crate) struct NetOutcome {
    /// The window the driver was granted, and how many vendor capabilities the
    /// kernel's walk decoded on the way to it.
    pub(crate) bar_base: u64,
    pub(crate) capabilities: u32,
    /// The client's report, which is the whole verdict in one word.
    pub(crate) report: u64,
    /// Messages the NIC raised, counted at the vector.
    pub(crate) msi: u64,
    /// Interrupt routes the kernel ended when the driver went away — one, and
    /// the supervisor named neither a vector nor a port to end it.
    pub(crate) routes_ended: usize,
}

/// Runs the network class against this machine's NIC.
///
/// `Ok(None)` when there is no network function, which is every boot that does
/// not attach one: a skip said out loud rather than a pass nobody earned.
pub(crate) fn net_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<NetOutcome>, u32> {
    use kcore::rights::Rights;

    if components::net_driver().is_empty()
        || components::net_client().is_empty()
        || components::device_manager().is_empty()
    {
        return Ok(None);
    }
    if !pci_window_is_clear(memory_map) {
        return Err(1);
    }
    let host = tessera_pci::Host {
        ecam_base: 0,
        ecam_len: 0x1000_0000,
        first_bus: 0,
        last_bus: 0,
    };
    let mut config = PortConfigSpace;
    let window = tessera_pci::Window {
        cpu_base: PCI_WINDOW_BASE,
        bus_base: PCI_WINDOW_BASE,
        len: PCI_WINDOW_LEN,
        is_32bit: true,
    };
    let mut functions = [PCI_BLANK_FUNCTION; MAX_PCI_FUNCTIONS];
    let found =
        tessera_pci::enumerate(&host, &mut config, window, &mut functions).map_err(|_| 2u32)?;
    // A **virtio** network function. The class alone would find any NIC, and
    // this driver speaks one transport.
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.class_code >> 16 == PCI_CLASS_NETWORK && f.vendor == VIRTIO_VENDOR)
    else {
        return Ok(None);
    };
    let Some(regions) = virtio_pci_regions(&host, &config, function) else {
        return Ok(None);
    };
    let bdf = (u32::from(function.bdf.bus) << 8)
        | (u32::from(function.bdf.device) << 3)
        | u32::from(function.bdf.function);

    // SAFETY: the boot CPU alone; a fresh table and executive for this check,
    // and the previous check's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    exec_ref()
        .device_register_identified(
            NET_DEVICE_OBJ,
            regions.bar_base,
            regions.bar_len,
            Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
            kcore::devmgr::DeviceIdentity {
                class_code: function.class_code,
                vendor: function.vendor,
                device: function.device,
                bdf: bdf as u16,
                revision: function.revision,
                bus: kcore::devmgr::DeviceBus::Pci,
            },
        )
        .map_err(|_| 3u32)?;
    exec_ref()
        .device_set_layout(NET_DEVICE_OBJ, regions.layout)
        .map_err(|_| 4u32)?;

    // **A receive path that is not interrupt-driven is not this class.** The
    // frame that wakes the driver arrives because somebody else sent it, so a
    // check that fell back to polling would leave the unsolicited send — the
    // one thing this class is here to prove — untested.
    let vector = crate::msi::arm_msix(&host, &mut config, function, kernel_vm, frames)?;
    exec_ref()
        .device_set_mmio_irq(NET_DEVICE_OBJ, vector)
        .map_err(|_| 5u32)?;

    // **One port carries both**, and that is what makes the push unsolicited
    // rather than merely asynchronous. The driver's single `PortWait` is a
    // select over "the NIC has a frame" and "the client asked for something":
    // when it sends, it is not sitting in anybody's call. Two ports would have
    // let it wait for the client and answer.
    let port = exec_ref().port_create().map_err(|_| 6u32)?;
    exec_ref().bind_port_object(port, NET_PORT_OBJ);
    exec_ref()
        .device_route_irq(NET_DEVICE_OBJ, port, NET_DRIVER_PROC_OBJ)
        .map_err(|_| 7u32)?;

    for (server, client, base) in [
        (NET_MANAGER_SERVER_OBJ, NET_MANAGER_CLIENT_OBJ, 8u32),
        (NET_SERVER_OBJ, NET_CLIENT_OBJ, 9),
        (NET_EVENT_DRIVER_OBJ, NET_EVENT_CLIENT_OBJ, 10),
    ] {
        let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| base)?;
        exec_ref().bind_endpoint_object(server_ep, server);
        exec_ref().bind_endpoint_object(client_ep, client);
    }
    exec_ref()
        .port_bind(
            port,
            u64::from(NET_SERVER_OBJ.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 11u32)?;

    // Where the kstack windows this check draws begin, so they go back with the
    // processes that hold them.
    let kstacks = kstack_mark();

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(bind_observer);
    tessera_karch_x86_64::set_device_irq_hook(crate::msi::msi_bridge_hook);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    crate::msi::forget_deliveries();
    // `frames` outlives the run; the loan is withdrawn before return.
    crate::syscalls::publish_frames(frames);

    // Server first, in both hops: the manager must be parked on `recv` before
    // the driver's bind call, and the driver on its port before the client's.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        1,
        NET_MANAGER_PROC_OBJ,
        kernel_vm,
        frames,
        20,
    )?;
    // SAFETY: the boot CPU alone; the process table is quiescent between spawns.
    unsafe {
        let manager = (&mut *&raw mut PROCESSES)
            .get_mut(manager_proc)
            .ok_or(30u32)?;
        manager
            .handles_mut()
            .install(NET_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 31u32)?;
        manager
            .handles_mut()
            .install(
                NET_DEVICE_OBJ,
                Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 32u32)?;
    }

    let (driver_thread, driver_proc) = spawn_elf_process(
        components::net_driver(),
        0,
        NET_DRIVER_PROC_OBJ,
        kernel_vm,
        frames,
        40,
    )?;
    // SAFETY: as above.
    unsafe {
        let driver = (&mut *&raw mut PROCESSES)
            .get_mut(driver_proc)
            .ok_or(50u32)?;
        driver
            .handles_mut()
            .install(NET_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 51u32)?;
        driver
            .handles_mut()
            .install(NET_PORT_OBJ, Rights::READ)
            .map_err(|_| 52u32)?;
        driver
            .handles_mut()
            .install(NET_SERVER_OBJ, Rights::READ)
            .map_err(|_| 53u32)?;
        // WRITE, because sending is putting a message in somebody else's
        // queue. The driver can never read this channel, which is the same
        // asymmetry that stops a client answering its own events.
        driver
            .handles_mut()
            .install(NET_EVENT_DRIVER_OBJ, Rights::WRITE)
            .map_err(|_| 54u32)?;
    }

    let (client_thread, client_proc) = spawn_elf_process(
        components::net_client(),
        0,
        NET_CLIENT_PROC_OBJ,
        kernel_vm,
        frames,
        60,
    )?;
    // SAFETY: as above.
    unsafe {
        let client = (&mut *&raw mut PROCESSES)
            .get_mut(client_proc)
            .ok_or(70u32)?;
        client
            .handles_mut()
            .install(NET_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 71u32)?;
        client
            .handles_mut()
            .install(NET_EVENT_CLIENT_OBJ, Rights::READ)
            .map_err(|_| 72u32)?;
    }

    // **Ring 3 with interrupts unmasked, and boot without them**, and the pump
    // matters more here than it did for the block class: the frame that wakes
    // the driver arrives long after every thread has parked, and the boot
    // context is the only thing left to take the interrupt.
    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    let truncated = crate::msi::pump_the_run("net", crate::msi::PUMP_BUDGET, || {
        BIND_REPORT_COUNT.load(Ordering::SeqCst) >= 1
    });
    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    // The driver's interrupt route ends with the driver, and the kernel is what
    // ends it — the supervisor names no vector and no port; the graph does.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let routes_ended = unsafe {
        let mut router = PicRouter;
        match (&mut *&raw mut PROCESSES).get_mut(driver_proc) {
            Some(driver) => exec_ref().end_device_irq_routes(driver, Some(&mut router)),
            None => 0,
        }
    };

    let outcome = if truncated {
        Err(80)
    } else {
        judge_net(&regions, routes_ended)
    };

    // **Before the frames go back**, for the reason the block check's teardown
    // gives: the device is still in `DRIVER_OK` with the addresses of pages
    // this teardown is about to return.
    reset_device(kernel_vm, frames, &regions);

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [client_thread, driver_thread, manager_thread] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in [client_proc, driver_proc, manager_proc] {
            if let Some(mut gone) = processes.remove(process) {
                exec_ref().release_memory_of(gone.id(), frames, None);
                gone.space_mut().teardown(frames);
            }
        }
    }
    // And the windows those processes held, back to the allocator along with
    // the records they occupied in the shared kernel space.
    kstack_release(kernel_vm, kstacks, BIND_KSTACK_PAGES);
    outcome.map(Some)
}

/// Reads what the run left and says what it establishes.
///
/// Split out because the teardown above must happen whatever the verdict is: a
/// check that returned early would leave three processes and their address
/// spaces behind, and the next check's frame accounting would be what noticed.
fn judge_net(regions: &VirtioRegions, routes_ended: usize) -> Result<NetOutcome, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(81);
    }
    // One: the client's. The driver and the manager are still parked — nothing
    // wakes a server blocked in `recv` when its client exits — which is the
    // shape of a resident service rather than an omission.
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(82);
    }
    let report = BIND_REPORTS[0].load(Ordering::SeqCst);
    if report != NET_CLIENT_EXPECTED {
        return Err(83);
    }
    // **And it was woken by the wire rather than watching for it.** A frame
    // arrives because somebody else sent one; the message the NIC wrote is what
    // the driver was parked on, and a run that took the same frames with no
    // message did not do the same thing.
    let msi = crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst);
    if msi == 0 {
        return Err(84);
    }
    // One route, ended by the graph rather than by anybody naming a vector.
    if routes_ended != 1 {
        return Err(85);
    }
    Ok(NetOutcome {
        bar_base: regions.bar_base,
        capabilities: regions.capabilities,
        report,
        msi,
        routes_ended,
    })
}
