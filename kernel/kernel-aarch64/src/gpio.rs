// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `gpio` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves **an interrupt object for something no interrupt controller can
/// see**.
///
/// A PL061 has eight lines and one interrupt output. A ring-3 driver binds it
/// — a platform device, on neither PCI nor virtio-mmio, that said what it was
/// through its own PrimeCell registers because there is nowhere else to look —
/// and hands each watching client a capability to *its* line. Two clients watch
/// two lines and park.
///
/// Then a button is pressed from outside the machine, over QMP, and exactly one
/// of them wakes. The one that does not is what makes the demultiplex real: a
/// mechanism that broadcast, or a driver that read the raw status instead of
/// the masked one, would wake both and neither client could tell.
pub(crate) fn gpio_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    dtb: u64,
    dtb_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(801u32)?;
        // **The bus, and its configuration space is the device tree.** Boot
        // grants the blob as the bus capability's window — the same
        // relationship a PCI host bridge has to ECAM — and nothing else about
        // the machine. What is in the tree is the controller's to find.
        exec.device_register_identified(
            PLATFORM_BUS_OBJ,
            dtb,
            dtb_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
            kcore::devmgr::DeviceIdentity {
                // A bridge, which is what a bus is to anything looking at it.
                class_code: 0x06_0000,
                vendor: 0,
                device: 0,
                bdf: 0,
                revision: 0,
                // **And the kind everything behind it inherits.** A device
                // declared here is on the platform bus, which is a binding
                // input in its own right: a driver written for one transport
                // cannot drive a device on another, and the graph saying "PCI"
                // about a device tree node would offer it to the wrong ones.
                bus: kcore::devmgr::DeviceBus::Platform,
            },
        )
        .map_err(|_| 802u32)?;
        exec.device_set_bus_window(
            PLATFORM_BUS_OBJ,
            kcore::devmgr::BusWindow {
                // How much of the blob the controller may read, which is what
                // it is told its own window is.
                config_len: dtb_len,
                forward_cpu_base: PLATFORM_FORWARD_BASE,
                forward_bus_base: PLATFORM_FORWARD_BASE,
                forward_len: PLATFORM_FORWARD_LEN,
                first_bus: 0,
                last_bus: 0,
                // **The wires it may hand out.** A range on the capability, so
                // a controller that declared a device on a line outside it is
                // refused rather than trusted.
                first_intid: PLATFORM_FIRST_INTID,
                intid_count: PLATFORM_INTID_COUNT,
            },
        )
        .map_err(|_| 803u32)?;

        let manager = exec.channel_create().map_err(|_| 804u32)?;
        exec.bind_endpoint_object(manager.0, GPIO_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, GPIO_MANAGER_CLIENT_OBJ);
        let manager2 = exec.channel_create().map_err(|_| 804u32)?;
        exec.bind_endpoint_object(manager2.0, GPIO_MANAGER_SERVER2_OBJ);
        exec.bind_endpoint_object(manager2.1, GPIO_MANAGER_CLIENT2_OBJ);
        let service_a = exec.channel_create().map_err(|_| 805u32)?;
        exec.bind_endpoint_object(service_a.0, GPIO_SERVICE_A_SERVER_OBJ);
        exec.bind_endpoint_object(service_a.1, GPIO_SERVICE_A_CLIENT_OBJ);
        let service_b = exec.channel_create().map_err(|_| 806u32)?;
        exec.bind_endpoint_object(service_b.0, GPIO_SERVICE_B_SERVER_OBJ);
        exec.bind_endpoint_object(service_b.1, GPIO_SERVICE_B_CLIENT_OBJ);

        // The driver's own hardware interrupt.
        let irq_port = exec.port_create().map_err(|_| 807u32)?;
        exec.bind_port_object(irq_port, GPIO_IRQ_PORT_OBJ);

        // **One port per line, bound to that line as its source.** The binding
        // is what a `PortSignal` holder may raise, so what the driver can wake
        // was decided here and not by the number it passes.
        for line in 0..u32::from(tessera_pl061::LINES) {
            let port = exec.port_create().map_err(|_| 808u32)?;
            exec.bind_port_object(
                port,
                kcore::object::ObjectId::from_raw(GPIO_LINE_PORT_BASE + line),
            );
            exec.port_bind(port, u64::from(line), kcore::exec::SOFTWARE_PORT_SIGNAL)
                .map_err(|_| 809u32)?;
        }
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        GPIO_MANAGER_KSTACK_VA,
        // **No devices granted at all.** Everything this manager holds arrives
        // as an offer from the bus controller, which is what "enumeration
        // happens outside the kernel" means when it is finished rather than
        // half done. Two service endpoints, one per caller.
        1 << 56,
        GPIO_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        810,
    )?;
    let (bus_idx, bus_proc) = ring3_host_spawn(
        components::platform_bus(),
        PLATFORM_BUS_KSTACK_VA,
        0,
        PLATFORM_BUS_PROC_OBJ,
        &mut kernel_space,
        frames,
        860,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::gpio_driver(),
        GPIO_DRIVER_KSTACK_VA,
        0,
        GPIO_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        820,
    )?;
    let (client_a_idx, client_a_proc) = ring3_host_spawn(
        components::gpio_client(),
        GPIO_CLIENT_A_KSTACK_VA,
        GPIO_BUTTON_LINE as usize,
        GPIO_CLIENT_A_PROC_OBJ,
        &mut kernel_space,
        frames,
        830,
    )?;
    let (client_b_idx, client_b_proc) = ring3_host_spawn(
        components::gpio_client(),
        GPIO_CLIENT_B_KSTACK_VA,
        GPIO_QUIET_LINE as usize,
        GPIO_CLIENT_B_PROC_OBJ,
        &mut kernel_space,
        frames,
        840,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(811u32)?;
            manager
                .handles_mut()
                .install(GPIO_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 811u32)?;
            manager
                .handles_mut()
                .install(GPIO_MANAGER_SERVER2_OBJ, Rights::READ)
                .map_err(|_| 811u32)?;
        }
        {
            let bus = processes.get_mut(bus_proc).ok_or(861u32)?;
            bus.handles_mut()
                .install(GPIO_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 861u32)?;
            bus.handles_mut()
                .install(
                    PLATFORM_BUS_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
                )
                .map_err(|_| 861u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(821u32)?;
            driver
                .handles_mut()
                .install(GPIO_MANAGER_CLIENT2_OBJ, Rights::WRITE)
                .map_err(|_| 821u32)?;
            driver
                .handles_mut()
                .install(GPIO_SERVICE_A_SERVER_OBJ, Rights::READ)
                .map_err(|_| 821u32)?;
            driver
                .handles_mut()
                .install(GPIO_SERVICE_B_SERVER_OBJ, Rights::READ)
                .map_err(|_| 821u32)?;
            driver
                .handles_mut()
                .install(GPIO_IRQ_PORT_OBJ, Rights::READ)
                .map_err(|_| 821u32)?;
            // **Two handles to each line's port.** One carries `SIGNAL` and
            // stays; the other carries `READ` and `TRANSFER` and is what the
            // driver hands to the client that watches the line. A transfer
            // moves a handle out of the sender's table, so a driver holding one
            // would give away the capability it needs in order to signal.
            for line in 0..u32::from(tessera_pl061::LINES) {
                let object = kcore::object::ObjectId::from_raw(GPIO_LINE_PORT_BASE + line);
                driver
                    .handles_mut()
                    .install(object, Rights::SIGNAL)
                    .map_err(|_| 822u32)?;
            }
            for line in 0..u32::from(tessera_pl061::LINES) {
                let object = kcore::object::ObjectId::from_raw(GPIO_LINE_PORT_BASE + line);
                driver
                    .handles_mut()
                    .install(object, Rights::READ | Rights::TRANSFER)
                    .map_err(|_| 823u32)?;
            }
        }
        processes
            .get_mut(client_a_proc)
            .ok_or(831u32)?
            .handles_mut()
            .install(GPIO_SERVICE_A_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 831u32)?;
        processes
            .get_mut(client_b_proc)
            .ok_or(841u32)?
            .handles_mut()
            .install(GPIO_SERVICE_B_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 841u32)?;
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

    // **Enumeration first, and then the route.** The bus controller walks the
    // tree, declares what it found and offers it to the manager, and every
    // program below waits on something that does not exist until it has. So it
    // runs to completion before anything else does — which it can, because
    // `run` returns when nothing is runnable and the manager parks between
    // requests.
    // SAFETY: transient raw access; `run` returns when no thread is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }

    // What the walk did with the machine it read, checked before the counters
    // are reused for the second act. Two devices declared — the GPIO
    // controller and the real-time clock — one withheld, and the transports a
    // megabyte above what this bus forwards counted as beyond its reach rather
    // than dropped in silence.
    let walked = EL0_REPORTS[0].load(Ordering::SeqCst);
    if walked >> 56 != 0x70 {
        return Err(827);
    }
    if (walked >> 32) & 0xffff != 2 {
        return Err(828);
    }
    if (walked >> 16) & 0xffff != 1 {
        return Err(829);
    }
    if walked & 0xffff == 0 {
        return Err(830);
    }
    // The second act's reports are the ones the verdict is about.
    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // **Routed from the graph, not from knowledge of the device.** This is the
    // one privileged step left, and it is worth being exact about what it
    // knows: boot asks the bus what is behind it, takes the child whose class
    // code says input, and routes whatever line the graph records for it. It
    // never learns what a PL061 is, where it lives, or which SPI it uses — a
    // driver cannot yet ask for its own route, and this is what stands in for
    // that until it can.
    // SAFETY: transient raw access to the static executive.
    let intid = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(824u32)?;
        let mut children = [kcore::object::ObjectId::from_raw(0); kcore::devmgr::MAX_DEVICES];
        let count = exec.device_children_of(PLATFORM_BUS_OBJ, &mut children);
        let mut routed = None;
        for child in &children[..count] {
            let Some(identity) = exec.identity_of_object(*child) else {
                continue;
            };
            if identity.class_code != PLATFORM_CLASS_GPIO {
                continue;
            }
            let mut lines = [0u32; 1 + kcore::devmgr::MAX_EXTRA_IRQS];
            if exec.intids_of_object(*child, &mut lines) == 0 {
                continue;
            }
            let port = exec.port_of_object(GPIO_IRQ_PORT_OBJ).ok_or(824u32)?;
            exec.device_route_irq_line(*child, lines[0], port, GPIO_DRIVER_PROC_OBJ)
                .map_err(|_| 825u32)?;
            routed = Some(lines[0]);
            break;
        }
        // Nothing behind the bus interrupts the way a GPIO controller does, so
        // there is nothing to prove and no line to enable.
        routed.ok_or(826u32)?
    };

    RING3_DRIVER_INTID.store(intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(intid) };
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);

    // The second run takes every thread to where it waits: the clients on their
    // line ports, the driver on its interrupt. Then the check says it is armed
    // — the button is pressed from outside the machine, and it cannot be
    // pressed before there is something to hear it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // gpio: armed — two clients hold interrupt objects for lines
    // {GPIO_BUTTON_LINE} and {GPIO_QUIET_LINE}, waiting for a button press
    // from outside the machine
    kprintln!(
        "gpio: armed — gpio button line={GPIO_BUTTON_LINE}, gpio quiet line={GPIO_QUIET_LINE}"
    );
    kcore::verdict::claims(&["gpio.armed"]);

    // The interrupt pump (D84/D85): the press is asynchronous and lands after
    // every thread has parked, so `run()` returns with nothing runnable and the
    // wake would be orphaned. Boot is the idle loop, and it must unmask every
    // iteration — `wfi` returns from a pending-but-masked interrupt without
    // ever taking it.
    // **Bounded, because most boots have nobody to press the button.** A
    // PL061 is on every `virt` machine, so this check runs on every aarch64
    // boot — and only the one driven over QMP presses anything. Running out is
    // therefore not a failure: it is "nobody pressed", which the caller reports
    // as a skip. Long enough for a press that is coming, short enough that a
    // boot with none pays a few seconds.
    let done = || EL0_REPORT_COUNT.load(Ordering::SeqCst) > 0;
    let mut pump_budget = 400u32;
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
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(intid) };
    RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(850);
    }
    // **Exactly one report, and it is the client whose line was pressed.** The
    // other client is still parked, which is the whole claim: a mechanism that
    // broadcast, or a driver reading the raw status instead of the masked one,
    // would have woken both.
    let reports = EL0_REPORT_COUNT.load(Ordering::SeqCst);
    let first = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Nobody pressed anything, which is every boot but the one driven over QMP.
    // Reported as such rather than as a failure: what would be wrong is a press
    // that reached the wrong client, and no press reached nobody.
    let pressed = reports > 0;
    if pressed {
        if first != GPIO_A_EXPECTED {
            return Err(851);
        }
        if reports != 1 {
            return Err(852);
        }
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_b_idx);
            exec.scheduler().reap(client_a_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(bus_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        GPIO_CLIENT_B_KSTACK_VA,
        GPIO_CLIENT_A_KSTACK_VA,
        GPIO_DRIVER_KSTACK_VA,
        PLATFORM_BUS_KSTACK_VA,
        GPIO_MANAGER_KSTACK_VA,
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
        for proc_idx in [
            client_b_proc,
            client_a_proc,
            driver_proc,
            bus_proc,
            manager_proc,
        ] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(if pressed { first } else { 0 })
}

// --- USB: a relaying bus host, a deep tree, and a device that is refused (D155) ---

pub(crate) const USB_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x140);
pub(crate) const USB_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x141);
pub(crate) const USB_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x142);
/// **One service channel per driver that calls.** A channel carries one
/// outstanding call, so two drivers blocked on the same one is a reply going to
/// whichever the kernel wakes first — a driver handed another driver's device.
/// This is the first machine here with more than one driver binding at once.
pub(crate) const USB_MANAGER_SERVER2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14f);
pub(crate) const USB_MANAGER_CLIENT2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x150);
pub(crate) const USB_MANAGER_SERVER3_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x151);
pub(crate) const USB_MANAGER_CLIENT3_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x152);
pub(crate) const USB_HOST_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x143);
pub(crate) const USB_HOST_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x144);
pub(crate) const USB_BLK_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x145);
pub(crate) const USB_BLK_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x146);
pub(crate) const USB_INPUT_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x147);
pub(crate) const USB_INPUT_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x148);
pub(crate) const USB_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x149);
pub(crate) const USB_HOST_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14a);
pub(crate) const USB_STORAGE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14b);
pub(crate) const USB_HID_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14c);
pub(crate) const USB_BLK_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14d);
pub(crate) const USB_INPUT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14e);

pub(crate) const USB_MANAGER_KSTACK_VA: u64 = 0xffff_0008_a000_0000;
pub(crate) const USB_HOST_KSTACK_VA: u64 = 0xffff_0008_b000_0000;
pub(crate) const USB_STORAGE_KSTACK_VA: u64 = 0xffff_0008_c000_0000;
pub(crate) const USB_HID_KSTACK_VA: u64 = 0xffff_0008_d000_0000;
pub(crate) const USB_BLK_KSTACK_VA: u64 = 0xffff_0008_e000_0000;
pub(crate) const USB_INPUT_KSTACK_VA: u64 = 0xffff_0008_f000_0000;

/// A USB host controller on PCI: serial bus controller, subclass USB. Matched
/// on both bytes, because the base byte covers FireWire, SMBus and CAN as well.
pub(crate) const PCI_CLASS_XHCI: u32 = 0x0c03;

/// What `blk-client` reports when it read the disk and the suite came back
/// complete: the disk magic rotated by its id, as on every other transport.
pub(crate) const USB_BLK_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAV").rotate_left(8);

/// What `input-client` reports. The three bits are separable claims and are
/// checked apart: the suite came back complete, an idle keyboard answered
/// `NO_REPORT` rather than failing, and a report was read back through the
/// relay. The low byte is the HID protocol the device declared, which is a
/// keyboard.
pub(crate) const USB_INPUT_EXPECTED: u64 = (0x1d << 56) | (1 << 34) | (1 << 33) | (1 << 32) | 1;

