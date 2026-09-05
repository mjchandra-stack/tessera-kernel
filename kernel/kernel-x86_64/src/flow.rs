// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **flow service** on this machine: a program reaches the network by
//! asking, and what it holds is a channel.
//!
//! `docs/roadmap/03` Phase 3 is called "The Network Is A Service". This is the
//! check that makes that sentence mean something here: four processes, and the
//! one that completes a DHCP exchange holds no device capability, no DMA, no
//! NIC and no Ethernet constant. Each knows strictly less than the one below
//! it — `flow-client` knows DHCP and the flow contract; `net-stack` knows
//! Ethernet, IPv4 and UDP and not what they carry; `net-driver` knows virtio
//! and not what a datagram is; the manager knows only that something asked for
//! the network class.
//!
//! **Separate from `net_check`, deliberately.** That check owns the driver's
//! client endpoint, and a driver serves one. Extending it would have meant
//! proxying the class-conformance legs through the stack instance, which
//! changes what `net-class.conformance-complete` asserts in order to test
//! something else. Two checks, two process sets, one NIC used twice.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it.
//!
//! Normative: docs/network/01-network-stack.md ("Flow API And Port Authority")

use crate::*;

/// This check's own topology, in a block of its own.
pub(crate) const FLOW_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x120);
pub(crate) const FLOW_PORT_OBJ: ObjectId = ObjectId::from_raw(0x121);
pub(crate) const FLOW_MANAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x122);
pub(crate) const FLOW_MANAGER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x123);
/// Driver requests: the stack instance calls, the driver serves.
pub(crate) const FLOW_DRIVER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x124);
pub(crate) const FLOW_DRIVER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x125);
/// Driver events: frames the driver pushes with nothing outstanding.
pub(crate) const FLOW_EVENT_DRIVER_OBJ: ObjectId = ObjectId::from_raw(0x126);
pub(crate) const FLOW_EVENT_STACK_OBJ: ObjectId = ObjectId::from_raw(0x127);
/// The flow channel, and it is the client's whole authority.
pub(crate) const FLOW_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x128);
pub(crate) const FLOW_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x129);
pub(crate) const FLOW_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x12a);
pub(crate) const FLOW_DRIVER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x12b);
pub(crate) const FLOW_STACK_PROC_OBJ: ObjectId = ObjectId::from_raw(0x12c);
pub(crate) const FLOW_CLIENT_PROC_OBJ: ObjectId = ObjectId::from_raw(0x12d);

/// What the two reporting programs must leave between them, and every bit of it
/// is a leg of the run: a DHCP OFFER read out of what the stack returned, a
/// `Bind` carrying an unresolvable port capability refused, a TCP peer
/// connected to and echoed from, and the shared transmit and receive regions
/// used rather than an object per frame.
///
/// Stated here as well as in the programs, and it is the same word the other
/// port expects — which is what says the two machines run the same check.
pub(crate) const FLOW_CLIENT_EXPECTED: u64 = 0x5e00_0000_0fff_bfff;

/// Every value the two speaking programs reported, folded together.
///
/// **A sink that composes by XOR rather than a list that counts**, and the
/// difference is what these programs are: each leg sets its own bit as it
/// passes, so a run reports a dozen times and the word only means anything
/// assembled. The block and network checks count reports instead, because each
/// of their programs speaks once at the end with everything it has to say.
///
/// XOR and not OR, which is what the other port's sink does and is load-bearing
/// rather than incidental: the two programs own disjoint ranges of the word, so
/// a bit one of them claims inside the other's range **cancels** and the run
/// reports neither claim. An OR would hide that, which is the whole reason a
/// range was given to each.
pub(crate) static FLOW_SINK: AtomicU64 = AtomicU64::new(0);

/// Folds a report into the sink, and leaves everything else to the shared
/// observer.
fn flow_observer(phase: crate::syscalls::Phase, number: SyscallNumber, frame: &SyscallFrame) {
    bind_observer(phase, number, frame);
    if matches!(phase, crate::syscalls::Phase::Entered)
        && number == SyscallNumber::DebugWrite
        && frame.arg1 == 0
    {
        FLOW_SINK.fetch_xor(frame.arg0, Ordering::SeqCst);
    }
}

/// What the flow check produced.
pub(crate) struct FlowOutcome {
    /// The composed report of the two programs that speak.
    pub(crate) report: u64,
    /// Messages the NIC raised while the datagrams were in flight.
    pub(crate) msi: u64,
    /// Device-visible addresses issued out of this device's aperture — zero on
    /// a machine with no remapping unit (D341).
    pub(crate) scoped_bytes: u64,
}

/// Runs a stack instance and a client that holds one channel.
///
/// `Ok(None)` when there is no NIC or no stack in the image.
pub(crate) fn flow_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    mut unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<FlowOutcome>, u32> {
    use kcore::rights::Rights;

    if components::net_driver().is_empty()
        || components::net_stack().is_empty()
        || components::flow_client().is_empty()
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

    // SAFETY: the boot CPU alone; a fresh table and executive for this check.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    exec_ref()
        .device_register_identified(
            FLOW_DEVICE_OBJ,
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
        .device_set_layout(FLOW_DEVICE_OBJ, regions.layout)
        .map_err(|_| 4u32)?;

    // **And behind an address space of its own, when this machine has a unit**
    // (D341). The same NIC the class check drove, named by a different object
    // because this is a different executive — the unit re-keys the tables it
    // already built for that function rather than making a second set. Without
    // this the stack would program physical addresses into a device whose
    // transactions are being translated, and every one of them would be
    // refused.
    let scoped = unit.is_some();
    if let Some(unit) = unit.as_deref_mut() {
        unit.scope(FLOW_DEVICE_OBJ, function, frames)
            .map_err(|which| 200 + which)?;
    }

    // The receive path is interrupt-driven here exactly as it is for the class
    // check: the frame that answers the DISCOVER arrives long after every
    // thread has parked.
    let vector = crate::msi::arm_msix(&host, &mut config, function, kernel_vm, frames, unit)?;
    exec_ref()
        .device_set_mmio_irq(FLOW_DEVICE_OBJ, vector)
        .map_err(|_| 5u32)?;
    let port = exec_ref().port_create().map_err(|_| 6u32)?;
    exec_ref().bind_port_object(port, FLOW_PORT_OBJ);
    exec_ref()
        .device_route_irq(FLOW_DEVICE_OBJ, port, FLOW_DRIVER_PROC_OBJ)
        .map_err(|_| 7u32)?;

    for (server, client, base) in [
        (FLOW_MANAGER_SERVER_OBJ, FLOW_MANAGER_CLIENT_OBJ, 8u32),
        (FLOW_DRIVER_SERVER_OBJ, FLOW_DRIVER_CLIENT_OBJ, 9),
        (FLOW_EVENT_DRIVER_OBJ, FLOW_EVENT_STACK_OBJ, 10),
        (FLOW_SERVER_OBJ, FLOW_CLIENT_OBJ, 11),
    ] {
        let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| base)?;
        exec_ref().bind_endpoint_object(server_ep, server);
        exec_ref().bind_endpoint_object(client_ep, client);
    }
    exec_ref()
        .port_bind(
            port,
            u64::from(FLOW_DRIVER_SERVER_OBJ.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 12u32)?;

    // Where the kstack windows this check draws begin, so they go back with the
    // processes that hold them.
    let kstacks = kstack_mark();

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(flow_observer);
    tessera_karch_x86_64::set_device_irq_hook(crate::msi::msi_bridge_hook);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    crate::msi::forget_deliveries();
    FLOW_SINK.store(0, Ordering::SeqCst);
    crate::syscalls::publish_frames(frames);

    // Servers before their clients, all the way down the chain: the manager
    // before the driver binds, the driver before the stack instance describes
    // it, and the stack instance before the client calls.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        1,
        FLOW_MANAGER_PROC_OBJ,
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
            .install(FLOW_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 31u32)?;
        manager
            .handles_mut()
            .install(
                FLOW_DEVICE_OBJ,
                Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 32u32)?;
    }

    let (driver_thread, driver_proc) = spawn_elf_process(
        components::net_driver(),
        0,
        FLOW_DRIVER_PROC_OBJ,
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
            .install(FLOW_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 51u32)?;
        driver
            .handles_mut()
            .install(FLOW_PORT_OBJ, Rights::READ)
            .map_err(|_| 52u32)?;
        driver
            .handles_mut()
            .install(FLOW_DRIVER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 53u32)?;
        driver
            .handles_mut()
            .install(FLOW_EVENT_DRIVER_OBJ, Rights::WRITE)
            .map_err(|_| 54u32)?;
    }

    let (stack_thread, stack_proc) = spawn_elf_process(
        components::net_stack(),
        0,
        FLOW_STACK_PROC_OBJ,
        kernel_vm,
        frames,
        60,
    )?;
    // **The stack instance's authority, and it is all channels.** It serves one
    // and calls on two. No device, no DMA, no port — a stack instance is a
    // component between two others, not a privileged one.
    // SAFETY: as above.
    unsafe {
        let stack = (&mut *&raw mut PROCESSES)
            .get_mut(stack_proc)
            .ok_or(70u32)?;
        stack
            .handles_mut()
            .install(FLOW_SERVER_OBJ, Rights::READ)
            .map_err(|_| 71u32)?;
        stack
            .handles_mut()
            .install(FLOW_DRIVER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 72u32)?;
        stack
            .handles_mut()
            .install(FLOW_EVENT_STACK_OBJ, Rights::READ)
            .map_err(|_| 73u32)?;
    }

    let (client_thread, client_proc) = spawn_elf_process(
        components::flow_client(),
        0,
        FLOW_CLIENT_PROC_OBJ,
        kernel_vm,
        frames,
        80,
    )?;
    // **One handle, and this is the claim.** Everything the client can reach on
    // the network, it reaches by asking through this.
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(client_proc)
            .ok_or(90u32)?
            .handles_mut()
            .install(FLOW_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 91u32)?;
    }

    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    // **Both programs report**, into disjoint bytes of the one sink, so the run
    // is finished when their composition is the expected word rather than when
    // either of them alone has spoken.
    let truncated = crate::msi::pump_for("flow", crate::msi::PUMP_BUDGET_WAITING_MS, || {
        FLOW_SINK.load(Ordering::SeqCst) == FLOW_CLIENT_EXPECTED
    });
    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    // What the aperture issued, read before the teardown gives it back (D341).
    let scoped_bytes = exec_ref()
        .aperture_of_object(FLOW_DEVICE_OBJ)
        .map_or(0, |aperture| aperture.next - aperture.base);
    let outcome = if truncated {
        Err(100)
    } else {
        judge_flow().and_then(|mut outcome| {
            if scoped && scoped_bytes == 0 {
                return Err(101);
            }
            outcome.scoped_bytes = scoped_bytes;
            Ok(outcome)
        })
    };

    reset_device(kernel_vm, frames, &regions);

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [client_thread, stack_thread, driver_thread, manager_thread] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in [client_proc, stack_proc, driver_proc, manager_proc] {
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
fn judge_flow() -> Result<FlowOutcome, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(101);
    }
    let report = FLOW_SINK.load(Ordering::SeqCst);
    if report != FLOW_CLIENT_EXPECTED {
        return Err(103);
    }
    let msi = crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst);
    if msi == 0 {
        return Err(104);
    }
    Ok(FlowOutcome {
        report,
        msi,
        // Filled in by the caller, which reads the aperture after the run.
        scoped_bytes: 0,
    })
}
