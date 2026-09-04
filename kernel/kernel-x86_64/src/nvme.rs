// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `nvme` device class on this machine: the block contract over a second
//! transport, with a vector per queue.
//!
//! **A class contract belongs to the class and not to the transport under it,
//! and this is what that sentence means.** The controller is brought up
//! entirely from ring 3 and serves `tessera.driver.block`; the client that
//! judges it is `blk-client` — the same program, byte for byte, that judges the
//! virtio driver, run with the id that carries both the conformance suite and
//! the out-of-line round trip. Nothing in the schema changed to accommodate an
//! NVMe controller.
//!
//! **Each I/O queue's completions arrive on its own vector and its own port.**
//! The driver never demultiplexes: it submits on a queue and waits where that
//! queue's interrupts land. That arrangement is why this port's
//! message-signalled vectors became a block rather than one (D328) — with a
//! single vector it cannot be expressed at all, and a check that routed both
//! queues to one port would be proving something else.
//!
//! Split out of `main.rs` by area (build/README.md, D265).
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage")

use crate::*;

/// This check's own topology, in a block of its own.
pub(crate) const NVME_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x130);
pub(crate) const NVME_PORT1_OBJ: ObjectId = ObjectId::from_raw(0x131);
pub(crate) const NVME_PORT2_OBJ: ObjectId = ObjectId::from_raw(0x132);
pub(crate) const NVME_MANAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x133);
pub(crate) const NVME_MANAGER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x134);
pub(crate) const NVME_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x135);
pub(crate) const NVME_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x136);
pub(crate) const NVME_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x137);
pub(crate) const NVME_DRIVER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x138);
pub(crate) const NVME_CLIENT_PROC_OBJ: ObjectId = ObjectId::from_raw(0x139);

/// The PCI class of an NVM Express controller: mass storage, subclass NVM.
pub(crate) const PCI_CLASS_NVME: u32 = 0x0108;

/// The MSI-X entries the driver's two I/O queues raise, which are also their
/// queue ids. The pairing is the contract with `userspace/nvme-driver`: it
/// creates queue *n* with vector *n*, and this routes the vector programmed
/// into entry *n* to the port it holds at that index.
pub(crate) const NVME_QUEUE_ENTRIES: [u16; 2] = [1, 2];

/// What `blk-client` reports when it has read both sectors, run the class
/// conformance suite to completion, and carried a buffer through the
/// out-of-line round trip.
///
/// The client rotates the disk magic by its own id, so the id the check spawns
/// it with is what fixes this. Three, because that id runs *both* proofs, and
/// it is the same word the other port expects of the same program.
pub(crate) const NVME_CLIENT_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAV").rotate_left(8 * 3);

/// The startup id that runs both proofs.
const NVME_CLIENT_ID: usize = 3;

/// What the NVMe check produced.
pub(crate) struct NvmeOutcome {
    /// The window the driver was granted.
    pub(crate) bar_base: u64,
    /// The client's report, which is the whole verdict in one word.
    pub(crate) report: u64,
    /// Messages each queue's vector raised. Both must be non-zero: a
    /// controller that answered every completion on one vector would leave the
    /// other at zero and the driver waiting on a port nothing signals.
    pub(crate) per_vector: [u64; NVME_QUEUE_ENTRIES.len()],
}

/// Runs the block class against an NVMe controller.
///
/// `Ok(None)` when the machine has none, which is every boot that does not
/// attach one.
pub(crate) fn nvme_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<NvmeOutcome>, u32> {
    use kcore::rights::Rights;

    if components::nvme_driver().is_empty()
        || components::blk_client().is_empty()
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
    // **By class and subclass, not by vendor.** An NVMe controller is whatever
    // implements the specification, which is the difference between this and
    // the virtio functions beside it.
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.class_code >> 8 == PCI_CLASS_NVME)
    else {
        return Ok(None);
    };
    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
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
    // **Registered with its identity, not just its window.** A PCI function
    // says what it is in configuration space, which no capability reaches, so
    // the manager classifies it from what the graph recorded — without this it
    // falls back to probing the device's own registers, which finds an NVMe
    // controller's capability register where a virtio transport announces
    // itself.
    exec_ref()
        .device_register_identified(
            NVME_DEVICE_OBJ,
            bar_base,
            bar_len,
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

    // Two entries, two vectors, two ports. Both lines recorded or the second is
    // one nothing can re-arm, and a route each is what makes the port the
    // driver wakes on identify the queue that finished.
    let mut vectors = [0u32; NVME_QUEUE_ENTRIES.len()];
    crate::msi::arm_msix_entries(
        &host,
        &mut config,
        function,
        kernel_vm,
        frames,
        &NVME_QUEUE_ENTRIES,
        &mut vectors,
    )?;
    exec_ref()
        .device_set_mmio_irq(NVME_DEVICE_OBJ, vectors[0])
        .map_err(|_| 4u32)?;
    exec_ref()
        .device_add_mmio_irq(NVME_DEVICE_OBJ, vectors[1])
        .map_err(|_| 5u32)?;
    for (slot, object) in [NVME_PORT1_OBJ, NVME_PORT2_OBJ].into_iter().enumerate() {
        let port = exec_ref().port_create().map_err(|_| 6u32)?;
        exec_ref().bind_port_object(port, object);
        exec_ref()
            .device_route_irq_line(NVME_DEVICE_OBJ, vectors[slot], port, NVME_DRIVER_PROC_OBJ)
            .map_err(|_| 7u32)?;
    }

    for (server, client, base) in [
        (NVME_MANAGER_SERVER_OBJ, NVME_MANAGER_CLIENT_OBJ, 8u32),
        (NVME_SERVER_OBJ, NVME_CLIENT_OBJ, 9),
    ] {
        let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| base)?;
        exec_ref().bind_endpoint_object(server_ep, server);
        exec_ref().bind_endpoint_object(client_ep, client);
    }

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
    crate::syscalls::publish_frames(frames);

    // Server first at each hop: the manager parked before the driver binds, the
    // driver before its client calls.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        1,
        NVME_MANAGER_PROC_OBJ,
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
            .install(NVME_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 31u32)?;
        manager
            .handles_mut()
            .install(
                NVME_DEVICE_OBJ,
                Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 32u32)?;
    }

    let (driver_thread, driver_proc) = spawn_elf_process(
        components::nvme_driver(),
        0,
        NVME_DRIVER_PROC_OBJ,
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
            .install(NVME_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 51u32)?;
        driver
            .handles_mut()
            .install(NVME_SERVER_OBJ, Rights::READ)
            .map_err(|_| 52u32)?;
        // A port per queue, in the order the driver's own constants name them.
        // This install order is the whole of its bootstrap contract.
        for object in [NVME_PORT1_OBJ, NVME_PORT2_OBJ] {
            driver
                .handles_mut()
                .install(object, Rights::READ)
                .map_err(|_| 53u32)?;
        }
    }

    let (client_thread, client_proc) = spawn_elf_process(
        components::blk_client(),
        NVME_CLIENT_ID,
        NVME_CLIENT_PROC_OBJ,
        kernel_vm,
        frames,
        60,
    )?;
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(client_proc)
            .ok_or(70u32)?
            .handles_mut()
            .install(NVME_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 71u32)?;
    }

    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    let truncated = crate::msi::pump_the_run("nvme", crate::msi::PUMP_BUDGET, || {
        BIND_REPORT_COUNT.load(Ordering::SeqCst) >= 1
    });
    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    let outcome = if truncated {
        Err(80)
    } else {
        judge_nvme(bar_base)
    };

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
fn judge_nvme(bar_base: u64) -> Result<NvmeOutcome, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(81);
    }
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(82);
    }
    let report = BIND_REPORTS[0].load(Ordering::SeqCst);
    if report != NVME_CLIENT_EXPECTED {
        return Err(83);
    }
    // **A vector per queue, counted per vector.** The driver waits where a
    // queue's completions land rather than asking which queue finished, so a
    // controller answering everything on one vector leaves the other port
    // silent — and the total alone could not tell that from two queues each
    // answering once.
    let mut per_vector = [0u64; NVME_QUEUE_ENTRIES.len()];
    for (slot, count) in per_vector.iter_mut().enumerate() {
        *count = crate::msi::MSI_BY_VECTOR[slot].load(Ordering::SeqCst);
        if *count == 0 {
            return Err(84);
        }
    }
    Ok(NvmeOutcome {
        bar_base,
        report,
        per_vector,
    })
}
