// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `pci_bus` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves **PCI enumeration outside the kernel** — `docs/drivers/01`, "Bus
/// Topology And Data Paths".
///
/// Four claims, and the first is the one that makes the others worth having:
///
/// 1. A ring-3 program held the host bridge and nothing else, walked it with
///    the same `tessera_pci` the kernel calls, placed the BARs, and **declared**
///    what it found. The devices in the graph afterwards were put there by an
///    unprivileged process.
/// 2. The device manager accepted them as *offers* rather than returns —
///    hardware it had never seen, arriving as a capability, because a body can
///    be forged by any sender and a transferred capability cannot.
/// 3. A driver bound one by class and mapped **its own configuration space**,
///    4 KiB scoped to one function, through `Rights::CONFIGURE`.
/// 4. What it read there agrees with what the graph says — and the graph's word
///    came from the bus driver, so this is the ring-3 walk being checked against
///    the hardware rather than against itself. The kernel's own enumeration,
///    which still runs, is the third opinion the expectation is built from.
pub(crate) fn pci_bus_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    host: &tessera_devicetree::PciHost,
    expected_word: u32,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let Some(memory) = host.memory else {
        return Err(460);
    };
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(461u32)?;
        // The bridge, as a device whose register window *is* configuration
        // space. That is what makes the containment check possible at all: the
        // kernel knows exactly how far the controller's own window reaches, so
        // a slot it declares either lies inside it or does not.
        exec.device_register_mmio(
            PCI_BUS_OBJ,
            host.ecam_base,
            PCI_BUS_CONFIG_LEN,
            Rights::READ
                | Rights::WRITE
                | Rights::MAP
                | Rights::DERIVE
                | Rights::CONFIGURE
                | Rights::TRANSFER,
        )
        .map_err(|_| 462u32)?;
        exec.device_set_bus_window(
            PCI_BUS_OBJ,
            kcore::devmgr::BusWindow {
                config_len: PCI_BUS_CONFIG_LEN,
                forward_cpu_base: memory.cpu_base,
                forward_bus_base: memory.bus_base,
                forward_len: memory.len,
                first_bus: host.first_bus,
                // The window's worth of buses, never more than the bridge
                // itself covers: a controller told it may walk a bus the host
                // bridge does not forward would read config space that answers
                // for nothing.
                last_bus: host
                    .last_bus
                    .min(host.first_bus.saturating_add(PCI_BUS_COUNT - 1)),
                // A PCI bridge forwards memory and no wires: its functions
                // interrupt by message, through a different door.
                first_intid: 0,
                intid_count: 0,
            },
        )
        .map_err(|_| 463u32)?;

        let manager = exec.channel_create().map_err(|_| 464u32)?;
        exec.bind_endpoint_object(manager.0, PCI_BUS_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, PCI_BUS_MANAGER_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // The manager first and holding **nothing**: its startup argument is zero
    // device capabilities, which is the whole point. Everything it ends up with
    // arrives from the bus driver.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        PCI_BUS_MANAGER_KSTACK_VA,
        0,
        PCI_BUS_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        470,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::pci_bus(),
        PCI_BUS_DRIVER_KSTACK_VA,
        0,
        PCI_BUS_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        480,
    )?;
    let (probe_idx, probe_proc) = ring3_host_spawn(
        components::blk_probe(),
        PCI_BUS_PROBE_KSTACK_VA,
        BLK_PROBE_CONFIG_REPORT,
        PCI_BUS_PROBE_PROC_OBJ,
        &mut kernel_space,
        frames,
        490,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(manager_proc)
            .ok_or(471u32)?
            .handles_mut()
            .install(PCI_BUS_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 471u32)?;
        {
            let driver = processes.get_mut(driver_proc).ok_or(481u32)?;
            driver
                .handles_mut()
                .install(PCI_BUS_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 481u32)?;
            // **The whole of what a bus controller is given.** READ and WRITE
            // because placing a BAR is a write to configuration space, MAP to
            // reach it at all, DERIVE to populate the bus, and CONFIGURE and
            // TRANSFER so the functions it declares can carry them onward. It
            // is told nothing else about the machine.
            driver
                .handles_mut()
                .install(
                    PCI_BUS_OBJ,
                    Rights::READ
                        | Rights::WRITE
                        | Rights::MAP
                        | Rights::DERIVE
                        | Rights::CONFIGURE
                        | Rights::TRANSFER,
                )
                .map_err(|_| 481u32)?;
        }
        processes
            .get_mut(probe_proc)
            .ok_or(491u32)?
            .handles_mut()
            .install(PCI_BUS_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 491u32)?;
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
    // Everything here is cooperative — a send, a call, a reply, an exit — so
    // the scheduler runs to quiescence without a tick to prod it.
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
        return Err(492);
    }
    // **Indexed rather than folded.** Two programs report here and one of them
    // reports a count; an XOR could not say which of them failed, and D124's
    // lesson was that a fold cannot tell "ran twice and agreed" from "never
    // ran".
    let bus_report = EL0_REPORTS[0].load(Ordering::SeqCst);
    let probe_report = EL0_REPORTS[1].load(Ordering::SeqCst);
    if bus_report >> 56 != 0x50 {
        return Err(493);
    }
    let found = (bus_report >> 8) & 0xff;
    let declared = bus_report & 0xff;
    if found == 0 || declared != found {
        return Err(494);
    }
    if probe_report >> 56 != 0x43 {
        return Err(495);
    }
    // What the driver read out of its own configuration space must be what the
    // kernel's independent walk found in the same register.
    if probe_report & 0xffff_ffff != u64::from(expected_word) {
        return Err(496);
    }
    // And the graph must have agreed with it, which is the bus driver's
    // declaration being checked against the hardware.
    if probe_report & (1 << 48) == 0 {
        return Err(497);
    }

    // Teardown: the bus driver and the probe exited; the manager is parked in
    // `recv` holding what it was offered.
    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(probe_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        PCI_BUS_PROBE_KSTACK_VA,
        PCI_BUS_DRIVER_KSTACK_VA,
        PCI_BUS_MANAGER_KSTACK_VA,
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
        for proc_idx in [probe_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(found)
}

// --- NVMe: a class contract over a second transport, a vector per queue (D153) ---

pub(crate) const NVME_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x100);
pub(crate) const NVME_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x101);
pub(crate) const NVME_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x102);
pub(crate) const NVME_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x103);
pub(crate) const NVME_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x104);
pub(crate) const NVME_PORT1_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x105);
pub(crate) const NVME_PORT2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x106);
pub(crate) const NVME_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x107);
pub(crate) const NVME_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x108);
pub(crate) const NVME_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x109);

pub(crate) const NVME_MANAGER_KSTACK_VA: u64 = 0xffff_0006_a000_0000;
pub(crate) const NVME_DRIVER_KSTACK_VA: u64 = 0xffff_0006_b000_0000;
pub(crate) const NVME_CLIENT_KSTACK_VA: u64 = 0xffff_0006_c000_0000;

/// The PCI class of an NVM Express controller: mass storage, subclass NVM.
pub(crate) const PCI_CLASS_NVME: u32 = 0x0108;

/// The MSI-X vectors the driver's two I/O queues raise, which are also their
/// queue ids. The pairing is the contract with `userspace/nvme-driver`: it
/// creates queue *n* with vector *n*, and this routes vector *n* to the port it
/// holds at that index.
pub(crate) const NVME_VECTORS: [u16; 2] = [1, 2];

/// What `blk-client` reports when it has read both sectors and the block
/// class's conformance suite came back complete. Its id is 1, and it rotates
/// the disk magic by its id.
pub(crate) const NVME_CLIENT_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAV").rotate_left(8);

