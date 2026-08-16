// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `usb` device class, driven from ring 3 and checked from here.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// Proves **a bus whose devices have no registers**: the relaying host
/// `docs/drivers/01` describes, which nothing in this tree has been.
///
/// Four programs and two contracts. A ring-3 host binds the xHCI controller,
/// walks the root ports and a hub, addresses what it finds, and puts every
/// device in the resource graph — hubs as buses with devices behind them, so
/// the graph is three levels deep where it has only ever been two. Two class
/// drivers then serve `tessera.driver.block` and `tessera.driver.input` off
/// devices they cannot touch: neither maps anything, because there is nothing
/// to map, and every byte they move crosses the host.
///
/// And one attached device is **refused**. Its class is not on the host's
/// allowlist, so it enumerates perfectly and is declared into the graph with a
/// class code no manifest entry claims — visible, and in nobody's hands. That
/// is the first policy here that turns away something that works.
pub(crate) fn usb_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
        return Err(700);
    };

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(701u32)?;
        exec.device_register_identified(
            USB_DEVICE_OBJ,
            bar_base,
            bar_len,
            // DERIVE, because this controller's children are devices and its
            // driver is what puts them in the graph — and its children's
            // children are too, which is what a hub is.
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
        .map_err(|_| 702u32)?;
        // A bus that forwards nothing and has no configuration window for its
        // children: a USB device owns no memory, and a declaration naming a
        // register window is refused. The same shape the SD controller has, and
        // the reason a hub declared behind this one can hold devices of its own.
        exec.device_set_bus_window(USB_DEVICE_OBJ, kcore::devmgr::BusWindow::default())
            .map_err(|_| 703u32)?;

        let manager = exec.channel_create().map_err(|_| 704u32)?;
        exec.bind_endpoint_object(manager.0, USB_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, USB_MANAGER_CLIENT_OBJ);
        let manager2 = exec.channel_create().map_err(|_| 704u32)?;
        exec.bind_endpoint_object(manager2.0, USB_MANAGER_SERVER2_OBJ);
        exec.bind_endpoint_object(manager2.1, USB_MANAGER_CLIENT2_OBJ);
        let manager3 = exec.channel_create().map_err(|_| 704u32)?;
        exec.bind_endpoint_object(manager3.0, USB_MANAGER_SERVER3_OBJ);
        exec.bind_endpoint_object(manager3.1, USB_MANAGER_CLIENT3_OBJ);
        let host = exec.channel_create().map_err(|_| 705u32)?;
        exec.bind_endpoint_object(host.0, USB_HOST_SERVER_OBJ);
        exec.bind_endpoint_object(host.1, USB_HOST_CLIENT_OBJ);
        let block = exec.channel_create().map_err(|_| 706u32)?;
        exec.bind_endpoint_object(block.0, USB_BLK_SERVER_OBJ);
        exec.bind_endpoint_object(block.1, USB_BLK_CLIENT_OBJ);
        let input = exec.channel_create().map_err(|_| 707u32)?;
        exec.bind_endpoint_object(input.0, USB_INPUT_SERVER_OBJ);
        exec.bind_endpoint_object(input.1, USB_INPUT_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        USB_MANAGER_KSTACK_VA,
        // One device granted, and two service endpoints beyond the first. The
        // extras are installed *after* the device handles, so the device base
        // is where every other check leaves it.
        1 | (2 << 56),
        USB_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        710,
    )?;
    let (host_idx, host_proc) = ring3_host_spawn(
        components::usb_host(),
        USB_HOST_KSTACK_VA,
        0,
        USB_HOST_PROC_OBJ,
        &mut kernel_space,
        frames,
        720,
    )?;
    let (storage_idx, storage_proc) = ring3_host_spawn(
        components::usb_storage(),
        USB_STORAGE_KSTACK_VA,
        0,
        USB_STORAGE_PROC_OBJ,
        &mut kernel_space,
        frames,
        730,
    )?;
    let (hid_idx, hid_proc) = ring3_host_spawn(
        components::usb_hid(),
        USB_HID_KSTACK_VA,
        0,
        USB_HID_PROC_OBJ,
        &mut kernel_space,
        frames,
        740,
    )?;
    // The same client program that judges virtio, NVMe and SD, with the same
    // argument. Nothing about it knows this disk is reached through two other
    // processes, which is the whole claim.
    let (blk_idx, blk_proc) = ring3_host_spawn(
        components::blk_client(),
        USB_BLK_KSTACK_VA,
        1,
        USB_BLK_PROC_OBJ,
        &mut kernel_space,
        frames,
        750,
    )?;
    let (input_idx, input_proc) = ring3_host_spawn(
        components::input_client(),
        USB_INPUT_KSTACK_VA,
        0,
        USB_INPUT_PROC_OBJ,
        &mut kernel_space,
        frames,
        760,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(711u32)?;
            manager
                .handles_mut()
                .install(USB_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 711u32)?;
            manager
                .handles_mut()
                .install(
                    USB_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
                )
                .map_err(|_| 711u32)?;
            manager
                .handles_mut()
                .install(USB_MANAGER_SERVER2_OBJ, Rights::READ)
                .map_err(|_| 711u32)?;
            manager
                .handles_mut()
                .install(USB_MANAGER_SERVER3_OBJ, Rights::READ)
                .map_err(|_| 711u32)?;
        }
        {
            let host = processes.get_mut(host_proc).ok_or(721u32)?;
            host.handles_mut()
                .install(USB_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 721u32)?;
            host.handles_mut()
                .install(USB_HOST_SERVER_OBJ, Rights::READ)
                .map_err(|_| 721u32)?;
        }
        {
            let storage = processes.get_mut(storage_proc).ok_or(731u32)?;
            storage
                .handles_mut()
                .install(USB_MANAGER_CLIENT2_OBJ, Rights::WRITE)
                .map_err(|_| 731u32)?;
            storage
                .handles_mut()
                .install(USB_HOST_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 731u32)?;
            storage
                .handles_mut()
                .install(USB_BLK_SERVER_OBJ, Rights::READ)
                .map_err(|_| 731u32)?;
        }
        {
            let hid = processes.get_mut(hid_proc).ok_or(741u32)?;
            hid.handles_mut()
                .install(USB_MANAGER_CLIENT3_OBJ, Rights::WRITE)
                .map_err(|_| 741u32)?;
            hid.handles_mut()
                .install(USB_HOST_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 741u32)?;
            hid.handles_mut()
                .install(USB_INPUT_SERVER_OBJ, Rights::READ)
                .map_err(|_| 741u32)?;
        }
        processes
            .get_mut(blk_proc)
            .ok_or(751u32)?
            .handles_mut()
            .install(USB_BLK_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 751u32)?;
        processes
            .get_mut(input_proc)
            .ok_or(761u32)?
            .handles_mut()
            .install(USB_INPUT_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 761u32)?;
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
        return Err(770);
    }
    // Two clients, two contracts, and both are load-bearing: the block report
    // is byte-identical to what virtio, NVMe and SD produce, and the input one
    // carries three separable claims that are checked apart.
    let mut block = 0u64;
    let mut input = 0u64;
    for report in &EL0_REPORTS {
        let value = report.load(Ordering::SeqCst);
        if value == USB_BLK_EXPECTED {
            block = value;
        } else if value >> 56 == 0x1d {
            input = value;
        }
    }
    if block != USB_BLK_EXPECTED {
        return Err(771);
    }
    if input & (1 << 32) == 0 {
        return Err(772);
    }
    if input & (1 << 33) == 0 {
        return Err(773);
    }
    if input & (1 << 34) == 0 {
        return Err(774);
    }
    if input != USB_INPUT_EXPECTED {
        return Err(775);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(input_idx);
            exec.scheduler().reap(blk_idx);
            exec.scheduler().reap(hid_idx);
            exec.scheduler().reap(storage_idx);
            exec.scheduler().reap(host_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        USB_INPUT_KSTACK_VA,
        USB_BLK_KSTACK_VA,
        USB_HID_KSTACK_VA,
        USB_STORAGE_KSTACK_VA,
        USB_HOST_KSTACK_VA,
        USB_MANAGER_KSTACK_VA,
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
            input_proc,
            blk_proc,
            hid_proc,
            storage_proc,
            host_proc,
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
    Ok(input)
}

// --- MMC/SD: a controller with card children, and a medium that can go (D154) ---

pub(crate) const SD_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x120);
pub(crate) const SD_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x121);
pub(crate) const SD_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x122);
pub(crate) const SD_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x123);
pub(crate) const SD_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x124);
pub(crate) const SD_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x125);
pub(crate) const SD_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x126);
pub(crate) const SD_CLIENT_A_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x127);
pub(crate) const SD_CLIENT_B_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x128);

pub(crate) const SD_MANAGER_KSTACK_VA: u64 = 0xffff_0007_a000_0000;
pub(crate) const SD_DRIVER_KSTACK_VA: u64 = 0xffff_0007_b000_0000;
pub(crate) const SD_CLIENT_A_KSTACK_VA: u64 = 0xffff_0007_c000_0000;
pub(crate) const SD_CLIENT_B_KSTACK_VA: u64 = 0xffff_0007_d000_0000;

/// An SD host controller on PCI: system peripheral, subclass SD. Matched on
/// both bytes because the base byte is a category shared with interrupt
/// controllers and timers.
pub(crate) const PCI_CLASS_SD_HOST: u32 = 0x0805;

/// The startup argument asking `blk-client` to wait for the medium to go
/// rather than to read something that must succeed. Must match `MEDIUM_GONE`
/// there.
pub(crate) const BLK_CLIENT_MEDIUM_GONE: usize = 1 << 58;

/// What the first client reports: the disk magic rotated by its id.
pub(crate) const SD_CLIENT_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAV").rotate_left(8);
/// What the second reports when it saw the card leave.
pub(crate) const SD_GONE_EXPECTED: u64 = 0x5344 << 48;

