// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The `usb` device class on this machine: a bus whose devices have no
//! registers.
//!
//! **Everything this port has driven so far owns memory.** A virtio function, a
//! NVMe controller, a NIC — each is a window a driver maps and writes. A USB
//! device is not: it owns nothing, it is reachable only by asking the
//! controller to move bytes on its behalf, and a driver for one maps nothing at
//! all. That is the relaying host `docs/drivers/01` describes, and this is the
//! first thing here to be one.
//!
//! Six programs and two contracts. A ring-3 host binds the xHCI controller,
//! walks the root ports and a hub, addresses what it finds, and puts every
//! device in the resource graph — **hubs as buses with devices behind them, so
//! the graph is three levels deep where it has only ever been two**. Two class
//! drivers then serve `tessera.driver.block` and `tessera.driver.input` off
//! devices they cannot touch, and the clients that judge them are the ones that
//! judge every other transport.
//!
//! And one attached device is **refused**: its class is not on the host's
//! allowlist, so it enumerates perfectly and is declared into the graph with a
//! class code no manifest entry claims — visible, and in nobody's hands.
//!
//! Split out of `main.rs` by area (build/README.md, D265).
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts"),
//! docs/drivers/02-storage-networking-usb-pcie.md ("USB")

use crate::*;

/// This check's own topology, in a block of its own.
pub(crate) const USB_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x140);
pub(crate) const USB_MANAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x141);
pub(crate) const USB_MANAGER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x142);
/// The manager serves three programs that bind, so it holds three endpoints.
pub(crate) const USB_MANAGER_SERVER2_OBJ: ObjectId = ObjectId::from_raw(0x143);
pub(crate) const USB_MANAGER_CLIENT2_OBJ: ObjectId = ObjectId::from_raw(0x144);
pub(crate) const USB_MANAGER_SERVER3_OBJ: ObjectId = ObjectId::from_raw(0x145);
pub(crate) const USB_MANAGER_CLIENT3_OBJ: ObjectId = ObjectId::from_raw(0x146);
/// The host's own contract: what a class driver asks it to move.
pub(crate) const USB_HOST_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x147);
pub(crate) const USB_HOST_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x148);
pub(crate) const USB_BLK_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x149);
pub(crate) const USB_BLK_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x14a);
pub(crate) const USB_INPUT_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x14b);
pub(crate) const USB_INPUT_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x14c);
pub(crate) const USB_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x14d);
pub(crate) const USB_HOST_PROC_OBJ: ObjectId = ObjectId::from_raw(0x14e);
pub(crate) const USB_STORAGE_PROC_OBJ: ObjectId = ObjectId::from_raw(0x14f);
pub(crate) const USB_HID_PROC_OBJ: ObjectId = ObjectId::from_raw(0x150);
pub(crate) const USB_BLK_PROC_OBJ: ObjectId = ObjectId::from_raw(0x151);
pub(crate) const USB_INPUT_PROC_OBJ: ObjectId = ObjectId::from_raw(0x152);

/// The PCI class of an xHCI controller: serial bus, subclass USB, programming
/// interface 0x30. Matched on both bytes, because the base byte covers
/// FireWire, SMBus and CAN as well.
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

/// How many devices the host may declare under one node before this check
/// stops counting. Four is what this machine attaches; the array is what a
/// walk of the graph writes into.
const MAX_DECLARED: usize = 8;

/// What the USB check produced.
pub(crate) struct UsbOutcome {
    pub(crate) bar_base: u64,
    /// Devices the host declared directly under the controller, and devices
    /// declared under those — a hub's own children, which is the third level.
    pub(crate) on_root: usize,
    pub(crate) behind_hub: usize,
    /// The two clients' reports: the block one byte-identical to what virtio
    /// and NVMe produce, and the input one carrying its three claims.
    pub(crate) block: u64,
    pub(crate) input: u64,
}

/// Runs the USB stack against an xHCI controller.
///
/// `Ok(None)` when the machine has none.
pub(crate) fn usb_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<UsbOutcome>, u32> {
    use kcore::rights::Rights;

    if components::usb_host().is_empty()
        || components::usb_storage().is_empty()
        || components::usb_hid().is_empty()
        || components::blk_client().is_empty()
        || components::input_client().is_empty()
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
        .find(|f| f.class_code >> 8 == PCI_CLASS_XHCI)
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
    exec_ref()
        .device_register_identified(
            USB_DEVICE_OBJ,
            bar_base,
            bar_len,
            // DERIVE, because this controller's children are devices and its
            // driver is what puts them in the graph — and its children's
            // children are too, which is what a hub is.
            Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
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
    // A bus that forwards nothing and has no configuration window for its
    // children: a USB device owns no memory, and a declaration naming a
    // register window is refused. That is what lets a hub declared behind this
    // one hold devices of its own.
    exec_ref()
        .device_set_bus_window(USB_DEVICE_OBJ, kcore::devmgr::BusWindow::default())
        .map_err(|_| 4u32)?;

    for (server, client, base) in [
        (USB_MANAGER_SERVER_OBJ, USB_MANAGER_CLIENT_OBJ, 5u32),
        (USB_MANAGER_SERVER2_OBJ, USB_MANAGER_CLIENT2_OBJ, 6),
        (USB_MANAGER_SERVER3_OBJ, USB_MANAGER_CLIENT3_OBJ, 7),
        (USB_HOST_SERVER_OBJ, USB_HOST_CLIENT_OBJ, 8),
        (USB_BLK_SERVER_OBJ, USB_BLK_CLIENT_OBJ, 9),
        (USB_INPUT_SERVER_OBJ, USB_INPUT_CLIENT_OBJ, 10),
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
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    crate::syscalls::publish_frames(frames);

    // Server first at every hop: the manager before anything binds, the host
    // before a class driver asks it to move bytes, each class driver before its
    // client calls.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        // One device granted, and two service endpoints beyond the first. The
        // extras are installed *after* the device handles, so the device base
        // is where every other check leaves it.
        1 | (2 << 56),
        USB_MANAGER_PROC_OBJ,
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
            .install(USB_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 31u32)?;
        manager
            .handles_mut()
            .install(
                USB_DEVICE_OBJ,
                Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
            )
            .map_err(|_| 32u32)?;
        manager
            .handles_mut()
            .install(USB_MANAGER_SERVER2_OBJ, Rights::READ)
            .map_err(|_| 33u32)?;
        manager
            .handles_mut()
            .install(USB_MANAGER_SERVER3_OBJ, Rights::READ)
            .map_err(|_| 34u32)?;
    }

    let (host_thread, host_proc) = spawn_elf_process(
        components::usb_host(),
        0,
        USB_HOST_PROC_OBJ,
        kernel_vm,
        frames,
        40,
    )?;
    // SAFETY: as above.
    unsafe {
        let usb_host = (&mut *&raw mut PROCESSES).get_mut(host_proc).ok_or(50u32)?;
        usb_host
            .handles_mut()
            .install(USB_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 51u32)?;
        usb_host
            .handles_mut()
            .install(USB_HOST_SERVER_OBJ, Rights::READ)
            .map_err(|_| 52u32)?;
    }

    let (storage_thread, storage_proc) = spawn_elf_process(
        components::usb_storage(),
        0,
        USB_STORAGE_PROC_OBJ,
        kernel_vm,
        frames,
        60,
    )?;
    // SAFETY: as above.
    unsafe {
        let storage = (&mut *&raw mut PROCESSES)
            .get_mut(storage_proc)
            .ok_or(70u32)?;
        storage
            .handles_mut()
            .install(USB_MANAGER_CLIENT2_OBJ, Rights::WRITE)
            .map_err(|_| 71u32)?;
        storage
            .handles_mut()
            .install(USB_HOST_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 72u32)?;
        storage
            .handles_mut()
            .install(USB_BLK_SERVER_OBJ, Rights::READ)
            .map_err(|_| 73u32)?;
    }

    let (hid_thread, hid_proc) = spawn_elf_process(
        components::usb_hid(),
        0,
        USB_HID_PROC_OBJ,
        kernel_vm,
        frames,
        80,
    )?;
    // SAFETY: as above.
    unsafe {
        let hid = (&mut *&raw mut PROCESSES).get_mut(hid_proc).ok_or(90u32)?;
        hid.handles_mut()
            .install(USB_MANAGER_CLIENT3_OBJ, Rights::WRITE)
            .map_err(|_| 91u32)?;
        hid.handles_mut()
            .install(USB_HOST_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 92u32)?;
        hid.handles_mut()
            .install(USB_INPUT_SERVER_OBJ, Rights::READ)
            .map_err(|_| 93u32)?;
    }

    // The same client program that judges virtio and NVMe, with the same
    // argument. Nothing about it knows this disk is reached through two other
    // processes, which is the whole claim.
    let (blk_thread, blk_proc) = spawn_elf_process(
        components::blk_client(),
        BLK_CLIENT_ID,
        USB_BLK_PROC_OBJ,
        kernel_vm,
        frames,
        100,
    )?;
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(blk_proc)
            .ok_or(110u32)?
            .handles_mut()
            .install(USB_BLK_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 111u32)?;
    }

    let (input_thread, input_proc) = spawn_elf_process(
        components::input_client(),
        0,
        USB_INPUT_PROC_OBJ,
        kernel_vm,
        frames,
        120,
    )?;
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(input_proc)
            .ok_or(130u32)?
            .handles_mut()
            .install(USB_INPUT_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 131u32)?;
    }

    // **No interrupt and no pump.** The host polls the controller's event ring:
    // nothing here is woken by a device, which is why this check needs neither
    // a vector nor an idle loop. A USB device that wanted to interrupt would be
    // interrupting the *host*, and the host is a program.
    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    let outcome = judge_usb(bar_base);

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [
            input_thread,
            blk_thread,
            hid_thread,
            storage_thread,
            host_thread,
            manager_thread,
        ] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in [
            input_proc,
            blk_proc,
            hid_proc,
            storage_proc,
            host_proc,
            manager_proc,
        ] {
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
fn judge_usb(bar_base: u64) -> Result<UsbOutcome, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(140);
    }
    // Two clients, two contracts, and both are load-bearing: the block report
    // is byte-identical to what virtio and NVMe produce, and the input one
    // carries three separable claims that are checked apart. Matched by their
    // own tags rather than by slot, because which client finishes first is a
    // scheduling accident.
    let mut block = 0u64;
    let mut input = 0u64;
    for slot in &BIND_REPORTS {
        let value = slot.load(Ordering::SeqCst);
        if value == USB_BLK_EXPECTED {
            block = value;
        } else if value >> 56 == 0x1d {
            input = value;
        }
    }
    if block != USB_BLK_EXPECTED {
        return Err(141);
    }
    // The conformance suite came back complete.
    if input & (1 << 32) == 0 {
        return Err(142);
    }
    // An idle keyboard answered `NO_REPORT` rather than failing — a device with
    // nothing to say is not a device that is broken.
    if input & (1 << 33) == 0 {
        return Err(143);
    }
    // And a report was read back through the relay.
    if input & (1 << 34) == 0 {
        return Err(144);
    }
    if input != USB_INPUT_EXPECTED {
        return Err(145);
    }

    // **The shape of the graph, read from the graph.** The host declared what
    // it found: three devices on the controller's root ports, and one behind
    // the hub — which is the third level, a bus with devices of its own where
    // this tree has only ever had a controller and its children.
    let mut root = [ObjectId::from_raw(0); MAX_DECLARED];
    let on_root = exec_ref().device_children_of(USB_DEVICE_OBJ, &mut root);
    if on_root < 3 {
        return Err(146);
    }
    let mut behind_hub = 0;
    for child in &root[..on_root] {
        let mut grandchildren = [ObjectId::from_raw(0); MAX_DECLARED];
        behind_hub += exec_ref().device_children_of(*child, &mut grandchildren);
    }
    if behind_hub == 0 {
        return Err(147);
    }
    // **And one of them is in nobody's hands.** Four devices were declared and
    // two class drivers reported: the third root-port device enumerated
    // perfectly, was declared with a class code no manifest entry claims, and
    // was offered to nobody. A host that bound everything it found would leave
    // these two numbers equal.
    if on_root + behind_hub <= 3 {
        return Err(148);
    }
    Ok(UsbOutcome {
        bar_base,
        on_root,
        behind_hub,
        block,
        input,
    })
}
