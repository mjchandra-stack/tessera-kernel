// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The block class on a real bus: a compiled ring-3 driver reads the disk.
//!
//! `pci_bus.rs` proves a ring-3 program can *find* a mass-storage function and
//! that a driver bound to it can reach its own registers. This is the next
//! sentence and the one the class contract needs: a ring-3 program brings the
//! device **up** — the modern virtio-pci handshake, a queue it configured, a
//! request it posted — and reads sector 0 off the disk QEMU attached.
//!
//! **Where the work is on this machine.** virtio-mmio names one register block
//! at a base the firmware reports; virtio-pci names nothing. Its controls live
//! in up to five structures described by the function's own vendor
//! capabilities, in a BAR that is **not** the lowest-numbered one — on
//! `1af4:1001` BAR 0 is an I/O port range and BAR 1 is the MSI-X table, and the
//! structures are in BAR 4. Configuration space is where that is written down,
//! and configuration space is not per-device: no capability to it can be handed
//! to a driver, so the walk is the kernel's and the driver is told offsets into
//! the window it was granted (`DeviceInfo`, `layout_valid`).
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/drivers/01-driver-framework.md,
//! docs/hardware/04-device-memory-and-unified-memory.md

use crate::*;

/// The magic sector 0 of the test disk carries (`//tools/qemu:virtio_test_disk`).
/// The driver reports the eight bytes it read; this is what they must be.
pub(crate) const DISK_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");

/// The test disk's size in 512-byte sectors — one mebibyte, which is what the
/// genrule truncates it to.
///
/// **Compared against what the driver read out of the device's own
/// configuration structure**, which is a different structure from the common
/// one and at a different offset in the BAR. A driver that guessed offset zero
/// would read the common configuration's feature selector; one that reported a
/// constant would report whatever disk it was written against. This number is a
/// fact about the build, stated here in the same spirit as [`DISK_MAGIC`].
pub(crate) const DISK_SECTORS: u64 = 1024 * 1024 / 512;

/// virtio's PCI vendor id. A mass-storage function from anyone else is a
/// controller this driver does not speak to, and is left alone rather than
/// declared a fatal error.
pub(crate) const VIRTIO_VENDOR: u16 = 0x1af4;

pub(crate) const BLK_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0xf0);
pub(crate) const BLK_MANAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0xf1);
pub(crate) const BLK_MANAGER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0xf2);
pub(crate) const BLK_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0xf3);
pub(crate) const BLK_DRIVER_PROC_OBJ: ObjectId = ObjectId::from_raw(0xf4);
/// The driver's own service channel: the block class contract, with the driver
/// serving and the block service calling.
pub(crate) const BLK_DRIVER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0xf5);
pub(crate) const BLK_DRIVER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0xf6);
/// The service's channel: **the same contract one layer up**, with the block
/// service serving and the client calling.
pub(crate) const BLK_SERVICE_SERVER_OBJ: ObjectId = ObjectId::from_raw(0xf7);
pub(crate) const BLK_SERVICE_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0xf8);
pub(crate) const BLK_SERVICE_PROC_OBJ: ObjectId = ObjectId::from_raw(0xf9);
pub(crate) const BLK_CLIENT_PROC_OBJ: ObjectId = ObjectId::from_raw(0xfa);
/// The port the device's message-signalled interrupt arrives on, bound to the
/// vector the graph records as this device's line and handed to the driver.
pub(crate) const BLK_PORT_OBJ: ObjectId = ObjectId::from_raw(0xfb);

/// Which scheduler slots the driver and the service run in, and how many
/// class-contract requests each of them was handed.
///
/// **Counted by the kernel rather than reported by the programs**, and that is
/// the whole reason these exist. A driver's own tally is the driver's word for
/// what it did; a count of the receives the kernel answered on that thread is
/// what a check can hold it to — and the two numbers together say something
/// neither says alone (see [`BLK_SERVICE_REQUESTS`]).
pub(crate) static BLK_DRIVER_THREAD: AtomicU64 = AtomicU64::new(u64::MAX);
pub(crate) static BLK_SERVICE_THREAD: AtomicU64 = AtomicU64::new(u64::MAX);
pub(crate) static BLK_DRIVER_RECEIVES: AtomicU64 = AtomicU64::new(0);
pub(crate) static BLK_SERVICE_RECEIVES: AtomicU64 = AtomicU64::new(0);

/// The bind check's observer, plus a count of what each layer was asked.
///
/// A `ChannelRecv` that answered is a request delivered; which layer it reached
/// is the thread it was delivered to, which the scheduler knows and neither
/// program can misreport.
pub(crate) fn blk_observer(
    phase: crate::syscalls::Phase,
    number: SyscallNumber,
    frame: &SyscallFrame,
) {
    bind_observer(phase, number, frame);
    if let crate::syscalls::Phase::Answered(result) = phase
        && number == SyscallNumber::ChannelRecv
        && result >= 0
        && let Some(thread) = chan_current_index().map(|slot| slot as u64)
    {
        if thread == BLK_DRIVER_THREAD.load(Ordering::SeqCst) {
            BLK_DRIVER_RECEIVES.fetch_add(1, Ordering::SeqCst);
        } else if thread == BLK_SERVICE_THREAD.load(Ordering::SeqCst) {
            BLK_SERVICE_RECEIVES.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// The startup argument that tells the driver it was composed behind a device
/// manager **and left resident**. Must match `COMPOSED_WITH_MANAGER` and
/// `SERVE_THE_CLASS` in `userspace/blk-driver`.
pub(crate) const BLK_DRIVER_COMPOSED_WITH_MANAGER: usize = 1;
pub(crate) const BLK_DRIVER_SERVE_THE_CLASS: usize = 2;
/// And that the port its device's interrupt arrives on was installed after its
/// endpoints. Must match `INTERRUPT_PORT_SEEDED` in `userspace/blk-driver`.
pub(crate) const BLK_DRIVER_INTERRUPT_PORT_SEEDED: usize = 4;

/// The client's id, which it folds into its report so a value cannot be
/// mistaken for one some other instance wrote. Id 1 is the leg that runs the
/// **conformance battery** and does not write the medium; see
/// `userspace/blk-client`.
pub(crate) const BLK_CLIENT_ID: usize = 1;

/// What `blk-client` reports when every leg of its run held: the disk magic
/// rotated by its id.
pub(crate) const BLK_CLIENT_EXPECTED: u64 = DISK_MAGIC.rotate_left(8 * BLK_CLIENT_ID as u32);

/// How many class-contract requests reach each layer.
///
/// **Measured, not predicted, and the difference between them is the point.**
/// `blk-client`'s id-1 leg makes twelve calls: two sector reads, then the
/// conformance suite's describe, read, write, read-back, flush, reset,
/// set-power, discard, a vendor-range ordinal and set-power again. All twelve
/// reach the service. **Eleven** reach the driver, because an ordinal this
/// contract does not define never becomes a request to forward — the service
/// refuses it where it arrives.
///
/// A service that answered a read out of memory of its own would leave the
/// driver's count short; one that was not there at all would make the two
/// counts equal. Neither number says that alone.
pub(crate) const BLK_SERVICE_REQUESTS: u64 = 12;
pub(crate) const BLK_DRIVER_REQUESTS: u64 = 11;

/// Where a virtio-pci function keeps its controls, as offsets into the BAR the
/// common configuration structure lives in.
///
/// Offsets and a length, and **no physical address**: what the driver is told
/// is where things are inside the window it was granted, and where that window
/// is on the machine stays a fact no driver is given.
pub(crate) struct VirtioRegions {
    pub(crate) layout: kcore::devmgr::DeviceLayout,
    /// The BAR the structures are in, and its full extent — the region a driver
    /// must be granted, which is not the one `first_bar` names.
    pub(crate) bar_base: u64,
    pub(crate) bar_len: u64,
    /// How many vendor capabilities the walk decoded. Reported rather than
    /// assumed, because "found its controls" is the claim and a literal in a
    /// verdict line proves nothing.
    pub(crate) capabilities: u32,
}

/// Resolves a virtio-pci function's configuration structures by walking its
/// vendor capabilities.
///
/// A virtio-pci device does not say where its controls are in any register — it
/// says so in **config space**, one vendor-specific capability per structure,
/// each naming a BAR and an offset within it. There are several of them, which
/// is why the walk has to be resumable ([`tessera_pci::find_capability_from`]):
/// stopping at the first match finds whichever structure the device happened to
/// list first and misses the rest.
///
/// All four structures are required. QEMU's virtio devices present all four,
/// and a driver told an offset for a structure that was never found would drive
/// whatever is at offset zero of the BAR — which for the common configuration
/// structure is a real register, so the mistake would not fault.
pub(crate) fn virtio_pci_regions(
    host: &tessera_pci::Host,
    config: &dyn tessera_pci::ConfigSpace,
    function: &tessera_pci::Function,
) -> Option<VirtioRegions> {
    tessera_virtio::pci::device_type(function.device)?;

    let (mut common, mut notify, mut isr, mut device_config) = (None, None, None, None);
    let mut multiplier = 0u32;
    let (mut bar_base, mut bar_len) = (0u64, 0u64);
    let mut capabilities = 0u32;
    let mut at = None;
    // Bounded by the capability list itself; `find_capability_from` refuses a
    // chain that loops or runs past the header.
    while let Ok(Some(offset)) =
        tessera_pci::find_capability_from(host, config, function.bdf, tessera_pci::CAP_VENDOR, at)
    {
        at = Some(offset);
        capabilities += 1;
        let word = |i: u16| host.read(config, function.bdf, offset + i * 4).unwrap_or(0);
        let cap = tessera_virtio::pci::decode_cap([word(0), word(1), word(2), word(3)]);
        let Some((base, len)) = function.bars.get(cap.bar as usize).copied().flatten() else {
            continue; // a structure in a BAR that was not placed is unreachable
        };
        // The device's own numbers, so they are checked before they are trusted.
        if u64::from(cap.offset) + u64::from(cap.length) > len {
            continue;
        }
        match cap.cfg_type {
            tessera_virtio::pci::cfg_type::COMMON => {
                common = Some(cap.offset);
                // The BAR the controls are in is the one a driver must be
                // granted; the structures are offsets within it.
                bar_base = base;
                bar_len = len;
            }
            tessera_virtio::pci::cfg_type::NOTIFY => {
                notify = Some(cap.offset);
                // The multiplier follows the standard capability, and only a
                // notify capability carries it.
                multiplier = tessera_virtio::pci::decode_notify_multiplier(word(4));
            }
            tessera_virtio::pci::cfg_type::ISR => isr = Some(cap.offset),
            tessera_virtio::pci::cfg_type::DEVICE => device_config = Some(cap.offset),
            _ => {}
        }
    }
    // Every structure has to have come from the same BAR: the driver is granted
    // one window and given offsets into it, so a structure in a different BAR
    // is one it cannot reach and must not be told about.
    Some(VirtioRegions {
        layout: kcore::devmgr::DeviceLayout {
            common: common?,
            notify: notify?,
            notify_multiplier: multiplier,
            isr: isr?,
            device_config: device_config?,
        },
        bar_base,
        bar_len,
        capabilities,
    })
}

/// Where this check maps the device's common configuration structure to put the
/// device back in its reset state. A kernel address, mapped for the length of
/// the write and taken down after; the driver's own mapping is gone by then.
pub(crate) const BLK_RESET_VA: u64 = 0xffff_a000_0100_0000;

/// Puts the device back in its reset state, **before the driver's DMA pages go
/// back to the allocator**.
///
/// A virtio device keeps the physical addresses its driver gave it until
/// something writes `device_status = 0`, and reads them again on the next
/// doorbell. Reaping a driver's threads and freeing its frames leaves a live
/// device pointed at memory the next owner is about to fill with ordinary data,
/// which the device would then read as a ring. It does not fault and it is not
/// in the serial log — it is one line on QEMU's stderr about an available index
/// no driver ever wrote.
///
/// One byte, at the one offset that matters. The whole `Regs` shim the driver
/// needs is not wanted here: this is not driving the device, it is taking it out
/// of service.
pub(crate) fn reset_device(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    regions: &VirtioRegions,
) {
    let at = regions.bar_base + u64::from(regions.layout.common);
    let page_base = at & !(FRAME_SIZE - 1);
    let Some(first) = PhysFrame::from_base(PhysAddr::new(page_base)) else {
        return;
    };
    if kernel_vm
        .map_device_range(
            VirtAddr::new(BLK_RESET_VA),
            first,
            1,
            kcore::vm::DeviceReach::Kernel,
            frames,
        )
        .is_err()
    {
        return;
    }
    let status = BLK_RESET_VA + (at & (FRAME_SIZE - 1)) + COMMON_DEVICE_STATUS;
    // SAFETY: the page just mapped covers the common configuration structure as
    // device memory, and `device_status` is one byte inside it. One byte and not
    // four: `config_generation` and `queue_select` are the next two fields, and
    // a wider write would rewrite both.
    unsafe { (status as *mut u8).write_volatile(0) };
    // The reset is not complete until the device says so by reading back zero.
    // Bounded, because a device that never answers must not hang the boot.
    for _ in 0..1_000_000u32 {
        // SAFETY: as above.
        if unsafe { (status as *const u8).read_volatile() } == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    kernel_vm.unmap_device_pages(VirtAddr::new(BLK_RESET_VA), 1);
}

/// `device_status` in the virtio-pci common configuration structure. Named here
/// rather than imported: `tessera_virtio::pci::common` is `pub`, and this is the
/// one field a caller that is not driving the device needs.
const COMMON_DEVICE_STATUS: u64 = tessera_virtio::pci::common::DEVICE_STATUS as u64;

/// What the block check produced.
pub(crate) struct BlkOutcome {
    /// Vendor capabilities the kernel's walk decoded.
    pub(crate) capabilities: u32,
    /// The window the driver was granted, which is the BAR the structures are
    /// in rather than the function's lowest-numbered one.
    pub(crate) bar_base: u64,
    pub(crate) bar_len: u64,
    /// The device's capacity in sectors, as the *driver* read it.
    pub(crate) capacity: u64,
    /// The eight bytes the driver read off sector 0.
    pub(crate) magic: u64,
    /// Class-contract requests each layer was handed, counted by the kernel.
    pub(crate) at_service: u64,
    pub(crate) at_driver: u64,
    /// Message-signalled interrupts this device raised, counted at the vector.
    pub(crate) msi: u64,
    /// Device-visible addresses issued out of this device's aperture — zero on
    /// a machine with no remapping unit, where the grants are physical and say
    /// so.
    pub(crate) scoped_bytes: u64,
}

/// A compiled ring-3 driver brings a virtio-blk PCI function up and reads it.
///
/// The programs are the same sources the other machines run: the device manager
/// that binds by class, and the block driver that drove a virtio-mmio transport
/// on RISC-V 64. Neither is compiled differently here — what changed is that
/// this machine's function keeps its controls somewhere a driver cannot look.
///
/// **The driver holds one channel endpoint when it starts.** Everything it ends
/// up with — the device, the window, the pages the device reads — arrives
/// because the manager transferred a capability or because the kernel answered
/// a call authorised by one.
pub(crate) fn blk_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<BlkOutcome>, u32> {
    use kcore::rights::Rights;

    if components::blk_driver().is_empty()
        || components::device_manager().is_empty()
        || components::block_service().is_empty()
        || components::blk_client().is_empty()
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
    // A **virtio** mass-storage function. The class alone stopped being enough
    // the moment a second storage transport could be attached: an NVMe
    // controller is mass storage too, and a walk looking for "the block device"
    // by class finds whichever the enumeration listed first.
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.class_code >> 16 == PCI_CLASS_MASS_STORAGE && f.vendor == VIRTIO_VENDOR)
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
            BLK_DEVICE_OBJ,
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
    // **And behind an address space of its own, when this machine has a unit**
    // (D340). From here the driver's `dma_alloc` is answered out of this
    // device's aperture rather than with a physical address, and the device
    // reaches the pages the graph gave it and no others — which is what makes
    // this the ordinary block stack running scoped rather than a check beside
    // it. The borrow ends here; the run below reaches the same unit through the
    // pointer `syscalls::publish_iommu` holds.
    let scoped = unit.is_some();
    if let Some(unit) = unit {
        unit.scope(BLK_DEVICE_OBJ, function, frames)
            .map_err(|which| 200 + which)?;
    }

    // Where its virtio structures are, read out of configuration space during
    // enumeration — a driver holding only a window has no way to find them,
    // because config space is not per-device and no capability to it can be
    // handed out.
    exec_ref()
        .device_set_layout(BLK_DEVICE_OBJ, regions.layout)
        .map_err(|_| 4u32)?;

    // **And where its interrupt goes**, which is the half a PCI function has
    // never had here. `arm_msix` programs the entry and hands back the vector
    // it raises; the graph records that as this device's line, and the port
    // bound to it is what a driver parks on. Both halves or neither: a device
    // programmed to send a message nobody routed raises an interrupt this
    // kernel counts as unclaimed, and a port bound to a line no device sends
    // is a driver that never wakes.
    let vector = crate::msi::arm_msix(&host, &mut config, function, kernel_vm, frames)?;
    exec_ref()
        .device_set_mmio_irq(BLK_DEVICE_OBJ, vector)
        .map_err(|_| 79u32)?;
    let port = exec_ref().port_create().map_err(|_| 80u32)?;
    exec_ref().bind_port_object(port, BLK_PORT_OBJ);
    exec_ref()
        .device_route_irq(BLK_DEVICE_OBJ, port, BLK_DEVICE_OBJ)
        .map_err(|_| 81u32)?;
    crate::msi::forget_deliveries();
    tessera_karch_x86_64::set_device_irq_hook(crate::msi::msi_bridge_hook);

    // Three channels, one per layer boundary. The middle two carry the **same**
    // class contract, which is what a block service is: a filesystem written
    // against `block_driver.isl` cannot tell which of them it reached.
    let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| 5u32)?;
    exec_ref().bind_endpoint_object(server_ep, BLK_MANAGER_SERVER_OBJ);
    exec_ref().bind_endpoint_object(client_ep, BLK_MANAGER_CLIENT_OBJ);
    let (driver_server, driver_client) = exec_ref().channel_create().map_err(|_| 6u32)?;
    exec_ref().bind_endpoint_object(driver_server, BLK_DRIVER_SERVER_OBJ);
    exec_ref().bind_endpoint_object(driver_client, BLK_DRIVER_CLIENT_OBJ);
    let (service_server, service_client) = exec_ref().channel_create().map_err(|_| 7u32)?;
    exec_ref().bind_endpoint_object(service_server, BLK_SERVICE_SERVER_OBJ);
    exec_ref().bind_endpoint_object(service_client, BLK_SERVICE_CLIENT_OBJ);

    // Where the kstack windows this check draws begin, so they go back with the
    // processes that hold them.
    let kstacks = kstack_mark();

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(blk_observer);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BLK_DRIVER_RECEIVES.store(0, Ordering::SeqCst);
    BLK_SERVICE_RECEIVES.store(0, Ordering::SeqCst);
    BLK_DRIVER_THREAD.store(u64::MAX, Ordering::SeqCst);
    BLK_SERVICE_THREAD.store(u64::MAX, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    // `frames` outlives the run; the loan is withdrawn before return.
    crate::syscalls::publish_frames(frames);

    // The manager first, so it is parked on its endpoint before the driver
    // calls. Its startup argument is the number of device capabilities boot
    // installed after its service endpoint — one.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        1,
        BLK_MANAGER_PROC_OBJ,
        kernel_vm,
        frames,
        10,
    )?;
    // SAFETY: the boot CPU alone; the process table is quiescent between spawns.
    unsafe {
        let manager = (&mut *&raw mut PROCESSES)
            .get_mut(manager_proc)
            .ok_or(20u32)?;
        manager
            .handles_mut()
            .install(BLK_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 21u32)?;
        // The device, with the authority to hand it on and no more. The manager
        // never maps it and never touches a register: it classifies from the
        // identity the graph holds and transfers.
        manager
            .handles_mut()
            .install(
                BLK_DEVICE_OBJ,
                Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 22u32)?;
    }

    // The driver: two endpoints, and no device at all. One is the manager it
    // asks; the other is the class contract it will answer once it has
    // something to answer with.
    let (driver_thread, driver_proc) = spawn_elf_process(
        components::blk_driver(),
        BLK_DRIVER_COMPOSED_WITH_MANAGER
            | BLK_DRIVER_SERVE_THE_CLASS
            | BLK_DRIVER_INTERRUPT_PORT_SEEDED,
        BLK_DRIVER_PROC_OBJ,
        kernel_vm,
        frames,
        30,
    )?;
    BLK_DRIVER_THREAD.store(driver_thread as u64, Ordering::SeqCst);
    // SAFETY: as above.
    unsafe {
        let driver = (&mut *&raw mut PROCESSES)
            .get_mut(driver_proc)
            .ok_or(40u32)?;
        driver
            .handles_mut()
            .install(BLK_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 41u32)?;
        driver
            .handles_mut()
            .install(BLK_DRIVER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 42u32)?;
        // The port its device's message arrives on, installed here and not
        // transferred with the device: what the manager hands on is authority
        // over a device, and where that device's interrupt is delivered is the
        // composition's arrangement rather than the manager's to pass around.
        // Last of what boot installs, which is what puts the device the
        // manager transfers after it.
        driver
            .handles_mut()
            .install(BLK_PORT_OBJ, Rights::READ)
            .map_err(|_| 43u32)?;
    }

    // **The block service, and it holds no device.** One channel down to the
    // driver at handle 0, one up to its client at handle 1 — the whole
    // authority of a middle layer, and the bootstrap contract the program's own
    // constants mirror. Spawned after the driver and before its client, for the
    // same server-first reason at each boundary.
    let (service_thread, service_proc) = spawn_elf_process(
        components::block_service(),
        0,
        BLK_SERVICE_PROC_OBJ,
        kernel_vm,
        frames,
        50,
    )?;
    BLK_SERVICE_THREAD.store(service_thread as u64, Ordering::SeqCst);
    // SAFETY: as above.
    unsafe {
        let service = (&mut *&raw mut PROCESSES)
            .get_mut(service_proc)
            .ok_or(60u32)?;
        service
            .handles_mut()
            .install(BLK_DRIVER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 61u32)?;
        service
            .handles_mut()
            .install(BLK_SERVICE_SERVER_OBJ, Rights::READ)
            .map_err(|_| 62u32)?;
    }

    // And the client, which holds one channel and knows nothing about what is
    // behind it. It reads two sectors and then runs the block class's
    // **conformance battery** against whatever answers — which here is the
    // service, and which the battery cannot tell from a driver.
    let (client_thread, client_proc) = spawn_elf_process(
        components::blk_client(),
        BLK_CLIENT_ID,
        BLK_CLIENT_PROC_OBJ,
        kernel_vm,
        frames,
        70,
    )?;
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(client_proc)
            .ok_or(80u32)?
            .handles_mut()
            .install(BLK_SERVICE_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 81u32)?;
    }

    // Everything here is cooperative — a call, a reply, a poll of memory the
    // device writes, an exit — so the scheduler runs to quiescence without a
    // tick to prod it.
    // **Ring 3 with interrupts unmasked, and boot without them** — the
    // discipline the COM2 driver check established on this port. A thread that
    // enters ring 3 with `IF` clear cannot take its device's interrupt at all,
    // and boot staying masked is what keeps the interrupt-context
    // `port_signal` from ever aliasing a live executive borrow: the only code
    // running when a message lands is a ring-3 thread.
    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    // Four reports is this composition complete: the driver's three and the
    // client's one.
    let truncated = crate::msi::pump_the_run("blk", crate::msi::PUMP_BUDGET, || {
        BIND_REPORT_COUNT.load(Ordering::SeqCst) >= 4
    });
    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    // **What the aperture issued, read before the teardown gives it back.** On
    // a scoped device this is the whole claim: every address the driver
    // programmed into the device came out of a range the graph owns, so the
    // number being greater than zero is what separates a scoped run from one
    // that was handed physical addresses and worked anyway.
    let scoped_bytes = exec_ref()
        .aperture_of_object(BLK_DEVICE_OBJ)
        .map_or(0, |aperture| aperture.next - aperture.base);
    let outcome = if truncated {
        Err(82)
    } else {
        judge(&regions, bdf, function).and_then(|mut outcome| {
            // A device the boot put behind an address space whose driver took
            // no address out of it is one that got physical addresses anyway —
            // which would work here and be exactly the silent downgrade the
            // whole facility exists to prevent.
            if scoped && scoped_bytes == 0 {
                return Err(83);
            }
            outcome.scoped_bytes = scoped_bytes;
            Ok(outcome)
        })
    };

    // **Before the frames go back.** The driver has exited and its mappings are
    // gone, but the device has not been told: it is still in `DRIVER_OK` with
    // the physical addresses of pages this teardown is about to return.
    reset_device(kernel_vm, frames, &regions);

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [client_thread, service_thread, driver_thread, manager_thread] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in [client_proc, service_proc, driver_proc, manager_proc] {
            if let Some(mut gone) = processes.remove(process) {
                gone.space_mut().teardown(frames);
            }
        }
    }
    // And the windows those processes held, back to the allocator along with
    // the records they occupied in the shared kernel space.
    kstack_release(kernel_vm, kstacks, BIND_KSTACK_PAGES);
    outcome.map(Some)
}

/// Reads the six reports the run left and says what they establish.
///
/// Split out because the teardown above must happen whatever the verdict is: a
/// check that returned early on a bad report would leave four processes and
/// their address spaces behind, and the next check's frame accounting would be
/// what noticed.
fn judge(
    regions: &VirtioRegions,
    bdf: u32,
    function: &tessera_pci::Function,
) -> Result<BlkOutcome, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(70);
    }
    // Four, in the order the run establishes them, and the order is forced by
    // what has to have happened before each: the driver says what it found
    // before it can serve anything, and the client cannot report before it has
    // been served. A count that is not four is a run that stopped part-way, and
    // which report is missing says where.
    //
    // **The driver and the service are still parked when this reads them**, and
    // that is the shape of a resident service rather than an omission: nothing
    // wakes a server blocked in `receive` when its client exits, so a stack that
    // reported its own shutdown would be reporting a mechanism this port does
    // not have. What each of them was asked is counted by the kernel instead.
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 4 {
        return Err(71);
    }
    let identity = BIND_REPORTS[0].load(Ordering::SeqCst);
    let capacity = BIND_REPORTS[1].load(Ordering::SeqCst);
    let magic = BIND_REPORTS[2].load(Ordering::SeqCst);
    let client = BIND_REPORTS[3].load(Ordering::SeqCst);
    let at_service = BLK_SERVICE_RECEIVES.load(Ordering::SeqCst);
    let at_driver = BLK_DRIVER_RECEIVES.load(Ordering::SeqCst);

    // **The function the driver ended up holding is the one the kernel walked
    // to.** A manager that bound this driver to some other device answers with
    // a different bus/device/function, and one that bound it to nothing leaves
    // `DeviceInfo` with nothing to answer.
    let wanted =
        (u64::from(bdf) << 32) | (u64::from(function.vendor) << 16) | u64::from(function.device);
    if identity != wanted {
        return Err(72);
    }
    if capacity != DISK_SECTORS {
        return Err(73);
    }
    if magic != DISK_MAGIC {
        return Err(74);
    }
    // **The client got the medium's bytes through two processes that both speak
    // the class contract**, and the one in the middle holds no device: it was
    // installed with two channel endpoints and nothing else. Its report is the
    // disk magic rotated by its own id, which it returns only if both sector
    // reads verified *and* every rule of the conformance battery held.
    if client != BLK_CLIENT_EXPECTED {
        return Err(75);
    }
    // And the traffic went through the service rather than around it or no
    // further than it. Both numbers, because neither says it alone.
    if at_service != BLK_SERVICE_REQUESTS {
        return Err(76);
    }
    if at_driver != BLK_DRIVER_REQUESTS {
        return Err(77);
    }
    // **And the driver was woken rather than watching.** Every completion this
    // run collected came from a message the device wrote to a vector this
    // kernel programmed, delivered to a port the graph routed — so a run that
    // took the same sectors with no interrupt at all did not do the same thing.
    // At least one, not exactly one: how many messages a device coalesces
    // across a queue's worth of completions is the device's business, and a
    // count fixed here would be asserting QEMU's implementation of it.
    let msi = crate::msi::MSI_DELIVERIES.load(Ordering::SeqCst);
    if msi == 0 {
        return Err(78);
    }
    Ok(BlkOutcome {
        capabilities: regions.capabilities,
        bar_base: regions.bar_base,
        bar_len: regions.bar_len,
        capacity,
        magic,
        at_service,
        at_driver,
        msi,
        // Filled in by the caller, which reads the aperture after the run.
        scoped_bytes: 0,
    })
}
