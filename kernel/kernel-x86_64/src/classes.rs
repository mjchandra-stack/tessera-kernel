// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The four device classes that are a manager, a driver and a client.
//!
//! **The fourth time a shape appears it becomes a function.** `gpu`, `snd`,
//! `sd` and `crypto` differ from one another in exactly four things: which PCI
//! function they look for, which two programs they run, what argument the
//! client is started with, and what it must report. Everything between — the
//! fresh executive, the device registered with its identity, the two channels,
//! the server-before-client spawn order, the handle installs each program's
//! bootstrap contract mirrors, the run, the teardown and the windows going back
//! — is the same paragraph four times over. The other port has it four times
//! over; here it is [`run_class`], and what a class check writes is the four
//! things that are its own.
//!
//! **None of them routes an interrupt.** Each driver polls the device it was
//! given, so there is no vector to program, no port to bind and no idle loop to
//! run — which is also why they fit one runner: an interrupt is the thing that
//! makes a composition need a shape of its own.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts"),
//! docs/drivers/02-storage-networking-usb-pcie.md

use crate::*;

/// The objects one class check needs. Eight ids, and every check's are its own
/// so two of them cannot collide even if a boot ran both.
pub(crate) struct ClassIds {
    pub(crate) device: ObjectId,
    pub(crate) manager_server: ObjectId,
    pub(crate) manager_client: ObjectId,
    pub(crate) server: ObjectId,
    pub(crate) client: ObjectId,
    pub(crate) manager_proc: ObjectId,
    pub(crate) driver_proc: ObjectId,
    pub(crate) client_proc: ObjectId,
}

/// What one class check is, beyond the shape it shares with the others.
///
/// No name here: the boot names the class it is running, because that is the
/// string that reaches the log whether the check ran, skipped or failed.
pub(crate) struct ClassSpec {
    /// The two programs: one binds the device by class, the other holds a
    /// single channel and judges what it is served.
    pub(crate) driver: &'static [u8],
    pub(crate) client: &'static [u8],
    /// The client's startup argument, which is what fixes the value it reports.
    pub(crate) client_arg: usize,
    /// The driver's, which is zero for every class that means to serve. The one
    /// run that does not passes the bit telling this driver to take a request
    /// and die holding it.
    pub(crate) driver_arg: usize,
    /// Whether this run expects the driver to **die mid-request**, and so
    /// judges the client's failure rather than its success.
    ///
    /// One flag rather than a second runner: what recovery needs is this exact
    /// composition — a manager, a driver bound to a real device, and a client
    /// that calls it — with the driver crashing at the one moment a caller is
    /// parked. Everything up to the run is identical, and only the verdict is
    /// the other way round.
    pub(crate) crash: bool,
    /// Whether this controller's device has **children of its own**, and so
    /// whether its driver may declare them.
    ///
    /// **A card is a device, not a register.** An SD host controller holds a
    /// card the way a USB controller holds what is plugged into it: the driver
    /// is what puts it in the graph, which takes `DERIVE` to be allowed to and
    /// a bus window to be allowed to declare something with no registers of its
    /// own. Without both, the declaration is refused `AccessDenied` and the
    /// failure surfaces three programs away, as a manager that could not answer
    /// a bind (build/README.md, D330).
    pub(crate) bus: bool,
    /// Whether this class's driver moves data by **DMA** at all.
    ///
    /// **False is a fact about the device, not a permission.** An SD host
    /// controller's driver reads a block through the controller's own buffer
    /// register a word at a time, so it never asks for a DMA buffer and spends
    /// nothing out of its aperture. The device is still put behind one — a
    /// controller that tried a descriptor-driven transfer would be refused,
    /// which is what an empty aperture is for — but the run cannot be asked to
    /// prove it took an address, because there was never one to take.
    pub(crate) dma: bool,
    /// Whether the function is a virtio one, and so whether the graph must
    /// record where its structures are. A driver holding only a window cannot
    /// find them: configuration space is not per-device and no capability to it
    /// can be handed out.
    pub(crate) virtio: bool,
    /// The high half of the client's report — its tag and its claim bits. The
    /// low half carries counts a verdict does not need and a failure does.
    pub(crate) expect_high: u32,
    /// Bit positions the report must carry, checked one at a time so a failure
    /// names the claim that did not hold rather than the word that did not
    /// match.
    pub(crate) bits: &'static [u32],
    /// The low sixteen bits the report must carry **exactly**, where they mean
    /// something rather than counting something.
    ///
    /// The class clients put counts there and the verdict ignores them; the
    /// certifier puts *which checks ran* there, and a run that quietly recorded
    /// a third is the failure that whole facility is shaped against — so for it
    /// the mask is compared rather than inspected for the bits that matter.
    pub(crate) expect_low_mask: Option<u16>,
    pub(crate) ids: ClassIds,
}

/// What a class check produced.
pub(crate) struct ClassOutcome {
    pub(crate) bar_base: u64,
    /// The client's report, which is the whole verdict in one word.
    pub(crate) report: u64,
    /// Device-visible addresses issued out of this device's aperture — zero on
    /// a machine with no remapping unit, where the grants are physical and say
    /// so (D342).
    pub(crate) scoped_bytes: u64,
}

/// Runs one class: a manager, a driver bound by class, and a client holding a
/// single channel endpoint.
///
/// `wanted` is asked of each enumerated function, because what makes a device
/// this class is a different question per class — a display controller is a
/// class code, a virtio crypto device is a device id, and neither is the
/// other's business.
pub(crate) fn run_class(
    spec: &ClassSpec,
    wanted: impl Fn(&tessera_pci::Function) -> bool,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<ClassOutcome>, u32> {
    use kcore::rights::Rights;

    if spec.driver.is_empty() || spec.client.is_empty() || components::device_manager().is_empty() {
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
    let Some(function) = functions[..found].iter().find(|f| wanted(f)) else {
        return Ok(None);
    };

    // A virtio function's window is the BAR its structures are in, which is not
    // the lowest-numbered one; anything else is granted its largest.
    let regions = if spec.virtio {
        match virtio_pci_regions(&host, &config, function) {
            Some(regions) => Some(regions),
            None => return Ok(None),
        }
    } else {
        None
    };
    let (bar_base, bar_len) = match &regions {
        Some(regions) => (regions.bar_base, regions.bar_len),
        None => match function
            .bars
            .iter()
            .flatten()
            .copied()
            .max_by_key(|(_, len)| *len)
        {
            Some(bar) => bar,
            None => return Ok(None),
        },
    };
    let bdf = (u32::from(function.bdf.bus) << 8)
        | (u32::from(function.bdf.device) << 3)
        | u32::from(function.bdf.function);

    // SAFETY: the boot CPU alone; a fresh table and executive for this check.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    let rights = if spec.bus {
        Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER | Rights::DERIVE
    } else {
        Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER
    };
    exec_ref()
        .device_register_identified(
            spec.ids.device,
            bar_base,
            bar_len,
            rights,
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
    if let Some(regions) = &regions {
        exec_ref()
            .device_set_layout(spec.ids.device, regions.layout)
            .map_err(|_| 4u32)?;
    }
    // **And behind an address space of its own, when this machine has a unit**
    // (D342). One line for all six of these compositions, which is what
    // `run_class` being a runner is worth: the scoping is the same paragraph
    // per class as everything else here. A function an earlier check already
    // put behind tables is re-keyed rather than given a second set — three of
    // these bind the same crypto device.
    let scoped = unit.is_some();
    if let Some(unit) = unit {
        unit.scope(spec.ids.device, function, frames)
            .map_err(|which| 200 + which)?;
    }

    if spec.bus {
        // A bus that forwards nothing and has no configuration window for its
        // children: a card owns no memory, and a declaration naming a register
        // window is refused.
        exec_ref()
            .device_set_bus_window(spec.ids.device, kcore::devmgr::BusWindow::default())
            .map_err(|_| 7u32)?;
    }

    for (server, client, base) in [
        (spec.ids.manager_server, spec.ids.manager_client, 5u32),
        (spec.ids.server, spec.ids.client, 6),
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

    // Server first at both hops: the manager parked before the driver binds,
    // the driver before its client calls.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        1,
        spec.ids.manager_proc,
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
            .install(spec.ids.manager_server, Rights::READ)
            .map_err(|_| 21u32)?;
        manager
            .handles_mut()
            .install(spec.ids.device, rights)
            .map_err(|_| 22u32)?;
    }

    let (driver_thread, driver_proc) = spawn_elf_process(
        spec.driver,
        spec.driver_arg,
        spec.ids.driver_proc,
        kernel_vm,
        frames,
        30,
    )?;
    // SAFETY: as above.
    unsafe {
        let driver = (&mut *&raw mut PROCESSES)
            .get_mut(driver_proc)
            .ok_or(40u32)?;
        driver
            .handles_mut()
            .install(spec.ids.manager_client, Rights::WRITE)
            .map_err(|_| 41u32)?;
        driver
            .handles_mut()
            .install(spec.ids.server, Rights::READ)
            .map_err(|_| 42u32)?;
    }

    let (client_thread, client_proc) = spawn_elf_process(
        spec.client,
        spec.client_arg,
        spec.ids.client_proc,
        kernel_vm,
        frames,
        50,
    )?;
    // **One handle, and that is the claim**: everything this program knows
    // about the device, it learns by asking through a channel.
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(client_proc)
            .ok_or(60u32)?
            .handles_mut()
            .install(spec.ids.client, Rights::WRITE)
            .map_err(|_| 61u32)?;
    }

    // No pump: every driver here polls the device it was given, so nothing in
    // this run is waiting for an interrupt that could land after the last
    // thread parks.
    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    // What the aperture issued, read before the teardown gives it back (D342).
    let scoped_bytes = exec_ref()
        .aperture_of_object(spec.ids.device)
        .map_or(0, |aperture| aperture.next - aperture.base);
    let outcome = if spec.crash {
        judge_crash(bar_base, driver_thread)
    } else {
        judge_class(spec, bar_base)
    }
    .and_then(|mut outcome| {
        // A device the boot put behind an address space whose driver took no
        // address out of it is one that got physical addresses anyway — which
        // works here, and is exactly the silent downgrade the facility exists
        // to prevent.
        if scoped && spec.dma && scoped_bytes == 0 {
            return Err(77);
        }
        outcome.scoped_bytes = scoped_bytes;
        Ok(outcome)
    });

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
fn judge_class(spec: &ClassSpec, bar_base: u64) -> Result<ClassOutcome, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(70);
    }
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(71);
    }
    let report = BIND_REPORTS[0].load(Ordering::SeqCst);
    // **The bits first, one at a time.** Each is a separable claim, and a check
    // that compared the whole word would name none of them: the failure would
    // say the report was wrong rather than which thing did not happen.
    for (index, bit) in spec.bits.iter().enumerate() {
        if report & (1u64 << bit) == 0 {
            return Err(80 + index as u32);
        }
    }
    // Then the tag and the claims together. The low half carries counts — pixels
    // drawn, periods played, rules reached — which the verdict does not need and
    // a failure does.
    if (report >> 32) as u32 != spec.expect_high {
        return Err(90);
    }
    if let Some(mask) = spec.expect_low_mask
        && (report & 0xffff) as u16 != mask
    {
        return Err(91);
    }
    Ok(ClassOutcome {
        report,
        bar_base,
        // Filled in by the runner, which reads the aperture after the run.
        scoped_bytes: 0,
    })
}

/// The tag `fail` puts in the top sixteen bits of every one of these programs'
/// reports, and the certifier's stage for **the channel call itself**.
///
/// Restated here rather than shared with the program: what a check reads out of
/// a sink is a number the program chose, and importing its constant would make
/// the two agree by construction.
const CLIENT_FAIL_TAG: u64 = 0xdead_0000_0000_0000;
const CLIENT_CHANNEL_STAGE: u64 = 0xc9;

/// Reads what a run whose driver was told to die left behind.
///
/// Three things, and each is a way this could pass without meaning anything.
/// **The driver has to have actually died** — a run where it served normally
/// proves nothing about recovery, and would otherwise look like a pass with an
/// unusual report. **The fault has to be the driver's**, not some other
/// program's, or the check would be reading a crash it did not arrange.
/// **And the client has to have come back**: a client still parked reports
/// nothing at all, so the count is the whole evidence — with an error, and
/// specifically the channel call's, because a client that returned claiming
/// success would be worse than one that hung.
fn judge_crash(bar_base: u64, driver_thread: usize) -> Result<ClassOutcome, u32> {
    if !BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(72);
    }
    if BIND_FAULT[3].load(Ordering::SeqCst) != driver_thread as u64 {
        return Err(73);
    }
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(74);
    }
    let report = BIND_REPORTS[0].load(Ordering::SeqCst);
    if report & 0xffff_0000_0000_0000 != CLIENT_FAIL_TAG {
        return Err(75);
    }
    if (report >> 16) & 0xffff != CLIENT_CHANNEL_STAGE {
        return Err(76);
    }
    Ok(ClassOutcome {
        report,
        bar_base,
        // Filled in by the runner, which reads the aperture after the run.
        scoped_bytes: 0,
    })
}

/// The PCI classes these four look for. A display controller and an audio
/// device are class codes; a virtio crypto device is a device id, because the
/// specification gives it no class of its own.
pub(crate) const PCI_CLASS_DISPLAY: u32 = 0x03;
pub(crate) const PCI_CLASS_AUDIO: u32 = 0x0401;
pub(crate) const PCI_CLASS_SD_HOST: u32 = 0x0805;
pub(crate) const VIRTIO_CRYPTO_DEVICE_ID: u16 = 0x1040 + 20;

/// What each client reports. The tag is the top byte and the claims are the
/// bits above 32; the low half is counts, which a verdict does not need.
///
/// Stated here as well as in each program, and they are the same words the
/// other port expects of the same programs — which is what says the two
/// machines run the same check rather than two checks that agree.
pub(crate) const GPU_CLIENT_EXPECTED: u64 = (0xd0 << 56) | (1 << 34) | (1 << 33) | (1 << 32);
pub(crate) const SND_CLIENT_EXPECTED: u64 = (0xa0 << 56) | (1 << 34) | (1 << 33) | (1 << 32);
pub(crate) const CRYPTO_CLIENT_EXPECTED: u64 = (0xc0 << 56)
    | (1 << 40)
    | (1 << 39)
    | (1 << 38)
    | (1 << 37)
    | (1 << 36)
    | (1 << 35)
    | (1 << 34)
    | (1 << 33)
    | (1 << 32);
/// The SD card is judged by `blk-client`, which reports the disk magic rotated
/// by its id — the same word virtio, NVMe and USB produce.
pub(crate) const SD_CLIENT_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAV").rotate_left(8);

/// A display served from ring 3: the driver arms a scanout and the client draws
/// through it, and a rectangle outside the framebuffer is refused rather than
/// clipped.
pub(crate) fn gpu_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::gpu_driver(),
        client: components::gpu_client(),
        client_arg: 0,
        driver_arg: 0,
        crash: false,
        dma: true,
        bus: false,
        virtio: true,
        expect_high: (GPU_CLIENT_EXPECTED >> 32) as u32,
        bits: &[32, 33, 34],
        expect_low_mask: None,
        ids: ClassIds {
            device: ObjectId::from_raw(0x160),
            manager_server: ObjectId::from_raw(0x161),
            manager_client: ObjectId::from_raw(0x162),
            server: ObjectId::from_raw(0x163),
            client: ObjectId::from_raw(0x164),
            manager_proc: ObjectId::from_raw(0x165),
            driver_proc: ObjectId::from_raw(0x166),
            client_proc: ObjectId::from_raw(0x167),
        },
    };
    run_class(
        &spec,
        // **A display controller *and* a virtio one.** The q35 machine attaches
        // a VGA adapter of its own unless told not to, and it is a display
        // controller too — a walk that took the first one found the emulator's
        // rather than the device this check is about, and then skipped because
        // its virtio structures did not resolve.
        |f| f.class_code >> 16 == PCI_CLASS_DISPLAY && f.vendor == VIRTIO_VENDOR,
        kernel_vm,
        frames,
        memory_map,
        unit,
    )
}

/// Sound served from ring 3: periods played through a stream the client fed,
/// and an underrun reported as an underrun rather than as a failure.
pub(crate) fn snd_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::snd_driver(),
        client: components::snd_client(),
        client_arg: 0,
        driver_arg: 0,
        crash: false,
        dma: true,
        bus: false,
        virtio: true,
        expect_high: (SND_CLIENT_EXPECTED >> 32) as u32,
        bits: &[32, 33, 34],
        expect_low_mask: None,
        ids: ClassIds {
            device: ObjectId::from_raw(0x168),
            manager_server: ObjectId::from_raw(0x169),
            manager_client: ObjectId::from_raw(0x16a),
            server: ObjectId::from_raw(0x16b),
            client: ObjectId::from_raw(0x16c),
            manager_proc: ObjectId::from_raw(0x16d),
            driver_proc: ObjectId::from_raw(0x16e),
            client_proc: ObjectId::from_raw(0x16f),
        },
    };
    run_class(
        &spec,
        |f| f.class_code >> 8 == PCI_CLASS_AUDIO,
        kernel_vm,
        frames,
        memory_map,
        unit,
    )
}

/// An SD card read through a host controller: the block class again, a third
/// transport, judged by the client that judges the other two.
pub(crate) fn sd_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::sd_host(),
        client: components::blk_client(),
        client_arg: BLK_CLIENT_ID,
        driver_arg: 0,
        crash: false,
        dma: false,
        // The card behind the controller is a device of its own, and the host
        // is what declares it.
        bus: true,
        // An SD host controller is not a virtio function: it has registers of
        // its own at a base the enumeration placed, and nothing to resolve.
        virtio: false,
        expect_high: (SD_CLIENT_EXPECTED >> 32) as u32,
        // No claim bits: this client's whole verdict is the word it reports,
        // which is the disk magic rotated by its id — the same one the other
        // transports produce, which is the claim.
        bits: &[],
        expect_low_mask: None,
        ids: ClassIds {
            device: ObjectId::from_raw(0x170),
            manager_server: ObjectId::from_raw(0x171),
            manager_client: ObjectId::from_raw(0x172),
            server: ObjectId::from_raw(0x173),
            client: ObjectId::from_raw(0x174),
            manager_proc: ObjectId::from_raw(0x175),
            driver_proc: ObjectId::from_raw(0x176),
            client_proc: ObjectId::from_raw(0x177),
        },
    };
    run_class(
        &spec,
        |f| f.class_code >> 8 == PCI_CLASS_SD_HOST,
        kernel_vm,
        frames,
        memory_map,
        unit,
    )
}

/// Encryption served from ring 3: the standard's own vector, a key that changes
/// the answer, and four things that should have been refused.
pub(crate) fn crypto_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::crypto_driver(),
        client: components::crypto_client(),
        client_arg: 0,
        driver_arg: 0,
        crash: false,
        dma: true,
        bus: false,
        virtio: true,
        expect_high: (CRYPTO_CLIENT_EXPECTED >> 32) as u32,
        bits: &[32, 33, 34, 35, 36, 37, 38, 39, 40],
        expect_low_mask: None,
        ids: ClassIds {
            device: ObjectId::from_raw(0x178),
            manager_server: ObjectId::from_raw(0x179),
            manager_client: ObjectId::from_raw(0x17a),
            server: ObjectId::from_raw(0x17b),
            client: ObjectId::from_raw(0x17c),
            manager_proc: ObjectId::from_raw(0x17d),
            driver_proc: ObjectId::from_raw(0x17e),
            client_proc: ObjectId::from_raw(0x17f),
        },
    };
    run_class(
        &spec,
        |f| f.vendor == VIRTIO_VENDOR && f.device == VIRTIO_CRYPTO_DEVICE_ID,
        kernel_vm,
        frames,
        memory_map,
        unit,
    )
}

/// The startup argument naming which driver this certification run is about,
/// because the certifier cannot find out. Must match the other port's.
pub(crate) const CERTIFIED_DRIVER_ID: usize = 0x6572_6100;

/// What the certifier reports: the two checks it can make from inside a channel
/// both held, it refused to certify on them, the refusal named nine, and the
/// rules refused a forged record and a stale contract version in ring 3.
///
/// The low bits are *which checks ran* — AbiConformance, ClassConformance,
/// Power and SuspendResume, and nothing else — and they are compared exactly.
pub(crate) const CERTIFIER_EXPECTED: u64 = (0xc1 << 56)
    | (1 << 39)
    | (1 << 38)
    | (1 << 37)
    | (1 << 36)
    | (1 << 35)
    | (1 << 34)
    | (1 << 33)
    | (1 << 32)
    | 0b110
    | (1 << 7)
    | (1 << 4);

/// A runner that **will not certify what it did not check**.
///
/// Every other check on this machine ends by reporting that something worked.
/// This one ends by reporting what was never asked: a ring-3 certifier runs the
/// two of the eleven checks a peer can make against a driver — the class rules,
/// and whether the driver's replies declare the shapes the reader assumed — and
/// both hold. It then **refuses to issue a certificate**, naming the checks
/// nobody ran, because a check nobody ran must never look like a check that
/// passed: the failure that would hide is not a driver bug but a rig that
/// stopped asking. The same rules refuse a forged record and a stale contract
/// version, in ring 3.
///
/// The composition is the crypto class's, with a certifier where the client
/// goes — which is the point of `run_class` being a runner rather than four
/// copies: what changes here is the third program and the word it must report.
pub(crate) fn certify_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::crypto_driver(),
        client: components::certifier(),
        client_arg: CERTIFIED_DRIVER_ID,
        driver_arg: 0,
        crash: false,
        dma: true,
        bus: false,
        virtio: true,
        expect_high: (CERTIFIER_EXPECTED >> 32) as u32,
        // Eight separable claims, checked apart so a failure names which one.
        bits: &[32, 33, 34, 35, 36, 37, 38, 39],
        expect_low_mask: Some((CERTIFIER_EXPECTED & 0xffff) as u16),
        ids: ClassIds {
            device: ObjectId::from_raw(0x1b0),
            manager_server: ObjectId::from_raw(0x1b1),
            manager_client: ObjectId::from_raw(0x1b2),
            server: ObjectId::from_raw(0x1b3),
            client: ObjectId::from_raw(0x1b4),
            manager_proc: ObjectId::from_raw(0x1b5),
            driver_proc: ObjectId::from_raw(0x1b6),
            client_proc: ObjectId::from_raw(0x1b7),
        },
    };
    run_class(
        &spec,
        |f| f.vendor == VIRTIO_VENDOR && f.device == VIRTIO_CRYPTO_DEVICE_ID,
        kernel_vm,
        frames,
        memory_map,
        unit,
    )
}

/// The startup bit that tells `crypto-driver` to take one request and die
/// holding it. Must match `CRASH_BEFORE_REPLYING` there.
pub(crate) const CRASH_BEFORE_REPLYING: usize = 1 << 63;

/// **A client parked on a driver that dies, and whether it comes back.**
///
/// What is being asked is not whether the driver died — that is arranged — but
/// whether the caller discovered it. Before the kernel closed a dying process's
/// endpoints, it did not: the call parked awaiting a reply, the server stopped
/// existing, and nothing connected the two, so the thread stayed blocked and
/// the run ended with it still waiting. A client that never returns reports
/// nothing at all, which is exactly how this reads.
///
/// The composition is the certification run's, with one bit changed in the
/// driver's startup argument — which is the point of `run_class` being a runner:
/// what differs between "a driver serves a certifier" and "a driver dies
/// holding its request" is one argument and the verdict.
pub(crate) fn crash_recovery_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::crypto_driver(),
        client: components::certifier(),
        client_arg: CERTIFIED_DRIVER_ID,
        driver_arg: CRASH_BEFORE_REPLYING,
        crash: true,
        dma: true,
        bus: false,
        virtio: true,
        // Unread on this path: `judge_crash` asks about a failure, and a run
        // that ends in one has no claim bits to inspect.
        expect_high: 0,
        bits: &[],
        expect_low_mask: None,
        ids: ClassIds {
            device: ObjectId::from_raw(0x210),
            manager_server: ObjectId::from_raw(0x211),
            manager_client: ObjectId::from_raw(0x212),
            server: ObjectId::from_raw(0x213),
            client: ObjectId::from_raw(0x214),
            manager_proc: ObjectId::from_raw(0x215),
            driver_proc: ObjectId::from_raw(0x216),
            client_proc: ObjectId::from_raw(0x217),
        },
    };
    run_class(
        &spec,
        |f| f.vendor == VIRTIO_VENDOR && f.device == VIRTIO_CRYPTO_DEVICE_ID,
        kernel_vm,
        frames,
        memory_map,
        unit,
    )
}
