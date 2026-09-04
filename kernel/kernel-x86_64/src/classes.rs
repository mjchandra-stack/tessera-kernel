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
    pub(crate) ids: ClassIds,
}

/// What a class check produced.
pub(crate) struct ClassOutcome {
    pub(crate) bar_base: u64,
    /// The client's report, which is the whole verdict in one word.
    pub(crate) report: u64,
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

    let (driver_thread, driver_proc) =
        spawn_elf_process(spec.driver, 0, spec.ids.driver_proc, kernel_vm, frames, 30)?;
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

    let outcome = judge_class(spec, bar_base);

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
    Ok(ClassOutcome { report, bar_base })
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
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::gpu_driver(),
        client: components::gpu_client(),
        client_arg: 0,
        bus: false,
        virtio: true,
        expect_high: (GPU_CLIENT_EXPECTED >> 32) as u32,
        bits: &[32, 33, 34],
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
    )
}

/// Sound served from ring 3: periods played through a stream the client fed,
/// and an underrun reported as an underrun rather than as a failure.
pub(crate) fn snd_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::snd_driver(),
        client: components::snd_client(),
        client_arg: 0,
        bus: false,
        virtio: true,
        expect_high: (SND_CLIENT_EXPECTED >> 32) as u32,
        bits: &[32, 33, 34],
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
    )
}

/// An SD card read through a host controller: the block class again, a third
/// transport, judged by the client that judges the other two.
pub(crate) fn sd_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::sd_host(),
        client: components::blk_client(),
        client_arg: BLK_CLIENT_ID,
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
    )
}

/// Encryption served from ring 3: the standard's own vector, a key that changes
/// the answer, and four things that should have been refused.
pub(crate) fn crypto_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<ClassOutcome>, u32> {
    let spec = ClassSpec {
        driver: components::crypto_driver(),
        client: components::crypto_client(),
        client_arg: 0,
        bus: false,
        virtio: true,
        expect_high: (CRYPTO_CLIENT_EXPECTED >> 32) as u32,
        bits: &[32, 33, 34, 35, 36, 37, 38, 39, 40],
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
    )
}
