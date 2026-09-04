// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A file read off a real ext2 volume, through the whole stack.
//!
//! Five programs, each already proved at its own level and none of that
//! establishing that they compose: the device manager binds by class,
//! `blk-driver` drives the disk, `block-service` is the layer between,
//! `fs-service` reads ext2 through it, and `fs-probe` asks what is in
//! `/hello.txt` and checks every byte against what `mke2fs` wrote there.
//!
//! **The volume is the second disk, and that is what keeps this check and the
//! block one apart.** The scratch disk `blk_check` binds is written to — the
//! conformance battery puts a sector on it — and that write lands where an
//! ext2 superblock would be. So a machine that runs this carries two, and this
//! check takes the second: a one-disk machine simply skips, which is every
//! other boot of this image.
//!
//! **What it needed below it was the out-of-line path.** A channel message's
//! inline payload cannot carry a sector, so `Read` hands back 64 bytes and
//! nothing built on it can read a superblock; `fs-service` moves whole sectors
//! with `ReadInto`/`WriteFrom`, through a memory object it owns and hands over.
//! That is the feature the driver gained for this milestone, and it does it
//! without ever mapping the caller's buffer.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! **It says `ext2:` and not `fs:` on the console**, because this port already
//! has a check that says `fs:` — the RAM-backed page-supply proof in `fs.rs`,
//! which is about a service filling a pager-backed object out of its own
//! buffer and has no volume at all. The claim is `fs.read`, the same key the
//! other port emits for the same sentence; the prefix is what a reader scanning
//! a boot needs to tell two checks apart.
//!
//! Normative: docs/storage/02-file-io-and-caching.md

use crate::*;

/// User-stack pages for the two programs that walk a filesystem.
///
/// **Twelve, and the four every other ring-3 program here gets is not enough.**
/// `fs-service` holds an ext2 reader, a sector buffer and an open-file table
/// and recurses through a directory; on four pages it ran off the bottom, which
/// arrives as a page fault just below `USER_STACK_BASE` naming neither the
/// stack nor the program. The other port measured the floor at ten and rounded
/// to twelve for the same reason, and the measurement transferred.
pub(crate) const EXT2_FS_STACK_PAGES: u64 = 12;

/// This check's own topology, in a block of its own.
pub(crate) const EXT2_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x100);
pub(crate) const EXT2_MANAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x101);
pub(crate) const EXT2_MANAGER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x102);
pub(crate) const EXT2_DRIVER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x103);
pub(crate) const EXT2_DRIVER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x104);
pub(crate) const EXT2_BLOCK_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x105);
pub(crate) const EXT2_BLOCK_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x106);
/// The filesystem's own channel — a different contract from the three below
/// it, and the only one in this stack that names a *file*.
pub(crate) const EXT2_FS_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x10e);
pub(crate) const EXT2_FS_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0x10f);
/// The endpoint the filesystem service answers **page requests** on, and its
/// peer. No process is given a handle to the peer: it exists so that a paged
/// object can name a pager at all, which every non-empty file this service
/// opens does.
pub(crate) const EXT2_PAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0x107);
pub(crate) const EXT2_PAGER_PEER_OBJ: ObjectId = ObjectId::from_raw(0x108);
pub(crate) const EXT2_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x109);
pub(crate) const EXT2_DRIVER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x10a);
pub(crate) const EXT2_BLOCK_PROC_OBJ: ObjectId = ObjectId::from_raw(0x10b);
pub(crate) const EXT2_SERVICE_PROC_OBJ: ObjectId = ObjectId::from_raw(0x10c);
pub(crate) const EXT2_PROBE_PROC_OBJ: ObjectId = ObjectId::from_raw(0x10d);

/// The ext2 volume's size in 512-byte sectors — four mebibytes, which is what
/// `//api/ext2:testdata/mkimage.sh` truncates it to before `mke2fs` runs.
///
/// **Compared against what the driver read off the device**, which is what says
/// this check took the volume and not the one-mebibyte scratch disk beside it.
/// Both carry the same magic at sector 0, so the size is the only thing that
/// tells them apart from inside the machine.
pub(crate) const EXT2_VOLUME_SECTORS: u64 = 4 * 1024 * 1024 / 512;

/// What `fs-probe` reports when it has opened `/hello.txt` by name, read it,
/// checked every byte against what the image builder wrote, and seen a missing
/// path refused with `NOT_FOUND` rather than with anything else.
///
/// Stated here as well as in the program, because a single shared definition
/// would make agreement automatic rather than checked.
pub(crate) const EXT2_PROBE_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAF").rotate_left(8);

/// `PageSupply` calls the run made: the filesystem service filling a page of a
/// file its client had **mapped**.
///
/// Nothing else in this stack makes that call. A run whose client only ever
/// read through messages makes none, which is what this separates a mapped
/// file from — the read leg above and the write leg below both go through
/// `Read`/`Write` and would leave this at zero.
pub(crate) static EXT2_PAGE_SUPPLIES: AtomicU64 = AtomicU64::new(0);

/// Dirty pages the kernel handed the service across every `Sync`, summed.
///
/// **The only thing between a store into a mapping and a sector.** A client
/// that stores into a page it mapped sends no message and the service is told
/// nothing; what makes the write persist is that the store faulted, the kernel
/// recorded the page, and `Sync` asked. A kernel that granted the write
/// without recording it leaves this at zero and loses the bytes silently,
/// which is why it is counted rather than inferred from the volume.
pub(crate) static EXT2_DIRTY_REPORTED: AtomicU64 = AtomicU64::new(0);

/// Dirty pages the whole run must produce: one for each store the client made
/// through its mapping.
///
/// **Two, and the second is a different mechanism from the first.** The first
/// store faults because the page is supplied read-only even though the mapping
/// grants write; the second faults because the kernel *re-protected* the page
/// when the flush marked it clean. A kernel that cleaned without re-protecting
/// takes the second store with no fault, records nothing, and reads one here.
/// Stated rather than measured-and-accepted: this is the count the two legs in
/// `fs-probe` are written to produce.
const EXT2_EXPECTED_DIRTY: u64 = 2;

/// The block stack's observer, and the two calls this check adds to it.
fn ext2_observer(phase: crate::syscalls::Phase, number: SyscallNumber, frame: &SyscallFrame) {
    blk_observer(phase, number, frame);
    if let crate::syscalls::Phase::Answered(result) = phase
        && result >= 0
    {
        match number {
            SyscallNumber::PageSupply => {
                EXT2_PAGE_SUPPLIES.fetch_add(1, Ordering::SeqCst);
            }
            // The answer *is* the count: `MemoryDirtyPages` returns how many
            // offsets it wrote, so summing the results is summing the pages
            // the kernel said had been written.
            SyscallNumber::MemoryDirtyPages => {
                EXT2_DIRTY_REPORTED.fetch_add(result as u64, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

/// What the ext2 check produced.
pub(crate) struct Ext2Outcome {
    /// Where the volume's function keeps its controls, so a failure names the
    /// device rather than leaving the reader to guess which disk was taken.
    pub(crate) bar_base: u64,
    /// Sectors on the volume, as the driver read them off the device.
    pub(crate) capacity: u64,
    /// Requests the filesystem service made of the block service, and the
    /// block service of the driver, counted by the kernel.
    pub(crate) at_block: u64,
    pub(crate) at_driver: u64,
    /// Pages the service supplied into the client's mapping, and dirty pages
    /// the kernel reported back to it.
    pub(crate) supplied: u64,
    pub(crate) dirtied: u64,
    /// Records this run left in the event ring, drained here so the checks
    /// after it still have somewhere to write.
    pub(crate) events: u64,
}

/// Runs the filesystem stack against the second disk.
///
/// `Ok(None)` when the machine has one, which is every other boot of this
/// image: a skip said out loud rather than a pass nobody earned.
pub(crate) fn ext2_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<Ext2Outcome>, u32> {
    use kcore::rights::Rights;

    if components::fs_service().is_empty()
        || components::fs_probe().is_empty()
        || components::block_service().is_empty()
        || components::blk_driver().is_empty()
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
    // **The second virtio mass-storage function, and the order is the QEMU
    // line's.** The first is the scratch disk `blk_check` writes a sector to;
    // taking it here would mean this check's volume had an ext2 superblock
    // overwritten by another check on the same boot.
    let Some(function) = functions[..found]
        .iter()
        .filter(|f| f.class_code >> 16 == PCI_CLASS_MASS_STORAGE && f.vendor == VIRTIO_VENDOR)
        .nth(1)
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
            EXT2_DEVICE_OBJ,
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
        .device_set_layout(EXT2_DEVICE_OBJ, regions.layout)
        .map_err(|_| 4u32)?;

    // Five channels. The two in the middle carry the **same** block class
    // contract, which is what a block service is; the top one carries the
    // filesystem's, which is the only one in this stack that names a file. The
    // last is the pager's, and no process holds its far end: it exists so that
    // a paged object can name a pager at all, which every non-empty file this
    // service opens does.
    for (server, client, base) in [
        (EXT2_MANAGER_SERVER_OBJ, EXT2_MANAGER_CLIENT_OBJ, 5u32),
        (EXT2_DRIVER_SERVER_OBJ, EXT2_DRIVER_CLIENT_OBJ, 6),
        (EXT2_BLOCK_SERVER_OBJ, EXT2_BLOCK_CLIENT_OBJ, 7),
        (EXT2_FS_SERVER_OBJ, EXT2_FS_CLIENT_OBJ, 8),
        (EXT2_PAGER_SERVER_OBJ, EXT2_PAGER_PEER_OBJ, 9),
    ] {
        let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| base)?;
        exec_ref().bind_endpoint_object(server_ep, server);
        exec_ref().bind_endpoint_object(client_ep, client);
    }

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(ext2_observer);
    // **The shared fault path, which this check is the first here to need.**
    // A client that maps a file stores into a page the service supplied, and
    // that store faults twice over: once because the page is not resident and
    // once because it is supplied read-only. Both are `kcore::dispatch`'s to
    // answer — the second is where the kernel records the page dirty, and a
    // resolver that granted the write without recording it would lose the
    // store with nothing saying so.
    set_page_fault_resolver(crate::syscalls::shared_page_fault_resolver);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    EXT2_PAGE_SUPPLIES.store(0, Ordering::SeqCst);
    EXT2_DIRTY_REPORTED.store(0, Ordering::SeqCst);
    BLK_DRIVER_RECEIVES.store(0, Ordering::SeqCst);
    BLK_SERVICE_RECEIVES.store(0, Ordering::SeqCst);
    BLK_DRIVER_THREAD.store(u64::MAX, Ordering::SeqCst);
    BLK_SERVICE_THREAD.store(u64::MAX, Ordering::SeqCst);
    // `frames` outlives the run; the loan is withdrawn before return.
    crate::syscalls::publish_frames(frames);

    // Server-first the whole way down: each program must be parked on `recv`
    // before the one above it calls.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        1,
        EXT2_MANAGER_PROC_OBJ,
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
            .install(EXT2_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 21u32)?;
        manager
            .handles_mut()
            .install(
                EXT2_DEVICE_OBJ,
                Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 22u32)?;
    }

    let (driver_thread, driver_proc) = spawn_elf_process(
        components::blk_driver(),
        BLK_DRIVER_COMPOSED_WITH_MANAGER | BLK_DRIVER_SERVE_THE_CLASS,
        EXT2_DRIVER_PROC_OBJ,
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
            .install(EXT2_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 41u32)?;
        driver
            .handles_mut()
            .install(EXT2_DRIVER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 42u32)?;
    }

    let (block_thread, block_proc) = spawn_elf_process(
        components::block_service(),
        0,
        EXT2_BLOCK_PROC_OBJ,
        kernel_vm,
        frames,
        50,
    )?;
    BLK_SERVICE_THREAD.store(block_thread as u64, Ordering::SeqCst);
    // SAFETY: as above.
    unsafe {
        let block = (&mut *&raw mut PROCESSES)
            .get_mut(block_proc)
            .ok_or(60u32)?;
        block
            .handles_mut()
            .install(EXT2_DRIVER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 61u32)?;
        block
            .handles_mut()
            .install(EXT2_BLOCK_SERVER_OBJ, Rights::READ)
            .map_err(|_| 62u32)?;
    }

    // **The filesystem service holds three channels and no device.** One down
    // to the block service, one up to its client, and one it answers page
    // requests on — `SUPPLY` as well as `READ`, because that is what
    // `MemoryCreatePaged` requires of the endpoint it names as pager, and a
    // service that could not supply must not be able to promise it.
    let (service_thread, service_proc) = spawn_elf_process_with_stack(
        components::fs_service(),
        0,
        EXT2_FS_STACK_PAGES,
        EXT2_SERVICE_PROC_OBJ,
        kernel_vm,
        frames,
        70,
    )?;
    // SAFETY: as above.
    unsafe {
        let service = (&mut *&raw mut PROCESSES)
            .get_mut(service_proc)
            .ok_or(80u32)?;
        service
            .handles_mut()
            .install(EXT2_BLOCK_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 81u32)?;
        service
            .handles_mut()
            .install(EXT2_FS_SERVER_OBJ, Rights::READ)
            .map_err(|_| 82u32)?;
        service
            .handles_mut()
            .install(EXT2_PAGER_SERVER_OBJ, Rights::READ | Rights::SUPPLY)
            .map_err(|_| 83u32)?;
    }

    let (probe_thread, probe_proc) = spawn_elf_process_with_stack(
        components::fs_probe(),
        0,
        EXT2_FS_STACK_PAGES,
        EXT2_PROBE_PROC_OBJ,
        kernel_vm,
        frames,
        90,
    )?;
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(probe_proc)
            .ok_or(100u32)?
            .handles_mut()
            .install(EXT2_FS_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 101u32)?;
    }

    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    let outcome = judge_ext2(&regions, drain_this_run());

    // **Before the frames go back**, for the reason `blk_check`'s teardown
    // gives: the driver is still in `DRIVER_OK` with the addresses of pages
    // this teardown is about to return.
    reset_device(kernel_vm, frames, &regions);

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [
            probe_thread,
            service_thread,
            block_thread,
            driver_thread,
            manager_thread,
        ] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in [
            probe_proc,
            service_proc,
            block_proc,
            driver_proc,
            manager_proc,
        ] {
            if let Some(mut gone) = processes.remove(process) {
                exec_ref().release_memory_of(gone.id(), frames, None);
                gone.space_mut().teardown(frames);
            }
        }
    }
    outcome.map(Some)
}

/// Empties the event ring, and says how much was in it.
///
/// **This check is the boot's largest single producer of events**, by a wide
/// margin: five processes, a bus, a device and a filesystem's worth of I/O
/// leave several hundred records where the checks around it leave tens. The
/// ring holds [`EVENT_RING_CAPACITY`](kcore::event::EVENT_RING_CAPACITY) and
/// **drops the newest when it is full**, so a run that left its records there
/// did not merely waste space: it silently discarded the crash, fault and link
/// records of the checks that come after, which then failed reporting zero of
/// everything, several steps from the cause and with nothing pointing here.
///
/// Draining here is what the other port's checks already do for their own
/// assertions — "drained before the assertions so a full ring cannot swallow
/// them". Raising the capacity is the fix this is *not*: three drain sites
/// hold an array of `EVENT_RING_CAPACITY` records on a kernel stack, so a ring
/// sized for this boot's emission would overflow them (D324's shape again).
/// And what makes draining safe rather than destructive is the order — the
/// link records `correlation_demo` needs are minted by `loader_demo`, which
/// now runs *after* this (build/README.md, D325).
fn drain_this_run() -> u64 {
    let blank = kcore::event::record(
        kcore::event::EventKind::EventsDropped,
        kcore::event::Severity::Debug,
        kcore::event::Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );
    let mut sink = [blank; kcore::event::EVENT_RING_CAPACITY];
    kcore::event::drain(&mut sink) as u64
}

/// Reads what the run left and says what it establishes.
///
/// Split out because the teardown above must happen whatever the verdict is: a
/// check that returned early on a bad report would leave five processes and
/// their address spaces behind, and the next check's frame accounting would be
/// what noticed.
fn judge_ext2(regions: &VirtioRegions, events: u64) -> Result<Ext2Outcome, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(110);
    }
    // Four: the driver's three about the device it took, and the probe's one
    // about the file. Nothing between them reports — a middle layer that had
    // something of its own to say would be a layer with an opinion.
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 4 {
        return Err(111);
    }
    let capacity = BIND_REPORTS[1].load(Ordering::SeqCst);
    let probe = BIND_REPORTS[3].load(Ordering::SeqCst);
    let at_block = BLK_SERVICE_RECEIVES.load(Ordering::SeqCst);
    let at_driver = BLK_DRIVER_RECEIVES.load(Ordering::SeqCst);
    let supplied = EXT2_PAGE_SUPPLIES.load(Ordering::SeqCst);
    let dirtied = EXT2_DIRTY_REPORTED.load(Ordering::SeqCst);

    // **Every byte of the file, and a name that is not on the volume refused.**
    // The probe returns this value only if the length the inode reported was
    // right, every byte matched what the image builder wrote, and a missing
    // path came back `NOT_FOUND` rather than as an I/O error.
    if probe != EXT2_PROBE_EXPECTED {
        return Err(112);
    }
    // The volume is not the scratch disk. Both are attached and the two are
    // different sizes, so this is what says the second function was taken.
    if capacity != EXT2_VOLUME_SECTORS {
        return Err(113);
    }
    // And the reads went all the way down. A filesystem service that answered
    // out of a cache of its own would leave both counts short; the block
    // service passes every out-of-line request through, so here the two agree
    // rather than differing by one as they do under `blk_check`.
    if at_driver == 0 || at_block != at_driver {
        return Err(114);
    }
    // **The page cache under the filesystem, from the kernel's side.** The
    // client mapped a file and stored into it, and both halves of that are
    // counted rather than inferred from the volume: a page the service
    // supplied because the client's load faulted, and the pages the kernel
    // reported dirty when it asked. Two stores were made, on either side of a
    // flush, and each had to fault for the kernel to see it — so a kernel that
    // granted the first write without recording it, or cleaned the page
    // without re-protecting it, reads one here instead of two.
    if supplied == 0 {
        return Err(115);
    }
    if dirtied != EXT2_EXPECTED_DIRTY {
        return Err(116);
    }
    Ok(Ext2Outcome {
        bar_base: regions.bar_base,
        capacity,
        at_block,
        at_driver,
        supplied,
        dirtied,
        events,
    })
}
