// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The driver framework on a real bus.
//!
//! A PCI function enumerated from ring 3, a manager that binds by class, and a
//! compiled driver that reads the device it was bound to.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- The driver framework: a real bus, a manager, and a compiled driver (D145) ---

/// Most PCI functions this port records. q35 with one attached device presents
/// a handful; the walk reports what it found and stops at the array's end.
pub(crate) const MAX_PCI_FUNCTIONS: usize = 16;

/// A zeroed function, for the enumeration array.
pub(crate) const PCI_BLANK_FUNCTION: tessera_pci::Function = tessera_pci::Function {
    revision: 0,
    bdf: tessera_pci::Bdf {
        bus: 0,
        device: 0,
        function: 0,
    },
    vendor: 0,
    device: 0,
    class_code: 0,
    header_type: 0,
    bars: [None; tessera_pci::MAX_BARS],
    parent: None,
};

/// The class byte the manager maps onto `DeviceClass::Block`.
pub(crate) const PCI_CLASS_MASS_STORAGE: u32 = 0x01;

/// The identity the root task's seeded bus wears, and it is the manager's
/// manifest that decides these three numbers rather than this port.
///
/// A bus node the manifest cannot identify is refused `PathUndeclared` rather
/// than treated as free — a manager charges a device's data path by the hubs
/// above it, and it can only do that for hubs it can name. These match the
/// near-hub entry in `userspace/device-manager`, which is the one that declares
/// a relay cost.
pub(crate) const PCI_BRIDGE_CLASS: u32 = 0x06_04_00;
pub(crate) const PCI_REDHAT_VENDOR: u16 = 0x1b36;
pub(crate) const PCI_NEAR_HUB_PRODUCT: u16 = 0x0001;

/// How far into its window the driver reads, and the kernel reads after it.
///
/// **Past the first page, deliberately.** A driver granted only its device's
/// first page would still pass a check that read at offset zero; this offset is
/// in the third page of the window, so agreeing with the kernel's read at the
/// same physical address means the whole window arrived.
pub(crate) const FAR_WINDOW_OFFSET: u64 = 0x2000;

/// Where this check maps the bound device's window to make that read. A kernel
/// address, mapped for the length of the comparison and taken down after — the
/// driver's own mapping is the one under test.
pub(crate) const PCI_FAR_READ_VA: u64 = 0xffff_a000_0000_0000;

/// Tags a driver's report as "this is what the kernel says the device is", so
/// the check cannot mistake a PCI identity for some other word. Must match
/// `blk-probe`'s constant of the same name.
pub(crate) const PCI_REPORT_TAG: u64 = 0x5043 << 48;

/// PCI configuration space through the legacy `0xCF8`/`0xCFC` port pair.
///
/// **This is why `drivers/pci` needed no change to run here.** `ConfigSpace` is
/// two methods over an ECAM-style byte offset, and ECAM's offset encoding is
/// just `bus:device:function:register` shifted — so the same offset a
/// memory-mapped implementation would add to a base is decoded back into the
/// address this port's host bridge wants. No ACAM window has to be found, no
/// ACPI table parsed, and no base hardcoded.
///
/// **Extended configuration space is out of reach here, and this says so
/// rather than aliasing.** The `0xCF8` address register has eight bits of
/// register number, so offsets at or past 0x100 cannot be expressed; wrapping
/// them into the first 256 bytes would answer a capability walk with the wrong
/// register and look entirely successful. Nothing this port reads lives there:
/// `find_capability` already bounds its chain to the 256-byte header.
pub(crate) struct PortConfigSpace;

/// The address and data ports of the mechanism-1 configuration pair.
pub(crate) const PCI_CONFIG_ADDRESS: u16 = 0xcf8;
pub(crate) const PCI_CONFIG_DATA: u16 = 0xcfc;
/// What a read of a register this mechanism cannot reach answers. The same
/// value the bus itself returns for a function that is not there, which is what
/// every caller already treats as "nothing here".
pub(crate) const PCI_CONFIG_UNREACHABLE: u32 = 0xffff_ffff;

impl PortConfigSpace {
    /// The `0xCF8` address word for an ECAM-style `offset`, or `None` when the
    /// offset names extended configuration space.
    fn address(offset: u64) -> Option<u32> {
        let register = offset & 0xfff;
        if register >= 0x100 {
            return None;
        }
        let bus = (offset >> 20) & 0xff;
        let device = (offset >> 15) & 0x1f;
        let function = (offset >> 12) & 0x7;
        Some(
            0x8000_0000
                | (bus as u32) << 16
                | (device as u32) << 11
                | (function as u32) << 8
                | (register as u32 & 0xfc),
        )
    }
}

impl tessera_pci::ConfigSpace for PortConfigSpace {
    fn read32(&self, offset: u64) -> u32 {
        let Some(address) = Self::address(offset) else {
            return PCI_CONFIG_UNREACHABLE;
        };
        // SAFETY: the configuration address/data pair is owned by this kernel
        // and by nothing else — no ring-3 program on this port can reach a port
        // at all, and the boot path is the boot CPU's alone, so no interleaved
        // writer can change the latched address between these two accesses.
        unsafe {
            tessera_karch_x86_64::outl(PCI_CONFIG_ADDRESS, address);
            tessera_karch_x86_64::inl(PCI_CONFIG_DATA)
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        let Some(address) = Self::address(offset) else {
            return;
        };
        // SAFETY: as for `read32` — the pair is this kernel's alone and the
        // address stays latched across the two writes.
        unsafe {
            tessera_karch_x86_64::outl(PCI_CONFIG_ADDRESS, address);
            tessera_karch_x86_64::outl(PCI_CONFIG_DATA, value);
        }
    }
}

/// The 32-bit window BARs are placed in on this machine.
///
/// q35 puts its ECAM at `0xb000_0000` and 512 MiB of RAM ends far below this,
/// so the region is bus address space rather than memory — but that is an
/// argument, not a check, which is why [`pci_window_is_clear`] runs before
/// anything is written.
pub(crate) const PCI_WINDOW_BASE: u64 = 0xc000_0000;
pub(crate) const PCI_WINDOW_LEN: u64 = 0x1000_0000;

/// Whether the BAR window overlaps anything the firmware called memory.
///
/// **Firmware has already assigned these BARs and this reassigns them**, which
/// is what `tessera_pci` does on every port — one code path rather than two.
/// The risk that creates is specific: a window chosen badly would have a device
/// decoding over RAM somebody else is using, and the failure would appear
/// arbitrarily later as corruption with no connection to PCI. So the window is
/// checked against the map the bootloader handed us, and enumeration is refused
/// rather than attempted if it overlaps.
pub(crate) fn pci_window_is_clear(map: &[MemoryRegion]) -> bool {
    let end = PCI_WINDOW_BASE + PCI_WINDOW_LEN;
    !map.iter().any(|region| {
        // Only usable RAM matters. A reserved region here is firmware saying
        // "not memory", which is exactly what a device window is.
        region.kind == MemoryKind::Usable
            && region.base.as_u64() < end
            && PCI_WINDOW_BASE < region.base.as_u64() + region.len
    })
}

/// The syscall surface a device manager and a driver need, routed to the shared
/// dispatcher.
///
/// **Every uniform arm delegates and none is reimplemented.** `kcore::dispatch`
/// is where channel IPC, capability transfer, `MapDevice`, `DeviceInfo` and the
/// lifecycle already live for the two ports that run this framework; a local
/// copy here would be a second implementation of semantics that are supposed to
/// be common, and the first divergence would show up as a port-specific bug in
/// a program neither port compiled differently.
///
/// Only the two genuinely local things stay: `DebugWrite`, which is how a
/// program reports into this port's sink, and `ProcessExit`, which has to reach
/// this port's scheduler.
pub(crate) fn driver_bind_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    let Some(caller_idx) = chan_current_id() else {
        return syscall::ENOSYS;
    };
    let Some(number) = SyscallNumber::from_u64(frame.number) else {
        return syscall::ENOSYS;
    };
    match number {
        SyscallNumber::DebugWrite => {
            let slot = BIND_REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
            if slot < BIND_REPORTS.len() {
                BIND_REPORTS[slot].store(frame.arg0, Ordering::SeqCst);
            }
            0
        }
        SyscallNumber::ProcessExit => chan_process_exit(caller_idx, frame.arg0 as i32),
        _ => {
            let req = SyscallRequest {
                number: frame.number,
                args: [
                    frame.arg0, frame.arg1, frame.arg2, frame.arg3, frame.arg4, frame.arg5,
                ],
            };
            // SAFETY: the boot CPU alone; EXEC/PROCESSES are populated before any
            // ring-3 thread runs and touched only on this CPU. The borrows are
            // built here and dropped at the end of the call, so none is parked
            // across the handoff a blocking channel op performs inside.
            let processes = unsafe { &mut *&raw mut PROCESSES };
            let mut router = PicRouter;
            let mut env = DispatchEnv {
                exec: exec_ref(),
                processes,
                caller: caller_idx,
                // The boot allocator, published for the run. A driver mapping
                // its register window needs page tables built inside the
                // syscall, which is the whole reason the other ports publish
                // theirs too.
                alloc: bind_frames(),
                // No IOMMU on this machine, so every DMA grant would be
                // unscoped — and says so rather than pretending (D121).
                iommu: None,
                irqs: Some(&mut router),
                clock: crate::loader::monotonic_nanos,
            };
            match dispatch(&mut env, &req) {
                DispatchOutcome::Return(value) => value,
                DispatchOutcome::Unhandled => syscall::ENOSYS,
            }
        }
    }
}

/// A contained user fault inside the bind check: vector, CR2, RIP, thread.
pub(crate) static BIND_FAULT: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
pub(crate) static BIND_FAULTED: AtomicBool = AtomicBool::new(false);

/// Contains a ring-3 fault taken inside the bind check.
///
/// **This check needs its own, and the reason is worth stating.** The handler
/// the single-process demos install drives `USER_PROCESS` and `USER_SCHEDULER`
/// — statics belonging to *that* demo's one process and one scheduler. A fault
/// here would find them stale, yield to a scheduler this check never populated,
/// and hang with nothing printed: the worst possible way to learn that a driver
/// touched something it should not have. So this one exits the faulting process
/// in *this* process table and blocks its thread, which returns control to the
/// boot context the same way an ordinary exit does.
pub(crate) fn bind_user_fault_handler(frame: &TrapFrame) -> ! {
    let cr2 = tessera_karch_x86_64::read_cr2();
    let thread = chan_current_index();
    BIND_FAULTED.store(true, Ordering::SeqCst);
    BIND_FAULT[0].store(frame.vector, Ordering::SeqCst);
    BIND_FAULT[1].store(cr2, Ordering::SeqCst);
    BIND_FAULT[2].store(frame.rip, Ordering::SeqCst);
    BIND_FAULT[3].store(thread.map_or(u64::MAX, |t| t as u64), Ordering::SeqCst);
    report_contained_fault(frame.vector, cr2);
    if let Some(caller) = thread {
        // SAFETY: the boot CPU alone; the tables are this check's own and quiescent
        // apart from the faulting thread, which is off-CPU from here on.
        let processes = unsafe { &mut *&raw mut PROCESSES };
        if let Some(process) = processes
            .process_of_thread(thread_id_of(caller).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        {
            process.exit(-1);
        }
        exec_ref().scheduler().block_current();
    }
    // Unreachable: `block_current` switched away and this thread never resumes.
    loop {
        core::hint::spin_loop();
    }
}

/// Where the bind check's ring-3 programs report, in the order they report.
///
/// Ordered rather than folded together, for the reason every other port's sink
/// is: the manager and the driver are two programs, and a single word they both
/// wrote into could not distinguish one of them failing from the other never
/// having run.
pub(crate) const MAX_BIND_REPORTS: usize = 4;
pub(crate) static BIND_REPORTS: [AtomicU64; MAX_BIND_REPORTS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
pub(crate) static BIND_REPORT_COUNT: AtomicU64 = AtomicU64::new(0);

/// The boot frame allocator, published for the syscall path's lifetime.
pub(crate) static mut BIND_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
    core::ptr::null_mut();

/// The published allocator, or a source that refuses. Never `None`: a syscall
/// arriving with no allocator is a bug in the boot glue, and answering
/// `NoFrames` makes it fail where it happened.
pub(crate) fn bind_frames() -> &'static mut dyn FrameSource {
    // SAFETY: the boot CPU alone; set before the ring-3 threads run and cleared after
    // the last one is off-CPU.
    let published = unsafe { *(&raw const BIND_FRAMES) };
    if published.is_null() {
        // SAFETY: `NoFrames` is a zero-sized refusing source; the static
        // reference is valid for the program's lifetime.
        return unsafe { &mut *(&raw mut BIND_NO_FRAMES) };
    }
    // SAFETY: the pointer was published from a live borrow that outlives the
    // run, and only this CPU dereferences it.
    unsafe { &mut *published }
}

pub(crate) static mut BIND_NO_FRAMES: NoFrames = NoFrames;

/// Kernel stack pages for a bind-check program. Eight, because a channel
/// operation parks a whole dispatch frame across the handoff.
pub(crate) const BIND_KSTACK_PAGES: u64 = 8;

/// Loads an ELF into a fresh address space and adds its initial thread.
///
/// **The first compiled ring-3 program on this port.** Everything ring 3 here
/// has been a hand-written `global_asm!` blob copied to a fixed address; this is
/// the sequence `loader_demo` performs on the root task, made a function so two
/// programs can use it, and shaped like the helper of the same name on the two
/// ports that already run the framework.
///
/// Returns the thread's scheduler index and the process's table index — two
/// different numbers, and releasing one without the other is the mistake
/// `Process::forget_thread` exists for.
pub(crate) fn spawn_elf_process(
    image: &[u8],
    arg: usize,
    process_obj: ObjectId,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    let parsed = elf::parse(image, elf::Machine::X86_64).map_err(|_| base_err)?;
    // W^X, checked here rather than trusted from the linker script: a segment
    // that is writable and executable is refused however it got that way.
    if parsed.segments().iter().any(|seg| seg.write && seg.exec) {
        return Err(base_err + 1);
    }

    let user_arch = kernel_vm
        .arch()
        .new_user(frames)
        .map_err(|_| base_err + 2)?;
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(
        user_arch,
        alloc_asid(),
        1u64 << kcore::percpu::current_index(),
    );
    let mut process = Process::new(process_obj, user_vm);

    // Reserve every segment writable to receive its bytes; the W^X protections
    // go on after the copy, which is the only order that works when the copy is
    // what makes the text executable.
    for seg in parsed.segments() {
        let (base, pages) = elf_seg_pages(seg);
        process
            .space_mut()
            .map_anonymous(
                VirtAddr::new(base),
                pages * FRAME_SIZE,
                PageFlags::rw().user(),
                frames,
            )
            .map_err(|_| base_err + 3)?;
    }

    let thread = Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(parsed.entry()),
        arg,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(BIND_KSTACK_PAGES),
        BIND_KSTACK_PAGES,
        process_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    )
    .map_err(|_| base_err + 4)?;
    let thread_idx = exec_ref().add_thread(thread).map_err(|_| base_err + 5)?;
    process
        .add_thread(thread_id_of(thread_idx).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        .map_err(|_| base_err + 6)?;

    // The copy happens with the target space active: this port has no
    // higher-half alias of another process's user pages, so the bytes go in
    // through the addresses the program will itself run at.
    // SAFETY: the user space shares the kernel higher half, so this boot code,
    // its stack and the direct map stay mapped across the switch.
    unsafe { process.space().activate(kcore::percpu::current_index()) };
    for seg in parsed.segments() {
        let src = image[seg.file_offset as usize..].as_ptr();
        // SAFETY: `parse` bounds-checked `[file_offset, file_offset+file_size)`
        // against the image, and the destination pages were mapped writable
        // above in the space that is now active.
        unsafe {
            // The kernel means to reach a user page here: it is populating a
            // process it is building, in that process's own space. Declared
            // rather than assumed, because SMAP now faults an undeclared one.
            // SAFETY: the destination is a page this boot glue just mapped
            // into the space it activated; the window permits reaching it.
            {
                let _access = kcore::useraccess::Window::open();
                core::ptr::copy_nonoverlapping(src, seg.vaddr as *mut u8, seg.file_size as usize);
            }
            let bss = (seg.mem_size - seg.file_size) as usize;
            if bss > 0 {
                // The tail of the same user segment, zeroed.
                // SAFETY: the target space is active and the range was just
                // mapped; the window permits reaching it.
                let _access = kcore::useraccess::Window::open();
                core::ptr::write_bytes((seg.vaddr + seg.file_size) as *mut u8, 0, bss);
            }
        }
    }
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    for seg in parsed.segments() {
        let (base, pages) = elf_seg_pages(seg);
        process
            .space_mut()
            .protect_range(VirtAddr::new(base), pages * FRAME_SIZE, elf_seg_rights(seg))
            .map_err(|_| base_err + 7)?;
    }

    process.set_running();
    let process_idx = processes_insert(process).map_err(|_| base_err + 8)?;
    Ok((thread_idx, process_idx))
}

/// The q35 host bridge's `PCIEXBAR`, at `0:0.0` configuration offset `0x60`.
///
/// **Where this port learns that ECAM exists at all.** It reaches configuration
/// space through the `0xCF8`/`0xCFC` pair, which is why `tessera_pci::Host` here
/// records an ECAM base of zero: the "window" is an encoding, not memory. A
/// ring-3 bus controller cannot use ports — it holds no I/O authority and there
/// is no capability shaped like one — so the memory-mapped window has to be
/// found before anything can be handed over. The chipset says where it put it.
pub(crate) const PCIEXBAR: u16 = 0x60;

/// The ECAM window's physical base, or `None` when the chipset says it is
/// disabled.
///
/// Refused rather than guessed. QEMU's q35 enables it and puts it at
/// `0xb0000000`, but a machine that says otherwise means it, and a controller
/// handed a window nothing decodes would read all-ones and declare a bus with
/// nothing on it — which is indistinguishable from a bus with nothing on it.
pub(crate) fn ecam_base(
    host: &tessera_pci::Host,
    cfg: &dyn tessera_pci::ConfigSpace,
) -> Option<u64> {
    let root = tessera_pci::Bdf::new(0, 0, 0)?;
    let low = host.read(cfg, root, PCIEXBAR).ok()?;
    // Bit 0 enables the window; bits 2:1 size it; the rest is the base.
    if low & 1 == 0 {
        return None;
    }
    // The upper half addresses windows above 4 GiB, which this port's mapping
    // path does not reach. Reported as absent rather than truncated into range.
    if host.read(cfg, root, PCIEXBAR + 4).ok()? != 0 {
        return None;
    }
    Some(u64::from(low & !0xfff))
}

pub(crate) const PCI_BUS_OBJ: ObjectId = ObjectId::from_raw(0xe0);
pub(crate) const PCI_BUS_MANAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0xe1);
pub(crate) const PCI_BUS_MANAGER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0xe2);
pub(crate) const PCI_BUS_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0xe3);
pub(crate) const PCI_BUS_DRIVER_PROC_OBJ: ObjectId = ObjectId::from_raw(0xe4);
pub(crate) const PCI_BUS_PROBE_PROC_OBJ: ObjectId = ObjectId::from_raw(0xe5);

/// How much configuration space the bus controller is granted: eight buses,
/// which is `kcore::dispatch::MAX_BUS_WINDOW_BYTES`.
pub(crate) const PCI_BUS_CONFIG_LEN: u64 = 0x80_0000;
pub(crate) const PCI_BUS_COUNT: u8 = 8;

/// The startup argument asking `blk-probe` to report what its own configuration
/// space says it is. Must match `CONFIG_REPORT` there.
pub(crate) const BLK_PROBE_CONFIG_REPORT: usize = 1 << 59;

/// What the bus-driver check produced.
pub(crate) struct BusOutcome {
    /// Functions the ring-3 walk found and declared.
    pub(crate) functions: u64,
    /// The vendor/device word the driver read out of its own configuration
    /// space, which must be what the kernel's independent walk found.
    pub(crate) word: u32,
}

/// Proves **PCI enumeration outside the kernel** on this port — the same ring-3
/// program the AArch64 port runs, against a machine whose configuration space
/// the kernel reaches through I/O ports.
///
/// That difference is the point. The kernel walks through `0xCF8`/`0xCFC`; the
/// controller walks through the memory-mapped window the chipset reports; and
/// the two must agree about the same function. Neither can produce the other's
/// answer by echoing it.
pub(crate) fn pci_bus_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<BusOutcome>, u32> {
    use kcore::rights::Rights;

    if components::pci_bus().is_empty() || components::blk_probe().is_empty() {
        return Ok(None);
    }
    if !pci_window_is_clear(memory_map) {
        return Err(1);
    }
    let ports = tessera_pci::Host {
        ecam_base: 0,
        ecam_len: 0x1000_0000,
        first_bus: 0,
        last_bus: 0,
    };
    let mut config = PortConfigSpace;
    let Some(ecam) = ecam_base(&ports, &config) else {
        return Ok(None);
    };
    // The kernel's own walk, which the controller's is checked against.
    let window = tessera_pci::Window {
        cpu_base: PCI_WINDOW_BASE,
        bus_base: PCI_WINDOW_BASE,
        len: PCI_WINDOW_LEN,
        is_32bit: true,
    };
    let mut functions = [PCI_BLANK_FUNCTION; MAX_PCI_FUNCTIONS];
    let found =
        tessera_pci::enumerate(&ports, &mut config, window, &mut functions).map_err(|_| 2u32)?;
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.class_code >> 16 == PCI_CLASS_MASS_STORAGE)
    else {
        return Ok(None);
    };
    let word = u32::from(function.vendor) | (u32::from(function.device) << 16);

    // SAFETY: the boot CPU alone; a fresh table and executive for this check, and
    // the previous demo's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    // The bridge, as a device whose register window *is* configuration space.
    exec_ref()
        .device_register_mmio(
            PCI_BUS_OBJ,
            ecam,
            PCI_BUS_CONFIG_LEN,
            Rights::READ
                | Rights::WRITE
                | Rights::MAP
                | Rights::DERIVE
                | Rights::CONFIGURE
                | Rights::TRANSFER,
        )
        .map_err(|_| 3u32)?;
    exec_ref()
        .device_set_bus_window(
            PCI_BUS_OBJ,
            kcore::devmgr::BusWindow {
                config_len: PCI_BUS_CONFIG_LEN,
                forward_cpu_base: PCI_WINDOW_BASE,
                forward_bus_base: PCI_WINDOW_BASE,
                forward_len: PCI_WINDOW_LEN,
                first_bus: 0,
                last_bus: PCI_BUS_COUNT - 1,
                // A PCI bridge forwards memory and no wires: its functions interrupt by
                // message, through a different door.
                first_intid: 0,
                intid_count: 0,
            },
        )
        .map_err(|_| 4u32)?;

    let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| 5u32)?;
    exec_ref().bind_endpoint_object(server_ep, PCI_BUS_MANAGER_SERVER_OBJ);
    exec_ref().bind_endpoint_object(client_ep, PCI_BUS_MANAGER_CLIENT_OBJ);

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(driver_bind_syscall_handler) };
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'static> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe { BIND_FRAMES = frames_ptr };

    // The manager holding **nothing**: its startup argument is zero device
    // capabilities, which is the whole point. Everything it ends up with
    // arrives from the bus driver.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::device_manager(),
        0,
        PCI_BUS_MANAGER_PROC_OBJ,
        kernel_vm,
        frames,
        10,
    )?;
    // SAFETY: the boot CPU alone; the process table is quiescent between spawns.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(manager_proc)
            .ok_or(20u32)?
            .handles_mut()
            .install(PCI_BUS_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 21u32)?;
    }
    let (driver_thread, driver_proc) = spawn_elf_process(
        components::pci_bus(),
        0,
        PCI_BUS_DRIVER_PROC_OBJ,
        kernel_vm,
        frames,
        30,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *&raw mut PROCESSES;
        let driver = processes.get_mut(driver_proc).ok_or(40u32)?;
        driver
            .handles_mut()
            .install(PCI_BUS_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 41u32)?;
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
            .map_err(|_| 42u32)?;
    }
    let (probe_thread, probe_proc) = spawn_elf_process(
        components::blk_probe(),
        BLK_PROBE_CONFIG_REPORT,
        PCI_BUS_PROBE_PROC_OBJ,
        kernel_vm,
        frames,
        50,
    )?;
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(probe_proc)
            .ok_or(60u32)?
            .handles_mut()
            .install(PCI_BUS_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 61u32)?;
    }

    // Everything here is cooperative — a send, a call, a reply, an exit — so
    // the scheduler runs to quiescence without a tick to prod it.
    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    unsafe { BIND_FRAMES = core::ptr::null_mut() };

    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(70);
    }
    let bus_report = BIND_REPORTS[0].load(Ordering::SeqCst);
    let probe_report = BIND_REPORTS[1].load(Ordering::SeqCst);
    if bus_report >> 56 != 0x50 {
        return Err(71);
    }
    let walked = (bus_report >> 8) & 0xff;
    if walked == 0 || bus_report & 0xff != walked {
        return Err(72);
    }
    if probe_report >> 56 != 0x43 {
        return Err(73);
    }
    if probe_report & 0xffff_ffff != u64::from(word) {
        return Err(74);
    }
    if probe_report & (1 << 48) == 0 {
        return Err(75);
    }

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [probe_thread, driver_thread, manager_thread] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for (_thread, process) in [
            (probe_thread, probe_proc),
            (driver_thread, driver_proc),
            (manager_thread, manager_proc),
        ] {
            if let Some(mut gone) = processes.remove(process) {
                gone.space_mut().teardown(frames);
            }
        }
    }
    Ok(Some(BusOutcome {
        functions: walked,
        word,
    }))
}
