// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The user-space loader: create, populate and start a child from ring 3.
//!
//! The docs' "kernel maps, user-space loads" model (docs/api/01) — the parent
//! syscalls `ProcessCreate` -> `AddressSpaceMap` -> `ProcessStart` and resumes when
//! the child exits. The unified dispatcher every ring-3 check installs is here.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- M14 loader: caller resolution, syscall handler, exit/fault handback ---

/// The unified ring-3 syscall dispatcher for the executive substrate. Every demo
/// that runs ring-3 processes on `EXEC` installs this one handler; it resolves the
/// caller from `PROCESSES` by the running thread (`chan_current_index`), so a
/// parent and the child/peer it creates share one dispatcher. Ops a given demo
/// never issues simply never fire. It covers, over the one `EXEC`/`PROCESSES`/
/// `OBJECTS` substrate: process lifecycle (`ProcessCreate`/`AddressSpaceMap`/
/// `ProcessStart` — the ring-3 loader, D42), channel IPC (`ChannelRecv`/`Call`/
/// `Reply`, M15), ports (`PortCreate`/`Bind`/`Wait`, M16), and capability-gated
/// device I/O (`DeviceIoRead`/`Write`, M16). It dispatches by the running
/// thread, which is what makes one handler enough for every check (D300).
///
/// Each arm borrows the process/object tables *locally* (never a handler-wide
/// borrow): the channel/port ops re-borrow `PROCESSES` internally, and a child's
/// re-entrant `ProcessExit` during `loader_process_start`'s handoff borrows it
/// again — one CPU, cooperative, so only one such borrow is ever dereferenced
/// at a time (the `exec_ref()` SAFETY note).
/// This port's process table.
///
/// **One access point rather than one per call site.** Every reach for a
/// `static mut` here is `(*(&raw mut TABLE))`, which clippy flags and whose
/// suggested fix edition 2024 forbids — so `tools/ci/arch-lint-baseline.txt`
/// says the answer is to funnel them through a helper rather than to raise the
/// count. This is that helper for the root-task path.
///
/// # Safety
///
/// The boot CPU alone. `PROCESSES` is populated before any ring-3 thread runs
/// and touched only on this CPU; the returned borrow is used and dropped
/// within one syscall, never held across a scheduler handoff.
pub(crate) fn root_processes() -> &'static mut ProcessTable<KernelAddressSpace> {
    // SAFETY: as the doc comment states — the boot CPU alone, and the borrow
    // does not outlive the call that took it.
    unsafe { &mut *&raw mut PROCESSES }
}

/// This port's object table, for the same reason and under the same rule as
/// [`root_processes`].
///
/// # Safety
///
/// The boot CPU alone; `OBJECTS` is touched only on this CPU.
pub(crate) fn root_objects() -> &'static mut ObjectTable {
    // SAFETY: as the doc comment states.
    unsafe { &mut *&raw mut OBJECTS }
}

/// What the root task's run records: the word each `DebugWrite` reported.
///
/// **Because a report word is not a string.** A program reporting a *value*
/// passes it in the pointer register with a length of zero, so the text path
/// prints nothing and the number would be lost — which is why the argument
/// register is read before anything tries to follow it (the same reading
/// AArch64 makes into `EL0_REPORTS`).
///
/// Read on the way in, so a report is recorded whether or not the write behind
/// it succeeded.
pub(crate) fn root_observer(
    phase: crate::syscalls::Phase,
    number: SyscallNumber,
    frame: &SyscallFrame,
) {
    if !matches!(phase, crate::syscalls::Phase::Entered) || number != SyscallNumber::DebugWrite {
        return;
    }
    let slot = ROOT_REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
    if let Some(cell) = ROOT_REPORTS.get(slot) {
        cell.store(frame.arg0, Ordering::SeqCst);
    }
}

/// **This port's one ring-3 syscall handler.**
///
/// Every check that runs a ring-3 program on the executive substrate installs
/// this, and there is nothing else to install. Each of the other four ports has
/// had one such function since it grew a substrate — AArch64's
/// `el0_dispatch_hook` (D79), RISC-V's `user_dispatch_hook` (D101) — beside a
/// pre-substrate bring-up hook that answers only its own two calls. This port
/// had **eight**, because its checks arrived one at a time and each brought a
/// process substrate of its own and therefore a handler of its own: eight
/// functions answering overlapping subsets of one ABI, which is how
/// `HandleDuplicate` and `PageSupply` came to mean two things in one tree
/// (D298).
///
/// The shape is the shared one. Resolve the caller by the running thread, hand
/// the request to `kcore::dispatch`, and keep only what this machine alone can
/// answer:
///
/// - `DebugWrite` and `ProcessExit`, which reach this port's console sink and
///   this port's scheduler.
/// - The three-phase loader (`ProcessCreate`/`AddressSpaceMap`/`ProcessStart`)
///   and `ProcessWait`, which run in `kcore::loader` behind a seam this port
///   fills with an address-space factory and its kstack windows (D251).
/// - `DeviceIoRead`/`DeviceIoWrite`: `in`/`out` instructions, as port-local as
///   `IrqComplete` is on AArch64. No other machine in this tree has them.
/// - `PageServe`/`PageSupply`, the M18 filesystem check's page-in protocol,
///   **and only while that check is running**. This is the one arm here that
///   shadows a shared one, and the reason is recorded rather than hidden:
///   `kcore::dispatch::page_supply` fills a paged *memory object* the executive
///   registered through `MemoryCreatePaged`, and this check's object is one the
///   boot glue minted and mapped by hand. Moving it is moving the check onto
///   the executive's pager registry, which changes what the check demonstrates
///   (D300). What changed is which of the two answers: routing it here for the
///   whole boot was invisible until a ring-3 service paged a real object and
///   had its `PageSupply` refused by a handler holding a different check's
///   pending fault (D325), so the check now takes these two numbers and gives
///   them back.
///
/// What a check adds is an [`Observer`](crate::syscalls::Observer), told what
/// was called and what it answered. It cannot change either.
pub(crate) fn syscall_handler(frame: &mut SyscallFrame) -> i64 {
    USER_RING3_REACHED.store(true, Ordering::Relaxed);
    USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);

    let Some(caller_idx) = chan_current_id() else {
        return syscall::ENOSYS;
    };
    let number = match SyscallNumber::from_u64(frame.number) {
        Some(number) => number,
        None => return syscall::ENOSYS,
    };
    crate::syscalls::entering(number, frame);
    // The local arms are decided *before* the dispatcher runs, not after it
    // declines: `PageSupply` is one the dispatcher would answer, and a
    // fall-through would send this port's page-in protocol somewhere that
    // cannot serve it.
    let local_pager = crate::fs::pager_syscalls_are_local()
        && matches!(number, SyscallNumber::PageServe | SyscallNumber::PageSupply);
    if !local_pager
        && !matches!(
            number,
            SyscallNumber::DebugWrite
                | SyscallNumber::ProcessExit
                | SyscallNumber::ProcessCreate
                | SyscallNumber::AddressSpaceMap
                | SyscallNumber::ProcessStart
                | SyscallNumber::ProcessWait
                | SyscallNumber::DeviceIoRead
                | SyscallNumber::DeviceIoWrite
        )
    {
        let shared = match crate::syscalls::shared(caller_idx, frame) {
            DispatchOutcome::Return(value) => value,
            DispatchOutcome::Unhandled => syscall::ENOSYS,
        };
        return crate::syscalls::answer(number, frame, shared);
    }

    let local = match number {
        SyscallNumber::DebugWrite => match root_processes().process_of_thread(caller_idx) {
            Some(process) => user_debug_write(process, frame.arg0, frame.arg1),
            None => syscall::ENOSYS,
        },
        SyscallNumber::ProcessExit => chan_process_exit(caller_idx, frame.arg0 as i32),
        SyscallNumber::PageServe => crate::fs::fs_page_serve(caller_idx, frame.arg0),
        SyscallNumber::PageSupply => crate::fs::fs_page_supply(caller_idx, frame.arg0),
        // Capability-gated port I/O: `in`/`out` instructions.
        SyscallNumber::DeviceIoRead => driver_device_io(caller_idx, frame.arg0, frame.arg1, None),
        SyscallNumber::DeviceIoWrite => {
            driver_device_io(caller_idx, frame.arg0, frame.arg1, Some(frame.arg2 as u8))
        }
        // The process lifecycle, in `kcore::loader`. What stays here is the
        // routing and the seam: this port lends an address-space factory, its
        // kernel half and its kstack windows, and nothing else (D251).
        _ => {
            let mut support = X86Loader;
            let mut env = kcore::loader::LoaderEnv {
                support: &mut support,
                objects: root_objects(),
            };
            let processes = root_processes();
            // The allocator this check lent the syscall path, through the one
            // seam every handler here takes it from (D299).
            let alloc: &mut dyn FrameSource = crate::syscalls::frames();
            // The two counters are this port's boot-check instrumentation and
            // stay here: what a run produced is the check's question, not the
            // mechanism's. Counted on the *result* rather than on entry, so a
            // refused start is not a launch.
            match number {
                SyscallNumber::ProcessCreate => {
                    kcore::loader::create(&mut env, processes, alloc, caller_idx, frame.arg0)
                }
                SyscallNumber::AddressSpaceMap => kcore::loader::address_space_map(
                    &mut env, processes, alloc, caller_idx, frame.arg0,
                ),
                SyscallNumber::ProcessStart => {
                    let result = kcore::loader::start(
                        &mut env,
                        exec_ref(),
                        processes,
                        alloc,
                        caller_idx,
                        frame.arg0,
                    );
                    if result >= 0 {
                        CHILD_LAUNCHES.fetch_add(1, Ordering::Relaxed);
                    }
                    result
                }
                _ => {
                    let result = kcore::loader::wait(
                        &mut env,
                        exec_ref(),
                        processes,
                        alloc,
                        caller_idx,
                        frame.arg0,
                    );
                    if result >= 0 {
                        LOADER_PARENT_RESUMED.store(true, Ordering::Relaxed);
                    }
                    result
                }
            }
        }
    };
    crate::syscalls::answer(number, frame, local)
}

/// The loader demo's ring-3 fault handler: contains the fault (terminate the
/// faulting process, D23) and — like `loader_process_exit` — hands back to a
/// waiting parent so a faulting child cannot strand it, or switches to boot.
pub(crate) fn loader_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    USER_FAULT_ADDR.store(tessera_karch_x86_64::read_cr2(), Ordering::Relaxed);
    report_contained_fault(frame.vector, tessera_karch_x86_64::read_cr2());
    let caller_idx = chan_current_id();
    // SAFETY: the boot CPU alone; statics set before the ring-3 thread runs.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    if let Some(idx) = caller_idx
        && let Some(process) = processes.process_of_thread(idx)
    {
        process.exit(-1);
    }
    // SAFETY: the boot CPU alone; PARENT_WAITER only set by `ProcessStart` on this CPU.
    let waiter = unsafe { (*&raw mut PARENT_WAITER).take() };
    // SAFETY: the boot CPU alone; EXEC is set before the ring-3 thread runs.
    match unsafe { (*&raw mut EXEC).as_mut() } {
        Some(exec) => {
            let scheduler = exec.scheduler();
            match waiter {
                Some(parent) => {
                    LOADER_CHILD_EXIT.store(-1, Ordering::Relaxed);
                    LOADER_CHILD_RAN.store(true, Ordering::Relaxed);
                    scheduler.handoff_to(parent);
                }
                None => scheduler.yield_to_boot(),
            }
        }
        None => DebugExit::exit(ExitCode::Failure),
    }
    // A handback/boot switch left this context; it never resumes.
    loop {
        core::hint::spin_loop();
    }
}

/// Maps the ISL `Rights` bits used by the loader onto neutral `PageFlags`. Every
/// mapped page is user-accessible; read/write/execute follow the requested bits.
/// The kernel rejects a writable+executable result (W^X) at the call site.
// Unused since the loader moved into `kcore` (D251): the shared path derives
// the same flags. Kept because this is where the mapping from ISL `Rights` to
// neutral `PageFlags` is written down, and the W^X rule below reads against it.
#[allow(dead_code)]
pub(crate) fn rights_to_pageflags(rights: Rights) -> PageFlags {
    let mut flags = PageFlags::none().user();
    if rights.contains(Rights::READ) {
        flags = flags.read();
    }
    if rights.contains(Rights::WRITE) {
        flags = flags.write();
    }
    if rights.contains(Rights::EXECUTE) {
        flags = flags.execute();
    }
    flags
}

/// The page range covering `[vaddr, vaddr + mem_size)`, rounded out to whole
/// pages: `(page_base, page_count)`.
pub(crate) fn elf_seg_pages(seg: &elf::Segment) -> (u64, u64) {
    let page_base = seg.vaddr & !(FRAME_SIZE - 1);
    let end = seg.vaddr + seg.mem_size;
    let page_end = (end + FRAME_SIZE - 1) & !(FRAME_SIZE - 1);
    (page_base, (page_end - page_base) / FRAME_SIZE)
}

/// The final page rights for a loaded segment: user + read, plus execute or
/// write per the segment flags. W^X holds by construction — the loader rejects a
/// write+execute segment before calling this.
pub(crate) fn elf_seg_rights(seg: &elf::Segment) -> PageFlags {
    let mut flags = PageFlags::none().read().user();
    if seg.exec {
        flags = flags.execute();
    }
    if seg.write {
        flags = flags.write();
    }
    flags
}

/// The machine's mass-storage PCI function: its biggest memory BAR and the
/// identity the kernel classified it by.
///
/// **Enumeration stays in the kernel, and that is not a compromise.** A PCI
/// function says what it is in configuration space, which is not per-device: a
/// capability to it would be authority over every function behind the bridge at
/// once, so there is nothing to hand a ring-3 enumerator. The kernel reads it,
/// normalizes what it found into the resource graph, and hands out a capability
/// naming one function — which is what a manager then classifies without
/// touching it (D114).
///
/// `None` is a machine with no such function attached, which is an answer and
/// not a failure.
pub(crate) fn pci_block_function(
    memory_map: &[MemoryRegion],
) -> Result<Option<(u64, u64, kcore::devmgr::DeviceIdentity)>, u32> {
    // Refusing beats placing a BAR over somebody's RAM and finding out later.
    if !pci_window_is_clear(memory_map) {
        return Err(1);
    }
    let host = tessera_pci::Host {
        // The offset encoding `PortConfigSpace` decodes, not a window anything
        // maps: this port reaches configuration space through ports, so the
        // "ECAM base" is zero and the length is the space the encoding spans.
        ecam_base: 0,
        ecam_len: 0x1000_0000,
        first_bus: 0,
        last_bus: 0,
    };
    let window = tessera_pci::Window {
        cpu_base: PCI_WINDOW_BASE,
        bus_base: PCI_WINDOW_BASE,
        len: PCI_WINDOW_LEN,
        is_32bit: true,
    };
    let mut config = PortConfigSpace;
    let mut functions = [PCI_BLANK_FUNCTION; MAX_PCI_FUNCTIONS];
    let found =
        tessera_pci::enumerate(&host, &mut config, window, &mut functions).map_err(|_| 2u32)?;

    // The one class this machine offers that the manager maps to `Block`.
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.class_code >> 16 == PCI_CLASS_MASS_STORAGE)
    else {
        return Ok(None);
    };
    // **The biggest memory BAR, not the lowest-indexed one.** `first_bar` is
    // the first BAR the function implements, and on a virtio-pci function that
    // is the MSI-X table — a single page. A driver granted that reaches a
    // window it cannot find its configuration structures in, and the read past
    // the first page that proves the *whole* window arrived faults instead.
    // AArch64 resolves the virtio capabilities to pick the right one; this port
    // has no capability walk yet, so it takes the largest, which on every
    // function this machine presents is the same BAR.
    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
        return Err(3);
    };
    if bar_len <= FAR_WINDOW_OFFSET {
        // Refused rather than checked at offset zero: a window too small to
        // read past its first page cannot show that the whole of it arrived,
        // and quietly moving the read would test one page and claim the rest.
        return Err(4);
    }
    Ok(Some((
        bar_base,
        bar_len,
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
    )))
}

/// The user-space loader demo (M14, closes D42's ring-3 gap): the kernel loads
/// the root-task ELF and runs it in ring 3 as the **parent/loader** (proving the
/// three-phase ELF load, D25), and the root task then drives `ProcessCreate` →
/// `AddressSpaceMap` → `ProcessStart` to create, populate, and start a **child
/// process** from user space — the docs' "kernel maps, user-space loads" model
/// (docs/api/01, "the loader operation"). The parent and child share one
/// scheduler; the parent hands off to the child it starts and resumes when the
/// child exits.
pub(crate) fn loader_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) {
    let image = components::root_task();
    if image.is_empty() {
        return kprintln!(
            "loader: skipped (no embedded ELF image; a profile turned it off, or the cargo inner loop)"
        );
    }
    let parsed = match elf::parse(image, elf::Machine::X86_64) {
        Ok(parsed) => parsed,
        Err(e) => return kprintln!("loader: FAIL — ELF parse rejected: {e:?}"),
    };
    // W^X: no loaded segment may be writable and executable (docs/kernel/03).
    for seg in parsed.segments() {
        if seg.write && seg.exec {
            return kprintln!("loader: FAIL — W+X segment at {:#x} rejected", seg.vaddr);
        }
    }

    // SAFETY: one-shot registration before this ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    crate::syscalls::set_observer(root_observer);
    set_user_fault_handler(loader_fault_handler);
    // Taken before anything runs, so the draw below is this run's and not the
    // boot's — which is what makes a bound on it mean anything.
    let frames_before = frames.handed_out();
    CHILD_LAUNCHES.store(0, Ordering::Relaxed);
    // Fresh tables, like every other check that runs late. Forty-five launches
    // need process and object slots, and by this point in the boot the earlier
    // checks have filled both — the first `ProcessCreate` was refused with a
    // resource error, which is not a statement about this mechanism.
    // SAFETY: the boot CPU alone; no ring-3 thread from an earlier check is
    // runnable, and the tables are rebuilt below before anything uses them.
    unsafe {
        PROCESSES = ProcessTable::new();
        OBJECTS = ObjectTable::new();
    }
    USER_RING3_REACHED.store(false, Ordering::Relaxed);
    LOADER_CHILD_RAN.store(false, Ordering::Relaxed);
    LOADER_PARENT_RESUMED.store(false, Ordering::Relaxed);
    LOADER_CHILD_EXIT.store(i32::MIN, Ordering::Relaxed);
    // Publish the boot kernel space + allocator so the loader syscalls (running
    // in trap context) can create child spaces and map into them.
    // SAFETY: the boot CPU alone; `_start` never returns, so these outlive every use.
    unsafe {
        LOADER_KERNEL_VM = core::ptr::from_mut(kernel_vm);
    }
    crate::syscalls::publish_frames(frames);

    // Phase 1 — create the parent (root-task) process and its address space.
    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => return kprintln!("loader: FAIL — new_user: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(
        user_arch,
        alloc_asid(),
        1u64 << kcore::percpu::current_index(),
    );
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => return kprintln!("loader: FAIL — process object: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    // Seed the parent with a job handle carrying `create-process` authority — the
    // gate `ProcessCreate` checks (docs/security/01). Deterministically the first
    // handle (raw 0); the root task passes it as the create job.
    let job_obj = match objects.create(ObjectType::Job) {
        Ok(id) => id,
        Err(e) => return kprintln!("loader: FAIL — job object: {e:?}"),
    };
    let job_handle = match process
        .handles_mut()
        .insert(job_obj, Rights::CREATE_PROCESS)
    {
        Ok(handle) => handle,
        Err(e) => return kprintln!("loader: FAIL — seed job handle: {e:?}"),
    };

    // **The second seed: a bus, with this machine's real mass-storage function
    // behind it.** The composition that used to be `driver_bind_check` — 234
    // lines of boot glue creating a channel, spawning a manager and a driver,
    // and reaching into both their handle tables — is the root task's now
    // (build/README.md, D256). What stays here is the part no capability could
    // replace: enumerating configuration space, and naming what was found.
    //
    // The bus carries the near hub's identity because that is what the
    // manager's manifest declares a relay cost for, and the function hangs
    // beneath it — so the manager derives the device from a bus it was handed
    // rather than being given the device, which is the whole difference between
    // a framework and a wiring diagram.
    let bus_obj = ObjectId::from_raw(0xd8);
    let device_obj = ObjectId::from_raw(0xd9);
    let seeded_device = match pci_block_function(memory_map) {
        Ok(found) => found,
        Err(which) => return kprintln!("loader: FAIL — PCI enumeration: check {which}"),
    };
    ROOT_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &ROOT_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    let bus_rights = Rights::READ | Rights::DERIVE;
    if seeded_device.is_some()
        // `TRANSFER` on top of what the manager will hold: handing a capability
        // on is itself an authority, and this is the process that hands it on.
        && process
            .handles_mut()
            .insert(bus_obj, bus_rights | Rights::TRANSFER)
            .is_err()
    {
        return kprintln!("loader: FAIL — seed bus handle");
    }

    // Phase 2a — reserve each PT_LOAD segment's pages writable, to receive bytes.
    let seg_count = parsed.segments().len();
    for seg in parsed.segments() {
        let (base, pages) = elf_seg_pages(seg);
        if process
            .space_mut()
            .map_anonymous(
                VirtAddr::new(base),
                pages * FRAME_SIZE,
                PageFlags::rw().user(),
                frames,
            )
            .is_err()
        {
            return kprintln!("loader: FAIL — map segment at {base:#x}");
        }
    }

    // Spawn the parent's initial thread at the ELF entry point.
    let thread = match Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(parsed.entry()),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(LOADER_PARENT_KSTACK_PAGES),
        LOADER_PARENT_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => return kprintln!("loader: FAIL — spawn_user: {e:?}"),
    };
    // SAFETY: the boot CPU alone; initializing the shared executive.
    unsafe { exec_restart(1) };

    // **The resource graph, after the restart and not before it.** `exec_restart`
    // builds a fresh Executive, and the device graph lives inside it — so
    // registrations made earlier in this function are simply gone by here. That
    // is how this check first came to seed a bus the root task could not find:
    // the handle was in its table and the object behind it named nothing.
    if let Some((bar_base, bar_len, identity)) = seeded_device {
        if exec_ref()
            .device_register_identified(
                bus_obj,
                0,
                0,
                bus_rights,
                kcore::devmgr::DeviceIdentity {
                    class_code: PCI_BRIDGE_CLASS,
                    vendor: PCI_REDHAT_VENDOR,
                    device: PCI_NEAR_HUB_PRODUCT,
                    bdf: 0,
                    revision: 0,
                    bus: kcore::devmgr::DeviceBus::Pci,
                },
            )
            .is_err()
        {
            return kprintln!("loader: FAIL — register bus");
        }
        if exec_ref()
            .device_register_identified(
                device_obj,
                bar_base,
                bar_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
                identity,
            )
            .is_err()
        {
            return kprintln!("loader: FAIL — register device");
        }
        if exec_ref().device_set_parent(device_obj, bus_obj).is_err() {
            return kprintln!("loader: FAIL — device parent");
        }
    }

    let thread_idx = match exec_ref().add_thread(thread) {
        Ok(idx) => idx,
        Err(_) => return kprintln!("loader: FAIL — add_thread"),
    };
    if process
        .add_thread(thread_id_of(thread_idx).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        .is_err()
    {
        return kprintln!("loader: FAIL — process add_thread");
    }

    // Phase 2b — activate the parent space (from boot context), copy each
    // segment's file bytes, zero its bss tail, then re-protect it to W^X. (The
    // parent is loaded here by the kernel; the *child* is populated by the parent
    // via `AddressSpaceMap` through the HHDM, no CR3 switch.)
    // SAFETY: the user space shares the kernel higher half; boot code, stack, and
    // the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(kcore::percpu::current_index()) };
    for seg in parsed.segments() {
        let src = image[seg.file_offset as usize..].as_ptr();
        // SAFETY: `parse` bounds-checked `[file_offset, file_offset+file_size)`
        // against the image; the destination pages are mapped writable in the
        // now-active user space.
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
    for seg in parsed.segments() {
        let (base, pages) = elf_seg_pages(seg);
        if process
            .space_mut()
            .protect_range(VirtAddr::new(base), pages * FRAME_SIZE, elf_seg_rights(seg))
            .is_err()
        {
            return kprintln!("loader: FAIL — protect segment at {base:#x}");
        }
    }

    // Phase 3 — publish the parent into the process table and start.
    process.set_running();
    let parent_pidx = match processes_insert(process) {
        Ok(idx) => idx,
        Err(e) => return kprintln!("loader: FAIL — process table insert: {e:?}"),
    };
    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    // Verify the composition: the root task ran, created a child, mapped a
    // real ELF into it, **granted it a capability the kernel never installed**,
    // started it, and read back the message the child sent on the end it was
    // given.
    let reached = USER_RING3_REACHED.load(Ordering::Relaxed);
    let child_ran = LOADER_CHILD_RAN.load(Ordering::Relaxed);
    // The **last** child anything waited on, which is the give-up run's
    // service and so is deliberately non-zero. Reported rather than asserted:
    // what each child exited with is the root task's to judge, and it judges by
    // exiting non-zero itself — which `parent_clean` below is the check for.
    let last_child_exit = LOADER_CHILD_EXIT.load(Ordering::Relaxed);
    let parent_resumed = LOADER_PARENT_RESUMED.load(Ordering::Relaxed);
    // SAFETY: the boot CPU alone; the ring-3 run has returned to boot.
    let parent_clean = matches!(
        unsafe { (*&raw mut PROCESSES).get(parent_pidx) }.map(Process::state),
        Some(ProcessState::Exited(0))
    );
    // **The grant, observed from the kernel side.** The root task's exit code
    // already depends on the child's message having arrived, which is an
    // end-to-end proof — but it is the *program's* claim, and a program can
    // say anything. This is the kernel's own record.
    //
    // Read from the event ring rather than from the child's handle table,
    // because there is no child left to read: `ProcessStart` reclaims it on
    // exit — process slot, address space and the parent's handle to it — which
    // is right and is why this had to be recorded when it happened rather than
    // reconstructed afterwards. That is what an audit record is for.
    // An observable, not an assertion. The grant happens in the first few
    // syscalls of a run that then makes forty-five more launches, each
    // emitting events, so the record is usually pushed out of the ring before
    // this reads it — it survived here and not on the second port, which is
    // luck rather than a property (build/README.md, D252).
    //
    // What the pass condition rests on instead is stronger: `parent_clean`
    // means the root task exited zero, and it only does that if the child's
    // message arrived on the endpoint it was granted. An audit record says a
    // grant was made; a message says the capability carried authority.
    let granted = granted_rights_from_events();
    // **What the three retired component-manager demos used to assert.** The
    // root task supervises a service to a clean start and gives up on one that
    // never comes up; the numbers those runs produce are checked here rather
    // than taken on the program's word.
    //
    // `launches` is the reclaim proof and not a supervision result: a process
    // slot and a scheduler thread slot are both capped at 16, so a seventeenth
    // launch fails `OutOfMemory` unless every exited instance gave back its
    // slots, its kernel stack and its frames. Reaching 41 clean launches plus
    // the give-up run's 3 cannot happen without reclaim.
    let launches = CHILD_LAUNCHES.load(Ordering::Relaxed);
    let restarted = launches == EXPECTED_CHILD_LAUNCHES;
    // And the draw is bounded rather than proportional: 45 launches drawing a
    // per-launch cost would be far past this.
    let frames_drawn = frames.handed_out() - frames_before;
    let bounded = frames_drawn < ROOT_TASK_FRAME_BOUND;

    // **And the driver the root task composed reached its own device.**
    //
    // The report is the driver's; `far` is the kernel's, read through a mapping
    // it makes and takes down at the same physical address the driver was
    // granted. That is what turns "the driver returned a number" into "the
    // driver reached its device": a grant of the wrong region answers with
    // different bytes, a one-page grant faults instead of reading, and neither
    // can agree with this by accident.
    //
    // Taken from the report *word* rather than the driver's exit code, which is
    // zero whatever happens — `blk-probe` reports by value and exits clean
    // either way, so a check reading the exit code reads nothing at all.
    let bound = match seeded_device {
        None => true,
        Some((bar_base, bar_len, identity)) => {
            let far = pci_far_word(kernel_vm, frames, bar_base, bar_len);
            let expected = PCI_REPORT_TAG
                | (far << 32)
                | (u64::from(identity.vendor) << 16)
                | u64::from(identity.device);
            ROOT_REPORTS[0].load(Ordering::SeqCst) == expected
        }
    };
    let pass =
        reached && child_ran && parent_resumed && parent_clean && restarted && bounded && bound;
    report(&verdict(
        DemoId::Loader,
        pass,
        [
            parsed.entry(),
            seg_count as u64,
            u64::from(job_handle.raw()),
            last_child_exit as u64,
            granted.map_or(0, Rights::bits),
            launches,
            frames_drawn,
            0,
        ],
    ));
    if pass {
        kcore::verdict::claims(&[
            // A ring-3 program created a channel. Nothing could before (D45).
            "roottask.channel-created",
            // **A child told what to work on** (D302, `docs/roadmap/04`
            // Phase 1). One program run three ways: it echoed back the
            // exact path its parent put in `StartupArgs`, and refused
            // the other two legs.
            "roottask.arguments",
            // And it refused them *differently* — `USAGE` for no
            // arguments, `NOT_FOUND` for a path it will not resolve —
            // in `ExitStatus`'s vocabulary rather than in numbers of
            // its own, so the parent acted on which failure it was.
            "roottask.exit-status",
            // **A program's output went to a contract, not a
            // syscall** (D303). The text crossed `diagnostic.isl` to a
            // collector that is neither the sender nor this task, was
            // forwarded whole, and the composer matched the exact
            // bytes — including the path it had chosen itself, coming
            // back through a third process.
            "roottask.diagnostics",
            // A capability reached a process because its parent put it there.
            "roottask.granted",
            // And the child used it: the message came back on the parent's end.
            "roottask.child-spoke",
            // Two children were runnable at once, which a start that waited for
            // its child could not produce.
            "roottask.concurrent",
            // A service was restarted until it came up, and one that never
            // would was given up on.
            "roottask.supervised",
            // Across 45 launches, with 16 process and 16 thread slots.
            "roottask.reclaimed",
            // A port this task made, bound to one source, and handed to
            // a child with SIGNAL and nothing else — which then woke it.
            "roottask.port",
        ]);
        if seeded_device.is_some() {
            // And the driver framework above it, on this port for the first
            // time: a manager holding a bus this task handed on, a driver
            // holding one channel, and a **real PCI function** that reached the
            // driver by transfer — which then read a word from beyond its first
            // page that the kernel confirms at the same physical address. This
            // is what `driver_bind_check` used to claim from kernel code
            // (build/README.md, D256).
            kcore::verdict::claims(&["roottask.framework"]);
        }
    } else {
        // Two lines rather than one: the fields are what a reader needs to tell
        // "the root task never ran" from "the grant did not happen" from "the
        // child ran and said nothing", and a line carrying all six is over the
        // console's width bound.
        kprintln!("loader: FAIL reached={reached} ran={child_ran} last={last_child_exit}");
        kprintln!("loader: FAIL resumed={parent_resumed} clean={parent_clean} granted={granted:?}");
        kprintln!("loader: FAIL launches={launches} frames={frames_drawn}");
        kprintln!(
            "loader: FAIL bound={bound} driver report={:#x}",
            ROOT_REPORTS[0].load(Ordering::SeqCst)
        );
    }
}

/// The word at `FAR_WINDOW_OFFSET` into a device's BAR, read by the kernel
/// through a mapping of its own.
///
/// The independent half of the bind claim: the driver reported what it read at
/// that offset in the window it was granted, and this reads the same physical
/// address without going through any capability. Zero for a window too small to
/// have such an offset, which the caller has already refused.
pub(crate) fn pci_far_word(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    bar_base: u64,
    bar_len: u64,
) -> u64 {
    if bar_len <= FAR_WINDOW_OFFSET {
        return 0;
    }
    let pages = FAR_WINDOW_OFFSET / FRAME_SIZE + 1;
    let Some(first) = PhysFrame::from_base(PhysAddr::new(bar_base)) else {
        return 0;
    };
    if kernel_vm
        .map_device_range(
            VirtAddr::new(PCI_FAR_READ_VA),
            first,
            pages,
            kcore::vm::DeviceReach::Kernel,
            frames,
        )
        .is_err()
    {
        return 0;
    }
    // SAFETY: the pages just mapped cover `[bar_base, bar_base + pages*4K)` as
    // device memory, and the read is 4-byte aligned inside them.
    let value =
        unsafe { ((PCI_FAR_READ_VA + FAR_WINDOW_OFFSET) as *const u32).read_volatile() & 0xffff };
    kernel_vm.unmap_device_pages(VirtAddr::new(PCI_FAR_READ_VA), pages);
    u64::from(value)
}

/// The rights the most recent `PROCESS_GRANTED` event recorded, or `None` if
/// no grant happened.
///
/// **Read from the event ring rather than from the child**, because the child
/// is gone by the time this runs: `ProcessStart` reclaims a process that has
/// exited. A capability handed down is exactly the kind of fact that has to be
/// recorded at the moment it is decided, and `kcore::event` is where this tree
/// records those.
///
/// `arg2` is the rights the *child* got. That is the number worth asserting:
/// the interesting mistake is a grant wider than the parent intended, and a
/// check that read the parent's rights instead would pass on one.
pub(crate) fn granted_rights_from_events() -> Option<Rights> {
    use kcore::event;
    let blank = event::record(
        event::EventKind::EventsDropped,
        event::Severity::Debug,
        event::Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );
    let mut tail = [blank; 64];
    let n = event::tail(&mut tail);
    tail[..n]
        .iter()
        .rev()
        .find(|e| e.kind == event::EventKind::ProcessGranted)
        .map(|e| Rights::from_bits(e.arg2))
}

/// Inserts `process` into the global loader process table. A thin wrapper so the
/// unsafe static access has one home.
pub(crate) fn processes_insert(process: Process<KernelAddressSpace>) -> Result<usize, KError> {
    // SAFETY: the boot CPU alone; PROCESSES is touched only on this CPU.
    unsafe { (*&raw mut PROCESSES).insert(process) }
}

/// Monotonic nanoseconds, for `ClockRead` (D281).
///
/// **The conversion is here rather than in `kcore`**, because `karch`'s
/// counter is deliberately unit-less and only the port knows its rate. A
/// machine whose counter frequency is unknown reports zero rather than a
/// number derived from a guess: a clock that is confidently wrong is worse
/// than one that says it does not know.
pub(crate) fn monotonic_nanos() -> u64 {
    use tessera_karch::CpuOps;
    let ticks = <Cpu as CpuOps>::counter_serialized();
    match <Cpu as CpuOps>::counter_hz() {
        Some(hz) if hz > 0 => (ticks as u128 * 1_000_000_000u128 / hz as u128) as u64,
        _ => 0,
    }
}
