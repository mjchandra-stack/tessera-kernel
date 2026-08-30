// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Demand paging and copy-on-write.
//!
//! The reclaim bet: a page fault the kernel resolves and resumes rather than one
//! it kills. A lazy anonymous region fills a page at a time, and a snapshot stays
//! unchanged when the writer writes.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- Demand paging + copy-on-write demonstration ---
//
// The reclaim bet: a page fault the kernel *resolves and resumes* rather than
// kills. A ring-3 program writes across a lazy anonymous region never populated
// at map time — each new page demand-faults, is zero-filled and mapped, and the
// write retries transparently (budget B8) — then writes to a copy-on-write page
// the kernel snapshotted, which faults, copies private, and resumes (budget
// B9). None of this terminates the program: it runs to a clean exit. The
// copy-on-write snapshot still holds the pre-write bytes while the writable copy
// holds the new ones — isolation. Proven on hardware; the mock cannot fault.

/// Lazy anonymous region the ring-3 program walks (demand-fill, B8).
pub(crate) const USER_LAZY_VA: u64 = 0x0000_0000_5000_0000;
pub(crate) const USER_LAZY_PAGES: u64 = 4;
/// Copy-on-write region: the kernel writes a pattern, snapshots it, then the
/// program writes it (COW copy, B9). The snapshot keeps the original bytes.
pub(crate) const USER_COW_VA: u64 = 0x0000_0000_6000_0000;
pub(crate) const USER_COW_SNAP_VA: u64 = 0x0000_0000_6100_0000;
/// Bytes: the kernel writes `COW_ORIG`, the program overwrites with `COW_NEW`.
pub(crate) const COW_ORIG: u8 = 0xaa;
pub(crate) const COW_NEW: u8 = 0xbb;
/// Page-fault resolutions observed, published by the resolver.
pub(crate) static DP_DEMAND_FILLS: AtomicU64 = AtomicU64::new(0);
pub(crate) static DP_COW_COPIES: AtomicU64 = AtomicU64::new(0);

/// Raw pointer to the boot frame allocator, so the fault resolver (which runs in
/// trap context) can allocate/free frames. `_start` never returns, so the
/// allocator it owns lives for the kernel's lifetime.
pub(crate) static mut RESOLVER_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
    core::ptr::null_mut();

// The ring-3 program. Absolute user VAs (it runs at USER_CODE_VA in its own
// space, and the demo maps the regions at fixed addresses). It writes one byte
// to each lazy page, one byte to the copy-on-write page, then exits cleanly.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global dp_program_start
.global dp_program_end
dp_program_start:
    mov rax, 0x50000000       # USER_LAZY_VA
    mov byte ptr [rax], 1     # page 0 -> demand fault
    add rax, 0x1000
    mov byte ptr [rax], 1     # page 1
    add rax, 0x1000
    mov byte ptr [rax], 1     # page 2
    add rax, 0x1000
    mov byte ptr [rax], 1     # page 3
    mov rax, 0x60000000       # USER_COW_VA
    mov byte ptr [rax], 0xbb  # COW_NEW -> copy-on-write fault
    mov eax, 5                # ProcessExit
    xor edi, edi             # code 0
    syscall
1:
    jmp 1b
dp_program_end:
.text
"#
);

// SAFETY: these name the demand-paging blob's bounds, defined by the global_asm
// block above; the extern block only declares them and does no unsafe operation.
unsafe extern "C" {
    pub(crate) static dp_program_start: u8;
    pub(crate) static dp_program_end: u8;
}

/// The registered page-fault resolver: classifies the #PF against the current
/// process's address space and repairs it (demand-fill or copy-on-write),
/// counting each. Returns `true` if resolved (the instruction is resumed) or
/// `false` for an unresolvable fault (which then contains/panics as before).
pub(crate) fn page_fault_resolver(frame: &mut TrapFrame) -> bool {
    let fault_addr = tessera_karch_x86_64::read_cr2();
    let write = (frame.error_code & 0b10) != 0; // #PF error-code bit 1: write
    // SAFETY: the boot CPU alone; USER_PROCESS is set before the ring-3 thread runs.
    let process = match unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        Some(process) if !process.is_exited() => process,
        _ => return false,
    };
    // SAFETY: the boot CPU alone; RESOLVER_FRAMES points at the boot frame allocator,
    // which lives for the kernel's lifetime (`_start` never returns).
    let alloc = match unsafe { RESOLVER_FRAMES.as_mut() } {
        Some(alloc) => alloc,
        None => return false,
    };
    // The classification and its repair are `kcore::fault`'s, shared with every
    // other port; what stays here is what only this port knows — where the
    // faulting address came from, and who to ask for a page.
    let repair = kcore::fault::repair(process.space_mut(), VirtAddr::new(fault_addr), write, alloc);
    match repair {
        kcore::fault::Repair::Filled => {
            DP_DEMAND_FILLS.fetch_add(1, Ordering::Relaxed);
            true
        }
        kcore::fault::Repair::Copied => {
            DP_COW_COPIES.fetch_add(1, Ordering::Relaxed);
            true
        }
        // A write to a clean pager page. This single-process demo resolver has
        // no Executive to consult, so it grants the write without the dirty
        // accounting the shared dispatcher does — the pager-pressure harness
        // drives that accounting directly in its own scenario drivers, which is
        // what this port exercises it with. A page dirtied here is never
        // written back, and the demo's object is read-mostly for that reason.
        kcore::fault::Repair::NeedsDirty { .. } => process
            .space_mut()
            .grant_write(VirtAddr::new(fault_addr))
            .is_ok(),
        // Pager-backed and not resident: forward a page request to the pager
        // over IPC, block the faulting thread, and resume once it supplies the
        // page (budget B10). `process` is no longer borrowed here — the install
        // happens on the pager thread, which re-borrows USER_PROCESS.
        kcore::fault::Repair::NeedsPageIn { object, offset } => {
            forward_page_in(fault_addr, object, offset)
        }
        kcore::fault::Repair::Fatal => false,
    }
}

/// Builds a ring-3 process with a lazy anonymous region and a copy-on-write
/// snapshot, runs it, and asserts every fault resolved-and-resumed (the program
/// exited cleanly) with copy-on-write isolation intact.
pub(crate) fn demand_paging_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // Resolvable faults route to the resolver; unresolvable ones still contain.
    set_page_fault_resolver(page_fault_resolver);
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(user_syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("demand-paging demo: new_user failed: {e:?}"),
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
        Err(e) => panic!("demand-paging demo: process object failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    let user = PageFlags::rw().user();
    // Code page (writable to copy the program in; locked to rx afterwards).
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(USER_CODE_VA), code_len, user, frames)
    {
        panic!("demand-paging demo: map code failed: {e:?}");
    }
    // The lazy region — reserved, populated on fault.
    if let Err(e) = process.space_mut().map_anonymous_demand(
        VirtAddr::new(USER_LAZY_VA),
        USER_LAZY_PAGES * FRAME_SIZE,
        user,
    ) {
        panic!("demand-paging demo: reserve lazy region failed: {e:?}");
    }
    // The copy-on-write source — eagerly mapped so the kernel can seed it.
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(USER_COW_VA), FRAME_SIZE, user, frames)
    {
        panic!("demand-paging demo: map COW region failed: {e:?}");
    }

    let thread = match Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("demand-paging demo: spawn_user failed: {e:?}"),
    };
    // SAFETY: the boot CPU alone; re-initializing the demo scheduler.
    unsafe { USER_SCHEDULER = Some(Scheduler::new(1, 0)) };
    let thread_idx = match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => match scheduler.add_thread(thread) {
            Ok(idx) => idx,
            Err(e) => panic!("demand-paging demo: scheduler full: {e:?}"),
        },
        None => panic!("demand-paging demo: scheduler uninitialized"),
    };
    if process
        .add_thread(thread_id_of(thread_idx).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        .is_err()
    {
        panic!("demand-paging demo: process thread set full");
    }

    // Activate the user space, copy the program in, lock it to rx, seed the
    // copy-on-write page, and snapshot it.
    // SAFETY: the user space shares the kernel higher-half; boot code, stack,
    // and the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(kcore::percpu::current_index()) };
    let code_src = &raw const dp_program_start;
    let code_bytes = (&raw const dp_program_end as usize) - (&raw const dp_program_start as usize);
    // SAFETY: [dp_program_start, dp_program_end) is the assembled ring-3 blob in
    // kernel rodata; USER_CODE_VA is a writable user page with room for it.
    unsafe {
        // The kernel means to reach a user page here: it is populating a
        // process it is building, in that process's own space. Declared
        // rather than assumed, because SMAP now faults an undeclared one.
        // SAFETY: the destination is a page this boot glue just mapped
        // into the space it activated; the window permits reaching it.
        {
            let _access = kcore::useraccess::Window::open();
            core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes);
        }
    }
    if let Err(e) = process.space_mut().protect_range(
        VirtAddr::new(USER_CODE_VA),
        code_len,
        PageFlags::rx().user(),
    ) {
        panic!("demand-paging demo: protect code failed: {e:?}");
    }
    // Seed the copy-on-write page and snapshot it (both sides now share it RO).
    // SAFETY: the COW page is mapped writable and user-accessible in the active
    // space; a single-byte write is in bounds.
    // Seeding and reading back a user page from the kernel: the demo is the
    // thing that knows what the page should contain.
    // SAFETY: the demo's space is active and the page is mapped writable.
    {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::write_volatile(USER_COW_VA as *mut u8, COW_ORIG) };
    }
    if let Err(e) = process.space_mut().snapshot_cow(
        VirtAddr::new(USER_COW_VA),
        VirtAddr::new(USER_COW_SNAP_VA),
        FRAME_SIZE,
        frames,
    ) {
        panic!("demand-paging demo: snapshot_cow failed: {e:?}");
    }

    // Wire the resolver's allocator and publish the process, then run.
    // SAFETY: `frames` lives for the kernel's lifetime (`_start` never returns).
    unsafe { RESOLVER_FRAMES = core::ptr::from_mut(frames) };
    // SAFETY: the boot CPU alone; publishing the running process.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }

    kprintln!("dpage: entering ring 3; lazy region + COW snapshot armed");
    // SAFETY: the boot CPU alone, path; USER_SCHEDULER was initialized above.
    match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => scheduler.run(),
        None => panic!("demand-paging demo: scheduler uninitialized"),
    }

    // Back on boot, user CR3 still active: read the two copy-on-write pages
    // before restoring the kernel space.
    // SAFETY: the pages are present and user-readable from ring 0; single byte.
    // SAFETY: as the seeding write above — the demo's own mapped pages.
    let cow_byte = {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::read_volatile(USER_COW_VA as *const u8) }
    };
    // SAFETY: as above.
    // A user page the demo reads to check what ring 3 left there.
    // SAFETY: the demo's space is active and the page is mapped readable.
    let snap_byte = {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::read_volatile(USER_COW_SNAP_VA as *const u8) }
    };
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    // Assert the bet held.
    let clean_exit = matches!(
        // SAFETY: the boot CPU alone, path; only this CPU touches USER_PROCESS.
        unsafe { (*&raw const USER_PROCESS).as_ref() }.map(Process::state),
        Some(ProcessState::Exited(0))
    );
    let fills = DP_DEMAND_FILLS.load(Ordering::Relaxed);
    let copies = DP_COW_COPIES.load(Ordering::Relaxed);
    if !clean_exit {
        panic!("demand-paging demo: program did not exit cleanly (a fault was not resolved)");
    }
    if fills != USER_LAZY_PAGES {
        panic!("demand-paging demo: {fills} demand-fills, expected {USER_LAZY_PAGES}");
    }
    if copies != 1 {
        panic!("demand-paging demo: {copies} COW copies, expected 1");
    }
    if cow_byte != COW_NEW {
        panic!("demand-paging demo: COW page is {cow_byte:#x}, expected {COW_NEW:#x}");
    }
    if snap_byte != COW_ORIG {
        panic!(
            "demand-paging demo: snapshot is {snap_byte:#x}, expected {COW_ORIG:#x} (isolation)"
        );
    }
    if frames.reclaim_overflows() != 0 {
        panic!("demand-paging demo: frame reclaim overflowed");
    }

    kprintln!(
        "dpage: {fills} demand-fills + {copies} COW copy resolved-and-resumed; program exited clean",
    );
    kprintln!(
        "dpage: COW isolation held (write {COW_NEW:#x} private; snapshot still {COW_ORIG:#x})"
    );
}
