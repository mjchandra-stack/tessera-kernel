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
    // **The faulting thread names the faulting process.** It used to be a
    // static holding "the one ring-3 process", which was true only while there
    // was one; resolving through the machine's table is what lets a check with
    // two processes fault in either of them (D300).
    let Some(caller) = chan_current_id() else {
        return false;
    };
    let process = match crate::loader::root_processes().process_of_thread(caller) {
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
        // happens on the pager thread, which re-resolves the faulter through the
        // process table.
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
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    // No observer: this check's evidence is what the *resolver* counted, and
    // its program's one syscall is the exit every handler here answers.
    crate::syscalls::clear_observer();
    crate::syscalls::withdraw_frames();
    set_user_fault_handler(user_fault_handler);

    DP_DEMAND_FILLS.store(0, Ordering::Relaxed);
    DP_COW_COPIES.store(0, Ordering::Relaxed);

    // SAFETY: the boot CPU alone; the previous check's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    let blob = &raw const dp_program_start;
    let blob_len = (&raw const dp_program_end as usize) - (&raw const dp_program_start as usize);
    let (mut process, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        blob_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );

    let user = PageFlags::rw().user();
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
    // Seed the copy-on-write page and snapshot it (both sides now share it RO).
    // `chan_build_process` left this process's space active, which is what the
    // window below reaches through.
    // Seeding a user page from the kernel: the check is the thing that knows
    // what the page should contain.
    // SAFETY: the COW page is mapped writable and user-accessible in the active
    // space; a single-byte write is in bounds.
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
    process.set_running();
    let slot = match processes_insert(process) {
        Ok(slot) => slot,
        Err(e) => panic!("demand-paging demo: insert process failed: {e:?}"),
    };

    kprintln!("dpage: entering ring 3; lazy region + COW snapshot armed");
    exec_ref().run();

    // Back on boot, user CR3 still active: read the two copy-on-write pages
    // before restoring the kernel space.
    // A user page the demo reads to check what ring 3 left there.
    // SAFETY: the demo's space is active and the page is mapped readable.
    let cow_byte = {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::read_volatile(USER_COW_VA as *const u8) }
    };
    // SAFETY: as above.
    let snap_byte = {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::read_volatile(USER_COW_SNAP_VA as *const u8) }
    };
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    // Assert the bet held.
    let clean_exit = matches!(
        crate::loader::root_processes()
            .get(slot)
            .map(Process::state),
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
