// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The external pager: a fault served over IPC.
//!
//! A fault on pager-backed memory forwarded from trap context as a request to a
//! pager, which supplies the page and hands control back to the faulting thread.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- External-pager page-in wiring ---
//
// A fault on a pager-backed page is forwarded, from trap context, as a request
// over an M5 channel to a pager kernel thread, which supplies the page and hands
// control back. The faulting thread and the pager thread share one `Executive`
// (`EXEC`), so `Executive::call` blocks the faulter and hands off directly to
// the pager — carrying the faulter's priority (budget B10's handoff rule) — and
// resumes it when the pager `reply`s. `supply` is an ownership transfer: the
// pager fills a fresh frame and installs it, no copy through a buffer.

/// The in-kernel pager protocol identifiers (a real ISL schema when the pager
/// becomes a user-space service).
pub(crate) const PAGER_IFACE_ID: u64 = 0x7061_6765_7200_0001;
pub(crate) const METHOD_PAGE_IN: u32 = 1;
pub(crate) const METHOD_SUPPLY_ACK: u32 = 2;
/// Page N of a pager-backed object is filled with the byte `PAGER_CONTENT_BASE
/// + N`, so ring 3 reading a distinct value proves the page came from the pager.
pub(crate) const PAGER_CONTENT_BASE: u64 = 0xc0;

/// The pager channel: `.0` is the fault/client end (the resolver calls on it),
/// `.1` the pager end (the pager thread receives on it). Set once in the demo.
pub(crate) static mut PAGER_ENDPOINTS: Option<(EndpointId, EndpointId)> = None;
/// Page-ins served over IPC (the observability hook; B10 path count).
pub(crate) static PAGER_PAGE_INS: AtomicU64 = AtomicU64::new(0);
/// The in-flight page-in fault (VA, object), stashed by `forward_page_in` before
/// it hands off to the pager, for a ring-3 FS pager's `PageSupply` to resolve
/// (M18). One slot — single in-flight fault (synchronous, one CPU). Inert
/// for the in-kernel pager (M12), which reads `USER_PROCESS` directly.
pub(crate) static mut FS_PENDING: Option<(u64, ObjectId)> = None;

/// The pager channel's endpoint ids.
pub(crate) fn pager_endpoints() -> (EndpointId, EndpointId) {
    // SAFETY: the boot CPU alone; set once in `pager_demo` before the threads run.
    unsafe {
        match (*&raw const PAGER_ENDPOINTS).as_ref() {
            Some(&pair) => pair,
            None => panic!("pager: endpoints uninitialized"),
        }
    }
}

/// Forwards a page-in request to the pager and blocks the faulting thread until
/// it supplies the page. Returns `true` once the page is installed (resume) or
/// `false` if the pager path is unavailable or errors (escalate). Runs as the
/// faulting thread, so `Executive::call` blocks *this* thread.
pub(crate) fn forward_page_in(fault_va: u64, object: ObjectId, offset: u64) -> bool {
    // SAFETY: the boot CPU alone; PAGER_ENDPOINTS is set before ring 3 runs, `None`
    // (so this returns false) during the earlier demos.
    let endpoints = match unsafe { (*&raw const PAGER_ENDPOINTS).as_ref() } {
        Some(&pair) => pair,
        None => return false,
    };
    // SAFETY: the boot CPU alone; EXEC holds the faulting + pager threads' scheduler.
    let exec = match unsafe { (*&raw mut EXEC).as_mut() } {
        Some(exec) => exec,
        None => return false,
    };
    // The faulting thread is still current here (the resolver runs in trap
    // context, before `call` blocks it), so this is the cause the request must
    // carry — `call` stamps exactly this onto the header (D60).
    CORRELATION_PAGE_IN_FAULTER.store(kcore::trace::current().correlation, Ordering::Relaxed);
    let mut request = Message::new(MessageHeader::new(PAGER_IFACE_ID, METHOD_PAGE_IN));
    let mut inline = [0u8; 20];
    inline[0..8].copy_from_slice(&fault_va.to_le_bytes());
    inline[8..12].copy_from_slice(&object.raw().to_le_bytes());
    inline[12..20].copy_from_slice(&offset.to_le_bytes());
    if request.set_inline(&inline).is_err() {
        return false;
    }
    // Stash the in-flight fault so a ring-3 FS pager's `PageSupply` can resolve it
    // (M18). Inert for the in-kernel pager, which supplies via `USER_PROCESS`.
    // SAFETY: the boot CPU alone; one in-flight page-in fault at a time (synchronous).
    unsafe { FS_PENDING = Some((fault_va, object)) };
    // Blocks the faulting thread and hands off to the pager (priority carried);
    // returns when the pager replies with the page already installed.
    let started = read_tsc_serialized();
    match exec.call(endpoints.0, request) {
        Ok(_ack) => {
            PAGER_PAGE_INS.fetch_add(1, Ordering::Relaxed);
            // The structured page-in-latency record: the served count and the
            // perf row are summaries; this is the per-page-in event (D33).
            kcore::event::emit(
                kcore::event::EventKind::PagerPageIn,
                kcore::event::Severity::Info,
                kcore::event::Component::Pager,
                [
                    u64::from(object.raw()),
                    offset,
                    read_tsc_serialized().saturating_sub(started),
                    0,
                ],
            );
            true
        }
        Err(_) => false,
    }
}

/// The in-kernel pager kernel thread: receives page requests, produces the
/// page's content, installs it into the faulting process, and replies (handing
/// control back to the faulter). A RAM-backed reference pager — its content is a
/// per-page byte pattern so provenance is verifiable.
pub(crate) extern "C" fn pager_thread_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (_client, pager_ep) = pager_endpoints();
    // First request parks us; thereafter reply-and-wait keeps us parked between
    // the many page-in calls (a bare reply would leave us blocked).
    let mut request = match exec.receive(pager_ep) {
        Ok(request) => request,
        Err(_) => loop {
            core::hint::spin_loop();
        },
    };
    loop {
        let supplied = serve_page_request(&request);
        let mut ack = Message::new(MessageHeader::new(PAGER_IFACE_ID, METHOD_SUPPLY_ACK));
        let _ = ack.set_inline(&[supplied as u8]);
        // Reply hands control back to the faulter and re-parks us for the next
        // request; on a supply failure the ack still returns (the faulter then
        // re-faults or is contained).
        request = match exec.reply_receive(pager_ep, ack) {
            Ok(request) => request,
            Err(_) => loop {
                core::hint::spin_loop();
            },
        };
    }
}

/// Serves one page request: decode the fault VA and object offset, produce the
/// page's content (a per-page byte pattern), and install (`supply`) the frame
/// into the faulting process. Returns whether the page was supplied.
pub(crate) fn serve_page_request(request: &Message) -> bool {
    // The cause the request arrived with — `docs/kernel/03`: "The request carries
    // object ID, page range, fault access type, and a correlation ID". It rides
    // the header, so the pager serves the fault under the faulting thread's cause
    // (D60). Recorded for the `correlation` verdict.
    let arrived = request.header().correlation;
    CORRELATION_PAGE_IN_SERVED.store(arrived, Ordering::Relaxed);
    CORRELATION_PAGE_IN_REQUESTS.fetch_add(1, Ordering::Relaxed);
    if arrived != 0 && arrived == CORRELATION_PAGE_IN_FAULTER.load(Ordering::Relaxed) {
        CORRELATION_PAGE_IN_MATCHED.fetch_add(1, Ordering::Relaxed);
    }
    let inline = request.inline();
    if inline.len() < 20 {
        return false;
    }
    let fault_va = u64::from_le_bytes([
        inline[0], inline[1], inline[2], inline[3], inline[4], inline[5], inline[6], inline[7],
    ]);
    let offset = u64::from_le_bytes([
        inline[12], inline[13], inline[14], inline[15], inline[16], inline[17], inline[18],
        inline[19],
    ]);
    let pattern = (PAGER_CONTENT_BASE + offset / FRAME_SIZE) as u8;
    // SAFETY: the boot CPU alone; RESOLVER_FRAMES and USER_PROCESS are set before the
    // ring-3 thread runs.
    let (frames, process) =
        match unsafe { (RESOLVER_FRAMES.as_mut(), (*&raw mut USER_PROCESS).as_mut()) } {
            (Some(frames), Some(process)) => (frames, process),
            _ => return false,
        };
    let Some(frame) = frames.alloc() else {
        return false;
    };
    let space = process.space_mut();
    // Produce the page's content, then transfer the frame into the mapping (an
    // ownership move, not a copy).
    space.arch().fill_frame(frame, pattern);
    space
        .supply_page(VirtAddr::new(fault_va), frame, frames)
        .is_ok()
}

// --- External-pager page-in demonstration ---
//
// The pager bet: a fault on service-backed memory served by a pager over IPC. A
// ring-3 program reads across a region backed by a memory object; each page is
// not resident, so the fault is forwarded (from trap context, as the faulting
// thread) over an M5 channel to a pager kernel thread, which supplies a page and
// hands control back — the read then resumes transparently. The pager fills each
// page with a distinct byte so the demo proves the content came from the pager,
// not a zero fill. Boot-proven; the mock has no ring transition or scheduler
// switch to exercise this.

/// The M8 user thread's kernel stack and the pager thread's kernel stack (in the
/// shared kernel VMAP slot, clear of the earlier demos' stacks).
/// The object-backed (pager) region the ring-3 program reads.
pub(crate) const PAGER_OBJ_VA: u64 = 0x0000_0000_8000_0000;
pub(crate) const PAGER_OBJ_PAGES: u64 = 4;

// The ring-3 program: read one byte from each page of the object-backed region
// (each read faults and is served by the pager), then exit clean.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global pager_program_start
.global pager_program_end
pager_program_start:
    mov rax, 0x80000000       # PAGER_OBJ_VA
    mov bl, [rax]             # page 0 read -> #PF -> page-in
    add rax, 0x1000
    mov bl, [rax]             # page 1
    add rax, 0x1000
    mov bl, [rax]             # page 2
    add rax, 0x1000
    mov bl, [rax]             # page 3
    mov eax, 5                # ProcessExit
    xor edi, edi
    syscall
1:
    jmp 1b
pager_program_end:
.text
"#
);

// SAFETY: these name the pager blob's bounds, defined by the global_asm block
// above; the extern block only declares them and does no unsafe operation.
unsafe extern "C" {
    pub(crate) static pager_program_start: u8;
    pub(crate) static pager_program_end: u8;
}

/// The M8 syscall handler: the program's only syscall is `ProcessExit`, which
/// yields the shared `EXEC` scheduler (the M8 user thread runs there, not in
/// `USER_SCHEDULER`).
pub(crate) fn pager_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    match SyscallNumber::from_u64(frame.number) {
        Some(SyscallNumber::ProcessExit) => {
            // SAFETY: the boot CPU alone; statics set before the ring-3 thread runs.
            if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
                process.exit(frame.arg0 as i32);
            }
            // SAFETY: the boot CPU alone; EXEC holds the M8 threads' scheduler.
            if let Some(exec) = unsafe { (*&raw mut EXEC).as_mut() } {
                exec.scheduler().yield_to_boot();
            }
            0
        }
        _ => syscall::ENOSYS,
    }
}

/// The M8 ring-3 fault handler: contains a genuine (non-resolvable) fault by
/// terminating the process and yielding the `EXEC` scheduler. Resolvable pager
/// faults never reach here — the resolver forwards and resumes them.
pub(crate) fn pager_user_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    // SAFETY: the boot CPU alone; statics set before the ring-3 thread runs.
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.exit(-1);
    }
    // SAFETY: the boot CPU alone; EXEC holds the M8 threads' scheduler.
    match unsafe { (*&raw mut EXEC).as_mut() } {
        Some(exec) => exec.scheduler().yield_to_boot(),
        None => DebugExit::exit(ExitCode::Failure),
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Sets up a pager kernel thread and a ring-3 process with a pager-backed
/// region in one `Executive`, runs it, and asserts every object-backed read was
/// served by the pager over IPC with the pager's content delivered to ring 3.
pub(crate) fn pager_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    set_page_fault_resolver(page_fault_resolver);
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(pager_syscall_handler) };
    set_user_fault_handler(pager_user_fault_handler);

    // One executive holds both the pager thread and the ring-3 thread, so the
    // page-in `call` blocks the faulter and hands off directly to the pager.
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let exec = exec_ref();
    let (client_ep, pager_ep) = match exec.channel_create() {
        Ok(pair) => pair,
        Err(e) => panic!("pager demo: channel create failed: {e:?}"),
    };
    // SAFETY: the boot CPU alone; set once before the threads run.
    unsafe { PAGER_ENDPOINTS = Some((client_ep, pager_ep)) };

    // Pager thread first, so it parks in `receive` and the faulter's `call`
    // hands off directly to it.
    let pager_thread = match Thread::<ContextSwitch>::spawn(
        pager_thread_entry,
        0,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("pager demo: pager thread spawn failed: {e:?}"),
    };
    if exec.add_thread(pager_thread).is_err() {
        panic!("pager demo: scheduler full (pager)");
    }

    // The ring-3 process with a pager-backed region.
    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("pager demo: new_user failed: {e:?}"),
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
        Err(e) => panic!("pager demo: process object failed: {e:?}"),
    };
    let mem_obj = match objects.create(ObjectType::Memory) {
        Ok(id) => id,
        Err(e) => panic!("pager demo: memory object failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    let user = PageFlags::rw().user();
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(USER_CODE_VA), code_len, user, frames)
    {
        panic!("pager demo: map code failed: {e:?}");
    }
    // The pager-backed region — nothing resident; pages arrive via `supply`.
    if let Err(e) = process.space_mut().map_object(
        VirtAddr::new(PAGER_OBJ_VA),
        PAGER_OBJ_PAGES * FRAME_SIZE,
        user,
        mem_obj,
        0,
    ) {
        panic!("pager demo: map_object failed: {e:?}");
    }

    let user_thread = match Thread::<ContextSwitch>::spawn_user(
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
        Err(e) => panic!("pager demo: spawn_user failed: {e:?}"),
    };
    let user_idx = match exec.add_thread(user_thread) {
        Ok(idx) => idx,
        Err(e) => panic!("pager demo: scheduler full (user): {e:?}"),
    };
    if process
        .add_thread(thread_id_of(user_idx).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        .is_err()
    {
        panic!("pager demo: process thread set full");
    }

    // Activate the user space, copy the program in, lock it to rx.
    // SAFETY: the user space shares the kernel higher-half; boot code, stack,
    // and the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(kcore::percpu::current_index()) };
    let code_src = &raw const pager_program_start as *const u8;
    let code_bytes =
        (&raw const pager_program_end as usize) - (&raw const pager_program_start as usize);
    // SAFETY: [pager_program_start, pager_program_end) is the assembled ring-3
    // blob in kernel rodata; USER_CODE_VA is a writable user page with room.
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
        panic!("pager demo: protect code failed: {e:?}");
    }

    // Publish the process + frame allocator for the resolver and pager thread.
    // SAFETY: the boot CPU alone; publishing the running process.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }
    // SAFETY: `frames` lives for the kernel's lifetime (`_start` never returns).
    unsafe { RESOLVER_FRAMES = core::ptr::from_mut(frames) };

    kprintln!("pager: entering ring 3; {PAGER_OBJ_PAGES} pager-backed pages armed");
    exec.run();

    // Back on boot, user CR3 still active: verify each page holds the pager's
    // distinct content before restoring the kernel space.
    let mut content_ok = true;
    for i in 0..PAGER_OBJ_PAGES {
        // SAFETY: the page is resident (supplied) and user-readable from ring 0.
        // A user page the demo reads to check what the service left there.
        // SAFETY: the demo's space is active and the page is mapped readable.
        let _access = unsafe { kcore::useraccess::Window::open() };
        let byte =
            unsafe { core::ptr::read_volatile((PAGER_OBJ_VA + i * FRAME_SIZE) as *const u8) };
        if byte != (PAGER_CONTENT_BASE + i) as u8 {
            content_ok = false;
        }
    }
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let page_ins = PAGER_PAGE_INS.load(Ordering::Relaxed);
    let clean_exit = matches!(
        // SAFETY: the boot CPU alone, path; only this CPU touches USER_PROCESS.
        unsafe { (*&raw const USER_PROCESS).as_ref() }.map(Process::state),
        Some(ProcessState::Exited(0))
    );
    if !clean_exit {
        panic!("pager demo: program did not exit cleanly (a page-in failed)");
    }
    if page_ins != PAGER_OBJ_PAGES {
        panic!("pager demo: {page_ins} page-ins served, expected {PAGER_OBJ_PAGES}");
    }
    if !content_ok {
        panic!("pager demo: a page did not hold the pager's content");
    }

    kprintln!(
        "pager: {page_ins} object-backed pages served by the pager over IPC (priority inherited)"
    );
    kprintln!("pager: ring 3 read the pager's content back; program exited clean");
}
