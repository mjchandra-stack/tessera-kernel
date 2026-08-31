// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A RAM-backed filesystem service, in ring 3.
//!
//! The pager's server moves out of the kernel: a ring-3 service supplies the page
//! a ring-3 client faulted on, and the kernel refuses a source the service does
//! not own.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- M18: RAM-backed filesystem service (a ring-3 service supplies pages) ------

/// Supplies a page-in from a ring-3 service's buffer: fills a fresh frame with
/// `src` (the service's file page, read while the *service's* CR3 is active) and
/// installs it (`supply_page` — ownership transfer, read-only) into the faulting
/// client at `fault_va`. Both the frame fill and `supply_page`'s page-table edit
/// go through the HHDM, so this works even though the service's CR3 is loaded.
/// `src` must be exactly one page. This is the M12 `serve_page_request` supply
/// with its byte-pattern generator replaced by "copy the service's page bytes".
pub(crate) fn fs_supply(
    client_space: &mut AddressSpace<KernelAddressSpace>,
    fault_va: u64,
    src: &[u8],
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> bool {
    if src.len() != FRAME_SIZE as usize {
        return false;
    }
    let Some(frame) = frames.alloc() else {
        return false;
    };
    client_space.arch().write_bytes_to_frame(frame, 0, src);
    client_space
        .supply_page(VirtAddr::new(fault_va), frame, frames)
        .is_ok()
}

/// A static source page (filled with the FS content byte) for the Step-0 supply
/// self-check — stands in for a ring-3 service's file buffer.
pub(crate) static FS_SELFTEST_SRC: [u8; 4096] = [FS_CONTENT_BASE as u8; 4096];
/// Scratch VA for the self-check's pager-backed page — a fixed data-page window
/// (not a kernel stack, so outside `alloc_kstack`'s pool), placed clear of the
/// stack-window region.
pub(crate) const FS_SELFTEST_VA: u64 = 0xffff_c000_5c00_0000;

/// M18 Step 0: prove the supply mechanism in isolation. Map a pager-backed page
/// in the (active) boot kernel space, `fs_supply` a known source page into it,
/// and read it back — validates the copy-to-frame + `supply_page` path the ring-3
/// `PageSupply` syscall will use, before any ring-3 complexity.
pub(crate) fn fs_supply_selftest(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let obj = match objects.create(ObjectType::Memory) {
        Ok(id) => id,
        Err(e) => return kprintln!("fs: supply FAIL — object: {e:?}"),
    };
    if kernel_vm
        .map_object(
            VirtAddr::new(FS_SELFTEST_VA),
            FRAME_SIZE,
            PageFlags::rw(),
            obj,
            0,
        )
        .is_err()
    {
        return kprintln!("fs: supply FAIL — map_object");
    }
    let supplied = fs_supply(kernel_vm, FS_SELFTEST_VA, &FS_SELFTEST_SRC, frames);
    // The boot kernel space is active, so the supplied read-only page is readable.
    // SAFETY: the page was just supplied (present, read-only) at FS_SELFTEST_VA.
    // A user page the demo reads to check what ring 3 left there.
    // SAFETY: the demo's space is active and the page is mapped readable.
    let byte = {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::read_volatile(FS_SELFTEST_VA as *const u8) }
    };
    let pass = supplied && u64::from(byte) == FS_CONTENT_BASE;
    report(&verdict(
        DemoId::FsSupply,
        pass,
        [u64::from(byte), 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("fs: supply FAIL — supplied={supplied} byte={byte:#04x}");
    }
}

/// FS content byte base: page N of the FS "file" holds `FS_CONTENT_BASE + N`,
/// distinct from the in-kernel pager's `PAGER_CONTENT_BASE` (0xc0) so a mix-up
/// fails the content check rather than passing silently.
pub(crate) const FS_CONTENT_BASE: u64 = 0xf0;
/// The FS service's file buffer VA in its own address space (its "page cache").
/// A low-half user VA (< 4 GiB) so the service blob can index it with a 32-bit
/// displacement; clear of the service's code (`0x40_0000`) and stack (`0x7000_0000`).
pub(crate) const FS_BUF_VA: u64 = 0x0000_0000_5000_0000;

/// Pages the ring-3 FS service supplied via `PageSupply` (want `PAGER_OBJ_PAGES`
/// — proves every page-in was served from ring 3).
pub(crate) static FS_SUPPLIED: AtomicU64 = AtomicU64::new(0);
/// Set once a `PageSupply` with an out-of-buffer `src_va` was correctly denied.
pub(crate) static FS_BAD_SRC_DENIED: AtomicBool = AtomicBool::new(false);
/// The FS client's ring-3 exit code (`i32::MIN` = not observed).
pub(crate) static FS_CLIENT_EXIT: AtomicI32 = AtomicI32::new(i32::MIN);

/// Whether the last `PageSupply` left a reply owed to the faulter, and whether
/// it supplied. `PageServe` sends it; a denied supply owes a reply too, or the
/// faulter waits for ever instead of re-faulting.
///
/// One slot, because a page-in is synchronous and one at a time — the same
/// reason [`FS_PENDING`] is one slot.
pub(crate) static mut FS_REPLY_OWED: Option<bool> = None;

/// Decodes the object offset (bytes 12..20) from a page-in request message.
pub(crate) fn fs_request_offset(request: &Message) -> u64 {
    let inline = request.inline();
    if inline.len() < 20 {
        return 0;
    }
    u64::from_le_bytes([
        inline[12], inline[13], inline[14], inline[15], inline[16], inline[17], inline[18],
        inline[19],
    ])
}

/// `PageServe`: the FS service parks on its endpoint for the next page-in
/// request, then returns the faulting object offset so it can locate the page in
/// its buffer. `exec.receive` parks the service (and switches to the faulter);
/// when the faulter's `forward_page_in` calls, the service resumes here.
///
/// **It is also the call that answers the previous request** (D298).
/// `PageSupply` declares no return value in `syscall_abi.isl` and the shared
/// dispatcher's returns none, so the fused reply-and-wait this demo used to do
/// inside `PageSupply` moved here — which is where a serve loop's reply belongs
/// anyway. The executive's `reply_receive` is kept whole rather than split into
/// `reply` then `receive`: a resident server that replies and then loops back to
/// its own receive is the hang this tree has debugged twice (D85, D91).
pub(crate) fn fs_page_serve(caller_idx: kcore::thread::ThreadId, ep_handle: u64) -> i64 {
    let ep = match chan_resolve_endpoint(caller_idx, ep_handle, Rights::READ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    // SAFETY: the boot CPU alone; one in-flight page-in at a time, so at most
    // one reply is ever owed.
    let owed = unsafe { (*&raw mut FS_REPLY_OWED).take() };
    let result = match owed {
        Some(supplied) => {
            let mut ack = Message::new(MessageHeader::new(PAGER_IFACE_ID, METHOD_SUPPLY_ACK));
            let _ = ack.set_inline(&[supplied as u8]);
            exec_ref().reply_receive(ep, ack)
        }
        None => exec_ref().receive(ep),
    };
    match result {
        Ok(request) => encode_result(Ok(fs_request_offset(&request))),
        Err(e) => encode_result(Err(e)),
    }
}

/// `PageSupply`: the FS service supplies the pending page-in from its buffer.
/// The 4 KiB read of the source page happens here — while the *service's* CR3 is
/// active (the M14 discipline) — and `supply_page` installs into the faulting
/// client (`USER_PROCESS`) through the HHDM (no CR3 switch). The reply that
/// releases the faulter is `PageServe`'s.
///
/// **It reads a `PageSupplyArgs` through `arg0`, which is what
/// `syscall_abi.isl` declares and what `kcore::dispatch` reads** (D298). Until
/// then this handler took an endpoint handle and a source address in two
/// registers and returned the next offset, so syscall 22 meant one thing here
/// and another on the four ports that run the shared dispatcher — a number
/// with two ABIs, which is the one thing a published surface cannot carry.
pub(crate) fn fs_page_supply(caller_idx: kcore::thread::ThreadId, args_ptr: u64) -> i64 {
    // SAFETY: the boot CPU alone; one in-flight page-in fault (synchronous).
    let (fault_va, object, offset) = match unsafe { *(&raw const FS_PENDING) } {
        Some(pending) => pending,
        None => return encode_result(Err(KError::Protocol)),
    };
    // Validate before interpreting, through the ISL-generated decoder — the
    // same one the shared dispatcher uses, so the two cannot disagree about
    // what a well-formed request is.
    let request = {
        // SAFETY: the boot CPU alone; PROCESSES populated before ring 3 runs.
        let processes = unsafe { &mut *&raw mut PROCESSES };
        let Some(service) = processes.process_of_thread(caller_idx) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::PAGE_SUPPLY_ARGS_SIZE];
        if let Err(e) = read_user(service, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_page_supply_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    // The capability, then the request. `memory` must name the object being
    // paged, with SUPPLY — a service that could fill any object it happened to
    // have a handle to would not be a capability system.
    {
        // SAFETY: the boot CPU alone, as above.
        let processes = unsafe { &mut *&raw mut PROCESSES };
        let Some(service) = processes.process_of_thread(caller_idx) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match service
            .handles()
            .lookup(kcore::handle::Handle::from_raw(request.memory))
        {
            Ok((named, held)) => {
                if named != object || !Rights::SUPPLY.is_subset_of(held) {
                    return encode_result(Err(KError::AccessDenied));
                }
            }
            Err(e) => return encode_result(Err(e)),
        }
    }
    // And the offset must be the one the kernel asked for. Decoding a field and
    // then ignoring it is reading the schema's shape while implementing
    // something else.
    if request.offset != offset {
        return encode_result(Err(KError::InvalidArgument));
    }
    let src_va = request.source;
    // Validate the service's source page lies in its own readable mappings.
    // SAFETY: the boot CPU alone; PROCESSES populated before the ring-3 threads run.
    let src_ok = {
        let processes = unsafe { &mut *&raw mut PROCESSES };
        match processes.process_of_thread(caller_idx) {
            Some(service) => {
                validate_user_range(service.space(), src_va, FRAME_SIZE, false).is_ok()
            }
            None => false,
        }
    };
    let supplied = if src_ok {
        // SAFETY: src_va validated as a 4 KiB user-readable range in the active
        // service space; read-only. Copied into a fresh frame + installed into
        // the faulting client below.
        // As the loader's source above: a validated user page the kernel reads.
        // SAFETY: `src_va` was validated as a 4 KiB user-readable range in the
        // active service space just above.
        // SAFETY: the boot CPU alone; RESOLVER_FRAMES + USER_PROCESS (the faulting
        // client) are set before the ring-3 threads run.
        let frames = unsafe { RESOLVER_FRAMES.as_mut() };
        let client = unsafe { (*&raw mut USER_PROCESS).as_mut() };
        // The window spans the *copy*, not the slice: `fs_supply` is what reads
        // the service's page. Closed at the end of the borrow it would already
        // be shut by the time the read happened.
        // SAFETY: `src_va` was validated user-readable in the active service
        // space above, which is what the window's contract asks for.
        let _access = unsafe { kcore::useraccess::Window::open() };
        // SAFETY: `src_va` was validated as a 4 KiB user-readable range in the
        // active service space above, and the window permits reaching it.
        let src = unsafe { core::slice::from_raw_parts(src_va as *const u8, FRAME_SIZE as usize) };
        match (frames, client) {
            (Some(frames), Some(client)) => fs_supply(client.space_mut(), fault_va, src, frames),
            _ => false,
        }
    } else {
        FS_BAD_SRC_DENIED.store(true, Ordering::Relaxed);
        false
    };
    if supplied {
        FS_SUPPLIED.fetch_add(1, Ordering::Relaxed);
    }
    // The faulter is still parked; `PageServe` is what answers it. Recorded
    // here because whether the page went in is what the answer says, and a
    // denied supply owes the reply just as much — otherwise the faulter waits
    // for ever instead of re-faulting.
    // SAFETY: the boot CPU alone; one in-flight page-in at a time.
    unsafe { FS_REPLY_OWED = Some(supplied) };
    encode_result(Ok(0))
}

/// The FS demo's syscall dispatcher. The FS *service* (in `PROCESSES`) drives
/// `PageServe`/`PageSupply`; the *client* is the faulter (`USER_PROCESS`) and only
/// calls `ProcessExit` (its reads fault and route through the page-fault
/// resolver). `ProcessExit` is therefore always the client.
pub(crate) fn fs_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    USER_RING3_REACHED.store(true, Ordering::Relaxed);
    USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);
    let number = match SyscallNumber::from_u64(frame.number) {
        Some(number) => number,
        None => return syscall::ENOSYS,
    };
    match number {
        SyscallNumber::Null => encode_result(Ok(0)),
        SyscallNumber::ProcessExit => {
            // The client (faulter) exits; end the run.
            // SAFETY: the boot CPU alone; statics set before the ring-3 threads run.
            if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
                process.exit(frame.arg0 as i32);
            }
            FS_CLIENT_EXIT.store(frame.arg0 as i32, Ordering::Relaxed);
            // SAFETY: the boot CPU alone; EXEC holds this demo's threads' scheduler.
            if let Some(exec) = unsafe { (*&raw mut EXEC).as_mut() } {
                exec.scheduler().yield_to_boot();
            }
            0
        }
        SyscallNumber::PageServe => {
            let Some(caller_idx) = chan_current_id() else {
                return syscall::ENOSYS;
            };
            fs_page_serve(caller_idx, frame.arg0)
        }
        SyscallNumber::PageSupply => {
            let Some(caller_idx) = chan_current_id() else {
                return syscall::ENOSYS;
            };
            fs_page_supply(caller_idx, frame.arg0)
        }
        _ => syscall::ENOSYS,
    }
}

// The ring-3 FS SERVICE: park for a page-in request (returns the fault offset),
// then supply that page from its buffer (`FS_BUF_VA + offset`) and wait for the
// next — a bare serve/supply loop. Endpoint handle raw 0.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global m18_fs_service_program_start
.global m18_fs_service_program_end
m18_fs_service_program_start:
    # The PageSupplyArgs this service reuses, built once on its own stack and
    # refilled per request. `offset` and `source` are the only fields that move.
    sub rsp, 48                        # 40 bytes of args, 16-byte aligned
    mov dword ptr [rsp], 40            # size
    mov dword ptr [rsp + 4], 1         # version
    mov qword ptr [rsp + 8], 0         # flags
    mov dword ptr [rsp + 16], 1        # memory = handle raw 1 (the object, SUPPLY)
    mov dword ptr [rsp + 20], 0        # reserved

    xor edi, edi                       # arg0 = endpoint handle (raw 0)
    mov eax, 21                        # PageServe -> rax = fault offset
    syscall
    # Negative probe: one deliberately out-of-buffer source — the kernel denies
    # it (the range is enforced), the faulter re-faults, then we serve it for real.
    mov [rsp + 24], rax                # offset (the one the kernel asked for)
    mov rdx, 0x60000000                # outside the buffer at FS_BUF_VA (0x50000000)
    mov [rsp + 32], rdx                # source
    mov rdi, rsp                       # arg0 = &PageSupplyArgs
    mov eax, 22                        # PageSupply(bad) -> denied
    syscall
    xor edi, edi
    mov eax, 21                        # PageServe -> rax = retried offset
    syscall
1:
    mov [rsp + 24], rax                # offset
    lea rdx, [rax + 0x50000000]        # source = FS_BUF_VA + offset
    mov [rsp + 32], rdx
    mov rdi, rsp                       # arg0 = &PageSupplyArgs
    mov eax, 22                        # PageSupply -> 0
    syscall
    xor edi, edi
    mov eax, 21                        # PageServe -> rax = next offset
    syscall
    jmp 1b
m18_fs_service_program_end:
.text
"#
);

// SAFETY: names the FS-service blob's bounds from the global_asm above; the
// extern block only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static m18_fs_service_program_start: u8;
    pub(crate) static m18_fs_service_program_end: u8;
}

/// M18: the RAM-backed filesystem service. A ring-3 client maps a pager-backed
/// memory object and reads it; each page fault drives the existing external-pager
/// handoff (`forward_page_in`→`exec.call`) to a ring-3 **FS service**, which
/// supplies the page from its own RAM buffer via `PageServe`/`PageSupply`. The
/// external-pager bet, end to end, with the pager in ring 3.
pub(crate) fn fs_service_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    set_page_fault_resolver(page_fault_resolver);
    // SAFETY: one-shot registration before this demo's ring-3 threads run.
    unsafe { set_syscall_handler(fs_syscall_handler) };
    set_user_fault_handler(pager_user_fault_handler);
    FS_SUPPLIED.store(0, Ordering::Relaxed);
    FS_BAD_SRC_DENIED.store(false, Ordering::Relaxed);
    FS_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    PAGER_PAGE_INS.store(0, Ordering::Relaxed);

    // One executive holds the service + the faulting client, so the page-in
    // `call` blocks the faulter and hands off directly to the service.
    // SAFETY: the boot CPU alone; fresh executive + process table for the demo.
    unsafe {
        exec_restart(1);
        PROCESSES = ProcessTable::new();
    }
    let (client_ep, service_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("fs: FAIL — channel create: {e:?}"),
    };
    // SAFETY: the boot CPU alone; set once before the threads run.
    unsafe { PAGER_ENDPOINTS = Some((client_ep, service_ep)) };
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let service_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("fs: FAIL — endpoint object: {e:?}"),
    };
    exec_ref().bind_endpoint_object(service_ep, service_ep_obj);
    let mem_obj = match objects.create(ObjectType::Memory) {
        Ok(id) => id,
        Err(e) => return kprintln!("fs: FAIL — memory object: {e:?}"),
    };

    // The FS SERVICE, built (and scheduled) first so it parks in `PageServe`
    // before the client faults. Its file buffer is mapped rw and pre-filled with
    // `FS_CONTENT_BASE+N` per page, under its own (now-active) CR3.
    let sblob = &raw const m18_fs_service_program_start;
    let slen = (&raw const m18_fs_service_program_end as usize)
        - (&raw const m18_fs_service_program_start as usize);
    let (mut service, _stidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        sblob,
        slen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    if service
        .space_mut()
        .map_anonymous(
            VirtAddr::new(FS_BUF_VA),
            PAGER_OBJ_PAGES * FRAME_SIZE,
            PageFlags::rw().user(),
            frames,
        )
        .is_err()
    {
        return kprintln!("fs: FAIL — map service buffer");
    }
    for n in 0..PAGER_OBJ_PAGES {
        // SAFETY: the service space is active (chan_build_process left it so); the
        // buffer page was just mapped writable in it. Fill the first byte (the
        // client reads one byte per page).
        // Seeding the service's buffer pages from the kernel, in its space.
        // SAFETY: the service space is active and the page is mapped writable.
        {
            let _access = unsafe { kcore::useraccess::Window::open() };
            unsafe { *((FS_BUF_VA + n * FRAME_SIZE) as *mut u8) = (FS_CONTENT_BASE + n) as u8 };
        }
    }
    if service
        .handles_mut()
        .install(service_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("fs: FAIL — install service endpoint");
    }
    // Handle raw 1: the object this service is the pager for. `PageSupplyArgs`
    // names the memory it fills, so the service has to hold a capability to it
    // — which is the difference between a pager and anything that can write
    // into any object it can name (D298).
    if service
        .handles_mut()
        .install(mem_obj, Rights::SUPPLY)
        .is_err()
    {
        return kprintln!("fs: FAIL — install service memory object");
    }

    // The CLIENT (the faulter = `USER_PROCESS`), built second. Reuses the M12
    // pager client blob; its pager-backed region is the memory object.
    let cblob = &raw const pager_program_start;
    let clen = (&raw const pager_program_end as usize) - (&raw const pager_program_start as usize);
    let (mut client, _ctidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        cblob,
        clen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    if client
        .space_mut()
        .map_object(
            VirtAddr::new(PAGER_OBJ_VA),
            PAGER_OBJ_PAGES * FRAME_SIZE,
            PageFlags::rw().user(),
            mem_obj,
            0,
        )
        .is_err()
    {
        return kprintln!("fs: FAIL — map_object client region");
    }

    // Re-activate the service (first-run) space; publish the service into the
    // process table (handler resolves it there) and the client as `USER_PROCESS`
    // (the resolver's faulter). `RESOLVER_FRAMES` for the supply path.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { service.space().activate(kcore::percpu::current_index()) };
    service.set_running();
    client.set_running();
    if processes_insert(service).is_err() {
        return kprintln!("fs: FAIL — insert service process");
    }
    // SAFETY: the boot CPU alone; publishing the faulting client + allocator.
    unsafe {
        USER_PROCESS = Some(client);
        RESOLVER_FRAMES = core::ptr::from_mut(frames);
    }

    exec_ref().run();

    // Back on boot with the client CR3 active (it ran last): verify each page
    // holds the FS service's content before restoring the kernel space.
    let mut content_ok = true;
    for i in 0..PAGER_OBJ_PAGES {
        // SAFETY: the page is resident (supplied) and user-readable from ring 0.
        // A user page the demo reads to check what the service left there.
        // SAFETY: the demo's space is active and the page is mapped readable.
        let _access = unsafe { kcore::useraccess::Window::open() };
        let byte =
            unsafe { core::ptr::read_volatile((PAGER_OBJ_VA + i * FRAME_SIZE) as *const u8) };
        if u64::from(byte) != FS_CONTENT_BASE + i {
            content_ok = false;
        }
    }
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let page_ins = PAGER_PAGE_INS.load(Ordering::Relaxed);
    let supplied = FS_SUPPLIED.load(Ordering::Relaxed);
    let client_exit = FS_CLIENT_EXIT.load(Ordering::Relaxed);
    let bad_denied = FS_BAD_SRC_DENIED.load(Ordering::Relaxed);
    // SAFETY: the boot CPU alone; the objects table is quiescent post-run.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let obj_conserved = objects.is_live(mem_obj) && objects.refcount(mem_obj) == Some(1);
    // One extra page-in: the out-of-buffer probe was denied, so page 0 re-faulted
    // once before being served for real. `supplied` counts only the good supplies.
    let pass = content_ok
        && page_ins == PAGER_OBJ_PAGES + 1
        && supplied == PAGER_OBJ_PAGES
        && client_exit == 0
        && obj_conserved
        && bad_denied;
    report(&verdict(
        DemoId::FsService,
        pass,
        [supplied, FS_CONTENT_BASE, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        // fs: FAIL — content_ok={content_ok} page_ins={page_ins}
        // supplied={supplied} client_exit={client_exit}
        // bad_denied={bad_denied} obj_conserved={obj_conserved}
        kprintln!(
            "fs: FAIL content={content_ok} page_ins={page_ins} supplied={supplied} exit={client_exit} bad={bad_denied} obj={obj_conserved}"
        );
    }
}
