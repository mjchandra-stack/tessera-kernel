// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! User-space channel IPC: a ring-3 client calls a ring-3 server.
//!
//! The same handoff `ipc` proves between kernel threads, made reachable from ring
//! 3 through handles, with a capability transferred in the reply.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- M19: component manager (a ring-3 service launches + supervises a service) --

// --- M15: user-space channel IPC (ring-3 client calls a ring-3 server) --------

/// Observations, published by the channel handlers and checked on boot.
/// Debug-write count (want 2: one per process).
pub(crate) static CHAN_PRINTS: AtomicU64 = AtomicU64::new(0);
/// Set once the server received the client's "ping".
pub(crate) static CHAN_SERVER_SAW_PING: AtomicBool = AtomicBool::new(false);

/// What the channel demos watch, all of it read out of what the calls did
/// rather than out of a copy of the calls.
///
/// **Every static below used to be set inside this port's own `ChannelRecv`
/// and `ChannelCall`** — two implementations of calls `kcore::dispatch`
/// already had, kept for six stores. The claims are the same and their
/// evidence is better: `ping` and `pong` are the bytes the kernel *delivered*
/// into the receiver's own buffer, not bytes peeked at on the way past, so a
/// kernel that decided not to deliver them now fails the check it used to pass
/// (D299).
pub(crate) fn chan_observer(
    phase: crate::syscalls::Phase,
    number: SyscallNumber,
    frame: &SyscallFrame,
) {
    use crate::syscalls::Phase;
    match (phase, number) {
        // How many times ring 3 reached this port's console. Counted on the way
        // in, so a write that failed validation still counts as a program
        // having tried — which is what "the client and the server each printed
        // once" is asking.
        (Phase::Entered, SyscallNumber::DebugWrite) => {
            CHAN_PRINTS.fetch_add(1, Ordering::Relaxed);
        }
        // A round trip's cost is a difference, so it needs the reading before.
        (Phase::Entered, SyscallNumber::ChannelCall) => {
            CHAN_CALL_SWITCHES_BEFORE.store(exec_ref().switch_count(), Ordering::Relaxed);
        }
        (Phase::Answered(result), SyscallNumber::ChannelCall) if result >= 0 => {
            let before = CHAN_CALL_SWITCHES_BEFORE.load(Ordering::Relaxed);
            CHAN_ROUNDTRIP_SWITCHES.store(
                exec_ref().switch_count().wrapping_sub(before),
                Ordering::Relaxed,
            );
            if let Some(delivered) = delivered_inline(frame.arg0) {
                CHAN_CLIENT_SAW_PONG.store(&delivered == b"pong", Ordering::Relaxed);
            }
            // And a reply may grant a capability, which the device-manager demo
            // is entirely about. Same evidence as on a receive: what the kernel
            // reported installing, against a sentinel the caller seeded.
            if let Some(installed) = installed_report(frame.arg0)
                && installed != u32::MAX
            {
                CHAN_HANDLE_TRANSFERRED.store(true, Ordering::Relaxed);
            }
        }
        (Phase::Answered(4), SyscallNumber::ChannelRecv) => {
            if let Some(delivered) = delivered_inline(frame.arg0) {
                CHAN_SERVER_SAW_PING.store(&delivered == b"ping", Ordering::Relaxed);
            }
            // A capability crossed if the kernel reported installing one. The
            // receiver seeded the slot, so an unchanged sentinel means nothing
            // arrived — which "handle 0" would not have distinguished.
            if let Some(installed) = installed_report(frame.arg0)
                && installed != u32::MAX
            {
                CHAN_HANDLE_TRANSFERRED.store(true, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

/// The four bytes a call or receive landed in the caller's own buffer, read
/// back through its `ChannelMsgArgs`.
fn delivered_inline(args_ptr: u64) -> Option<[u8; 4]> {
    let caller_idx = chan_current_id()?;
    // SAFETY: the boot CPU alone; PROCESSES is populated before the ring-3
    // threads run and touched only on this boot CPU. The call has returned, so
    // the caller is current and nothing is parked.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    let process = processes.process_of_thread(caller_idx)?;
    let mut abuf = [0u8; syscall::CHANNEL_MSG_ARGS_SIZE];
    read_user(process, args_ptr, &mut abuf).ok()?;
    let args = syscall::decode_channel_msg_args(&abuf).ok()?;
    let mut got = [0u8; 4];
    read_user(process, args.inline_ptr, &mut got).ok()?;
    Some(got)
}

/// The handle the kernel reported installing from an arrived message, as the
/// receiver's `installed_ptr` names.
fn installed_report(args_ptr: u64) -> Option<u32> {
    let caller_idx = chan_current_id()?;
    // SAFETY: the boot CPU alone, as above.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    let process = processes.process_of_thread(caller_idx)?;
    let mut abuf = [0u8; syscall::CHANNEL_MSG_ARGS_SIZE];
    read_user(process, args_ptr, &mut abuf).ok()?;
    let args = syscall::decode_channel_msg_args(&abuf).ok()?;
    if args.installed_ptr == 0 {
        return None;
    }
    let mut raw = [0u8; 4];
    read_user(process, args.installed_ptr, &mut raw).ok()?;
    Some(u32::from_le_bytes(raw))
}

/// The reading a round trip's cost is measured against.
static CHAN_CALL_SWITCHES_BEFORE: AtomicU64 = AtomicU64::new(0);
/// Set once the client received the server's "pong".
pub(crate) static CHAN_CLIENT_SAW_PONG: AtomicBool = AtomicBool::new(false);
/// Set once the server installed the handle the client transferred.
pub(crate) static CHAN_HANDLE_TRANSFERRED: AtomicBool = AtomicBool::new(false);
/// Scheduler switches consumed by the client's `ChannelCall` round trip (want 2).
pub(crate) static CHAN_ROUNDTRIP_SWITCHES: AtomicU64 = AtomicU64::new(u64::MAX);
/// The client's ring-3 exit code (`i32::MIN` = not observed).
pub(crate) static CHAN_CLIENT_EXIT: AtomicI32 = AtomicI32::new(i32::MIN);
/// The client thread's scheduler index, so the exit handler can tell it from the
/// server (`u64::MAX` = unset).
pub(crate) static CHAN_CLIENT_TIDX: AtomicU64 = AtomicU64::new(u64::MAX);

// The ring-3 SERVER. Announces itself, then (Steps 3+) receives a request on its
// endpoint (handle raw 0) and replies. SYSCALL ABI: rax = number, args in
// rdi/rsi. Message lengths are hardcoded immediates kept in sync with the
// `.ascii` below (a symbol used as an immediate assembles as a memory load in
// Intel-syntax global_asm!; only `.quad`/`.long` label differences are real
// constants — the M13 gotcha).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global chan_server_program_start
.global chan_server_program_end
chan_server_program_start:
    lea rdi, [rip + chan_server_msg]   # arg0 = message pointer
    mov esi, 18                        # arg1 = length (== chan_server_msg bytes)
    mov eax, 1                         # SyscallNumber::DebugWrite
    syscall
    # Receive the client's request on the endpoint (handle raw 0). Blocks in the
    # kernel until the client's Call hands off here.
    mov eax, 0x70000010                 # a sentinel in the installed-handle slot,
    mov dword ptr [rax], 0xffffffff     # so "nothing arrived" is not "handle 0"
    lea rdi, [rip + chan_server_recv_args] # arg0 = ChannelMsgArgs
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # SyscallNumber::ChannelRecv
    syscall
    # Reply "pong" and hand off back to the caller (this thread is then Blocked).
    lea rdi, [rip + chan_reply_args]   # arg0 = ChannelMsgArgs (the reply)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 15                        # SyscallNumber::ChannelReply
    syscall
1:
    jmp 1b
chan_server_msg:
    .ascii "chan: server ready"
.balign 8
chan_reply_args:
    .long 88                           # size
    .long 4                            # version
    .quad 0                            # flags
    .quad 0xabcd                       # interface_id
    .quad 0                            # txn_id (kernel stamps)
    .long 1                            # method_id
    .long 0                            # msg_flags
    # inline_ptr: runtime VA of the body. The blob loads at USER_CODE_VA
    # (0x400000), so start-relative offset + that base is the live VA (a label
    # *difference* is a real assemble-time constant; an absolute label would be a
    # kernel VA once relocated — the M13 gotcha).
    .quad 0x400000 + chan_pong_body - chan_server_program_start
    .quad 4                            # inline_len
    .quad 0                            # handles_ptr
    .quad 0                            # handle_count
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
chan_pong_body:
    .ascii "pong"
.balign 8
chan_server_recv_args:
    .long 88                           # ChannelMsgArgs: size
    .long 4                            # version
    .quad 0                            # flags
    .quad 0                            # interface_id (any, on a receive)
    .quad 0                            # txn_id
    .long 0                            # method_id
    .long 0                            # msg_flags (blocking)
    .quad 0x70000000                   # inline_ptr: a writable landing area in
    .quad 4                            # this program's own stack region
    .quad 0                            # handles_ptr
    .quad 0                            # handle_count
    .quad 0x70000010                   # installed_ptr: where the kernel says which
    .quad 1                            # installed_cap: handle it installed, if any
chan_server_program_end:
.text
"#
);

// The ring-3 CLIENT. Announces itself, then (Step 4+) calls the server and reads
// the reply. Same ABI/length rules as the server blob.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global chan_client_program_start
.global chan_client_program_end
chan_client_program_start:
    lea rdi, [rip + chan_client_msg]   # arg0 = message pointer
    mov esi, 18                        # arg1 = length (== chan_client_msg bytes)
    mov eax, 1                         # SyscallNumber::DebugWrite
    syscall
    # Call the server with "ping" on the endpoint (handle raw 0); blocks for the
    # reply, which the kernel verifies handler-side.
    mov eax, 0x70000000                 # the request goes in the landing area, not
    mov dword ptr [rax], 0x676e6970    # in read-only code: a reply lands here too
    lea rdi, [rip + chan_call_args]    # arg0 = ChannelMsgArgs (the request)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    xor edx, edx                       # arg2 = no deadline on the reply (D283)
    mov eax, 14                        # SyscallNumber::ChannelCall
    syscall
    xor edi, edi                       # exit code 0
    mov eax, 5                         # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
chan_client_msg:
    .ascii "chan: client ready"
.balign 8
chan_call_args:
    .long 88                           # size
    .long 4                            # version
    .quad 0                            # flags
    .quad 0xabcd                       # interface_id
    .quad 0                            # txn_id (kernel stamps)
    .long 1                            # method_id
    .long 0                            # msg_flags
    .quad 0x70000000                   # inline_ptr: a writable landing area in
    .quad 4                            # inline_len
    .quad 0x400000 + chan_client_handles - chan_client_program_start  # handles_ptr (live VA)
    .quad 1                            # handle_count (transfer one capability)
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
chan_ping_body:
    .ascii "ping"
.balign 8
chan_client_handles:
    # One HandleTransfer descriptor (channel_msg.isl): handle, mode, rights.
    # Mode 0 is TransferMode::TRANSFER — the sender's copy goes away.
    # This demo is about the transfer itself, so the capability travels with the
    # rights it was granted (READ|TRANSFER) rather than a narrowed set.
    .long 1                            # the transfer object handle (slot 1, raw 1)
    .long 0                            # reserved (must be zero)
    .quad 0x81                         # rights: READ|TRANSFER
chan_client_program_end:
.text
"#
);

// SAFETY: names the two channel-demo blob bounds from the global_asm above; the
// extern block only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static chan_server_program_start: u8;
    pub(crate) static chan_server_program_end: u8;
    pub(crate) static chan_client_program_start: u8;
    pub(crate) static chan_client_program_end: u8;
}

/// The scheduler index of the thread currently running under the channel demo —
/// how a channel syscall resolves its caller. `None` before the demo's executive
/// starts.
pub(crate) fn chan_current_index() -> Option<usize> {
    // SAFETY: the boot CPU alone; EXEC is set before any channel ring-3 thread runs and
    // touched only on this boot CPU.
    unsafe { (*&raw mut EXEC).as_mut() }.and_then(|exec| exec.scheduler().current())
}

/// The running thread's **identity**, which is what the machine-wide process
/// table is keyed on.
///
/// Its slot ([`chan_current_index`]) indexes this CPU's own arrays and means
/// nothing to another CPU, so the two are not interchangeable and both exist.
/// The identity of the thread in this CPU's scheduler slot `idx`.
///
/// A process claims the identity: the process table is machine-wide and a slot
/// is one CPU's own numbering. `None` for an empty slot, which has no identity
/// to record — and recording a wrong one is how a process comes to answer for
/// somebody else's thread.
pub(crate) fn thread_id_of(idx: usize) -> Option<kcore::thread::ThreadId> {
    exec_ref().scheduler().thread_id(idx)
}

pub(crate) fn chan_current_id() -> Option<kcore::thread::ThreadId> {
    let slot = chan_current_index()?;
    thread_id_of(slot)
}

/// Closes every channel endpoint the process owning `thread` holds, waking
/// whoever was parked awaiting a reply from it.
///
/// **A caller mid-call, and nobody else.** `Executive::close_endpoints_of`
/// leaves a peer that is merely parked in a receive alone, and that distinction
/// is the whole design: a device manager sits in a receive on the channel a
/// *replacement* driver will be bound over, and telling it the peer is gone
/// ends the conversation recovery depends on. A caller awaiting a reply from
/// this process specifically is the opposite case — nothing will ever send one.
///
/// **Read from the process's own handle table**, never from a list kept beside
/// it: a channel it was given late, or one that arrived by transfer, is exactly
/// the one a separate list forgets.
///
/// Called from the two places a process stops being able to answer — the ring-3
/// fault path and `ProcessExit` — and from nowhere else. Doing it on every
/// thread exit is not the same thing and was measured on the other port to take
/// most of a boot's checks down with it.
pub(crate) fn close_endpoints_of(thread: kcore::thread::ThreadId) {
    /// Handle slots one process can hold. The table itself is this size, so an
    /// audit that filled this array read all of it.
    const SLOTS: usize = 32;
    let mut audit = [(ObjectId::from_raw(0), kcore::rights::Rights::none()); SLOTS];
    // SAFETY: transient raw access to the static process table; a read, and the
    // executive borrow below does not overlap it.
    let count = unsafe {
        (&mut *&raw mut PROCESSES)
            .process_of_thread(thread)
            .map(|process| process.handles().audit(&mut audit))
            .unwrap_or(0)
    };
    let mut held = [ObjectId::from_raw(0); SLOTS];
    for (slot, (object, _)) in held.iter_mut().zip(audit.iter()).take(count) {
        *slot = *object;
    }
    exec_ref().close_endpoints_of(&held[..count]);
}

/// `sys_process_exit` on the executive substrate. Marks the exiting process
/// `Exited` and records the client's code, then either:
///   - if a parent is parked in `ProcessStart` awaiting this child (the
///     loader / component-manager synchronous handoff), hands control back to
///     the parent with the child's exit code (the child is left `Blocked` and
///     never resumes); or
///   - otherwise parks the exiting thread and switches to the next ready thread
///     — or to boot when none remain (ending the run). The channel server is
///     normally left `Blocked` after its reply and does not reach here.
pub(crate) fn chan_process_exit(caller_idx: kcore::thread::ThreadId, code: i32) -> i64 {
    // SAFETY: the boot CPU alone; statics set before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    if CHAN_CLIENT_TIDX.load(Ordering::Relaxed) == caller_idx.0 {
        CHAN_CLIENT_EXIT.store(code, Ordering::Relaxed);
    }
    // **The endpoints this process held go first, while it is still findable.**
    // A program that finishes normally leaves a peer awaiting its reply just as
    // stuck as one that crashes, and `notify_exit` below marks the process gone
    // — after which the handle audit would find nothing to close.
    close_endpoints_of(caller_idx);
    // Marks the process exited and hands back whoever was waiting on it. The
    // wake happens before this thread leaves the CPU, which is the order that
    // matters and is `kcore::loader`'s to get right.
    let woke = kcore::loader::notify_exit(exec_ref(), processes, caller_idx, code);
    if woke {
        LOADER_CHILD_EXIT.store(code, Ordering::Relaxed);
        LOADER_CHILD_RAN.store(true, Ordering::Relaxed);
    }
    // Terminates this thread and picks the next ready one, rather than merely
    // blocking it: a blocked thread is one something might wake, and nothing
    // ever will.
    exec_ref().scheduler().exit_current();
    0
}

/// The legacy PIC as the kernel core's interrupt-revocation seam
/// (`kcore::devmgr::InterruptRouter`).
///
/// Zero-sized: the controller is a pair of fixed I/O ports. It exists as a
/// type solely because the kernel core must not name a PIC — and this port's
/// PIC is itself tracked debt (build/README.md, D87), which the seam makes
/// replaceable without kcore noticing.
pub(crate) struct PicRouter;

impl kcore::devmgr::InterruptRouter for PicRouter {
    fn mask(&mut self, intid: u32) {
        // A PIC line is 0..=15; anything wider names no line this controller
        // has, and masking a truncated value would mask a *different* device's
        // interrupt. Refusing to act on a value that cannot be a line is the
        // only correct answer, and it cannot happen — the graph's INTIDs on
        // this port come from `register_com2_device`.
        if let Ok(line) = u8::try_from(intid) {
            tessera_karch_x86_64::mask_irq(line);
        }
    }
}

/// Resolves the endpoint a channel syscall targets: looks the endpoint handle up
/// in the caller's table, checks it carries `need`, and maps its object id back
/// to the live `EndpointId` (the handle→endpoint bridge). Returns a `Copy`
/// `EndpointId` and drops every `PROCESSES` borrow, so the caller may hand off
/// without a borrow spanning the switch.
pub(crate) fn chan_resolve_endpoint(
    caller_idx: kcore::thread::ThreadId,
    ep_handle: u64,
    need: Rights,
) -> Result<EndpointId, KError> {
    // SAFETY: the boot CPU alone; PROCESSES is populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    kcore::dispatch::resolve_endpoint(exec_ref(), processes, caller_idx, ep_handle, need)
}

/// Builds a ring-3 process from a rodata blob: its own address space, a code page
/// (copied from the blob, then re-protected rx — W^X), a user stack + kernel
/// stack, and an initial thread (added to `EXEC`, recorded in the process).
/// Returns the not-yet-inserted process and its scheduler thread index, and
/// leaves the new space active (the caller re-activates the first-run space
/// before `run`). Panics on any setup failure, like the other ring-3 demos.
#[allow(clippy::too_many_arguments)]
pub(crate) fn chan_build_process(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    asid: u16,
    blob_start: *const u8,
    blob_len: usize,
    kstack_base: u64,
    arg: usize,
) -> (Process<KernelAddressSpace>, usize) {
    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("chan demo: new_user failed: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(
        user_arch,
        Asid(asid),
        1u64 << kcore::percpu::current_index(),
    );
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => panic!("chan demo: process object failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    if process
        .space_mut()
        .map_anonymous(
            VirtAddr::new(USER_CODE_VA),
            code_len,
            PageFlags::rw().user(),
            frames,
        )
        .is_err()
    {
        panic!("chan demo: map code failed");
    }
    let thread = match Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(USER_CODE_VA),
        arg,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        VirtAddr::new(kstack_base),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("chan demo: spawn_user failed: {e:?}"),
    };
    let tidx = match exec_ref().add_thread(thread) {
        Ok(idx) => idx,
        Err(e) => panic!("chan demo: add_thread failed: {e:?}"),
    };
    if process
        .add_thread(thread_id_of(tidx).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        .is_err()
    {
        panic!("chan demo: process add_thread failed");
    }

    // Activate the new space to copy the blob into its code page, then re-protect
    // it rx (W^X). All of the blob's data (message, arg structs) is read-only in
    // this rx page — no writable user page is needed.
    // SAFETY: the user space shares the kernel higher-half; boot code, stack, and
    // the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(kcore::percpu::current_index()) };
    // SAFETY: the blob is in kernel rodata; USER_CODE_VA is a writable user page
    // in the now-active space with room for it.
    // The kernel means to reach a user page here: it is populating a
    // process it is building, in that process's own space. Declared
    // rather than assumed, because SMAP now faults an undeclared one.
    // SAFETY: the destination is a page this boot glue just mapped
    // into the space it activated; the window permits reaching it.
    {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::copy_nonoverlapping(blob_start, USER_CODE_VA as *mut u8, blob_len) };
    }
    if process
        .space_mut()
        .protect_range(
            VirtAddr::new(USER_CODE_VA),
            code_len,
            PageFlags::rx().user(),
        )
        .is_err()
    {
        panic!("chan demo: protect code failed");
    }
    (process, tidx)
}

/// Channel IPC: a ring-3 CLIENT process calls a ring-3 SERVER process over a
/// channel — inline bytes plus a transferred capability handle — using the
/// kernel's synchronous call/reply handoff (`Executive::call`/`reply`). Proves
/// the "services talk over channels" model across the privilege boundary and two
/// address spaces (docs/kernel/02 "Channels"; the B3 round trip). The channel is
/// created and its endpoints installed here (the bootstrap-channel model; ring-3
/// `ChannelCreate` is deferred, build/README.md D45).
pub(crate) fn channel_ipc_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration before this demo's ring-3 threads run.
    unsafe { set_syscall_handler(syscall_handler) };
    crate::syscalls::set_observer(crate::host::host_observer);
    set_user_fault_handler(user_fault_handler);

    CHAN_PRINTS.store(0, Ordering::Relaxed);
    CHAN_SERVER_SAW_PING.store(false, Ordering::Relaxed);
    CHAN_CLIENT_SAW_PONG.store(false, Ordering::Relaxed);
    CHAN_HANDLE_TRANSFERRED.store(false, Ordering::Relaxed);
    CHAN_ROUNDTRIP_SWITCHES.store(u64::MAX, Ordering::Relaxed);
    CHAN_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    CHAN_CLIENT_TIDX.store(u64::MAX, Ordering::Relaxed);

    // A fresh process table (so the channel threads' scheduler indices cannot
    // collide with the loader demo's stale entries) and a fresh executive
    // (scheduler + channel table) shared by both ring-3 processes.
    // SAFETY: the boot CPU alone; the loader demo's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    // Create the channel and mint an `ObjectType::Channel` object per endpoint,
    // binding each to its `EndpointId` (the handle→endpoint bridge).
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let (server_ep, client_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("chan: FAIL — channel_create: {e:?}"),
    };
    let server_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("chan: FAIL — server endpoint object: {e:?}"),
    };
    let client_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("chan: FAIL — client endpoint object: {e:?}"),
    };
    exec_ref().bind_endpoint_object(server_ep, server_ep_obj);
    exec_ref().bind_endpoint_object(client_ep, client_ep_obj);

    // Build the SERVER first so it is scheduled first (runs, then parks on
    // `receive`), then the CLIENT. Each gets its endpoint handle at slot 0
    // (raw 0), which its blob names directly.
    let server_blob = &raw const chan_server_program_start;
    let server_len = (&raw const chan_server_program_end as usize)
        - (&raw const chan_server_program_start as usize);
    let (mut server, _server_tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        server_blob,
        server_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    if server
        .handles_mut()
        .install(server_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("chan: FAIL — install server endpoint handle");
    }

    let client_blob = &raw const chan_client_program_start;
    let client_len = (&raw const chan_client_program_end as usize)
        - (&raw const chan_client_program_start as usize);
    let (mut client, client_tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        client_blob,
        client_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    if client
        .handles_mut()
        .install(
            client_ep_obj,
            Rights::READ | Rights::WRITE | Rights::TRANSFER,
        )
        .is_err()
    {
        return kprintln!("chan: FAIL — install client endpoint handle");
    }
    // A capability the client transfers to the server over the channel — installed
    // at slot 1 (raw 1) with `TRANSFER`, which the client blob names. Its refcount
    // must stay 1 as it moves client→message→server (the reference is conserved).
    let xfer_obj = match objects.create(ObjectType::Memory) {
        Ok(id) => id,
        Err(e) => return kprintln!("chan: FAIL — transfer object: {e:?}"),
    };
    if client
        .handles_mut()
        .install(xfer_obj, Rights::READ | Rights::TRANSFER)
        .is_err()
    {
        return kprintln!("chan: FAIL — install transfer handle");
    }
    CHAN_CLIENT_TIDX.store(
        thread_id_of(client_tidx).map_or(u64::MAX, |t| t.0),
        Ordering::Relaxed,
    );

    // Re-activate the server (first-run) space before starting the scheduler, and
    // publish both processes into the table so the handler can resolve callers.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { server.space().activate(kcore::percpu::current_index()) };
    server.set_running();
    client.set_running();
    if processes_insert(server).is_err() {
        return kprintln!("chan: FAIL — insert server process");
    }
    if processes_insert(client).is_err() {
        return kprintln!("chan: FAIL — insert client process");
    }

    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let prints = CHAN_PRINTS.load(Ordering::Relaxed);
    let client_exit = CHAN_CLIENT_EXIT.load(Ordering::Relaxed);
    let saw_ping = CHAN_SERVER_SAW_PING.load(Ordering::Relaxed);
    let saw_pong = CHAN_CLIENT_SAW_PONG.load(Ordering::Relaxed);
    let switches = CHAN_ROUNDTRIP_SWITCHES.load(Ordering::Relaxed);
    let handle_moved = CHAN_HANDLE_TRANSFERRED.load(Ordering::Relaxed);
    // The transferred capability moved client→message→server: its reference is
    // conserved (refcount stays 1, now owned by the server's table).
    // SAFETY: the boot CPU alone; the ring-3 run has returned to boot.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let xfer_conserved = objects.is_live(xfer_obj) && objects.refcount(xfer_obj) == Some(1);
    let pass = prints == 2
        && client_exit == 0
        && saw_ping
        && saw_pong
        && switches == 2
        && handle_moved
        && xfer_conserved;
    report(&verdict(DemoId::ChannelIpc, pass, [0; 8]));
    if !pass {
        // chan: FAIL prints={prints} client_exit={client_exit}
        // saw_ping={saw_ping} saw_pong={saw_pong} switches={switches}
        // handle_moved={handle_moved} xfer_conserved={xfer_conserved}
        kprintln!(
            "chan: FAIL prints={prints} exit={client_exit} ping={saw_ping} pong={saw_pong} sw={switches} moved={handle_moved} xfer={xfer_conserved}"
        );
    }
}
