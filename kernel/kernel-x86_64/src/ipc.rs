// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The synchronous IPC round trip, and the executive every check runs on.
//!
//! The architectural bet that a call between two components costs about what a
//! function call costs, which needs the direct caller->callee handoff rather than
//! a trip through the run queue. `EXEC` and its restart live here because this is
//! the check that first needed them.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- Synchronous IPC round-trip demonstration ---
//
// The riskiest architectural bet: a request/response *call* between two
// components must cost about what a function call costs, which needs the
// synchronous handoff — a direct caller->callee switch and a direct
// callee->caller switch on reply, exactly two context switches, no run-queue
// traffic (docs/architecture/03 "B3"; the two-switch check is
// docs/prototypes/01). A real handoff transfers control, which the mock
// `switch` cannot do, so this property is proven here on hardware; the pure
// logic is host-tested in `kcore`.
//
// The callee is spawned first so it runs first and parks in `receive`; the
// caller then `call`s, handing off directly to the parked callee. With no other
// ready threads, the round trip is exactly two switches. The `Executive` owns
// the scheduler and channel table and lives behind a `static`, re-borrowed per
// operation, because a switch suspends a thread mid-call and a Rust `&mut`
// cannot span it (the same one-CPU-per-scheduler pattern the scheduler uses).

/// Interface/method identifiers for the demo protocol (the ISL expression of
/// this header is `api/isl/examples/channel_msg.isl`).
pub(crate) const IPC_IFACE_ID: u64 = 0x7e55_e2a0_0000_0001;
pub(crate) const IPC_METHOD_PING: u32 = 1;
pub(crate) const IPC_METHOD_PONG: u32 = 2;
pub(crate) const IPC_QUANTUM_TICKS: u32 = 1;
pub(crate) const IPC_STACK_PAGES: u64 = 4;

/// The demo executive (scheduler + channel table). Initialized once in
/// `ipc_roundtrip_demo` before any demo thread runs; thereafter touched only by
/// the boot path and the two demo threads, which are serialized by the handoff
/// (only one runs at a time on this CPU).
pub(crate) static mut EXEC: Option<Executive<ContextSwitch>> = None;

/// The demo channel's two endpoint ids: `.0` is the caller's end, `.1` the
/// callee's. Set once before the threads run.
pub(crate) static mut IPC_ENDPOINTS: Option<(EndpointId, EndpointId)> = None;

/// Separate handle tables for the two demo peers, so the transferred handle is
/// taken from the caller's and installed into the callee's — never shared.
pub(crate) static mut IPC_CALLER_HANDLES: HandleTable = HandleTable::new();
pub(crate) static mut IPC_CALLEE_HANDLES: HandleTable = HandleTable::new();

/// Round-trip results, published by the threads and checked back on boot.
pub(crate) static IPC_ROUNDTRIP_SWITCHES: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPC_REPLY_OK: AtomicBool = AtomicBool::new(false);
pub(crate) static IPC_HANDLE_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Correlation-propagation probes taken from inside the synchronous round trip
/// (D59). The mock scheduler cannot show adoption — its `switch` is a no-op, so
/// a callee never actually runs — so the observation is made here, on target,
/// where the handoff is a real context switch: the callee samples its ambient id
/// before parking and again when `receive` returns under the caller's call.
pub(crate) static CORRELATION_CALLEE_OWN: AtomicU64 = AtomicU64::new(0);
pub(crate) static CORRELATION_CALLEE_DURING_CALL: AtomicU64 = AtomicU64::new(0);
pub(crate) static CORRELATION_CALLER: AtomicU64 = AtomicU64::new(0);
/// Scheduler index of the IPC callee, so the restore can be checked after.
pub(crate) static CORRELATION_CALLEE_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
/// The cause a page-in request left with, and the cause it arrived carrying —
/// the on-target proof that causality survives the message boundary (D60).
/// Page-ins are synchronous and one-at-a-time (see `FS_PENDING`), so the faulter
/// slot always names the request the pager is currently serving. Matches are
/// *counted* at serve time rather than compared at the end, because the last
/// page-in of the boot is served by the ring-3 FS path, which never reaches
/// `serve_page_request` — comparing final values would compare two different
/// requests.
pub(crate) static CORRELATION_PAGE_IN_FAULTER: AtomicU64 = AtomicU64::new(0);
pub(crate) static CORRELATION_PAGE_IN_SERVED: AtomicU64 = AtomicU64::new(0);
pub(crate) static CORRELATION_PAGE_IN_REQUESTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static CORRELATION_PAGE_IN_MATCHED: AtomicU64 = AtomicU64::new(0);

/// The callee's id once the call returned. Sampled immediately after the round
/// trip, not at report time: later demos restart services often enough to reuse
/// the callee's scheduler slot, and the slot's *current* occupant would say
/// nothing about this call.
pub(crate) static CORRELATION_CALLEE_RESTORED: AtomicU64 = AtomicU64::new(0);

/// The single owner of the demo executive, re-borrowed per operation.
pub(crate) fn exec_ref() -> &'static mut Executive<ContextSwitch> {
    // Every path to the executive goes through here, which is what makes this
    // the place to record who reached it (`kcore::exec::occupancy`).
    kcore::exec::occupancy::note_visit();
    // SAFETY: the boot CPU, and one borrow *in use* rather than one borrow
    // live. Several are live: a thread parked in `receive` or `reply` is
    // suspended inside a `&mut Executive` method and holds its borrow until it
    // resumes, which for a server is the rest of the boot — measured at 13 at
    // the end of this one (build/README.md, D230). What makes the reads honest
    // is that a suspended frame touches nothing until it is switched back to,
    // and this CPU runs one thread at a time. Aliasing `&mut` is still UB by
    // the language's rules, and `kcore::exec::occupancy` is where the count
    // that says so is kept.
    unsafe {
        match (*&raw mut EXEC).as_mut() {
            Some(exec) => exec,
            None => panic!("ipc demo: executive uninitialized"),
        }
    }
}

/// Returns the executive to its starting state for the next demo.
///
/// **Restarts the one that exists rather than building a new one.** The two
/// are the same thing for the boot CPU and not for any other: since
/// build/README.md D233 each CPU has its own half of the executive, and a
/// fresh `Executive` brings fresh halves for all of them — so replacing it
/// would rebuild a running secondary's run queue underneath it, once per demo.
///
/// # Safety
///
/// The boot CPU alone, with no live borrow of the executive.
pub(crate) unsafe fn exec_restart(quantum: u32) {
    // SAFETY: the caller's contract, restated.
    unsafe {
        // `<*mut T>::as_mut` rather than an immediate dereference, as in
        // `exec_ref` above — the pointer method is the one form clippy has no
        // finding for, and its suggestion for the other is to name the static,
        // which edition 2024 forbids.
        match (&raw mut EXEC).as_mut().and_then(Option::as_mut) {
            Some(exec) => exec.restart(quantum, 0),
            None => (&raw mut EXEC).write(Some(Executive::new(
                quantum,
                0,
                crate::loader::monotonic_nanos,
            ))),
        }
    }
}

/// The demo channel's endpoint ids.
pub(crate) fn ipc_endpoints() -> (EndpointId, EndpointId) {
    // SAFETY: the boot CPU alone; set once in `ipc_roundtrip_demo` before the threads
    // run, read-only thereafter.
    unsafe {
        match (*&raw const IPC_ENDPOINTS).as_ref() {
            Some(&pair) => pair,
            None => panic!("ipc demo: endpoints uninitialized"),
        }
    }
}

/// Callee: parks in `receive` until the caller's `call` hands off the request,
/// installs the transferred handle into its own table, and `reply`s — which
/// hands control directly back to the caller.
pub(crate) extern "C" fn ipc_callee_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (_caller_ep, callee_ep) = ipc_endpoints();
    // SAFETY: the boot CPU; this static handle table is touched only here.
    let callee_handles = unsafe { &mut *&raw mut IPC_CALLEE_HANDLES };

    // The callee's own causal id, before it parks (D59).
    CORRELATION_CALLEE_OWN.store(kcore::trace::current().correlation, Ordering::Relaxed);

    let request = match exec.receive(callee_ep) {
        Ok(message) => message,
        Err(e) => panic!("ipc demo: callee receive failed: {e:?}"),
    };

    // Resumed by the caller's handoff: the work done from here until the reply
    // belongs to the *caller's* cause, not the callee's own.
    CORRELATION_CALLEE_DURING_CALL.store(kcore::trace::current().correlation, Ordering::Relaxed);

    // Adopt every transferred handle into the callee's table; the object
    // reference conserved across the transfer kept it alive in flight.
    let mut installed = 0usize;
    for transferred in request.handles() {
        match callee_handles.install(transferred.object, transferred.rights) {
            Ok(_) => installed += 1,
            Err(e) => panic!("ipc demo: handle install failed: {e:?}"),
        }
    }
    IPC_HANDLE_RECEIVED.store(
        installed == 1 && request.inline() == b"ping",
        Ordering::Relaxed,
    );

    let mut reply = Message::new(MessageHeader::new(IPC_IFACE_ID, IPC_METHOD_PONG));
    if reply.set_inline(b"pong").is_err() {
        panic!("ipc demo: reply payload too large");
    }
    if let Err(e) = exec.reply(callee_ep, reply) {
        panic!("ipc demo: callee reply failed: {e:?}");
    }
    // `reply` handed off to the caller; the callee is left blocked and is never
    // resumed in this demo. If it ever were, it would simply park again.
    loop {
        let _ = exec.receive(callee_ep);
    }
}

/// Caller: builds a request carrying a transferred handle, issues a synchronous
/// `call` (measuring the switch count across it — the load-bearing check), then
/// hands control back to boot so the run ends.
pub(crate) extern "C" fn ipc_caller_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (caller_ep, _callee_ep) = ipc_endpoints();
    // SAFETY: the boot CPU; these statics are touched only on this boot
    // path (the caller thread and, for `OBJECTS`, the earlier self-check which
    // has already finished and left it empty).
    let caller_handles = unsafe { &mut *&raw mut IPC_CALLER_HANDLES };
    let objects = unsafe { &mut *&raw mut OBJECTS };

    // Create an object and a transferable handle to it, then take the handle for
    // the request — `take` conserves the object reference (no release); the
    // in-flight message carries it to the callee.
    let object = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => panic!("ipc demo: object create failed: {e:?}"),
    };
    let handle = match caller_handles.insert(object, Rights::READ | Rights::TRANSFER) {
        Ok(handle) => handle,
        Err(e) => panic!("ipc demo: handle insert failed: {e:?}"),
    };
    let (transferred_object, transferred_rights) = match caller_handles.take(handle) {
        Ok(pair) => pair,
        Err(e) => panic!("ipc demo: handle take failed: {e:?}"),
    };

    let mut request = Message::new(MessageHeader::new(IPC_IFACE_ID, IPC_METHOD_PING));
    if request.set_inline(b"ping").is_err() {
        panic!("ipc demo: request payload too large");
    }
    if request
        .add_handle(TransferredHandle {
            object: transferred_object,
            rights: transferred_rights,
            // This demo hands the capability over; the sender keeps nothing.
            shared: false,
        })
        .is_err()
    {
        panic!("ipc demo: too many handles on the request");
    }

    // The measurement: a synchronous call must cost exactly two switches —
    // caller->callee to deliver the request, callee->caller to deliver the
    // reply — with no ready-queue traffic in between.
    CORRELATION_CALLER.store(kcore::trace::current().correlation, Ordering::Relaxed);
    let before = exec.switch_count();
    let reply = match exec.call(caller_ep, request) {
        Ok(message) => message,
        Err(e) => panic!("ipc demo: call failed: {e:?}"),
    };
    let after = exec.switch_count();

    IPC_ROUNDTRIP_SWITCHES.store(after - before, Ordering::Relaxed);
    IPC_REPLY_OK.store(reply.inline() == b"pong", Ordering::Relaxed);

    // Hand control back to the boot context; `run` returns and the demo ends.
    exec.scheduler().yield_to_boot();
    // Unreachable: `yield_to_boot` switched away and this thread is never
    // resumed, but the entry signature demands divergence.
    loop {
        core::hint::spin_loop();
    }
}

/// Scheduling passes the boot CPU makes waiting for the cross-CPU call.
///
/// **Much smaller than `ARRIVAL_SPINS`, because an iteration here is not a
/// spin.** Each one drains this CPU's wakeup bitmap, asks the run queue for
/// work, and scans the ports — hundreds of nanoseconds, against the couple of
/// microseconds the other CPU needs to take the wakeup and answer. A bound
/// borrowed from the arrival spin turns a lost wakeup into a boot that hangs
/// for minutes instead of a check that fails.
pub(crate) const CROSS_CALL_PASSES: u64 = 200_000;

/// The boot core's half of the cross-CPU call: one synchronous call out of a
/// kernel thread, to a server parked on another core.
pub(crate) extern "C" fn cross_call_caller(_arg: usize) -> ! {
    let exec = exec_ref();
    kcore::cross_call::call(exec);
    // Back to the boot context, which is spinning in the pump below.
    exec.scheduler().yield_to_boot();
    loop {
        Cpu::halt_until_interrupt();
    }
}

/// Runs the cross-CPU call and returns what it did.
pub(crate) fn cross_cpu_call(
    space: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) -> kcore::cross_call::CrossCall {
    let exec = exec_ref();

    // Wait for the server to register itself on its end. See
    // `kcore::cross_call::server_parked` for why this is waited for rather
    // than assumed — without it the request never crosses.
    let mut left = secondaries::ARRIVAL_SPINS;
    while !kcore::cross_call::server_parked(exec) && left > 0 {
        core::hint::spin_loop();
        left -= 1;
    }

    let base = VirtAddr::new(SECONDARY_THREAD_STACKS);
    let Ok(thread) = kcore::thread::Thread::spawn(
        cross_call_caller,
        0,
        base,
        SECONDARY_THREAD_STACK_BYTES / FRAME_SIZE,
        space,
        frames,
    ) else {
        return kcore::cross_call::outcome();
    };
    if exec.add_thread(thread).is_err() {
        return kcore::cross_call::outcome();
    }

    // **A pump, not one `run`.** The caller blocks on a reply that comes from
    // another core, so this one has nothing runnable in between — `run` returns
    // rather than waiting, and each fresh call to it drains whatever the other
    // core has posted before deciding again. The bound is what stops a lost
    // wakeup hanging the boot instead of failing the check.
    let mut left = CROSS_CALL_PASSES;
    while !kcore::cross_call::finished() && left > 0 {
        exec.run();
        left -= 1;
    }
    kcore::cross_call::outcome()
}

/// Creates one channel and two kernel threads, runs the cooperative round trip,
/// and asserts it completed in exactly two context switches with the
/// transferred handle delivered. A defect fails the boot loudly here.
pub(crate) fn ipc_roundtrip_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    // SAFETY: the boot CPU alone; the only initialization of `EXEC`, before
    // any demo thread runs.
    unsafe { exec_restart(IPC_QUANTUM_TICKS) };
    let exec = exec_ref();

    let (caller_ep, callee_ep) = match exec.channel_create() {
        Ok(pair) => pair,
        Err(e) => panic!("ipc demo: channel create failed: {e:?}"),
    };
    // SAFETY: the boot CPU alone; set once before the threads run.
    unsafe { IPC_ENDPOINTS = Some((caller_ep, callee_ep)) };

    // Callee first: it runs first and parks in `receive`, so the caller's `call`
    // hands off directly to it (no run-queue detour).
    let callee = match Thread::<ContextSwitch>::spawn(
        ipc_callee_entry,
        0,
        alloc_kstack(IPC_STACK_PAGES),
        IPC_STACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("ipc demo: callee spawn failed: {e:?}"),
    };
    match exec.add_thread(callee) {
        Ok(idx) => CORRELATION_CALLEE_INDEX.store(idx as u64, Ordering::Relaxed),
        Err(_) => panic!("ipc demo: thread table full (callee)"),
    }
    let caller = match Thread::<ContextSwitch>::spawn(
        ipc_caller_entry,
        0,
        alloc_kstack(IPC_STACK_PAGES),
        IPC_STACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("ipc demo: caller spawn failed: {e:?}"),
    };
    if exec.add_thread(caller).is_err() {
        panic!("ipc demo: thread table full (caller)");
    }

    // Cooperative run (no timer): switches to the callee (parks), then the
    // caller (round trip), and returns when the caller yields back to boot.
    exec.run();

    // The callee's own id must be back now that the call has returned (D59).
    let callee_idx = CORRELATION_CALLEE_INDEX.load(Ordering::Relaxed) as usize;
    CORRELATION_CALLEE_RESTORED.store(
        exec.scheduler().thread_correlation(callee_idx).unwrap_or(0),
        Ordering::Relaxed,
    );

    let switches = IPC_ROUNDTRIP_SWITCHES.load(Ordering::Relaxed);
    if !IPC_REPLY_OK.load(Ordering::Relaxed) {
        panic!("ipc demo: caller did not receive the expected reply");
    }
    if !IPC_HANDLE_RECEIVED.load(Ordering::Relaxed) {
        panic!("ipc demo: transferred handle did not arrive at the callee");
    }
    if switches != 2 {
        panic!("ipc demo: round trip used {switches} switches, expected exactly 2");
    }
    kprintln!(
        "ipc: sync call round trip in {switches} switches (direct handoff); reply \"pong\", 1 handle transferred"
    );
}
