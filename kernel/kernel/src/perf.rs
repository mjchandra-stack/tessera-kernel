// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The microbenchmark harness (docs/prototypes/01).
//!
//! Serialized invariant-TSC timing and exact percentiles from the sorted sample
//! buffer, over the primitives the budgets in docs/architecture/03 are written
//! against.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- Performance microbenchmark harness (docs/prototypes/01) ---
//
// Measures the primitives M2–M8 built — B1 syscall, B2 handle op, B3 IPC round
// trip, B7 context switch, B8 anon fault, B9 COW fault, B10 pager page-in —
// with serialized invariant-TSC timing and EXACT percentiles from the sorted
// sample set (never a streaming estimator). Per the harness spec, "QEMU/KVM
// runs validate harness correctness only; budget compliance is judged
// exclusively on bare-metal R1" — so these numbers validate the rig and catch
// regressions, but the R1 gate is bare-metal (build/README.md, D34). A budget
// miss is never a boot failure: the harness always reports and returns.

/// Measured samples per benchmark (reduced from the 1M mandate for boot-time
/// feasibility, D35); enough for stable p50/p90/p99.
pub(crate) const PERF_SAMPLES: usize = 1024;
/// Untimed warm-up iterations before measuring (warms I-cache / predictors).
pub(crate) const PERF_WARMUP: usize = 64;

/// Shared sample buffer — one benchmark runs at a time on the boot CPU.
pub(crate) static mut PERF_BUF: [u64; PERF_SAMPLES] = [0; PERF_SAMPLES];
/// A scratch handle table for the B2 benchmark.
pub(crate) static mut PERF_HANDLES: HandleTable = HandleTable::new();

/// Computes and prints one benchmark's statistics (in TSC cycles).
pub(crate) fn perf_report(name: &str, samples: &mut [u64]) {
    match Stats::from_samples(samples) {
        Some(s) => kprintln!(
            "perf: {name:<16} n={} p50={} p90={} p99={} max={} mean={}",
            s.count,
            s.p50,
            s.p90,
            s.p99,
            s.max,
            s.mean,
        ),
        None => kprintln!("perf: {name:<16} no samples"),
    }
}

/// B2 — handle object operation: query the rights of a handle (a handle-table
/// lookup + rights read), the repeatable read-only form of BM-2.
pub(crate) fn perf_bench_handle_op() {
    // SAFETY: the boot CPU alone; these statics are used only here, and
    // OBJECTS/PERF_HANDLES are not concurrently accessed.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let handles = unsafe { &mut *&raw mut PERF_HANDLES };
    let buf = unsafe { &mut *&raw mut PERF_BUF };

    let handle = match objects
        .create(ObjectType::Test)
        .and_then(|object| handles.insert(object, Rights::all_core()))
    {
        Ok(handle) => handle,
        Err(_) => return perf_report("B2 handle-op", &mut []),
    };
    for _ in 0..PERF_WARMUP {
        let _ = core::hint::black_box(handles.rights(handle));
    }
    for slot in buf.iter_mut() {
        let start = read_tsc_serialized();
        let _ = core::hint::black_box(handles.rights(handle));
        let end = read_tsc_serialized();
        *slot = end.wrapping_sub(start);
    }
    perf_report("B2 handle-op", buf);
}

/// B8 — anonymous zero-fill page fault: time `resolve_fault` demand-filling a
/// fresh lazy page each iteration (one frame per fault).
pub(crate) fn perf_bench_anon_fault(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const BASE: u64 = 0x0000_0000_1000_0000;
    let arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(_) => return perf_report("B8 anon-fault", &mut []),
    };
    let mut space = AddressSpace::from_arch(arch, alloc_asid(), 0);
    let pages = (PERF_WARMUP + PERF_SAMPLES) as u64;
    if space
        .map_anonymous_demand(
            VirtAddr::new(BASE),
            pages * FRAME_SIZE,
            PageFlags::rw().user(),
        )
        .is_err()
    {
        return perf_report("B8 anon-fault", &mut []);
    }
    // `resolve_fault` edits the scratch space's tables through the direct map,
    // so it needs no CR3 switch. Each page is distinct (a lazy fault fills once).
    let mut warm = 0u64;
    for i in 0..pages {
        let va = VirtAddr::new(BASE + i * FRAME_SIZE);
        if i < PERF_WARMUP as u64 {
            let _ = space.resolve_fault(va, false, frames);
            warm = warm.wrapping_add(1);
            continue;
        }
        let slot = (i - PERF_WARMUP as u64) as usize;
        let start = read_tsc_serialized();
        let _ = core::hint::black_box(space.resolve_fault(va, false, frames));
        let end = read_tsc_serialized();
        // SAFETY: the boot CPU alone; PERF_BUF used only here.
        unsafe { (*&raw mut PERF_BUF)[slot] = end.wrapping_sub(start) };
    }
    let _ = warm;
    // SAFETY: the boot CPU alone; PERF_BUF used only here.
    perf_report("B8 anon-fault", unsafe { &mut *&raw mut PERF_BUF });
}

/// B9 — copy-on-write fault: snapshot an eager region, then time `resolve_fault`
/// copying a shared page private on each write (one frame per copy).
pub(crate) fn perf_bench_cow_fault(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const SRC: u64 = 0x0000_0000_2000_0000;
    const DST: u64 = 0x0000_0000_3000_0000;
    let arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(_) => return perf_report("B9 cow-fault", &mut []),
    };
    let mut space = AddressSpace::from_arch(arch, alloc_asid(), 0);
    let pages = (PERF_WARMUP + PERF_SAMPLES) as u64;
    let len = pages * FRAME_SIZE;
    let rights = PageFlags::rw().user();
    if space
        .map_anonymous(VirtAddr::new(SRC), len, rights, frames)
        .and_then(|()| space.snapshot_cow(VirtAddr::new(SRC), VirtAddr::new(DST), len, frames))
        .is_err()
    {
        return perf_report("B9 cow-fault", &mut []);
    }
    for i in 0..pages {
        let va = VirtAddr::new(SRC + i * FRAME_SIZE);
        if i < PERF_WARMUP as u64 {
            let _ = space.resolve_fault(va, true, frames);
            continue;
        }
        let slot = (i - PERF_WARMUP as u64) as usize;
        let start = read_tsc_serialized();
        let _ = core::hint::black_box(space.resolve_fault(va, true, frames));
        let end = read_tsc_serialized();
        // SAFETY: the boot CPU alone; PERF_BUF used only here.
        unsafe { (*&raw mut PERF_BUF)[slot] = end.wrapping_sub(start) };
    }
    // SAFETY: the boot CPU alone; PERF_BUF used only here.
    perf_report("B9 cow-fault", unsafe { &mut *&raw mut PERF_BUF });
}

/// One page-in under a resident cap (the pager-pressure page-in path): if the
/// object cache is at the cap, evict a clean page first (unmap + free), then
/// alloc, fill, and supply the requested page. This is the work whose latency
/// B10 must hold under pressure (`docs/prototypes/02` S1).
pub(crate) fn perf_page_in_once(
    space: &mut AddressSpace<KernelAddressSpace>,
    base: u64,
    cache: &mut ObjectCache,
    offset: u64,
    cap: u32,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // Under pressure (at the cap), reclaim a clean page before bringing one in.
    if cache.resident_count() as u32 >= cap
        && let Some(evict_off) = cache.evict_candidate()
    {
        let _ = space.evict_page(VirtAddr::new(base + evict_off), frames);
        cache.forget(evict_off);
    }
    if let Some(frame) = frames.alloc() {
        let pattern = (0xc0 + (offset / FRAME_SIZE)) as u8;
        space.arch().fill_frame(frame, pattern);
        if space
            .supply_page(VirtAddr::new(base + offset), frame, frames)
            .is_ok()
        {
            let _ = cache.install(offset);
        }
    }
}

/// B10 (S1) — external-pager page-in latency **under pressure**. Times the
/// page-in path at ~50/90/99 % frame utilization: a resident cap models the
/// utilization level, so at high utilization every page-in must first evict a
/// clean page (docs/prototypes/02, "Page-In Latency Under Pressure" — the point
/// is the shape of the curve, no cliff). Kernel-side timing (the IPC handoff is
/// measured by B3); QEMU numbers are correctness/regression only (D34/D41).
pub(crate) fn perf_bench_page_in(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const BASE: u64 = 0x0000_0000_4000_0000;
    // "Physical memory" for the bench, in pages; utilization sets the resident cap.
    const CAPACITY: u32 = MAX_CACHED_PAGES as u32;
    let mut p50s = [0u64; 3];
    for (level, (util, name)) in [
        (50u32, "B10 page-in/50%"),
        (90, "B10 page-in/90%"),
        (99, "B10 page-in/99%"),
    ]
    .into_iter()
    .enumerate()
    {
        let cap = (CAPACITY * util / 100).max(1);
        let arch = match kernel_vm.arch().new_user(frames) {
            Ok(arch) => arch,
            Err(_) => {
                perf_report(name, &mut []);
                continue;
            }
        };
        let mut space = AddressSpace::from_arch(arch, alloc_asid(), 0);
        let object = ObjectId::from_raw(0x0b10_0000);
        let total = cap as u64 + (PERF_WARMUP + PERF_SAMPLES) as u64 + 1;
        if space
            .map_object(
                VirtAddr::new(BASE),
                total * FRAME_SIZE,
                PageFlags::rw().user(),
                object,
                0,
            )
            .is_err()
        {
            perf_report(name, &mut []);
            continue;
        }
        let mut cache = ObjectCache::new(CAPACITY);
        // Fill memory to the utilization cap (the resident working set).
        for off in 0..cap as u64 {
            perf_page_in_once(&mut space, BASE, &mut cache, off, cap, frames);
        }
        // Time page-ins of successive fresh pages: at the cap each evicts the
        // oldest clean page first (a sliding resident window).
        let mut next = cap as u64;
        for i in 0..(PERF_WARMUP + PERF_SAMPLES) as u64 {
            if (i as usize) < PERF_WARMUP {
                perf_page_in_once(&mut space, BASE, &mut cache, next, cap, frames);
                next += 1;
                continue;
            }
            let slot = i as usize - PERF_WARMUP;
            let start = read_tsc_serialized();
            perf_page_in_once(&mut space, BASE, &mut cache, next, cap, frames);
            let end = read_tsc_serialized();
            // SAFETY: the boot CPU alone; PERF_BUF used only here.
            unsafe { (*&raw mut PERF_BUF)[slot] = end.wrapping_sub(start) };
            next += 1;
        }
        // SAFETY: the boot CPU alone; PERF_BUF used only here.
        let buf = unsafe { &mut *&raw mut PERF_BUF };
        p50s[level] = match Stats::from_samples(buf) {
            Some(s) => {
                kprintln!(
                    "perf: {name:<16} n={} p50={} p90={} p99={} max={} mean={}",
                    s.count,
                    s.p50,
                    s.p90,
                    s.p99,
                    s.max,
                    s.mean,
                );
                s.p50
            }
            None => {
                kprintln!("perf: {name:<16} no samples");
                0
            }
        };
    }
    // S1 pass shape: page-in latency must not *cliff* as utilization rises —
    // graceful degradation within budget is fine (docs/prototypes/02 S1).
    let lo = p50s.iter().copied().min().unwrap_or(0).max(1);
    let hi = p50s.iter().copied().max().unwrap_or(0);
    kprintln!(
        "perf: B10 validity: page-in p50 {lo}..{hi} across 50/90/99% util ({})",
        if hi <= lo * 2 {
            "no cliff, graceful"
        } else {
            "CLIFF"
        }
    );
}

/// Perf-harness kernel stacks: distinct slots in the VMAP region (clear of the
/// demos' stacks), since each benchmark's abandoned threads keep their mappings.
pub(crate) const PERF_KSTACK_PAGES: u64 = 4;
pub(crate) const PERF_IFACE_ID: u64 = 0x7065_7266_0000_0001;

/// The base of perf-harness kernel-stack slot `i` (slots 0..=8). A contiguous
/// block is reserved from the window allocator on first use; slot `i` is stable.
pub(crate) fn perf_kstack(i: u64) -> u64 {
    static BASE: AtomicU64 = AtomicU64::new(0);
    let mut base = BASE.load(Ordering::Relaxed);
    if base == 0 {
        base = reserve_kstack_block(9);
        BASE.store(base, Ordering::Relaxed);
    }
    base + i * KSTACK_WINDOW_SLOT
}

/// The B3 benchmark channel (`.0` client, `.1` server) and its switch count.
pub(crate) static mut PERF_ENDPOINTS: Option<(EndpointId, EndpointId)> = None;
pub(crate) static PERF_B3_SWITCHES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn perf_endpoints() -> (EndpointId, EndpointId) {
    // SAFETY: the boot CPU alone; set once in perf_bench_ipc before the threads run.
    unsafe {
        match (*&raw const PERF_ENDPOINTS).as_ref() {
            Some(&pair) => pair,
            None => panic!("perf: endpoints uninitialized"),
        }
    }
}

/// B3 server: park, then reply-and-wait forever (echoes an empty ack).
pub(crate) extern "C" fn perf_b3_server_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (_client, server_ep) = perf_endpoints();
    let mut request = match exec.receive(server_ep) {
        Ok(request) => request,
        Err(_) => loop {
            core::hint::spin_loop();
        },
    };
    loop {
        let _ = &request;
        let reply = Message::new(MessageHeader::new(PERF_IFACE_ID, 2));
        request = match exec.reply_receive(server_ep, reply) {
            Ok(request) => request,
            Err(_) => loop {
                core::hint::spin_loop();
            },
        };
    }
}

/// B3 client: time each synchronous `call` round trip, record the switch count
/// for the two-switches-per-round-trip validity check, then hand back to boot.
pub(crate) extern "C" fn perf_b3_client_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (client_ep, _server) = perf_endpoints();
    for _ in 0..PERF_WARMUP {
        let _ = exec.call(
            client_ep,
            Message::new(MessageHeader::new(PERF_IFACE_ID, 1)),
        );
    }
    let before = exec.switch_count();
    // SAFETY: the boot CPU alone; PERF_BUF used by one benchmark at a time.
    let buf = unsafe { &mut *&raw mut PERF_BUF };
    for slot in buf.iter_mut() {
        let request = Message::new(MessageHeader::new(PERF_IFACE_ID, 1));
        let start = read_tsc_serialized();
        let _ = core::hint::black_box(exec.call(client_ep, request));
        let end = read_tsc_serialized();
        *slot = end.wrapping_sub(start);
    }
    PERF_B3_SWITCHES.store(exec.switch_count() - before, Ordering::Relaxed);
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// B3 — same-core synchronous IPC round trip. A client/server pair in one
/// executive; the client times each `call`. Also asserts the round trip is
/// exactly two context switches (the BM-3 handoff validity check).
pub(crate) fn perf_bench_ipc(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let exec = exec_ref();
    let (client_ep, server_ep) = match exec.channel_create() {
        Ok(pair) => pair,
        Err(_) => return perf_report("B3 ipc-rtt", &mut []),
    };
    // SAFETY: the boot CPU alone; set once before the threads run.
    unsafe { PERF_ENDPOINTS = Some((client_ep, server_ep)) };

    // Server first so it parks and the client's `call` hands off directly to it.
    for (entry, kstack) in [
        (
            perf_b3_server_entry as extern "C" fn(usize) -> !,
            perf_kstack(0),
        ),
        (
            perf_b3_client_entry as extern "C" fn(usize) -> !,
            perf_kstack(1),
        ),
    ] {
        let thread = match Thread::<ContextSwitch>::spawn(
            entry,
            0,
            VirtAddr::new(kstack),
            PERF_KSTACK_PAGES,
            kernel_vm,
            frames,
        ) {
            Ok(thread) => thread,
            Err(_) => return perf_report("B3 ipc-rtt", &mut []),
        };
        if exec.add_thread(thread).is_err() {
            return perf_report("B3 ipc-rtt", &mut []);
        }
    }
    exec.run();

    // SAFETY: the boot CPU alone; PERF_BUF used by one benchmark at a time.
    perf_report("B3 ipc-rtt", unsafe { &mut *&raw mut PERF_BUF });
    let switches = PERF_B3_SWITCHES.load(Ordering::Relaxed);
    let expected = 2 * PERF_SAMPLES as u64;
    kprintln!(
        "perf: B3 validity: {switches} switches for {PERF_SAMPLES} round trips (want {expected}, 2/trip) {}",
        if switches == expected {
            "OK"
        } else {
            "MISMATCH"
        }
    );
}

/// The submission timestamp the B11 client writes just before each `call`; the
/// server reads it when the request becomes visible.
pub(crate) static PERF_B11_SUBMIT: AtomicU64 = AtomicU64::new(0);
/// The B11 sample index (advanced by the server as each request is received).
pub(crate) static PERF_B11_IDX: AtomicUsize = AtomicUsize::new(0);

/// B11 server: on each request received, record the submission→visible delta.
pub(crate) extern "C" fn perf_b11_server_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (_client, server_ep) = perf_endpoints();
    let mut request = match exec.receive(server_ep) {
        Ok(request) => request,
        Err(_) => loop {
            core::hint::spin_loop();
        },
    };
    // SAFETY: the boot CPU alone; PERF_BUF used by one benchmark at a time.
    let buf = unsafe { &mut *&raw mut PERF_BUF };
    loop {
        // The request is now visible to the driver host; record the latency from
        // the client's submission.
        let visible = read_tsc_serialized();
        let submit = PERF_B11_SUBMIT.load(Ordering::Relaxed);
        let idx = PERF_B11_IDX.fetch_add(1, Ordering::Relaxed);
        if idx < PERF_SAMPLES {
            buf[idx] = visible.wrapping_sub(submit);
        }
        let _ = &request;
        let ack = Message::new(MessageHeader::new(PERF_IFACE_ID, 2));
        request = match exec.reply_receive(server_ep, ack) {
            Ok(request) => request,
            Err(_) => loop {
                core::hint::spin_loop();
            },
        };
    }
}

/// B11 client: submit N I/O requests, timestamping each just before the `call`
/// so the server can measure how long until the request is visible to it.
pub(crate) extern "C" fn perf_b11_client_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (client_ep, _server) = perf_endpoints();
    for _ in 0..PERF_WARMUP {
        PERF_B11_SUBMIT.store(read_tsc_serialized(), Ordering::Relaxed);
        let _ = exec.call(
            client_ep,
            Message::new(MessageHeader::new(PERF_IFACE_ID, 1)),
        );
    }
    // Discard the warmup samples the server recorded.
    PERF_B11_IDX.store(0, Ordering::Relaxed);
    for _ in 0..PERF_SAMPLES {
        PERF_B11_SUBMIT.store(read_tsc_serialized(), Ordering::Relaxed);
        let _ = core::hint::black_box(exec.call(
            client_ep,
            Message::new(MessageHeader::new(PERF_IFACE_ID, 1)),
        ));
    }
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// B11 — I/O submission to driver-host visibility (docs/architecture/03 "B11").
/// A client/driver pair in one executive; the client timestamps each submission
/// and the driver records when the request becomes visible. Mirrors the M16
/// client→driver channel path with a kernel-thread rig for a tight measurement
/// (QEMU/TCG numbers are correctness/regression only, D34/D41).
pub(crate) fn perf_bench_b11(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let exec = exec_ref();
    let (client_ep, server_ep) = match exec.channel_create() {
        Ok(pair) => pair,
        Err(_) => return perf_report("B11 io-visible", &mut []),
    };
    // SAFETY: the boot CPU alone; set once before the threads run.
    unsafe { PERF_ENDPOINTS = Some((client_ep, server_ep)) };
    PERF_B11_IDX.store(0, Ordering::Relaxed);

    // Server (driver) first so it parks and the client's `call` hands off to it.
    for (entry, kstack) in [
        (
            perf_b11_server_entry as extern "C" fn(usize) -> !,
            perf_kstack(2),
        ),
        (
            perf_b11_client_entry as extern "C" fn(usize) -> !,
            perf_kstack(3),
        ),
    ] {
        let thread = match Thread::<ContextSwitch>::spawn(
            entry,
            0,
            VirtAddr::new(kstack),
            PERF_KSTACK_PAGES,
            kernel_vm,
            frames,
        ) {
            Ok(thread) => thread,
            Err(_) => return perf_report("B11 io-visible", &mut []),
        };
        if exec.add_thread(thread).is_err() {
            return perf_report("B11 io-visible", &mut []);
        }
    }
    exec.run();

    // SAFETY: the boot CPU alone; PERF_BUF used by one benchmark at a time.
    perf_report("B11 io-visible", unsafe { &mut *&raw mut PERF_BUF });
}

/// Null syscalls the B1 ring-3 program times (kept in sync with the blob's
/// counter immediate). Reduced from 1M for boot-time feasibility (D35).
pub(crate) const PERF_B1_SYSCALLS: u64 = 20000;
/// Total ring-3-measured cycles for the B1 batch, reported via the exit syscall.
pub(crate) static PERF_B1_DELTA: AtomicU64 = AtomicU64::new(0);

// The B1 ring-3 program: RDTSC, N null syscalls, RDTSC, report the delta via the
// exit syscall's argument. Self-timed in ring 3 so it captures the full
// SYSCALL/SYSRET round trip (swapgs + entry stub + dispatch + sysret).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global perf_b1_program_start
.global perf_b1_program_end
perf_b1_program_start:
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r14, rax              # start cycle count
    mov r12d, 20000           # N null syscalls (== PERF_B1_SYSCALLS)
1:
    xor eax, eax              # SyscallNumber::Null
    syscall
    dec r12d
    jnz 1b
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r14              # delta = end - start
    mov rdi, rax             # exit arg0 = total cycles
    mov eax, 5               # ProcessExit
    syscall
2:
    jmp 2b
perf_b1_program_end:
.text
"#
);

// SAFETY: names the B1 blob's bounds, defined by the global_asm above; the
// extern block only declares them and does no unsafe operation.
unsafe extern "C" {
    pub(crate) static perf_b1_program_start: u8;
    pub(crate) static perf_b1_program_end: u8;
}

/// The B1 syscall handler: the measured `Null` returns immediately; `ProcessExit`
/// records the ring-3-measured cycle total and yields to boot.
pub(crate) fn perf_b1_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    match SyscallNumber::from_u64(frame.number) {
        Some(SyscallNumber::Null) => 0,
        Some(SyscallNumber::ProcessExit) => {
            PERF_B1_DELTA.store(frame.arg0, Ordering::Relaxed);
            // SAFETY: the boot CPU alone; statics set before the ring-3 thread runs.
            if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
                process.exit(0);
            }
            // SAFETY: the boot CPU alone; USER_SCHEDULER holds the B1 thread.
            if let Some(scheduler) = unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
                scheduler.yield_to_boot();
            }
            0
        }
        _ => syscall::ENOSYS,
    }
}

/// B1 — null syscall. A ring-3 program self-times a batch of null syscalls (the
/// full SYSCALL/SYSRET round trip) and reports the total; the kernel reports the
/// mean per syscall (D35: mean over a batch, not per-sample percentiles).
pub(crate) fn perf_bench_syscall(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration before this benchmark's ring-3 thread runs.
    unsafe { set_syscall_handler(perf_b1_syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(_) => return kprintln!("perf: B1 null-syscall   setup failed"),
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
        Err(_) => return kprintln!("perf: B1 null-syscall   setup failed"),
    };
    let mut process = Process::new(proc_obj, user_vm);
    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    let user = PageFlags::rw().user();
    if process
        .space_mut()
        .map_anonymous(VirtAddr::new(USER_CODE_VA), code_len, user, frames)
        .is_err()
    {
        return kprintln!("perf: B1 null-syscall   setup failed");
    }
    let thread = match Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        VirtAddr::new(perf_kstack(6)),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(_) => return kprintln!("perf: B1 null-syscall   setup failed"),
    };
    // SAFETY: the boot CPU alone; re-initializing the user scheduler.
    unsafe { USER_SCHEDULER = Some(Scheduler::new(1, 0)) };
    let idx = match unsafe { (*&raw mut USER_SCHEDULER).as_mut() }
        .and_then(|s| s.add_thread(thread).ok())
    {
        Some(idx) => idx,
        None => return kprintln!("perf: B1 null-syscall   setup failed"),
    };
    if process
        .add_thread(thread_id_of(idx).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        .is_err()
    {
        return kprintln!("perf: B1 null-syscall   setup failed");
    }

    // SAFETY: the user space shares the kernel higher-half; boot code, stack,
    // and the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(kcore::percpu::current_index()) };
    let code_src = &raw const perf_b1_program_start as *const u8;
    let code_bytes =
        (&raw const perf_b1_program_end as usize) - (&raw const perf_b1_program_start as usize);
    // SAFETY: the blob is in kernel rodata; USER_CODE_VA is a writable user page
    // in the now-active space with room for it.
    // The kernel means to reach a user page here: it is populating a
    // process it is building, in that process's own space. Declared
    // rather than assumed, because SMAP now faults an undeclared one.
    // SAFETY: the destination is a page this boot glue just mapped
    // into the space it activated; the window permits reaching it.
    {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes) };
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
        return kprintln!("perf: B1 null-syscall   setup failed");
    }
    // SAFETY: the boot CPU alone; publishing the running process.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }
    // SAFETY: the boot CPU alone; USER_SCHEDULER was initialized above.
    match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => scheduler.run(),
        None => return kprintln!("perf: B1 null-syscall   setup failed"),
    }
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let delta = PERF_B1_DELTA.load(Ordering::Relaxed);
    let mean = delta / PERF_B1_SYSCALLS.max(1);
    kprintln!(
        "perf: B1 null-syscall   mean={mean} (over {PERF_B1_SYSCALLS} syscalls, ring-3 self-timed)"
    );
}

/// The two B7 ping-pong threads' scheduler indices.
pub(crate) static PERF_B7_A: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PERF_B7_B: AtomicUsize = AtomicUsize::new(0);

/// B7 driver thread: time each A→B→A round trip (two switches) and record the
/// per-switch cost. Thread B bounces every handoff straight back.
pub(crate) extern "C" fn perf_b7_a_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let b = PERF_B7_B.load(Ordering::Relaxed);
    for _ in 0..PERF_WARMUP {
        exec.scheduler().handoff_to(b);
    }
    // SAFETY: the boot CPU alone; PERF_BUF used by one benchmark at a time.
    let buf = unsafe { &mut *&raw mut PERF_BUF };
    for slot in buf.iter_mut() {
        let start = read_tsc_serialized();
        exec.scheduler().handoff_to(b); // A→B, B hands straight back: A→B→A
        let end = read_tsc_serialized();
        *slot = end.wrapping_sub(start) / 2; // round trip is two switches
    }
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// B7 bouncer thread: hand every switch straight back to the driver.
pub(crate) extern "C" fn perf_b7_b_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let a = PERF_B7_A.load(Ordering::Relaxed);
    loop {
        exec.scheduler().handoff_to(a);
    }
}

/// B7 — same-core context switch. Two kernel threads ping-pong via directed
/// handoff. `cross` gives each thread a distinct address space so every switch
/// pays a CR3 load (the budgeted cross-address-space cost); otherwise both share
/// the kernel space (the comparison variant that exposes the CR3 delta).
pub(crate) fn perf_bench_ctxsw(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    cross: bool,
    name: &str,
    slot_a: u64,
    slot_b: u64,
) {
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let (root_a, root_b) = if cross {
        // Two scratch spaces (kernel higher-half shared) force per-switch CR3
        // loads. Their page-table frames outlive the values (no free path).
        match (
            kernel_vm.arch().new_user(frames),
            kernel_vm.arch().new_user(frames),
        ) {
            (Ok(a), Ok(b)) => (Some(a.root_phys()), Some(b.root_phys())),
            _ => return perf_report(name, &mut []),
        }
    } else {
        (None, None)
    };
    let exec = exec_ref();
    let mut spawn_bench_thread = |entry: extern "C" fn(usize) -> !, kstack: u64, root| {
        let mut thread = Thread::<ContextSwitch>::spawn(
            entry,
            0,
            VirtAddr::new(kstack),
            PERF_KSTACK_PAGES,
            kernel_vm,
            frames,
        )
        .ok()?;
        thread.set_space_root(root);
        exec.add_thread(thread).ok()
    };
    // Driver (A) first so it runs first and drives the loop.
    let a_idx = match spawn_bench_thread(perf_b7_a_entry, perf_kstack(slot_a), root_a) {
        Some(idx) => idx,
        None => return perf_report(name, &mut []),
    };
    let b_idx = match spawn_bench_thread(perf_b7_b_entry, perf_kstack(slot_b), root_b) {
        Some(idx) => idx,
        None => return perf_report(name, &mut []),
    };
    PERF_B7_A.store(a_idx, Ordering::Relaxed);
    PERF_B7_B.store(b_idx, Ordering::Relaxed);
    exec.run();
    // SAFETY: the boot CPU alone; PERF_BUF used by one benchmark at a time.
    perf_report(name, unsafe { &mut *&raw mut PERF_BUF });
}

/// The two B6 ping-pong words. Their values never change — the waiter reads the
/// current value and waits on it, so the compare-true → block path (the real
/// wait-on-address semantic) runs every iteration rather than being bypassed.
pub(crate) static PERF_B6_D_WORD: AtomicU64 = AtomicU64::new(0);
pub(crate) static PERF_B6_P_WORD: AtomicU64 = AtomicU64::new(0);

/// The two words' physical addresses, resolved once where the kernel address
/// space is in hand and read by the bench threads, which have no space to
/// translate through.
///
/// A futex key is physical since D240 — the only name for a word of memory
/// that every holder agrees on — and these two words are kernel statics, so
/// the translation is a fact about this boot rather than about either thread.
pub(crate) static PERF_B6_D_PHYS: AtomicU64 = AtomicU64::new(0);
pub(crate) static PERF_B6_P_PHYS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn perf_b6_keys() -> (kcore::wait::WaitKey, kcore::wait::WaitKey) {
    (
        kcore::wait::WaitKey::at(PERF_B6_D_PHYS.load(Ordering::Relaxed)),
        kcore::wait::WaitKey::at(PERF_B6_P_PHYS.load(Ordering::Relaxed)),
    )
}

/// B6 driver thread: time each `wake(peer)` + `wait(self)` round trip. Waking
/// the peer makes it Ready; blocking in our own wait lets the scheduler run it,
/// and it wakes us straight back — one round trip is two wake→wakeup transitions.
pub(crate) extern "C" fn perf_b6_d_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (d_key, p_key) = perf_b6_keys();
    for _ in 0..PERF_WARMUP {
        exec.wake(p_key, 1);
        let v = PERF_B6_D_WORD.load(Ordering::Relaxed);
        let _ = exec.wait_on_address(d_key, v, || Ok(PERF_B6_D_WORD.load(Ordering::Relaxed)));
    }
    // SAFETY: the boot CPU alone; PERF_BUF used by one benchmark at a time.
    let buf = unsafe { &mut *&raw mut PERF_BUF };
    for slot in buf.iter_mut() {
        let start = read_tsc_serialized();
        exec.wake(p_key, 1); // wake peer (now Ready)
        let v = PERF_B6_D_WORD.load(Ordering::Relaxed);
        // The word is read again inside the executive, under the hold that
        // enrolls — which is the whole of what D240 changed.
        let _ = exec.wait_on_address(d_key, v, || Ok(PERF_B6_D_WORD.load(Ordering::Relaxed)));
        let end = read_tsc_serialized();
        *slot = end.wrapping_sub(start) / 2; // round trip is two transitions
    }
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// B6 peer thread: wake the driver, then wait to be woken — bouncing every
/// round trip straight back.
pub(crate) extern "C" fn perf_b6_p_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (d_key, p_key) = perf_b6_keys();
    loop {
        exec.wake(d_key, 1);
        let v = PERF_B6_P_WORD.load(Ordering::Relaxed);
        let _ = exec.wait_on_address(p_key, v, || Ok(PERF_B6_P_WORD.load(Ordering::Relaxed)));
    }
}

/// B6 — contended wake (wait-on-address). Two kernel threads ping-pong through
/// `wait_on_address`/`wake` on two stable words; time the round trip, report the
/// per-transition cost. This is the kernel-thread wait/wake half — not the
/// ring-3 BM-6 wake-call-entry-to-waiter-running, the owner-aware-lock boosted
/// path, or the cross-core B5 path (build/README.md, D39).
pub(crate) fn perf_bench_waitwake(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    PERF_B6_D_WORD.store(0, Ordering::Relaxed);
    PERF_B6_P_WORD.store(0, Ordering::Relaxed);
    // Where the two words physically are, resolved here because this is where
    // an address space to translate through exists.
    for (word, slot) in [
        (&raw const PERF_B6_D_WORD as u64, &PERF_B6_D_PHYS),
        (&raw const PERF_B6_P_WORD as u64, &PERF_B6_P_PHYS),
    ] {
        let Some((frame, _)) = kernel_vm.arch().translate(VirtAddr::new(word)) else {
            return perf_report("B6 wait-wake", &mut []);
        };
        slot.store(
            frame.base().as_u64() + (word % FRAME_SIZE),
            Ordering::Relaxed,
        );
    }
    let exec = exec_ref();
    let mut spawn_bench_thread = |entry: extern "C" fn(usize) -> !, kstack: u64| {
        let thread = Thread::<ContextSwitch>::spawn(
            entry,
            0,
            VirtAddr::new(kstack),
            PERF_KSTACK_PAGES,
            kernel_vm,
            frames,
        )
        .ok()?;
        exec.add_thread(thread).ok()
    };
    // Driver first so it runs first and drives the loop. Slots 7/8 are clear of
    // the B3 (0/1) and B7 (2..5) and B1 (6) benchmark stacks.
    if spawn_bench_thread(perf_b6_d_entry, perf_kstack(7)).is_none() {
        return perf_report("B6 wait-wake", &mut []);
    }
    if spawn_bench_thread(perf_b6_p_entry, perf_kstack(8)).is_none() {
        return perf_report("B6 wait-wake", &mut []);
    }
    exec.run();
    // SAFETY: the boot CPU alone; PERF_BUF used by one benchmark at a time.
    perf_report("B6 wait-wake", unsafe { &mut *&raw mut PERF_BUF });
}

/// Runs the microbenchmark suite and reports each result over serial. Always
/// returns so the boot reaches the alive marker; a budget miss is informational.
pub(crate) fn perf_harness(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    kprintln!(
        "perf: microbenchmarks, {PERF_SAMPLES} samples, TSC {} (QEMU/TCG cycles — not R1 compliance)",
        if tsc_invariant() {
            "invariant"
        } else {
            "non-invariant"
        }
    );
    perf_bench_handle_op();
    perf_bench_anon_fault(kernel_vm, frames);
    perf_bench_cow_fault(kernel_vm, frames);
    perf_bench_page_in(kernel_vm, frames);
    perf_bench_ipc(kernel_vm, frames);
    perf_bench_b11(kernel_vm, frames);
    perf_bench_syscall(kernel_vm, frames);
    perf_bench_ctxsw(kernel_vm, frames, false, "B7 ctx-sw/same", 2, 3);
    perf_bench_ctxsw(kernel_vm, frames, true, "B7 ctx-sw/cross", 4, 5);
    perf_bench_waitwake(kernel_vm, frames);
    // The cross-AS benchmark leaves a scratch CR3 active; restore the kernel
    // space so the alive marker and exit run under it.
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
}
