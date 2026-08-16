// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The budgeted paths this machine measures, and the timer that drives them.
//!
//! Normative: docs/architecture/03-performance-budgets.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

/// Measures the context-switch path (budget B7).
///
/// This is the one Stage-0 primitive budget the EL1 port can measure
/// honestly: B1-B11 otherwise need syscalls, IPC and the executive, none of
/// which exist before EL0. The main thread switches to a pong thread that
/// immediately switches straight back, and the counter delta brackets exactly
/// two `ContextSwitch::switch` calls per sample.
///
/// Reported in nanoseconds, not raw counter ticks. `CNTVCT_EL0` runs at the
/// system-counter frequency (~62.5 MHz under QEMU), far coarser than the
/// core clock the TSC tracks, so a raw tick count would be both tiny and
/// incomparable with the x86-64 rig — and under QEMU/TCG every number here is
/// a regression tripwire only, never an R1 measurement (build/README.md,
/// D34/D56).
pub(crate) fn perf_context_switch(
    space: &mut KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) {
    use tessera_karch::{AddressSpaceOps, ContextOps, CpuOps, FrameSource};

    // Guarded two-page stack for the pong thread, above the conformance
    // scratch so nothing collides.
    let base = VirtAddr::new(CONFORMANCE_SCRATCH + 0x10_0000);
    const PAGES: u64 = 2;
    for page in 0..PAGES {
        let Some(f) = frames.alloc() else {
            return kprintln!("perf: B7 ctx-switch    setup failed (no frame)");
        };
        let at = VirtAddr::new(base.as_u64() + page * FRAME_SIZE);
        if space.map(at, f, PageFlags::rw().global(), frames).is_err() {
            return kprintln!("perf: B7 ctx-switch    setup failed (map)");
        }
    }
    let top = VirtAddr::new(base.as_u64() + PAGES * FRAME_SIZE);

    // SAFETY: `top` tops the two exclusively-owned pages just mapped, and
    // `perf_pong` never returns.
    let pong = unsafe { ContextSwitch::init(top, perf_pong, 0) };
    // SAFETY: single-threaded boot; these statics are written before the
    // switch that reads them and nothing else touches them.
    unsafe {
        (&raw mut PERF_PONG_CTX).write(Some(pong));
        (&raw mut PERF_MAIN_CTX).write(Some(ContextSwitch::empty()));
    }

    let hz = <Cpu as CpuOps>::counter_hz().unwrap_or(1).max(1);
    // The pong thread needs no stop signal: every sample is a full round trip
    // that returns here, and after the loop the main thread simply stops
    // switching to it. Pong is left suspended at its `switch` call — a saved
    // context on a stack that is never resumed — and its frames are freed
    // below, which is sound precisely because nothing switches into it again.
    for i in 0..PERF_SAMPLES {
        let start = <Cpu as CpuOps>::counter_serialized();
        // SAFETY: `PERF_MAIN_CTX` is valid storage to save into, and
        // `PERF_PONG_CTX` was produced by `init` (or the pong thread's own
        // save on a prior round), so its stack holds a matching frame.
        unsafe {
            let main = &raw mut PERF_MAIN_CTX;
            let pong = &raw const PERF_PONG_CTX;
            if let (Some(main_ref), Some(pong_ref)) = ((*main).as_mut(), (*pong).as_ref()) {
                ContextSwitch::switch(main_ref, pong_ref);
            }
        }
        let end = <Cpu as CpuOps>::counter_serialized();
        // Two switches per round trip; report the per-round-trip time in ns.
        let ticks = end.saturating_sub(start);
        // SAFETY: single-threaded; the buffer is written only here.
        unsafe { (*&raw mut PERF_BUF)[i] = ticks * 1_000_000_000 / hz };
    }

    for page in 0..PAGES {
        let at = VirtAddr::new(base.as_u64() + page * FRAME_SIZE);
        if let Ok(f) = space.unmap(at) {
            frames.free_frame(f);
        }
    }

    // SAFETY: single-threaded; PERF_BUF is not aliased during the report.
    let samples = unsafe { &mut *&raw mut PERF_BUF };
    match kcore::bench::Stats::from_samples(samples) {
        Some(s) => kprintln!(
            "perf: B7 ctx-switch    n={} p50={}ns p90={}ns p99={}ns max={}ns mean={}ns (2 switches/rt, QEMU-only)",
            s.count,
            s.p50,
            s.p90,
            s.p99,
            s.max,
            s.mean
        ),
        None => kprintln!("perf: B7 ctx-switch    no samples"),
    }
}

/// Pong end of the context-switch benchmark: switch straight back to main,
/// forever. The main thread stops driving it after the measured rounds, so
/// this simply suspends at its final switch and is never resumed.
pub(crate) extern "C" fn perf_pong(_arg: usize) -> ! {
    use tessera_karch::ContextOps;
    loop {
        // SAFETY: single-threaded boot; `PERF_PONG_CTX` is this thread's own
        // save slot and `PERF_MAIN_CTX` holds the caller's live context.
        unsafe {
            let mine = &raw mut PERF_PONG_CTX;
            let main = &raw const PERF_MAIN_CTX;
            if let (Some(mine_ref), Some(main_ref)) = ((*mine).as_mut(), (*main).as_ref()) {
                ContextSwitch::switch(mine_ref, main_ref);
            }
        }
    }
}

/// Ticks the hook has observed, so the check can prove delivery rather than
/// merely that the timer was programmed.
pub(crate) static OBSERVED_TICKS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn on_tick() {
    OBSERVED_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Starts the tick, waits for interrupts to actually arrive, and stops it.
///
/// Programming a timer proves nothing on its own: the interrupt has to make
/// it through the GIC's priority mask, the distributor's enable, the CPU
/// interface, and the vector table before the hook runs. This waits on the
/// hook's own count, so only end-to-end delivery satisfies it.
pub(crate) fn timer_check() -> Result<u64, u32> {
    use tessera_karch::{InterruptControl, TimerControl};

    tessera_karch_aarch64::set_tick_hook(on_tick);
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    tessera_karch_aarch64::Cpu::enable();

    // Bounded wait: spin on the counter rather than trusting the timer, so a
    // controller that never delivers fails the check instead of hanging the
    // boot. The bound is counter ticks, read from the same counter the timer
    // compares against, so it is a real time limit and not a spin count.
    const WANTED: u64 = 3;
    let deadline =
        tessera_karch_aarch64::read_counter() + tessera_karch_aarch64::counter_frequency() * 2;
    while OBSERVED_TICKS.load(Ordering::Relaxed) < WANTED {
        if tessera_karch_aarch64::read_counter() > deadline {
            tessera_karch_aarch64::Cpu::disable();
            tessera_karch_aarch64::stop_timer();
            return Err(1);
        }
        core::hint::spin_loop();
    }

    tessera_karch_aarch64::Cpu::disable();
    tessera_karch_aarch64::stop_timer();

    // The architecture's own tick count and the hook's must agree; a
    // mismatch means ticks were delivered that the hook never saw.
    let counted = tessera_karch_aarch64::GenericTimer::ticks();
    let observed = OBSERVED_TICKS.load(Ordering::Relaxed);
    if counted != observed {
        return Err(2);
    }
    if tessera_karch_aarch64::unexpected_irqs() != 0 {
        return Err(3);
    }
    Ok(observed)
}

/// Reports a fatal exception and ends the run. Before this existed a kernel
// --- EL0 (ring 3) bring-up (D70) ---

/// User virtual addresses for the EL0 proof. Both in the low `TTBR0` range
/// with EL0 access, clear of the device range (`< 0x4000_0000`) — the user
/// program's private slice of the low half.
pub(crate) const USER_CODE_VA: u64 = 0x0000_1000_0000_0000;
pub(crate) const USER_STACK_VA: u64 = 0x0000_1000_0010_0000;

/// Kernel stack for the EL0 thread. A high-half (`TTBR1`, kernel) address:
/// the EL1 vector lands on it when EL0 traps, so it must be kernel memory,
/// resident regardless of which low half is active. Clear of the kernel image
/// and the conformance scratch.
pub(crate) const EL0_KSTACK_VA: u64 = 0xffff_0000_6000_0000;
pub(crate) const EL0_KSTACK_PAGES: u64 = 4;

/// Syscall numbers (in `x8`, the AArch64 convention). `SYS_LOG` returns to
/// EL0; any other number, including `SYS_EXIT`, ends the thread — so the
/// handler matches only `SYS_LOG` explicitly.
pub(crate) const SYS_LOG: u64 = 0;
const _SYS_EXIT: u64 = 1;

/// EL0 program: `svc` LOG with the magic already in `x0`, then `svc` EXIT.
/// Position-independent (no absolute addresses), hand-assembled little-endian.
///
/// ```text
///   movz x8, #0      ; SYS_LOG   (x0 already = magic, the entry arg)
///   svc  #0
///   movz x8, #1      ; SYS_EXIT
///   movz x0, #0      ; exit code 0
///   svc  #0
///   b    .           ; unreachable
/// ```
pub(crate) const LOG_EXIT_BLOB: &[u8] = &[
    0x08, 0x00, 0x80, 0xd2, // movz x8, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// EL0 program that stores to its own (read-execute) code page — a W^X
/// violation the hardware must fault. `adr x1, .` takes the code address;
/// `str x0, [x1]` writes it.
pub(crate) const WX_BLOB: &[u8] = &[
    0x01, 0x00, 0x00, 0x10, // adr x1, .
    0x20, 0x00, 0x00, 0xf9, // str x0, [x1]
    0x00, 0x00, 0x00, 0x14, // b .
];

/// EL0 program that reads the kernel address passed in `x0` — a privilege
/// violation (kernel pages are `AP=EL1-only`) the hardware must fault.
pub(crate) const KREAD_BLOB: &[u8] = &[
    0x02, 0x00, 0x40, 0xf9, // ldr x2, [x0]
    0x00, 0x00, 0x00, 0x14, // b .
];

// --- per-process address spaces (D74) ---

/// A user data page each process maps at the *same* virtual address to its
/// *own* frame — the address whose contents differ between processes and so
/// prove per-process isolation. Clear of the code/stack pages above.
pub(crate) const USER_DATA_VA: u64 = 0x0000_1000_0030_0000;

/// Distinct sentinels the two processes store at `USER_DATA_VA`; the isolation
/// proof is that each reads back its own.
pub(crate) const SENTINEL_A: u64 = 0xa1a1_a1a1_a1a1_a1a1;
pub(crate) const SENTINEL_B: u64 = 0xb2b2_b2b2_b2b2_b2b2;

/// EL0 program that reads the u64 at [`USER_DATA_VA`] into `x0` and logs it,
/// then exits. Position-independent (it materializes the fixed user VA rather
/// than depending on where it is loaded), hand-assembled little-endian.
///
/// ```text
///   movz x1, #0x0030, lsl #16   ; x1 = USER_DATA_VA (0x1000_0030_0000)
///   movk x1, #0x1000, lsl #32
///   ldr  x0, [x1]               ; x0 = this space's sentinel
///   movz x8, #0                 ; SYS_LOG
///   svc  #0
///   movz x8, #1                 ; SYS_EXIT
///   movz x0, #0
///   svc  #0
///   b    .
/// ```
pub(crate) const READ_DATA_BLOB: &[u8] = &[
    0x01, 0x06, 0xa0, 0xd2, // movz x1, #0x30, lsl #16
    0x01, 0x00, 0xc2, 0xf2, // movk x1, #0x1000, lsl #32
    0x20, 0x00, 0x40, 0xf9, // ldr x0, [x1]
    0x08, 0x00, 0x80, 0xd2, // movz x8, #0  (SYS_LOG)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1  (SYS_EXIT)
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// Monotonic ASID allocator for per-process spaces. ASID 0 is the shared
/// boot/kernel low space; live processes draw 1, 2, … (no reuse here).
pub(crate) static NEXT_ASID: AtomicU64 = AtomicU64::new(1);

