// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The supervisor timer as the boot hart's periodic tick, programmed through
//! `stimecmp`/`stimecmph` (the Sstc extension).
//!
//! The choice of Sstc over the SBI timer call is the 64-bit port's, for the
//! same reason: one CSR write per tick instead of a round trip through M-mode
//! firmware, and **no fallback**, so a machine without it is reported rather
//! than silently degraded. QEMU's `rv32` CPU implements it.
//!
//! # The part that is genuinely different
//!
//! The compare register is 64 bits and the machine's registers are 32, so it
//! is **two CSRs** — `stimecmp` (low) and `stimecmph` (high) — and the order
//! they are written in is load-bearing rather than stylistic.
//!
//! The pending bit is defined as `time >= {stimecmph, stimecmp}`. Writing the
//! low half first would, for the duration of one instruction, pair a *new* low
//! with an *old* high; if the new low is small and the old high is in the
//! past, that intermediate value is already due and the hart takes a spurious
//! timer interrupt before the second write lands. The architecturally
//! recommended sequence avoids the window entirely: push the low half to
//! all-ones (a deadline that cannot be reached), then write the high half,
//! then the real low half. Every intermediate state is in the future.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Timer
//! interface"), docs/kernel/02-scheduling-memory-ipc.md ("Scheduling")
//! Budget: none (the tick handler itself is budgeted with the switch path)

use core::arch::asm;
use core::sync::atomic::Ordering;
use tessera_karch::TimerControl;
use tessera_karch::atomic::AtomicU64;

// `stimecmp` is CSR 0x14d and `stimecmph` is CSR 0x15d. Both are written by
// address rather than by name in the `asm!` below, so the pinned assembler
// needs no knowledge of the Sstc extension to encode them.

/// `sie.STIE` — the supervisor timer interrupt enable.
const SIE_STIE: u32 = 1 << 5;

/// Rate of the `time` counter on the `virt` machine, in Hz.
///
/// RISC-V publishes this as the device tree's `/cpus/timebase-frequency`
/// rather than in any CSR, so a port either reads the tree or knows its
/// platform. This is the virtual platform profile's documented value — the
/// same 10 MHz the 64-bit machine reports — on the same footing as the
/// hard-coded UART base, and superseded by the discovered value when the
/// platform-support package lands.
pub const TIMEBASE_HZ: u64 = 10_000_000;

/// Counter ticks between interrupts, established by `start_periodic`.
static INTERVAL: AtomicU64 = AtomicU64::new(0);
/// Ticks observed since `start_periodic`.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// The supervisor timer as this architecture's tick source.
pub struct SupervisorTimer;

impl TimerControl for SupervisorTimer {
    fn start_periodic(hz: u32) {
        let interval = TIMEBASE_HZ / u64::from(hz.max(1));
        INTERVAL.store(interval, Ordering::Relaxed);
        TICKS.store(0, Ordering::Relaxed);
        arm(interval);
        // SAFETY: `sie` is the supervisor interrupt-enable CSR; setting STIE
        // permits timer interrupts to reach this hart. Delivery still depends
        // on `sstatus.SIE`, which the caller controls.
        unsafe { asm!("csrs sie, {}", in(reg) SIE_STIE, options(nomem, nostack)) };
    }

    fn ticks() -> u64 {
        TICKS.load(Ordering::Relaxed)
    }
}

/// Programs the compare pair to fire `interval` counter ticks from now.
fn arm(interval: u64) {
    let deadline = crate::cpu::read_counter().wrapping_add(interval);
    let low = deadline as u32;
    let high = (deadline >> 32) as u32;
    // SAFETY: `stimecmp`/`stimecmph` are the Sstc supervisor timer compare
    // registers. Writing them reprograms this hart's own timer and — because
    // the pending bit is `time >= compare` — simultaneously acknowledges the
    // expiry being rearmed. The three-write order is the one the module header
    // explains: no intermediate pair is ever a deadline in the past, so no
    // spurious interrupt can be raised between the writes. On a machine
    // without Sstc the first write traps as an illegal instruction, which is
    // the reported failure the header describes rather than a silent one.
    unsafe {
        asm!(
            "csrw 0x14d, {ones}",
            "csrw 0x15d, {high}",
            "csrw 0x14d, {low}",
            ones = in(reg) u32::MAX,
            high = in(reg) high,
            low = in(reg) low,
            options(nomem, nostack),
        );
    }
}

/// Accounts for one expiry and rearms. Called from the trap path when the
/// cause is a supervisor timer interrupt.
pub(crate) fn on_expiry() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    arm(INTERVAL.load(Ordering::Relaxed));
}

/// Stops the timer, so a hart can leave interrupts enabled without taking
/// ticks.
pub fn stop() {
    // SAFETY: clearing `sie.STIE` masks this hart's timer interrupt, and
    // pushing both halves of the compare to their maximum stops it becoming
    // pending at all; neither has any other effect.
    unsafe {
        asm!("csrc sie, {}", in(reg) SIE_STIE, options(nomem, nostack));
        asm!(
            "csrw 0x14d, {ones}",
            "csrw 0x15d, {ones}",
            ones = in(reg) u32::MAX,
            options(nomem, nostack),
        );
    }
}
