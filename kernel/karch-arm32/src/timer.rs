// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The Arm generic timer as the boot CPU's periodic tick.
//!
//! This is the *same timer* the AArch64 port drives — same counter, same
//! compare, same private peripheral interrupt — reached through coprocessor
//! 15 instead of named system registers. That is worth stating because it is
//! the clearest example of what the two Arm ports do and do not share: the
//! device drivers came out into `tessera-karch-arm-common` unchanged, but the
//! timer could not, because it is not a device — it is part of the CPU, and
//! the instruction that reaches it is the part that differs.
//!
//! Like AArch64's and unlike the PIT, it is a *down-counter* rearmed on each
//! expiry, so the interval restarts when the tick is serviced rather than
//! when the previous one elapsed. Long handlers stretch the interval instead
//! of stacking missed ticks.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Timer
//! interface"), docs/kernel/02-scheduling-memory-ipc.md ("Scheduling")
//! Budget: none (the tick handler itself is budgeted with the switch path)

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use tessera_karch::TimerControl;

/// Private peripheral interrupt the non-secure physical timer raises. PPI 14
/// on this architecture, and the GIC numbers PPIs from 16 — so interrupt id
/// 30, the same number the AArch64 port uses, because it is architecture
/// rather than a board detail.
pub const TIMER_INTID: u32 = 30;

/// `CNTP_CTL.ENABLE`. `IMASK` is left clear so expiry actually reaches the
/// interrupt controller.
const CNTP_CTL_ENABLE: u32 = 1 << 0;

/// Counter ticks between interrupts, established by `start_periodic`.
static INTERVAL: AtomicU64 = AtomicU64::new(0);
/// Ticks observed since `start_periodic`.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// The generic timer as this architecture's tick source.
pub struct GenericTimer;

impl TimerControl for GenericTimer {
    fn start_periodic(hz: u32) {
        let interval = u64::from(crate::cpu::counter_frequency()) / u64::from(hz.max(1));
        INTERVAL.store(interval, Ordering::Relaxed);
        TICKS.store(0, Ordering::Relaxed);
        arm(interval);
    }

    fn ticks() -> u64 {
        TICKS.load(Ordering::Relaxed)
    }
}

/// Programs the timer to fire `interval` counter ticks from now.
///
/// `CNTP_TVAL` is 32 bits, so an interval wider than that cannot be expressed
/// — it is clamped rather than truncated, because a truncated interval would
/// silently produce a *much shorter* tick period than asked for, which looks
/// like a working timer running fast. At the reference machine's 62.5 MHz a
/// full 32-bit value is over a minute, so the clamp is unreachable in
/// practice and present because "unreachable in practice" is not a guarantee.
fn arm(interval: u64) {
    let tval = u32::try_from(interval).unwrap_or(u32::MAX);
    // SAFETY: `CNTP_TVAL` (CP15 c14, c2, 0) and `CNTP_CTL` (c14, c2, 1) are
    // this core's own physical-timer controls; writing them programs and
    // enables its timer and has no other effect.
    unsafe {
        asm!(
            "mcr p15, 0, {tval}, c14, c2, 0",
            "mcr p15, 0, {ctl}, c14, c2, 1",
            tval = in(reg) tval,
            ctl = in(reg) CNTP_CTL_ENABLE,
            options(nomem, nostack),
        );
    }
}

/// Accounts for one expiry and rearms. Called from the interrupt path once
/// the GIC has named this interrupt, before the end-of-interrupt.
pub(crate) fn on_expiry() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    arm(INTERVAL.load(Ordering::Relaxed));
}

/// Stops the timer, so a core can leave interrupts enabled without taking
/// ticks.
pub fn stop() {
    // SAFETY: writing `CNTP_CTL` with every bit clear disables this core's
    // physical timer and has no other effect.
    unsafe { asm!("mcr p15, 0, {}, c14, c2, 1", in(reg) 0u32, options(nomem, nostack)) };
}
