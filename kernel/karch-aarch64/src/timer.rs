// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The Arm generic timer as the boot CPU's periodic tick.
//!
//! The x86-64 port programs an 8254 PIT through port I/O; here the timer is
//! part of the CPU, reached through system registers, and its interrupt is a
//! private peripheral interrupt the GIC delivers. There is no divisor to pick
//! and no counter to chase: the timer compares against the same system
//! counter `CNTVCT_EL0` reads, at the frequency `CNTFRQ_EL0` reports, so a
//! tick period is a plain division.
//!
//! It is a *down-counter* rearmed on each expiry rather than a free-running
//! periodic source, which means the interval restarts when the tick is
//! serviced rather than when the previous one elapsed. Long-running handlers
//! therefore stretch the interval instead of stacking up missed ticks — the
//! right failure mode for a scheduler tick, and worth stating because the PIT
//! behaves the other way.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Timer
//! interface"), docs/kernel/02-scheduling-memory-ipc.md ("Scheduling")
//! Budget: none (the tick handler itself is budgeted with the switch path)

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use tessera_karch::TimerControl;

/// Private peripheral interrupt the EL1 physical timer raises on the `virt`
/// machine, and on every GIC-based Arm platform: this is architecture, not a
/// board detail.
pub const TIMER_INTID: u32 = 30;

/// `CNTP_CTL_EL0.ENABLE`. `IMASK` is left clear so expiry actually reaches
/// the interrupt controller.
const CNTP_CTL_ENABLE: u64 = 1 << 0;

/// Counter ticks between interrupts, established by `start_periodic`.
static INTERVAL: AtomicU64 = AtomicU64::new(0);
/// Ticks each CPU has taken on its own timer.
///
/// One counter per CPU because there is one timer per CPU — the generic timer
/// is part of the core, not a device beside it. A single counter would answer
/// "did the machine tick" where the question is "did *this* CPU tick", and the
/// two differ exactly when a CPU's own timer never started.
static TICKS: [AtomicU64; tessera_karch_arm_common::gic::MAX_CPU_INTERFACES] =
    [const { AtomicU64::new(0) }; tessera_karch_arm_common::gic::MAX_CPU_INTERFACES];

/// The slot of the CPU running this code, bounded so an index past the
/// controller's reach counts nowhere rather than into another CPU's.
fn this_cpu() -> usize {
    let index = <crate::Cpu as tessera_karch::CpuLocal>::index() as usize;
    if index >= tessera_karch_arm_common::gic::MAX_CPU_INTERFACES {
        0
    } else {
        index
    }
}

/// The generic timer as this architecture's tick source.
pub struct GenericTimer;

impl TimerControl for GenericTimer {
    fn start_periodic_this_cpu(hz: u32) {
        let interval = crate::cpu::counter_frequency() / u64::from(hz.max(1));
        INTERVAL.store(interval, Ordering::Relaxed);
        TICKS[this_cpu()].store(0, Ordering::Relaxed);
        arm(interval);
    }

    fn ticks() -> u64 {
        TICKS[this_cpu()].load(Ordering::Relaxed)
    }

    fn ticks_on(index: u32) -> u64 {
        TICKS
            .get(index as usize)
            .map_or(0, |slot| slot.load(Ordering::Relaxed))
    }
}

/// Programs the timer to fire `interval` counter ticks from now.
fn arm(interval: u64) {
    // SAFETY: `CNTP_TVAL_EL0` and `CNTP_CTL_EL0` are the EL1-accessible
    // physical-timer controls; writing them programs and enables this core's
    // own timer and has no other effect.
    unsafe {
        asm!(
            "msr cntp_tval_el0, {interval}",
            "msr cntp_ctl_el0, {enable}",
            interval = in(reg) interval,
            enable = in(reg) CNTP_CTL_ENABLE,
            options(nomem, nostack),
        );
    }
}

/// Accounts for one expiry and rearms. Called from the interrupt path once
/// the GIC has named this interrupt, before the end-of-interrupt.
pub(crate) fn on_expiry() {
    TICKS[this_cpu()].fetch_add(1, Ordering::Relaxed);
    arm(INTERVAL.load(Ordering::Relaxed));
}

/// Stops the timer, so a core can leave interrupts enabled without taking
/// ticks. Used where the x86-64 port masks the PIT's IRQ line.
pub fn stop() {
    // SAFETY: writing `CNTP_CTL_EL0` with every bit clear disables this
    // core's physical timer and has no other effect.
    unsafe { asm!("msr cntp_ctl_el0, xzr", options(nomem, nostack)) };
}
