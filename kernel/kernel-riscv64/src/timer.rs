// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The supervisor timer, and the tick that proves it fires.
//!
//! Sstc's `stimecmp` is a requirement of this port's CPU profile rather than a
//! convenience (D86); a machine without it is a different machine.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

pub(crate) static OBSERVED_TICKS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn on_tick() {
    OBSERVED_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Starts the tick, waits for interrupts to actually arrive, and stops it.
///
/// Programming a timer proves nothing on its own: the interrupt has to make
/// it past `sie`, past `sstatus.SIE`, through the trap vector and the cause
/// decode before the hook runs. This waits on the hook's own count, so only
/// end-to-end delivery satisfies it.
pub(crate) fn timer_check() -> Result<u64, u32> {
    use tessera_karch::{InterruptControl, TimerControl};

    tessera_karch_riscv64::set_tick_hook(on_tick);
    <SupervisorTimer as tessera_karch::TimerControl>::start_periodic_this_cpu(TICK_HZ);
    Cpu::enable();

    // Bounded wait: spin on the counter rather than trusting the timer, so a
    // controller that never delivers fails the check instead of hanging the
    // boot. The bound is counter ticks, read from the same counter the timer
    // compares against, so it is a real time limit and not a spin count.
    const WANTED: u64 = 3;
    let deadline = tessera_karch_riscv64::read_counter() + tessera_karch_riscv64::TIMEBASE_HZ * 2;
    while OBSERVED_TICKS.load(Ordering::Relaxed) < WANTED {
        if tessera_karch_riscv64::read_counter() > deadline {
            Cpu::disable();
            tessera_karch_riscv64::stop_timer();
            return Err(1);
        }
        core::hint::spin_loop();
    }

    Cpu::disable();
    tessera_karch_riscv64::stop_timer();

    // The architecture's own tick count and the hook's must agree; a mismatch
    // means ticks were delivered that the hook never saw.
    let counted = SupervisorTimer::ticks();
    let observed = OBSERVED_TICKS.load(Ordering::Relaxed);
    if counted != observed {
        return Err(2);
    }
    if tessera_karch_riscv64::unexpected_irqs() != 0 {
        return Err(3);
    }
    Ok(observed)
}
