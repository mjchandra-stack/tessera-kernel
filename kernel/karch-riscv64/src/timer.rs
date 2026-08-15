// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The supervisor timer as the boot hart's periodic tick, programmed through
//! `stimecmp` (the Sstc extension).
//!
//! Three ways to get a tick exist on this architecture, and the choice is not
//! a detail. The oldest is to ask M-mode firmware to program the CLINT's
//! `mtimecmp` on the kernel's behalf, through an `ecall` into the SBI timer
//! extension — universally available, and a round trip through firmware on
//! every single tick. **Sstc** replaces that with a supervisor-writable
//! compare register, so arming the next tick is one CSR write and never
//! leaves the kernel. It is mandatory in the RVA23 profile this port targets
//! (`docs/hardware/01-platform-and-cpu-support.md`), so using it is not an
//! optimisation for later hardware — it is what the target profile says the
//! machine has, and the reference machine (`-cpu rva23s64`) provides it.
//!
//! There is deliberately **no fallback to the SBI path**. A kernel that
//! silently degrades to a firmware round trip would meet its tick budget on
//! one machine and miss it on another with no visible difference
//! (docs/lifecycle/04, "No Silent Fallback"). A machine without Sstc traps on
//! the first `stimecmp` write and is reported as the unsupported platform it
//! is.
//!
//! Like AArch64's and unlike the PIT, this is a *compare* rearmed on each
//! expiry, so the interval restarts when the tick is serviced. Long handlers
//! stretch the interval instead of stacking missed ticks — the right failure
//! mode for a scheduler tick.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Timer
//! interface"), docs/kernel/02-scheduling-memory-ipc.md ("Scheduling")
//! Budget: none (the tick handler itself is budgeted with the switch path)

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use tessera_karch::TimerControl;

// `stimecmp` is CSR 0x14d. It is written by address rather than by name in
// every `asm!` below, so the pinned assembler needs no knowledge of the Sstc
// extension to encode it.

/// `sie.STIE` — the supervisor timer interrupt enable.
const SIE_STIE: u64 = 1 << 5;

/// Rate of the `time` counter on the `virt` machine, in Hz.
///
/// RISC-V publishes this as the device tree's `/cpus/timebase-frequency`
/// rather than in any CSR (see `crate::cpu::CpuOps::counter_hz`), so a port
/// either reads the tree or knows its platform. This constant is the virtual
/// platform profile's documented value, on the same footing as the UART base
/// address in `crate::uart`: correct for the reference machine, and superseded
/// by the discovered value when the platform-support package lands.
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

/// Programs the compare register to fire `interval` counter ticks from now.
fn arm(interval: u64) {
    let deadline = crate::cpu::read_counter().wrapping_add(interval);
    // SAFETY: `stimecmp` is the Sstc supervisor timer compare. Writing it
    // reprograms this hart's own timer — and, because the pending bit is
    // defined as `time >= stimecmp`, simultaneously acknowledges the expiry
    // that is being rearmed. It has no other effect. The write traps as an
    // illegal instruction on a machine without Sstc, which is the reported
    // failure the module header describes rather than a silent one.
    unsafe {
        asm!(
            "csrw 0x14d, {deadline}",
            deadline = in(reg) deadline,
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
/// ticks. Used where the x86-64 port masks the PIT's IRQ line.
pub fn stop() {
    // SAFETY: clearing `sie.STIE` masks this hart's timer interrupt and
    // pushing the compare to its maximum stops it becoming pending at all;
    // neither has any other effect.
    unsafe {
        asm!("csrc sie, {}", in(reg) SIE_STIE, options(nomem, nostack));
        asm!(
            "csrw 0x14d, {never}",
            never = in(reg) u64::MAX,
            options(nomem, nostack),
        );
    }
}
