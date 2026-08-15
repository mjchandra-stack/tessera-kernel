// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! CPU identity, idle, entropy, interrupt masking, and the invariant counter
//! for ARM 32-bit.
//!
//! The architecture is the same one AArch64 implements — a generic timer, an
//! `MPIDR`, `WFI` — reached through a different door. AArch64 names system
//! registers directly (`mrs x0, mpidr_el1`); ARMv7-A reaches the same state
//! through coprocessor 15 (`mrc p15, 0, r0, c0, c0, 5`), and the 64-bit
//! physical counter needs `mrrc`, which returns a **register pair** because
//! no single register can hold it. That is the same shape as the RISC-V 32
//! port's two-CSR counter read, and for the same reason.
//!
//! Interrupt masking is `CPSR.I` rather than `DAIF.I`, set and cleared with
//! `cpsid i` / `cpsie i`.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Architecture
//! Porting Layer"), docs/prototypes/01-ipc-benchmark-harness.md
//! Budget: none (identity and idle paths)

use core::arch::asm;
use tessera_karch::{CpuOps, InterruptControl};

/// `CPSR.I` — the IRQ mask bit.
const CPSR_IRQ_MASK: u32 = 1 << 7;

pub struct Cpu;

impl CpuOps for Cpu {
    fn cpu_id() -> u32 {
        let mpidr: u32;
        // SAFETY: `MPIDR` (CP15 c0, c0, 5) is a read-only identification
        // register readable in a privileged mode; the read has no side effects.
        unsafe { asm!("mrc p15, 0, {}, c0, c0, 5", out(reg) mpidr, options(nomem, nostack)) };
        // Aff0 is the dense per-core index on the single-cluster machines this
        // milestone targets, exactly as on AArch64.
        mpidr & 0xff
    }

    fn halt_until_interrupt() {
        // SAFETY: `wfi` is a hint with no memory effects; it either sleeps
        // until an interrupt or retires immediately.
        unsafe { asm!("wfi", options(nomem, nostack)) };
    }

    fn hw_random() -> Option<u64> {
        // ARMv7-A has no architectural entropy instruction — FEAT_RNG is an
        // Armv8.5 addition with no 32-bit counterpart. "No entropy source" is
        // the honest answer, not a degraded fallback, and the caller
        // (boot-time layout randomization) documents what it does instead.
        None
    }

    fn counter_serialized() -> u64 {
        read_counter_serialized()
    }

    fn counter_hz() -> Option<u64> {
        Some(u64::from(counter_frequency()))
    }
}

impl InterruptControl for Cpu {
    fn enable() {
        // SAFETY: `cpsie i` clears `CPSR.I`, unmasking IRQs on this core.
        // Pairing with `disable` is the caller's responsibility.
        unsafe { asm!("cpsie i", options(nomem, nostack)) };
    }

    fn disable() {
        // SAFETY: `cpsid i` sets `CPSR.I`, masking IRQs on this core; masking
        // is always sound.
        unsafe { asm!("cpsid i", options(nomem, nostack)) };
    }

    fn are_enabled() -> bool {
        let cpsr: u32;
        // SAFETY: reading `CPSR` is a side-effect-free read of the current
        // program status.
        unsafe { asm!("mrs {}, cpsr", out(reg) cpsr, options(nomem, nostack)) };
        cpsr & CPSR_IRQ_MASK == 0
    }
}

/// Raw physical-counter read. The counter is 64 bits and the registers are
/// 32, so `mrrc` returns it as a pair — the architecture's own answer to the
/// problem the RISC-V 32 port solves with two CSR reads, and a cheaper one:
/// `mrrc` is a single instruction, so the halves cannot skew and no retry
/// loop is needed.
pub fn read_counter() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: `CNTPCT` (CP15 c14, 64-bit access via coprocessor 0) is a
    // read-only counter readable in a privileged mode; the read has no side
    // effects.
    unsafe {
        asm!("mrrc p15, 0, {}, {}, c14", out(reg) low, out(reg) high, options(nomem, nostack))
    };
    (u64::from(high) << 32) | u64::from(low)
}

/// Counter read with a preceding context synchronization, so the counter
/// cannot be sampled before earlier instructions have completed. `ISB` is the
/// same barrier the AArch64 port uses, and unlike the RISC-V ports this
/// architecture genuinely has one.
pub fn read_counter_serialized() -> u64 {
    // SAFETY: `ISB` is a context-synchronization barrier with no memory
    // effects.
    unsafe { asm!("isb", options(nomem, nostack)) };
    read_counter()
}

/// Frequency of the system counter in Hz, as firmware programmed it.
pub fn counter_frequency() -> u32 {
    let frequency: u32;
    // SAFETY: `CNTFRQ` (CP15 c14, c0, 0) is a read-only frequency register;
    // the read has no side effects.
    unsafe { asm!("mrc p15, 0, {}, c14, c0, 0", out(reg) frequency, options(nomem, nostack)) };
    frequency
}
