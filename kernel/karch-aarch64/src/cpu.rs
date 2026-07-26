// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! CPU identity, idle, entropy, interrupt masking, and the invariant cycle
//! counter for AArch64.
//!
//! The counter is `CNTVCT_EL0`, which
//! docs/prototypes/01-ipc-benchmark-harness.md already names as this
//! architecture's timing source ("TSC on x86-64, CNTVCT on AArch64"). Unlike
//! the TSC it counts at a fixed system frequency (`CNTFRQ_EL0`) rather than
//! at the core clock, so it is invariant by construction — but its
//! resolution is the system counter's, not the core's, which the perf rig
//! must account for rather than assume cycles.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Architecture
//! Porting Layer"), docs/prototypes/01-ipc-benchmark-harness.md
//! Budget: none (identity and idle paths)

use core::arch::asm;
use tessera_karch::CpuOps;
use tessera_karch::InterruptControl;

/// `DAIF.I` — the IRQ mask bit.
const DAIF_IRQ_MASK: u64 = 1 << 7;

/// `ID_AA64ISAR0_EL1.RNDR` field position; non-zero means `RNDR`/`RNDRRS`
/// (FEAT_RNG, Armv8.5) are implemented.
const ID_AA64ISAR0_RNDR_SHIFT: u64 = 60;

pub struct Cpu;

impl CpuOps for Cpu {
    fn cpu_id() -> u32 {
        let mpidr: u64;
        // SAFETY: `MPIDR_EL1` is a read-only identification register
        // readable at EL1; the read has no side effects.
        unsafe { asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)) };
        // Aff0 is the dense per-core index on the single-cluster machines
        // this milestone targets. Cluster-aware packing arrives with SMP.
        (mpidr & 0xff) as u32
    }

    fn halt_until_interrupt() {
        // SAFETY: `wfi` is a hint with no memory effects; it either sleeps
        // until an interrupt (or other wake event) or retires immediately.
        unsafe { asm!("wfi", options(nomem, nostack)) };
    }

    fn hw_random() -> Option<u64> {
        if !rndr_implemented() {
            // Not a degraded fallback — the CPU simply has no entropy tap,
            // and the caller (boot-time layout randomization) documents what
            // it does instead. General randomness never comes from here.
            return None;
        }

        let value: u64;
        let failed: u32;
        // SAFETY: `RNDR` (encoded `s3_3_c2_c4_0`, spelled numerically so the
        // assembler need not be told the CPU is Armv8.5) is readable at EL1
        // once `ID_AA64ISAR0_EL1.RNDR` reports it, which was just checked.
        // It sets `PSTATE.Z` on failure and returns zero, so the condition
        // must be captured before anything else can clobber the flags —
        // hence the `cset` inside the same asm block. Flags are treated as
        // clobbered (no `preserves_flags`).
        unsafe {
            asm!(
                "mrs {value}, s3_3_c2_c4_0",
                "cset {failed:w}, eq",
                value = out(reg) value,
                failed = out(reg) failed,
                options(nomem, nostack),
            );
        }

        if failed != 0 { None } else { Some(value) }
    }
    fn counter_serialized() -> u64 {
        read_counter_serialized()
    }

    fn counter_hz() -> Option<u64> {
        // Unlike the TSC this *is* architecturally reported, by CNTFRQ_EL0.
        Some(counter_frequency())
    }
}

/// True when the CPU implements `FEAT_RNG`.
fn rndr_implemented() -> bool {
    let isar0: u64;
    // SAFETY: `ID_AA64ISAR0_EL1` is a read-only feature-identification
    // register readable at EL1; the read has no side effects.
    unsafe { asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack)) };
    (isar0 >> ID_AA64ISAR0_RNDR_SHIFT) & 0xf != 0
}

impl InterruptControl for Cpu {
    fn enable() {
        // SAFETY: clearing `DAIF.I` unmasks IRQs on this core. Pairing with
        // `disable` is the caller's responsibility, as the trait documents.
        unsafe { asm!("msr daifclr, #2", options(nomem, nostack)) };
    }

    fn disable() {
        // SAFETY: setting `DAIF.I` masks IRQs on this core; masking is
        // always sound.
        unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
    }

    fn are_enabled() -> bool {
        let daif: u64;
        // SAFETY: reading `DAIF` is a side-effect-free read of the current
        // exception-mask state.
        unsafe { asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack)) };
        daif & DAIF_IRQ_MASK == 0
    }
}

/// Raw system-counter read. Cheap, but not ordered against surrounding
/// instructions — use [`read_counter_serialized`] to time a region.
pub fn read_counter() -> u64 {
    let counter: u64;
    // SAFETY: `CNTVCT_EL0` is a read-only counter; the read has no side
    // effects and is permitted at EL1.
    unsafe { asm!("mrs {}, cntvct_el0", out(reg) counter, options(nomem, nostack)) };
    counter
}

/// System-counter read with a preceding context synchronization, so the
/// counter cannot be sampled before earlier instructions have completed.
/// This is the AArch64 analogue of the x86-64 port's serialized TSC read.
pub fn read_counter_serialized() -> u64 {
    let counter: u64;
    // SAFETY: `ISB` is a context-synchronization barrier with no memory
    // effects; `CNTVCT_EL0` is a side-effect-free read.
    unsafe {
        asm!(
            "isb",
            "mrs {}, cntvct_el0",
            out(reg) counter,
            options(nomem, nostack),
        );
    }
    counter
}

/// Frequency of the system counter in Hz, as firmware programmed it.
pub fn counter_frequency() -> u64 {
    let frequency: u64;
    // SAFETY: `CNTFRQ_EL0` is a read-only frequency register readable at
    // EL1; the read has no side effects.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack)) };
    frequency & 0xffff_ffff
}
