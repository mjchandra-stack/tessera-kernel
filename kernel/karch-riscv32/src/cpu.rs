// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! CPU identity, idle, entropy, interrupt masking, and the invariant time
//! counter for RISC-V 32.
//!
//! Everything here is the 64-bit port's `cpu` module at half the register
//! width, with one genuine addition: **the time counter no longer fits in a
//! register.** `rdtime` reads the low 32 bits and `rdtimeh` the high, and the
//! counter can carry between the two reads, so a correct 64-bit reading needs
//! the same retry-on-high-half protocol `kcore::atomic`'s split counter uses.
//! That is not a coincidence — it is the same problem (publishing a 64-bit
//! quantity through 32-bit accesses) appearing in hardware rather than in
//! memory, and the same shape solves it.
//!
//! The other differences are consequences of the width and are silent if you
//! do not look for them: a CSR value passed to `asm!` must be `u32`, because
//! `in(reg)` with a `u64` does not fit a register on this target and will not
//! compile. That is the porting layer's word-size assumption showing up as a
//! build error, which is where it should show up.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Architecture
//! Porting Layer"), docs/prototypes/01-ipc-benchmark-harness.md
//! Budget: none (identity and idle paths)

use core::arch::asm;
use tessera_karch::CpuOps;
use tessera_karch::InterruptControl;

/// `sstatus.SIE` — the supervisor interrupt-enable bit.
const SSTATUS_SIE: u32 = 1 << 1;

/// `sie.SEIE` — the supervisor external interrupt enable.
const SIE_SEIE: u32 = 1 << 9;

pub struct Cpu;

impl CpuOps for Cpu {
    fn cpu_id() -> u32 {
        let hart: u32;
        // SAFETY: `tp` is a general-purpose register. This kernel's boot stub
        // is the only writer, and it writes the firmware-supplied hart id
        // before any Rust code runs; reading it has no side effects.
        unsafe { asm!("mv {}, tp", out(reg) hart, options(nomem, nostack, preserves_flags)) };
        hart
    }

    fn halt_until_interrupt() {
        // SAFETY: `wfi` is a hint with no memory effects; it either sleeps
        // until an interrupt is pending or retires immediately. It wakes on a
        // pending-but-masked interrupt and returns *without taking* it — the
        // caller unmasks around this call if it means to be woken by one.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }

    fn hw_random() -> Option<u64> {
        // As on the 64-bit port: the `seed` CSR (Zkr) is read-locked to M-mode
        // unless firmware grants S-mode access, and nothing here negotiates
        // that grant, so a blind read would trap. "No entropy source" is the
        // honest answer, not a degraded fallback.
        None
    }

    fn counter_serialized() -> u64 {
        read_counter_serialized()
    }

    fn counter_hz() -> Option<u64> {
        // Deliberately `None`: RISC-V reports the `time` CSR's frequency in
        // the device tree, not in a CSR, at either width.
        None
    }
}

impl InterruptControl for Cpu {
    fn enable() {
        // SAFETY: setting `sstatus.SIE` unmasks supervisor interrupts on this
        // hart. Pairing with `disable` is the caller's responsibility, as the
        // trait documents.
        unsafe { asm!("csrs sstatus, {}", in(reg) SSTATUS_SIE, options(nomem, nostack)) };
    }

    fn disable() {
        // SAFETY: clearing `sstatus.SIE` masks supervisor interrupts on this
        // hart; masking is always sound.
        unsafe { asm!("csrc sstatus, {}", in(reg) SSTATUS_SIE, options(nomem, nostack)) };
    }

    fn are_enabled() -> bool {
        let sstatus: u32;
        // SAFETY: reading `sstatus` is a side-effect-free read of the current
        // supervisor status, permitted at S-mode.
        unsafe { asm!("csrr {}, sstatus", out(reg) sstatus, options(nomem, nostack)) };
        sstatus & SSTATUS_SIE != 0
    }
}

/// Brings the interrupt controller up for this hart: opens the PLIC's
/// supervisor context and permits external interrupts to reach the hart.
///
/// # Safety
///
/// Called once, on the boot hart, with the PLIC mapped read-write and
/// interrupts masked.
pub unsafe fn init_plic() {
    // SAFETY: forwarded — boot hart, PLIC mapped, interrupts masked.
    unsafe { tessera_karch_riscv_common::plic::open_context() };
    // SAFETY: `sie` is the supervisor interrupt-enable CSR; setting SEIE
    // permits external interrupts to reach this hart. Delivery still depends
    // on `sstatus.SIE`, which the caller controls.
    unsafe { asm!("csrs sie, {}", in(reg) SIE_SEIE, options(nomem, nostack)) };
}

/// Reads the 64-bit `time` counter through its two 32-bit halves.
///
/// The high half is read, then the low, then the high again; if the high half
/// is unchanged no carry happened between them and the pair is consistent.
/// This is the architecturally documented sequence for reading a 64-bit
/// counter on RV32, and it is why `read_counter` is a loop here and a single
/// instruction on the 64-bit port.
pub fn read_counter() -> u64 {
    loop {
        let (high, low, again): (u32, u32, u32);
        // SAFETY: `time` and `timeh` are read-only counter CSRs, readable from
        // S-mode when `mcounteren.TM` is set — which the firmware that entered
        // this kernel does. The reads have no side effects.
        unsafe {
            asm!("rdtimeh {}", out(reg) high, options(nomem, nostack));
            asm!("rdtime {}", out(reg) low, options(nomem, nostack));
            asm!("rdtimeh {}", out(reg) again, options(nomem, nostack));
        }
        if high == again {
            return (u64::from(high) << 32) | u64::from(low);
        }
    }
}

/// `time` read with a preceding memory fence, so the counter cannot be
/// sampled before earlier memory operations have completed.
///
/// The same caveat as the 64-bit port applies and is worth repeating rather
/// than cross-referencing: `fence` orders *memory accesses*, not instruction
/// retirement, and the base ISA has no serializing instruction. A budget
/// measurement cannot be claimed from this counter until that is solved. The
/// two-CSR read widens the sampling window further, which is a reason to fix
/// it here first rather than a new problem.
pub fn read_counter_serialized() -> u64 {
    // SAFETY: `fence` is an ordering barrier with no memory effect of its own.
    unsafe { asm!("fence rw, rw", options(nostack)) };
    read_counter()
}
