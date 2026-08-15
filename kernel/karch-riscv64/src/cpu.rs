// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! CPU identity, idle, entropy, interrupt masking, and the invariant time
//! counter for RISC-V 64.
//!
//! Three things differ from the other two ports and are worth naming rather
//! than discovering:
//!
//! * **The hart id is not readable at this privilege level.** `mhartid` is an
//!   M-mode CSR, and the kernel runs in S-mode under firmware. The id arrives
//!   once, in `a0` at entry, and the boot stub parks it in `tp` — the
//!   architecture's thread pointer, which by convention holds exactly this.
//!   So [`CpuOps::cpu_id`] reads a register the port itself established.
//! * **The counter has no architectural frequency register.** x86-64
//!   calibrates its TSC and AArch64 reads `CNTFRQ_EL0`; RISC-V publishes the
//!   `time` CSR's rate as a device-tree property (`timebase-frequency`) and
//!   nowhere in the ISA. [`CpuOps::counter_hz`] therefore answers `None`,
//!   which is the trait's documented "must be calibrated instead" case rather
//!   than a gap in this port.
//! * **There is no serializing instruction.** `counter_serialized` is built
//!   from a `fence` rather than from x86's `lfence`-class barrier or AArch64's
//!   `isb`, and what that buys is stated at the function.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Architecture
//! Porting Layer"), docs/prototypes/01-ipc-benchmark-harness.md
//! Budget: none (identity and idle paths)

use core::arch::asm;
use tessera_karch::CpuOps;
use tessera_karch::InterruptControl;

/// `sstatus.SIE` — the supervisor interrupt-enable bit.
const SSTATUS_SIE: u64 = 1 << 1;

pub struct Cpu;

impl CpuOps for Cpu {
    fn cpu_id() -> u32 {
        let hart: u64;
        // SAFETY: `tp` is a general-purpose register. This kernel's boot stub
        // is the only writer, and it writes the firmware-supplied hart id
        // before any Rust code runs; reading it has no side effects.
        unsafe { asm!("mv {}, tp", out(reg) hart, options(nomem, nostack, preserves_flags)) };
        hart as u32
    }

    fn halt_until_interrupt() {
        // SAFETY: `wfi` is a hint with no memory effects; it either sleeps
        // until an interrupt is pending or retires immediately. Note that it
        // wakes on a pending interrupt even when `sstatus.SIE` masks delivery,
        // and then returns *without taking* it — the caller unmasks around
        // this call if it means to be woken by one.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }

    fn hw_random() -> Option<u64> {
        // The `seed` CSR (Zkr) is the architecture's entropy tap, but it is
        // read-locked to M-mode unless firmware grants S-mode access through
        // `mseccfg.SSEED`, and nothing in this port negotiates that grant. A
        // blind read would trap as an illegal instruction, so the honest
        // answer is that this port has no entropy source — the same answer
        // AArch64 gives on a CPU without FEAT_RNG, and not a degraded
        // fallback. General randomness never comes from here in any case.
        None
    }

    fn counter_serialized() -> u64 {
        read_counter_serialized()
    }

    fn counter_hz() -> Option<u64> {
        // Deliberately `None`: RISC-V reports the `time` CSR's frequency in
        // the device tree, not in a CSR. A caller that needs real time reads
        // `/cpus/timebase-frequency`; a caller that needs only a difference
        // needs neither, which is most of them.
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
        let sstatus: u64;
        // SAFETY: reading `sstatus` is a side-effect-free read of the current
        // supervisor status, permitted at S-mode.
        unsafe { asm!("csrr {}, sstatus", out(reg) sstatus, options(nomem, nostack)) };
        sstatus & SSTATUS_SIE != 0
    }
}

/// `sie.SEIE` — the supervisor external interrupt enable.
const SIE_SEIE: u64 = 1 << 9;

/// Brings the interrupt controller up for this hart: opens the PLIC's
/// supervisor context and permits external interrupts to reach the hart.
///
/// The split is the one the shared-device crate's header describes — the PLIC
/// is a device and lives there, `sie` is architectural state of the register's
/// width and lives here.
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

/// Raw `time` CSR read. Cheap, but not ordered against surrounding
/// instructions — use [`read_counter_serialized`] to time a region.
pub fn read_counter() -> u64 {
    let counter: u64;
    // SAFETY: `time` is a read-only counter CSR. It is readable from S-mode
    // when `mcounteren.TM` is set, which the firmware that entered this kernel
    // does; the read has no side effects.
    unsafe { asm!("rdtime {}", out(reg) counter, options(nomem, nostack)) };
    counter
}

/// `time` read with a preceding memory fence, so the counter cannot be
/// sampled before earlier memory operations have completed.
///
/// This is weaker than the other two ports' serialization and the difference
/// is deliberate rather than overlooked. x86-64 has an instruction that
/// serializes execution and AArch64 has `ISB`; RISC-V's base ISA has neither,
/// and `fence` orders *memory accesses*, not instruction retirement. On an
/// out-of-order implementation the counter read may still be hoisted past
/// non-memory work. `docs/prototypes/01-ipc-benchmark-harness.md` requires
/// serialization around a measured region, so this port cannot yet claim a
/// budget measurement on hardware — which is recorded rather than papered
/// over, and costs nothing today because the measured regions are memory-
/// bound and the reference machine is an emulator.
pub fn read_counter_serialized() -> u64 {
    let counter: u64;
    // SAFETY: `fence` is an ordering barrier with no memory effect of its own;
    // `time` is a side-effect-free read.
    unsafe {
        asm!(
            "fence rw, rw",
            "rdtime {}",
            out(reg) counter,
            options(nostack),
        );
    }
    counter
}
