// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The local interrupt controller, in x2APIC mode.
//!
//! # Why x2APIC and not the memory-mapped form
//!
//! The local APIC has two register interfaces. The older one is a 4 KiB page
//! of memory-mapped registers; x2APIC is the same controller reached through
//! model-specific registers instead. The MSR form is better here for reasons
//! that are not stylistic: there is no page to map (and therefore no
//! uncacheable mapping to get wrong), the interrupt command register is one
//! 64-bit write rather than two ordered 32-bit writes with a delivery-status
//! poll between them, and the identifier is 32 bits wide instead of 8 — which
//! is the field a targeted interrupt names a CPU by.
//!
//! `docs/hardware/01-platform-and-cpu-support.md` ("Modern Hardware Only") is
//! what settles it. x2APIC has been architectural since 2008, and supporting
//! the memory-mapped form as well would mean two drivers for one controller,
//! the second existing only for machines this kernel has already said it does
//! not target. A CPU without it is **refused at boot**, loudly, rather than
//! quietly falling back (`docs/lifecycle/04`, "No Silent Fallback").
//!
//! # What replaced what
//!
//! This module and its two neighbours are the exit from build/README.md's D87.
//! The 8259 pair is gone: it is masked once at boot so it cannot deliver, and
//! nothing else touches it. The tick is the local APIC's own timer, calibrated
//! against the HPET. Device lines arrive through the I/O APIC. And the thing
//! none of the legacy parts could do at all — one CPU interrupting another —
//! is the interrupt command register here.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Modern Hardware
//! Only"), docs/roadmap/02-smp-bring-up-plan.md ("Phase 2")
//! Budget: none (init path; EOI is one MSR write on the interrupt path)

use crate::cpu::{read_msr, write_msr};
use core::sync::atomic::{AtomicU32, Ordering};

/// `IA32_APIC_BASE`: where the controller is, and whether it is on.
const IA32_APIC_BASE: u32 = 0x1b;
/// x2APIC mode. Setting it without [`APIC_BASE_ENABLE`] is an invalid state.
const APIC_BASE_EXTD: u64 = 1 << 10;
/// The controller is enabled at all.
const APIC_BASE_ENABLE: u64 = 1 << 11;

// x2APIC register MSRs. The numbering mirrors the memory-mapped offsets:
// register at offset `n` is MSR `0x800 + n/16`.
const APIC_ID: u32 = 0x802;
const APIC_TPR: u32 = 0x808;
const APIC_EOI: u32 = 0x80b;
const APIC_SVR: u32 = 0x80f;
const APIC_ICR: u32 = 0x830;
const APIC_LVT_TIMER: u32 = 0x832;
const APIC_LVT_LINT0: u32 = 0x835;
const APIC_LVT_LINT1: u32 = 0x836;
const APIC_LVT_ERROR: u32 = 0x837;
const APIC_TIMER_INITIAL: u32 = 0x838;
const APIC_TIMER_CURRENT: u32 = 0x839;
const APIC_TIMER_DIVIDE: u32 = 0x83e;

/// Spurious-vector register: the software enable, plus the vector delivered
/// when an interrupt is withdrawn between being raised and being taken.
const SVR_SOFTWARE_ENABLE: u32 = 1 << 8;

/// Local vector table: masked.
const LVT_MASKED: u32 = 1 << 16;
/// Local vector table, timer: periodic mode.
const LVT_TIMER_PERIODIC: u32 = 0b01 << 17;

/// Timer divide configuration for "divide by 1" — the encoding is not the
/// number, and 0b1011 is it.
const TIMER_DIVIDE_BY_1: u32 = 0b1011;

/// Interrupt command: fixed delivery, physical destination, assert, edge.
const ICR_FIXED_ASSERT: u32 = 1 << 14;
/// Destination shorthand "all excluding self".
const ICR_ALL_BUT_SELF: u32 = 0b11 << 18;

/// Each CPU's controller identifier, recorded by that CPU, indexed by the
/// kernel's dense index. `u32::MAX` means no CPU has claimed the slot.
///
/// The same indirection the other port needs and for the same reason: a
/// controller identifier is sparse and assigned by firmware, a kernel index is
/// dense and assigned here, and only the CPU itself can say which one it holds.
/// Zero is a real identifier — it is the boot CPU's on every machine here — so
/// the empty value has to be something else.
static IDENTIFIERS: [AtomicU32; crate::CPU_TABLE_SLOTS] =
    [const { AtomicU32::new(u32::MAX) }; crate::CPU_TABLE_SLOTS];

/// Records this CPU's controller identifier against the kernel's `index`.
///
/// Returns it, or `None` when `index` is beyond what this port has slots for.
///
/// # Safety
///
/// This CPU's controller must be enabled, and `index` must be this CPU's and
/// held by no other.
pub unsafe fn record_cpu(index: u32) -> Option<u32> {
    let slot = index as usize;
    if slot >= crate::CPU_TABLE_SLOTS {
        return None;
    }
    let identifier = id();
    IDENTIFIERS[slot].store(identifier, Ordering::Release);
    Some(identifier)
}

/// The controller identifier recorded for the CPU at dense `index`.
pub fn identifier_of(index: u32) -> Option<u32> {
    let slot = index as usize;
    if slot >= crate::CPU_TABLE_SLOTS {
        return None;
    }
    match IDENTIFIERS[slot].load(Ordering::Acquire) {
        u32::MAX => None,
        identifier => Some(identifier),
    }
}

/// Whether this CPU has an x2APIC (`CPUID.01H:ECX[21]`).
pub fn supported() -> bool {
    crate::cpu::cpuid(1, 0).2 & (1 << 21) != 0
}

/// Enables this CPU's local controller in x2APIC mode.
///
/// `spurious_vector` is delivered when an interrupt is withdrawn between being
/// raised and being taken. It is never acknowledged — see [`eoi`].
///
/// # Safety
///
/// This CPU has an x2APIC ([`supported`]), the interrupt descriptor table is
/// loaded, and this runs once per CPU with interrupts masked.
pub unsafe fn init_cpu(spurious_vector: u8) {
    // SAFETY: the caller's contract. Enabling the controller only makes it able
    // to deliver; nothing is unmasked here that the IDT does not already cover.
    unsafe {
        let base = read_msr(IA32_APIC_BASE);
        write_msr(IA32_APIC_BASE, base | APIC_BASE_ENABLE | APIC_BASE_EXTD);

        // Accept every priority. The task-priority register resets to zero on
        // most parts and is written anyway: a boot that inherited a raised
        // priority would take no interrupts and report nothing about why.
        write_msr(APIC_TPR, 0);

        // Everything the controller can raise on its own, masked until
        // something asks for it. `LINT0`/`LINT1` matter most: on a machine
        // where firmware wired the legacy timer through LINT0, leaving them
        // enabled delivers a second, unrelated tick.
        write_msr(APIC_LVT_TIMER, u64::from(LVT_MASKED));
        write_msr(APIC_LVT_LINT0, u64::from(LVT_MASKED));
        write_msr(APIC_LVT_LINT1, u64::from(LVT_MASKED));
        write_msr(APIC_LVT_ERROR, u64::from(LVT_MASKED));

        // Software-enable last, so the controller comes up with its local
        // sources already quiet.
        write_msr(
            APIC_SVR,
            u64::from(SVR_SOFTWARE_ENABLE | u32::from(spurious_vector)),
        );
    }
}

/// This CPU's local-controller identifier, as the controller reports it.
pub fn id() -> u32 {
    // SAFETY: the x2APIC ID register is read-only and readable once the
    // controller is enabled; reading it has no side effect.
    unsafe { read_msr(APIC_ID) as u32 }
}

/// Acknowledges the interrupt currently being serviced.
///
/// **Not for the spurious vector.** That one is the controller saying it has
/// nothing in service, and acknowledging it would end whatever genuinely is.
///
/// # Safety
///
/// Called from interrupt context on a CPU whose controller is enabled, once
/// per interrupt taken.
pub unsafe fn eoi() {
    // SAFETY: writing zero to the end-of-interrupt register completes the
    // interrupt in service, which is the caller's intent per the contract.
    unsafe { write_msr(APIC_EOI, 0) }
}

/// Starts this CPU's local timer at `count` ticks per interrupt, delivering
/// `vector`.
///
/// # Safety
///
/// The controller must be enabled on this CPU and `vector` present in the
/// interrupt descriptor table.
pub unsafe fn start_timer(vector: u8, count: u32) {
    // SAFETY: the caller's contract. The divide and count registers only shape
    // the timer; the LVT write is what makes it deliver, and is last.
    unsafe {
        write_msr(APIC_TIMER_DIVIDE, u64::from(TIMER_DIVIDE_BY_1));
        write_msr(
            APIC_LVT_TIMER,
            u64::from(LVT_TIMER_PERIODIC | u32::from(vector)),
        );
        write_msr(APIC_TIMER_INITIAL, u64::from(count));
    }
}

/// Runs the timer down from `count` with no interrupt, for calibration, and
/// returns how far it got.
///
/// # Safety
///
/// The controller must be enabled on this CPU. `measure` must not itself
/// depend on the timer.
pub unsafe fn count_down_during(count: u32, measure: impl FnOnce()) -> u32 {
    // SAFETY: the timer is left masked throughout, so nothing is delivered; the
    // count registers have no effect beyond the counter itself.
    unsafe {
        write_msr(APIC_TIMER_DIVIDE, u64::from(TIMER_DIVIDE_BY_1));
        write_msr(APIC_LVT_TIMER, u64::from(LVT_MASKED));
        write_msr(APIC_TIMER_INITIAL, u64::from(count));
        measure();
        let left = read_msr(APIC_TIMER_CURRENT) as u32;
        write_msr(APIC_TIMER_INITIAL, 0);
        count.saturating_sub(left)
    }
}

/// Sends `vector` to the CPU whose controller identifier is `dest`.
///
/// # Safety
///
/// The target CPU's controller must be enabled and `vector` present in its
/// interrupt descriptor table, or the interrupt stays in service there.
pub unsafe fn send(dest: u32, vector: u8) {
    // SAFETY: the caller's contract. In x2APIC the command register is a single
    // 64-bit write, which is why there is no delivery-status poll here: the
    // race the poll existed for is the one two 32-bit writes created.
    unsafe {
        write_msr(
            APIC_ICR,
            (u64::from(dest) << 32) | u64::from(ICR_FIXED_ASSERT | u32::from(vector)),
        )
    }
}

/// Sends `vector` to every CPU except this one.
///
/// # Safety
///
/// As [`send`], for every CPU on the machine.
pub unsafe fn send_all_but_self(vector: u8) {
    // SAFETY: as `send`. The shorthand makes the destination field unused.
    unsafe {
        write_msr(
            APIC_ICR,
            u64::from(ICR_ALL_BUT_SELF | ICR_FIXED_ASSERT | u32::from(vector)),
        )
    }
}
