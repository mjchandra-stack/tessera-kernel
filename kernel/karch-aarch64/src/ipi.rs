// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Interrupting another CPU, AArch64.
//!
//! The mechanism is the interrupt controller's software-generated interrupts:
//! a CPU writes one distributor register naming an interrupt id and a set of
//! target CPU interfaces, and the controller delivers it as an ordinary
//! interrupt at the other end. There is no separate doorbell and no message —
//! the id *is* the message, which is why [`IpiReason`] maps to an id rather
//! than to a payload.
//!
//! # The three names of a CPU
//!
//! Sending needs the third one. A CPU's affinity register is what firmware
//! takes to start it; the kernel's dense index is what indexes its state; and a
//! target list is a bit position in the controller's own numbering, which is
//! neither of those and which a CPU can only learn by reading a register that
//! answers differently depending on who is reading. The translation lives in
//! `karch-arm-common`'s GIC module, where the register does, and each CPU
//! records its own bit on the way up.
//!
//! Normative: docs/roadmap/02-smp-bring-up-plan.md ("Phase 2"),
//! docs/kernel/08-multicore-scalability.md
//! Budget: none this milestone (nothing sends one on a scheduling path yet)

use tessera_karch::{Ipi, IpiReason};
use tessera_karch_arm_common::gic;

/// The software-generated interrupt id carrying [`IpiReason::Reschedule`].
///
/// Ids 0-15 are the controller's; this kernel uses one of them and leaves the
/// rest. The number itself is arbitrary and the *mapping* is not: a reason and
/// an id are one thing, and a second reason takes a second id rather than a
/// flag inside this one.
pub const RESCHEDULE_SGI: u32 = 0;

/// The id carrying [`IpiReason::TlbShootdown`].
pub const SHOOTDOWN_SGI: u32 = 1;

const fn sgi_for(reason: IpiReason) -> u32 {
    match reason {
        IpiReason::Reschedule => RESCHEDULE_SGI,
        IpiReason::TlbShootdown => SHOOTDOWN_SGI,
    }
}

/// The reason an id carries, for a receiver deciding what it was woken for.
pub const fn reason_of(sgi: u32) -> Option<IpiReason> {
    match sgi {
        RESCHEDULE_SGI => Some(IpiReason::Reschedule),
        SHOOTDOWN_SGI => Some(IpiReason::TlbShootdown),
        _ => None,
    }
}

/// Prepares **this** CPU to receive interrupts from others, and records where
/// it is so they can be aimed at it.
///
/// Returns the controller bit this CPU claimed, or `None` if it has none —
/// which means no other CPU can interrupt it, and is reported rather than
/// guessed at.
///
/// # Safety
///
/// The GIC must be mapped, its CPU interface initialized on this CPU, and
/// `index` must be this CPU's dense index and held by no other.
pub unsafe fn init_cpu(index: u32) -> Option<u32> {
    // SAFETY: forwarded to the caller's contract. Enabling the id is done per
    // CPU because the registers covering ids below 32 are banked — the boot
    // CPU's write reaches its own copy and nobody else's.
    unsafe {
        gic::enable(RESCHEDULE_SGI);
        gic::enable(SHOOTDOWN_SGI);
        gic::record_cpu_interface(index)
    }
}

/// The GIC's software-generated interrupts.
pub struct Sgi;

impl Ipi for Sgi {
    // SAFETY: the trait's contract, forwarded to the GIC module, which owns the
    // register and the target-list translation.
    unsafe fn send(index: u32, reason: IpiReason) -> bool {
        // SAFETY: the id is one of this kernel's own, below the first private
        // interrupt; the target's interface is the caller's obligation.
        unsafe { gic::send_sgi(index, sgi_for(reason)) }
    }

    // SAFETY: as above, for every CPU on the machine.
    unsafe fn send_all_but_self(reason: IpiReason) {
        // SAFETY: as `send`.
        unsafe { gic::broadcast_sgi(sgi_for(reason)) }
    }
}
