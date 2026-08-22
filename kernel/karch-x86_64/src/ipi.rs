// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Interrupting another CPU, x86-64.
//!
//! **This is the thing the legacy interrupt path could not do at all.** The
//! 8259 has no register that names a destination CPU; the question is not one
//! it can express. So the local APIC was not an improvement to the interrupt
//! path so much as the precondition for there being an SMP kernel above it,
//! which is why build/README.md's D87 records the swap as being on the SMP
//! critical path rather than beside it.
//!
//! The mechanism is the interrupt command register: one 64-bit write naming a
//! destination and a vector. As on the other port, the reason maps to a vector
//! rather than to a payload — the controller has 224 of them free and making
//! every recipient read shared state, with interrupts masked, to find out what
//! it was woken for re-asks a question the controller already answered.
//!
//! Normative: docs/roadmap/02-smp-bring-up-plan.md ("Phase 2"), build/README.md
//! D87
//! Budget: none this milestone (nothing sends one on a scheduling path yet)

use tessera_karch::{Ipi, IpiReason};

const fn vector_for(reason: IpiReason) -> u8 {
    match reason {
        IpiReason::Reschedule => crate::timer::IPI_VECTOR,
    }
}

/// The local controller's interrupt command register.
pub struct InterCpu;

impl Ipi for InterCpu {
    // SAFETY: the trait's contract, forwarded to the local controller, which
    // owns the register and the index-to-identifier translation.
    unsafe fn send(index: u32, reason: IpiReason) -> bool {
        let Some(destination) = crate::apic::identifier_of(index) else {
            return false;
        };
        // SAFETY: the vector is this kernel's own and present in every CPU's
        // table; the target's controller being enabled is the caller's
        // obligation, and is what recording the identifier implies.
        unsafe { crate::apic::send(destination, vector_for(reason)) };
        true
    }

    // SAFETY: as above, for every CPU on the machine.
    unsafe fn send_all_but_self(reason: IpiReason) {
        // SAFETY: as `send`. The shorthand makes the destination field unused,
        // so this reaches CPUs the kernel has no index for.
        unsafe { crate::apic::send_all_but_self(vector_for(reason)) }
    }
}
