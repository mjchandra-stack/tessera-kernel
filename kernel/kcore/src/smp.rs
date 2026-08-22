// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What the machine has, and what this kernel started on it.
//!
//! Those are two numbers, and this milestone they disagree: every port
//! discovers how many CPUs the platform presents and brings up exactly one
//! (build/README.md, D8). The gap is the deviation, and a deviation nothing
//! prints is one no boot can be held to — a kernel running on one of four CPUs
//! is indistinguishable from a kernel on a single-CPU machine unless it says
//! so (`docs/lifecycle/04-coding-guidelines.md`, "No Silent Fallback").
//!
//! **Discovery is the port's, the report is not.** How many CPUs exist is an
//! architecture question answered three different ways — a boot protocol's
//! response here, a device tree's `/cpus` there — but *what the answer means*
//! is the same on every port, so it is stated once here rather than in each
//! `main.rs`. That is the same division `kernel/boot-checks` draws, and it is
//! the division `../roadmap/02-smp-bring-up-plan.md` builds the rest of SMP on:
//! the porting layer supplies mechanism, the core supplies policy.
//!
//! This module is deliberately the smallest thing that can carry that
//! sentence. Bring-up, per-CPU state, and the cross-core paths land on top of
//! it in later phases; what it establishes now is that the count is a fact the
//! kernel holds rather than an assumption it makes.
//!
//! Normative: docs/kernel/08-multicore-scalability.md,
//! docs/roadmap/02-smp-bring-up-plan.md
//! Budget: none (boot reporting only)

use crate::event::{Component, EventKind, Severity, emit};

/// The CPUs the boot CPU found, and the one it is running on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Topology {
    /// How many CPUs the platform presents, or `None` when the platform was
    /// asked and did not answer.
    ///
    /// `None` is not "one". A firmware that does not report its CPUs and a
    /// machine that has one CPU are different facts, and folding them together
    /// is how a four-CPU board comes to look like a single-core one for a
    /// milestone at a time.
    pub present: Option<usize>,
    /// How many this kernel brought online. One, until bring-up lands (D8).
    pub online: usize,
    /// The boot CPU's hardware identifier, as its architecture numbers it —
    /// an affinity register here, an interrupt-controller id there. Reported,
    /// never used as an index: it is sparse on both, which is the confusion
    /// the bring-up plan's dense index exists to end.
    pub boot_cpu_hw_id: u64,
}

impl Topology {
    /// How many CPUs the kernel found and did not start, or `None` when the
    /// platform did not say how many there are.
    pub fn parked(&self) -> Option<usize> {
        self.present.map(|n| n.saturating_sub(self.online))
    }
}

/// Emits the topology event and prints the boot line.
///
/// Returns the claim keys a boot check should assert, so the port's harness
/// names them the way it names every other claim rather than this module
/// printing them itself — the renderer's job stays with the harness
/// (`crate::verdict`).
pub fn report(topology: Topology) -> &'static [&'static str] {
    emit(
        EventKind::CpuTopology,
        Severity::Info,
        Component::Scheduler,
        [
            topology.present.unwrap_or(0) as u64,
            topology.online as u64,
            topology.boot_cpu_hw_id,
            0,
        ],
    );

    match (topology.present, topology.parked()) {
        (Some(present), Some(parked)) => crate::kprintln!(
            "smp: {present} CPU(s) present, {} online, {parked} parked (D8), boot cpu id {:#x}",
            topology.online,
            topology.boot_cpu_hw_id
        ),
        _ => crate::kprintln!(
            "smp: CPU count not reported by the platform, {} online, boot cpu id {:#x}",
            topology.online,
            topology.boot_cpu_hw_id
        ),
    }

    // Two keys, because they are separable claims and a check that asserted
    // only the first would pass on a machine whose CPUs were never counted.
    // `smp.single` is what D8 says; `smp.counted` is that the kernel knows what
    // it is deviating from.
    match topology.present {
        Some(_) => &["smp.single", "smp.counted"],
        None => &["smp.single"],
    }
}

#[cfg(test)]
#[path = "tests/smp.rs"]
mod tests;
