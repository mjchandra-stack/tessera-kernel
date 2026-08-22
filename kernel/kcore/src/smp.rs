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
use crate::percpu::{BOOT_CPU, PerCpu};

/// What the kernel knows about one CPU.
///
/// The hardware id sits *beside* the slot rather than selecting it: it is
/// sparse and architecture-shaped, while the index is dense and assigned
/// (`crate::percpu`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuState {
    /// Whether this kernel has brought the CPU up and dispatches to it.
    pub online: bool,
    /// The identifier the architecture gives it, recorded when it came online
    /// and meaningless before.
    pub hw_id: u64,
}

impl CpuState {
    const OFFLINE: Self = Self {
        online: false,
        hw_id: 0,
    };
}

/// The registry. One slot per CPU the kernel could carry, of which exactly one
/// is ever marked online this milestone (build/README.md, D8/D217).
static CPUS: PerCpu<CpuState> = PerCpu::new(CpuState::OFFLINE);

/// Records that the boot CPU is online, carrying the identifier its
/// architecture gives it.
pub fn register_boot_cpu(hw_id: u64) {
    // SAFETY: the boot CPU, before any other CPU exists to hold a reference
    // into the registry — which is the whole of `PerCpu`'s obligation.
    unsafe {
        CPUS.with_mut(BOOT_CPU, |cpu| {
            *cpu = CpuState {
                online: true,
                hw_id,
            };
        });
    }
}

/// How many CPUs the kernel has brought online.
pub fn online_count() -> usize {
    CPUS.iter().filter(|cpu| cpu.online).count()
}

/// The state recorded for `index`, or `None` beyond the compiled-in ceiling.
pub fn cpu(index: u32) -> Option<&'static CpuState> {
    CPUS.get(index)
}

/// The CPUs the boot CPU found, and the ones it brought online.
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
    /// The same identifier as the *platform's* CPU list gives it — a
    /// bootloader's response, a device tree's `cpu` node — or `None` where the
    /// port has no second source for it.
    ///
    /// Two sources for one number, kept apart on purpose. The kernel will
    /// shortly hand this identifier to firmware to start a CPU and to an
    /// interrupt controller to address one, and neither reports a
    /// misidentified target: the CPU that was meant to start simply does not,
    /// or an interrupt arrives somewhere else. Comparing them here is the only
    /// place the disagreement is cheap to see.
    pub platform_hw_id: Option<u64>,
}

/// Registers the boot CPU and reads back what the kernel then knows, against
/// the `present` count the port discovered.
///
/// This is the call a port makes. The online half comes from the registry, so
/// no port states it — every port passed a literal `1` before, which is the
/// same assumption written once per port and checkable in none of them. A port
/// that starts a CPU without registering it now reports a number that
/// disagrees with its own boot line, rather than one that stayed right by
/// coincidence.
pub fn survey(
    present: Option<usize>,
    boot_cpu_hw_id: u64,
    platform_hw_id: Option<u64>,
) -> Topology {
    register_boot_cpu(boot_cpu_hw_id);
    Topology {
        present,
        online: online_count(),
        boot_cpu_hw_id,
        platform_hw_id,
    }
}

impl Topology {
    /// How many CPUs the kernel found and did not start, or `None` when the
    /// platform did not say how many there are.
    pub fn parked(&self) -> Option<usize> {
        self.present.map(|n| n.saturating_sub(self.online))
    }

    /// Whether the CPU's own identifier matches the platform's for it, or
    /// `None` where there is only one source and so nothing to check.
    pub fn boot_id_agrees(&self) -> Option<bool> {
        self.platform_hw_id.map(|id| id == self.boot_cpu_hw_id)
    }
}

/// Emits the topology event and prints the boot line.
///
/// Returns the claim keys a boot check should assert, so the port's harness
/// names them the way it names every other claim rather than this module
/// printing them itself — the renderer's job stays with the harness
/// (`crate::verdict`).
pub fn report(topology: Topology) -> &'static [&'static str] {
    // Error rather than Info when the two sources disagree, because the event
    // is what a log service filters on and this is the one thing in the
    // topology worth waking someone for.
    let severity = match topology.boot_id_agrees() {
        Some(false) => Severity::Error,
        _ => Severity::Info,
    };
    emit(
        EventKind::CpuTopology,
        severity,
        Component::Scheduler,
        [
            topology.present.unwrap_or(0) as u64,
            topology.online as u64,
            topology.boot_cpu_hw_id,
            topology.platform_hw_id.unwrap_or(u64::MAX),
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

    // Printed, not exited: this module has no way to end a boot and no business
    // deciding to, and the port that does gets the same signal from the
    // withheld claim below. `FATAL` in this tree is followed by an exit
    // (`kernel/kernel/src/main.rs`'s store check), so this deliberately does
    // not say it.
    match topology.boot_id_agrees() {
        Some(false) => crate::kprintln!(
            "smp: boot cpu id MISMATCH — the CPU reads {:#x}, the platform lists {:#x}",
            topology.boot_cpu_hw_id,
            topology.platform_hw_id.unwrap_or(0)
        ),
        Some(true) => crate::kprintln!(
            "smp: boot cpu id agrees with the platform's list ({:#x})",
            topology.boot_cpu_hw_id
        ),
        None => {}
    }

    // Separable claims, and a check that asserted only the first would pass on
    // a machine whose CPUs were never counted. `smp.single` is what D8 says;
    // `smp.counted` is that the kernel knows what it is deviating from;
    // `smp.boot_id` is that the identifier it will address CPUs by is the one
    // the platform uses.
    match (topology.present, topology.boot_id_agrees()) {
        (Some(_), Some(true)) => &["smp.single", "smp.counted", "smp.boot_id"],
        (Some(_), _) => &["smp.single", "smp.counted"],
        (None, Some(true)) => &["smp.single", "smp.boot_id"],
        (None, _) => &["smp.single"],
    }
}

#[cfg(test)]
#[path = "tests/smp.rs"]
mod tests;
