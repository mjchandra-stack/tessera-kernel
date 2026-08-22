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

use crate::atomic::AtomicU64;
use crate::event::{Component, EventKind, Severity, emit};
use crate::percpu::{BOOT_CPU, MAX_CPUS, PerCpu};
use core::sync::atomic::Ordering;
use tessera_karch::{CpuBringUp, CpuStartError, Ipi, IpiReason};

/// What the kernel knows about one CPU.
///
/// The hardware id sits *beside* the slot rather than selecting it: it is
/// sparse and architecture-shaped, while the index is dense and assigned
/// (`crate::percpu`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuState {
    /// Whether the CPU is executing this kernel's code at all.
    ///
    /// Distinct from [`online`](Self::online), and the distinction is the whole
    /// of what bring-up buys before scheduling does: a CPU that has arrived has
    /// taken this kernel's page tables, its index, and its stack, and is
    /// waiting. Nothing dispatches to it. Folding the two into one flag would
    /// make the boot line say the kernel is running on CPUs it is not.
    pub arrived: bool,
    /// Whether the scheduler dispatches to it. One CPU, until D8 exits.
    pub online: bool,
    /// The identifier the architecture gives it, recorded when it arrived and
    /// meaningless before.
    pub hw_id: u64,
}

impl CpuState {
    const OFFLINE: Self = Self {
        arrived: false,
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
                arrived: true,
                online: true,
                hw_id,
            };
        });
    }
}

/// The indices of CPUs that have reached kernel code, one bit each.
///
/// **This, and not the registry, is what an arriving CPU touches.** The
/// registry is a [`PerCpu`] array behind one `UnsafeCell`, and its mutable path
/// carries the obligation that no other reference into the array is live — an
/// obligation two CPUs cannot keep by convention. So a secondary sets one bit
/// with an atomic read-modify-write and nothing else, and the boot CPU, which
/// is the registry's only writer, records the arrival once it observes the bit.
///
/// One `u64` is enough because the CPU ceiling is, and the ceiling says so.
static ARRIVED: AtomicU64 = AtomicU64::new(0);

const _: () = assert!(
    MAX_CPUS <= 64,
    "the arrival bitmap is one u64; raise it before raising MAX_CPUS past 64"
);

/// Announces that this CPU is executing kernel code, at `index`.
///
/// Called by the arriving CPU itself, and it is the *only* thing that CPU is
/// permitted to do to shared kernel state before the boot CPU has acknowledged
/// it. Out-of-range indices are dropped rather than folded into another CPU's
/// bit: an index nobody assigned is not an arrival, and claiming to be CPU 0
/// would be worse than being invisible.
pub fn announce_arrival(index: u32) {
    if index >= PerCpu::<u8>::capacity() {
        return;
    }
    ARRIVED.fetch_or(1u64 << index, Ordering::Release);
}

/// Whether the CPU at `index` has announced its arrival.
pub fn has_arrived(index: u32) -> bool {
    if index >= PerCpu::<u8>::capacity() {
        return false;
    }
    ARRIVED.load(Ordering::Acquire) & (1u64 << index) != 0
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

/// Interrupts each CPU has taken from another CPU, one counter per slot.
///
/// A counter rather than a bit, because the interesting question is not "has
/// this CPU ever been interrupted" but "did it take *this* one" — and the only
/// way to ask that without a handshake per message is to read the count before
/// and after.
static IPIS_TAKEN: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Records that this CPU took an interrupt sent by another.
///
/// Called from the receiving CPU's interrupt path, with interrupts masked, and
/// it is the whole of what that CPU does about it this milestone. Like
/// [`announce_arrival`], an out-of-range index is dropped rather than folded
/// into another CPU's counter.
pub fn note_ipi(index: u32) {
    if index >= PerCpu::<u8>::capacity() {
        return;
    }
    IPIS_TAKEN[index as usize].fetch_add(1, Ordering::Release);
}

/// How many interrupts from other CPUs the CPU at `index` has taken.
pub fn ipis_taken(index: u32) -> u64 {
    if index >= PerCpu::<u8>::capacity() {
        return 0;
    }
    IPIS_TAKEN[index as usize].load(Ordering::Acquire)
}

/// What one round of interrupting every other CPU came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IpiRound {
    /// CPUs that had arrived and were therefore interrupted.
    pub targeted: usize,
    /// Of those, how many this port could address at all.
    pub addressed: usize,
    /// Of those, how many took the interrupt and said so.
    pub acknowledged: usize,
}

impl IpiRound {
    /// Whether every CPU that was interrupted took it.
    ///
    /// False when nothing was targeted: a machine running one CPU has not
    /// demonstrated that it can interrupt another, and letting "nothing failed"
    /// stand for "it works" is how a check comes to pass on a kernel that
    /// stopped sending.
    pub fn complete(&self) -> bool {
        self.targeted > 0 && self.acknowledged == self.targeted
    }
}

/// Interrupts every CPU that has arrived, one at a time, and waits for each to
/// say it took it.
///
/// One at a time for the same reason bring-up is: a CPU that does not respond
/// is attributable to itself. The broadcast form is checked separately, by
/// [`broadcast_ipi`], because it is a different register write with different
/// addressing and a check that exercised only one of them would leave the other
/// untested.
///
/// # Safety
///
/// Every arrived CPU must have its interrupt-controller interface initialized
/// and be able to acknowledge — see [`Ipi::send`].
pub unsafe fn ping_each<I: Ipi>(reason: IpiReason, spins: u64) -> IpiRound {
    let mut round = IpiRound {
        targeted: 0,
        addressed: 0,
        acknowledged: 0,
    };
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        round.targeted += 1;
        let before = ipis_taken(index);
        // SAFETY: the caller's contract — the CPU arrived, which is what makes
        // its interface initialized.
        if !unsafe { I::send(index, reason) } {
            continue;
        }
        round.addressed += 1;
        if wait_for_ipi(index, before, spins) {
            round.acknowledged += 1;
        }
    }
    round
}

/// Interrupts every other CPU at once, and waits for each arrived one to say it
/// took it.
///
/// # Safety
///
/// As [`ping_each`], and for every CPU on the machine — a broadcast reaches
/// CPUs the kernel has no index for.
pub unsafe fn broadcast_ipi<I: Ipi>(reason: IpiReason, spins: u64) -> IpiRound {
    let mut round = IpiRound {
        targeted: 0,
        addressed: 0,
        acknowledged: 0,
    };
    let mut before = [0u64; MAX_CPUS];
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        before[index as usize] = ipis_taken(index);
        round.targeted += 1;
    }
    if round.targeted == 0 {
        return round;
    }
    // One write, every CPU: nothing here can fail to address a target, so
    // `addressed` is the whole set by construction. That is the difference the
    // broadcast buys and the reason it cannot report a per-CPU failure.
    round.addressed = round.targeted;
    // SAFETY: the caller's contract, for every CPU on the machine.
    unsafe { I::send_all_but_self(reason) };
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        if wait_for_ipi(index, before[index as usize], spins) {
            round.acknowledged += 1;
        }
    }
    round
}

fn wait_for_ipi(index: u32, before: u64, spins: u64) -> bool {
    let mut left = spins;
    while ipis_taken(index) == before && left > 0 {
        core::hint::spin_loop();
        left -= 1;
    }
    ipis_taken(index) != before
}

/// Emits the event and prints the boot line for both rounds, returning the
/// claim keys a boot check should assert.
pub fn report_ipi(targeted: IpiRound, broadcast: IpiRound) -> &'static [&'static str] {
    let both = targeted.complete() && broadcast.complete();
    emit(
        EventKind::CpuIpi,
        if both || targeted.targeted == 0 {
            Severity::Info
        } else {
            Severity::Error
        },
        Component::Scheduler,
        [
            targeted.targeted as u64,
            targeted.acknowledged as u64,
            broadcast.targeted as u64,
            broadcast.acknowledged as u64,
        ],
    );

    if targeted.targeted == 0 {
        crate::kprintln!("smp: no other CPU to interrupt");
        return &[];
    }
    crate::kprintln!(
        "smp: {}/{} CPU(s) took a targeted interrupt ({} addressable), {}/{} took the broadcast",
        targeted.acknowledged,
        targeted.targeted,
        targeted.addressed,
        broadcast.acknowledged,
        broadcast.targeted
    );

    // Two claims, because they are two register writes with different
    // addressing: the targeted send turns a dense index into the controller's
    // own numbering, and the broadcast skips that translation entirely. A check
    // asserting one would pass with the other broken.
    //
    // Neither key is a prefix of the other, and that is not tidiness. A boot
    // check greps for a claim as a substring, so a `smp.ipi` would have been
    // satisfied by the line announcing `smp.ipi-broadcast` — the check would
    // have passed with the targeted send aimed at the wrong CPU, which is
    // exactly the defect it exists to catch, and did catch once the names were
    // separable.
    match (targeted.complete(), broadcast.complete()) {
        (true, true) => &["smp.ipi-targeted", "smp.ipi-broadcast"],
        (true, false) => &["smp.ipi-targeted"],
        (false, true) => &["smp.ipi-broadcast"],
        (false, false) => &[],
    }
}

/// What one attempt to start the machine's other CPUs came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BringUp {
    /// CPUs the kernel tried to start — every one the platform listed except
    /// the boot CPU, capped at the compiled-in ceiling.
    pub attempted: usize,
    /// Of those, how many firmware accepted a start request for.
    pub started: usize,
    /// Of those, how many then reached kernel code and said so.
    pub arrived: usize,
    /// CPUs the platform has that this kernel did not try to start.
    ///
    /// Derived from the platform's own count rather than from the list handed
    /// in, because there are two ways to lose a CPU and only one of them is
    /// visible in that list: an index past the compiled-in ceiling, and a CPU
    /// the port could not even collect into its buffer. Counting from the
    /// count catches both, and catches a third nobody has thought of yet.
    pub beyond_ceiling: usize,
    /// Whether the platform's CPU list contained the boot CPU's own identifier.
    ///
    /// The kernel reads that identifier off the hardware and the platform
    /// states it separately, and this is the one place the two are compared. It
    /// is also the one place the comparison matters: bring-up's first act is to
    /// leave this CPU out of its own targets, and it does that by identifier.
    /// A port that read the wrong field — Aff0 alone where the machine has two
    /// clusters — would find no match, and would then start the CPU it is
    /// running on.
    pub boot_cpu_listed: bool,
    /// The first reason a start was refused, if any. One is kept rather than
    /// all of them because they are nearly always the same reason, and the
    /// count above already says how many.
    pub first_error: Option<CpuStartError>,
}

impl BringUp {
    /// Whether every CPU the kernel tried to start is now running its code,
    /// and the set it tried was the right one.
    ///
    /// False when nothing was attempted. A machine with one CPU has not
    /// succeeded at bring-up, it has not needed any — and a vacuous success is
    /// how a check comes to pass on a kernel that stopped starting CPUs.
    pub fn complete(&self) -> bool {
        self.boot_cpu_listed && self.attempted > 0 && self.arrived == self.attempted
    }
}

/// Starts every CPU in `hw_ids` except the boot CPU, one at a time, and waits
/// for each to reach kernel code.
///
/// # One at a time
///
/// Slower than a broadcast and worth it: a CPU that never arrives is
/// attributable to itself rather than to the batch, and the boot line can name
/// it. Nothing here is on a path where the difference is measurable.
///
/// # The wait is bounded, and this one may be
///
/// `arrival_spins` bounds how long each CPU is waited for. The x86-64 parking
/// path deliberately waits forever, because a core that has not arrived there
/// is still executing memory about to be overwritten and continuing would be
/// worse than hanging. Nothing like that is true here: a CPU that does not
/// arrive is simply absent, the kernel is not about to reuse anything of its,
/// and a boot that reports the absence is more useful than one that stops.
///
/// `present` is the platform's own count of its CPUs, used only to report how
/// many were left behind — see [`BringUp::beyond_ceiling`].
///
/// # Safety
///
/// Whatever per-CPU storage the arriving CPUs use at the indices assigned here
/// — their stacks above all — must already exist and be reserved. `boot_hw_id`
/// must be this CPU's, or this CPU will be asked to start itself.
pub unsafe fn start_secondaries<B: CpuBringUp>(
    hw_ids: &[u64],
    boot_hw_id: u64,
    present: Option<usize>,
    arrival_spins: u64,
) -> BringUp {
    let mut result = BringUp {
        attempted: 0,
        started: 0,
        arrived: 0,
        beyond_ceiling: 0,
        boot_cpu_listed: hw_ids.contains(&boot_hw_id),
        first_error: None,
    };
    // Dense, assigned, and in the order the platform listed them — which is
    // not an order this decides to trust, only one it declines to reorder.
    let mut next_index = BOOT_CPU + 1;

    for &hw_id in hw_ids {
        if hw_id == boot_hw_id {
            continue;
        }
        if next_index >= PerCpu::<u8>::capacity() {
            continue;
        }
        let index = next_index;
        next_index += 1;
        result.attempted += 1;

        // SAFETY: the index is one no CPU holds — it is minted here, once, and
        // never reused — and the caller's contract covers the storage behind
        // it.
        match unsafe { B::start(hw_id, index) } {
            Ok(()) => result.started += 1,
            Err(error) => {
                result.first_error.get_or_insert(error);
                continue;
            }
        }

        let mut spins = arrival_spins;
        while !has_arrived(index) && spins > 0 {
            core::hint::spin_loop();
            spins -= 1;
        }
        if has_arrived(index) {
            result.arrived += 1;
            // SAFETY: the boot CPU is the registry's only writer, and the
            // arriving CPU touches the bitmap and nothing else — which is why
            // the acknowledgement is recorded here rather than there.
            unsafe {
                CPUS.with_mut(index, |cpu| {
                    cpu.arrived = true;
                    cpu.hw_id = hw_id;
                });
            }
        } else {
            result.first_error.get_or_insert(CpuStartError::NoArrival);
        }
    }
    // The boot CPU is one of the present count and was never a target.
    result.beyond_ceiling = present.map_or(0, |n| n.saturating_sub(1 + result.attempted));
    result
}

/// Emits the bring-up event and prints the boot line, returning the claim keys
/// a boot check should assert.
pub fn report_bring_up(bring_up: BringUp) -> &'static [&'static str] {
    emit(
        EventKind::CpuBringUp,
        if bring_up.complete() || bring_up.attempted == 0 {
            Severity::Info
        } else {
            Severity::Error
        },
        Component::Scheduler,
        [
            bring_up.attempted as u64,
            bring_up.started as u64,
            bring_up.arrived as u64,
            bring_up.beyond_ceiling as u64,
        ],
    );

    match bring_up.first_error {
        Some(error) => crate::kprintln!(
            "smp: {} of {} secondary CPU(s) reached the kernel ({} started, first failure {:?})",
            bring_up.arrived,
            bring_up.attempted,
            bring_up.started,
            error
        ),
        None => crate::kprintln!(
            "smp: {} of {} secondary CPU(s) reached the kernel, parked (D8)",
            bring_up.arrived,
            bring_up.attempted
        ),
    }
    if !bring_up.boot_cpu_listed {
        crate::kprintln!("smp: the platform's CPU list does not contain the boot CPU's own id");
    }
    if bring_up.beyond_ceiling > 0 {
        crate::kprintln!(
            "smp: {} CPU(s) present and not started, ceiling {}",
            bring_up.beyond_ceiling,
            MAX_CPUS
        );
    }

    // Withheld when nothing was attempted, so a kernel that stopped starting
    // CPUs fails the check rather than passing it vacuously.
    if bring_up.complete() {
        &["smp.started"]
    } else {
        &[]
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
