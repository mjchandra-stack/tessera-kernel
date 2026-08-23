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
use crate::atomic::CpuCounter;
use crate::event::{Component, EventKind, Severity, emit, emit_with_flags};
use crate::percpu::{BOOT_CPU, MAX_CPUS, PerCpu};
use core::sync::atomic::Ordering;
use tessera_karch::{CpuBringUp, CpuStartError, Ipi, IpiReason, TimerControl};

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

/// Records that the CPU at `index` is one the kernel now runs work on.
///
/// Called by that CPU, once, as it takes up a run queue of its own — which is
/// the moment "online" starts being true of it. Distinct from arrival by design
/// (`CpuState`): a CPU can be executing this kernel's code for a long time
/// before anything is dispatched to it, and the two were one flag in no version
/// of this.
pub fn mark_online(index: u32) {
    // SAFETY: a CPU writes its own slot and no other, and the boot CPU has
    // stopped writing this registry by the time any secondary reaches here —
    // it wrote each slot once, before releasing that CPU.
    unsafe {
        CPUS.with_mut(index, |cpu| cpu.online = true);
    }
}

/// How many CPUs the kernel has brought online.
pub fn online_count() -> usize {
    CPUS.iter().filter(|cpu| cpu.online).count()
}

/// The CPUs the scheduler dispatches to, one bit each.
///
/// The shootdown's target set for anything mapped in the kernel's own space,
/// which every CPU runs on — see `crate::vm::AddressSpace::mark_active_everywhere`.
pub fn online_mask() -> u64 {
    let mut mask = 0u64;
    for index in 0..PerCpu::<u8>::capacity().min(u64::BITS) {
        if cpu(index).is_some_and(|state| state.online) {
            mask |= 1u64 << index;
        }
    }
    mask
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
static IPIS_TAKEN: [CpuCounter; MAX_CPUS] = [const { CpuCounter::new(0) }; MAX_CPUS];

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
    IPIS_TAKEN[index as usize].add(1, Ordering::Release);
}

/// How many interrupts from other CPUs the CPU at `index` has taken.
pub fn ipis_taken(index: u32) -> u64 {
    if index >= PerCpu::<u8>::capacity() {
        return 0;
    }
    IPIS_TAKEN[index as usize].get(Ordering::Acquire)
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
    /// Interrupts taken across the round beyond the one each CPU was sent.
    ///
    /// A targeted round sends each CPU exactly one, so every counter should
    /// end the round exactly one higher than it started. Anything above that
    /// is an interrupt a CPU took without being named, which is the half of
    /// "reaches its target" that counting acknowledgements cannot see: a send
    /// that ignores its argument and wakes everybody acknowledges perfectly.
    pub surplus: u64,
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

    /// Whether every interrupt reached its target **and only** its target.
    ///
    /// Three conditions, and the last two are what keep the property from
    /// being earned without being shown:
    ///
    /// * [`complete`](Self::complete), because a send that delivers nothing
    ///   strays nowhere. Exclusivity on its own is a property of doing
    ///   nothing.
    /// * More than one CPU targeted. With a single other CPU there is no
    ///   address to get wrong: a send that ignores its argument and a send
    ///   that honours it produce the same counters. The distinction needs a
    ///   third CPU on the machine, which is why the boot checks asserting this
    ///   run `-smp 4` and why a two-CPU run does not make the claim rather
    ///   than making it vacuously.
    /// * No surplus.
    pub fn exclusive(&self) -> bool {
        self.complete() && self.targeted > 1 && self.surplus == 0
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
/// # Counting rather than sampling
///
/// Each CPU's counter is read once for the whole round, not once per send, and
/// the round's verdict is that every one of them ended **exactly one** higher.
/// Per-send sampling can only ask "did this CPU take an interrupt", which a
/// send that wakes every CPU answers correctly for each target in turn; asking
/// for an exact count instead makes the extra interrupts the ones nobody was
/// sent, and they have nowhere to hide. It also costs one settle for the round
/// rather than one per send.
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
        surplus: 0,
    };
    let mut before = [0u64; MAX_CPUS];
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        before[index as usize] = ipis_taken(index);
    }
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        round.targeted += 1;
        // SAFETY: the caller's contract — the CPU arrived, which is what makes
        // its interface initialized.
        if !unsafe { I::send(index, reason) } {
            continue;
        }
        round.addressed += 1;
        if wait_for_ipi(index, before[index as usize], spins) {
            round.acknowledged += 1;
        }
    }
    // Only when there is a wrong address to have used. Below two targets the
    // surplus cannot be a finding — `exclusive` withholds the claim on the
    // count of targets alone — and a settle bought nothing on every
    // single-CPU boot in the tree, which is most of them.
    if round.targeted > 1 {
        round.surplus = settled_surplus(&before, spins / SETTLE_FRACTION);
    }
    round
}

/// How much a settle costs relative to the budget for a delivery.
///
/// A stray is an interrupt nobody waited for, so nothing in the round paces
/// it. Waiting for the targets is not enough on its own: run against a port
/// that woke every CPU on every send, a round that counted the moment its last
/// target answered found one stray, and the same round after a settle found
/// three. What is wanted is a wait of the same order as the deliveries that
/// just succeeded, which is what a fraction of their budget is, and small
/// enough that a boot pays it once rather than once per send.
///
/// The settled number is still what the machine did rather than what the
/// defect implies. Three sends waking three CPUs is nine interrupts by
/// arithmetic and was six here, because a controller that already has this
/// interrupt pending for a CPU from this sender does not queue a second. That
/// is the reason the claim turns on the count being zero and not on it
/// matching a prediction.
const SETTLE_FRACTION: u64 = 8;

/// Sums what every CPU took beyond the one interrupt it was sent, after giving
/// stragglers `settle` spins to arrive.
///
/// The wait comes first and the count second, rather than counting in a loop
/// and stopping at the first non-zero. Stopping early answers the question —
/// anything above zero fails the claim — but it answers it with whichever
/// stray happened to land first, and reported one where the settled count is
/// three. The number is what the boot line prints and what a person reads to
/// tell "one CPU was addressed wrongly" from "every send went everywhere", so
/// it is worth the settle a failing boot pays once.
fn settled_surplus(before: &[u64; MAX_CPUS], settle: u64) -> u64 {
    // Absence is what is being waited out — there is nothing to watch for that
    // would end this early, which is the whole difficulty of checking that
    // something did *not* happen.
    for _ in 0..settle {
        core::hint::spin_loop();
    }
    let mut surplus = 0;
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        // Saturating, because a CPU that never took its own interrupt is under
        // by one and that is `acknowledged`'s finding, not this one's.
        surplus += ipis_taken(index)
            .wrapping_sub(before[index as usize])
            .saturating_sub(1);
    }
    surplus
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
        // Every arrived CPU is a target here, so there is no CPU that should
        // not have been reached and nothing for a surplus to mean. The
        // broadcast's own risk is the opposite one — reaching a CPU the kernel
        // has no index for — and no counter of the kernel's can see that.
        surplus: 0,
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
    let both = targeted.complete() && broadcast.complete() && targeted.surplus == 0;
    // The surplus goes in `flags` rather than in an `arg`: all four are spent
    // on the two rounds' counts, and this is exactly the per-kind detail that
    // field exists for.
    emit_with_flags(
        EventKind::CpuIpi,
        if both || targeted.targeted == 0 {
            Severity::Info
        } else {
            Severity::Error
        },
        Component::Scheduler,
        targeted.surplus,
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
    // Said separately rather than folded into the line above, because it is a
    // count of interrupts nobody asked for and a zero there is the finding.
    if targeted.targeted > 1 {
        crate::kprintln!(
            "smp: {} interrupt(s) taken by a CPU that was not the target",
            targeted.surplus
        );
    }

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
    //
    // `smp.ipi-only-target` is the third because it is a different question
    // about the same write: `smp.ipi-targeted` says the named CPU took it, and
    // this one says nobody else did. A send that woke every CPU on the machine
    // earns the first and not the second, and keeping them apart is what makes
    // an inversion say which of the two broke.
    match (
        targeted.complete(),
        targeted.exclusive(),
        broadcast.complete(),
    ) {
        (true, true, true) => &[
            "smp.ipi-targeted",
            "smp.ipi-broadcast",
            "smp.ipi-only-target",
        ],
        (true, true, false) => &["smp.ipi-targeted", "smp.ipi-only-target"],
        (true, false, true) => &["smp.ipi-targeted", "smp.ipi-broadcast"],
        (true, false, false) => &["smp.ipi-targeted"],
        // `exclusive` implies `complete`, so there is no fourth case here.
        (false, _, true) => &["smp.ipi-broadcast"],
        (false, _, false) => &[],
    }
}

/// What came of handing work to the CPUs the kernel started.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SecondWork {
    /// CPUs that were given a thread.
    pub given: usize,
    /// Of those, how many ran it.
    pub ran: usize,
}

/// Waits for every CPU that was given work to show that it ran it.
///
/// `progress` reports how many times the CPU at that index has run its thread;
/// it is the port's, because what the thread does is the port's, and this only
/// decides what the count means.
pub fn second_cpu_ran(given: usize, progress: fn(u32) -> u64, spins: u64) -> SecondWork {
    let mut result = SecondWork { given, ran: 0 };
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        let mut left = spins;
        while progress(index) == 0 && left > 0 {
            core::hint::spin_loop();
            left -= 1;
        }
        if progress(index) > 0 {
            result.ran += 1;
        }
    }
    result
}

/// Prints the boot line for the first work another CPU did, and returns the
/// claim keys.
pub fn report_second_cpu(work: SecondWork, present: Option<usize>) -> &'static [&'static str] {
    if work.given == 0 {
        return &[];
    }
    let online = online_count();
    crate::kprintln!(
        "smp: {}/{} CPU(s) ran a thread off a run queue of their own; {online} online",
        work.ran,
        work.given
    );

    // Two claims, and the second is D8's exit criterion rather than a restating
    // of the first. `smp.second-cpu-runs` says a CPU other than the boot CPU
    // dispatched work; `smp.all-online` says none was left out — a machine
    // where one of four CPUs failed to start would earn the first and not the
    // second, and the difference is the whole of what D8 was about.
    match (work.ran == work.given, present == Some(online)) {
        (true, true) => &["smp.second-cpu-runs", "smp.all-online"],
        (true, false) => &["smp.second-cpu-runs"],
        (false, true) => &["smp.all-online"],
        (false, false) => &[],
    }
}

/// A kernel address another CPU is to read when interrupted, or zero for none.
///
/// **The only way to make another CPU translate an address on demand.** A CPU
/// that is idling runs nothing of its own, so a check that needs its view of
/// the page tables has to arrive as an interrupt. This is that check's
/// argument, [`PROBE_SAW`] is its answer, and the generation is what tells
/// "read again and saw the same thing" from "did not read at all".
///
/// Here rather than in a port because none of it is architectural: an address,
/// a read, a counter. Both ports drive the same checks with it.
static PROBE_VA: AtomicU64 = AtomicU64::new(0);
static PROBE_SAW: AtomicU64 = AtomicU64::new(0);
static PROBE_GENERATION: crate::counter::Sharded = crate::counter::Sharded::new();

/// Asks the next interrupted CPU to read `virt`, returning the generation to
/// wait past.
///
/// # Safety
///
/// `virt` must be a kernel address mapped readable in the tables every CPU is
/// running on, and must stay mapped until the answer is in.
pub unsafe fn probe_at(virt: u64) -> u64 {
    PROBE_VA.store(virt, Ordering::Release);
    PROBE_GENERATION.total()
}

/// The value a CPU read, once the generation has moved past `since`.
pub fn probe_answer(since: u64, spins: u64) -> Option<u64> {
    let mut left = spins;
    while PROBE_GENERATION.total() == since && left > 0 {
        core::hint::spin_loop();
        left -= 1;
    }
    if PROBE_GENERATION.total() == since {
        return None;
    }
    Some(PROBE_SAW.load(Ordering::Acquire))
}

/// Stops asking.
pub fn probe_off() {
    PROBE_VA.store(0, Ordering::Release);
}

/// Reads whatever the boot CPU asked about, from the CPU that was interrupted.
///
/// # Safety
///
/// Called from an interrupt path; [`probe_at`]'s contract is what makes the
/// read valid, and the boot CPU keeps the page mapped until the answer is in.
pub unsafe fn serve_probe() {
    let virt = PROBE_VA.load(Ordering::Acquire);
    if virt == 0 {
        return;
    }
    // SAFETY: `probe_at`'s contract, restated.
    let saw = unsafe { (virt as *const u64).read_volatile() };
    PROBE_SAW.store(saw, Ordering::Release);
    PROBE_GENERATION.bump();
}

/// What came of asking every online CPU to pass a quiescent state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GraceRound {
    /// CPUs other than this one that were online and therefore waited for.
    pub waited_for: usize,
    /// Whether the grace period completed.
    pub completed: bool,
}

/// Starts a grace period and waits for it.
///
/// **What this shows that a host test cannot**: the CPUs being waited for are
/// real ones, idling in their own run loops, and the grace period completes
/// only because each of them reaches a point where it holds nothing and says
/// so. A facility whose readers never quiesced would look identical until the
/// first writer tried to reclaim something.
/// How long a boot check waits for a grace period.
///
/// **Its own bound, and much smaller than the arrival one.** A CPU either
/// arrives quickly or not at all, so waiting a long time for it costs nothing
/// on the path that succeeds. A grace period is different: the failing case is
/// a CPU that is running and simply never quiesces, and the boot CPU spins the
/// whole bound before it can say so. With the arrival bound that took longer
/// than the harness allows the whole boot, so the check could not report its
/// own failure — it timed out instead, which says nothing about why. A bounded
/// wait whose bound outlives the run is not a bounded wait.
///
/// Sized against the success path: an idle CPU quiesces once per pass of its
/// run loop, and that loop turns on its own tick, so the wait is at most a tick
/// period plus the emulator's overhead.
pub const GRACE_SPINS: u64 = 20_000_000;

pub fn grace_period(spins: u64) -> GraceRound {
    let waited_for = (0..PerCpu::<u8>::capacity())
        .filter(|&index| index != BOOT_CPU && cpu(index).is_some_and(|state| state.online))
        .count();
    let epoch = crate::epoch::advance();
    crate::epoch::quiesce();
    GraceRound {
        waited_for,
        completed: crate::epoch::wait_for_grace(epoch, spins),
    }
}

/// Prints the boot line for a grace period and returns the claim keys.
pub fn report_grace(round: GraceRound) -> &'static [&'static str] {
    if round.waited_for == 0 {
        return &[];
    }
    crate::kprintln!(
        "smp: a grace period completed across {} other CPU(s): {}",
        round.waited_for,
        if round.completed { "yes" } else { "NO" }
    );
    if round.completed {
        &["smp.grace-period"]
    } else {
        &[]
    }
}

/// What one round of waking every other CPU came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WakeRound {
    /// CPUs that had arrived and were therefore woken.
    pub targeted: usize,
    /// Of those, how many took the wakeup off their own bitmap.
    pub delivered: usize,
}

impl WakeRound {
    /// Whether every CPU that was woken took it.
    ///
    /// False when nothing was targeted, for the reason every other round here
    /// says so: a machine with one CPU has not shown that a wakeup crosses.
    pub fn complete(&self) -> bool {
        self.targeted > 0 && self.delivered == self.targeted
    }
}

/// Wakes a thread slot on every arrived CPU and waits for each to take it.
///
/// **This is the cross-core wakeup with the thread taken out of it**: a bit
/// set by one CPU, an interrupt to prompt the other, and the other taking it
/// off its own bitmap. It names no thread — it posts
/// [`ThreadId::UNASSIGNED`], which `Scheduler::unblock_thread` matches against
/// nothing — because what it is checking is that a *bit* crosses, on a machine
/// where the far CPU may have no thread in that slot at all. The executive's
/// own wakes name the thread they are for (`kcore::wakeup::wake`).
///
/// # Safety
///
/// Every arrived CPU must be able to take the prompt — see [`Ipi::send`].
pub unsafe fn wake_each<I: Ipi>(slot: usize, spins: u64) -> WakeRound {
    let mut round = WakeRound {
        targeted: 0,
        delivered: 0,
    };
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        round.targeted += 1;
        let before = crate::wakeup::taken(index);
        // SAFETY: the caller's contract — the CPU arrived, which is what makes
        // its controller interface initialized.
        if !unsafe {
            crate::wakeup::wake_remote::<I>(index, slot, crate::thread::ThreadId::UNASSIGNED)
        } {
            continue;
        }
        let mut left = spins;
        while crate::wakeup::taken(index) == before && left > 0 {
            core::hint::spin_loop();
            left -= 1;
        }
        if crate::wakeup::taken(index) != before {
            round.delivered += 1;
        }
    }
    round
}

/// Prints the boot line for a wakeup round and returns the claim keys.
pub fn report_wakeups(round: WakeRound) -> &'static [&'static str] {
    if round.targeted == 0 {
        crate::kprintln!("smp: no other CPU to wake");
        return &[];
    }
    crate::kprintln!(
        "smp: {}/{} CPU(s) took a wakeup posted from another CPU",
        round.delivered,
        round.targeted
    );
    if round.complete() {
        &["smp.wakeup-crosses"]
    } else {
        &[]
    }
}

/// What one round of checking every CPU's own tick came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TickRound {
    /// CPUs that had arrived and were therefore expected to be ticking.
    pub expected: usize,
    /// Of those, how many advanced their own counter.
    pub ticking: usize,
}

impl TickRound {
    /// Whether every CPU that should be ticking is.
    ///
    /// False when nothing was expected: a machine running one CPU has not shown
    /// that a *second* CPU's timer works, and letting "nothing failed" stand for
    /// "it works" is how a check comes to pass on a kernel that stopped
    /// starting them.
    pub fn complete(&self) -> bool {
        self.expected > 0 && self.ticking == self.expected
    }
}

/// Waits for every arrived CPU's own tick counter to advance.
///
/// **The counter is per CPU because the timer is.** A single machine-wide count
/// would advance on the boot CPU's tick alone, so a secondary whose timer never
/// started would be indistinguishable from one whose did — which is exactly the
/// state every port was in while the tick was one device for the whole machine.
pub fn ticks_advanced<T: TimerControl>(spins: u64) -> TickRound {
    let mut round = TickRound {
        expected: 0,
        ticking: 0,
    };
    let mut before = [0u64; MAX_CPUS];
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        before[index as usize] = T::ticks_on(index);
        round.expected += 1;
    }
    for index in 0..PerCpu::<u8>::capacity() {
        if index == BOOT_CPU || !cpu(index).is_some_and(|state| state.arrived) {
            continue;
        }
        let mut left = spins;
        while T::ticks_on(index) == before[index as usize] && left > 0 {
            core::hint::spin_loop();
            left -= 1;
        }
        if T::ticks_on(index) != before[index as usize] {
            round.ticking += 1;
        }
    }
    round
}

/// Prints the boot line for a tick round and returns the claim keys.
pub fn report_ticks(round: TickRound) -> &'static [&'static str] {
    if round.expected == 0 {
        crate::kprintln!("smp: no other CPU to tick");
        return &[];
    }
    crate::kprintln!(
        "smp: {}/{} CPU(s) are ticking on a timer of their own",
        round.ticking,
        round.expected
    );
    if round.complete() {
        &["smp.tick-per-cpu"]
    } else {
        &[]
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

    // **`smp.single` is gone.** It said "this kernel dispatches to one CPU",
    // which is what D8 declared, and it stopped being true the moment a second
    // CPU took a thread off a run queue of its own. What replaces it is
    // `smp.all-online`, asserted after bring-up rather than here, because "how
    // many CPUs this kernel runs work on" is not a fact the survey can know —
    // the survey runs before any of them are started.
    //
    // `smp.counted` is that the kernel knows how many CPUs there are;
    // `smp.boot_id` is that the identifier it addresses them by is the one the
    // platform uses. Both are still facts about the survey.
    match (topology.present, topology.boot_id_agrees()) {
        (Some(_), Some(true)) => &["smp.counted", "smp.boot_id"],
        (Some(_), _) => &["smp.counted"],
        (None, Some(true)) => &["smp.boot_id"],
        (None, _) => &[],
    }
}

#[cfg(test)]
#[path = "tests/smp.rs"]
mod tests;
