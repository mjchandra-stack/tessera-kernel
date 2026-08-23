// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Does this kernel go faster with more CPUs — budgets B19 and B20.
//!
//! # What parallel efficiency is, and why it is a division of two wall times
//!
//! `docs/prototypes/01`'s scaling condition replicates BM-3 "as fully
//! independent instances, one pinned per core", and reports "aggregate
//! throughput at N cores divided by N times the single-instance baseline".
//!
//! Every worker does the **same** number of round trips in every phase, so the
//! algebra collapses: aggregate throughput at N is `N·R / window_N`, the
//! baseline is `R / window_1`, and the ratio of the first to N times the second
//! is `window_1 / window_N`. **Efficiency is what the wall clock does when
//! more CPUs join.** Perfect scaling means three CPUs finish their work in the
//! time one CPU took to finish its own.
//!
//! # Independent by construction, and checked
//!
//! Each worker is a client and a server on *one* CPU, calling over a channel
//! nobody else touches. Nothing in the benchmark is shared — which is the
//! point: what is left is whatever the *kernel* shares, and
//! `docs/kernel/08`'s no-hot-path-serialization rule is what B19 exists to
//! test. A pair that was not actually same-core would post cross-CPU wakeups,
//! so the count of those is asserted at zero rather than assumed.
//!
//! # The boot CPU stays out
//!
//! It drives the phases and does not run a pair. A harness thread competing
//! with the thing it measures is a harness that changes the answer, and with
//! four CPUs there are three workers, which is enough for a knee to show.
//!
//! # Two things replicated, not one
//!
//! The scaling condition names both "BM-3 as independent client/server pairs"
//! (B19) and "a zero-fill fault loop over private mappings" (B20). They share
//! every part of the harness except the work in the middle, so they share the
//! phase protocol and differ by a [`PhaseKind`] — and they are worth having
//! together, because they contend on *different* kernel structures. The IPC
//! pairs go through the executive's machine-wide lock on every call; the fault
//! loops touch nothing shared at all, each walking its own address space with
//! its own frames. One is the serialization test and the other is its control.
//!
//! Normative: docs/prototypes/01-ipc-benchmark-harness.md ("Scaling
//! Condition"), docs/kernel/08-multicore-scalability.md
//! Budget: B19 (independent same-core IPC pairs), B20 (anonymous zero-fill
//! faults on private mappings) — this is their measurement

use crate::atomic::{AtomicU64, SharedCounter};
use crate::exec::Executive;
use crate::ipc::{EndpointId, Message, MessageHeader};
use crate::vm::AddressSpace;
use core::sync::atomic::Ordering;
use tessera_karch::{AddressSpaceOps, ContextOps, FRAME_SIZE, FrameSource, PageFlags, VirtAddr};

/// Round trips each worker makes in each phase it takes part in.
pub const ROUNDS: usize = 200;

/// Zero-fill faults each worker takes in each phase it takes part in.
///
/// Fewer than the IPC rounds because each one consumes a frame that is never
/// given back — a pool is exhausted, not recycled — and the boot CPU has to
/// draw them all in advance. Sixty-four is enough for a percentile and costs a
/// quarter of a megabyte per worker per phase.
pub const FAULT_ROUNDS: usize = 64;

/// Frames one worker's pool must hold: every fault it will take, over every
/// phase it takes part in — **and the page tables to map them through**.
///
/// The slack is not padding. `AddressSpace::resolve_fault` allocates the
/// intermediate levels a mapping needs as it walks, so a pool sized exactly to
/// the data pages runs dry partway through the first phase — which is how this
/// was found: `complete` refused, the claim was withheld, and the boot said
/// so. Sixteen covers every level a region this size can need on any of the
/// five ports, and a pool that is over-provisioned costs frames the boot has
/// in abundance.
pub const FAULT_TABLE_SLACK: usize = 16;

/// Frames one worker's pool must hold.
pub const FAULT_FRAMES: usize = FAULT_ROUNDS * MAX_WORKERS + FAULT_TABLE_SLACK;

/// Where each worker's demand-mapped region starts in its own space. Its own
/// space, so every worker may use the same address.
pub const FAULT_BASE: u64 = 0x0000_0000_4000_0000;

/// What a phase measures.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PhaseKind {
    /// Synchronous channel calls between a client and server on one CPU — the
    /// path that goes through the executive's machine-wide lock.
    Ipc,
    /// Zero-fill faults on a private mapping — the path that shares nothing.
    Fault,
}

/// Workers the benchmark can hold — every CPU but the boot CPU.
pub const MAX_WORKERS: usize = crate::percpu::MAX_CPUS - 1;

const IFACE: u64 = 0x0000_0000_0042_0013;
const METHOD: u32 = 1;
const NO_ENDPOINT: u64 = u64::MAX;
/// No phase has started.
const NO_PHASE: u64 = u64::MAX;

/// Each worker's channel: the client's end and the server's.
static CLIENT_END: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(NO_ENDPOINT) }; MAX_WORKERS];
static SERVER_END: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(NO_ENDPOINT) }; MAX_WORKERS];

/// How many workers the boot CPU set up.
static WORKERS: AtomicU64 = AtomicU64::new(0);
/// The phase now running, or [`NO_PHASE`].
static PHASE: AtomicU64 = AtomicU64::new(NO_PHASE);
/// Workers taking part in the phase now running.
static ACTIVE: AtomicU64 = AtomicU64::new(0);
/// Workers that have finished the phase now running — every worker reports,
/// whether it took part or not, so the boot CPU waits for a fixed number.
static REPORTED: SharedCounter = SharedCounter::new(0);
/// When each worker started and ended its share of the phase.
static STARTED_AT: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
static ENDED_AT: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
/// Round trips each worker has completed, over the whole run.
static COMPLETED: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
/// Wakeups that crossed a CPU while the benchmark ran. Must be none.
static CROSSINGS: AtomicU64 = AtomicU64::new(0);
/// Times a CPU had to wait for the executive's machine-wide lock during each
/// phase. Indexed by phase, of which there are two per worker.
///
/// **The scaling condition's "name the contended structure" half.**
/// `docs/prototypes/01` asks that a failure "attaches a shared-cache-line
/// profile ... so a serialization regression arrives naming the contended
/// structure". Coherence counters do not exist under an emulator, and this is
/// the better answer anyway: nothing in the benchmark is shared, so a number
/// that falls short can only be the kernel's own serialization, and
/// `crate::machine_lock` is the one lock every channel operation takes.
static CONTENDED: [AtomicU64; MAX_WORKERS * 2] = [const { AtomicU64::new(0) }; MAX_WORKERS * 2];

fn encode(endpoint: EndpointId) -> u64 {
    ((endpoint.channel as u64) << 8) | (endpoint.side as u64)
}

fn decode(raw: u64) -> Option<EndpointId> {
    if raw == NO_ENDPOINT {
        return None;
    }
    Some(EndpointId {
        channel: (raw >> 8) as usize,
        side: (raw & 0xff) as usize,
    })
}

/// Creates one channel per worker, on the boot CPU before any CPU is given
/// work.
pub fn open<C: ContextOps>(exec: &mut Executive<C>, workers: usize) -> bool {
    let workers = workers.min(MAX_WORKERS);
    for worker in 0..workers {
        let Ok((client, server)) = exec.channel_create() else {
            return false;
        };
        SERVER_END[worker].store(encode(server), Ordering::Release);
        CLIENT_END[worker].store(encode(client), Ordering::Release);
    }
    WORKERS.store(workers as u64, Ordering::Release);
    workers > 0
}

/// How many workers this boot set up.
pub fn workers() -> usize {
    WORKERS.load(Ordering::Acquire) as usize
}

/// Phases the run makes: one per worker count, from one up to all of them.
pub fn phases() -> usize {
    workers()
}

/// The kind of work phase `phase` measures.
///
/// The IPC phases come first and the fault phases after, so a worker walks one
/// list and the boot CPU drives one loop.
pub fn kind_of(phase: usize) -> PhaseKind {
    if phase < workers() {
        PhaseKind::Ipc
    } else {
        PhaseKind::Fault
    }
}

/// Workers taking part in `phase`: one in the first of each kind, all of them
/// in the last.
fn active_in(phase: usize) -> usize {
    phase % workers().max(1) + 1
}

/// Channel round trips worker `worker` makes over the whole run.
///
/// A worker takes part in every phase from its own index onward — worker 0 in
/// all of them, the last in only the widest — because a phase at N runs
/// workers 0..N. So the earlier workers do more, and each server has to know
/// exactly how many to answer: a server that stopped early would leave its
/// client blocked and a server that waited for one more would never end.
pub fn rounds_for(worker: usize) -> usize {
    ROUNDS * phases().saturating_sub(worker)
}

/// Faults worker `worker` takes over the whole run, by the same reasoning.
pub fn faults_for(worker: usize) -> usize {
    FAULT_ROUNDS * phases().saturating_sub(worker)
}

/// Frames worker `worker`'s pool must be filled with: its faults, plus the
/// page tables to map them through.
pub fn frames_for(worker: usize) -> usize {
    faults_for(worker) + FAULT_TABLE_SLACK
}

/// The server half of one worker's pair, on that worker's own CPU.
pub fn serve<C: ContextOps>(exec: &mut Executive<C>, worker: usize) {
    let Some(server_end) = decode(SERVER_END[worker].load(Ordering::Acquire)) else {
        return;
    };
    // One priming call before the timed ones (see [`client`]), so the total is
    // one more than the rounds.
    let calls = rounds_for(worker) + 1;
    if calls == 0 || exec.receive(server_end).is_err() {
        return;
    }
    for _ in 1..calls {
        let Ok(response) = reply() else { return };
        if exec.reply_receive(server_end, response).is_err() {
            return;
        }
    }
    // The continuing form for the last, so this thread is still runnable
    // afterwards — a bare `reply` hands the CPU to the client and blocks the
    // replier, which for a server that is finishing means it never returns
    // (build/README.md, D242).
    if let Ok(response) = reply() {
        let _ = exec.reply_and_continue(server_end, response);
    }
}

/// The client half of one worker's pair, and the same worker's fault loop.
///
/// Walks every phase, taking part in the ones its index qualifies for and
/// reporting either way, so the boot CPU always waits for the same number of
/// reports.
///
/// `space` and `frames` are this worker's own — a scratch address space that
/// is never activated and a pool of frames drawn for it in advance. Neither is
/// shared with any other CPU, which is what "private mappings" means and what
/// makes the fault phases a control for the IPC ones.
pub fn client<C: ContextOps, A: AddressSpaceOps>(
    exec: &mut Executive<C>,
    worker: usize,
    now: fn() -> u64,
    space: &mut AddressSpace<A>,
    frames: &mut dyn FrameSource,
) {
    let Some(client_end) = decode(CLIENT_END[worker].load(Ordering::Acquire)) else {
        return;
    };
    // The whole region, marked lazy once: `map_anonymous_demand` records the
    // mapping and touches no frame, so this costs nothing the fault loop is
    // trying to measure. A distinct sub-range per phase, because a lazy page
    // fills exactly once and a second pass over the same address would measure
    // a lookup.
    if space
        .map_anonymous_demand(
            VirtAddr::new(FAULT_BASE),
            (FAULT_FRAMES as u64) * FRAME_SIZE,
            PageFlags::rw().user(),
        )
        .is_err()
    {
        return;
    }
    // The priming call, untimed: it is what parks this worker's server as its
    // endpoint's blocked receiver, and until it is, `call` has nobody to hand
    // off to and takes the slower path.
    let Ok(first) = request() else { return };
    if exec.call(client_end, first).is_err() {
        return;
    }

    let phases_per_kind = phases();
    let phases = phases_per_kind * 2;
    for phase in 0..phases {
        while PHASE.load(Ordering::Acquire) != phase as u64 {
            core::hint::spin_loop();
        }
        if (worker as u64) < ACTIVE.load(Ordering::Acquire) {
            STARTED_AT[worker].store(now(), Ordering::Release);
            let done = match kind_of(phase) {
                PhaseKind::Ipc => {
                    let mut done = 0u64;
                    for _ in 0..ROUNDS {
                        let Ok(message) = request() else { break };
                        if exec.call(client_end, message).is_err() {
                            break;
                        }
                        done += 1;
                    }
                    done
                }
                PhaseKind::Fault => fault_loop(space, frames, phase - phases_per_kind),
            };
            ENDED_AT[worker].store(now(), Ordering::Release);
            COMPLETED[worker].store(
                COMPLETED[worker].load(Ordering::Acquire) + done,
                Ordering::Release,
            );
        }
        REPORTED.fetch_add(1, Ordering::AcqRel);
    }
}

/// Fills `FAULT_ROUNDS` lazy pages, one frame each, and returns how many it
/// filled.
///
/// The sub-range is `round`'s own, so every page is fresh: a lazy page fills
/// once, and faulting the same address twice would time a page-table lookup
/// rather than a fill.
fn fault_loop<A: AddressSpaceOps>(
    space: &mut AddressSpace<A>,
    frames: &mut dyn FrameSource,
    round: usize,
) -> u64 {
    let mut filled = 0u64;
    for page in 0..FAULT_ROUNDS {
        let offset = ((round * FAULT_ROUNDS + page) as u64) * FRAME_SIZE;
        let at = VirtAddr::new(FAULT_BASE + offset);
        if space.resolve_fault(at, false, frames) != crate::vm::FaultOutcome::Filled {
            break;
        }
        filled += 1;
    }
    filled
}

fn request() -> Result<Message, ()> {
    let mut message = Message::new(MessageHeader::new(IFACE, METHOD));
    message.set_inline(b"go").map_err(|_| ())?;
    Ok(message)
}

fn reply() -> Result<Message, ()> {
    Ok(Message::new(MessageHeader::new(IFACE, METHOD)))
}

/// What one phase did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Phase {
    /// Workers that took part.
    pub active: usize,
    /// What the phase measured.
    pub kind: PhaseKind,
    /// Counter ticks from the first worker starting to the last one ending.
    pub window: u64,
    /// Times a CPU had to wait for the machine lock during this phase.
    pub contended: u64,
}

/// Runs every phase, from one worker up to all of them, and fills `out`.
///
/// Driven from the boot CPU's own context: this side never blocks, and a
/// harness thread would be a fourth participant in a three-worker measurement.
/// `spins` bounds each phase so a worker that never reports fails the
/// benchmark rather than hanging the boot.
pub fn run<C: ContextOps>(_exec: &mut Executive<C>, out: &mut [Phase], spins: u64) -> usize {
    let workers = workers();
    if workers == 0 {
        return 0;
    }
    let before = crate::wakeup::crossings();
    let mut done = 0usize;
    for (phase, slot) in out.iter_mut().take(workers * 2).enumerate() {
        let active = active_in(phase);
        ACTIVE.store(active as u64, Ordering::Release);
        REPORTED.swap(0, Ordering::AcqRel);
        let contended_before = crate::machine_lock::contended();
        PHASE.store(phase as u64, Ordering::Release);

        let mut left = spins;
        while REPORTED.load(Ordering::Acquire) < workers as u64 && left > 0 {
            core::hint::spin_loop();
            left -= 1;
        }
        if REPORTED.load(Ordering::Acquire) < workers as u64 {
            break;
        }
        CONTENDED[phase].store(
            crate::machine_lock::contended().saturating_sub(contended_before),
            Ordering::Release,
        );

        let mut first = u64::MAX;
        let mut last = 0u64;
        for worker in 0..active {
            first = first.min(STARTED_AT[worker].load(Ordering::Acquire));
            last = last.max(ENDED_AT[worker].load(Ordering::Acquire));
        }
        *slot = Phase {
            active,
            kind: kind_of(phase),
            window: last.saturating_sub(first),
            contended: CONTENDED[phase].load(Ordering::Acquire),
        };
        done += 1;
    }
    CROSSINGS.store(
        crate::wakeup::crossings().saturating_sub(before),
        Ordering::Release,
    );
    done
}

/// Parallel efficiency at each phase, in percent of the single-worker
/// baseline.
///
/// `window_1 / window_N`, which is the whole of the metric — see the module
/// header. Zero for a phase whose window did not measure.
pub fn efficiency(phases: &[Phase]) -> [u64; MAX_WORKERS * 2] {
    let mut out = [0u64; MAX_WORKERS * 2];
    // One baseline per kind: the single-worker phase of that kind. Comparing a
    // fault phase against an IPC baseline would divide two different pieces of
    // work and call the answer scaling.
    let baseline = |kind: PhaseKind| {
        phases
            .iter()
            .find(|p| p.kind == kind && p.active == 1)
            .map(|p| p.window)
            .unwrap_or(0)
    };
    for (slot, phase) in out.iter_mut().zip(phases) {
        let base = baseline(phase.kind);
        if phase.window > 0 && base > 0 {
            *slot = base.saturating_mul(100) / phase.window;
        }
    }
    out
}

/// Whether every worker completed every round trip and every fault it was
/// asked for.
pub fn complete() -> bool {
    let workers = workers();
    workers > 0
        && COMPLETED
            .iter()
            .take(workers)
            .enumerate()
            .all(|(w, done)| done.load(Ordering::Acquire) == (rounds_for(w) + faults_for(w)) as u64)
}

/// Prints what the workers did and returns the claim keys.
///
/// **The efficiency number is printed and never claimed** — under QEMU/TCG a
/// wall-clock ratio across vCPU threads is the host's scheduler as much as the
/// kernel's (build/README.md, D34/D56). What is claimed is that the thing
/// measured was what it says: every worker completed every round trip, and not
/// one wakeup crossed a CPU. A pair whose server had ended up somewhere else
/// would still produce a plausible efficiency and would cross on every call.
pub fn report_shape() -> &'static [&'static str] {
    let workers = workers();
    if workers == 0 {
        return &[];
    }
    let crossed = CROSSINGS.load(Ordering::Acquire);
    // The shortfall named rather than left to be inferred from a missing
    // marker: a worker that stopped early is a different fault from one whose
    // pair was not really same-core, and the two withhold the same claim.
    let mut owed = 0u64;
    for (worker, done) in COMPLETED.iter().take(workers).enumerate() {
        let want = (rounds_for(worker) + faults_for(worker)) as u64;
        owed += want.saturating_sub(done.load(Ordering::Acquire));
    }
    crate::kprintln!(
        "perf: scaling ran {} independent pair(s), {} crossing(s), {} unit(s) of work owed",
        workers,
        crossed,
        owed
    );
    if complete() && crossed == 0 {
        &["perf.scaling-replicated"]
    } else {
        &[]
    }
}
