// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Whether a timer tick may take the running thread off this CPU right now.
//!
//! # The question, and why it is not "is preemption enabled"
//!
//! A tick arrives on a CPU that is running a thread. Switching to another
//! thread there is only safe if nothing the interrupted code holds would travel
//! to the incoming thread — and on this kernel two things would.
//!
//! - **[`crate::machine_lock`] is owned per CPU, not per thread.** A thread
//!   preempted inside an executive method leaves the hold behind: the incoming
//!   thread finds `depth > 0`, takes a free nested hold over tables the
//!   outgoing one is halfway through updating, and can release a hold it never
//!   took. That is not a race that needs two CPUs; one CPU and a tick is
//!   enough.
//! - **[`crate::epoch`]'s read-side depth is the same shape.** A thread
//!   preempted inside a read section leaves the depth raised, and the CPU then
//!   never declares itself quiescent — one preemption stalls reclamation for
//!   every writer on the machine, for ever.
//!
//! Both are per-CPU counters that a context switch does not carry, so the
//! honest answer is not to preempt while either is raised. **Asking is cheaper
//! than fixing**, and it is also the smaller claim: making them per-thread
//! means teaching the switch path to carry them on five ports, and nothing
//! yet needs preemption badly enough to buy that.
//!
//! # What a deferred tick costs, and why it is counted
//!
//! A quantum. The thread keeps the CPU until the next tick finds it outside
//! both, which for a thread that blocks — every server in this tree — happens
//! within one tick. What it is *not* is a lost preemption: nothing here decides
//! a thread may never be preempted, only that this tick is not the moment.
//!
//! It is counted because a kernel that stopped preempting would otherwise look
//! exactly like one with nothing to preempt (`../lifecycle/04-coding-guidelines.md`,
//! "No Silent Fallback"). A deferral rate that climbs is a CPU spending its
//! time inside the executive, which is the contention D244 measured arriving
//! by a different road.
//!
//! # What this module is not
//!
//! It is not the mechanism. Masking interrupts across the context switch is
//! what makes preemption safe at all, and that lives in
//! `Scheduler::switch_to`; this only decides whether to call it.
//!
//! **That mask is scoped to the CPUs whose tick can re-enter the scheduler,
//! which is every CPU but the boot CPU**, and the scoping was forced rather
//! than chosen: masking every switch on the boot CPU too regressed the AArch64
//! ring-3 filesystem checks under full-suite load, reproducibly, for reasons
//! that are not yet understood. It buys nothing there — the boot CPU's tick
//! drives whichever scheduler the running check installed, never the
//! executive's — so the narrower mask is both the safe one and the only one
//! that passes. Preempting the boot CPU will have to answer that question
//! first.
//!
//! Normative: docs/kernel/08-multicore-scalability.md,
//! docs/roadmap/02-smp-bring-up-plan.md ("Phase 3"), build/README.md D246
//! Budget: none (two per-CPU loads on the tick path)

/// Preemptions a tick actually performed.
static TAKEN: crate::counter::Sharded = crate::counter::Sharded::new();

/// Ticks that found the CPU holding something a switch would not carry.
static DEFERRED: crate::counter::Sharded = crate::counter::Sharded::new();

/// Whether a tick may switch away from the thread running on this CPU.
///
/// See the module header for the two holds that say no. Both are per-CPU
/// facts, so this is a question about the CPU rather than about the thread —
/// which is exactly right: what must not travel across the switch is what the
/// CPU is holding, whoever put it there.
pub fn allowed() -> bool {
    !crate::machine_lock::held_here() && !crate::epoch::reading_here()
}

/// Runs `switch` if this is a safe moment, and counts either way.
///
/// The whole policy, in the one place a tick reaches it. `switch` is the
/// caller's because only the caller knows which scheduler this CPU dispatches
/// out of.
pub fn on_tick(switch: impl FnOnce()) {
    if !allowed() {
        DEFERRED.bump();
        return;
    }
    TAKEN.bump();
    switch();
}

/// Ticks that preempted the running thread.
pub fn taken() -> u64 {
    TAKEN.total()
}

/// Ticks that could not, because the CPU held the machine lock or was inside
/// an epoch read section.
pub fn deferred() -> u64 {
    DEFERRED.total()
}

/// Emits the boot line. No claim of its own: **neither number is a verdict.**
///
/// Zero preemptions is correct on a kernel whose threads all yield, and a
/// deferral is correct by construction — the check that a secondary is
/// preemptible is `smp.secondary-preempted`, which asks whether two threads
/// that never yield both ran, and that is a question about the outcome rather
/// than about these counters.
pub fn report() {
    crate::event::emit(
        crate::event::EventKind::Preemption,
        crate::event::Severity::Info,
        crate::event::Component::Scheduler,
        [taken(), deferred(), 0, 0],
    );
    crate::kprintln!(
        "sched: {} tick(s) preempted a thread, {} deferred inside the executive",
        taken(),
        deferred()
    );
}

/// Workers the preemption check hands to one secondary.
///
/// Two, because one proves nothing: a single thread that runs to completion
/// looks the same whether or not it could have been taken off the CPU.
pub const WORKERS: usize = 2;

/// How far into its spin each worker has got. Non-zero means it ran at all.
static SPUN: [crate::atomic::CpuCounter; WORKERS] =
    [const { crate::atomic::CpuCounter::new(0) }; WORKERS];

/// Whether each worker saw the *other* one running while it was still running.
static SAW_PEER: [crate::atomic::AtomicU64; WORKERS] =
    [const { crate::atomic::AtomicU64::new(0) }; WORKERS];

/// Set by the boot CPU to tell a worker to stop waiting for its peer.
///
/// **The bound lives here rather than in the worker, and that is what keeps a
/// failure cheap.** A worker counting its own iterations has to be given a
/// number large enough to cover a tick and small enough not to dominate the
/// boot, and it spends that whole number on exactly the run where the check
/// fails. The boot CPU is already waiting on the answer with a bound of its
/// own, so it is the one that knows when to stop — and on the passing run it
/// never sets this at all.
static GIVE_UP: crate::atomic::AtomicU64 = crate::atomic::AtomicU64::new(0);

/// Workers that have finished and left their CPU's run queue.
static DONE: crate::atomic::CpuCounter = crate::atomic::CpuCounter::new(0);

/// Spins for the peer to appear, and reports whether it did.
///
/// **What this shows that a counter cannot.** Two threads that each run to
/// completion advance two counters whether the CPU preempted or simply ran one
/// after the other. So each worker spins waiting to observe the other, and only
/// a tick that takes the first off the CPU lets the second start — a
/// cooperative kernel leaves worker 0 spinning out its whole bound with nothing
/// to see.
///
/// **Bounded, so the failure is a verdict and not a hang.** A check that hung
/// when it failed would cost a two-minute timeout and report nothing, which is
/// the lesson `build/README.md` D237 paid for once already.
///
/// Ends by taking itself off its CPU's run queue, so the pair leaves the
/// secondary as it found it.
///
/// Handed to a secondary as a thread entry point, so it is safe to *name* and
/// the obligation is on the caller that spawns it: a CPU running
/// [`crate::secondary::run_this_cpu`], `C` that CPU's context switch, `index`
/// below [`WORKERS`].
pub extern "C" fn spin_worker<C: tessera_karch::ContextOps>(index: usize) -> ! {
    if index < WORKERS {
        let peer = 1 - index;
        SPUN[index].add(1, core::sync::atomic::Ordering::Release);
        loop {
            if SPUN[peer].get(core::sync::atomic::Ordering::Acquire) != 0 {
                SAW_PEER[index].store(1, core::sync::atomic::Ordering::Release);
                break;
            }
            if GIVE_UP.load(core::sync::atomic::Ordering::Acquire) != 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }
    DONE.add(1, core::sync::atomic::Ordering::Release);
    // SAFETY: this runs as a kernel thread dispatched by `run_this_cpu` on
    // this CPU — the spawner's obligation, above — so that CPU's scheduler is
    // published and is the one this leaves.
    unsafe { crate::secondary::exit_here::<C>() };
    // `exit_current` switches away and never comes back to this thread.
    loop {
        core::hint::spin_loop();
    }
}

/// Spins the boot CPU allows the pair before giving up on them.
///
/// **Sized for the failing run, not the passing one.** A passing run reaches
/// `interleaved()` within a tick or two and never spends this; a failing run
/// spends all of it, and the tree's arrival bound — two hundred million — costs
/// more than a whole boot under QEMU/TCG, which turns a check that should
/// report into one that times out. Two million is comfortably more than the
/// tick period this waits on and cheap enough that the inversion finishes.
pub const WAIT_SPINS: u64 = 2_000_000;

/// Tells both workers to stop waiting for each other.
///
/// Called by the boot CPU once its own bounded wait has expired — see
/// [`GIVE_UP`].
pub fn give_up() {
    GIVE_UP.store(1, core::sync::atomic::Ordering::Release);
}

/// How many workers have finished and left their run queue.
pub fn finished() -> u64 {
    DONE.get(core::sync::atomic::Ordering::Acquire)
}

/// Whether both workers ran and each saw the other still going.
pub fn interleaved() -> bool {
    (0..WORKERS).all(|i| {
        SPUN[i].get(core::sync::atomic::Ordering::Acquire) != 0
            && SAW_PEER[i].load(core::sync::atomic::Ordering::Acquire) != 0
    })
}

/// How many of the workers observed their peer.
pub fn observers() -> usize {
    (0..WORKERS)
        .filter(|&i| SAW_PEER[i].load(core::sync::atomic::Ordering::Acquire) != 0)
        .count()
}

/// Emits the boot line for the preemption check, returning the claim keys.
///
/// Withheld rather than failed on a machine with no secondary: a uniprocessor
/// has no CPU to run the pair on, and a claim earned vacuously is worse than
/// one absent.
pub fn report_secondary_preempted(handed: bool) -> &'static [&'static str] {
    if !handed {
        return &[];
    }
    let ran = (0..WORKERS)
        .filter(|&i| SPUN[i].get(core::sync::atomic::Ordering::Acquire) != 0)
        .count();
    crate::kprintln!(
        "sched: {}/{} preemption worker(s) ran, {}/{} saw the other still running \
         ({} tick(s) preempted, {} deferred)",
        ran,
        WORKERS,
        observers(),
        WORKERS,
        taken(),
        deferred()
    );
    if interleaved() {
        &["smp.secondary-preempted"]
    } else {
        &[]
    }
}

/// Forgets everything recorded. Tests only — these are process-wide.
#[cfg(test)]
pub fn forget() {
    TAKEN.take();
    DEFERRED.take();
}

#[cfg(test)]
#[path = "tests/preempt.rs"]
mod tests;
