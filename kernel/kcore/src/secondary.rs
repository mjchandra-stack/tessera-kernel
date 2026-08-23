// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A CPU other than the boot CPU, running threads off a run queue of its own.
//!
//! # Where the scheduler lives, and why it moved
//!
//! **In the executive, in the half this CPU's index names.** It used to be a
//! local on this CPU's own stack (build/README.md D225), which was defensible
//! while a secondary ran kernel threads and nothing else: the runner never
//! returns, so the scheduler's lifetime was the CPU's, and a local on a stack
//! no other CPU can name is unreachable by construction rather than by
//! convention.
//!
//! What that arrangement could not survive is the executive. `Executive::call`
//! asks *this CPU's* scheduler who is running and who to block, and it finds
//! that through `Executive::cpu` — so a secondary doing IPC out of a scheduler
//! the executive has never heard of would block a thread in one run queue and
//! look for it in another. There is no way to hold the two in step; they have
//! to be the same object. `Executive` has held one `CpuLocal` per CPU since
//! D233 for exactly this, and this is the CPU that asks for its own.
//!
//! The trade is real and worth naming: the scheduler is reachable by index
//! now, so "no other CPU can name it" has become a convention — `cpu_at` will
//! hand any index to anyone who asks — where it used to be a fact about
//! addresses. What the convention buys is that the arrangement can be checked
//! at all, which the stack-local one could not be: see [`SCHEDULERS`].
//!
//! One pointer per CPU is still published, because a kernel thread that wants
//! to exit holds no `&mut` to what dispatched it. It now points into a static
//! rather than into a stack frame, which makes the same dereference sounder
//! than it was.
//!
//! # What this is and is not
//!
//! A secondary reaches the executive: `claim exec.multi-cpu` says so, and it
//! is the inversion of `exec.one-cpu`, which said the opposite and was true
//! until this. What a secondary still does not do is *use* the machine-wide
//! half — no channels, no ports, no page faults, no syscalls — so nothing here
//! contends `crate::machine_lock` yet. The cross-core channel call is what
//! will (`../roadmap/02-smp-bring-up-plan.md`, Phase 3).
//!
//! Normative: docs/kernel/08-multicore-scalability.md,
//! docs/roadmap/02-smp-bring-up-plan.md ("Phase 3")
//! Budget: none (boot path; the run loop is the idle loop)

use crate::atomic::AtomicU64;
use crate::exec::Executive;
use crate::percpu::{MAX_CPUS, PerCpu};
use crate::sched::Scheduler;
use crate::thread::Thread;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, Ordering};
use tessera_karch::{ContextOps, CpuOps};

/// A thread the boot CPU built for another CPU to run.
///
/// The boot CPU owns the address space and the frame allocator, so it is the
/// only CPU that can build a thread at all this milestone. Handing one over is
/// therefore the shape every secondary's first thread has to take.
///
/// One producer, one consumer, and a flag between them: the thread is written
/// first and the flag second, so a consumer that sees the flag sees the thread.
/// No compare-and-swap, for the reason `crate::wakeup` gives — the core's
/// 64-bit atomic does not offer one, because on a 32-bit target it cannot.
pub struct Handoff<C: ContextOps> {
    threads: [UnsafeCell<Option<Thread<C>>>; MAX_CPUS],
    filled: [AtomicU64; MAX_CPUS],
}

// SAFETY: a slot is written by the boot CPU before the target CPU is released
// and read by the target CPU alone, with the flag ordering the two. Both
// obligations are on the `unsafe` functions below.
unsafe impl<C: ContextOps + Send> Sync for Handoff<C> {}

impl<C: ContextOps> Default for Handoff<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: ContextOps> Handoff<C> {
    pub const fn new() -> Self {
        Self {
            threads: [const { UnsafeCell::new(None) }; MAX_CPUS],
            filled: [const { AtomicU64::new(0) }; MAX_CPUS],
        }
    }

    /// Leaves `thread` for the CPU at `index`.
    ///
    /// # Safety
    ///
    /// Called on the boot CPU, at most once per index, and the target CPU must
    /// not yet have taken anything from that slot.
    pub unsafe fn give(&self, index: u32, thread: Thread<C>) -> bool {
        if index >= PerCpu::<u8>::capacity() {
            return false;
        }
        // SAFETY: the caller's contract — this is the only writer, and the
        // reader is gated on the flag stored after it.
        unsafe { *self.threads[index as usize].get() = Some(thread) };
        // Store the flag last: a reader that sees it sees the thread.
        self.filled[index as usize].store(1, Ordering::Release);
        true
    }

    /// Takes whatever was left for this CPU.
    ///
    /// # Safety
    ///
    /// Called on the CPU that `index` names, and by nobody else.
    pub unsafe fn take(&self, index: u32) -> Option<Thread<C>> {
        if index >= PerCpu::<u8>::capacity()
            || self.filled[index as usize].load(Ordering::Acquire) == 0
        {
            return None;
        }
        self.filled[index as usize].store(0, Ordering::Relaxed);
        // SAFETY: the flag was stored after the thread, so this read sees it;
        // and the caller's contract makes this CPU the only reader.
        unsafe { (*self.threads[index as usize].get()).take() }
    }
}

/// One pointer per CPU to the scheduler that CPU dispatches out of, so a
/// thread can reach the scheduler running it.
///
/// Written by the CPU it belongs to and dereferenced only by that CPU. It
/// points into the executive's static now rather than into a stack frame,
/// which is a strictly weaker obligation than the one D225 had to carry.
///
/// **It is also the check.** What a secondary publishes here is whatever
/// `Executive::scheduler` handed *it* — that CPU's own half, selected by its
/// own index — and the boot CPU compares that against the half it believes
/// belongs to that index. Two different mistakes fail the comparison: a
/// secondary running out of a scheduler of its own publishes a stack address,
/// and an `Executive::cpu` that ignored its index would publish the boot CPU's
/// half from every CPU. Neither is visible in any other observable the boot
/// has, because a thread that runs prints the same counter either way.
static SCHEDULERS: [AtomicPtr<()>; MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];

/// Context switches each CPU's half of the executive has performed, published
/// by that CPU.
///
/// Published rather than read out of the executive directly: a scheduler's
/// switch count is a plain `u64`, so the boot CPU reaching into a running
/// CPU's half for it would be reading a field that CPU is writing — a data
/// race however stable the value looks. Only the *address* of that half is
/// read from the executive, and an address does not change. This is the same
/// shape a secondary's work counter already takes, for the same reason.
static EXEC_SWITCHES: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Ends the calling kernel thread, on whichever CPU it is running on.
///
/// This is the one thing a kernel thread cannot do for itself without help: it
/// holds no reference to the scheduler that dispatched it. Returns only if
/// there is no scheduler published for this CPU, which cannot happen for a
/// thread that a scheduler dispatched.
///
/// # Safety
///
/// Called from a kernel thread dispatched by [`run_this_cpu`] on this CPU, and
/// never from the boot context or an interrupt.
pub unsafe fn exit_here<C: ContextOps>() {
    let index = crate::percpu::current_index();
    if index >= PerCpu::<u8>::capacity() {
        return;
    }
    let raw = SCHEDULERS[index as usize].load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: the pointer was published by this CPU, in `run_this_cpu`, and
    // points at this CPU's half of the executive — a `static`, so it outlives
    // every thread dispatched out of it. The caller's contract makes this CPU
    // the only dereferencer, and a dispatched thread is not concurrent with the
    // runner's own use of it: the runner is suspended inside `run` while this
    // thread runs.
    let scheduler = unsafe { &mut *raw.cast::<Scheduler<C>>() };
    scheduler.exit_current();
}

/// Runs this CPU's half of the executive: takes the thread left for it, runs
/// until nothing is runnable, then idles on wakeups.
///
/// Never returns. The CPU is marked online before the first dispatch, because
/// from that instant it is a CPU this kernel runs work on — which is the whole
/// of what `smp.single` used to deny.
///
/// `exec` is the machine's one executive, built by the boot CPU before any
/// other CPU was started, so a CPU that reaches here has one to be given. It is
/// a shared reference and not an exclusive one on purpose: the boot CPU holds
/// its own for the whole boot, and what makes both sound is that each reaches a
/// different half (`Executive::cpu`) and the shared half is taken under
/// `crate::machine_lock`.
///
/// # Safety
///
/// Called on the CPU that `index` names, once, after that CPU has its own
/// descriptor tables, interrupt-controller interface and tick, with interrupts
/// enabled.
pub unsafe fn run_this_cpu<C: ContextOps, P: CpuOps>(
    index: u32,
    handoff: &Handoff<C>,
    exec: &Executive<C>,
    quantum: u32,
) -> ! {
    // Records this CPU against the executive, which is what the ports' own
    // accessors do for the boot CPU. Without it a secondary could dispatch out
    // of the executive all boot and `claim exec.multi-cpu` would still report
    // one — the count would be measuring who owns an accessor rather than who
    // reached the tables.
    crate::exec::occupancy::note_visit();

    // This CPU's half, at the quantum a secondary runs at — and **only** its
    // own half. `Executive::restart` would have been the obvious call and is
    // the wrong one: it clears the machine tables too, which belong to the
    // machine and are in use by the boot CPU at the moment this runs.
    exec.adopt_cpu(quantum, 0);
    if index < PerCpu::<u8>::capacity() {
        // `scheduler()` and not `scheduler_at(index)`: what is published has to
        // be the half this CPU actually reaches, or the comparison the boot CPU
        // makes is between two expressions that cannot disagree.
        SCHEDULERS[index as usize].store(
            (exec.scheduler() as *mut Scheduler<C>).cast::<()>(),
            Ordering::Release,
        );
    }

    crate::smp::mark_online(index);
    // Into the reclamation scheme as of now, not as of boot: a CPU that starts
    // late and reports the epoch it has "seen" as zero would make every grace
    // period since boot look unfinished.
    crate::epoch::attach(index);

    loop {
        // **An idle CPU is quiescent by construction**, which is why this is
        // the natural place for it: nothing is in hand here, so the declaration
        // costs one store and is always true. A CPU that never reached a point
        // like this would stall reclamation for every writer on the machine.
        crate::epoch::quiesce();

        // Re-borrowed each pass rather than held across the loop, which is the
        // executive's own discipline (`kcore::exec`): what a CPU has is the
        // right to reach its half, not a reference it keeps.
        let scheduler = exec.scheduler();

        // **The handoff is checked every time round, not once.** This CPU
        // reaches here as soon as it has a tick, which is before the boot CPU
        // has an address space quiet enough to build a thread in — so a
        // one-shot read would find nothing and this CPU would idle for ever
        // with work waiting for it. Its own tick is what brings it back to
        // look.
        //
        // SAFETY: the caller's contract — this is the CPU the slot names.
        if let Some(thread) = unsafe { handoff.take(index) } {
            let _ = scheduler.add_thread(thread);
        }
        // Anything another CPU asked to be made runnable here, before asking
        // the queue what is runnable. The order is the point: a wakeup posted
        // while this CPU was running is taken before it decides it has nothing
        // to do.
        // Identity-checked: a wakeup carries the slot it was posted for *and*
        // the thread it was posted for, and by the time it is taken that slot
        // may hold a different thread. `unblock_thread` refuses the mismatch,
        // which is `index_of`'s refusal arriving from the other direction.
        crate::wakeup::drain(index, |slot, id| {
            scheduler.unblock_thread(slot, id);
        });
        scheduler.run();
        if index < PerCpu::<u8>::capacity() {
            EXEC_SWITCHES[index as usize].store(scheduler.switch_count(), Ordering::Release);
        }
        P::halt_until_interrupt();
    }
}

/// What the boot CPU can see of the other CPUs' halves of the executive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExecutiveRun {
    /// CPUs other than the boot CPU that reached [`run_this_cpu`].
    pub cpus: usize,
    /// Of those, how many dispatched out of the half the executive keeps for
    /// their index.
    pub matched: usize,
    /// Context switches those halves performed between them.
    pub switches: u64,
}

/// Asks each started CPU which scheduler it dispatched out of, and compares it
/// against the half the executive keeps for that CPU.
pub fn dispatched_from_executive<C: ContextOps>(exec: &Executive<C>) -> ExecutiveRun {
    let mut run = ExecutiveRun {
        cpus: 0,
        matched: 0,
        switches: 0,
    };
    for index in 0..PerCpu::<u8>::capacity() {
        if index == crate::percpu::BOOT_CPU {
            continue;
        }
        let published = SCHEDULERS[index as usize].load(Ordering::Acquire);
        if published.is_null() {
            continue;
        }
        run.cpus += 1;
        run.switches += EXEC_SWITCHES[index as usize].load(Ordering::Acquire);
        if core::ptr::eq(
            published,
            (exec.scheduler_at(index) as *mut Scheduler<C>).cast::<()>(),
        ) {
            run.matched += 1;
        }
    }
    run
}

/// Prints the boot line for what the other CPUs' halves did, and returns the
/// claim keys.
pub fn report_executive_run(run: ExecutiveRun) -> &'static [&'static str] {
    if run.cpus == 0 {
        return &[];
    }
    crate::kprintln!(
        "exec: {}/{} other CPU(s) dispatched out of their own half, {} switch(es)",
        run.matched,
        run.cpus,
        run.switches
    );
    // Every one of them, not merely one: a CPU that reached the runner and
    // dispatched out of somewhere else is the bug this exists to find, and a
    // check satisfied by its neighbour would not find it.
    if run.matched == run.cpus {
        &["exec.second-cpu-scheduled"]
    } else {
        &[]
    }
}
