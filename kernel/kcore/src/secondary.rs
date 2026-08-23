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

/// Threads the boot CPU built for another CPU to run.
///
/// The boot CPU owns the address space and the frame allocator, so it is the
/// only CPU that can build a thread at all this milestone. Handing them over is
/// therefore the shape every secondary's threads have to take.
///
/// **More than one per CPU, since build/README.md D244.** It carried exactly
/// one, which is all a CPU with a single worker needs — and the scaling
/// benchmark needs a *pair* on each CPU, a client and the server it calls, so
/// that what is replicated is a whole independent instance rather than half of
/// one. A queue rather than a second slot, because "two" would be the same
/// assumption one line further out.
///
/// One producer, one consumer, and two counts between them: a thread is
/// written into its slot first and the *given* count raised second, so a
/// consumer that sees the count sees the thread. The consumer keeps its own
/// count and never writes the producer's. No compare-and-swap, for the reason
/// `crate::wakeup` gives — the core's 64-bit atomic does not offer one,
/// because on a 32-bit target it cannot.
pub struct Handoff<C: ContextOps> {
    threads: [[UnsafeCell<Option<Thread<C>>>; PER_CPU]; MAX_CPUS],
    /// Threads the boot CPU has left for each CPU.
    given: [AtomicU64; MAX_CPUS],
    /// Threads each CPU has taken. Written only by that CPU.
    taken: [AtomicU64; MAX_CPUS],
}

/// Threads the handoff holds for one CPU at a time.
///
/// Two: a scaling instance is a client and its server, and nothing has wanted
/// more. It is a ring, so a CPU that takes its threads as it goes can be given
/// further ones later without the bound growing.
pub const PER_CPU: usize = 2;

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
            threads: [const { [const { UnsafeCell::new(None) }; PER_CPU] }; MAX_CPUS],
            given: [const { AtomicU64::new(0) }; MAX_CPUS],
            taken: [const { AtomicU64::new(0) }; MAX_CPUS],
        }
    }

    /// Leaves `thread` for the CPU at `index`.
    ///
    /// Returns `false` for a CPU that does not exist, or when that CPU already
    /// has [`PER_CPU`] threads outstanding — refused rather than overwriting
    /// one it has not taken yet, because a thread quietly replaced is a thread
    /// whose stack is still mapped and whose entry point never runs.
    ///
    /// # Safety
    ///
    /// Called on the boot CPU, and by nobody else.
    pub unsafe fn give(&self, index: u32, thread: Thread<C>) -> bool {
        if index >= PerCpu::<u8>::capacity() {
            return false;
        }
        let cpu = index as usize;
        let given = self.given[cpu].load(Ordering::Relaxed);
        if given.saturating_sub(self.taken[cpu].load(Ordering::Acquire)) >= PER_CPU as u64 {
            return false;
        }
        let slot = (given as usize) % PER_CPU;
        // SAFETY: the caller's contract — this is the only writer, the slot is
        // one the consumer has not reached (the bound above), and the reader is
        // gated on the count stored after it.
        unsafe { *self.threads[cpu][slot].get() = Some(thread) };
        // Raise the count last: a reader that sees it sees the thread.
        self.given[cpu].store(given + 1, Ordering::Release);
        true
    }

    /// Takes the next thread left for this CPU, if there is one.
    ///
    /// # Safety
    ///
    /// Called on the CPU that `index` names, and by nobody else.
    pub unsafe fn take(&self, index: u32) -> Option<Thread<C>> {
        if index >= PerCpu::<u8>::capacity() {
            return None;
        }
        let cpu = index as usize;
        let taken = self.taken[cpu].load(Ordering::Relaxed);
        if taken >= self.given[cpu].load(Ordering::Acquire) {
            return None;
        }
        let slot = (taken as usize) % PER_CPU;
        // SAFETY: the count was raised after the thread was written, so this
        // read sees it; and the caller's contract makes this CPU the only
        // reader. The count is raised after the take, so the producer cannot
        // reuse this slot until the value is out.
        let thread = unsafe { (*self.threads[cpu][slot].get()).take() };
        self.taken[cpu].store(taken + 1, Ordering::Release);
        thread
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
        // Everything waiting, not one per pass: a CPU given a pair — a client
        // and the server it calls — would otherwise admit them a whole tick
        // apart.
        // SAFETY: the caller's contract — this is the CPU the slot names.
        while let Some(thread) = unsafe { handoff.take(index) } {
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

/// Preempts the thread running on this secondary, if this is a safe moment.
///
/// **The other half of the ports' tick dispatch.** The boot CPU's tick drives
/// whatever hook the boot installed — a demo scheduler, a counter, whatever the
/// current check wants — and a secondary must not run that: it would drive the
/// boot CPU's run queue from the wrong CPU. So a secondary's tick comes here
/// instead, and here dispatches out of the half its own index names, which is
/// the same half [`run_this_cpu`] runs threads from (build/README.md D236).
///
/// Reached through [`SCHEDULERS`] rather than through the executive, because
/// this is an interrupt path and the pointer is the one thing about this CPU's
/// scheduler that is published for reading. A null slot is a CPU that has not
/// reached its run loop yet — it has no run queue, so there is nothing to
/// preempt and nothing to report.
///
/// Whether it is safe at all is [`crate::preempt`]'s question, and the answer
/// is not always yes; that module says what a deferral costs and why it is
/// counted rather than assumed harmless.
///
/// # Safety
///
/// Called from the timer-interrupt path of a CPU that is not the boot CPU, with
/// `C` the context switch that CPU's executive half was built with.
pub unsafe fn on_tick<C: ContextOps>() {
    let index = crate::percpu::current_index();
    if index == crate::percpu::BOOT_CPU || index >= PerCpu::<u8>::capacity() {
        return;
    }
    let published = SCHEDULERS[index as usize].load(Ordering::Acquire);
    if published.is_null() {
        return;
    }
    crate::preempt::on_tick(|| {
        // SAFETY: as below — this CPU published it and is the only reader.
        let scheduler = unsafe { &mut *published.cast::<Scheduler<C>>() };
        // **Only a thread that is still Running may be taken off the CPU**, and
        // this one line is what makes the prologues of the scheduler's own
        // switching methods safe without masking interrupts across them.
        //
        // Each of `block_current`, `handoff_to` and `exit_current` sets the
        // current thread's state before it touches the run queue. A tick that
        // lands *before* that store finds a Running thread and preempts it,
        // which is harmless — nothing has been mutated yet, and the method
        // resumes from the top of its body when the thread runs again. A tick
        // that lands *after* it finds a thread that is Blocked or Exited and
        // returns here, leaving the queue alone while the method finishes with
        // it. `run` is covered by the same rule from the other side: it
        // dispatches from the run loop, where there is no current thread at
        // all.
        //
        // Masking those methods instead was tried and reverted: it regressed a
        // ring-3 filesystem check under load, for reasons not yet understood,
        // and `switch_to`'s own mask already covers the switch itself.
        let running = scheduler
            .current()
            .and_then(|slot| scheduler.thread_state(slot))
            .is_some_and(|state| state == crate::thread::ThreadState::Running);
        if !running {
            return;
        }
        // The pointer was published by `run_this_cpu` on this CPU, from the
        // executive's half for this index, and that half outlives the kernel.
        // This is the CPU that published it, so no other CPU is reaching it —
        // the same discipline `Executive::scheduler` states, on the interrupt
        // path rather than the thread path, and the masks in `Scheduler` are
        // what keep the two from overlapping on this one.
        scheduler.on_tick();
    });
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
