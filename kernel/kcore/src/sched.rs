// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A per-CPU, preemptive round-robin scheduler. The run queue, the current
//! thread, and the tick/quantum state all live in this one structure — one
//! per CPU — so no lock guards a scheduling decision and its contention
//! cannot grow with core count (docs/kernel/08-multicore-scalability.md,
//! "Scheduler Structure": run queues are per core). **Adding cores added
//! instances rather than a lock**, which is what that shape was for: every CPU
//! the machine has now runs threads off one of these, and no two schedulers
//! share a field (build/README.md, D225).
//!
//! The *selection* logic — run-queue order, quantum expiry, tick-limit
//! termination — is pure and host-tested against `tessera-karch-mock` (whose
//! `switch` records the call and returns). The actual register/stack swap is
//! the architecture `ContextOps::switch`, exercised on target by the boot
//! smoke test.
//!
//! Concurrency discipline (single lock-free per-CPU structure): the scheduler
//! is touched only from the timer interrupt (interrupt gates run with IF
//! clear, so ticks never nest) and from boot setup with interrupts disabled.
//! A dedicated `hlt` idle thread is selected when the run queue is empty; it
//! becomes load-bearing once threads can block, which is a later milestone —
//! until then the always-runnable workers keep the queue non-empty, and the
//! empty-queue path is covered by unit tests.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Scheduling"),
//! docs/kernel/08-multicore-scalability.md ("Scheduler Structure")
//! Budget: B7 (context switch) via `ContextOps::switch`; unmeasured until the
//! perf rig lands (build/README.md, deviation D9)

use crate::thread::{Thread, ThreadId, ThreadState};
use crate::trace::TraceContext;
use tessera_karch::{ContextOps, KError};

/// Maximum threads a single CPU's scheduler tracks this milestone.
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_THREADS;

/// Enqueues the ring refused because it was full — see [`Scheduler::enqueue`].
///
/// Machine-wide rather than per scheduler, because what a reader wants to know
/// is whether it happened at all, and a per-CPU number that is zero everywhere
/// is the same answer said `MAX_CPUS` times.
static REFUSED_ENQUEUES: crate::counter::Sharded = crate::counter::Sharded::new();

/// How many times a run queue refused a thread that should have been runnable.
///
/// Zero on every run so far, and the point of reading it is that "so far" is a
/// measurement rather than an assumption.
pub fn refused_enqueues() -> u64 {
    REFUSED_ENQUEUES.total()
}

/// A per-CPU ready queue: a fixed-capacity ring of thread-table indices in
/// round-robin order. Pure and fully host-tested.
pub struct RunQueue {
    slots: [usize; MAX_THREADS],
    head: usize,
    len: usize,
}

impl RunQueue {
    pub const fn new() -> Self {
        Self {
            slots: [0; MAX_THREADS],
            head: 0,
            len: 0,
        }
    }

    /// Appends `idx` to the back of the queue; `false` if the queue is full.
    pub fn push(&mut self, idx: usize) -> bool {
        if self.len >= MAX_THREADS {
            return false;
        }
        let tail = (self.head + self.len) % MAX_THREADS;
        self.slots[tail] = idx;
        self.len += 1;
        true
    }

    /// Removes and returns the front index, or `None` if empty.
    pub fn pop(&mut self) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let idx = self.slots[self.head];
        self.head = (self.head + 1) % MAX_THREADS;
        self.len -= 1;
        Some(idx)
    }

    /// Removes every occurrence of `idx`, preserving the order of the rest;
    /// returns whether any were removed. Used when a thread is reaped so its
    /// (now-freed) table index can never be popped and dispatched
    /// (`context_ptr` would panic on the empty slot).
    pub fn remove(&mut self, idx: usize) -> bool {
        let mut kept = [0usize; MAX_THREADS];
        let mut n = 0;
        let mut removed = false;
        for i in 0..self.len {
            let v = self.slots[(self.head + i) % MAX_THREADS];
            if v == idx {
                removed = true;
            } else {
                kept[n] = v;
                n += 1;
            }
        }
        self.slots[..n].copy_from_slice(&kept[..n]);
        self.head = 0;
        self.len = n;
        removed
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A per-CPU preemptive round-robin scheduler over a fixed thread table.
pub struct Scheduler<C: ContextOps> {
    threads: [Option<Thread<C>>; MAX_THREADS],
    ready: RunQueue,
    /// Table index of the running thread, or `None` while the boot/entry
    /// context (the caller of [`run`](Scheduler::run)) is current.
    current: Option<usize>,
    /// Saved boot/entry context — where `run` returns to when the tick limit
    /// is reached.
    boot: C::Context,
    /// Ticks remaining in the current thread's quantum.
    quantum: u32,
    quantum_reset: u32,
    ticks: u64,
    /// Stop after this many ticks (0 = run indefinitely) by switching back to
    /// the boot context, so a CI run terminates.
    tick_limit: u64,
    switches: u64,
    /// The next sequence this CPU will mint a [`ThreadId`] from. Starts at one
    /// so that zero stays [`ThreadId::UNASSIGNED`].
    next_thread_id: u64,
}

impl<C: ContextOps> Scheduler<C> {
    /// A scheduler giving each thread a `quantum`-tick slice, optionally
    /// stopping after `tick_limit` ticks (0 = never).
    pub fn new(quantum: u32, tick_limit: u64) -> Self {
        Self {
            threads: [const { None }; MAX_THREADS],
            next_thread_id: 1,
            ready: RunQueue::new(),
            current: None,
            boot: C::empty(),
            quantum: quantum.max(1),
            quantum_reset: quantum.max(1),
            ticks: 0,
            tick_limit,
            switches: 0,
        }
    }

    /// Adds a `Ready` thread to the table and the back of the run queue,
    /// returning its table index, or [`KError::OutOfMemory`] if the fixed
    /// table or run queue is full.
    /// Spawning is a fan-out: the new thread gets a **fresh** id rather than
    /// sharing its parent's, and a link event names the parent, so a trace forms
    /// a tree "that can be joined without ambiguity about which branch an event
    /// belongs to" (docs/observability/02, "Fan-out links, not shared IDs").
    /// Mints the next identity for a thread this CPU is admitting.
    ///
    /// The CPU index goes in the high bits and this scheduler's own sequence in
    /// the low ones, so no two CPUs can mint the same value and neither has to
    /// ask the other. Exhausting the sequence is refused rather than wrapped:
    /// wrapping would eventually produce zero, and zero means "no scheduler has
    /// this thread" — an identifier that silently starts meaning its own
    /// negation is the failure this bound exists to prevent.
    fn mint_thread_id(&mut self) -> Result<ThreadId, KError> {
        let sequence = self.next_thread_id;
        if sequence >> ThreadId::CPU_SHIFT != 0 {
            return Err(KError::LimitExceeded);
        }
        self.next_thread_id += 1;
        let cpu = u64::from(crate::percpu::current_index());
        Ok(ThreadId((cpu << ThreadId::CPU_SHIFT) | sequence))
    }

    pub fn add_thread(&mut self, mut thread: Thread<C>) -> Result<usize, KError> {
        let idx = self.free_slot().ok_or(KError::OutOfMemory)?;
        thread.set_id(self.mint_thread_id()?);
        thread.set_state(ThreadState::Ready);
        let child = crate::trace::mint();
        thread.set_correlation(child);
        self.threads[idx] = Some(thread);
        if !self.ready.push(idx) {
            self.threads[idx] = None;
            return Err(KError::OutOfMemory);
        }
        // The parent is whoever is running (the boot context contributes 0, the
        // root of the tree). Emitted with the *child's* id in the envelope and
        // the parent's in the payload, so the edge is unambiguous.
        let parent = self
            .current
            .and_then(|cur| self.thread_correlation(cur))
            .unwrap_or(0);
        let restore = crate::trace::current();
        crate::trace::set_current_correlation(child);
        crate::event::emit(
            crate::event::EventKind::CorrelationLink,
            crate::event::Severity::Debug,
            crate::event::Component::Scheduler,
            [parent, idx as u64, 0, 0],
        );
        crate::trace::set_current(restore);
        Ok(idx)
    }

    /// Starts scheduling: saves the boot context and switches to the first
    /// ready thread. Returns when the tick limit switches back to boot (or
    /// immediately if nothing is ready).
    pub fn run(&mut self) {
        let Some(first) = self.pop_ready() else {
            return;
        };
        self.quantum = self.quantum_reset;
        self.switch_to(Some(first));
    }

    /// Blocks the current thread and switches to the next ready thread (or the
    /// boot context if none). The current thread is not requeued — it resumes
    /// only when [`unblock`](Self::unblock)ed and later scheduled, or when a
    /// [`handoff_to`](Self::handoff_to) targets it. This is how a `receive` with
    /// no message, or a `call` awaiting its reply, parks a thread.
    pub fn block_current(&mut self) {
        // The machine tables must not be held across this. The check is here,
        // at the moment the thread actually leaves the CPU, rather than in the
        // executive: a park routed through `machine_lock::park` releases them,
        // and one that was not still compiles — so a facility that only
        // counted the parks it was told about would report zero for exactly
        // the bug it exists to find.
        crate::machine_lock::assert_released();
        if let Some(cur) = self.current
            && let Some(thread) = self.threads[cur].as_mut()
        {
            thread.set_state(ThreadState::Blocked);
        }
        let next = self.pop_ready();
        self.switch_to(next);
    }

    /// Marks the current thread `Blocked` and switches *directly* to `target`,
    /// bypassing the ready queue — the synchronous handoff (caller→callee, and
    /// callee→caller on reply). `target` may itself be blocked; it is made
    /// `Running`. Exactly one context switch, no run-queue traffic — the
    /// mechanism budget B3 depends on (docs/architecture/03; docs/prototypes/01).
    pub fn handoff_to(&mut self, target: usize) {
        // The machine tables must not be held across this. The check is here,
        // at the moment the thread actually leaves the CPU, rather than in the
        // executive: a park routed through `machine_lock::park` releases them,
        // and one that was not still compiles — so a facility that only
        // counted the parks it was told about would report zero for exactly
        // the bug it exists to find.
        crate::machine_lock::assert_released();
        if let Some(cur) = self.current
            && let Some(thread) = self.threads[cur].as_mut()
        {
            thread.set_state(ThreadState::Blocked);
        }
        self.switch_to(Some(target));
    }

    /// Switches back to the boot/entry context, ending the run (the caller of
    /// [`run`](Self::run) resumes). The current thread's context is saved but it
    /// is left as-is; used by a cooperative demo to hand control back to boot.
    pub fn yield_to_boot(&mut self) {
        self.switch_to(None);
    }

    /// Puts `idx` on the ready ring, and says whether it went.
    ///
    /// **The one place a thread is enqueued, because a refusal here is
    /// invisible everywhere else.** Both callers mark the thread `Ready`
    /// before asking, so a dropped enqueue leaves a runnable thread on no
    /// queue: it never runs again, nothing faults, and every structure that
    /// names it still reports it as fine. Both used to discard this answer.
    ///
    /// The refusal should be unreachable — the ring holds [`MAX_THREADS`]
    /// entries and the table holds [`MAX_THREADS`] threads, so it can only
    /// fill if some thread is on it twice — which is exactly why it is
    /// counted and emitted rather than trusted (docs/lifecycle/04, "No Silent
    /// Fallback"): an invariant nothing checks is an invariant nobody learns
    /// has broken.
    fn enqueue(&mut self, idx: usize) -> bool {
        if self.ready.push(idx) {
            return true;
        }
        REFUSED_ENQUEUES.bump();
        crate::event::emit(
            crate::event::EventKind::RunQueueFull,
            crate::event::Severity::Error,
            crate::event::Component::Scheduler,
            [
                idx as u64,
                self.ready.len() as u64,
                u64::from(crate::percpu::current_index()),
                0,
            ],
        );
        false
    }

    /// Marks a **blocked** thread `Ready` and enqueues it, without switching.
    /// The caller decides whether to also hand off to it.
    ///
    /// # Why it refuses a thread that is not blocked
    ///
    /// A thread that is already `Ready` is already on the ring, and pushing it
    /// again puts it there twice — which is the only way the ring can overflow,
    /// and which also lets a single thread be dispatched to two contexts. A
    /// thread that is `Running` is on the CPU and belongs on no queue at all.
    /// Neither is a wakeup that should do anything, and both arrive here in
    /// ordinary running: a wakeup that crossed from another CPU can race a
    /// local one, and a server that replies and then wakes its caller can
    /// reach a caller something else already woke.
    ///
    /// So this is idempotent rather than additive, and the ring's "each thread
    /// at most once" is a property of this function rather than of every
    /// caller remembering.
    pub fn unblock(&mut self, idx: usize) {
        if self.thread_state(idx) != Some(ThreadState::Blocked) {
            return;
        }
        if let Some(thread) = self.threads[idx].as_mut() {
            thread.set_state(ThreadState::Ready);
        }
        if !self.enqueue(idx) {
            // Put it back. A lost wakeup is bad; a thread whose state says
            // runnable and whose queue says nothing is worse, because there is
            // no state left from which anything could put it right — every
            // later wakeup would find it `Ready` and decline. Left `Blocked`,
            // it is exactly where it was, and the next wakeup works.
            if let Some(thread) = self.threads[idx].as_mut() {
                thread.set_state(ThreadState::Blocked);
            }
        }
    }

    /// Marks the thread in `idx` `Ready` **only if it is still `id`**, and says
    /// whether it was.
    ///
    /// This is [`index_of`](Self::index_of)'s refusal in the other direction.
    /// A wakeup that crossed from another CPU carries a slot, because a slot is
    /// how a run queue is indexed — and by the time it is taken, that slot may
    /// hold the thread that replaced the one it was posted for. Unblocking on
    /// the slot alone would make a stranger runnable; checking the identity
    /// turns the same staleness into the same `false` that a local lookup
    /// turns it into.
    ///
    /// [`ThreadId::UNASSIGNED`] matches nothing, so a wakeup posted with no
    /// identity to name — the bring-up probe's — moves no thread.
    pub fn unblock_thread(&mut self, idx: usize, id: ThreadId) -> bool {
        if id == ThreadId::UNASSIGNED || self.thread_id(idx) != Some(id) {
            return false;
        }
        self.unblock(idx);
        true
    }

    /// Terminates the **current** thread and switches to the next ready
    /// thread — or back to the boot context only when nothing is runnable.
    /// This is how a thread's exit ends *it* without ending the run: earlier
    /// exit paths did `terminate` + [`yield_to_boot`](Self::yield_to_boot),
    /// which abandons still-ready threads the moment the first one exits —
    /// harmless while every check had one exiting thread, wrong for a
    /// multi-client service run (D82).
    pub fn exit_current(&mut self) {
        if let Some(cur) = self.current
            && let Some(thread) = self.threads[cur].as_mut()
        {
            thread.set_state(ThreadState::Exited);
        }
        let next = self.pop_ready();
        self.switch_to(next);
    }

    /// Terminates thread `idx` — marks it `Exited` so it is never resumed. A
    /// terminated thread left in the ready queue is skipped by [`pop_ready`]
    /// (Self::pop_ready). This is the primitive a job kill uses to stop each
    /// member thread (docs/kernel/05). Terminating a stale index is a no-op.
    pub fn terminate(&mut self, idx: usize) {
        if let Some(thread) = self.threads.get_mut(idx).and_then(Option::as_mut) {
            thread.set_state(ThreadState::Exited);
        }
    }

    /// Reaps a **non-running** thread: removes it from the ready ring and the
    /// thread table, freeing its slot for reuse, and returns it so the caller
    /// can reclaim its kernel stack (docs/kernel/05, deterministic reclaim).
    /// Refuses the current thread — you cannot free the stack you are running
    /// on — returning `None` for it or for a stale/empty index. This completes
    /// [`terminate`](Self::terminate) (which only marks `Exited`) with the slot
    /// removal, once the thread is off-CPU.
    pub fn reap(&mut self, idx: usize) -> Option<Thread<C>> {
        if self.current == Some(idx) {
            return None;
        }
        self.ready.remove(idx);
        self.threads.get_mut(idx).and_then(Option::take)
    }

    /// Pops the next runnable thread from the ready queue, skipping any entry
    /// whose thread is not actually `Ready` — terminated (`Exited`), reaped
    /// (the slot is empty), already `Running`, or `Blocked` again since it was
    /// queued.
    ///
    /// **`Ready` rather than "not `Exited`", because a queue entry is a claim
    /// and the state is the fact.** Everything that enqueues sets `Ready`
    /// first, so an entry naming a thread in any other state is stale: the
    /// thread was handed off to and is on a CPU, or it blocked again before
    /// this entry came up. Dispatching one of those resumes a thread that is
    /// waiting for something — no fault, no message, just a thread running
    /// past the event it was parked on.
    fn pop_ready(&mut self) -> Option<usize> {
        while let Some(idx) = self.ready.pop() {
            if self.thread_state(idx) == Some(ThreadState::Ready) {
                return Some(idx);
            }
        }
        None
    }

    /// The scheduling state of thread `idx`, if it exists.
    pub fn thread_state(&self, idx: usize) -> Option<ThreadState> {
        self.threads
            .get(idx)
            .and_then(Option::as_ref)
            .map(Thread::state)
    }

    /// The effective priority of thread `idx`, if it exists.
    pub fn thread_priority(&self, idx: usize) -> Option<u8> {
        self.threads
            .get(idx)
            .and_then(Option::as_ref)
            .map(Thread::priority)
    }

    /// Sets the effective priority of thread `idx` (used to carry a caller's
    /// priority to a callee for a synchronous call's duration).
    pub fn set_thread_priority(&mut self, idx: usize, priority: u8) {
        if let Some(thread) = self.threads.get_mut(idx).and_then(Option::as_mut) {
            thread.set_priority(priority);
        }
    }

    /// The causal id thread `idx`'s work belongs to, if it exists.
    /// The slot holding the thread with identity `id`, or `None` if this CPU is
    /// not running it — because it exited, or because it was never here.
    ///
    /// **`None` is the point, not an inconvenience.** A slot is reused the
    /// moment its thread is reaped, so machine-wide state that remembered a
    /// slot would go on naming *whatever thread landed in it next* — a stale
    /// reference that silently aliases a live stranger instead of failing. An
    /// identity cannot be reused, so the same staleness resolves to `None` and
    /// the caller has to say what it means.
    pub fn index_of(&self, id: ThreadId) -> Option<usize> {
        if id == ThreadId::UNASSIGNED {
            return None;
        }
        self.threads
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|t| t.id() == id))
    }

    /// The identity of the thread in slot `idx`, or `None` if the slot is empty.
    ///
    /// A slot number is this CPU's own bookkeeping and means nothing to another
    /// CPU; the identity is what machine-wide state should hold. This is the
    /// direction that translation goes today (`docs/roadmap/02-smp-bring-up-plan.md`,
    /// Phase 1d).
    pub fn thread_id(&self, idx: usize) -> Option<ThreadId> {
        self.threads
            .get(idx)
            .and_then(Option::as_ref)
            .map(Thread::id)
    }

    pub fn thread_correlation(&self, idx: usize) -> Option<u64> {
        self.threads
            .get(idx)
            .and_then(Option::as_ref)
            .map(Thread::correlation)
    }

    /// Sets the causal id of thread `idx` (used to carry a caller's id to a
    /// callee for a synchronous call's duration, and to restore it after).
    /// Republishes the ambient context when `idx` is the running thread, so an
    /// event emitted before the next switch is attributed correctly.
    pub fn set_thread_correlation(&mut self, idx: usize, correlation: u64) {
        if let Some(thread) = self.threads.get_mut(idx).and_then(Option::as_mut) {
            thread.set_correlation(correlation);
        }
        if self.current == Some(idx) {
            crate::trace::set_current_correlation(correlation);
        }
    }

    /// The identity the event facility stamps onto records while thread `idx`
    /// runs, or the empty context for the boot context.
    fn trace_context(&self, idx: Option<usize>) -> TraceContext {
        let Some(thread) = idx
            .and_then(|idx| self.threads.get(idx))
            .and_then(Option::as_ref)
        else {
            return TraceContext::NONE;
        };
        TraceContext {
            thread_id: thread.id().0,
            process_id: thread.process().map_or(0, |p| u64::from(p.raw())),
            correlation: thread.correlation(),
        }
    }

    /// Called once per timer tick from the interrupt path. Advances the tick
    /// count, ends the run at the tick limit, and preempts the current thread
    /// round-robin when its quantum expires.
    pub fn on_tick(&mut self) {
        self.ticks += 1;

        if self.tick_limit != 0 && self.ticks >= self.tick_limit {
            self.requeue_current();
            self.switch_to(None);
            return;
        }

        if self.quantum > 1 {
            self.quantum -= 1;
            return;
        }
        self.quantum = self.quantum_reset;

        // Round-robin: run the front of the queue next, current goes to back.
        let Some(next) = self.pick_next() else {
            return; // nobody else ready; keep running current
        };
        self.requeue_current();
        self.switch_to(Some(next));
    }

    /// Chooses the next thread to run (front of the ready queue, skipping
    /// terminated threads), or `None` when the queue is empty (idle). Pure — no
    /// switch happens here.
    fn pick_next(&mut self) -> Option<usize> {
        self.pop_ready()
    }

    /// Puts the current thread back on the ready queue as `Ready` (it was
    /// preempted, not blocked).
    fn requeue_current(&mut self) {
        if let Some(cur) = self.current {
            if let Some(thread) = self.threads[cur].as_mut() {
                thread.set_state(ThreadState::Ready);
            }
            self.enqueue(cur);
        }
    }

    /// Switches from the current context to thread `next` (or the boot
    /// context when `None`), updating bookkeeping first so the post-switch
    /// state is consistent from the resumed side.
    fn switch_to(&mut self, next: Option<usize>) {
        // **Interrupts off for the switch, and this is what lets a tick preempt
        // at all.** A timer tick that lands between the bookkeeping below and
        // the register switch would call back into this function on a CPU
        // already inside it — the reentrancy the `C::switch` call's own safety
        // argument rules out. Masking here is what makes that argument true
        // rather than merely likely, and it is the precondition for
        // `crate::preempt` letting a secondary's tick take a thread off the CPU
        // (build/README.md D246).
        //
        // **Only where a tick can actually re-enter, which is not the boot
        // CPU.** The hook the boot CPU's tick runs drives whichever scheduler
        // the current check installed, never this one, so masking there buys
        // nothing — and it is not free: masking every switch on the boot CPU
        // regressed the AArch64 ring-3 filesystem checks under load, for
        // reasons not yet understood. The mask is for the CPU whose tick calls
        // back into this scheduler, and only a secondary's does.
        //
        // **Restoring is the resumed side's job, and the asymmetry is the
        // point.** `were_enabled` is a local, so it travels with *this* context:
        // whichever thread resumes here restores the state it masked, whenever
        // that is. A thread being started for the first time never reaches the
        // restore, because it arrives at the port's `thread_trampoline` instead
        // — and every port's trampoline already enables interrupts as its first
        // instruction, which is the same fact stated where it belongs.
        let were_enabled = if crate::percpu::current_index() == crate::percpu::BOOT_CPU {
            None
        } else {
            crate::sync::mask_interrupts()
        };
        // **The user-access permission travels with the thread, not the CPU.**
        // A validated copy can fault on a page its pager has not supplied; that
        // fault blocks the copying thread and runs another one, so a bit left
        // set on the CPU would be set while a thread that opened no window
        // runs. This is the one moment a thread stops being the one the
        // register describes, so this is where it is taken off and put on.
        //
        // Cleared between the two, so the window is closed for the whole of the
        // switch itself — the incoming thread's value is established below,
        // after its address space and kernel stack are.
        let outgoing_access = crate::useraccess::get();
        if let Some(cur) = self.current
            && let Some(thread) = self.threads[cur].as_mut()
        {
            thread.set_user_access(outgoing_access);
        }
        crate::useraccess::set(false);
        let prev_ptr: *mut C::Context = match self.current {
            Some(idx) => self.context_ptr(idx),
            None => &raw mut self.boot,
        };
        let next_ptr: *const C::Context = match next {
            Some(idx) => {
                if let Some(thread) = self.threads[idx].as_ref() {
                    let kernel_stack_top = thread.kernel_stack_top();
                    let space_root = thread.space_root();
                    // Program the per-CPU kernel stack (for ring-3 entry) and
                    // switch address space (for a user thread) before the
                    // register switch — the B7 cross-address-space cost.
                    // SAFETY: `kernel_stack_top` tops the resuming thread's kernel
                    // stack; `space_root`, if `Some`, is its live page-table
                    // root, which maps the kernel (built by `new_user`).
                    unsafe { C::prepare_resume(kernel_stack_top, space_root) };
                }
                if let Some(thread) = self.threads[idx].as_mut() {
                    thread.set_state(ThreadState::Running);
                }
                // ...and the incoming thread's window is reopened if it had
                // one. A thread resumed mid-copy resumes able to finish it.
                let resumed_access = self.threads[idx]
                    .as_ref()
                    .is_some_and(crate::thread::Thread::user_access);
                crate::useraccess::set(resumed_access);
                self.context_ptr(idx)
            }
            None => &raw const self.boot,
        };
        // Republish the causal identity events are stamped with. This is the one
        // place `current` changes, so it is the one place the ambient context
        // needs updating (`crate::trace`); a tick landing between here and the
        // switch leaves it briefly describing the outgoing thread, exactly the
        // existing exposure of `self.current`.
        crate::trace::set_current(self.trace_context(next));
        self.current = next;
        self.switches += 1;
        // Compiler fences bracket the switch: another thread of *this*
        // scheduler runs between them and mutates state this one will read
        // (channel queues, reply slots), so the compiler must not cache reads
        // across the switch or move memory accesses past it. This makes the
        // read-after-handoff in the IPC path (exec.rs) see the callee's writes.
        //
        // A compiler fence and not a processor one, and that is still right
        // with more than one CPU running: the two threads either side of this
        // switch are both this scheduler's, and this scheduler belongs to one
        // CPU. What crosses a CPU boundary goes through `kcore::wakeup` or an
        // atomic, and carries its own ordering.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: both pointers reference live `Context` storage owned by this
        // scheduler (a table thread's slot or the boot slot); `next` was
        // produced by `Thread::spawn`/`init` or a prior switch. The scheduler
        // is not reentered across this call: it belongs to the CPU making it,
        // that CPU is inside this function until the switch returns, and
        // interrupts are masked above so no tick can call back in meanwhile.
        unsafe { C::switch(prev_ptr, next_ptr) }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // Back on a CPU, in whichever context saved `were_enabled` — see the
        // masking at the top of this function.
        if let Some(were_enabled) = were_enabled {
            crate::sync::restore_interrupts(were_enabled);
        }
    }

    /// Raw context pointer for table index `idx` (panics on a stale index —
    /// an internal invariant violation, never a runtime input).
    fn context_ptr(&mut self, idx: usize) -> *mut C::Context {
        match self.threads[idx].as_mut() {
            Some(thread) => thread.context_ptr(),
            None => panic!("scheduler: stale thread index {idx}"),
        }
    }

    fn free_slot(&self) -> Option<usize> {
        self.threads.iter().position(Option::is_none)
    }

    /// Total context switches performed.
    pub fn switch_count(&self) -> u64 {
        self.switches
    }

    /// Ticks observed.
    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Table index of the running thread, or `None` for the boot context.
    pub fn current(&self) -> Option<usize> {
        self.current
    }
}

#[cfg(test)]
#[path = "tests/sched.rs"]
mod tests;
