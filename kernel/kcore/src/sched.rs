// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A per-CPU, preemptive round-robin scheduler. The run queue, the current
//! thread, and the tick/quantum state all live in this one structure — one
//! per CPU — so no lock guards a scheduling decision and its contention
//! cannot grow with core count (docs/kernel/08-multicore-scalability.md,
//! "Scheduler Structure": run queues are per core). Single-core this
//! milestone; the structure is already per-CPU so adding cores adds
//! instances, not a global lock.
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

use crate::thread::{Thread, ThreadState};
use crate::trace::TraceContext;
use tessera_karch::{ContextOps, KError};

/// Maximum threads a single CPU's scheduler tracks this milestone.
pub const MAX_THREADS: usize = 16;

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
}

impl<C: ContextOps> Scheduler<C> {
    /// A scheduler giving each thread a `quantum`-tick slice, optionally
    /// stopping after `tick_limit` ticks (0 = never).
    pub fn new(quantum: u32, tick_limit: u64) -> Self {
        Self {
            threads: [const { None }; MAX_THREADS],
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
    pub fn add_thread(&mut self, mut thread: Thread<C>) -> Result<usize, KError> {
        let idx = self.free_slot().ok_or(KError::OutOfMemory)?;
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

    /// Marks a blocked thread `Ready` and enqueues it, without switching. The
    /// caller decides whether to also hand off to it.
    pub fn unblock(&mut self, idx: usize) {
        if let Some(thread) = self.threads[idx].as_mut() {
            thread.set_state(ThreadState::Ready);
        }
        self.ready.push(idx);
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

    /// Pops the next runnable thread from the ready queue, skipping any that
    /// have been terminated (`Exited`) or reaped (the slot is now empty) — a
    /// killed or reaped thread is never dispatched even if its index was queued
    /// before the kill.
    fn pop_ready(&mut self) -> Option<usize> {
        while let Some(idx) = self.ready.pop() {
            if matches!(self.thread_state(idx), Some(s) if s != ThreadState::Exited) {
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
            self.ready.push(cur);
        }
    }

    /// Switches from the current context to thread `next` (or the boot
    /// context when `None`), updating bookkeeping first so the post-switch
    /// state is consistent from the resumed side.
    fn switch_to(&mut self, next: Option<usize>) {
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
        // Compiler fences bracket the switch: single-core, another thread runs
        // between them and mutates shared executive state (channel queues, reply
        // slots), so the compiler must not cache reads across the switch or move
        // memory accesses past it. This makes the read-after-handoff in the IPC
        // path (exec.rs) see the callee's writes.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: both pointers reference live `Context` storage owned by this
        // scheduler (a table thread's slot or the boot slot); `next` was
        // produced by `Thread::spawn`/`init` or a prior switch. On single-core
        // the scheduler is not reentered across this call.
        unsafe { C::switch(prev_ptr, next_ptr) }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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
mod tests {
    use super::*;
    use crate::thread::{Thread, ThreadId, ThreadState};
    use crate::vm::{AddressSpace, Asid};
    use tessera_karch::VirtAddr;
    use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

    extern "C" fn never(_: usize) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    fn make_thread(vm: &mut AddressSpace<MockAddressSpace>, id: u64) -> Thread<MockContextOps> {
        let mut frames = MockFrameSource::new(0x10_0000 + id * 0x10_0000, 64);
        let base = 0xffff_e000_0000_0000 + id * 0x10_0000;
        Thread::<MockContextOps>::spawn(
            ThreadId(id),
            never,
            id as usize,
            VirtAddr::new(base),
            2,
            vm,
            &mut frames,
        )
        .expect("spawn")
    }

    fn vm() -> AddressSpace<MockAddressSpace> {
        let mut frames = MockFrameSource::new(0x1000_0000, 64);
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(0))
            .expect("vm")
    }

    #[test]
    fn switch_invokes_prepare_resume_for_the_target() {
        // Running a thread must program its kernel stack / address space via the
        // arch `prepare_resume` hook before the register switch. The mock's
        // counter is process-global (tests run in parallel), so assert on the
        // delta this scheduler produces rather than an absolute value.
        let mut vm = vm();
        let mut sched = Scheduler::<MockContextOps>::new(4, 0);
        let t = make_thread(&mut vm, 0);
        sched.add_thread(t).expect("add");
        let before = MockContextOps::prepare_resume_count();
        sched.run(); // boot -> thread 0
        assert_eq!(sched.switch_count(), 1, "run switches into the thread");
        assert!(
            MockContextOps::prepare_resume_count() > before,
            "resume hook fires when switching into the thread"
        );
    }

    #[test]
    fn runqueue_is_fifo() {
        let mut q = RunQueue::new();
        assert!(q.is_empty());
        assert!(q.push(3));
        assert!(q.push(1));
        assert!(q.push(2));
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop(), Some(3));
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn runqueue_wraps_and_rejects_when_full() {
        let mut q = RunQueue::new();
        for i in 0..MAX_THREADS {
            assert!(q.push(i));
        }
        assert!(!q.push(99), "full queue rejects");
        // Drain and refill past the wrap point.
        assert_eq!(q.pop(), Some(0));
        assert!(q.push(99));
        for expected in 1..MAX_THREADS {
            assert_eq!(q.pop(), Some(expected));
        }
        assert_eq!(q.pop(), Some(99));
    }

    #[test]
    fn round_robin_rotates_in_order() {
        // The mock switch returns immediately, so after each call the
        // scheduler's `current` reflects the thread it chose to run.
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(1, 0);
        for id in 0..3 {
            let t = make_thread(&mut space, id);
            sched.add_thread(t).expect("add");
        }
        sched.run();
        assert_eq!(sched.current(), Some(0));
        // quantum is 1, so every tick rotates to the next ready thread.
        sched.on_tick();
        assert_eq!(sched.current(), Some(1));
        sched.on_tick();
        assert_eq!(sched.current(), Some(2));
        sched.on_tick();
        assert_eq!(sched.current(), Some(0), "wraps back around");
        assert!(sched.switch_count() >= 4);
    }

    #[test]
    fn a_terminated_thread_is_exited_and_never_dispatched() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(1, 0);
        let mut idx = [0usize; 3];
        for id in 0..3u64 {
            let t = make_thread(&mut space, id);
            idx[id as usize] = sched.add_thread(t).expect("add");
        }
        sched.run();
        assert_eq!(sched.current(), Some(idx[0]));
        // Terminate thread 1 while it sits Ready in the queue.
        sched.terminate(idx[1]);
        assert_eq!(sched.thread_state(idx[1]), Some(ThreadState::Exited));
        // Round-robin must skip the terminated thread: 0 → 2 (not 1) → 0.
        sched.on_tick();
        assert_eq!(sched.current(), Some(idx[2]), "skips the terminated thread");
        sched.on_tick();
        assert_eq!(
            sched.current(),
            Some(idx[0]),
            "wraps past the terminated one"
        );
    }

    #[test]
    fn quantum_holds_current_until_it_expires() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(3, 0);
        for id in 0..2 {
            let t = make_thread(&mut space, id);
            sched.add_thread(t).expect("add");
        }
        sched.run();
        assert_eq!(sched.current(), Some(0));
        // Quantum 3: two ticks decrement without switching...
        sched.on_tick();
        assert_eq!(sched.current(), Some(0));
        sched.on_tick();
        assert_eq!(sched.current(), Some(0));
        // ...the third expires the quantum and rotates.
        sched.on_tick();
        assert_eq!(sched.current(), Some(1));
    }

    #[test]
    fn tick_limit_returns_to_boot() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(1, 3);
        let t = make_thread(&mut space, 0);
        sched.add_thread(t).expect("add");
        sched.run();
        assert_eq!(sched.current(), Some(0));
        sched.on_tick(); // tick 1
        sched.on_tick(); // tick 2
        assert!(sched.current().is_some());
        sched.on_tick(); // tick 3 == limit -> boot
        assert_eq!(sched.current(), None, "returned to boot context");
    }

    #[test]
    fn running_thread_is_marked_running() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(2, 0);
        let t = make_thread(&mut space, 0);
        let idx = sched.add_thread(t).expect("add");
        assert_eq!(sched.thread_state(idx), Some(ThreadState::Ready));
        sched.run();
        assert_eq!(sched.thread_state(idx), Some(ThreadState::Running));
    }

    #[test]
    fn add_thread_fills_table_then_rejects() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(1, 0);
        for id in 0..MAX_THREADS as u64 {
            let t = make_thread(&mut space, id);
            assert!(sched.add_thread(t).is_ok());
        }
        let overflow = make_thread(&mut space, 99);
        assert!(sched.add_thread(overflow).is_err());
    }

    #[test]
    fn block_unblock_and_handoff_state_transitions() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(4, 0);
        let a = {
            let t = make_thread(&mut space, 0);
            sched.add_thread(t).expect("add a")
        };
        let b = {
            let t = make_thread(&mut space, 1);
            sched.add_thread(t).expect("add b")
        };
        sched.run(); // current = a (Running), b Ready
        assert_eq!(sched.current(), Some(a));
        assert_eq!(sched.thread_state(a), Some(ThreadState::Running));

        // Priority carriage: set a's priority onto b.
        sched.set_thread_priority(b, 30);
        assert_eq!(sched.thread_priority(b), Some(30));

        // Handoff a -> b: a Blocked, b Running, exactly one more switch, no
        // run-queue traffic for the target.
        let before = sched.switch_count();
        sched.handoff_to(b);
        assert_eq!(sched.switch_count(), before + 1);
        assert_eq!(sched.current(), Some(b));
        assert_eq!(sched.thread_state(a), Some(ThreadState::Blocked));
        assert_eq!(sched.thread_state(b), Some(ThreadState::Running));

        // Unblock a (Ready, requeued) without switching.
        let before = sched.switch_count();
        sched.unblock(a);
        assert_eq!(sched.switch_count(), before);
        assert_eq!(sched.thread_state(a), Some(ThreadState::Ready));
    }

    #[test]
    fn block_current_switches_to_next_ready() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(4, 0);
        let a = {
            let t = make_thread(&mut space, 0);
            sched.add_thread(t).expect("add a")
        };
        let b = {
            let t = make_thread(&mut space, 1);
            sched.add_thread(t).expect("add b")
        };
        sched.run(); // current = a, b Ready
        sched.block_current(); // a Blocked, switch to b
        assert_eq!(sched.current(), Some(b));
        assert_eq!(sched.thread_state(a), Some(ThreadState::Blocked));
    }

    #[test]
    fn exit_current_runs_the_next_ready_thread_then_boot() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(4, 0);
        let a = {
            let t = make_thread(&mut space, 0);
            sched.add_thread(t).expect("add a")
        };
        let b = {
            let t = make_thread(&mut space, 1);
            sched.add_thread(t).expect("add b")
        };
        sched.run(); // current = a, b Ready
        sched.exit_current(); // a Exited — b must run, not boot
        assert_eq!(sched.current(), Some(b));
        assert_eq!(sched.thread_state(a), Some(ThreadState::Exited));
        sched.exit_current(); // b Exited, nothing ready — back to boot
        assert_eq!(sched.thread_state(b), Some(ThreadState::Exited));
    }

    #[test]
    fn runqueue_remove_compacts_all_occurrences() {
        let mut q = RunQueue::new();
        for v in [3, 1, 3, 2] {
            assert!(q.push(v));
        }
        assert!(q.remove(3), "removed something");
        assert!(!q.remove(9), "nothing to remove");
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop(), Some(1), "order preserved past the removals");
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn reap_frees_slot_and_returns_thread() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(4, 0);
        let a = {
            let t = make_thread(&mut space, 0);
            sched.add_thread(t).expect("add a")
        };
        let b = {
            let t = make_thread(&mut space, 1);
            sched.add_thread(t).expect("add b")
        };
        sched.run(); // current = a; b Ready
        // b is not the running thread, so it can be reaped.
        let reaped = sched.reap(b);
        assert!(
            reaped.is_some(),
            "reap returns the thread for stack reclaim"
        );
        assert_eq!(sched.thread_state(b), None, "slot cleared");
        // The freed slot is reused by the next add.
        let c = {
            let t = make_thread(&mut space, 2);
            sched.add_thread(t).expect("add c")
        };
        assert_eq!(c, b, "first-free slot is the reaped one");
        // a is untouched.
        assert_eq!(sched.thread_state(a), Some(ThreadState::Running));
    }

    #[test]
    fn reap_refuses_the_running_thread() {
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(4, 0);
        let a = {
            let t = make_thread(&mut space, 0);
            sched.add_thread(t).expect("add a")
        };
        sched.run(); // current = a
        assert!(sched.reap(a).is_none(), "cannot reap the running thread");
        assert_eq!(
            sched.thread_state(a),
            Some(ThreadState::Running),
            "still live"
        );
        // A stale/empty index is also a harmless None.
        assert!(sched.reap(15).is_none());
    }

    #[test]
    fn a_reaped_index_is_never_dispatched() {
        // Reaping b (Ready, still queued) must remove its index from the ready
        // ring, so a full rotation only ever runs a and c — never panicking on
        // the emptied slot.
        let mut space = vm();
        let mut sched = Scheduler::<MockContextOps>::new(1, 0);
        let mut idx = [0usize; 3];
        for id in 0..3u64 {
            let t = make_thread(&mut space, id);
            idx[id as usize] = sched.add_thread(t).expect("add");
        }
        sched.run();
        assert_eq!(sched.current(), Some(idx[0]));
        assert!(sched.reap(idx[1]).is_some(), "b reaped (not current)");
        assert_eq!(sched.thread_state(idx[1]), None);
        // Drive a full rotation: 0 → 2 → 0, skipping the reaped slot.
        sched.on_tick();
        assert_eq!(sched.current(), Some(idx[2]), "skips the reaped slot");
        sched.on_tick();
        assert_eq!(
            sched.current(),
            Some(idx[0]),
            "wraps without touching the reaped index"
        );
    }
}
