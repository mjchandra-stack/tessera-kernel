// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A CPU other than the boot CPU, running threads off a run queue of its own.
//!
//! # Where the scheduler lives, and why it matters
//!
//! **On the CPU's own stack.** Not in a static array indexed by CPU, which is
//! what every other per-CPU structure here does — because this one does not
//! have to be. The runner below never returns, so the scheduler's lifetime is
//! the CPU's; nothing else in the kernel needs to reach it; and a local on a
//! stack no other CPU can name is unreachable by construction rather than by
//! convention. `PerCpu`'s borrowing obligation, which the arrival bitmap exists
//! to avoid needing, does not arise at all.
//!
//! What *does* need reaching is the current thread's own scheduler, from the
//! thread — a kernel thread that wants to exit has no `&mut` to anything. So
//! one pointer per CPU is published, written by that CPU and dereferenced only
//! by it. That is the whole of the shared surface, and it is one word.
//!
//! # What this is not
//!
//! It is not the executive. A secondary here runs kernel threads and nothing
//! else: no channels, no ports, no page faults, no syscalls. Those live in
//! machine-wide tables that two CPUs would have to take turns over, and the
//! turn-taking is the next step rather than this one
//! (`../roadmap/02-smp-bring-up-plan.md`, Phase 3). Keeping the first CPU to
//! run scheduled work away from all of it is what makes this increment one
//! thing instead of two.
//!
//! Normative: docs/kernel/08-multicore-scalability.md,
//! docs/roadmap/02-smp-bring-up-plan.md ("Phase 3")
//! Budget: none (boot path; the run loop is the idle loop)

use crate::atomic::AtomicU64;
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

/// One pointer per CPU to that CPU's own scheduler, so a thread can reach the
/// scheduler running it.
///
/// Written by the CPU it belongs to and dereferenced only by that CPU, which is
/// the whole of why a raw pointer into a stack frame is sound here: the frame
/// belongs to a function that never returns, and no other CPU can name the
/// slot's contents.
static SCHEDULERS: [AtomicPtr<()>; MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];

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
    // points at a live scheduler in a frame that outlives every thread it
    // dispatched. The caller's contract makes this CPU the only dereferencer,
    // and a dispatched thread is not concurrent with the frame's own use of it
    // — the frame is suspended inside `run` while this thread runs.
    let scheduler = unsafe { &mut *raw.cast::<Scheduler<C>>() };
    scheduler.exit_current();
}

/// Runs this CPU's own scheduler: takes the thread left for it, runs until
/// nothing is runnable, then idles on wakeups.
///
/// Never returns. The CPU is marked online before the first dispatch, because
/// from that instant it is a CPU this kernel runs work on — which is the whole
/// of what `smp.single` used to deny.
///
/// # Safety
///
/// Called on the CPU that `index` names, once, after that CPU has its own
/// descriptor tables, interrupt-controller interface and tick, with interrupts
/// enabled.
pub unsafe fn run_this_cpu<C: ContextOps, P: CpuOps>(
    index: u32,
    handoff: &Handoff<C>,
    quantum: u32,
) -> ! {
    let mut scheduler = Scheduler::<C>::new(quantum, 0);
    if index < PerCpu::<u8>::capacity() {
        SCHEDULERS[index as usize].store((&raw mut scheduler).cast::<()>(), Ordering::Release);
    }

    crate::smp::mark_online(index);

    loop {
        // **The handoff is checked every time round, not once.** This CPU
        // reaches here as soon as it has a tick, which is before the boot CPU
        // has an address space quiet enough to build a thread in — so a
        // one-shot read would find nothing and this CPU would idle for ever
        // with work waiting for it. Its own tick is what brings it back to
        // look.
        // SAFETY: the caller's contract — this is the CPU the slot names.
        if let Some(thread) = unsafe { handoff.take(index) } {
            let _ = scheduler.add_thread(thread);
        }
        // Anything another CPU asked to be made runnable here, before asking
        // the queue what is runnable. The order is the point: a wakeup posted
        // while this CPU was running is taken before it decides it has nothing
        // to do.
        crate::wakeup::drain(index, |slot| scheduler.unblock(slot));
        scheduler.run();
        P::halt_until_interrupt();
    }
}
