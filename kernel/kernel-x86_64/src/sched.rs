// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The preemptive scheduler demonstration.
//!
//! CPU-bound workers that never yield voluntarily, preempted round-robin off the
//! timer tick: that all three make progress is what proves the tick switched
//! between them rather than that they cooperated.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- Scheduler demonstration (preemptive) ---
//
// Spawns CPU-bound worker threads that never yield voluntarily, then lets the
// per-CPU scheduler preempt them round-robin off the timer tick. That all
// workers make progress proves the timer genuinely switched between them
// without cooperation. The run stops after a fixed number of ticks by
// switching back to this boot context, so CI terminates.

pub(crate) const WORKERS: usize = 3;
pub(crate) const WORKER_STACK_PAGES: u64 = 4;
pub(crate) const SCHED_QUANTUM_TICKS: u32 = 2;
pub(crate) const SCHED_TICK_LIMIT: u64 = 40;

/// Per-worker progress counters, incremented in the workers' spin loops.
pub(crate) static WORKER_PROGRESS: [AtomicU64; WORKERS] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// The boot CPU's scheduler. Initialized once in `_start` before the timer is
/// enabled; thereafter touched only by the boot path (interrupts disabled) and
/// the timer interrupt (serialized), so no lock is needed: both are this CPU's.
pub(crate) static mut SCHEDULER: Option<Scheduler<ContextSwitch>> = None;

/// A CPU-bound worker: spins forever incrementing its progress counter. It is
/// never resumed cooperatively — only the timer preempts it.
pub(crate) extern "C" fn spin_worker(idx: usize) -> ! {
    loop {
        WORKER_PROGRESS[idx].fetch_add(1, Ordering::Relaxed);
    }
}

/// The timer-tick preemption hook: drives one scheduler tick. Registered with
/// the architecture timer path, it runs in interrupt context.
pub(crate) fn preempt_tick() {
    // SAFETY: the boot CPU — the scheduler is initialized before the timer is
    // enabled, and only this hook (in the masked timer interrupt) and the boot
    // path (interrupts disabled) ever touch it, so there is no concurrent
    // access.
    unsafe {
        if let Some(scheduler) = (*&raw mut SCHEDULER).as_mut() {
            scheduler.on_tick();
        }
    }
}

/// Spawns the workers, starts preemptive scheduling under the timer, and
/// reports the switch count and per-worker progress once the tick limit
/// returns control here.
pub(crate) fn scheduler_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    // SAFETY: the boot CPU, before the timer is enabled; this is the
    // only initialization of the scheduler.
    unsafe { SCHEDULER = Some(Scheduler::new(SCHED_QUANTUM_TICKS, SCHED_TICK_LIMIT)) };

    for idx in 0..WORKERS {
        let stack_base = alloc_kstack(WORKER_STACK_PAGES);
        let thread = match Thread::<ContextSwitch>::spawn(
            spin_worker,
            idx,
            stack_base,
            WORKER_STACK_PAGES,
            kernel_vm,
            frames,
        ) {
            Ok(thread) => thread,
            Err(e) => panic!("scheduler demo: spawn failed: {e:?}"),
        };
        // SAFETY: the boot CPU alone; the timer is not yet enabled, so the
        // scheduler is not concurrently accessed.
        unsafe {
            match (*&raw mut SCHEDULER).as_mut() {
                Some(scheduler) => {
                    if scheduler.add_thread(thread).is_err() {
                        panic!("scheduler demo: thread table full");
                    }
                }
                None => panic!("scheduler demo: scheduler uninitialized"),
            }
        }
    }

    use tessera_karch::{InterruptControl, TimerControl};
    use tessera_karch_x86_64::{ApicTimer, set_tick_hook, unexpected_irqs};
    ApicTimer::start_periodic_this_cpu(TICK_HZ);
    set_tick_hook(preempt_tick);
    Cpu::enable();
    // SAFETY: the scheduler is initialized above; `run` drives preemptive
    // round-robin and returns when the tick limit switches back to this boot
    // context. The timer interrupt is the only other accessor, and it is
    // serialized with this call by the context switches themselves.
    unsafe {
        match (*&raw mut SCHEDULER).as_mut() {
            Some(scheduler) => scheduler.run(),
            None => panic!("scheduler demo: scheduler uninitialized"),
        }
    }
    Cpu::disable();

    // SAFETY: the boot CPU alone again (interrupts disabled, run returned).
    let switches = unsafe {
        match (*&raw const SCHEDULER).as_ref() {
            Some(scheduler) => scheduler.switch_count(),
            None => 0,
        }
    };
    kprintln!(
        "sched: {switches} preemptive switches over {} ticks ({} unexpected IRQs)",
        ApicTimer::ticks(),
        unexpected_irqs()
    );
    kprintln!(
        "sched: worker progress [{}, {}, {}] (all nonzero => timer preemption)",
        WORKER_PROGRESS[0].load(Ordering::Relaxed),
        WORKER_PROGRESS[1].load(Ordering::Relaxed),
        WORKER_PROGRESS[2].load(Ordering::Relaxed),
    );
}
