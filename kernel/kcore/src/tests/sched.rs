// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::sched`.

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
    AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(0)).expect("vm")
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
