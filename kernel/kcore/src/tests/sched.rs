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
    Thread::<MockContextOps>::spawn(never, id as usize, VirtAddr::new(base), 2, vm, &mut frames)
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
    assert_eq!(q.take_at(0), Some(3));
    assert_eq!(q.take_at(0), Some(1));
    assert_eq!(q.take_at(0), Some(2));
    assert_eq!(q.take_at(0), None);
}

#[test]
fn runqueue_wraps_and_rejects_when_full() {
    let mut q = RunQueue::new();
    for i in 0..MAX_THREADS {
        assert!(q.push(i));
    }
    assert!(!q.push(99), "full queue rejects");
    // Drain and refill past the wrap point.
    assert_eq!(q.take_at(0), Some(0));
    assert!(q.push(99));
    for expected in 1..MAX_THREADS {
        assert_eq!(q.take_at(0), Some(expected));
    }
    assert_eq!(q.take_at(0), Some(99));
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
    assert_eq!(q.take_at(0), Some(1), "order preserved past the removals");
    assert_eq!(q.take_at(0), Some(2));
    assert_eq!(q.take_at(0), None);
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

#[test]
fn admitting_a_thread_mints_a_distinct_identity() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);

    let first = sched.add_thread(make_thread(&mut vm, 1)).expect("first");
    let second = sched.add_thread(make_thread(&mut vm, 2)).expect("second");

    let a = sched.thread_id(first).expect("first has an id");
    let b = sched.thread_id(second).expect("second has an id");

    // The discriminator, and the reason this test exists: every caller used to
    // pass a hand-picked constant, and four different threads across the tree
    // were `ThreadId(1)`. Distinctness is exactly what that could not give.
    assert_ne!(a, b);
    assert_ne!(a, ThreadId::UNASSIGNED);
    assert_ne!(b, ThreadId::UNASSIGNED);

    // Minted by this CPU, sequential within it.
    assert_eq!(
        (a.cpu(), b.cpu()),
        (
            crate::percpu::current_index(),
            crate::percpu::current_index()
        )
    );
    assert_eq!((a.sequence(), b.sequence()), (1, 2));
}

#[test]
fn an_identity_carries_the_minting_cpu_above_the_sequence() {
    // The halves must not overlap, or two CPUs could mint the same value —
    // which is the whole reason the id is split rather than a bare counter.
    let low = ThreadId((1 << ThreadId::CPU_SHIFT) - 1);
    assert_eq!(
        (low.cpu(), low.sequence()),
        (0, (1 << ThreadId::CPU_SHIFT) - 1)
    );

    let other_cpu = ThreadId((3 << ThreadId::CPU_SHIFT) | 5);
    assert_eq!((other_cpu.cpu(), other_cpu.sequence()), (3, 5));

    // Same sequence, different CPU, different identity.
    assert_ne!(ThreadId(5), other_cpu);
}

#[test]
fn a_wakeup_that_names_the_wrong_thread_moves_nothing() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let slot = sched.add_thread(make_thread(&mut vm, 0)).expect("add");
    let id = sched.thread_id(slot).expect("id");
    sched.run();
    sched.block_current();

    // The identity the wakeup was posted for is the one in the slot: it moves.
    assert!(sched.unblock_thread(slot, id));

    // The slot's occupant has changed since the wakeup was posted — which is
    // what happens when the thread it named exited and its slot was reused.
    // Unblocking on the slot alone would make a stranger runnable; this is
    // `index_of`'s refusal arriving from the other direction.
    let stranger = ThreadId(id.0 ^ 0xffff);
    assert!(!sched.unblock_thread(slot, stranger));

    // An empty slot, and a wakeup that names nobody — what the bring-up probe
    // posts, since it is checking that a bit crosses and has no thread to name.
    assert!(!sched.unblock_thread(slot + 1, id));
    assert!(!sched.unblock_thread(slot, ThreadId::UNASSIGNED));
}

// --- The ready ring holds each thread once, and says so when it cannot ------

/// **A second wakeup does not put a thread on the ring twice.**
///
/// The ring is the same size as the thread table, so it can only fill if some
/// thread is on it more than once — and a double wakeup is ordinary running,
/// not a defect: a wakeup that crossed from another CPU can race a local one,
/// and a server that replies and then wakes its caller can reach a caller
/// something else already woke. Duplicates also let one thread be dispatched
/// to two contexts, which is worse than the overflow.
#[test]
fn waking_a_thread_twice_queues_it_once() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let a = sched.add_thread(make_thread(&mut vm, 0)).expect("add");
    let _second = sched.add_thread(make_thread(&mut vm, 1)).expect("add");
    sched.run(); // a runs, the second thread is queued
    sched.block_current(); // a blocks, the second runs
    assert_eq!(sched.thread_state(a), Some(ThreadState::Blocked));

    let before = sched.ready.len();
    sched.unblock(a);
    sched.unblock(a);
    sched.unblock(a);
    assert_eq!(
        sched.ready.len(),
        before + 1,
        "three wakeups of one thread put it on the ring once",
    );
    assert_eq!(sched.thread_state(a), Some(ThreadState::Ready));

    // And it is dispatched once: the second pop finds nothing of it.
    assert_eq!(sched.pop_ready(), Some(a));
    assert_ne!(sched.pop_ready(), Some(a));
}

/// Waking a thread that is *running* moves nothing. It is on a CPU, not on a
/// queue, and enqueuing it would be the same duplicate by another route.
#[test]
fn waking_the_running_thread_moves_nothing() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let a = sched.add_thread(make_thread(&mut vm, 0)).expect("add");
    sched.run();
    assert_eq!(sched.thread_state(a), Some(ThreadState::Running));

    let before = sched.ready.len();
    sched.unblock(a);
    assert_eq!(sched.ready.len(), before, "a running thread is not queued");
    assert_eq!(sched.thread_state(a), Some(ThreadState::Running));
}

/// A stale ring entry does not resume a thread that has parked since.
///
/// An entry is a claim and the state is the fact. A thread handed off to while
/// it was queued is `Running` with its entry still on the ring; if it then
/// blocks, dispatching that entry would resume a thread waiting for something
/// that has not happened — no fault, no message, just a thread running past
/// the event it was parked on.
#[test]
fn a_stale_ring_entry_does_not_resume_a_parked_thread() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let _first = sched.add_thread(make_thread(&mut vm, 0)).expect("add");
    let b = sched.add_thread(make_thread(&mut vm, 1)).expect("add");
    sched.run(); // the first runs; b is queued and Ready

    // b is handed off to without coming off the ring — its entry is now stale.
    sched.handoff_to(b);
    assert_eq!(sched.thread_state(b), Some(ThreadState::Running));
    // ...and b then parks.
    sched.block_current();
    assert_eq!(sched.thread_state(b), Some(ThreadState::Blocked));

    // The stale entry is still there, and must not dispatch b.
    assert_ne!(sched.pop_ready(), Some(b));
}

/// **A refused enqueue is counted and reported, and leaves the thread where it
/// was.** It should be unreachable — hence a ring filled by hand — but a
/// wakeup that vanished is invisible: the thread never runs again and every
/// structure that names it still says it is fine.
#[test]
fn a_refused_enqueue_is_counted_and_leaves_the_thread_blocked() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let a = sched.add_thread(make_thread(&mut vm, 0)).expect("add");
    sched.run();
    sched.block_current();
    assert_eq!(sched.thread_state(a), Some(ThreadState::Blocked));

    // Fill the ring behind the scheduler's back with indices it will never
    // dispatch, so the next enqueue has nowhere to go.
    while sched.ready.push(usize::MAX) {}

    let before = refused_enqueues();
    sched.unblock(a);
    assert_eq!(
        refused_enqueues(),
        before + 1,
        "the refusal is counted, not dropped",
    );
    assert_eq!(
        sched.thread_state(a),
        Some(ThreadState::Blocked),
        "and the thread is left where it was, so a later wakeup can still work",
    );
}

// --- Priority decides who runs, and ties still take turns ------------------

/// **The most urgent ready thread runs next.**
///
/// The priority was carried and inherited and never consulted: `pop_ready` took
/// the front of the ring, so `set_thread_priority` moved a number that changed
/// nothing. A caller's priority reaching a server it calls is only worth
/// plumbing if it decides something.
#[test]
fn the_most_urgent_ready_thread_is_chosen() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let low = sched.add_thread(make_thread(&mut vm, 0)).expect("add");
    let high = sched.add_thread(make_thread(&mut vm, 1)).expect("add");
    let mid = sched.add_thread(make_thread(&mut vm, 2)).expect("add");

    // Queued low, high, mid — so the answer cannot come from arrival order.
    sched.set_thread_priority(low, 1);
    sched.set_thread_priority(high, 30);
    sched.set_thread_priority(mid, 10);

    assert_eq!(sched.pop_ready(), Some(high));
    assert_eq!(sched.pop_ready(), Some(mid));
    assert_eq!(sched.pop_ready(), Some(low));
    assert_eq!(sched.pop_ready(), None);
}

/// ...and threads of equal priority still take turns in arrival order, which
/// is every thread in this tree until something sets a priority. Round-robin
/// is not replaced by this; it is what happens inside a level.
#[test]
fn equal_priorities_still_take_turns() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let first = sched.add_thread(make_thread(&mut vm, 0)).expect("add");
    let second = sched.add_thread(make_thread(&mut vm, 1)).expect("add");
    let third = sched.add_thread(make_thread(&mut vm, 2)).expect("add");

    assert_eq!(sched.pop_ready(), Some(first));
    assert_eq!(sched.pop_ready(), Some(second));
    assert_eq!(sched.pop_ready(), Some(third));
}

/// **The inheritance seam now decides something**, which is the whole point of
/// carrying a caller's priority to its callee.
///
/// The classic inversion: an urgent client calls a server that is less urgent
/// than a third thread. Without inheritance the middle thread runs and the
/// urgent client waits behind it; with it, the server is raised for the call's
/// duration and goes first. `Executive::call` has set that priority since the
/// executive landed — this is the half that reads it.
#[test]
fn a_server_raised_to_its_callers_priority_runs_before_a_middling_thread() {
    let mut vm = vm();
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let server = sched.add_thread(make_thread(&mut vm, 0)).expect("add");
    let middle = sched.add_thread(make_thread(&mut vm, 1)).expect("add");

    sched.set_thread_priority(server, 1);
    sched.set_thread_priority(middle, 10);
    assert_eq!(
        sched.pop_ready(),
        Some(middle),
        "unraised, the middling thread wins and the urgent caller waits",
    );

    // Put it back and raise the server the way a synchronous call does.
    sched.unblock_pushed_for_test(middle);
    sched.set_thread_priority(server, 30);
    assert_eq!(
        sched.pop_ready(),
        Some(server),
        "raised to its caller's priority, the server goes first",
    );
}
