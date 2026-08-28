// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `karch::atomic`.

// The split implementation is tested directly, not through the cfg-
// selected alias: on a 64-bit host the alias is the delegating newtype,
// and testing that would only be testing the standard library.
use super::split::{AtomicU64, CpuCounter, SharedCounter};
use core::sync::atomic::Ordering::Relaxed;

#[test]
fn a_value_survives_the_round_trip_through_two_halves() {
    for value in [
        0,
        1,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        0x0123_4567_89ab_cdef,
        u64::MAX,
    ] {
        let counter = AtomicU64::new(value);
        assert_eq!(counter.load(Relaxed), value, "new/load {value:#x}");

        let counter = AtomicU64::new(0);
        counter.store(value, Relaxed);
        assert_eq!(counter.load(Relaxed), value, "store/load {value:#x}");
    }
}

#[test]
fn a_per_cpu_counter_carries_across_the_halves() {
    // Ordinary increment, no carry.
    let counter = CpuCounter::new(7);
    counter.add(1, Relaxed);
    assert_eq!(counter.get(Relaxed), 8);

    // The case the split representation exists to get right: the low half
    // wraps and the high half must take the carry.
    let counter = CpuCounter::new(u64::from(u32::MAX));
    counter.add(1, Relaxed);
    assert_eq!(counter.get(Relaxed), u64::from(u32::MAX) + 1);

    // An addend wider than the low half carries too.
    let counter = CpuCounter::new(0);
    let wide = (3u64 << 32) | 5;
    counter.add(wide, Relaxed);
    assert_eq!(counter.get(Relaxed), wide);

    // Both at once: a wide addend that also wraps the low half.
    let counter = CpuCounter::new(u64::from(u32::MAX));
    counter.add(wide, Relaxed);
    assert_eq!(counter.get(Relaxed), u64::from(u32::MAX) + wide);
}

#[test]
fn a_long_run_of_increments_crosses_the_carry_without_drift() {
    // Starts just below the boundary and walks across it, so the carry is
    // taken in the middle of a sequence rather than in isolation.
    let start = u64::from(u32::MAX) - 4;
    let counter = CpuCounter::new(start);
    for step in 0..10u64 {
        assert_eq!(counter.get(Relaxed), start + step);
        counter.add(1, Relaxed);
    }
    assert_eq!(counter.get(Relaxed), start + 10);
}

#[test]
fn a_shared_counter_returns_the_previous_value_across_the_carry() {
    // The operation `AtomicU64` used to offer and could not honestly provide.
    // Here it is serialized on the sequence word, so the previous value is the
    // whole 64 bits and not a pair read either side of a carry.
    let counter = SharedCounter::new(u64::from(u32::MAX));
    assert_eq!(counter.fetch_add(1, Relaxed), u64::from(u32::MAX));
    assert_eq!(counter.load(Relaxed), u64::from(u32::MAX) + 1);

    let wide = (3u64 << 32) | 5;
    assert_eq!(
        counter.fetch_add(wide, Relaxed),
        u64::from(u32::MAX) + 1,
        "a wide addend is added whole, not half at a time"
    );
    assert_eq!(counter.load(Relaxed), u64::from(u32::MAX) + 1 + wide);

    assert_eq!(counter.swap(0, Relaxed), u64::from(u32::MAX) + 1 + wide);
    assert_eq!(counter.load(Relaxed), 0);
}

#[test]
fn a_shared_counter_leaves_its_sequence_even_so_a_reader_can_get_in() {
    // The rule the type cannot enforce is that writers do not nest; the rule
    // it *must* keep is that a completed write leaves the sequence even, or
    // every later reader spins for ever. Ten writes and a read is the cheapest
    // statement of it, and it fails if `begin` and the release ever disagree
    // about parity.
    let counter = SharedCounter::new(0);
    for _ in 0..10 {
        counter.fetch_add(3, Relaxed);
    }
    assert_eq!(counter.load(Relaxed), 30);
}

#[test]
fn swap_returns_the_previous_value_and_installs_the_new_one() {
    let counter = AtomicU64::new(0xdead_beef_cafe_f00d);
    assert_eq!(counter.swap(1, Relaxed), 0xdead_beef_cafe_f00d);
    assert_eq!(counter.load(Relaxed), 1);
}

#[test]
fn the_halves_hold_the_expected_bits() {
    // Guards the layout the load/store protocol assumes: the high half is
    // bits 63..32 and the low half is 31..0, not the reverse.
    let counter = AtomicU64::new(0xaaaa_bbbb_cccc_dddd);
    assert_eq!(counter.load(Relaxed) >> 32, 0xaaaa_bbbb);
    assert_eq!(counter.load(Relaxed) & 0xffff_ffff, 0xcccc_dddd);
}

/// A split `swap` accepts every ordering a read-modify-write may carry.
///
/// **The panic this replaces was reached by running, not by compiling.** The
/// 32-bit halves of these types have been built on every `bazel build //...`
/// since `//kernel/width-conformance` existed, and building them says nothing
/// about which `Ordering` reaches which half: `swap` passed the caller's
/// ordering to *both*, so `swap(.., Acquire)` handed `Acquire` to a store and
/// the standard library's answer to that is a panic. It fired the first time a
/// 32-bit port ran a thread that drained a wakeup (build/README.md, D260).
///
/// Written as a loop over the four orderings a swap can be given rather than as
/// one case, because the pair that was wrong — `Acquire` and `AcqRel` — is
/// exactly the pair a test written for the ordering people usually reach for
/// would have missed.
///
/// **What this does not check**, measured rather than assumed: replacing the
/// split with `Relaxed` on both halves passes it. These assert that no ordering
/// *panics* and that the value round-trips, not that the memory ordering is
/// honoured — that needs real concurrency, and `kernel/kcore/src/tests/counter.rs`
/// is where the protocol is run against threads.
#[test]
fn a_split_swap_takes_every_read_modify_write_ordering() {
    use core::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release, SeqCst};
    for order in [Relaxed, Acquire, Release, AcqRel, SeqCst] {
        let cell = AtomicU64::new(0x1234_5678_9abc_def0);
        assert_eq!(cell.swap(0, order), 0x1234_5678_9abc_def0);
        assert_eq!(cell.load(Relaxed), 0);
    }
}

/// And a split load and store take theirs.
///
/// `load(Release)` and `store(Acquire)` are the two the standard library
/// refuses outright; a split type that forwarded its caller's ordering
/// unchanged would panic on both.
#[test]
fn a_split_load_and_store_take_every_ordering() {
    use core::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release, SeqCst};
    for order in [Relaxed, Acquire, Release, AcqRel, SeqCst] {
        let cell = AtomicU64::new(0);
        cell.store(0xdead_beef_0000_0001, order);
        assert_eq!(cell.load(order), 0xdead_beef_0000_0001);
    }
}
