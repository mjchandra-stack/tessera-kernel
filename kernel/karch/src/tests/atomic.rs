// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `karch::atomic`.

// The split implementation is tested directly, not through the cfg-
// selected alias: on a 64-bit host the alias is the delegating newtype,
// and testing that would only be testing the standard library.
use super::split::AtomicU64;
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
fn fetch_add_returns_the_previous_value_and_carries_across_the_halves() {
    // Ordinary increment, no carry.
    let counter = AtomicU64::new(7);
    assert_eq!(counter.fetch_add(1, Relaxed), 7);
    assert_eq!(counter.load(Relaxed), 8);

    // The case the split representation exists to get right: the low half
    // wraps and the high half must take the carry.
    let counter = AtomicU64::new(u64::from(u32::MAX));
    assert_eq!(counter.fetch_add(1, Relaxed), u64::from(u32::MAX));
    assert_eq!(counter.load(Relaxed), u64::from(u32::MAX) + 1);

    // An addend wider than the low half carries too.
    let counter = AtomicU64::new(0);
    let wide = (3u64 << 32) | 5;
    assert_eq!(counter.fetch_add(wide, Relaxed), 0);
    assert_eq!(counter.load(Relaxed), wide);

    // Both at once: a wide addend that also wraps the low half.
    let counter = AtomicU64::new(u64::from(u32::MAX));
    assert_eq!(counter.fetch_add(wide, Relaxed), u64::from(u32::MAX));
    assert_eq!(counter.load(Relaxed), u64::from(u32::MAX) + wide);
}

#[test]
fn a_long_run_of_increments_crosses_the_carry_without_drift() {
    // Starts just below the boundary and walks across it, so the carry is
    // taken in the middle of a sequence rather than in isolation.
    let start = u64::from(u32::MAX) - 4;
    let counter = AtomicU64::new(start);
    for step in 0..10u64 {
        assert_eq!(counter.fetch_add(1, Relaxed), start + step);
    }
    assert_eq!(counter.load(Relaxed), start + 10);
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
