// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::wait`.

use super::*;

const K1: WaitKey = WaitKey {
    space: 0,
    addr: 0x1000,
};
const K2: WaitKey = WaitKey {
    space: 0,
    addr: 0x2000,
};
// Same address, different space — a distinct key (no cross-space aliasing).
const K1_OTHER_SPACE: WaitKey = WaitKey {
    space: 0xdead_0000,
    addr: 0x1000,
};

#[test]
fn enroll_then_pop_returns_the_waiter_once() {
    let mut set = WaitSet::new();
    set.enroll(K1, 3).expect("enroll");
    assert_eq!(set.len(), 1);
    assert_eq!(set.pop_matching(K1), Some(3));
    // Consumed: a second pop finds nothing.
    assert_eq!(set.pop_matching(K1), None);
    assert!(set.is_empty());
}

#[test]
fn pop_targets_only_the_matching_key() {
    let mut set = WaitSet::new();
    set.enroll(K1, 1).expect("enroll k1");
    set.enroll(K2, 2).expect("enroll k2");
    // A pop on K1 leaves the K2 waiter untouched.
    assert_eq!(set.pop_matching(K1), Some(1));
    assert_eq!(set.pop_matching(K1), None);
    assert_eq!(set.pop_matching(K2), Some(2));
}

#[test]
fn same_address_in_different_spaces_is_a_distinct_key() {
    let mut set = WaitSet::new();
    set.enroll(K1, 1).expect("enroll");
    set.enroll(K1_OTHER_SPACE, 2).expect("enroll other space");
    // Waking K1 must not wake the same-address waiter in another space.
    assert_eq!(set.pop_matching(K1), Some(1));
    assert_eq!(set.pop_matching(K1), None);
    assert_eq!(set.pop_matching(K1_OTHER_SPACE), Some(2));
}

#[test]
fn multiple_waiters_on_one_key_pop_until_drained() {
    // Models wake(key, count): pop up to `count` matching waiters.
    let mut set = WaitSet::new();
    for t in 0..4 {
        set.enroll(K1, t).expect("enroll");
    }
    let mut woken = 0;
    while woken < 3 && set.pop_matching(K1).is_some() {
        woken += 1;
    }
    assert_eq!(woken, 3);
    assert_eq!(set.len(), 1); // one waiter left un-woken
}

#[test]
fn a_full_pool_rejects_enroll_without_dropping() {
    let mut set = WaitSet::new();
    for t in 0..MAX_WAITERS {
        set.enroll(K1, t).expect("enroll");
    }
    assert_eq!(set.enroll(K1, 999), Err(KError::OutOfMemory));
    assert_eq!(set.len(), MAX_WAITERS);
}

#[test]
fn pop_on_absent_key_is_none() {
    let mut set = WaitSet::new();
    assert_eq!(set.pop_matching(K1), None);
}
