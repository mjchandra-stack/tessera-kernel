// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::wait`.

use super::*;
use crate::thread::ThreadId;

/// Two words in the same physical frame, and one in another.
const K1: WaitKey = WaitKey::at(0x1000);
const K2: WaitKey = WaitKey::at(0x2000);
/// The same offset in a different frame — a distinct key.
const K1_OTHER_FRAME: WaitKey = WaitKey::at(0x3000);
/// A different word *inside* K1's frame. The offset is part of the key, or one
/// lock per page would be the whole of what a futex could express.
const K1_NEIGHBOUR: WaitKey = WaitKey::at(0x1008);

#[test]
fn enroll_then_pop_returns_the_waiter_once() {
    let mut set = WaitSet::new();
    set.enroll(K1, ThreadId(3)).expect("enroll");
    assert_eq!(set.len(), 1);
    assert_eq!(set.pop_matching(K1), Some(ThreadId(3)));
    // Consumed: a second pop finds nothing.
    assert_eq!(set.pop_matching(K1), None);
    assert!(set.is_empty());
}

#[test]
fn pop_targets_only_the_matching_key() {
    let mut set = WaitSet::new();
    set.enroll(K1, ThreadId(1)).expect("enroll k1");
    set.enroll(K2, ThreadId(2)).expect("enroll k2");
    // A pop on K1 leaves the K2 waiter untouched.
    assert_eq!(set.pop_matching(K1), Some(ThreadId(1)));
    assert_eq!(set.pop_matching(K1), None);
    assert_eq!(set.pop_matching(K2), Some(ThreadId(2)));
}

#[test]
fn the_key_is_a_word_and_not_a_page() {
    let mut set = WaitSet::new();
    set.enroll(K1, ThreadId(1)).expect("enroll");
    set.enroll(K1_NEIGHBOUR, ThreadId(2))
        .expect("enroll neighbour");
    set.enroll(K1_OTHER_FRAME, ThreadId(3))
        .expect("enroll other frame");

    // Two words in one frame are two keys. A key that was the frame alone
    // would make every lock on a page the same lock.
    assert_eq!(set.pop_matching(K1), Some(ThreadId(1)));
    assert_eq!(set.pop_matching(K1), None);
    assert_eq!(set.pop_matching(K1_NEIGHBOUR), Some(ThreadId(2)));
    // ...and the same offset in another frame is another key.
    assert_eq!(set.pop_matching(K1_OTHER_FRAME), Some(ThreadId(3)));
}

#[test]
fn one_word_reached_through_two_mappings_is_one_key() {
    // **The point of physical keying.** Two processes mapping the same page at
    // different virtual addresses — or one process mapping it twice — arrive
    // at the same key, so a wake through either mapping reaches a waiter that
    // enrolled through the other. Under the old `(space, virtual address)` key
    // these were two keys and neither could ever wake the other.
    let mut set = WaitSet::new();
    let through_one_mapping = WaitKey::at(0x4020);
    let through_another = WaitKey::at(0x4020);
    set.enroll(through_one_mapping, ThreadId(7))
        .expect("enroll");
    assert_eq!(set.pop_matching(through_another), Some(ThreadId(7)));
}

#[test]
fn multiple_waiters_on_one_key_pop_until_drained() {
    // Models wake(key, count): pop up to `count` matching waiters.
    let mut set = WaitSet::new();
    for t in 0..4 {
        set.enroll(K1, ThreadId(t as u64)).expect("enroll");
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
        set.enroll(K1, ThreadId(t as u64)).expect("enroll");
    }
    assert_eq!(set.enroll(K1, ThreadId(999)), Err(KError::OutOfMemory));
    assert_eq!(set.len(), MAX_WAITERS);
}

#[test]
fn pop_on_absent_key_is_none() {
    let mut set = WaitSet::new();
    assert_eq!(set.pop_matching(K1), None);
}
