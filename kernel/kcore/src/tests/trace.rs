// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::trace`.

use super::*;

#[test]
fn minted_ids_are_fresh_and_never_zero() {
    let a = mint();
    let b = mint();
    assert_ne!(a, 0);
    assert_ne!(b, 0);
    assert_ne!(a, b);
}

#[test]
fn the_empty_context_is_all_zero() {
    assert_eq!(TraceContext::NONE.thread_id, 0);
    assert_eq!(TraceContext::NONE.process_id, 0);
    assert_eq!(TraceContext::NONE.correlation, 0);
    assert_eq!(TraceContext::default(), TraceContext::NONE);
}

// The ambient statics are global, so a test that publishes cannot run
// concurrently with one that reads. Both live in this single test.
#[test]
fn publishing_a_context_makes_it_current() {
    let cx = TraceContext {
        thread_id: 7,
        process_id: 9,
        correlation: 11,
    };
    set_current(cx);
    assert_eq!(current(), cx);

    // An origin can replace the cause without disturbing identity.
    set_current_correlation(12);
    let after = current();
    assert_eq!(after.correlation, 12);
    assert_eq!((after.thread_id, after.process_id), (7, 9));

    set_current(TraceContext::NONE);
    assert_eq!(current(), TraceContext::NONE);
}

#[test]
fn the_epoch_round_trips() {
    set_epoch(0xdead_beef);
    assert_eq!(epoch(), 0xdead_beef);
}
