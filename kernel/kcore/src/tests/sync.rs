// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::sync`.

use super::*;

#[test]
fn lock_excludes_and_releases() {
    let lock = SpinLock::new(1);
    {
        let mut guard = lock.lock();
        *guard += 1;
        assert!(lock.try_lock().is_none());
    }
    assert_eq!(*lock.lock(), 2);
}

#[test]
fn force_unlock_busts_a_held_lock() {
    let lock = SpinLock::new(());
    core::mem::forget(lock.lock());
    assert!(lock.try_lock().is_none());
    // SAFETY: single-threaded test; the forgotten guard is never used.
    unsafe { lock.force_unlock() };
    assert!(lock.try_lock().is_some());
}
