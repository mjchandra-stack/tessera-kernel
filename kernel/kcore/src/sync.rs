// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A minimal spinlock for boot-time state. This milestone runs the boot
//! CPU only with interrupts mostly off; interrupt-safe lock acquisition
//! (disable-on-lock) arrives with the interrupt milestone. Not for budgeted
//! paths — per-CPU state is the default there
//! (docs/kernel/08-multicore-scalability.md).
//!
//! Lock ordering: this module's locks are leaves; nothing may be acquired
//! while holding one.
//!
//! Normative: docs/kernel/01-kernel-model.md
//! Budget: none (init and panic paths only)

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the lock guarantees exclusive access to the inner value before
// any reference to it is produced, so sharing the lock across threads is
// sound whenever the value itself may move between threads.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            core::hint::spin_loop();
        }
    }

    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }

    /// Busts a held lock without running the holder's release. Panic path
    /// only: once the system is halting, a deadlocked console lock must not
    /// silence the report.
    ///
    /// # Safety
    ///
    /// Only sound when no other CPU or interrupt handler can still be
    /// inside the critical section — i.e. single CPU with interrupts
    /// disabled on the way down.
    pub unsafe fn force_unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while the lock is held, so the
        // exclusive-access invariant makes this reference unique.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above — the held lock guarantees uniqueness.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
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
}
