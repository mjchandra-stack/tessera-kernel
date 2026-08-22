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

/// A stand-in for a port's interrupt control, recording what the lock did to it.
mod fake_cpu {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    pub static ENABLED: AtomicBool = AtomicBool::new(true);
    pub static MASKED_WHILE_HELD: AtomicU32 = AtomicU32::new(0);

    pub struct Cpu;

    impl tessera_karch::InterruptControl for Cpu {
        fn enable() {
            ENABLED.store(true, Ordering::SeqCst);
        }
        fn disable() {
            ENABLED.store(false, Ordering::SeqCst);
        }
        fn are_enabled() -> bool {
            ENABLED.load(Ordering::SeqCst)
        }
    }
}

/// The interrupt control and the flag it drives are process-wide, and the test
/// harness runs tests in parallel threads. So this is deliberately **one** test
/// walking three scenarios in sequence rather than three tests racing over one
/// static — three would pass most of the time, which is the worst outcome
/// available.
#[test]
fn the_lock_masks_interrupts_for_exactly_the_critical_section() {
    use core::sync::atomic::Ordering;
    let enabled = || <fake_cpu::Cpu as tessera_karch::InterruptControl>::are_enabled();
    let _ = install_interrupt_control::<fake_cpu::Cpu>();
    let lock = SpinLock::new(0u32);

    // Held with interrupts on: they go off for the critical section and come
    // back after it. A handler running inside would deadlock against this very
    // section, which is what the mask exists to prevent.
    fake_cpu::ENABLED.store(true, Ordering::SeqCst);
    {
        let _guard = lock.lock();
        assert!(!enabled(), "interrupts stayed on inside a critical section");
    }
    assert!(
        enabled(),
        "interrupts were not restored when the guard dropped"
    );

    // Held with interrupts already off — a lock taken inside a handler. They
    // must stay off: the handler's contract is that they are masked, and
    // unconditionally enabling on release would break it. This is why the
    // previous state is saved rather than assumed.
    fake_cpu::ENABLED.store(false, Ordering::SeqCst);
    {
        let _guard = lock.lock();
        assert!(!enabled());
    }
    assert!(
        !enabled(),
        "a lock re-enabled interrupts its caller had masked"
    );

    // A refused `try_lock` holds nothing, so it must not leave the mask on.
    // It masks before attempting — the attempt is not interruptible either —
    // so the undo is a real step and not a no-op.
    fake_cpu::ENABLED.store(true, Ordering::SeqCst);
    let held = lock.lock();
    assert!(lock.try_lock().is_none());
    drop(held);
    assert!(enabled(), "a refused try_lock left interrupts masked");
}
