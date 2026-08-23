// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A spinlock that masks this CPU's interrupts for the critical section. Not
//! for budgeted paths — per-CPU state is the default there
//! (docs/kernel/08-multicore-scalability.md).
//!
//! # Why the mask is part of the lock
//!
//! A lock taken by ordinary code and then wanted by an interrupt handler on the
//! same CPU deadlocks: the handler spins for something only the code it
//! interrupted can release, and that code cannot run until the handler returns.
//! One core is not protection from this — it is the *cause* of it.
//!
//! This module's header used to promise the mask would arrive "with the
//! interrupt milestone". Interrupts arrived (build/README.md, D84) and it did
//! not, which left every caller relying on hand-audited reasoning about which
//! locks an interrupt path could reach. That reasoning is now in the lock.
//!
//! # Where the masking comes from
//!
//! Masking is a two-instruction architecture operation and these locks live in
//! `static`s, so the type cannot be generic over the porting layer — a `static`
//! has to name a concrete type and `kcore` does not know which. Boot glue
//! installs the pair instead, exactly as it installs the event clock
//! (`crate::event::set_clock`), through [`install_interrupt_control`].
//!
//! Acquisitions before that happens are **counted, not assumed harmless**:
//! [`set_interrupt_control`] returns the count so a port can report it. On
//! every port the window is boot with interrupts already masked, which is why
//! it is safe; a growing count after boot would mean a port never installed the
//! pair, and that is worth being able to see
//! (`docs/lifecycle/04-coding-guidelines.md`, "No Silent Fallback").
//!
//! Lock ordering: this module's locks are leaves; nothing may be acquired
//! while holding one.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/kernel/08-multicore-scalability.md
//! Budget: none (init and panic paths only)

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use tessera_karch::InterruptControl;

/// Masks this CPU's interrupts, returning whether they had been enabled.
type InterruptMask = fn() -> bool;

/// Restores this CPU's interrupts to the state an [`InterruptMask`] reported.
type InterruptRestore = fn(bool);

/// The installed pair, as raw function addresses. Null means "not installed".
///
/// Two cells rather than one, with a publication order that makes the pair
/// atomic in the only way that matters: `RESTORE` is stored first and `MASK`
/// last, and a reader that sees a non-zero `MASK` is therefore guaranteed to
/// see the `RESTORE` that was installed with it. A lock cannot be used to guard
/// them — this is the module that implements locks.
static MASK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static RESTORE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Critical sections entered before the interrupt control was installed.
static UNPROTECTED: crate::counter::Sharded = crate::counter::Sharded::new();

/// Installs interrupt masking built from the port's [`InterruptControl`],
/// returning how many critical sections were entered without it.
///
/// One call per port, and the mask/restore pair itself is written once here
/// rather than five times: it is the same three operations on every
/// architecture, and a port that spelled it differently would be a port whose
/// locks behaved differently for no reason anyone chose.
///
/// `#[must_use]` for the reason `set_clock` is: a port that installs this and
/// discards the answer cannot notice it installed it too late.
#[must_use]
pub fn install_interrupt_control<I: InterruptControl>() -> u64 {
    fn mask<I: InterruptControl>() -> bool {
        let were_enabled = I::are_enabled();
        I::disable();
        were_enabled
    }
    fn restore<I: InterruptControl>(were_enabled: bool) {
        // Only re-enable what was enabled. Unconditionally enabling would let a
        // lock taken inside an interrupt handler return with interrupts on,
        // which is the handler's contract broken by the lock it used.
        if were_enabled {
            I::enable();
        }
    }
    RESTORE.store(restore::<I> as *mut (), Ordering::Release);
    MASK.store(mask::<I> as *mut (), Ordering::Release);
    UNPROTECTED.take()
}

/// Masks interrupts for a critical section, reporting the state to restore.
///
/// `None` means no control is installed, and the count says so.
fn mask_interrupts() -> Option<bool> {
    let mask = MASK.load(Ordering::Acquire);
    if mask.is_null() {
        UNPROTECTED.bump();
        return None;
    }
    // SAFETY: non-null only because `install_interrupt_control` stored an
    // `InterruptMask` there, and the release/acquire pair above publishes it.
    let mask: InterruptMask = unsafe { core::mem::transmute::<*mut (), InterruptMask>(mask) };
    Some(mask())
}

/// Restores what [`mask_interrupts`] reported.
fn restore_interrupts(were_enabled: bool) {
    let restore = RESTORE.load(Ordering::Acquire);
    if restore.is_null() {
        return;
    }
    // SAFETY: as above — non-null only because `install_interrupt_control`
    // stored an `InterruptRestore` there, and it is published before `MASK`.
    let restore: InterruptRestore =
        unsafe { core::mem::transmute::<*mut (), InterruptRestore>(restore) };
    restore(were_enabled);
}

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

    /// Acquires the lock, masking this CPU's interrupts until the guard drops.
    ///
    /// Masking happens **before** the first attempt, not after success: an
    /// interrupt landing in between would find the lock held by the code it
    /// interrupted, which is the deadlock the mask exists to prevent.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let were_enabled = mask_interrupts();
        loop {
            if self.acquire() {
                return SpinLockGuard {
                    lock: self,
                    were_enabled,
                };
            }
            core::hint::spin_loop();
        }
    }

    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let were_enabled = mask_interrupts();
        if self.acquire() {
            Some(SpinLockGuard {
                lock: self,
                were_enabled,
            })
        } else {
            // Nothing was locked, so nothing is held across the return — undo
            // the mask rather than leaving the caller's interrupts off on a
            // path that reports failure.
            if let Some(were_enabled) = were_enabled {
                restore_interrupts(were_enabled);
            }
            None
        }
    }

    fn acquire(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
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
    /// Whether interrupts were enabled when the lock was taken, or `None` if no
    /// interrupt control was installed to ask.
    were_enabled: Option<bool>,
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
        // Release, then unmask. The other order would let an interrupt arrive
        // while this CPU still holds the lock, which is the state the mask was
        // taken to avoid.
        self.lock.locked.store(false, Ordering::Release);
        if let Some(were_enabled) = self.were_enabled {
            restore_interrupts(were_enabled);
        }
    }
}

#[cfg(test)]
#[path = "tests/sync.rs"]
mod tests;
