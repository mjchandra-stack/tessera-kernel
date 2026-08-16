// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wait-on-address: the futex-style compare-and-block / wake primitive
//! (docs/kernel/04, "Wait-On-Address" — *"the lowest-level primitive is
//! futex-style wait and wake on a user-space address … carries no
//! kernel-visible owner … the building block for uncontended user-space
//! locks"*). It is deliberately owner-less and priority-inheritance-free; the
//! owner-aware lock (a separate primitive) is what carries inheritance.
//!
//! This module is the pure enrollment table — a fixed pool recording *which
//! thread* is blocked on *which key*. The comparison of the address's value
//! against the caller's expected word, and the actual park/wake, live on the
//! executive (`exec.rs`): kcore never dereferences a user pointer, so the
//! word is read by the arch/syscall entry and passed in. A key is
//! `(space, addr)` — the caller's address-space root and the waited virtual
//! address — so a thread can only be woken through the same space it waited
//! in (no ambient cross-space authority in v0; a physical-frame key for
//! cross-process shared-memory futexes is deferred, build/README.md D37).
//!
//! Normative: docs/kernel/04-synchronization-and-ipc-guarantees.md
//! ("Wait-On-Address")
//! Budget: B6 (contended wake) — the mechanism this enrolls for; measured by
//! the perf rig (build/README.md, D39)

use tessera_karch::KError;

/// Blocked waiters the set can hold at once. A thread blocks in at most one
/// place, so this is sized to the scheduler's thread table
/// (`sched::MAX_THREADS`); kept a local constant to keep this module free of a
/// scheduler dependency.
pub const MAX_WAITERS: usize = 16;

/// The key a waiter blocks on: an address within a specific address space.
/// `space` is the address-space root's physical bits (`0` for a kernel thread,
/// which has no user root); `addr` is the waited virtual address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WaitKey {
    pub space: u64,
    pub addr: u64,
}

/// One blocked waiter: the key it is parked on and its scheduler thread index.
#[derive(Clone, Copy)]
struct Waiter {
    key: WaitKey,
    thread: usize,
}

/// A fixed pool of blocked waiters. No allocation, no overflow beyond the cap
/// (a full set rejects `enroll` with [`KError::OutOfMemory`] rather than
/// silently dropping a waiter).
pub struct WaitSet {
    waiters: [Option<Waiter>; MAX_WAITERS],
}

impl WaitSet {
    pub const fn new() -> Self {
        Self {
            waiters: [const { None }; MAX_WAITERS],
        }
    }

    /// Records that `thread` is blocked on `key`. Returns
    /// [`KError::OutOfMemory`] if the pool is full (the caller must not then
    /// block). The caller is responsible for parking the thread after a
    /// successful enrollment.
    pub fn enroll(&mut self, key: WaitKey, thread: usize) -> Result<(), KError> {
        let slot = self
            .waiters
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.waiters[slot] = Some(Waiter { key, thread });
        Ok(())
    }

    /// Removes and returns one waiter blocked on `key` (lowest slot first), or
    /// `None` if none match. Removing before the woken thread runs guarantees
    /// its enrollment is gone by the time it resumes, so there is no stale
    /// entry and no self-inflicted spurious wake. Wake order among several
    /// waiters on one key is slot order, not a guaranteed FIFO (v0; D37).
    pub fn pop_matching(&mut self, key: WaitKey) -> Option<usize> {
        let slot = self
            .waiters
            .iter()
            .position(|w| matches!(w, Some(entry) if entry.key == key))?;
        let waiter = self.waiters[slot].take();
        waiter.map(|w| w.thread)
    }

    /// Number of enrolled waiters (test/observability helper).
    pub fn len(&self) -> usize {
        self.waiters.iter().filter(|w| w.is_some()).count()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for WaitSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/wait.rs"]
mod tests;
