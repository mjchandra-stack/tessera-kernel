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
//! word is read by the arch/syscall entry — which is now asked to read it
//! *when* the executive says, rather than beforehand (see
//! `Executive::wait_on_address`).
//!
//! # The key is the memory, not the name for it
//!
//! A key is `(frame, offset)`: the **physical** frame the word lives in and
//! its byte offset within that frame. It used to be `(address-space root,
//! virtual address)`, which names the same word differently in every process
//! that maps it — so two processes sharing a page could not wake each other,
//! and the same process mapping a page twice could not wake itself through the
//! other mapping. A futex is a lock on a *word of memory*, and the only name
//! for a word of memory that every holder agrees on is where it physically is.
//!
//! **kcore still does not translate.** The caller supplies the physical
//! address, exactly as it supplies the word, because the address space and the
//! validation of the pointer belong to the syscall entry. What this module
//! decides is only what a key is.
//!
//! One property is lost with the old key and is worth naming: it was an
//! ambient capability check, in that a thread could only wake something in a
//! space it had a root for. It never was one — the root is a number the caller
//! passes — and a real one belongs in the handle table, not in a futex key.
//!
//! Normative: docs/kernel/04-synchronization-and-ipc-guarantees.md
//! ("Wait-On-Address")
//! Budget: B6 (contended wake) — the mechanism this enrolls for; measured by
//! the perf rig (build/README.md, D39)

use crate::thread::ThreadId;
use tessera_karch::KError;

/// Blocked waiters the set can hold at once. A thread blocks in at most one
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_WAITERS;

/// The key a waiter blocks on: a word of physical memory.
///
/// `frame` is the physical frame number and `offset` the byte offset within
/// it. Split rather than kept as one physical address so that the pair reads
/// as what it is — a page and a word inside it — and so a caller that has a
/// `PhysFrame` in hand does not have to reassemble an address to be taken
/// apart again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WaitKey {
    pub frame: u64,
    pub offset: u64,
}

impl WaitKey {
    /// The key for the word at physical address `phys`.
    pub const fn at(phys: u64) -> Self {
        Self {
            frame: phys / tessera_karch::FRAME_SIZE,
            offset: phys % tessera_karch::FRAME_SIZE,
        }
    }
}

/// One blocked waiter: the key it is parked on and the identity of the thread
/// parked there.
///
/// The identity, not the scheduler slot. A slot belongs to one CPU and is
/// reused the moment its thread is reaped, so a set that outlives either would
/// wake whichever thread inherited the number
/// (`docs/roadmap/02-smp-bring-up-plan.md`, Phase 1d).
#[derive(Clone, Copy)]
struct Waiter {
    key: WaitKey,
    thread: ThreadId,
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
    pub fn enroll(&mut self, key: WaitKey, thread: ThreadId) -> Result<(), KError> {
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
    pub fn pop_matching(&mut self, key: WaitKey) -> Option<ThreadId> {
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
