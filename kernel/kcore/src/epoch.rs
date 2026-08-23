// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Knowing when nobody can still be looking at something.
//!
//! `docs/kernel/08-multicore-scalability.md` mandates **one** epoch-based
//! reclamation facility — "the Rust equivalent of RCU" — as the standard
//! mechanism, and says ad hoc lock-free schemes are not accepted where it
//! suffices. This is it. The structures it exists for are the ones every
//! syscall reads and almost nothing writes: handle tables, the resource-graph
//! view, policy inputs, topology.
//!
//! # The question it answers
//!
//! A writer that has unlinked something needs to know when the memory can be
//! reused. Not "has anyone got a reference" — nothing counts references on the
//! read path, which is the point — but the weaker and cheaper question: *has
//! every CPU passed through a moment where it demonstrably held none?*
//!
//! That moment is a **quiescent state**, and this facility is the
//! quiescent-state flavour of the idea rather than the pinned-epoch one. A
//! reader takes no atomic and writes nothing shared; it only refrains from
//! quiescing while it holds a reference. The whole read-side cost is a counter
//! this CPU alone touches, which is what lets a handle check on the syscall
//! path perform no shared writes at all.
//!
//! # What a writer waits for
//!
//! [`advance`] bumps a global counter and returns the value a grace period must
//! reach. [`wait_for_grace`] returns once every **online** CPU has quiesced at
//! or after that value. Offline CPUs are not waited for and could not be: a CPU
//! that has never run cannot hold a reference, and waiting for it would stall
//! reclamation for ever on every machine with a spare slot.
//!
//! # The obligation this puts on a reader
//!
//! **A CPU that never quiesces stalls reclamation for ever.** That is the
//! standing cost of the design and it cannot be checked for, only arranged: a
//! read-side section must be bounded, must not block, and must not span a
//! context switch. The places a CPU is quiescent by construction — an idle
//! loop, the moment after a syscall returns, a scheduler tick with nothing
//! held — are where [`quiesce`] belongs, and they are cheap because they are
//! places where nothing is in hand anyway.
//!
//! Normative: docs/kernel/08-multicore-scalability.md, build/README.md D14
//! Budget: none (the read side is one local counter; the wait is the writer's)

use crate::atomic::AtomicU64;
use crate::atomic::SharedCounter;
use crate::percpu::{MAX_CPUS, PerCpu};
use core::sync::atomic::Ordering;

/// The counter a writer bumps. Readers observe it; nobody else writes it.
static GLOBAL: SharedCounter = SharedCounter::new(1);

/// The value each CPU last observed while holding nothing.
static SEEN: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// How deep this CPU is inside read-side sections. Written and read by that
/// CPU alone — it is not synchronisation, it is a note to self.
static DEPTH: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Brings a CPU into the scheme, as of now.
///
/// Called by a CPU as it comes online. Starting it at the current value rather
/// than at zero is what stops a freshly started CPU from looking like one that
/// has been asleep since boot — which would make every grace period since then
/// appear unfinished.
pub fn attach(index: u32) {
    if index >= PerCpu::<u8>::capacity() {
        return;
    }
    SEEN[index as usize].store(GLOBAL.load(Ordering::Acquire), Ordering::Release);
}

/// Enters a read-side section on this CPU. The returned guard leaves it.
///
/// Takes no lock and writes nothing another CPU reads. Its only effect is that
/// this CPU will not report itself quiescent until the guard is dropped.
pub fn read() -> ReadGuard {
    let index = crate::percpu::current_index();
    if index < PerCpu::<u8>::capacity() {
        let depth = &DEPTH[index as usize];
        depth.store(depth.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    }
    ReadGuard { index }
}

/// A live read-side section. Dropping it ends the section.
pub struct ReadGuard {
    index: u32,
}

impl Drop for ReadGuard {
    fn drop(&mut self) {
        if self.index < PerCpu::<u8>::capacity() {
            let depth = &DEPTH[self.index as usize];
            let now = depth.load(Ordering::Relaxed);
            depth.store(now.saturating_sub(1), Ordering::Relaxed);
        }
    }
}

/// Reports this CPU as holding nothing, if it is in fact holding nothing.
///
/// A no-op inside a read-side section, which is the whole of the read side's
/// protection: a CPU cannot accidentally declare itself quiescent while it
/// still has a reference, because the declaration checks.
pub fn quiesce() {
    let index = crate::percpu::current_index();
    if index >= PerCpu::<u8>::capacity() || DEPTH[index as usize].load(Ordering::Relaxed) != 0 {
        return;
    }
    SEEN[index as usize].store(GLOBAL.load(Ordering::Acquire), Ordering::Release);
}

/// Starts a grace period, returning the value every CPU must reach.
pub fn advance() -> u64 {
    GLOBAL.fetch_add(1, Ordering::AcqRel) + 1
}

/// Whether every online CPU has quiesced at or after `epoch`.
pub fn grace_reached(epoch: u64) -> bool {
    for index in 0..PerCpu::<u8>::capacity() {
        if !crate::smp::cpu(index).is_some_and(|state| state.online) {
            continue;
        }
        if SEEN[index as usize].load(Ordering::Acquire) < epoch {
            return false;
        }
    }
    true
}

/// Waits until every online CPU has quiesced at or after `epoch`.
///
/// `false` means one had not within `spins` — which the caller must treat as
/// the memory still being reachable. There is no partial answer here: a grace
/// period that has not completed says nothing about which CPU is late, and a
/// caller that reused the memory anyway would be reusing it under a reader.
pub fn wait_for_grace(epoch: u64, spins: u64) -> bool {
    let mut left = spins;
    while !grace_reached(epoch) {
        if left == 0 {
            return false;
        }
        left -= 1;
        core::hint::spin_loop();
    }
    true
}

/// The value the CPU at `index` last quiesced at.
pub fn seen(index: u32) -> u64 {
    if index >= PerCpu::<u8>::capacity() {
        return 0;
    }
    SEEN[index as usize].load(Ordering::Acquire)
}

#[cfg(test)]
#[path = "tests/epoch.rs"]
mod tests;
