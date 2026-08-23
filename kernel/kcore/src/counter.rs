// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A machine-wide tally that no CPU shares a cache line for.
//!
//! # Why a sum of parts and not one number
//!
//! Three reasons, and only the third is about speed.
//!
//! **It is the only honest 64-bit counter on two of the five targets.** A
//! read-modify-write on a value wider than the machine's widest atomic cannot
//! be one operation; `tessera_karch::atomic` splits its counters by intent for
//! that reason, and the one kind that is safe *everywhere* is the kind with a
//! single writer. Give every CPU its own and every writer is single by
//! construction.
//!
//! **It is reentrancy-safe, which the alternative is not.** The shared counter
//! in `karch::atomic` serializes writers on a sequence word where the target
//! has no 64-bit atomic, and that carries a rule: a writer must not be
//! interrupted by another writer of the same counter. Several of the tallies
//! in this kernel are bumped from interrupt paths — a dropped console write, a
//! contended lock, an unstamped event — so they cannot take that rule.
//! Adding to a per-CPU shard has no critical section to be interrupted inside.
//!
//! **And it does not share a cache line.** `docs/kernel/08` asks for exactly
//! this — "counters shard per CPU with lazy aggregation" — so that a tally
//! bumped on every CPU does not turn one cache line into the machine's
//! bottleneck.
//!
//! # What "lazy" costs
//!
//! [`Sharded::total`] sums the shards as it reads them, so the number it
//! returns is not a snapshot taken at an instant: shards read later may have
//! moved since the ones read earlier. For a tally that only grows, that means
//! the answer is between the true value when the read started and the true
//! value when it ended, which is what a monotonic count means anyway. Nothing
//! here is compared for ordering — the values that are (`crate::epoch`'s
//! generation, `crate::shootdown`'s) use `karch::atomic::SharedCounter`, which
//! is a single number for exactly that reason.
//!
//! Normative: docs/kernel/08-multicore-scalability.md ("Per-CPU by default"),
//! docs/roadmap/02-smp-bring-up-plan.md ("Phase 4")
//! Budget: none (one `fetch_add` to bump, `MAX_CPUS` loads to read)

use crate::percpu::{MAX_CPUS, PerCpu, current_index};
use core::sync::atomic::Ordering;
use tessera_karch::atomic::CpuCounter;

/// A count kept as one tally per CPU and summed when read.
pub struct Sharded {
    shards: [CpuCounter; MAX_CPUS],
}

impl Default for Sharded {
    fn default() -> Self {
        Self::new()
    }
}

impl Sharded {
    pub const fn new() -> Self {
        Self {
            shards: [const { CpuCounter::new(0) }; MAX_CPUS],
        }
    }

    /// Adds one to the calling CPU's shard.
    pub fn bump(&self) {
        self.add(1);
    }

    /// Adds `value` to the calling CPU's shard.
    ///
    /// A CPU index past the ceiling folds to the boot CPU's shard rather than
    /// being dropped: the count is a tally, and losing it would be a worse
    /// answer than attributing it to the wrong CPU — which nothing here reads
    /// separately anyway.
    pub fn add(&self, value: u64) {
        let index = current_index();
        let index = if index < PerCpu::<u8>::capacity() {
            index as usize
        } else {
            crate::percpu::BOOT_CPU as usize
        };
        self.shards[index].add(value, Ordering::Relaxed);
    }

    /// The machine-wide total.
    pub fn total(&self) -> u64 {
        self.shards.iter().fold(0u64, |sum, shard| {
            sum.saturating_add(shard.get(Ordering::Acquire))
        })
    }

    /// The total, leaving every shard at zero.
    ///
    /// Shard by shard, so a bump that lands between two of them is counted in
    /// the *next* read rather than lost. For the one caller — a boot reporting
    /// how much it dropped before its console existed — that is the whole of
    /// what has to be true.
    pub fn take(&self) -> u64 {
        let mut total = 0u64;
        for shard in &self.shards {
            total = total.saturating_add(shard.get(Ordering::Acquire));
            shard.set(0, Ordering::Release);
        }
        total
    }

    /// This CPU's own shard, for a test that wants to read what it wrote
    /// without depending on the others being empty.
    #[cfg(test)]
    pub fn here(&self) -> u64 {
        self.shards[current_index() as usize].get(Ordering::Acquire)
    }
}

#[cfg(test)]
#[path = "tests/counter.rs"]
mod tests;
