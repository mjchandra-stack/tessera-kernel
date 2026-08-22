// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Making a thread runnable on a CPU that is not this one.
//!
//! # Why this is a bitmap and not a queue
//!
//! A wakeup carries no information beyond *which thread*. It is idempotent —
//! waking a runnable thread twice is waking it once — and it has no useful
//! order, because the CPU that receives it is about to consult its own run
//! queue and decide for itself. Those two facts make the right structure a
//! **set**, and a set of small integers is a bitmap.
//!
//! That is not a stylistic preference. A queue of this shape needs a
//! compare-and-swap to reserve a slot, a published-marker per slot so the
//! consumer cannot read one that is reserved but not yet written, and a
//! decision about what to do when it is full — three problems a bitmap does
//! not have. Setting a bit is one `fetch_or`; taking every bit is one `swap`.
//! Both are single instructions, neither can fail, and duplicates collapse on
//! their own. The queue would also have to answer "what if two CPUs wake the
//! same thread", and its answer would be "the thread is woken twice".
//!
//! `kcore::atomic::AtomicU64` offers `fetch_or` and `swap` and deliberately
//! does not offer compare-and-swap: on a 32-bit target it is a pair of words
//! and cannot. Choosing the structure that needs neither is what keeps this
//! module the same code on all five ports.
//!
//! # What a bit means
//!
//! Bit `n` in CPU `c`'s bitmap means "the thread in slot `n` of CPU `c`'s
//! scheduler should be considered runnable". A slot is per-CPU, so the pair
//! (CPU, slot) names a thread without a lookup — which is the shape
//! `ThreadId` already has (`kcore::thread`), and the reason this can be a
//! bitmap at all.
//!
//! # The interrupt is not the message
//!
//! [`wake_remote`] posts the bit and *then* interrupts. The two are separate
//! because the bit is the message and the interrupt is only a prompt to look:
//! a target that was already about to look needs no interrupt, and a target
//! that misses the interrupt still finds the bit. Ordering them the other way
//! would let a CPU be interrupted, find nothing, and go back to sleep with the
//! wakeup still to come.
//!
//! Normative: docs/kernel/08-multicore-scalability.md,
//! docs/roadmap/02-smp-bring-up-plan.md ("Phase 3")
//! Budget: none (a `fetch_or` to post, a `swap` per word to drain)

use crate::atomic::AtomicU64;
use crate::percpu::{MAX_CPUS, PerCpu};
use crate::sched::MAX_THREADS;
use core::sync::atomic::Ordering;
use tessera_karch::{Ipi, IpiReason};

/// Bits per word of the bitmap.
const BITS: usize = 64;
/// Words needed to cover one CPU's scheduler slots.
const WORDS: usize = MAX_THREADS.div_ceil(BITS);

/// One bitmap per CPU. Written by any CPU, cleared only by its owner.
static PENDING: [[AtomicU64; WORDS]; MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; WORDS] }; MAX_CPUS];

/// Wakeups each CPU has taken off its own bitmap.
static TAKEN: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Posts a wakeup for the thread in `slot` of `cpu`'s scheduler.
///
/// Returns `false` for a CPU or slot that does not exist — neither is folded
/// into a valid one, because a wakeup delivered to the wrong thread is worse
/// than one not delivered at all.
///
/// Safe, and callable from any CPU including the target itself: setting a bit
/// nobody has cleared yet is the same as setting it once.
pub fn post(cpu: u32, slot: usize) -> bool {
    if cpu >= PerCpu::<u8>::capacity() || slot >= MAX_THREADS {
        return false;
    }
    PENDING[cpu as usize][slot / BITS].fetch_or(1u64 << (slot % BITS), Ordering::Release);
    true
}

/// Takes every wakeup posted for `cpu` and calls `f` with each slot.
///
/// Called by the CPU that owns the bitmap, from its interrupt path. Returns
/// how many there were.
///
/// **A word is taken with one `swap`**, so a wakeup posted while this runs is
/// either taken now or left for the next drain; it cannot be lost between the
/// two. That is the whole of the concurrency argument, and it is why the
/// structure was chosen.
pub fn drain(cpu: u32, mut f: impl FnMut(usize)) -> usize {
    if cpu >= PerCpu::<u8>::capacity() {
        return 0;
    }
    let mut count = 0usize;
    for (word, bits) in PENDING[cpu as usize].iter().enumerate() {
        let mut taken = bits.swap(0, Ordering::Acquire);
        while taken != 0 {
            let bit = taken.trailing_zeros() as usize;
            taken &= taken - 1;
            f(word * BITS + bit);
            count += 1;
        }
    }
    if count > 0 {
        TAKEN[cpu as usize].fetch_add(count as u64, Ordering::Release);
    }
    count
}

/// How many wakeups the CPU at `index` has taken since boot.
pub fn taken(index: u32) -> u64 {
    if index >= PerCpu::<u8>::capacity() {
        return 0;
    }
    TAKEN[index as usize].load(Ordering::Acquire)
}

/// Whether `cpu` has any wakeup posted and not yet taken.
pub fn pending(cpu: u32) -> bool {
    if cpu >= PerCpu::<u8>::capacity() {
        return false;
    }
    PENDING[cpu as usize]
        .iter()
        .any(|bits| bits.load(Ordering::Acquire) != 0)
}

/// Posts a wakeup for another CPU and prompts it to look.
///
/// The post comes first and the interrupt second — see the module header. A
/// send that this port cannot address still leaves the bit set, and the target
/// finds it at its next tick; `false` says the prompt did not go, not that the
/// wakeup was lost.
///
/// # Safety
///
/// As [`Ipi::send`]: the target CPU's interrupt-controller interface must be
/// initialized.
pub unsafe fn wake_remote<I: Ipi>(cpu: u32, slot: usize) -> bool {
    if !post(cpu, slot) {
        return false;
    }
    // SAFETY: the caller's contract.
    unsafe { I::send(cpu, IpiReason::Reschedule) }
}

#[cfg(test)]
#[path = "tests/wakeup.rs"]
mod tests;
