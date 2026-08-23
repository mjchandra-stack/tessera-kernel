// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Making the other CPUs drop a translation, and waiting until they have.
//!
//! # Why the sender waits, when the wakeup does not
//!
//! A cross-CPU wakeup is advisory: the target looks when it gets round to it,
//! and nothing is wrong in the meantime. This is the opposite. The sender is
//! about to reuse the frame the translation pointed at, and until every CPU
//! that could still translate to it has stopped, that frame is reachable from
//! a CPU which has no idea it was freed. So the sender blocks, and what it
//! blocks on is an acknowledgement from each target rather than an elapsed
//! time or a hope.
//!
//! # A generation, not a queue of addresses
//!
//! The protocol is two numbers. A requester takes the next generation; each
//! target, when it services the interrupt, drops **every** cached translation
//! it has and publishes the generation it has reached. The requester waits
//! until every target's published number is at least its own.
//!
//! Dropping everything rather than one page is deliberate for now and it is a
//! cost, not a subtlety: a per-address queue would need a bound, a policy for
//! overflow, and a decision about what a target does when it overflows —
//! whose only correct answer is to drop everything anyway. Starting from the
//! answer the overflow path needs means the mechanism has one behaviour rather
//! than two, and the narrower one is an optimisation with a measurement behind
//! it, which there is not yet.
//!
//! **A late target is not a lost one.** A CPU that services two requests as one
//! publishes the higher generation, and both requesters are satisfied by it —
//! correctly, because the flush it performed covers both. That collapsing is
//! what makes a counter the right structure and a queue the wrong one.
//!
//! Normative: docs/kernel/08-multicore-scalability.md,
//! docs/roadmap/02-smp-bring-up-plan.md ("Phase 3")
//! Budget: none (the wait is the cost, and it is the caller's)

use crate::atomic::AtomicU64;
use crate::atomic::{CpuCounter, SharedCounter};
use crate::percpu::{MAX_CPUS, PerCpu};
use core::sync::atomic::Ordering;
use tessera_karch::{Ipi, IpiReason};

/// The generation a requester most recently asked for.
static REQUESTED: SharedCounter = SharedCounter::new(0);

/// The generation each CPU has flushed to. Zero until it has flushed at all.
static ACKED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// How many shootdowns each CPU has serviced, for a boot check to read.
static SERVICED: [CpuCounter; MAX_CPUS] = [const { CpuCounter::new(0) }; MAX_CPUS];

/// Asks every CPU in `targets` to drop its cached translations, and waits.
///
/// Returns `true` when every target acknowledged. An empty target set is
/// `true` immediately and sends nothing — which is the whole of what a
/// broadcasting architecture costs, and why
/// [`AddressSpaceOps::INVALIDATE_IS_BROADCAST`](tessera_karch::AddressSpaceOps::INVALIDATE_IS_BROADCAST)
/// is a constant: on such a port `targets` is empty by construction and this
/// call is a branch the optimizer removes.
///
/// `false` means a target did not answer within `spins`. The caller must treat
/// that as the frame still being reachable — it is the one failure here that
/// cannot be reported and continued past.
///
/// # Safety
///
/// Every CPU named in `targets` must be able to take the interrupt and service
/// it — see [`Ipi::send`] — or this waits out its bound and reports failure.
pub unsafe fn request<I: Ipi>(targets: u64, spins: u64) -> bool {
    if targets == 0 {
        return true;
    }
    let generation = REQUESTED.fetch_add(1, Ordering::AcqRel) + 1;

    for index in 0..PerCpu::<u8>::capacity() {
        if targets & (1u64 << index) == 0 {
            continue;
        }
        // SAFETY: the caller's contract.
        unsafe { I::send(index, IpiReason::TlbShootdown) };
    }

    let mut left = spins;
    loop {
        let mut outstanding = false;
        for index in 0..PerCpu::<u8>::capacity() {
            if targets & (1u64 << index) == 0 {
                continue;
            }
            if ACKED[index as usize].load(Ordering::Acquire) < generation {
                outstanding = true;
                break;
            }
        }
        if !outstanding {
            return true;
        }
        if left == 0 {
            return false;
        }
        left -= 1;
        core::hint::spin_loop();
    }
}

/// Services a shootdown on this CPU: drops what `flush` drops, then says so.
///
/// `flush` is the port's, because "every cached translation" is an instruction
/// this layer does not have. It is called before the acknowledgement and never
/// after — a CPU that published first and flushed second would be telling a
/// requester the frame is safe while it can still reach it.
///
/// # Safety
///
/// Called from the interrupt path of the CPU that `index` names, and `flush`
/// must actually drop every translation this CPU has cached.
pub unsafe fn service_here(index: u32, flush: impl FnOnce()) {
    if index >= PerCpu::<u8>::capacity() {
        return;
    }
    let generation = REQUESTED.load(Ordering::Acquire);
    flush();
    SERVICED[index as usize].add(1, Ordering::Relaxed);
    ACKED[index as usize].store(generation, Ordering::Release);
}

/// How many shootdowns the CPU at `index` has serviced.
pub fn serviced(index: u32) -> u64 {
    if index >= PerCpu::<u8>::capacity() {
        return 0;
    }
    SERVICED[index as usize].get(Ordering::Relaxed)
}

#[cfg(test)]
#[path = "tests/shootdown.rs"]
mod tests;
