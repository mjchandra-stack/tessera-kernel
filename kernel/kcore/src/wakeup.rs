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
//! # What a bit means, and why a bit is not enough
//!
//! Bit `n` in CPU `c`'s bitmap means "the thread in slot `n` of CPU `c`'s
//! scheduler should be considered runnable". A slot is per-CPU, so the pair
//! (CPU, slot) names a thread without a lookup — which is the shape
//! `ThreadId` already has (`kcore::thread`), and the reason this can be a
//! bitmap at all.
//!
//! **A slot alone names the wrong thread eventually.** It is reused the moment
//! its occupant is reaped, so a wakeup posted for the thread that was in slot 3
//! and taken after that thread exited would make a *stranger* runnable — the
//! same staleness `Scheduler::index_of` exists to refuse, arriving by a
//! different road. So each bit carries the identity it was posted for, stored
//! before the bit and checked by the CPU that takes it
//! (`Scheduler::unblock_thread`). The identity is what the waker had in the
//! first place; the slot is only how to find it quickly.
//!
//! Nothing about the structure changes: a store and a `fetch_or` to post, a
//! `swap` and a load to take, still no compare-and-swap. Two wakes for the same
//! slot with different identities can only mean the slot was reused between
//! them, and the older of the two is a wake for a thread that no longer exists.
//!
//! # Prompting a CPU without naming its port
//!
//! Sending the interrupt needs `Ipi`, which is a *type*, and the code that
//! wants to wake a thread — `kcore::exec` — is generic over a context switch
//! and nothing else. Threading a second type parameter through the executive
//! to reach one function is the tail wagging the dog, so the port installs its
//! sender once at boot ([`install_prompt`]) and [`wake`] uses it. This is the
//! same shape `kcore::percpu::install_index_source` has, for the same reason:
//! a fact about the machine that neutral code needs and cannot name.
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
use crate::thread::ThreadId;
use core::sync::atomic::{AtomicPtr, Ordering};
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

/// The identity each pending bit was posted for.
///
/// Written before the bit and read after it, so a CPU that sees the bit sees
/// the identity that goes with it. [`ThreadId::UNASSIGNED`] means "no identity
/// to check" — what the bring-up probe posts, since it is testing that a bit
/// crosses and has no thread to name.
static PENDING_ID: [[AtomicU64; MAX_THREADS]; MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; MAX_THREADS] }; MAX_CPUS];

/// Wakeups posted to a CPU other than the one posting them.
///
/// The observable that says the cross-CPU path was actually taken. A round
/// trip that completed says nothing on its own — it completes identically when
/// both ends happen to be on one CPU — so a check that a call *crossed* has to
/// read this rather than the result.
static CROSSINGS: AtomicU64 = AtomicU64::new(0);

/// This port's way of interrupting another CPU, installed once at boot.
///
/// A `fn(u32) -> bool` and not an `Ipi` implementation, because the caller
/// that needs it cannot name a type — see the module header.
static PROMPT: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Installs the port's way of prompting another CPU to look at its bitmap.
///
/// # Safety
///
/// The boot CPU, once, after the interrupt controller is up, with `send` a
/// function whose `Ipi::send` obligations are met for every CPU this kernel
/// has started.
pub unsafe fn install_prompt(send: fn(u32) -> bool) {
    PROMPT.store(send as *mut (), Ordering::Release);
}

/// Prompts `cpu` to look, or `false` if this port installed no sender.
fn prompt(cpu: u32) -> bool {
    let installed = PROMPT.load(Ordering::Acquire);
    if installed.is_null() {
        return false;
    }
    // SAFETY: non-null only because `install_prompt` stored a `fn(u32) -> bool`
    // there, and the release/acquire pair publishes it.
    let send: fn(u32) -> bool =
        unsafe { core::mem::transmute::<*mut (), fn(u32) -> bool>(installed) };
    send(cpu)
}

/// Posts a wakeup for the thread in `slot` of `cpu`'s scheduler.
///
/// Returns `false` for a CPU or slot that does not exist — neither is folded
/// into a valid one, because a wakeup delivered to the wrong thread is worse
/// than one not delivered at all.
///
/// Safe, and callable from any CPU including the target itself: setting a bit
/// nobody has cleared yet is the same as setting it once.
pub fn post(cpu: u32, slot: usize, id: ThreadId) -> bool {
    if cpu >= PerCpu::<u8>::capacity() || slot >= MAX_THREADS {
        return false;
    }
    // The identity first and the bit second, so a CPU that sees the bit sees
    // the identity it belongs to — the same ordering rule the handoff slot
    // uses, for the same reason.
    PENDING_ID[cpu as usize][slot].store(id.0, Ordering::Release);
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
pub fn drain(cpu: u32, mut f: impl FnMut(usize, ThreadId)) -> usize {
    if cpu >= PerCpu::<u8>::capacity() {
        return 0;
    }
    let mut count = 0usize;
    for (word, bits) in PENDING[cpu as usize].iter().enumerate() {
        let mut taken = bits.swap(0, Ordering::Acquire);
        while taken != 0 {
            let bit = taken.trailing_zeros() as usize;
            taken &= taken - 1;
            let slot = word * BITS + bit;
            f(
                slot,
                ThreadId(PENDING_ID[cpu as usize][slot].load(Ordering::Acquire)),
            );
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
pub unsafe fn wake_remote<I: Ipi>(cpu: u32, slot: usize, id: ThreadId) -> bool {
    if !post(cpu, slot, id) {
        return false;
    }
    // SAFETY: the caller's contract.
    unsafe { I::send(cpu, IpiReason::Reschedule) }
}

/// Makes the thread `id` — in `slot` of `cpu`'s scheduler — runnable, and
/// prompts that CPU to look.
///
/// The same thing [`wake_remote`] does, through the sender the port installed
/// rather than one the caller names. `false` says the bit was not posted at all
/// (a CPU or slot that does not exist) **or** that no prompt went; the two are
/// distinguished by nothing here on purpose, because the caller's next move is
/// the same either way — the bit, if posted, is found at the target's next
/// pass whether or not it was prompted.
pub fn wake(cpu: u32, slot: usize, id: ThreadId) -> bool {
    if !post(cpu, slot, id) {
        return false;
    }
    if cpu != crate::percpu::current_index() {
        CROSSINGS.fetch_add(1, Ordering::Release);
    }
    prompt(cpu)
}

/// How many wakeups have been posted to a CPU other than the one posting.
pub fn crossings() -> u64 {
    CROSSINGS.load(Ordering::Acquire)
}

#[cfg(test)]
#[path = "tests/wakeup.rs"]
mod tests;
