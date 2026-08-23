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
//! docs/roadmap/02-smp-bring-up-plan.md ("Phase 3"), build/README.md D227
//! (the mechanism), D245 (its callers)
//! Budget: none (the wait is the cost, and it is the caller's)

use crate::atomic::AtomicU64;
use crate::atomic::{CpuCounter, SharedCounter};
use crate::percpu::{MAX_CPUS, PerCpu};
use core::sync::atomic::{AtomicPtr, Ordering};
use tessera_karch::{Ipi, IpiReason};

/// The generation a requester most recently asked for.
static REQUESTED: SharedCounter = SharedCounter::new(0);

/// The generation each CPU has flushed to. Zero until it has flushed at all.
static ACKED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// How many shootdowns each CPU has serviced, for a boot check to read.
static SERVICED: [CpuCounter; MAX_CPUS] = [const { CpuCounter::new(0) }; MAX_CPUS];

/// This port's way of interrupting another CPU for a shootdown, installed once
/// at boot, and the bound a requester waits within.
///
/// **Why an installed function and not a type parameter.** The callers that
/// need this are `crate::vm`'s unmap paths, and an [`AddressSpace`] is generic
/// over [`AddressSpaceOps`] and nothing else. Threading an [`Ipi`] parameter
/// through every mapping operation to reach one call is the tail wagging the
/// dog, so the port installs its sender once — the same shape
/// [`crate::wakeup::install_prompt`] and [`crate::percpu::install_index_source`]
/// have, and for the same reason: a fact about the machine that neutral code
/// needs and cannot name.
///
/// The bound comes with it because the port is what knows its own scale; a
/// number invented here would be a guess about somebody else's machine.
/// `SPINS` is stored first and `SENDER` last, so a reader that sees a sender
/// sees the bound installed with it.
///
/// [`AddressSpace`]: crate::vm::AddressSpace
/// [`AddressSpaceOps`]: tessera_karch::AddressSpaceOps
static SENDER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static SPINS: AtomicU64 = AtomicU64::new(0);

/// Shootdowns that went out and were acknowledged by every target.
static COMPLETED: crate::counter::Sharded = crate::counter::Sharded::new();

/// Shootdowns that were wanted and did not complete.
///
/// Three causes, counted as one because the caller's position is identical in
/// all three: a CPU may still be able to translate to memory this one has
/// stopped protecting. No sender installed on a port that started secondaries,
/// a target the sender could not address, and a target that never answered
/// within the bound are all that.
static INCOMPLETE: crate::counter::Sharded = crate::counter::Sharded::new();

/// Installs the port's way of interrupting another CPU for a shootdown, and
/// the bound a requester waits for the acknowledgement within.
///
/// # Safety
///
/// The boot CPU, once, after the interrupt controller is up, with `send` a
/// function whose [`Ipi::send`] obligations are met for every CPU this kernel
/// has started, delivering [`IpiReason::TlbShootdown`]. `spins` must outlast a
/// target's worst-case time to reach its interrupt handler; a bound shorter
/// than that turns a working shootdown into a counted failure.
pub unsafe fn install_sender(send: Sender, spins: u64) {
    SPINS.store(spins, Ordering::Release);
    SENDER.store(send as *mut (), Ordering::Release);
}

/// Interrupts the CPU at this index for a shootdown, reporting whether the
/// send went. The port's half, as a function rather than an [`Ipi`] — see
/// [`SENDER`].
type Sender = fn(u32) -> bool;

/// The installed sender and its bound, or `None` while no port has installed
/// one.
fn installed() -> Option<(Sender, u64)> {
    let send = SENDER.load(Ordering::Acquire);
    if send.is_null() {
        return None;
    }
    // SAFETY: non-null only because `install_sender` stored a `fn(u32) -> bool`
    // there, and the release/acquire pair publishes it along with the bound
    // stored ahead of it.
    let send: Sender = unsafe { core::mem::transmute::<*mut (), Sender>(send) };
    Some((send, SPINS.load(Ordering::Acquire)))
}

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
    // SAFETY: the caller's contract, restated for each target by the closure.
    send_and_wait(targets, spins, |index| unsafe {
        I::send(index, IpiReason::TlbShootdown)
    })
}

/// Asks every CPU in `targets` through the sender the port installed.
///
/// The form [`crate::vm`] uses, because it cannot name an [`Ipi`]. Safe, for
/// the reason [`crate::wakeup::wake`] is: the obligation was discharged once at
/// [`install_sender`] rather than at every call.
///
/// **A `false` here is counted, not returned to a caller who could act on it.**
/// An unmap that has already happened cannot be undone by learning that a CPU
/// did not answer, and the mapping state the caller is told about would be a
/// lie either way. So the failure goes to [`INCOMPLETE`] and the boot line, per
/// `docs/lifecycle/04-coding-guidelines.md`'s "No Silent Fallback" — a kernel
/// that could not complete a shootdown says how many times.
pub fn request_here(targets: u64) -> bool {
    if targets == 0 {
        return true;
    }
    let Some((send, spins)) = installed() else {
        // A port with no secondaries never reaches here, because `targets` is
        // empty on a machine with one CPU. Reaching here means a port started
        // CPUs and did not install a sender, which is a defect and not a
        // configuration.
        INCOMPLETE.bump();
        return false;
    };
    let completed = send_and_wait(targets, spins, send);
    if completed {
        COMPLETED.bump();
    } else {
        INCOMPLETE.bump();
    }
    completed
}

/// Sends to every target and waits for all of them to publish the generation.
///
/// The generation is taken *before* the first send and the wait is for every
/// target to reach it, so a target that services two requests as one satisfies
/// both — see the module header.
fn send_and_wait(targets: u64, spins: u64, send: impl Fn(u32) -> bool) -> bool {
    if targets == 0 {
        return true;
    }
    let generation = REQUESTED.fetch_add(1, Ordering::AcqRel) + 1;

    let mut addressed = true;
    for index in 0..PerCpu::<u8>::capacity() {
        if targets & (1u64 << index) == 0 {
            continue;
        }
        // A send that did not go is a target that will never acknowledge, so
        // waiting the full bound for it would turn one defect into a stall.
        addressed &= send(index);
    }
    if !addressed {
        return false;
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

/// Shootdowns every target acknowledged.
pub fn completed() -> u64 {
    COMPLETED.total()
}

/// Shootdowns that were wanted and did not complete. Zero, or a CPU somewhere
/// can still reach memory this one has stopped protecting.
pub fn incomplete() -> u64 {
    INCOMPLETE.total()
}

/// Emits the boot line, returning the claim keys a boot check should assert.
///
/// **The claim is about the failures, not the successes.** A port whose
/// invalidate broadcasts completes none of these and is entirely correct, so
/// "some shootdowns happened" is not a property every port has; "none of the
/// ones that were needed went unanswered" is.
pub fn report() -> &'static [&'static str] {
    let (completed, incomplete) = (completed(), incomplete());
    crate::event::emit(
        crate::event::EventKind::TlbShootdown,
        if incomplete == 0 {
            crate::event::Severity::Info
        } else {
            crate::event::Severity::Error
        },
        crate::event::Component::Memory,
        [completed, incomplete, 0, 0],
    );
    crate::kprintln!(
        "vm: {} shootdown(s) acknowledged by every target, {} unanswered",
        completed,
        incomplete
    );
    if incomplete == 0 {
        &["vm.shootdowns-answered"]
    } else {
        &[]
    }
}

/// Forgets everything recorded. Tests only — these are process-wide.
#[cfg(test)]
pub fn forget() {
    COMPLETED.take();
    INCOMPLETE.take();
    SENDER.store(core::ptr::null_mut(), Ordering::Release);
    SPINS.store(0, Ordering::Release);
}

#[cfg(test)]
#[path = "tests/shootdown.rs"]
mod tests;
