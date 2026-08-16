// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Correlation identity: who caused the work a structured event belongs to.
//!
//! `docs/observability/02` ("Correlation IDs, Normatively") defines one model,
//! "ending per-subsystem improvisation": a correlation id is a 128-bit value
//! **minted at a causal origin** — whoever converts the outside world into work
//! mints it — and propagation is automatic where the kernel can see causality:
//! "a thread carries a current correlation ID; synchronous calls and reply
//! delegations propagate it to the callee for the duration of handling". When one
//! cause fans out, each branch mints a *fresh* id and emits a **link event**
//! naming the parent, so traces form a tree rather than an ambiguous set sharing
//! one id.
//!
//! This module owns the id itself and the ambient "what is running now" context
//! that [`crate::event`] stamps onto every record. It deliberately does not
//! depend on the event ring, so [`crate::sched`] and [`crate::exec`] can carry
//! identity without pulling observability into the switch path.
//!
//! # The id is `(epoch, sequence)`
//!
//! The high half is a per-boot **epoch**, installed once by boot glue; the low
//! half is a monotonic **sequence** from [`mint`]. Splitting it this way is what
//! makes the ambient publish safe rather than merely convenient: because the
//! epoch never changes after boot, publishing the current id is a *single*
//! [`AtomicU64`] store, so it cannot tear and it takes no lock. A `SpinLock<u128>`
//! would deadlock outright — the timer tick reaches this module through
//! `on_tick` → `switch_to`, so a lock held by the interrupted code could never be
//! released.
//!
//! The design requires 128 bits and freshness; it never requires unpredictability
//! (and its VM-boundary clause is explicit that no host semantics depend on an
//! id). A monotonic counter is therefore the mechanism, not a degraded stand-in
//! for one — there is no kernel CSPRNG to degrade *from*, and `hw_random` is
//! RDRAND-gated and absent on the CI CPU model (build/README.md, D6/D59).
//!
//! # Staleness under interrupt
//!
//! The published context is updated inside `Scheduler::switch_to` next to
//! `self.current`. A timer tick landing between the publish and the register
//! switch leaves the ambient context briefly describing the outgoing thread —
//! exactly the existing exposure of `Scheduler::current`, and no worse. Events
//! emitted in that window are attributed to the wrong thread; they are never
//! torn, and no ordering depends on the value.
//!
//! Normative: docs/observability/02-collection-persistence-and-telemetry.md
//! ("Correlation IDs, Normatively")
//! Budget: none (a relaxed atomic load per emitted event)

use crate::atomic::AtomicU64;
use core::sync::atomic::Ordering;

/// The identity an event is stamped with: the thread and process that were
/// running, and the causal id that work belongs to.
///
/// The correlation is the *sequence* half; [`epoch`] supplies the high half when
/// the full 128-bit id is written to a record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TraceContext {
    /// The running thread's id, or 0 when no thread is current (boot context).
    pub thread_id: u64,
    /// The running thread's owning process, or 0 for a kernel thread.
    pub process_id: u64,
    /// The causal id this work belongs to, or 0 before any origin has minted.
    pub correlation: u64,
}

impl TraceContext {
    /// The empty context: no thread, no process, no cause — what the boot
    /// context publishes and what events carry before an origin mints.
    pub const NONE: Self = Self {
        thread_id: 0,
        process_id: 0,
        correlation: 0,
    };
}

/// The high half of every correlation id minted this boot.
static EPOCH: AtomicU64 = AtomicU64::new(0);
/// The next sequence to hand out. Starts at 1 so 0 stays "no cause".
static NEXT: AtomicU64 = AtomicU64::new(1);

static CURRENT_CORRELATION: AtomicU64 = AtomicU64::new(0);
static CURRENT_THREAD: AtomicU64 = AtomicU64::new(0);
static CURRENT_PROCESS: AtomicU64 = AtomicU64::new(0);

/// Installs the per-boot epoch (the id's high half). Boot glue calls this once,
/// before the first origin mints; until then ids carry epoch 0.
pub fn set_epoch(epoch: u64) {
    EPOCH.store(epoch, Ordering::Relaxed);
}

/// The per-boot epoch — the high half of every id minted this boot.
pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Relaxed)
}

/// Mints a fresh causal id at an origin (or for a fan-out branch). Never returns
/// 0, which is reserved for "no cause".
pub fn mint() -> u64 {
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Publishes the running context. Called by the scheduler as the current thread
/// changes; each field is a single relaxed store (see the module header on
/// staleness).
pub fn set_current(cx: TraceContext) {
    CURRENT_THREAD.store(cx.thread_id, Ordering::Relaxed);
    CURRENT_PROCESS.store(cx.process_id, Ordering::Relaxed);
    CURRENT_CORRELATION.store(cx.correlation, Ordering::Relaxed);
}

/// Sets only the ambient causal id, leaving thread and process identity alone —
/// what an origin does when it converts an external stimulus into work while
/// already running as some thread.
pub fn set_current_correlation(correlation: u64) {
    CURRENT_CORRELATION.store(correlation, Ordering::Relaxed);
}

/// The running context, as stamped onto every emitted event.
pub fn current() -> TraceContext {
    TraceContext {
        thread_id: CURRENT_THREAD.load(Ordering::Relaxed),
        process_id: CURRENT_PROCESS.load(Ordering::Relaxed),
        correlation: CURRENT_CORRELATION.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
#[path = "tests/trace.rs"]
mod tests;
