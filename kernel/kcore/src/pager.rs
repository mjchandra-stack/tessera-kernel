// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel's page cache for one pager-backed memory object: which of its
//! pages are resident, and which are dirty. This is the accounting the
//! write-back and eviction rules of docs/kernel/03 operate on:
//!
//! - Dirty tracking is "maintained by the kernel using page-table dirty bits or
//!   **software emulation** where hardware lacks them" (L96) — v0 is software:
//!   a page is supplied read-only, and the write fault that first touches it is
//!   what marks it dirty (the flip is done by `vm.rs`; this module records it).
//! - "A producer that dirties faster than its pager writes back is **throttled
//!   at the write fault**" (L133) — [`mark_dirty`](ObjectCache::mark_dirty)
//!   returns [`DirtyOutcome::Throttle`] once the per-object dirty bound is hit.
//! - "The kernel never marks a page clean before acknowledgment" (L138) — the
//!   caller only calls [`mark_clean`](ObjectCache::mark_clean) after the pager
//!   acks a write-back.
//! - Eviction reclaims **clean** pages (L95); [`evict_candidate`](ObjectCache::
//!   evict_candidate) never offers a dirty one.
//! - On pager death, bound objects enter a faulted state and the lost dirty
//!   ranges are reported exactly (L105) — [`fault`](ObjectCache::fault).
//!
//! Alongside the per-object cache, this module holds the paging failure-model
//! guards the pager-pressure harness exercises (scenarios S3/S5/S7, D55):
//! [`WriteBackReservation`] (reclaim-deadlock — write-back reservation),
//! [`SelfPagingGraph`] (self-paging cycle detection), and [`PageInSupervisor`]
//! (page-in deadline + supervision). The forbidden outcome for all is a hang.
//!
//! Pure accounting — no frames, no arch, no scheduler — so it is host-tested.
//! `vm.rs` performs the matching page-table operations (supply read-only, grant
//! write, evict); the harness (`main.rs`) drives the write-back IPC. v0 is one
//! mapping per object (build/README.md, D41).
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Write-Back And
//! Eviction Flow", "Write-Back Under Memory Pressure", "Anti-Deadlock Rules",
//! "Page-In Flow")
//! Budget: B10 (page-in) — the path this feeds; measured under pressure by the
//! pager-pressure harness (docs/prototypes/02)

use crate::event;
use crate::isl_binding::event::{Component, EventKind, Severity};
use tessera_karch::KError;

/// Resident pages a single object's cache tracks this milestone (bounded, like
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_CACHED_PAGES;

/// The result of a write marking a page dirty.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirtyOutcome {
    /// The page is dirty and within the object's dirty bound — grant the write.
    Marked,
    /// Marking this page dirty would exceed the dirty bound: the writer must be
    /// throttled at the write fault until a write-back drains dirty pages
    /// (docs/kernel/03, "Dirty throttling"). The page is left clean.
    Throttle,
}

#[derive(Clone, Copy)]
struct PageEntry {
    offset: u64,
    dirty: bool,
}

/// One pager-backed object's resident/dirty page set with a dirty ceiling.
pub struct ObjectCache {
    pages: [Option<PageEntry>; MAX_CACHED_PAGES],
    dirty_limit: u32,
    faulted: bool,
}

impl ObjectCache {
    /// A cache admitting at most `dirty_limit` simultaneously-dirty pages before
    /// throttling writers.
    pub const fn new(dirty_limit: u32) -> Self {
        Self {
            pages: [const { None }; MAX_CACHED_PAGES],
            dirty_limit,
            faulted: false,
        }
    }

    /// Records that the page at `offset` is now resident and clean (the kernel
    /// side of a page-in supply). Idempotent for an already-resident page.
    /// `BadHandle` once the object is faulted; `OutOfMemory` if the cache is full.
    pub fn install(&mut self, offset: u64) -> Result<(), KError> {
        if self.faulted {
            return Err(KError::BadHandle);
        }
        if self.find(offset).is_some() {
            return Ok(());
        }
        let slot = self
            .pages
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.pages[slot] = Some(PageEntry {
            offset,
            dirty: false,
        });
        Ok(())
    }

    /// Marks a resident page dirty on a write fault, or asks the caller to
    /// throttle the writer if the object is already at its dirty bound. Marking
    /// an already-dirty page is free ([`Marked`](DirtyOutcome::Marked)).
    pub fn mark_dirty(&mut self, offset: u64) -> DirtyOutcome {
        let Some(idx) = self.find(offset) else {
            // A write to a non-resident page never reaches dirtying (it pages in
            // first); refuse defensively rather than fabricate an entry.
            return DirtyOutcome::Throttle;
        };
        if self.pages[idx].map(|p| p.dirty).unwrap_or(false) {
            return DirtyOutcome::Marked;
        }
        if self.dirty_count() >= self.dirty_limit {
            return DirtyOutcome::Throttle;
        }
        if let Some(page) = self.pages[idx].as_mut() {
            page.dirty = true;
        }
        DirtyOutcome::Marked
    }

    /// Marks a page clean — called only after the pager acknowledges its
    /// write-back (durability ordering, docs/kernel/03 L138). No-op if absent.
    pub fn mark_clean(&mut self, offset: u64) {
        if let Some(idx) = self.find(offset)
            && let Some(page) = self.pages[idx].as_mut()
        {
            page.dirty = false;
        }
    }

    /// The offset of a clean resident page eligible for eviction, or `None` if
    /// every resident page is dirty (a dirty page must be written back first —
    /// eviction reclaims clean pages only, docs/kernel/03 L95). Lowest offset.
    pub fn evict_candidate(&self) -> Option<u64> {
        self.pages
            .iter()
            .flatten()
            .filter(|p| !p.dirty)
            .map(|p| p.offset)
            .min()
    }

    /// Removes a page from the cache (it has been evicted or faulted; its next
    /// access re-pages-in).
    pub fn forget(&mut self, offset: u64) {
        if let Some(idx) = self.find(offset) {
            self.pages[idx] = None;
        }
    }

    /// Fills `out` with the offsets of every dirty page, ascending, and returns
    /// the count — the dirty-range query pagers use for coordinated flush
    /// (docs/kernel/03 L96–98; harness scenario S8). Truncates to `out.len()`.
    pub fn dirty_offsets(&self, out: &mut [u64]) -> usize {
        let mut n = 0;
        for page in self.pages.iter().flatten() {
            if page.dirty && n < out.len() {
                out[n] = page.offset;
                n += 1;
            }
        }
        out[..n].sort_unstable();
        n
    }

    /// Number of dirty resident pages.
    pub fn dirty_count(&self) -> u32 {
        self.pages.iter().flatten().filter(|p| p.dirty).count() as u32
    }

    /// Number of resident pages (clean + dirty).
    pub fn resident_count(&self) -> usize {
        self.pages.iter().flatten().count()
    }

    /// Whether `offset` is resident.
    pub fn is_resident(&self, offset: u64) -> bool {
        self.find(offset).is_some()
    }

    /// Whether `offset` is resident and dirty.
    pub fn is_dirty(&self, offset: u64) -> bool {
        self.find(offset)
            .and_then(|i| self.pages[i])
            .map(|p| p.dirty)
            .unwrap_or(false)
    }

    /// Faults the object (pager death): reports the lost dirty ranges into `out`
    /// (ascending, exactly the dirty pages — no more, no fewer, docs/kernel/03
    /// L105), drops every resident page, and marks the object faulted so clean
    /// pages re-fault and no further page is admitted. Returns the lost count.
    pub fn fault(&mut self, out: &mut [u64]) -> usize {
        let lost = self.dirty_offsets(out);
        // The data-integrity record: exactly what was lost, as a structured event
        // (docs/kernel/03 L105) — not only a return value.
        event::emit(
            EventKind::PagerObjectFaulted,
            Severity::Critical,
            Component::Pager,
            // `out[0]` is the lowest lost offset only when something was lost;
            // the caller's buffer is otherwise untouched by `dirty_offsets`.
            [lost as u64, if lost > 0 { out[0] } else { 0 }, 0, 0],
        );
        self.pages = [const { None }; MAX_CACHED_PAGES];
        self.faulted = true;
        lost
    }

    /// Whether the object has been faulted (its pager died).
    pub fn is_faulted(&self) -> bool {
        self.faulted
    }

    fn find(&self, offset: u64) -> Option<usize> {
        self.pages
            .iter()
            .position(|p| matches!(p, Some(e) if e.offset == offset))
    }
}

/// A pager's **write-back reservation** (docs/kernel/03, "Write-Back Under Memory
/// Pressure", L126-132): frames guaranteed available to the write-back path and
/// protected from ordinary allocation, so reclaim can always make forward progress
/// even at hard memory pressure — the classic reclaim-needs-memory deadlock is
/// broken by reserving ahead. Ordinary (fault/page-in) allocation may not consume
/// the reservation; the write-back path draws from it, and over-allocating past it
/// fails cleanly (the caller faults the range) rather than blocking.
///
/// Pure accounting over a frame budget: the harness drives it (scenario S3), and a
/// real pager would back the reservation with `resource_domain` frames protected
/// from reclaim (docs/kernel/05). The one forbidden outcome is a hang — every
/// method returns promptly.
pub struct WriteBackReservation {
    capacity: u32,
    reserved: u32,
    ordinary_in_use: u32,
    writeback_in_use: u32,
}

impl WriteBackReservation {
    /// A budget of `capacity` frames with `reserved` of them set aside exclusively
    /// for the write-back path (`reserved` is clamped to `capacity`).
    pub const fn new(capacity: u32, reserved: u32) -> Self {
        let reserved = if reserved > capacity {
            capacity
        } else {
            reserved
        };
        Self {
            capacity,
            reserved,
            ordinary_in_use: 0,
            writeback_in_use: 0,
        }
    }

    /// Allocates one frame for the ordinary (fault/page-in) path. Returns `None`
    /// once only the protected reservation remains — memory pressure the caller
    /// resolves by reclaiming (a write-back), never by spinning.
    pub fn alloc_ordinary(&mut self) -> Option<()> {
        if self.ordinary_in_use < self.capacity.saturating_sub(self.reserved) {
            self.ordinary_in_use += 1;
            Some(())
        } else {
            None
        }
    }

    /// Frees one ordinary frame (e.g. after a write-back drained a dirty page and
    /// reclaim advanced).
    pub fn free_ordinary(&mut self) {
        self.ordinary_in_use = self.ordinary_in_use.saturating_sub(1);
    }

    /// Allocates one frame for the write-back path, drawing from the reservation so
    /// it makes progress even when `alloc_ordinary` is blocked. Returns `None` only
    /// when the write-back would exceed its declared reservation — a clean failure
    /// (the caller faults the range), never a hang.
    pub fn alloc_writeback(&mut self) -> Option<()> {
        if self.writeback_in_use < self.reserved {
            self.writeback_in_use += 1;
            Some(())
        } else {
            None
        }
    }

    /// Frees one write-back frame (after the pager acks and the frame is released).
    pub fn free_writeback(&mut self) {
        self.writeback_in_use = self.writeback_in_use.saturating_sub(1);
    }

    /// Whether the ordinary path is at hard memory pressure — only the reservation
    /// remains, so ordinary allocation blocks but write-back can still progress.
    pub fn at_pressure(&self) -> bool {
        self.ordinary_in_use >= self.capacity.saturating_sub(self.reserved)
    }
}

/// The result of a page-in request routed through the anti-deadlock guard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PageInResult {
    /// The request may proceed — its server is not already in the waits-for chain.
    Served,
    /// Serving it would re-enter a pager already blocked in the chain: a
    /// self-paging cycle. The kernel breaks it by faulting the request rather than
    /// blocking (docs/kernel/03 "Anti-Deadlock Rules").
    Cycle,
}

/// Bound on tracked pager bindings / in-flight page-in edges (like every kcore
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_PAGERS;

/// The **anti-deadlock guard** for pager-backed page-ins (docs/kernel/03 L112-117):
/// "A pager must not fault, in its own page-in handler, on an object it itself
/// pages. The kernel detects self-paging cycles across pagers and breaks them by
/// faulting the request rather than blocking." Each pager has at most one
/// outstanding page-in (synchronous v0), so the in-flight requests form a
/// waits-for graph; a new request that would close a loop in it is a cycle and is
/// faulted. Handles the degenerate single self-paging pager (a pager faulting on
/// the object it itself pages) as an immediate cycle.
///
/// Pure accounting — object ids are `u64`, pager ids are `u32` (opaque tags); the
/// harness (scenario S5) drives it. No frames, no scheduler, host-tested.
pub struct SelfPagingGraph {
    bindings: [(u64, u32); MAX_PAGERS],
    binding_count: usize,
    // In-flight waits-for edges: (waiter pager, the pager serving its page-in).
    waits: [(u32, u32); MAX_PAGERS],
    wait_count: usize,
}

impl SelfPagingGraph {
    /// An empty guard — no bindings, no in-flight requests.
    pub const fn new() -> Self {
        Self {
            bindings: [(0, 0); MAX_PAGERS],
            binding_count: 0,
            waits: [(0, 0); MAX_PAGERS],
            wait_count: 0,
        }
    }

    /// Records that `object` is paged by `pager`. `OutOfMemory` if the binding
    /// table is full.
    pub fn bind(&mut self, object: u64, pager: u32) -> Result<(), KError> {
        if self.binding_count >= MAX_PAGERS {
            return Err(KError::OutOfMemory);
        }
        self.bindings[self.binding_count] = (object, pager);
        self.binding_count += 1;
        Ok(())
    }

    /// Routes a page-in of `object` requested (in-handler) by `requester`. Returns
    /// [`PageInResult::Cycle`] — the request must be faulted, not blocked — when the
    /// object's serving pager is the requester itself or already transitively waits
    /// for the requester; otherwise records the in-flight edge and returns
    /// [`PageInResult::Served`].
    pub fn request_page_in(&mut self, requester: u32, object: u64) -> PageInResult {
        let Some(server) = self.server_of(object) else {
            // No pager can serve it → cannot be satisfied; fault rather than hang.
            return PageInResult::Cycle;
        };
        if server == requester || self.reaches(server, requester) {
            return PageInResult::Cycle;
        }
        if self.wait_count < MAX_PAGERS {
            self.waits[self.wait_count] = (requester, server);
            self.wait_count += 1;
        }
        PageInResult::Served
    }

    /// Clears `requester`'s in-flight edge (its page-in completed or was faulted).
    pub fn complete(&mut self, requester: u32) {
        if let Some(i) = self.waits[..self.wait_count]
            .iter()
            .position(|&(w, _)| w == requester)
        {
            self.wait_count -= 1;
            self.waits[i] = self.waits[self.wait_count];
        }
    }

    /// Number of in-flight page-in requests.
    pub fn in_flight(&self) -> usize {
        self.wait_count
    }

    fn server_of(&self, object: u64) -> Option<u32> {
        self.bindings[..self.binding_count]
            .iter()
            .find(|&&(o, _)| o == object)
            .map(|&(_, p)| p)
    }

    /// Whether, following the current waits-for edges from `from`, `target` is
    /// reachable (so a new `target -> from` edge would close a cycle).
    fn reaches(&self, from: u32, target: u32) -> bool {
        let mut node = from;
        // Each pager has ≤1 outgoing edge, so the chain length is bounded by the
        // number of edges; walk it, stopping if we revisit the start.
        for _ in 0..=self.wait_count {
            match self.waits[..self.wait_count]
                .iter()
                .find(|&&(w, _)| w == node)
            {
                Some(&(_, next)) => {
                    if next == target {
                        return true;
                    }
                    node = next;
                }
                None => return false,
            }
        }
        false
    }
}

impl Default for SelfPagingGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a page-in request is still within its deadline or has expired.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeadlineOutcome {
    /// The request is within its deadline — keep waiting.
    Pending,
    /// The deadline expired: the kernel delivers a fault error to the faulting
    /// thread's exception path and marks the range faulted (docs/kernel/03 L78-83),
    /// never blocking indefinitely.
    Expired,
}

/// Whether a recorded deadline miss escalates to supervised restart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MissOutcome {
    /// The miss is counted; the pager is still within its supervision budget.
    Continue,
    /// Repeated misses crossed the supervision threshold — escalate (restart the
    /// pager per policy).
    Escalate,
}

/// The **page-in deadline supervisor** (docs/kernel/03 L78-83): "A pager that does
/// not respond within policy deadlines is subject to supervision and restart; its
/// consumers observe faulted ranges rather than indefinite hangs." A request past
/// its deadline expires (the faulter gets a bounded fault error, the range is
/// faulted); every `escalate_after` misses escalate to a supervised restart. Misses
/// and escalations are counted so each is observable as an event ("emit the event
/// that says so").
///
/// Deadlines are a logical tick budget the caller advances (no real timer/watchdog
/// in v0 — D37); the harness (scenario S7) drives it. Pure accounting, host-tested.
pub struct PageInSupervisor {
    deadline: u64,
    escalate_after: u32,
    misses: u32,
    escalations: u32,
}

impl PageInSupervisor {
    /// A supervisor allowing `deadline` ticks per page-in and escalating every
    /// `escalate_after` misses (`escalate_after` is forced to at least 1).
    pub const fn new(deadline: u64, escalate_after: u32) -> Self {
        let escalate_after = if escalate_after == 0 {
            1
        } else {
            escalate_after
        };
        Self {
            deadline,
            escalate_after,
            misses: 0,
            escalations: 0,
        }
    }

    /// Whether a request started at tick `started` has expired by tick `now`. A
    /// request is [`DeadlineOutcome::Expired`] only once elapsed *exceeds* the
    /// deadline, so the fault is delivered within deadline plus a bounded margin.
    pub fn check(&self, started: u64, now: u64) -> DeadlineOutcome {
        if now.saturating_sub(started) > self.deadline {
            DeadlineOutcome::Expired
        } else {
            DeadlineOutcome::Pending
        }
    }

    /// Records a deadline miss and reports whether it escalates to a supervised
    /// restart (every `escalate_after` misses).
    pub fn record_miss(&mut self) -> MissOutcome {
        self.misses += 1;
        event::emit(
            EventKind::PagerDeadlineMiss,
            Severity::Warning,
            Component::Pager,
            [
                u64::from(self.misses),
                self.deadline,
                u64::from(self.escalate_after),
                0,
            ],
        );
        if self.misses.is_multiple_of(self.escalate_after) {
            self.escalations += 1;
            event::emit(
                EventKind::PagerSupervisionEscalate,
                Severity::Error,
                Component::Pager,
                [u64::from(self.misses), u64::from(self.escalations), 0, 0],
            );
            MissOutcome::Escalate
        } else {
            MissOutcome::Continue
        }
    }

    /// Total deadline misses observed (each an event).
    pub fn misses(&self) -> u32 {
        self.misses
    }

    /// Total supervised-restart escalations (each an event).
    pub fn escalations(&self) -> u32 {
        self.escalations
    }
}

#[cfg(test)]
#[path = "tests/pager.rs"]
mod tests;
