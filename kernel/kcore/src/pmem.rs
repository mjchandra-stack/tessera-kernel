// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Boot-time physical frame allocation: a bump allocator over the usable
//! regions of the boot memory map, with a **bounded reclaim path** for the
//! demand-paging / copy-on-write milestone. New frames come from the bump
//! cursor; freed frames go on a fixed-capacity free-list and are reused before
//! the cursor advances again. Shared frames (copy-on-write) carry a reference
//! count in a fixed-capacity side-table — a frame not listed there has a single
//! implicit reference. The general allocator with unbounded reclaim still
//! arrives with memory objects and the pager (build/README.md, D29); the caps
//! here are honest and their exhaustion is counted, never silent.
//!
//! Pure arithmetic over the map — no unsafe, fully host-testable.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Memory Manager"),
//! docs/kernel/03-paging-faults-and-exceptions.md ("External Pager Protocol")
//! Budget: B8 (anon fault), B9 (COW fault) — the reclaim substrate; unmeasured
//! until the perf rig lands (build/README.md, D30)

use crate::event;
use crate::isl_binding::event::{Component, EventKind, Severity};
use tessera_karch::{FRAME_SIZE, FrameSource, MemoryKind, MemoryRegion, PhysAddr, PhysFrame};

/// `MEM_RECLAIM_OVERFLOW` reasons (the event's `arg0`): which bound was hit.
pub const RECLAIM_OVERFLOW_FREE_LIST_FULL: u64 = 1;
pub const RECLAIM_OVERFLOW_SHARED_TABLE_FULL: u64 = 2;
/// A memory object's frames were **not** reclaimed because a device could
/// still reach them (`kcore::memory::MemoryTable::destroy`). Not a bound at
/// all, which is why it is worth saying out loud: it means a detach was
/// skipped somewhere, and the leak is the deliberate lesser harm.
pub const RECLAIM_REFUSED_STILL_ATTACHED: u64 = 3;

pub use crate::config::MAX_FREE_FRAMES;

pub use crate::config::MAX_SHARED_FRAMES;

pub struct BumpFrameAllocator<'a> {
    map: &'a [MemoryRegion],
    /// Index of the region currently being consumed.
    region: usize,
    /// Next un-handed-out address within that region (frame-aligned).
    cursor: u64,
    handed_out: u64,
    /// Freed frames available for reuse before the cursor advances (a stack of
    /// frame base addresses).
    free_list: [u64; MAX_FREE_FRAMES],
    free_count: usize,
    /// Reference counts for shared frames: `(base, count)` with `count >= 2`. A
    /// frame not listed has an implicit count of 1.
    shared: [(u64, u32); MAX_SHARED_FRAMES],
    shared_count: usize,
    /// Reclaim events that exceeded a bound (free-list or shared table full);
    /// the frame leaks but the event is surfaced, never silent (D29).
    reclaim_overflows: u64,
}

impl<'a> BumpFrameAllocator<'a> {
    /// The map must be sorted by base and non-overlapping (the boot-glue
    /// contract from `tessera_karch::BootInfo`). Malformed regions
    /// (wrapping or sub-frame) are skipped, never trusted.
    pub fn new(map: &'a [MemoryRegion]) -> Self {
        let mut allocator = Self {
            map,
            region: 0,
            cursor: 0,
            handed_out: 0,
            free_list: [0; MAX_FREE_FRAMES],
            free_count: 0,
            shared: [(0, 0); MAX_SHARED_FRAMES],
            shared_count: 0,
            reclaim_overflows: 0,
        };
        allocator.advance_to_usable_region(0);
        allocator
    }

    /// Hands out the next free frame, or `None` when physical memory is
    /// exhausted. Exhaustion is a normal outcome for the caller to handle —
    /// allocation is fallible everywhere.
    pub fn alloc(&mut self) -> Option<PhysFrame> {
        // Reuse a freed frame before consuming new physical memory. Reuse does
        // not advance `handed_out` — that counts frames drawn from the map.
        if self.free_count > 0 {
            self.free_count -= 1;
            let base = self.free_list[self.free_count];
            return PhysFrame::from_base(PhysAddr::new(base));
        }
        loop {
            let (start, end) = self.usable_bounds(self.region)?;
            if self.cursor < start {
                self.cursor = start;
            }
            if self.cursor.checked_add(FRAME_SIZE)? <= end {
                let frame = PhysFrame::from_base(tessera_karch::PhysAddr::new(self.cursor))?;
                self.cursor += FRAME_SIZE;
                self.handed_out += 1;
                return Some(frame);
            }
            self.advance_to_usable_region(self.region + 1);
            if self.region >= self.map.len() {
                return None;
            }
        }
    }

    /// Hands out `count` physically contiguous frames, returning the base
    /// of the run. Frames consumed while searching past region boundaries
    /// are not returned (init-only allocator); `None` once memory is
    /// exhausted before a long-enough run is found.
    pub fn alloc_contiguous(&mut self, count: u64) -> Option<tessera_karch::PhysAddr> {
        if count == 0 {
            return None;
        }
        let mut run_start = self.alloc()?;
        let mut run_len = 1;
        let mut prev = run_start;
        while run_len < count {
            let frame = self.alloc()?;
            if frame.base().as_u64() == prev.base().as_u64() + FRAME_SIZE {
                run_len += 1;
            } else {
                run_start = frame;
                run_len = 1;
            }
            prev = frame;
        }
        Some(run_start.base())
    }

    /// Frames handed out so far.
    pub fn handed_out(&self) -> u64 {
        self.handed_out
    }

    /// Frames currently available for reuse on the free-list.
    pub fn free_list_depth(&self) -> usize {
        self.free_count
    }

    /// Distinct frames currently tracked as shared (reference count > 1).
    pub fn shared_frame_count(&self) -> usize {
        self.shared_count
    }

    /// Reclaim events that overflowed a bound (free-list or shared table full).
    /// Should be zero in a healthy run; surfaced so a leak is never silent.
    pub fn reclaim_overflows(&self) -> u64 {
        self.reclaim_overflows
    }

    /// Adds one reference to the frame at `base` (copy-on-write sharing).
    fn retain(&mut self, base: u64) {
        for entry in &mut self.shared[..self.shared_count] {
            if entry.0 == base {
                entry.1 += 1;
                return;
            }
        }
        if self.shared_count < MAX_SHARED_FRAMES {
            self.shared[self.shared_count] = (base, 2);
            self.shared_count += 1;
        } else {
            // Cannot track the extra reference: treat as permanently shared
            // (the frame will never be reclaimed) and count the overflow.
            self.reclaim_overflows += 1;
            event::emit(
                EventKind::MemReclaimOverflow,
                Severity::Error,
                Component::Memory,
                [
                    RECLAIM_OVERFLOW_SHARED_TABLE_FULL,
                    MAX_SHARED_FRAMES as u64,
                    base,
                    0,
                ],
            );
        }
    }

    /// Releases one reference to the frame at `base`; reclaims it to the
    /// free-list when the last reference drops.
    fn release(&mut self, base: u64) {
        for i in 0..self.shared_count {
            if self.shared[i].0 == base {
                self.shared[i].1 -= 1;
                if self.shared[i].1 <= 1 {
                    // Back to a single implicit reference: drop from the table.
                    self.shared_count -= 1;
                    self.shared[i] = self.shared[self.shared_count];
                }
                return;
            }
        }
        // Not shared: this was the last reference, so reclaim the frame.
        if self.free_count < MAX_FREE_FRAMES {
            self.free_list[self.free_count] = base;
            self.free_count += 1;
        } else {
            // Free-list full: the frame leaks, and the event says so.
            self.reclaim_overflows += 1;
            event::emit(
                EventKind::MemReclaimOverflow,
                Severity::Error,
                Component::Memory,
                [
                    RECLAIM_OVERFLOW_FREE_LIST_FULL,
                    MAX_FREE_FRAMES as u64,
                    base,
                    0,
                ],
            );
        }
    }

    /// Total usable frames in the map, independent of consumption.
    pub fn total_usable_frames(&self) -> u64 {
        (0..self.map.len())
            .filter_map(|i| self.usable_bounds(i))
            .map(|(start, end)| (end - start) / FRAME_SIZE)
            .sum()
    }

    /// Frame-aligned `(start, end)` of region `index` if it is usable and
    /// well-formed.
    fn usable_bounds(&self, index: usize) -> Option<(u64, u64)> {
        let region = self.map.get(index)?;
        if region.kind != MemoryKind::Usable {
            return None;
        }
        let start = region.base.align_up(FRAME_SIZE)?.as_u64();
        let end = region.end()?.align_down(FRAME_SIZE).as_u64();
        if end <= start {
            return None;
        }
        Some((start, end))
    }

    fn advance_to_usable_region(&mut self, from: usize) {
        self.region = from;
        while self.region < self.map.len() && self.usable_bounds(self.region).is_none() {
            self.region += 1;
        }
        if let Some((start, _)) = self.usable_bounds(self.region) {
            self.cursor = start;
        }
    }
}

/// Lets the architecture page-table walker draw intermediate-table frames
/// from the boot allocator without knowing how physical memory is tracked.
/// A frame source over a fixed set of frames handed to it in advance.
///
/// **For a CPU that needs to allocate and does not own an allocator.** The
/// boot CPU owns the machine's physical memory; a secondary that has to fill
/// pages — the scaling condition's fault benchmark
/// (`docs/prototypes/01`) — cannot share it, because
/// [`BumpFrameAllocator`] is reached by `&mut` and two CPUs cannot hold one.
/// So the boot CPU draws frames in advance and hands over a pool, and what the
/// two CPUs share afterwards is nothing at all. That is also what makes the
/// measurement mean something: a benchmark whose workers contended for one
/// allocator would be measuring the allocator.
///
/// Hands frames out in the order they were put in and never reclaims — a pool
/// is exhausted, not recycled, which is the honest shape for something with a
/// fixed set and no free list. `alloc_frame` returning `None` is how a caller
/// finds out, and every caller of it already has to handle that.
pub struct FramePool<const N: usize> {
    frames: [u64; N],
    /// Frames put in.
    len: usize,
    /// Frames handed out.
    next: usize,
}

impl<const N: usize> Default for FramePool<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FramePool<N> {
    pub const fn new() -> Self {
        Self {
            frames: [0; N],
            len: 0,
            next: 0,
        }
    }

    /// Draws up to `count` frames from `source` into the pool, returning how
    /// many it got.
    ///
    /// Fewer than asked for is reported rather than treated as failure: the
    /// caller knows what it needs, and a partly-filled pool is better
    /// diagnosis than an empty one.
    pub fn fill(&mut self, source: &mut dyn FrameSource, count: usize) -> usize {
        let mut filled = 0;
        while self.len < N && filled < count {
            let Some(frame) = source.alloc_frame() else {
                break;
            };
            self.frames[self.len] = frame.base().as_u64();
            self.len += 1;
            filled += 1;
        }
        filled
    }

    /// Frames still to hand out.
    pub fn remaining(&self) -> usize {
        self.len.saturating_sub(self.next)
    }
}

impl<const N: usize> FrameSource for FramePool<N> {
    fn alloc_frame(&mut self) -> Option<PhysFrame> {
        if self.next >= self.len {
            return None;
        }
        let base = self.frames[self.next];
        self.next += 1;
        PhysFrame::from_base(PhysAddr::new(base))
    }
}

impl FrameSource for BumpFrameAllocator<'_> {
    fn alloc_frame(&mut self) -> Option<PhysFrame> {
        self.alloc()
    }

    fn retain_frame(&mut self, frame: PhysFrame) {
        self.retain(frame.base().as_u64());
    }

    fn free_frame(&mut self, frame: PhysFrame) {
        self.release(frame.base().as_u64());
    }

    fn frames_available(&self) -> Option<u64> {
        // What the map still holds, plus what has come back. Reuse is drawn
        // first, so both are genuinely available.
        let untouched = self.total_usable_frames().saturating_sub(self.handed_out());
        Some(untouched + self.free_count as u64)
    }
}

#[cfg(test)]
#[path = "tests/pmem.rs"]
mod tests;
