// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **A heap for a ring-3 program.**
//!
//! Every user-space program in this tree is `#![no_std]` and fixed-buffer: it
//! picks a virtual address out of `tessera_uabi::layout`, calls `memory_create`
//! and `memory_map`, and lives inside what it asked for. That is right for a
//! driver, whose working set is a property of its device and whose data path
//! must not allocate. It is impossible for a compiler, whose working set is a
//! property of its input — which is why `docs/roadmap/04` makes this its
//! Phase 0 and why nothing above it can start (`build/README.md`, D301).
//!
//! **The algorithm is address arithmetic, and that is deliberate.** A
//! conventional allocator stores its bookkeeping *in* the memory it manages,
//! which means every operation is a raw pointer write and none of it can be
//! tested without real memory. Here the free list is an array of extents held
//! outside the heap, so [`Extents`] is total arithmetic over `usize`: it needs
//! no allocator to test, no memory to run against, and no `unsafe` at all. The
//! only `unsafe` in this crate is the [`GlobalAlloc`] shim that turns an
//! address into a pointer, which is the one thing that genuinely is unsafe.
//!
//! **Sizes come back on free.** `GlobalAlloc::dealloc` is handed the `Layout`
//! it was allocated with, so this never has to record the size of a live
//! block — only the holes between them. That is what makes out-of-line
//! metadata affordable: the array tracks free extents, of which there are few,
//! rather than allocations, of which there are many.
//!
//! **Bounded, and it refuses rather than degrades.** Fragmentation is what
//! grows the extent array, and it has a fixed capacity. A heap that silently
//! forgot an extent would leak memory no counter could find, so a full array
//! refuses the free and says so — `docs/lifecycle/04` forbids the other
//! choice. The same applies to growth: past its ceiling this returns null and
//! reports, rather than wrapping into somebody else's mapping.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 0"),
//! docs/lifecycle/04-coding-guidelines.md ("No silent fallback")
//! Budget: none (not on a data path — see the module note above)

#![no_std]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// A half-open range of addresses that is free.
///
/// `start` and `len` rather than `start` and `end` because every caller has a
/// length in hand and the one that has an end can subtract; the reverse turns
/// each call site into arithmetic that can be got wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    /// First address in the range.
    pub start: usize,
    /// How many bytes it covers. Never zero — an empty extent is absence, and
    /// [`Extents`] records absence by not holding the slot.
    pub len: usize,
}

impl Extent {
    /// One past the last address, or `None` if that would wrap.
    ///
    /// Fallible because this crate is compiled for 32-bit machines too, where
    /// `usize` is the pointer width and the arithmetic has to survive it.
    ///
    /// **The bound this places on the heap**: ends are exclusive, so the
    /// highest extent expressible is one ending at `usize::MAX`, and an extent
    /// containing the final byte of the address space is refused as
    /// [`HeapError::Invalid`]. That costs one byte nobody can map — no port's
    /// user half reaches it — and buys arithmetic that cannot wrap. An end
    /// that wrapped to zero would compare as below its own start, and every
    /// ordering and overlap test here would then be answering about a range
    /// that does not exist.
    #[must_use]
    pub fn end(&self) -> Option<usize> {
        self.start.checked_add(self.len)
    }
}

/// Why a heap operation could not be done.
///
/// Values rather than a formatted string, because a program above this cannot
/// print and the caller has to be able to act on the answer
/// (`docs/lifecycle/04`, "Errors are stable-domain values").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapError {
    /// No free extent could satisfy the request, and growth is the caller's
    /// next move rather than an error.
    NoSpace,
    /// The free-list array is full. The memory is not lost — it is still
    /// mapped — but this allocator can no longer describe where the hole is,
    /// so it declines to pretend otherwise.
    TooFragmented,
    /// The request is not one any arrangement of memory could satisfy: a zero
    /// or non-power-of-two alignment, or a size whose alignment round-up
    /// overflows the address space.
    Invalid,
    /// A freed range overlaps one already free, which means somebody freed
    /// twice or freed something they did not own.
    NotAllocated,
}

/// The free list: address-ordered, coalescing, and of fixed capacity.
///
/// `N` is the number of *disjoint holes* this heap can describe at once, which
/// is a fragmentation bound and not an allocation bound — a heap of a thousand
/// live objects with no gaps between them needs one extent.
#[derive(Debug)]
pub struct Extents<const N: usize> {
    free: [Extent; N],
    len: usize,
}

impl<const N: usize> Default for Extents<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Extents<N> {
    /// An empty free list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            free: [Extent { start: 0, len: 0 }; N],
            len: 0,
        }
    }

    /// How many disjoint holes are being tracked. The fragmentation measure,
    /// exposed because a caller that wants to know how close it is to
    /// [`HeapError::TooFragmented`] should not have to guess.
    #[must_use]
    pub fn holes(&self) -> usize {
        self.len
    }

    /// Total free bytes across every hole.
    #[must_use]
    pub fn free_bytes(&self) -> usize {
        self.free[..self.len].iter().map(|e| e.len).sum()
    }

    /// The extents, in address order. For tests and for a caller reporting
    /// what it holds.
    #[must_use]
    pub fn as_slice(&self) -> &[Extent] {
        &self.free[..self.len]
    }

    /// Adds `extent` to the free list, coalescing with whatever it touches.
    ///
    /// **Overlap is an error and not a merge.** Two free extents that overlap
    /// can only mean the same memory was freed twice or freed by somebody who
    /// did not hold it, and coalescing them would turn a caller's bug into
    /// this allocator handing the same address out twice.
    pub fn insert(&mut self, extent: Extent) -> Result<(), HeapError> {
        if extent.len == 0 {
            return Ok(());
        }
        let end = extent.end().ok_or(HeapError::Invalid)?;

        // Where it belongs in address order, and whether it collides on the
        // way. Both answers come from one walk.
        let mut at = self.len;
        for (i, held) in self.free[..self.len].iter().enumerate() {
            let held_end = held.end().ok_or(HeapError::Invalid)?;
            if extent.start < held_end && held.start < end {
                return Err(HeapError::NotAllocated);
            }
            if held.start >= end {
                at = i;
                break;
            }
        }

        // **Coalescing is decided before anything is inserted**, because the
        // obvious order — insert, then merge with the neighbours — needs a
        // free slot to hold the extent in between, and the case where the
        // array is full is exactly the case where merging would have made one
        // unnecessary. A full list must still accept a free that closes a gap.
        let joins_before = at > 0 && self.free[at - 1].end() == Some(extent.start);
        let joins_after = at < self.len && self.free[at].start == end;

        match (joins_before, joins_after) {
            // Fills the gap between two holes: they become one and a slot is
            // returned to the array.
            (true, true) => {
                self.free[at - 1].len += extent.len + self.free[at].len;
                self.remove(at);
            }
            (true, false) => self.free[at - 1].len += extent.len,
            (false, true) => {
                self.free[at].start = extent.start;
                self.free[at].len += extent.len;
            }
            // Touches nothing, so it needs a slot of its own. This is the only
            // path that can be refused, and it is refused before the list is
            // touched.
            (false, false) => {
                if self.len == N {
                    return Err(HeapError::TooFragmented);
                }
                self.free.copy_within(at..self.len, at + 1);
                self.free[at] = extent;
                self.len += 1;
            }
        }
        Ok(())
    }

    /// Takes `size` bytes aligned to `align`, first fit, returning the address.
    ///
    /// **First fit rather than best fit**, because best fit costs a full walk
    /// on every allocation to buy a fragmentation improvement that the
    /// literature has never been able to show reliably, and because a full
    /// walk is the one thing a bounded array makes cheap to do wrongly.
    pub fn take(&mut self, size: usize, align: usize) -> Result<usize, HeapError> {
        if size == 0 || align == 0 || !align.is_power_of_two() {
            return Err(HeapError::Invalid);
        }
        for i in 0..self.len {
            let extent = self.free[i];
            let Some(start) = align_up(extent.start, align) else {
                continue;
            };
            // The head is what alignment wasted; the tail is what is left over.
            // Both go back on the list, and either may be empty.
            let head = start - extent.start;
            let Some(used_end) = start.checked_add(size) else {
                continue;
            };
            let Some(extent_end) = extent.end() else {
                return Err(HeapError::Invalid);
            };
            if used_end > extent_end {
                continue;
            }
            let tail = extent_end - used_end;

            // A split makes two holes out of one and so needs a slot. Checked
            // before anything is mutated, so a refusal leaves the list as it
            // was.
            if head > 0 && tail > 0 && self.len == N {
                return Err(HeapError::TooFragmented);
            }

            if head == 0 && tail == 0 {
                self.remove(i);
            } else if head == 0 {
                self.free[i] = Extent {
                    start: used_end,
                    len: tail,
                };
            } else {
                self.free[i] = Extent {
                    start: extent.start,
                    len: head,
                };
                if tail > 0 {
                    self.free.copy_within(i + 1..self.len, i + 2);
                    self.free[i + 1] = Extent {
                        start: used_end,
                        len: tail,
                    };
                    self.len += 1;
                }
            }
            return Ok(start);
        }
        Err(HeapError::NoSpace)
    }

    fn remove(&mut self, at: usize) {
        self.free.copy_within(at + 1..self.len, at);
        self.len -= 1;
    }
}

/// Rounds `value` up to a multiple of `align`, or `None` if that wraps.
///
/// `align` must be a power of two; callers check, because a checked round-up
/// that also validated its alignment would be doing two jobs and the callers
/// here have already had to decide what an invalid alignment means.
#[must_use]
pub fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|v| v & !mask)
}

#[cfg(test)]
#[path = "tests/extents.rs"]
mod tests;
