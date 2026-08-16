// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::pmem`.

use super::*;
use std::vec;
use std::vec::Vec;
use tessera_karch_mock::synthetic_map;

#[test]
fn allocates_across_regions_and_exhausts() {
    let map = synthetic_map(&[
        (0x1000, 2 * FRAME_SIZE, MemoryKind::Usable),
        (0x100000, FRAME_SIZE, MemoryKind::Reserved),
        (0x200000, FRAME_SIZE, MemoryKind::Usable),
    ]);
    let mut alloc = BumpFrameAllocator::new(&map);
    assert_eq!(alloc.total_usable_frames(), 3);
    let bases: Vec<u64> = core::iter::from_fn(|| alloc.alloc())
        .map(|f| f.base().as_u64())
        .collect();
    assert_eq!(bases, vec![0x1000, 0x2000, 0x200000]);
    assert_eq!(alloc.alloc(), None);
    assert_eq!(alloc.alloc(), None, "exhaustion is stable");
    assert_eq!(alloc.handed_out(), 3);
}

#[test]
fn unaligned_regions_are_trimmed_to_frames() {
    // 0x1800..0x3800: only 0x2000..0x3000 is a whole aligned frame.
    let map = synthetic_map(&[(0x1800, 2 * FRAME_SIZE, MemoryKind::Usable)]);
    let mut alloc = BumpFrameAllocator::new(&map);
    assert_eq!(alloc.total_usable_frames(), 1);
    assert_eq!(alloc.alloc().map(|f| f.base().as_u64()), Some(0x2000));
    assert_eq!(alloc.alloc(), None);
}

#[test]
fn malformed_and_subframe_regions_are_skipped() {
    let map = synthetic_map(&[
        (u64::MAX - 0x100, 0x1000, MemoryKind::Usable), // wraps
        (0x5000, 0x800, MemoryKind::Usable),            // sub-frame
    ]);
    let mut alloc = BumpFrameAllocator::new(&map);
    assert_eq!(alloc.total_usable_frames(), 0);
    assert_eq!(alloc.alloc(), None);
}

#[test]
fn empty_map_yields_nothing() {
    let mut alloc = BumpFrameAllocator::new(&[]);
    assert_eq!(alloc.alloc(), None);
}

fn frame(base: u64) -> PhysFrame {
    PhysFrame::from_base(PhysAddr::new(base)).expect("aligned frame")
}

#[test]
fn freed_frames_are_reused_before_bumping() {
    let map = synthetic_map(&[(0x1000, 4 * FRAME_SIZE, MemoryKind::Usable)]);
    let mut alloc = BumpFrameAllocator::new(&map);
    let a = alloc.alloc().expect("a");
    let b = alloc.alloc().expect("b");
    assert_eq!(alloc.handed_out(), 2);
    // Free `a`; the next alloc reuses it (LIFO) without consuming new memory.
    alloc.free_frame(a);
    assert_eq!(alloc.free_list_depth(), 1);
    let reused = alloc.alloc().expect("reused");
    assert_eq!(reused.base().as_u64(), a.base().as_u64());
    assert_eq!(alloc.handed_out(), 2, "reuse does not consume new frames");
    assert_eq!(alloc.free_list_depth(), 0);
    // Next alloc bumps past `b`.
    let c = alloc.alloc().expect("c");
    assert_ne!(c.base().as_u64(), b.base().as_u64());
}

#[test]
fn shared_frames_survive_until_the_last_reference() {
    let map = synthetic_map(&[(0x1000, 4 * FRAME_SIZE, MemoryKind::Usable)]);
    let mut alloc = BumpFrameAllocator::new(&map);
    let f = alloc.alloc().expect("f");
    // Share it (reference count 2).
    alloc.retain_frame(f);
    assert_eq!(alloc.shared_frame_count(), 1);
    // First release: back to a single implicit reference, NOT reclaimed.
    alloc.free_frame(f);
    assert_eq!(alloc.shared_frame_count(), 0);
    assert_eq!(alloc.free_list_depth(), 0, "still referenced, not freed");
    // Second release: last reference drops, frame reclaimed.
    alloc.free_frame(f);
    assert_eq!(alloc.free_list_depth(), 1);
    assert_eq!(
        alloc.alloc().map(|r| r.base().as_u64()),
        Some(f.base().as_u64())
    );
}

#[test]
fn free_list_overflow_is_counted_never_silent() {
    let map = synthetic_map(&[(0x1000, FRAME_SIZE, MemoryKind::Usable)]);
    let mut alloc = BumpFrameAllocator::new(&map);
    // Free more distinct frames than the free-list can hold.
    for i in 0..(MAX_FREE_FRAMES as u64 + 1) {
        alloc.free_frame(frame(0x10_0000 + i * FRAME_SIZE));
    }
    assert_eq!(alloc.free_list_depth(), MAX_FREE_FRAMES);
    assert_eq!(alloc.reclaim_overflows(), 1, "the overflow is surfaced");
}

#[test]
fn contiguous_runs_do_not_span_regions() {
    // Two usable frames in one region, three in the next: a 3-frame
    // run must come entirely from the second region.
    let map = synthetic_map(&[
        (0x1000, 2 * FRAME_SIZE, MemoryKind::Usable),
        (0x100000, 3 * FRAME_SIZE, MemoryKind::Usable),
    ]);
    let mut alloc = BumpFrameAllocator::new(&map);
    assert_eq!(
        alloc.alloc_contiguous(3).map(|a| a.as_u64()),
        Some(0x100000)
    );
    assert_eq!(alloc.alloc_contiguous(1), None, "everything consumed");
    let mut fresh = BumpFrameAllocator::new(&map);
    assert_eq!(fresh.alloc_contiguous(6), None, "no run that long");
}
