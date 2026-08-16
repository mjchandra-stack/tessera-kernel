// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::heap`.

use super::*;
use std::boxed::Box;
use std::vec::Vec;

const HEAP_SIZE: usize = 4096;

#[repr(align(16))]
struct Backing([u8; HEAP_SIZE]);

fn new_heap() -> Heap {
    let backing = Box::leak(Box::new(Backing([0; HEAP_SIZE])));
    let mut heap = Heap::empty();
    // SAFETY: the leaked backing is exclusively owned and 'static.
    unsafe { heap.init(NonNull::from(&mut backing.0[0]), HEAP_SIZE) };
    heap
}

fn layout(size: usize, align: usize) -> Layout {
    Layout::from_size_align(size, align).unwrap()
}

#[test]
fn allocations_are_aligned_disjoint_and_in_range() {
    let mut heap = new_heap();
    let a = heap.try_alloc(layout(24, 8)).unwrap();
    let b = heap.try_alloc(layout(24, 8)).unwrap();
    assert_ne!(a, b);
    assert_eq!(a.as_ptr() as usize % 16, 0);
    let distance = (b.as_ptr() as usize).abs_diff(a.as_ptr() as usize);
    assert!(distance >= 32, "normalized blocks must not overlap");
}

#[test]
fn high_alignment_is_honored() {
    let mut heap = new_heap();
    let p = heap.try_alloc(layout(16, 256)).unwrap();
    assert_eq!(p.as_ptr() as usize % 256, 0);
}

#[test]
fn oom_returns_err_and_heap_stays_consistent() {
    let mut heap = new_heap();
    assert_eq!(heap.try_alloc(layout(HEAP_SIZE * 2, 16)), Err(AllocError));
    let mut held = Vec::new();
    while let Ok(p) = heap.try_alloc(layout(64, 16)) {
        held.push(p);
    }
    assert!(!held.is_empty());
    assert_eq!(heap.try_alloc(layout(64, 16)), Err(AllocError));
    // Still functional after exhaustion.
    for p in held.drain(..) {
        // SAFETY: allocated above with the same layout, used once.
        unsafe { heap.dealloc(p, layout(64, 16)) };
    }
    assert!(heap.try_alloc(layout(64, 16)).is_ok());
}

#[test]
fn coalescing_restores_the_full_region() {
    let mut heap = new_heap();
    let total = heap.total();
    let l = layout(128, 16);
    let a = heap.try_alloc(l).unwrap();
    let b = heap.try_alloc(l).unwrap();
    let c = heap.try_alloc(l).unwrap();
    // Free out of order to exercise forward and backward merges.
    // SAFETY: each pointer came from try_alloc with layout `l`.
    unsafe {
        heap.dealloc(b, l);
        heap.dealloc(a, l);
        heap.dealloc(c, l);
    }
    assert_eq!(heap.used(), 0);
    // A single coalesced hole must satisfy the whole region again.
    assert!(heap.try_alloc(layout(total, 16)).is_ok());
}

#[test]
fn zero_size_allocations_work() {
    let mut heap = new_heap();
    let p = heap.try_alloc(layout(0, 1)).unwrap();
    // SAFETY: just allocated, same layout.
    unsafe { heap.dealloc(p, layout(0, 1)) };
    assert_eq!(heap.used(), 0);
}
