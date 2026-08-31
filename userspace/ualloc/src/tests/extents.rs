// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The free list, exercised as arithmetic.
//!
//! **No memory is allocated by any test here**, which is the point of keeping
//! the metadata out of line: a heap whose bookkeeping lived in the bytes it
//! manages could only be tested against real mappings, and a ring-3 binary has
//! no host test target to run them from (the lesson `//userspace/elfload`
//! records, D294). Every case below is addresses and lengths.

use super::{Extent, Extents, HeapError, align_up};

/// A heap of `len` bytes at `start`, as a fresh free list.
fn heap<const N: usize>(start: usize, len: usize) -> Extents<N> {
    let mut extents = Extents::<N>::new();
    extents.insert(Extent { start, len }).expect("seed");
    extents
}

#[test]
fn a_fresh_heap_is_one_hole() {
    let extents = heap::<8>(0x1000, 0x1000);
    assert_eq!(extents.holes(), 1);
    assert_eq!(extents.free_bytes(), 0x1000);
}

#[test]
fn take_carves_from_the_front_and_leaves_the_tail() {
    let mut extents = heap::<8>(0x1000, 0x1000);
    assert_eq!(extents.take(0x100, 1), Ok(0x1000));
    assert_eq!(
        extents.as_slice(),
        &[Extent {
            start: 0x1100,
            len: 0xf00
        }]
    );
}

#[test]
fn take_respects_alignment_and_the_skipped_head_stays_free() {
    let mut extents = heap::<8>(0x1008, 0x1000);
    // 0x1008 is not 64-aligned; the next one that is, is 0x1040.
    assert_eq!(extents.take(0x10, 64), Ok(0x1040));
    assert_eq!(
        extents.as_slice(),
        &[
            Extent {
                start: 0x1008,
                len: 0x38
            },
            Extent {
                start: 0x1050,
                len: 0xfb8
            },
        ]
    );
    assert_eq!(extents.free_bytes(), 0x38 + 0xfb8);
}

#[test]
fn an_exact_fit_removes_the_hole() {
    let mut extents = heap::<8>(0x1000, 0x100);
    assert_eq!(extents.take(0x100, 1), Ok(0x1000));
    assert_eq!(extents.holes(), 0);
    assert_eq!(extents.free_bytes(), 0);
}

#[test]
fn free_puts_it_back_and_the_heap_is_whole_again() {
    let mut extents = heap::<8>(0x1000, 0x1000);
    let a = extents.take(0x100, 1).expect("a");
    let b = extents.take(0x100, 1).expect("b");
    extents
        .insert(Extent {
            start: a,
            len: 0x100,
        })
        .expect("free a");
    extents
        .insert(Extent {
            start: b,
            len: 0x100,
        })
        .expect("free b");
    // **One hole, not three.** A free list that did not coalesce would pass
    // every test above and fragment a long-running program to death.
    assert_eq!(extents.holes(), 1);
    assert_eq!(extents.free_bytes(), 0x1000);
}

#[test]
fn freeing_the_middle_gap_last_joins_both_neighbours() {
    let mut extents = heap::<8>(0x1000, 0x300);
    let a = extents.take(0x100, 1).expect("a");
    let b = extents.take(0x100, 1).expect("b");
    let c = extents.take(0x100, 1).expect("c");
    assert_eq!(extents.holes(), 0);
    extents
        .insert(Extent {
            start: a,
            len: 0x100,
        })
        .expect("free a");
    extents
        .insert(Extent {
            start: c,
            len: 0x100,
        })
        .expect("free c");
    assert_eq!(extents.holes(), 2);
    // The three-way join: the hole being inserted touches one on each side.
    extents
        .insert(Extent {
            start: b,
            len: 0x100,
        })
        .expect("free b");
    assert_eq!(extents.holes(), 1);
    assert_eq!(extents.free_bytes(), 0x300);
}

#[test]
fn a_three_way_join_is_accepted_by_a_full_list() {
    // Capacity two, both slots held, and the free that arrives closes the gap
    // between them. Inserting first and merging after would need a third slot
    // and refuse a free this heap can plainly satisfy.
    let mut extents = Extents::<2>::new();
    extents
        .insert(Extent {
            start: 0x1000,
            len: 0x100,
        })
        .expect("low");
    extents
        .insert(Extent {
            start: 0x1200,
            len: 0x100,
        })
        .expect("high");
    assert_eq!(extents.holes(), 2);
    extents
        .insert(Extent {
            start: 0x1100,
            len: 0x100,
        })
        .expect("the gap between them");
    assert_eq!(extents.holes(), 1);
    assert_eq!(extents.free_bytes(), 0x300);
}

#[test]
fn a_full_list_refuses_a_hole_that_touches_nothing() {
    let mut extents = Extents::<2>::new();
    extents
        .insert(Extent {
            start: 0x1000,
            len: 0x10,
        })
        .expect("one");
    extents
        .insert(Extent {
            start: 0x2000,
            len: 0x10,
        })
        .expect("two");
    assert_eq!(
        extents.insert(Extent {
            start: 0x3000,
            len: 0x10
        }),
        Err(HeapError::TooFragmented)
    );
    // **Refused, and unchanged.** A refusal that had already shifted the array
    // would corrupt the list it declined to extend.
    assert_eq!(extents.holes(), 2);
    assert_eq!(extents.free_bytes(), 0x20);
}

#[test]
fn a_split_that_needs_a_slot_is_refused_before_it_mutates() {
    // Capacity two, both held. The first hole is too small to serve the
    // request at all; the second is misaligned *and* larger than needed, so
    // satisfying it leaves waste at both ends — two holes where one stood, and
    // no slot to put the second in.
    let mut extents = Extents::<2>::new();
    extents
        .insert(Extent {
            start: 0x1000,
            len: 0x8,
        })
        .expect("one");
    extents
        .insert(Extent {
            start: 0x2008,
            len: 0x1000,
        })
        .expect("two");
    let before = extents.free_bytes();
    assert_eq!(extents.take(0x10, 0x100), Err(HeapError::TooFragmented));
    assert_eq!(extents.free_bytes(), before);
    assert_eq!(extents.holes(), 2);
    assert_eq!(
        extents.as_slice(),
        &[
            Extent {
                start: 0x1000,
                len: 0x8
            },
            Extent {
                start: 0x2008,
                len: 0x1000
            },
        ]
    );
}

#[test]
fn a_split_with_room_for_the_tail_is_served() {
    // The same request against the same holes, with one slot spare. This is
    // what makes the refusal above a statement about capacity rather than
    // about the request.
    let mut extents = Extents::<3>::new();
    extents
        .insert(Extent {
            start: 0x1000,
            len: 0x8,
        })
        .expect("one");
    extents
        .insert(Extent {
            start: 0x2008,
            len: 0x1000,
        })
        .expect("two");
    assert_eq!(extents.take(0x10, 0x100), Ok(0x2100));
    assert_eq!(extents.holes(), 3);
}

#[test]
fn overlapping_frees_are_refused_rather_than_merged() {
    let mut extents = heap::<8>(0x1000, 0x1000);
    let a = extents.take(0x100, 1).expect("a");
    extents
        .insert(Extent {
            start: a,
            len: 0x100,
        })
        .expect("free once");
    // **The same block freed twice.** Coalescing this would put one address on
    // the free list under two lengths and hand it out to two callers.
    assert_eq!(
        extents.insert(Extent {
            start: a,
            len: 0x100
        }),
        Err(HeapError::NotAllocated)
    );
}

#[test]
fn freeing_something_that_was_never_taken_is_refused() {
    let mut extents = heap::<8>(0x1000, 0x1000);
    assert_eq!(
        extents.insert(Extent {
            start: 0x1800,
            len: 0x10
        }),
        Err(HeapError::NotAllocated)
    );
}

#[test]
fn no_space_is_distinct_from_too_fragmented() {
    let mut extents = heap::<8>(0x1000, 0x100);
    // The heap simply is not big enough, which is the caller's cue to grow
    // rather than a sign anything is wrong.
    assert_eq!(extents.take(0x200, 1), Err(HeapError::NoSpace));
}

#[test]
fn a_zero_or_unaligned_request_is_invalid() {
    let mut extents = heap::<8>(0x1000, 0x1000);
    assert_eq!(extents.take(0, 1), Err(HeapError::Invalid));
    assert_eq!(extents.take(0x10, 0), Err(HeapError::Invalid));
    assert_eq!(extents.take(0x10, 3), Err(HeapError::Invalid));
}

#[test]
fn growth_is_a_free_that_joins_the_end() {
    // What the syscall-backed grow path does: map more memory immediately
    // after what is held and hand the range to the free list. Contiguous
    // growth must not cost a hole, or a program that grew often would run out
    // of extents rather than out of memory.
    let mut extents = heap::<8>(0x1000, 0x1000);
    extents
        .insert(Extent {
            start: 0x2000,
            len: 0x1000,
        })
        .expect("grow");
    assert_eq!(extents.holes(), 1);
    assert_eq!(extents.free_bytes(), 0x2000);
    assert_eq!(extents.take(0x1800, 1), Ok(0x1000));
}

#[test]
fn a_gap_between_growths_stays_a_gap() {
    // And when the mapping is not contiguous — which the allocator may not
    // assume, because a VA it asked for may be refused — the two stay
    // separate and an allocation spanning them is refused rather than
    // straddling unmapped memory.
    let mut extents = heap::<8>(0x1000, 0x1000);
    extents
        .insert(Extent {
            start: 0x9000,
            len: 0x1000,
        })
        .expect("grow elsewhere");
    assert_eq!(extents.holes(), 2);
    assert_eq!(extents.take(0x1800, 1), Err(HeapError::NoSpace));
    assert_eq!(extents.free_bytes(), 0x2000);
}

#[test]
fn alignment_round_up_does_not_wrap() {
    assert_eq!(align_up(0x1001, 0x1000), Some(0x2000));
    assert_eq!(align_up(0x1000, 0x1000), Some(0x1000));
    assert_eq!(align_up(usize::MAX, 0x1000), None);
}

#[test]
fn an_extent_reaching_the_last_representable_address_works() {
    // Ends are exclusive, so the highest extent this can describe is one whose
    // end is `usize::MAX` — every address below the final byte. That is not a
    // narrow escape: it is the whole address space bar one byte, and no port's
    // user half comes near it (32-bit RISC-V's ends at the 2 GiB boundary,
    // D106).
    let mut extents = Extents::<4>::new();
    let start = usize::MAX - 0x100;
    extents.insert(Extent { start, len: 0x100 }).expect("top");
    assert_eq!(extents.take(0x100, 1), Ok(start));
    assert_eq!(extents.holes(), 0);
}

#[test]
fn an_extent_including_the_final_byte_is_refused_rather_than_wrapped() {
    // One byte further and the exclusive end is unrepresentable. **Refused,
    // not truncated and not wrapped**: an extent whose end silently became 0
    // would compare as ending below its own start and the free list would hand
    // out addresses inside it for ever.
    let mut extents = Extents::<4>::new();
    assert_eq!(
        extents.insert(Extent {
            start: usize::MAX - 0xff,
            len: 0x100
        }),
        Err(HeapError::Invalid)
    );
    assert_eq!(extents.holes(), 0);
}

#[test]
fn a_repeated_take_and_free_cycle_does_not_leak_holes() {
    // The shape a long-running program actually has. Fragmentation that grew
    // by one hole per cycle would pass every single-shot test above and fail
    // this on the sixteenth iteration.
    let mut extents = heap::<8>(0x1000, 0x1000);
    for _ in 0..1000 {
        let a = extents.take(0x40, 16).expect("a");
        let b = extents.take(0x80, 16).expect("b");
        extents
            .insert(Extent {
                start: a,
                len: 0x40,
            })
            .expect("free a");
        extents
            .insert(Extent {
                start: b,
                len: 0x80,
            })
            .expect("free b");
    }
    assert_eq!(extents.holes(), 1);
    assert_eq!(extents.free_bytes(), 0x1000);
}
