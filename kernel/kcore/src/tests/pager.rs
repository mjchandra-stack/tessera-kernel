// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::pager`.

use super::*;

const PAGE: u64 = 4096;

#[test]
fn install_records_a_clean_resident_page() {
    let mut cache = ObjectCache::new(8);
    cache.install(0).expect("install");
    assert!(cache.is_resident(0));
    assert!(!cache.is_dirty(0));
    assert_eq!(cache.resident_count(), 1);
    // Idempotent.
    cache.install(0).expect("install again");
    assert_eq!(cache.resident_count(), 1);
}

#[test]
fn a_write_marks_dirty_until_the_bound_then_throttles() {
    let mut cache = ObjectCache::new(2);
    for i in 0..3 {
        cache.install(i * PAGE).expect("install");
    }
    assert_eq!(cache.mark_dirty(0), DirtyOutcome::Marked);
    assert_eq!(cache.mark_dirty(PAGE), DirtyOutcome::Marked);
    assert_eq!(cache.dirty_count(), 2);
    // The third distinct dirty page would exceed the bound of 2 → throttle,
    // and it stays clean.
    assert_eq!(cache.mark_dirty(2 * PAGE), DirtyOutcome::Throttle);
    assert!(!cache.is_dirty(2 * PAGE));
    assert_eq!(cache.dirty_count(), 2);
    // Re-dirtying an already-dirty page is always free.
    assert_eq!(cache.mark_dirty(0), DirtyOutcome::Marked);
}

#[test]
fn a_write_back_ack_lets_a_throttled_writer_proceed() {
    let mut cache = ObjectCache::new(1);
    cache.install(0).expect("install");
    cache.install(PAGE).expect("install");
    assert_eq!(cache.mark_dirty(0), DirtyOutcome::Marked);
    assert_eq!(cache.mark_dirty(PAGE), DirtyOutcome::Throttle);
    // The pager acks page 0's write-back → clean → room for another dirty.
    cache.mark_clean(0);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.mark_dirty(PAGE), DirtyOutcome::Marked);
}

#[test]
fn eviction_offers_only_clean_pages() {
    let mut cache = ObjectCache::new(8);
    cache.install(0).expect("install");
    cache.install(PAGE).expect("install");
    cache.mark_dirty(0);
    // Page 0 is dirty; the only evictable page is the clean one.
    assert_eq!(cache.evict_candidate(), Some(PAGE));
    cache.forget(PAGE);
    assert!(!cache.is_resident(PAGE));
    // Now every resident page is dirty — nothing may be evicted.
    assert_eq!(cache.evict_candidate(), None);
}

#[test]
fn dirty_offsets_are_exact_and_sorted() {
    let mut cache = ObjectCache::new(8);
    for off in [3 * PAGE, PAGE, 5 * PAGE, 0] {
        cache.install(off).expect("install");
    }
    cache.mark_dirty(5 * PAGE);
    cache.mark_dirty(PAGE);
    cache.mark_dirty(0);
    let mut buf = [0u64; 8];
    let n = cache.dirty_offsets(&mut buf);
    // Exactly the three dirtied offsets, ascending — not the clean 3*PAGE.
    assert_eq!(&buf[..n], &[0, PAGE, 5 * PAGE]);
}

#[test]
fn fault_reports_exactly_the_lost_dirty_ranges_and_seals_the_object() {
    let mut cache = ObjectCache::new(8);
    for off in [0, PAGE, 2 * PAGE] {
        cache.install(off).expect("install");
    }
    cache.mark_dirty(2 * PAGE);
    cache.mark_dirty(0);
    // Page 1*PAGE stays clean — it is not lost.
    let mut lost = [0u64; 8];
    let n = cache.fault(&mut lost);
    assert_eq!(&lost[..n], &[0, 2 * PAGE]);
    assert!(cache.is_faulted());
    assert_eq!(cache.resident_count(), 0);
    // A faulted object admits nothing further.
    assert_eq!(cache.install(0), Err(KError::BadHandle));
}

#[test]
fn a_full_cache_refuses_further_pages() {
    let mut cache = ObjectCache::new(0);
    for i in 0..MAX_CACHED_PAGES as u64 {
        cache.install(i * PAGE).expect("install");
    }
    assert_eq!(
        cache.install(MAX_CACHED_PAGES as u64 * PAGE),
        Err(KError::OutOfMemory)
    );
}

#[test]
fn reservation_keeps_write_back_progressing_at_pressure() {
    // 8 frames, 2 reserved for write-back → 6 for the ordinary path.
    let mut res = WriteBackReservation::new(8, 2);
    // Drive the ordinary path to hard pressure: exactly 6 succeed, then block.
    let mut ordinary = 0;
    while res.alloc_ordinary().is_some() {
        ordinary += 1;
    }
    assert_eq!(ordinary, 6);
    assert!(res.at_pressure());
    assert_eq!(res.alloc_ordinary(), None); // blocked, not a hang
    // The reserved write-back path still makes progress under pressure.
    assert_eq!(res.alloc_writeback(), Some(()));
    // A write-back that drained a dirty page frees an ordinary frame → reclaim
    // progresses (an ordinary alloc now succeeds again).
    res.free_ordinary();
    assert_eq!(res.alloc_ordinary(), Some(()));
}

#[test]
fn write_back_past_the_reservation_fails_cleanly() {
    let mut res = WriteBackReservation::new(4, 2);
    // The reservation guarantees exactly 2 write-back frames.
    assert_eq!(res.alloc_writeback(), Some(()));
    assert_eq!(res.alloc_writeback(), Some(()));
    // Over-allocating past the reservation fails cleanly (None), never hangs.
    assert_eq!(res.alloc_writeback(), None);
    // Freeing one makes room again.
    res.free_writeback();
    assert_eq!(res.alloc_writeback(), Some(()));
}

#[test]
fn reservation_is_clamped_to_capacity() {
    let mut res = WriteBackReservation::new(2, 8);
    // reserved clamped to 2 → the whole budget is the reservation; ordinary
    // is immediately at pressure, write-back has the full budget.
    assert!(res.at_pressure());
    assert_eq!(res.alloc_ordinary(), None);
    assert_eq!(res.alloc_writeback(), Some(()));
    assert_eq!(res.alloc_writeback(), Some(()));
    assert_eq!(res.alloc_writeback(), None);
}

// Pager ids and object ids for the self-paging tests.
const PAGER_A: u32 = 0xA;
const PAGER_B: u32 = 0xB;
const OBJ_X: u64 = 0x100; // pager A's working set, paged by B
const OBJ_Y: u64 = 0x200; // pager B's working set, paged by A

#[test]
fn mutual_self_paging_is_detected_as_a_cycle() {
    let mut graph = SelfPagingGraph::new();
    graph.bind(OBJ_X, PAGER_B).expect("bind");
    graph.bind(OBJ_Y, PAGER_A).expect("bind");
    // A faults on its working set (served by B): no cycle yet.
    assert_eq!(graph.request_page_in(PAGER_A, OBJ_X), PageInResult::Served);
    // B then faults on its working set (served by A): A already waits for B,
    // so this closes A→B→A — a cycle, faulted rather than blocked.
    assert_eq!(graph.request_page_in(PAGER_B, OBJ_Y), PageInResult::Cycle);
    assert_eq!(graph.in_flight(), 1); // only A's edge; B's was faulted
}

#[test]
fn degenerate_single_self_paging_pager_is_a_cycle() {
    let mut graph = SelfPagingGraph::new();
    // A pages an object that is its own working set → faulting on it in its own
    // handler is an immediate self-cycle.
    graph.bind(OBJ_X, PAGER_A).expect("bind");
    assert_eq!(graph.request_page_in(PAGER_A, OBJ_X), PageInResult::Cycle);
}

#[test]
fn independent_page_ins_do_not_false_positive() {
    let mut graph = SelfPagingGraph::new();
    graph.bind(OBJ_X, PAGER_B).expect("bind");
    // A distinct client (not a pager in the graph) paging through B is fine,
    // and completing it clears the edge.
    assert_eq!(graph.request_page_in(PAGER_A, OBJ_X), PageInResult::Served);
    graph.complete(PAGER_A);
    assert_eq!(graph.in_flight(), 0);
    assert_eq!(graph.request_page_in(PAGER_A, OBJ_X), PageInResult::Served);
}

#[test]
fn an_unbound_object_faults_rather_than_hangs() {
    let mut graph = SelfPagingGraph::new();
    assert_eq!(graph.request_page_in(PAGER_A, OBJ_X), PageInResult::Cycle);
}

#[test]
fn a_request_expires_only_past_its_deadline() {
    let sup = PageInSupervisor::new(10, 3);
    // Within deadline (elapsed == deadline) → still pending.
    assert_eq!(sup.check(0, 10), DeadlineOutcome::Pending);
    // Past deadline (plus a bounded margin) → expired, so the fault is bounded.
    assert_eq!(sup.check(0, 11), DeadlineOutcome::Expired);
    assert_eq!(sup.check(100, 200), DeadlineOutcome::Expired);
}

#[test]
fn repeated_misses_escalate_on_the_threshold() {
    let mut sup = PageInSupervisor::new(10, 3);
    // First two misses stay within budget.
    assert_eq!(sup.record_miss(), MissOutcome::Continue);
    assert_eq!(sup.record_miss(), MissOutcome::Continue);
    // The third crosses the threshold → supervised restart.
    assert_eq!(sup.record_miss(), MissOutcome::Escalate);
    // The next cycle repeats: two continue, then escalate again.
    assert_eq!(sup.record_miss(), MissOutcome::Continue);
    assert_eq!(sup.record_miss(), MissOutcome::Continue);
    assert_eq!(sup.record_miss(), MissOutcome::Escalate);
    assert_eq!(sup.misses(), 6);
    assert_eq!(sup.escalations(), 2);
}

#[test]
fn a_zero_escalation_budget_escalates_every_miss() {
    let mut sup = PageInSupervisor::new(0, 0);
    assert_eq!(sup.record_miss(), MissOutcome::Escalate);
    assert_eq!(sup.record_miss(), MissOutcome::Escalate);
    assert_eq!(sup.escalations(), 2);
}
