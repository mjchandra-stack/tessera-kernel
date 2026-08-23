// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::counter`.

use super::*;

#[test]
fn a_sharded_count_totals_what_was_added_to_every_shard() {
    let counter = Sharded::new();
    assert_eq!(counter.total(), 0);

    counter.bump();
    counter.add(41);
    assert_eq!(counter.total(), 42);
    assert_eq!(
        counter.here(),
        42,
        "a host test is one CPU, so its own shard holds everything"
    );

    // Another CPU's shard, written the way that CPU would write it — a host
    // test cannot *be* another CPU, because the per-CPU index source is one
    // process-wide store and pointing it elsewhere would move every parallel
    // test's state with it.
    counter.shards[1].add(8, Ordering::Relaxed);
    assert_eq!(
        counter.total(),
        50,
        "the total is the sum, or a machine-wide tally would report whichever \
         CPU happened to be asked"
    );

    // Taking empties every shard, not only the caller's — otherwise a boot
    // reporting what it dropped would go on reporting another CPU's drops for
    // ever.
    assert_eq!(counter.take(), 50);
    assert_eq!(counter.total(), 0);
}

/// The split [`SharedCounter`] protocol, under real threads.
///
/// **Here and not in `karch` because `karch` is `no_std`.** Its own tests can
/// check that the arithmetic carries, which was never the doubtful half; what
/// needed a second thread is whether a *reader* can catch a write in flight.
/// This crate's test build has `std`, so it can ask.
///
/// Nothing on a 64-bit target reaches the split path in the kernel — the
/// cfg-selected type is a `core::sync::atomic::AtomicU64` — so this is the
/// only place the two 32-bit ports' counter is exercised at all.
#[test]
fn a_shared_counter_never_shows_a_reader_a_value_that_went_backwards() {
    use core::sync::atomic::{AtomicBool, Ordering::Relaxed};
    use std::sync::Arc;
    use tessera_karch::atomic::split::SharedCounter;

    /// Adds per writer. Enough that the reader below samples across many
    /// thousands of carries rather than hoping to land on one.
    const EACH: u64 = 100_000;
    const WRITERS: u64 = 3;
    /// **Every single add wraps the low half.** Adding `u32::MAX` to any low
    /// half above zero carries, so the window this test is looking for is open
    /// on essentially every operation instead of once per 2^32. A counter that
    /// carried into the high half as a *separate* operation — the `fetch_add`
    /// this type replaced — leaves a reader seeing a value 2^32 short for the
    /// length of that window, and with the window always open the reader finds
    /// it in milliseconds.
    const STEP: u64 = u32::MAX as u64;

    let counter = Arc::new(SharedCounter::new(1));
    let done = Arc::new(AtomicBool::new(false));

    let reader = {
        let counter = Arc::clone(&counter);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let mut highest = 0u64;
            let mut samples = 0u64;
            while !done.load(Relaxed) {
                let seen = counter.load(Relaxed);
                assert!(
                    seen >= highest,
                    "a counter that only grows was read going backwards: \
                     {seen} after {highest} — a reader caught a carry in flight"
                );
                highest = seen;
                samples += 1;
            }
            samples
        })
    };

    let writers: std::vec::Vec<_> = (0..WRITERS)
        .map(|_| {
            let counter = Arc::clone(&counter);
            std::thread::spawn(move || {
                for _ in 0..EACH {
                    counter.fetch_add(STEP, Relaxed);
                }
            })
        })
        .collect();
    for writer in writers {
        assert!(writer.join().is_ok(), "a writer panicked");
    }
    done.store(true, Relaxed);
    let samples = reader.join();
    assert!(samples.is_ok(), "the reader saw the counter go backwards");
    assert!(
        samples.unwrap_or(0) > 0,
        "the reader took no samples, so it checked nothing"
    );

    assert_eq!(
        counter.load(Relaxed),
        1 + WRITERS * EACH * STEP,
        "and every increment landed — the writers excluded each other"
    );
}
