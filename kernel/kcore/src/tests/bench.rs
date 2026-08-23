// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::bench`.

use super::*;

#[test]
fn percentiles_are_exact_observed_samples() {
    // 1..=100 in scrambled order → sorted stats are the values themselves.
    let mut samples: [u64; 100] = core::array::from_fn(|i| ((i * 37) % 100) as u64 + 1);
    let stats = Stats::from_samples(&mut samples).expect("stats");
    assert_eq!(stats.count, 100);
    assert_eq!(stats.min, 1);
    assert_eq!(stats.max, 100);
    assert_eq!(stats.mean, 50); // (1+..+100)/100 = 50 (integer)
    // nearest-rank: p50 → sample[49]=50, p90 → sample[89]=90, p99 → sample[98]=99.
    assert_eq!(stats.p50, 50);
    assert_eq!(stats.p90, 90);
    assert_eq!(stats.p99, 99);
}

#[test]
fn single_sample_is_every_statistic() {
    let mut samples = [42u64];
    let stats = Stats::from_samples(&mut samples).expect("stats");
    assert_eq!(
        stats,
        Stats {
            count: 1,
            min: 42,
            max: 42,
            mean: 42,
            p50: 42,
            p90: 42,
            p99: 42,
        }
    );
}

#[test]
fn all_equal_samples() {
    let mut samples = [7u64; 16];
    let stats = Stats::from_samples(&mut samples).expect("stats");
    assert_eq!(stats.min, 7);
    assert_eq!(stats.max, 7);
    assert_eq!(stats.mean, 7);
    assert_eq!(stats.p99, 7);
}

#[test]
fn empty_set_has_no_stats() {
    let mut samples: [u64; 0] = [];
    assert_eq!(Stats::from_samples(&mut samples), None);
}

#[test]
fn outliers_are_counted_not_dropped() {
    let samples = [10u64, 10, 10, 10, 500, 900];
    // The two large samples are reported, never removed from the set.
    assert_eq!(Stats::outliers_at_or_above(&samples, 100), 2);
    assert_eq!(Stats::outliers_at_or_above(&samples, 1000), 0);
}

#[test]
fn a_duration_is_exact_below_ten_milliseconds_and_never_wider_than_its_bound() {
    use core::fmt::Write as _;

    let render = |ns: u64| {
        let mut buf = std::string::String::new();
        write!(&mut buf, "{}", Nanos(ns)).expect("render");
        buf
    };

    // Exact nanoseconds where a reader acts on the digits. `1872ns` is the
    // number, and `1.9us` is a different one.
    assert_eq!(render(0), "0ns");
    assert_eq!(render(1_872), "1872ns");
    assert_eq!(render(84_064), "84064ns");
    assert_eq!(render(9_999_999), "9999999ns");

    // Past ten milliseconds the value is an outlier from something outside
    // the kernel, so it scales rather than growing the line.
    assert_eq!(render(10_000_000), "10.0ms");
    assert_eq!(render(3_620_809_000), "3620.8ms");
    assert_eq!(render(9_999_999_999), "9999.9ms");
    assert_eq!(render(10_000_000_000), "10.0s");
    assert_eq!(render(9_999_999_999_999), "9999.9s");

    // ...and past ten thousand seconds it is refused rather than clamped
    // silently: `>` says the number was not rendered.
    assert_eq!(render(10_000_000_000_000), ">9999s");
    assert_eq!(render(u64::MAX), ">9999s");

    // **The bound itself**, checked across every range rather than argued.
    // This is what the line-length budget rests on: a log line built from
    // these fields has a width that does not depend on what was measured.
    for ns in [
        0,
        1,
        9_999_999,
        10_000_000,
        9_999_999_999,
        10_000_000_000,
        9_999_999_999_999,
        10_000_000_000_000,
        u64::MAX,
    ] {
        let rendered = render(ns);
        assert!(
            rendered.len() <= Nanos::MAX_WIDTH,
            "{ns} rendered as {rendered:?}, {} characters against a bound of {}",
            rendered.len(),
            Nanos::MAX_WIDTH
        );
    }
}
