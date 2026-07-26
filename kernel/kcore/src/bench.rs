// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Microbenchmark statistics for the performance harness
//! (docs/prototypes/01-ipc-benchmark-harness.md). Percentiles are computed
//! **exactly from the fully sorted sample set** — never a streaming estimator,
//! as the methodology requires — and outliers are counted, never dropped. Pure
//! arithmetic over a caller-owned sample slice (no allocation), so it is
//! host-tested; the benchmark *driving* (the serialized cycle reads and the
//! measured loops) lives in the port and the kernel crate.
//!
//! Normative: docs/prototypes/01-ipc-benchmark-harness.md ("Measurement
//! Methodology", "Reporting")
//! Budget: none (this measures budgets; it is not itself on a budgeted path)

/// Summary statistics of one benchmark's sample set, in the samples' unit
/// (e.g. TSC cycles). Percentiles are actual observed samples (nearest-rank).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stats {
    pub count: usize,
    pub min: u64,
    pub max: u64,
    pub mean: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
}

impl Stats {
    /// Computes exact statistics from `samples`, **sorting it in place**. Returns
    /// `None` for an empty set. Each percentile uses the nearest-rank method on
    /// the sorted set — `rank = ceil(p/100 · n)`, 1-based, clamped to `[1, n]` —
    /// so every reported value is an actually observed sample.
    pub fn from_samples(samples: &mut [u64]) -> Option<Stats> {
        let count = samples.len();
        if count == 0 {
            return None;
        }
        // Mean is order-independent; accumulate in u128 to avoid overflow.
        let sum: u128 = samples.iter().map(|&s| u128::from(s)).sum();
        let mean = (sum / count as u128) as u64;
        samples.sort_unstable();
        let percentile = |p: u64| -> u64 {
            let rank = (p * count as u64).div_ceil(100).clamp(1, count as u64);
            samples[(rank - 1) as usize]
        };
        Some(Stats {
            count,
            min: samples[0],
            max: samples[count - 1],
            mean,
            p50: percentile(50),
            p90: percentile(90),
            p99: percentile(99),
        })
    }

    /// Number of samples at or above `threshold` — the outlier count the
    /// methodology requires be *reported*, not dropped. Order-independent.
    pub fn outliers_at_or_above(samples: &[u64], threshold: u64) -> usize {
        samples.iter().filter(|&&s| s >= threshold).count()
    }
}

#[cfg(test)]
mod tests {
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
}
