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
#[path = "tests/bench.rs"]
mod tests;
