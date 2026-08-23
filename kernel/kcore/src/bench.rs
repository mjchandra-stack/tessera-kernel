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

/// A nanosecond duration rendered in **bounded** width — never more than
/// [`Nanos::MAX_WIDTH`] characters, for any `u64`.
///
/// # Why a log line cannot print a raw measurement
///
/// `//tools/qemu`'s boot checks reject any rendered line over 150 characters,
/// and `//tools/checks:logging` enforces the same bound on the format strings.
/// The static gate cannot see interpolated values, which is exactly why the
/// runtime one exists — and a *measured* value has no width. AArch64's B7
/// context-switch line sat at 147 characters with `max=84064ns`; under host
/// load that outlier gains digits and the line tips over, so the check failed
/// on a different random subset of boots each run. The value was a fact about
/// the host's scheduler; the failure was a fact about `{}`.
///
/// # Exact where it matters, bounded always
///
/// Anything under ten milliseconds prints as exact nanoseconds, which is every
/// sample anyone reads — a p50, a p99, an ordinary maximum. Beyond that the
/// number is an outlier from something outside the kernel, and precision in it
/// buys nothing, so it scales to milliseconds or seconds and stays narrow. A
/// duration past ten thousand seconds is reported as *greater than* rather
/// than rendered, because a benchmark sample that long is not a measurement.
///
/// Scaling everything would have been the obvious answer and is the wrong one:
/// `1872ns` is the number a reader acts on, and `1.9us` is not the same
/// number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Nanos(pub u64);

impl Nanos {
    /// The widest this can ever render: `9999999ns`.
    ///
    /// The bound the line-length budget is built on, and checked directly
    /// rather than reasoned about — the widest value in each range is rendered
    /// and measured (`tests/bench.rs`).
    pub const MAX_WIDTH: usize = 9;

    /// Below this, nanoseconds are printed exactly.
    const EXACT_BELOW: u64 = 10_000_000;
    /// Below this, milliseconds with one decimal.
    const MILLIS_BELOW: u64 = 10_000_000_000;
    /// Below this, seconds with one decimal; at or above it, a bound.
    const SECONDS_BELOW: u64 = 10_000_000_000_000;
}

impl core::fmt::Display for Nanos {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let value = self.0;
        if value < Self::EXACT_BELOW {
            write!(f, "{value}ns")
        } else if value < Self::MILLIS_BELOW {
            write!(f, "{}.{}ms", value / 1_000_000, (value / 100_000) % 10)
        } else if value < Self::SECONDS_BELOW {
            write!(
                f,
                "{}.{}s",
                value / 1_000_000_000,
                (value / 100_000_000) % 10
            )
        } else {
            // Not rendered, and not clamped silently either: `>` says the
            // number was refused rather than that it happened to be this.
            write!(f, ">9999s")
        }
    }
}

#[cfg(test)]
#[path = "tests/bench.rs"]
mod tests;
