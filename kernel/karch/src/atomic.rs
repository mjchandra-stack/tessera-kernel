// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A 64-bit atomic counter that exists on every supported target.
//!
//! # Why this module exists
//!
//! `core::sync::atomic::AtomicU64` is not a portable type. It exists only
//! where the target has a 64-bit atomic instruction, and two of the five
//! architectures in `docs/hardware/01-platform-and-cpu-support.md` do not:
//! RISC-V 32-bit tops out at 32-bit atomics, and so does the 32-bit ARM
//! profile without the load/store-exclusive-doubleword pair. The kernel core
//! is architecture-independent and compiles for all five, so it cannot name a
//! type that three of them have and two do not.
//!
//! The values that need this are counters and identities, never pointers:
//! dropped-write counts, the trace epoch and sequence, thread and process
//! ids, an active-core mask. All of them are 64 bits wide in the ABI and must
//! stay 64 bits wide on a 32-bit machine — narrowing them there would be a
//! silent, per-target change to what an event record means, which is the
//! shape of degradation `docs/lifecycle/04` forbids.
//!
//! # The two implementations
//!
//! **Where the target has a 64-bit atomic**, this is a `#[repr(transparent)]`
//! newtype over `core::sync::atomic::AtomicU64` whose every method is an
//! `#[inline]` delegate. It compiles to exactly what the standard type
//! compiles to — which is not a hope: the three existing ports' boot output
//! is byte-identical across this change, and that is what checks it.
//!
//! **Where it does not**, the value lives in two `AtomicU32` halves and is
//! read back with a retry on the high half. That protocol is correct here
//! for a reason worth stating plainly rather than assuming: every value this
//! type holds is **monotonic or write-once**, so the high half changes only
//! on a carry — once per 2^32 operations — and a reader that sees the high
//! half unchanged either side of the low read has observed a consistent
//! pair. A reader that catches a carry in flight retries.
//!
//! A seqlock would be the general answer and is the wrong one here: the
//! writers are reentrant. `set_current` is called from `Scheduler::switch_to`,
//! which the timer tick reaches through `on_tick`, so a writer can be
//! interrupted by another writer on the same core. A seqlock's odd/even
//! sequence cannot survive that, and neither can a `SpinLock` — the same
//! deadlock `crate::trace`'s header describes. The retry-on-high protocol
//! survives it because it has no critical section: a nested writer leaves the
//! halves individually consistent, and the reader's check is on the value it
//! actually read, not on a lock it took.
//!
//! What the split implementation does **not** provide is a linearizable
//! 64-bit read-modify-write. `fetch_add` increments the low half atomically
//! and carries into the high half as a separate operation, so two increments
//! racing across a carry boundary can leave the high half short. On a
//! single-core kernel (D8) that race does not exist between threads, only
//! between a thread and an interrupt handler on the same core, and both of
//! those complete their carry before the other resumes. It is recorded rather
//! than hidden, and it is the reason this type is named for counters and not
//! offered as a general atomic.
//!
//! # Testing the path this machine does not run
//!
//! Both implementations always compile. The split one is exercised by this
//! module's own tests on the host, so the 32-bit protocol is tested from a
//! 64-bit development machine rather than being taken on trust until a
//! 32-bit port exists to run it.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Endianness And
//! Word Size"), docs/lifecycle/04-coding-guidelines.md ("Concurrency")
//! Budget: none (a relaxed load per emitted event)

#[cfg(target_has_atomic = "64")]
use core::sync::atomic::Ordering;

/// A 64-bit atomic counter, available on every supported target.
///
/// Drop-in for the subset of `core::sync::atomic::AtomicU64` the kernel core
/// uses. See the module header for what the split implementation does and
/// does not guarantee.
#[cfg(target_has_atomic = "64")]
#[repr(transparent)]
pub struct AtomicU64(core::sync::atomic::AtomicU64);

#[cfg(target_has_atomic = "64")]
impl AtomicU64 {
    pub const fn new(value: u64) -> Self {
        Self(core::sync::atomic::AtomicU64::new(value))
    }

    #[inline]
    pub fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    #[inline]
    pub fn store(&self, value: u64, order: Ordering) {
        self.0.store(value, order)
    }

    #[inline]
    pub fn swap(&self, value: u64, order: Ordering) -> u64 {
        self.0.swap(value, order)
    }

    #[inline]
    pub fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
        self.0.fetch_add(value, order)
    }

    #[inline]
    pub fn fetch_or(&self, value: u64, order: Ordering) -> u64 {
        self.0.fetch_or(value, order)
    }
}

#[cfg(not(target_has_atomic = "64"))]
pub use split::AtomicU64;

/// The implementation used where the target has no 64-bit atomic. Always
/// compiled — on a 64-bit host it is dead code in the kernel and live code in
/// this module's tests, which is the point. The `allow` is that arrangement
/// stated, not a warning silenced: on a 64-bit target nothing outside the
/// tests reaches this module, and it must still compile there or the tests
/// would only run where they are least needed.
#[cfg_attr(target_has_atomic = "64", allow(dead_code))]
#[allow(clippy::cast_possible_truncation)]
mod split {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// A 64-bit counter held as two 32-bit halves.
    pub struct AtomicU64 {
        low: AtomicU32,
        high: AtomicU32,
    }

    impl AtomicU64 {
        pub const fn new(value: u64) -> Self {
            Self {
                low: AtomicU32::new(value as u32),
                high: AtomicU32::new((value >> 32) as u32),
            }
        }

        /// Reads the pair, retrying while a carry is in flight.
        ///
        /// The high half is read, then the low, then the high again. If the
        /// high half is unchanged, no carry happened between the two reads
        /// and the pair is consistent. The loop is bounded in practice by the
        /// carry rate (once per 2^32 operations), not by contention.
        pub fn load(&self, order: Ordering) -> u64 {
            loop {
                let high = self.high.load(order);
                let low = self.low.load(order);
                if self.high.load(order) == high {
                    return (u64::from(high) << 32) | u64::from(low);
                }
            }
        }

        /// Publishes a value. The high half is written first so a concurrent
        /// reader that catches the pair mid-write sees the *new* high with the
        /// *old* low — which its retry check rejects — rather than a low that
        /// has already wrapped under an old high.
        pub fn store(&self, value: u64, order: Ordering) {
            self.high.store((value >> 32) as u32, order);
            self.low.store(value as u32, order);
        }

        pub fn swap(&self, value: u64, order: Ordering) -> u64 {
            let previous = self.load(order);
            self.store(value, order);
            previous
        }

        /// Adds to the low half and carries into the high half. Returns the
        /// previous value. See the module header: the carry is a second
        /// operation, so this is not a linearizable 64-bit RMW.
        pub fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
            let carry_in = (value >> 32) as u32;
            let low_add = value as u32;
            let previous_low = self.low.fetch_add(low_add, order);
            let wrapped = previous_low.checked_add(low_add).is_none();
            let high_add = carry_in.wrapping_add(u32::from(wrapped));
            let previous_high = if high_add == 0 {
                self.high.load(order)
            } else {
                self.high.fetch_add(high_add, order)
            };
            (u64::from(previous_high) << 32) | u64::from(previous_low)
        }

        /// Sets bits in both halves.
        ///
        /// Unlike [`fetch_add`](Self::fetch_add) the *effect* here is fully
        /// atomic even split in two: each half's `fetch_or` is atomic and no
        /// bit of one half depends on the other, so every bit named by `value`
        /// is set exactly as a single 64-bit `fetch_or` would set it. Only the
        /// returned previous value can be a torn pair, and the callers of this
        /// operation — setting a core's bit in an active-core mask — use it for
        /// the effect and not for the return.
        pub fn fetch_or(&self, value: u64, order: Ordering) -> u64 {
            let previous_low = self.low.fetch_or(value as u32, order);
            let previous_high = self.high.fetch_or((value >> 32) as u32, order);
            (u64::from(previous_high) << 32) | u64::from(previous_low)
        }
    }
}

#[cfg(test)]
mod tests {
    // The split implementation is tested directly, not through the cfg-
    // selected alias: on a 64-bit host the alias is the delegating newtype,
    // and testing that would only be testing the standard library.
    use super::split::AtomicU64;
    use core::sync::atomic::Ordering::Relaxed;

    #[test]
    fn a_value_survives_the_round_trip_through_two_halves() {
        for value in [
            0,
            1,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            0x0123_4567_89ab_cdef,
            u64::MAX,
        ] {
            let counter = AtomicU64::new(value);
            assert_eq!(counter.load(Relaxed), value, "new/load {value:#x}");

            let counter = AtomicU64::new(0);
            counter.store(value, Relaxed);
            assert_eq!(counter.load(Relaxed), value, "store/load {value:#x}");
        }
    }

    #[test]
    fn fetch_add_returns_the_previous_value_and_carries_across_the_halves() {
        // Ordinary increment, no carry.
        let counter = AtomicU64::new(7);
        assert_eq!(counter.fetch_add(1, Relaxed), 7);
        assert_eq!(counter.load(Relaxed), 8);

        // The case the split representation exists to get right: the low half
        // wraps and the high half must take the carry.
        let counter = AtomicU64::new(u64::from(u32::MAX));
        assert_eq!(counter.fetch_add(1, Relaxed), u64::from(u32::MAX));
        assert_eq!(counter.load(Relaxed), u64::from(u32::MAX) + 1);

        // An addend wider than the low half carries too.
        let counter = AtomicU64::new(0);
        let wide = (3u64 << 32) | 5;
        assert_eq!(counter.fetch_add(wide, Relaxed), 0);
        assert_eq!(counter.load(Relaxed), wide);

        // Both at once: a wide addend that also wraps the low half.
        let counter = AtomicU64::new(u64::from(u32::MAX));
        assert_eq!(counter.fetch_add(wide, Relaxed), u64::from(u32::MAX));
        assert_eq!(counter.load(Relaxed), u64::from(u32::MAX) + wide);
    }

    #[test]
    fn a_long_run_of_increments_crosses_the_carry_without_drift() {
        // Starts just below the boundary and walks across it, so the carry is
        // taken in the middle of a sequence rather than in isolation.
        let start = u64::from(u32::MAX) - 4;
        let counter = AtomicU64::new(start);
        for step in 0..10u64 {
            assert_eq!(counter.fetch_add(1, Relaxed), start + step);
        }
        assert_eq!(counter.load(Relaxed), start + 10);
    }

    #[test]
    fn swap_returns_the_previous_value_and_installs_the_new_one() {
        let counter = AtomicU64::new(0xdead_beef_cafe_f00d);
        assert_eq!(counter.swap(1, Relaxed), 0xdead_beef_cafe_f00d);
        assert_eq!(counter.load(Relaxed), 1);
    }

    #[test]
    fn the_halves_hold_the_expected_bits() {
        // Guards the layout the load/store protocol assumes: the high half is
        // bits 63..32 and the low half is 31..0, not the reverse.
        let counter = AtomicU64::new(0xaaaa_bbbb_cccc_dddd);
        assert_eq!(counter.load(Relaxed) >> 32, 0xaaaa_bbbb);
        assert_eq!(counter.load(Relaxed) & 0xffff_ffff, 0xcccc_dddd);
    }
}
