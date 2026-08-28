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
//! # Three types, because there are three intents
//!
//! [`AtomicU64`] used to offer a `fetch_add`, and it was the one operation the
//! split representation could not honestly provide: the low half is
//! incremented atomically and the carry into the high half is a *second*
//! operation, so between the two there is a window in which a reader sees a
//! value 2^32 short. That was recorded as tolerable because the two targets
//! without a 64-bit atomic are the two 32-bit ports and neither starts a
//! second CPU — a condition about the machine, standing in for a property of
//! the type, in a type that any neutral code could reach.
//!
//! It is split by what the counter is *for* instead:
//!
//! * **[`AtomicU64`]** — a 64-bit *value*: loaded, stored, swapped, or
//!   bit-set. Every one of those is honest split in two (see the retry
//!   protocol above, and [`AtomicU64::fetch_or`] for why the bitwise case is
//!   fully atomic). There is no arithmetic on it, so the carry window cannot
//!   arise.
//! * **[`CpuCounter`]** — a counter **one CPU increments**, like a per-CPU
//!   tick or a per-CPU tally. Split-safe by construction: with a single
//!   writer there is no second increment to race the carry against, and a
//!   nested writer on the same CPU — an interrupt handler — completes its own
//!   carry before the interrupted one resumes.
//! * **[`SharedCounter`]** — a counter **any CPU increments**. This is the one
//!   the split representation cannot do with a read-modify-write, so it does
//!   not try: it serializes on a sequence word instead. Every target has a
//!   32-bit compare-and-swap (build/README.md, D234), which is what makes that
//!   possible at all, and the price is a contract — see the type.
//!
//! The plan this closes (`docs/roadmap/02-smp-bring-up-plan.md`, Phase 4)
//! predicted that a shared counter "simply does not exist on a target that
//! cannot implement it". It can, and the reason it can was found later: D234
//! established that a 32-bit compare-and-swap is available everywhere while
//! looking for a lock word. Non-existence would have been the wrong answer
//! anyway — `kcore` compiles for all five targets, so a type missing on two of
//! them is a type `kcore` cannot use.
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

/// A 64-bit atomic *value*, available on every supported target.
///
/// Loaded, stored, swapped, or bit-set — never added to. See the module
/// header: arithmetic is what the split representation cannot do honestly, and
/// it lives on [`CpuCounter`] and [`SharedCounter`] instead, each of which
/// says which concurrency it is for.
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
    pub fn fetch_or(&self, value: u64, order: Ordering) -> u64 {
        self.0.fetch_or(value, order)
    }
}

/// A 64-bit counter **one CPU increments**.
///
/// Per-CPU tallies: this CPU's ticks, this CPU's wakeups taken, this CPU's
/// shootdowns serviced. Any CPU may read it; only its owner adds to it.
///
/// **Split-safe by construction, which is why this is a type and not a
/// convention.** The split representation's carry is a second operation, and
/// what makes that harmless here is that there is no second writer to race it:
/// a nested writer on the same CPU — an interrupt handler — runs to completion
/// before the interrupted one resumes, so each increment applies its own carry
/// exactly once. Two CPUs adding to one instance is the case this type refuses
/// to be used for, and [`SharedCounter`] is what that case is for.
///
/// No `fetch_add`. The previous value is what a caller who is racing wants,
/// and a counter with one writer has nobody to race; returning it would be an
/// invitation to build a read-modify-write out of two operations, which is the
/// defect this split exists to remove.
#[cfg(target_has_atomic = "64")]
#[repr(transparent)]
pub struct CpuCounter(core::sync::atomic::AtomicU64);

#[cfg(target_has_atomic = "64")]
impl CpuCounter {
    pub const fn new(value: u64) -> Self {
        Self(core::sync::atomic::AtomicU64::new(value))
    }

    /// Adds to this CPU's tally.
    #[inline]
    pub fn add(&self, value: u64, order: Ordering) {
        self.0.fetch_add(value, order);
    }

    #[inline]
    pub fn get(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    #[inline]
    pub fn set(&self, value: u64, order: Ordering) {
        self.0.store(value, order)
    }
}

/// A 64-bit counter **any CPU increments**.
///
/// Machine-wide tallies and machine-wide monotonic sequences: the reclamation
/// epoch, the shootdown generation, dropped console writes.
///
/// **Where the target has a 64-bit atomic this is one instruction and carries
/// no contract.** Where it does not, it serializes writers on a sequence word,
/// and that costs a rule the type cannot enforce:
///
/// > A writer must not be interruptible by another writer of *the same*
/// > counter on the same CPU.
///
/// That rule is why [`AtomicU64`] does not use this protocol for its own
/// `store`: `crate::trace`'s publisher is reached from `Scheduler::switch_to`,
/// which the timer tick also reaches, so its writers *are* reentrant and a
/// sequence word would deadlock them. The counters here are advanced from
/// ordinary kernel paths — an unmap, a grace period, a dropped write — and
/// never from an interrupt handler that could land on one of them.
///
/// Readers take no lock and never block a writer; they retry while a write is
/// in flight.
#[cfg(target_has_atomic = "64")]
#[repr(transparent)]
pub struct SharedCounter(core::sync::atomic::AtomicU64);

#[cfg(target_has_atomic = "64")]
impl SharedCounter {
    pub const fn new(value: u64) -> Self {
        Self(core::sync::atomic::AtomicU64::new(value))
    }

    /// Adds, and returns what was there before.
    #[inline]
    pub fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
        self.0.fetch_add(value, order)
    }

    #[inline]
    pub fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    #[inline]
    pub fn swap(&self, value: u64, order: Ordering) -> u64 {
        self.0.swap(value, order)
    }
}

#[cfg(not(target_has_atomic = "64"))]
pub use split::{AtomicU64, CpuCounter, SharedCounter};

/// The implementations used where the target has no 64-bit atomic. Always
/// compiled — on a 64-bit host they are dead code in the kernel and live code
/// in this module's tests, which is the point. The `allow` is that arrangement
/// stated, not a warning silenced: on a 64-bit target nothing outside the
/// tests reaches this module, and it must still compile there or the tests
/// would only run where they are least needed.
/// **Public, and hidden from the documentation, so a crate that *has* threads
/// can hammer it.** This crate is unconditionally `no_std`, so its own tests
/// are single-threaded and can only check arithmetic — which is the half of
/// [`SharedCounter`] that was never in doubt. `kcore`'s test build has `std`,
/// and `kernel/kcore/src/tests/counter.rs` runs real threads against the
/// protocol below. Nothing in the kernel reaches this path on a 64-bit target;
/// exporting it is what lets it be tested from one.
#[doc(hidden)]
#[cfg_attr(target_has_atomic = "64", allow(dead_code))]
#[allow(clippy::cast_possible_truncation)]
pub mod split {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// The ordering a **load** may carry, for a caller's ordering that names a
    /// whole read-modify-write.
    ///
    /// `Release` and `AcqRel` are not orderings a load can have — the standard
    /// library panics on one rather than weakening it — so a split operation
    /// has to say which half of its caller's ordering belongs to which half of
    /// the operation. This is the same mapping `fetch_*` makes internally on a
    /// machine that has the instruction.
    #[inline]
    const fn load_order(order: Ordering) -> Ordering {
        match order {
            Ordering::Release => Ordering::Relaxed,
            Ordering::AcqRel => Ordering::Acquire,
            other => other,
        }
    }

    /// The ordering a **store** may carry, as [`load_order`] for the write.
    #[inline]
    const fn store_order(order: Ordering) -> Ordering {
        match order {
            Ordering::Acquire => Ordering::Relaxed,
            Ordering::AcqRel => Ordering::Release,
            other => other,
        }
    }

    /// Reads a pair of halves, retrying while a carry is in flight.
    ///
    /// The high half is read, then the low, then the high again. If the high
    /// half is unchanged, no carry happened between the two reads and the pair
    /// is consistent. The loop is bounded in practice by the carry rate (once
    /// per 2^32 operations), not by contention.
    #[inline]
    fn load_pair(high: &AtomicU32, low: &AtomicU32, order: Ordering) -> u64 {
        let order = load_order(order);
        loop {
            let top = high.load(order);
            let bottom = low.load(order);
            if high.load(order) == top {
                return (u64::from(top) << 32) | u64::from(bottom);
            }
        }
    }

    /// Publishes a value into a pair of halves. The high half is written first
    /// so a concurrent reader that catches the pair mid-write sees the *new*
    /// high with the *old* low — which [`load_pair`]'s retry check rejects —
    /// rather than a low that has already wrapped under an old high.
    #[inline]
    fn store_pair(high: &AtomicU32, low: &AtomicU32, value: u64, order: Ordering) {
        let order = store_order(order);
        high.store((value >> 32) as u32, order);
        low.store(value as u32, order);
    }

    /// A 64-bit value held as two 32-bit halves.
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

        pub fn load(&self, order: Ordering) -> u64 {
            load_pair(&self.high, &self.low, order)
        }

        pub fn store(&self, value: u64, order: Ordering) {
            store_pair(&self.high, &self.low, value, order);
        }

        /// Reads the pair and replaces it, splitting the caller's ordering
        /// across the two halves of the operation.
        ///
        /// **Not atomic as a whole, and its callers do not need it to be.**
        /// The pair is read and then written, so a concurrent writer could
        /// land between them; every caller of this in the kernel is a single
        /// consumer draining a value it alone takes (`kcore::wakeup` taking a
        /// CPU's pending bits, `kcore::scaling` taking a report). A caller that
        /// needed a true exchange would need a lock here, and would be wrong to
        /// use this.
        ///
        /// The **ordering** is split rather than passed through, which is what
        /// this was doing wrong: a `swap(.., Acquire)` handed `Acquire` to a
        /// store, and the standard library's answer to that is a panic —
        /// reached the moment this port first ran a thread that drained a
        /// wakeup (build/README.md, D260).
        pub fn swap(&self, value: u64, order: Ordering) -> u64 {
            let previous = load_pair(&self.high, &self.low, order);
            store_pair(&self.high, &self.low, value, order);
            previous
        }

        /// Sets bits in both halves.
        ///
        /// The *effect* here is fully atomic even split in two: each half's
        /// `fetch_or` is atomic and no bit of one half depends on the other,
        /// so every bit named by `value` is set exactly as a single 64-bit
        /// `fetch_or` would set it. Only the returned previous value can be a
        /// torn pair, and the callers of this operation — setting a CPU's bit
        /// in a mask — use it for the effect and not for the return.
        pub fn fetch_or(&self, value: u64, order: Ordering) -> u64 {
            let previous_low = self.low.fetch_or(value as u32, order);
            let previous_high = self.high.fetch_or((value >> 32) as u32, order);
            (u64::from(previous_high) << 32) | u64::from(previous_low)
        }
    }

    /// A 64-bit counter with one writer, held as two 32-bit halves.
    pub struct CpuCounter {
        low: AtomicU32,
        high: AtomicU32,
    }

    impl CpuCounter {
        pub const fn new(value: u64) -> Self {
            Self {
                low: AtomicU32::new(value as u32),
                high: AtomicU32::new((value >> 32) as u32),
            }
        }

        /// Adds to the low half and carries into the high half.
        ///
        /// Two operations, and correct because the type's contract says there
        /// is one writer: the carry belongs to this increment and no other
        /// increment can be between them. A *reader* can still catch the
        /// window — the low half wrapped, the high half not yet raised — and
        /// sees a value 2^32 short for the length of one instruction, once
        /// every 2^32 increments. That is a per-CPU tally, read for a boot line
        /// or a health check, and the alternative is serializing every
        /// increment against a reader that almost never looks.
        pub fn add(&self, value: u64, order: Ordering) {
            let carry_in = (value >> 32) as u32;
            let low_add = value as u32;
            let previous_low = self.low.fetch_add(low_add, order);
            let wrapped = previous_low.checked_add(low_add).is_none();
            let high_add = carry_in.wrapping_add(u32::from(wrapped));
            if high_add != 0 {
                self.high.fetch_add(high_add, order);
            }
        }

        pub fn get(&self, order: Ordering) -> u64 {
            load_pair(&self.high, &self.low, order)
        }

        pub fn set(&self, value: u64, order: Ordering) {
            store_pair(&self.high, &self.low, value, order);
        }
    }

    /// A 64-bit counter any CPU may increment, serialized on a sequence word.
    ///
    /// **A sequence and not a lock**, so a reader never waits on a writer and
    /// never has to release anything: the writer makes `seq` odd, updates both
    /// halves, and makes it even again; a reader that saw an odd `seq`, or a
    /// different one either side of its two loads, retries. The
    /// compare-and-swap that claims the odd value is what excludes a second
    /// *writer*, and it is 32-bit, which every target in
    /// `docs/hardware/01-platform-and-cpu-support.md` has.
    pub struct SharedCounter {
        seq: AtomicU32,
        low: AtomicU32,
        high: AtomicU32,
    }

    impl SharedCounter {
        pub const fn new(value: u64) -> Self {
            Self {
                seq: AtomicU32::new(0),
                low: AtomicU32::new(value as u32),
                high: AtomicU32::new((value >> 32) as u32),
            }
        }

        /// Claims the write side, returning the sequence to publish on release.
        fn begin(&self) -> u32 {
            loop {
                let seen = self.seq.load(Ordering::Acquire);
                if seen & 1 == 0
                    && self
                        .seq
                        .compare_exchange(seen, seen | 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                {
                    return seen.wrapping_add(2);
                }
                core::hint::spin_loop();
            }
        }

        pub fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
            let release = self.begin();
            let previous =
                (u64::from(self.high.load(order)) << 32) | u64::from(self.low.load(order));
            let next = previous.wrapping_add(value);
            self.high.store((next >> 32) as u32, order);
            self.low.store(next as u32, order);
            self.seq.store(release, Ordering::Release);
            previous
        }

        pub fn swap(&self, value: u64, order: Ordering) -> u64 {
            let release = self.begin();
            let previous =
                (u64::from(self.high.load(order)) << 32) | u64::from(self.low.load(order));
            self.high.store((value >> 32) as u32, order);
            self.low.store(value as u32, order);
            self.seq.store(release, Ordering::Release);
            previous
        }

        /// Reads, retrying while a write is in flight. Takes nothing, so it
        /// cannot deadlock against a writer and cannot be nested wrongly.
        pub fn load(&self, order: Ordering) -> u64 {
            loop {
                let before = self.seq.load(Ordering::Acquire);
                if before & 1 != 0 {
                    core::hint::spin_loop();
                    continue;
                }
                let high = self.high.load(order);
                let low = self.low.load(order);
                if self.seq.load(Ordering::Acquire) == before {
                    return (u64::from(high) << 32) | u64::from(low);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/atomic.rs"]
mod tests;
