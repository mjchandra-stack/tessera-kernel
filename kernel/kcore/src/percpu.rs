// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Per-CPU state: one slot per CPU, reached by the index of the CPU asking.
//!
//! `docs/kernel/08-multicore-scalability.md` makes per-CPU the default state
//! model — "kernel state is per-CPU by default; shared state must justify
//! itself in review the way unsafe code justifies itself". A default needs
//! somewhere to live before anything can be written against it, and this is it.
//!
//! # The index is not the hardware's number
//!
//! Every CPU has an identifier its architecture gives it — an affinity
//! register, an interrupt-controller id — and none of them is an index. They
//! are sparse, they are wide, and on a machine with two clusters they are not
//! even ordered the way the CPUs are. Indexing an array with one is a bug that
//! looks like working code on every machine small enough to test on, which is
//! why `1u64 << Cpu::cpu_id()` is in this tree today.
//!
//! So the index here is **assigned**, dense, and `0..MAX_CPUS`. The hardware id
//! is a fact about a CPU that gets recorded next to its slot, never the way the
//! slot is found.
//!
//! # What [`current_index`] is, this milestone
//!
//! Resolving "which CPU am I" without being told is itself per-CPU state, and
//! it needs a register only the port can read — `GS` on x86-64, `TPIDR_EL1` on
//! AArch64. That mechanism is Phase 2 of `docs/roadmap/02-smp-bring-up-plan.md`
//! and does not exist yet. Until it does, [`current_index`] answers
//! [`BOOT_CPU`], which is correct for the reason the boot line prints every
//! time: exactly one CPU is ever brought online (build/README.md, D8/D217).
//!
//! That is a fact this module can state rather than assume, and
//! [`current_index`] is written so the seam is one function body. Its callers
//! do not change when Phase 2 fills it in.
//!
//! # Borrowing discipline
//!
//! [`PerCpu::get`] hands out a shared reference and is safe. The only mutable
//! path is [`PerCpu::with_mut`], which is `unsafe` and carries one obligation:
//! no other reference into the array may be live while it runs. That is
//! stronger than "no other reference to this slot" and deliberately so — the
//! slots share one [`UnsafeCell`], because a per-slot cell cannot be built in a
//! `const` initializer from a runtime value and these live in statics.
//!
//! In practice the obligation costs nothing: a CPU mutates its own slot and
//! nobody else's, and the whole-array readers ([`PerCpu::iter`]) are boot and
//! reporting paths that do not overlap a mutation. It is written down because
//! the type cannot enforce it, which is the same reason `unsafe` is on the
//! function that needs it.
//!
use core::cell::UnsafeCell;

/// CPUs the kernel reserves state for.
///
/// Declared in `config/kernel.config`, with the reasoning for the bound.
pub use crate::config::MAX_CPUS;

/// The index the boot CPU is assigned. Zero by construction: it is the first
/// CPU to be given one, and the assignment is dense from zero.
pub const BOOT_CPU: u32 = 0;

/// The index of the CPU this code is running on.
///
/// See the module header: this is [`BOOT_CPU`] until per-CPU hardware storage
/// lands, and that is a consequence of one CPU being online rather than an
/// assumption made here.
#[inline]
pub fn current_index() -> u32 {
    BOOT_CPU
}

/// One `T` per CPU.
pub struct PerCpu<T> {
    /// One cell over the whole array — see the module header's borrowing
    /// discipline for why it is not one cell per slot.
    slots: UnsafeCell<[T; MAX_CPUS]>,
}

// SAFETY: a slot is reachable only by index, `get` and `iter` yield shared
// references, and the only mutable path (`with_mut`) is unsafe and carries the
// no-other-reference obligation. Sharing the array across CPUs is then sound
// whenever the value itself may move between them.
unsafe impl<T: Send> Sync for PerCpu<T> {}

impl<T: Copy> PerCpu<T> {
    /// An array with every slot set to `init`.
    pub const fn new(init: T) -> Self {
        Self {
            slots: UnsafeCell::new([init; MAX_CPUS]),
        }
    }
}

impl<T> PerCpu<T> {
    /// How many slots there are — the compiled-in CPU ceiling, not how many
    /// CPUs the machine has.
    pub const fn capacity() -> u32 {
        MAX_CPUS as u32
    }

    /// `index`'s slot, or `None` if it is beyond the ceiling.
    ///
    /// Out of range is `None` rather than a panic because the index can come
    /// from a count the firmware reported, and a machine with more CPUs than
    /// this kernel was built for is a configuration to report, not a crash.
    pub fn get(&self, index: u32) -> Option<&T> {
        if index >= Self::capacity() {
            return None;
        }
        // SAFETY: the index is in bounds, and the only mutable access is
        // `with_mut`, whose contract is that no other reference into the array
        // is live for its duration.
        Some(unsafe { &(*self.slots.get())[index as usize] })
    }

    /// Runs `f` on `index`'s slot mutably, returning `None` if it is beyond the
    /// ceiling.
    ///
    /// # Safety
    ///
    /// No other reference into the array may be live for the duration of `f`.
    pub unsafe fn with_mut<R>(&self, index: u32, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        if index >= Self::capacity() {
            return None;
        }
        // SAFETY: the index is in bounds; exclusivity is the caller's
        // obligation, restated.
        Some(f(unsafe { &mut (*self.slots.get())[index as usize] }))
    }

    /// Every slot, in index order. Reads only — see [`get`](Self::get).
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        // SAFETY: as `get` — a shared reference, valid while no `with_mut` is
        // in flight, which is this type's documented obligation.
        unsafe { (*self.slots.get()).iter() }
    }
}

#[cfg(test)]
#[path = "tests/percpu.rs"]
mod tests;
