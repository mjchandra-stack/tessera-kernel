// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The lock over the executive's machine-wide tables, and the one rule it
//! cannot enforce for itself.
//!
//! # Why it is re-entrant
//!
//! `kcore::exec` reaches its machine half from 173 places, most of them one
//! expression inside a method that is doing several. A lock taken per access
//! would release between the statements of a single update — enqueue a request,
//! set the pending caller, signal an arrival — and another CPU could see the
//! half of it. So the section that matters is the *method*, and each of those
//! 173 accesses then finds the lock already held by itself.
//!
//! Re-entrancy is the cheap way to make both true at once: the method takes a
//! [`Hold`] at the top, the accesses take nested ones, and only the outermost
//! actually touches the lock. It costs a depth counter and a per-CPU owner
//! word, and it saves auditing 173 call sites for which ones may release.
//!
//! # The rule the type cannot express
//!
//! **A thread must not park while its CPU holds this.** Nine executive methods
//! suspend the calling thread inside their own borrow — a server parked in
//! `receive` stays there for the rest of the boot — so a hold that survived the
//! park would be a hold nobody ever releases. `build/README.md` D230 measured
//! that: thirteen threads are inside those methods when a boot ends. The first
//! server to park would stop the machine.
//!
//! [`park`] is the way to park: it puts the hold down, runs the parking
//! operation, and picks the hold back up when the thread runs again. What it
//! does *not* do is guarantee that every park went through it — a
//! `block_current` called directly still compiles. So [`assert_released`] is
//! called from the scheduler at the moment it parks a thread, and a hold found
//! there is counted and reported rather than assumed absent. That check needs
//! no second CPU to be useful: it fails today, on one CPU, for a method whose
//! park was not converted.
//!
//! Normative: docs/roadmap/02-smp-bring-up-plan.md ("Phase 3"), build/README.md
//! D230, D231
//! Budget: none (nothing but the boot CPU takes it yet — a secondary reaches
//! the executive since build/README.md D236 but only its own per-CPU half,
//! which this does not cover)

use crate::atomic::AtomicU64;
use crate::percpu::{MAX_CPUS, PerCpu, current_index};
use core::sync::atomic::{AtomicU32, Ordering};

/// No CPU. `MAX_CPUS` is out of range for a real index, so it cannot collide
/// with one, and zero cannot be used because zero is the boot CPU.
const NOBODY: u32 = MAX_CPUS as u32;

/// The CPU holding the lock, or [`NOBODY`].
///
/// **`core::sync::atomic::AtomicU32` and not `kcore::atomic::AtomicU64`.**
/// That type exists because two of the five targets have no 64-bit atomic
/// instruction, and what it cannot offer as a result is a compare-and-swap —
/// which is the one operation a lock is. Thirty-two bits is not a compromise
/// here: every target in `docs/hardware/01` has a 32-bit atomic, a CPU index
/// fits in a byte, and the reason `kcore::atomic` exists at all is 64-bit
/// *values* whose width is part of an ABI. An owner word is neither.
static OWNER: AtomicU32 = AtomicU32::new(NOBODY);

/// How deep the owning CPU is. Written only by that CPU, so relaxed load/store
/// is enough — the same argument [`crate::epoch`]'s per-CPU depth makes, and
/// `kcore::atomic::AtomicU64` has no read-modify-write to offer besides.
static DEPTH: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Parks that happened with the lock still held — the discipline check.
static PARKED_HOLDING: AtomicU64 = AtomicU64::new(0);

/// Times the outermost hold had to wait for another CPU.
static CONTENDED: AtomicU64 = AtomicU64::new(0);

fn depth_of(index: u32) -> u64 {
    if index >= PerCpu::<u8>::capacity() {
        return 0;
    }
    DEPTH[index as usize].load(Ordering::Relaxed)
}

fn set_depth(index: u32, value: u64) {
    if index < PerCpu::<u8>::capacity() {
        DEPTH[index as usize].store(value, Ordering::Relaxed);
    }
}

/// A live hold on the machine tables. Dropping it releases one level.
pub struct Hold {
    cpu: u32,
}

/// Takes a hold, waiting for another CPU only if one has it.
pub fn hold() -> Hold {
    let cpu = current_index();
    let depth = depth_of(cpu);
    if depth == 0 {
        acquire(cpu);
    }
    set_depth(cpu, depth + 1);
    Hold { cpu }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let depth = depth_of(self.cpu).saturating_sub(1);
        set_depth(self.cpu, depth);
        if depth == 0 {
            release();
        }
    }
}

fn acquire(cpu: u32) {
    if try_take(cpu) {
        return;
    }
    // Contended: counted once per wait rather than once per spin, so the
    // number means "how often did a CPU have to wait" and not "how fast is
    // this loop".
    CONTENDED.fetch_add(1, Ordering::Relaxed);
    while !try_take(cpu) {
        // Read-only until the word looks free, so the waiters are not fighting
        // each other's exclusive accesses for the cache line the holder is
        // trying to release.
        while OWNER.load(Ordering::Relaxed) != NOBODY {
            core::hint::spin_loop();
        }
    }
}

/// One attempt at the owner word.
///
/// Split out so a host test can exercise the exclusion without threads: a
/// thread-based test cannot, because the lock is re-entrant *per CPU* and
/// every host thread answers `current_index()` with the boot CPU — two of them
/// would both be let in, correctly, and the test would be measuring the
/// re-entrancy rather than the exclusion.
fn try_take(cpu: u32) -> bool {
    OWNER
        .compare_exchange(NOBODY, cpu, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

fn release() {
    OWNER.store(NOBODY, Ordering::Release);
}

/// The CPU holding the lock, or `None`. Tests and reporting.
pub fn owner() -> Option<u32> {
    match OWNER.load(Ordering::Acquire) {
        NOBODY => None,
        cpu => Some(cpu),
    }
}

/// Takes a hold for one expression.
///
/// For the few places that reach the machine tables outside a method that
/// holds them for its whole body — `Executive::run` above all, which never
/// returns and so can never be one of them.
pub fn hold_for<R>(f: impl FnOnce() -> R) -> R {
    let _held = hold();
    f()
}

/// Whether this CPU holds the lock.
pub fn held_here() -> bool {
    depth_of(current_index()) > 0
}

/// Puts this CPU's hold down for the duration of `f`, and picks it back up.
///
/// The whole depth, not one level: the point is that nothing is held while the
/// thread is off the CPU, and a method three levels deep still has to let go of
/// all three. The depth is restored rather than re-derived, so the [`Hold`]s
/// still on the stack — belonging to frames that will resume later — remain
/// accurate.
pub fn park<R>(f: impl FnOnce() -> R) -> R {
    let cpu = current_index();
    let depth = depth_of(cpu);
    if depth > 0 {
        set_depth(cpu, 0);
        release();
    }
    let result = f();
    // Back on this CPU, which may be a different CPU from the one that let go
    // if the thread was migrated — so the depth is restored where the thread
    // is *now*, not where it was.
    let cpu = current_index();
    if depth > 0 {
        acquire(cpu);
        set_depth(cpu, depth);
    }
    result
}

/// Records a park that happened while this CPU held the lock.
///
/// Called by the scheduler at the moment it takes a thread off the CPU. This
/// is the check that a park was routed through [`park`]; one that was not
/// leaves a hold nobody will release, which is a deadlock waiting for a second
/// CPU to exist. Counted rather than fatal — `kcore` has no business ending a
/// boot — and reported by [`report`].
pub fn assert_released() {
    if held_here() {
        PARKED_HOLDING.fetch_add(1, Ordering::Relaxed);
    }
}

/// Parks that happened with the lock held. Zero, or there is a bug.
pub fn parked_holding() -> u64 {
    PARKED_HOLDING.load(Ordering::Acquire)
}

/// Times an outermost hold found another CPU already holding.
pub fn contended() -> u64 {
    CONTENDED.load(Ordering::Acquire)
}

/// Emits the boot line, returning the claim keys a boot check should assert.
pub fn report() -> &'static [&'static str] {
    let parked = parked_holding();
    crate::event::emit(
        crate::event::EventKind::ExecOccupancy,
        if parked == 0 {
            crate::event::Severity::Info
        } else {
            crate::event::Severity::Error
        },
        crate::event::Component::Scheduler,
        [parked, contended(), 0, 0],
    );
    crate::kprintln!(
        "exec: {} park(s) with the machine lock held, {} contended hold(s)",
        parked,
        contended()
    );
    if parked == 0 {
        &["exec.lock-released-at-park"]
    } else {
        &[]
    }
}

/// Forgets everything recorded. Tests only — these are process-wide.
#[cfg(test)]
pub fn forget() {
    for slot in &DEPTH {
        slot.store(0, Ordering::Release);
    }
    OWNER.store(NOBODY, Ordering::Release);
    PARKED_HOLDING.store(0, Ordering::Release);
    CONTENDED.store(0, Ordering::Release);
}

#[cfg(test)]
#[path = "tests/machine_lock.rs"]
mod tests;
