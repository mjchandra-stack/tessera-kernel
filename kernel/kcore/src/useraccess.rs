// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Whether this CPU may dereference a user page, as a **per-thread** property.
//!
//! # The hardware says "this CPU", and the truth is "this thread"
//!
//! Every architecture here spells the same control differently and puts it in
//! the same kind of place: x86-64's `EFLAGS.AC` against `CR4.SMAP`, AArch64's
//! `PSTATE.PAN`, RISC-V's `sstatus.SUM`. All three are per-CPU registers, and
//! what wants the permission is one thread inside one validated copy. A bit
//! set for a copy and left set is a bit that is set while some *other* thread
//! runs — which is the D81 class of defect, and is why RISC-V set `SUM` once at
//! boot and left it rather than trying to scope it (build/README.md, D247).
//!
//! # Why scoping it to the copy is not enough
//!
//! The obvious answer — enable, copy, disable, with interrupts masked so
//! nothing preempts — does not survive the fault. `validate_user_range` checks
//! the caller's *tracked* mappings, not residency, so a copy into a
//! pager-backed page that is not resident faults part-way through; the fault is
//! forwarded to the pager over IPC and **the faulting thread blocks**. Another
//! thread then runs, with the window still open, and the copy resumes minutes
//! of machine time later. Masking interrupts does not help: the fault is an
//! exception, not an interrupt.
//!
//! So the permission is carried. [`Window`] sets it for the running thread;
//! `Scheduler::switch_to` saves it into the outgoing thread and restores the
//! incoming thread's, which is the one place a thread stops being the one on
//! the CPU. Nothing else needs to know it exists.
//!
//! # Installed rather than generic
//!
//! `kcore::syscall::read_user` is generic over the address space and not over
//! the context, and giving it a second type parameter would put one on every
//! dispatch arm that calls it. The port installs the pair once at boot instead,
//! exactly as it installs interrupt control (`crate::sync`) and the event clock
//! (`crate::event::set_clock`).
//!
//! A port that installs nothing keeps whatever its hardware does by default,
//! and the copies it makes meanwhile are **counted**: a kernel with no
//! protection and a kernel whose protection stopped being installed are
//! otherwise the same kernel (docs/lifecycle/04, "No Silent Fallback").
//!
//! Normative: docs/security/01-security-model.md ("Memory Safety"),
//! docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (the pair is two instructions inside an already-bounded copy)

use core::sync::atomic::{AtomicPtr, Ordering};

/// Sets whether this CPU may reach user pages.
type SetAccess = fn(bool);
/// Reads what [`SetAccess`] last established on this CPU.
type GetAccess = fn() -> bool;

/// The installed pair, as raw function addresses. Null means "not installed".
///
/// Published in the order `crate::sync` publishes its own: `GET` first and
/// `SET` last, so a reader that sees a non-null `SET` is guaranteed to see the
/// `GET` installed with it.
static SET: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static GET: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Copies made across the user boundary with no hardware protection installed.
static UNPROTECTED: crate::counter::Sharded = crate::counter::Sharded::new();

/// Installs the port's user-access control, returning how many user copies
/// were made before it.
///
/// `#[must_use]` for the reason [`crate::sync::install_interrupt_control`] is:
/// a port that installs this and discards the answer cannot notice it
/// installed it too late.
#[must_use]
pub fn install(set: SetAccess, get: GetAccess) -> u64 {
    GET.store(get as *mut (), Ordering::Release);
    SET.store(set as *mut (), Ordering::Release);
    UNPROTECTED.take()
}

/// Whether a port has installed the control at all.
pub fn is_installed() -> bool {
    !SET.load(Ordering::Acquire).is_null()
}

/// User copies made with no protection installed — see [`install`].
pub fn unprotected_copies() -> u64 {
    UNPROTECTED.total()
}

/// Sets this CPU's permission, if a port installed a way to.
pub(crate) fn set(allowed: bool) {
    let raw = SET.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: non-null only because `install` stored a `SetAccess` there, and
    // the release/acquire pair above publishes it.
    let set: SetAccess = unsafe { core::mem::transmute::<*mut (), SetAccess>(raw) };
    set(allowed);
}

/// This CPU's permission, or `false` where no port installed a way to ask.
///
/// `false` is the right answer for a port with no control: it permits
/// everything, so there is no state for a switch to carry and nothing is lost
/// by saying the bit is clear.
pub(crate) fn get() -> bool {
    let raw = GET.load(Ordering::Acquire);
    if raw.is_null() {
        return false;
    }
    // SAFETY: as `set` — non-null only because `install` stored a `GetAccess`.
    let get: GetAccess = unsafe { core::mem::transmute::<*mut (), GetAccess>(raw) };
    get()
}

/// Permits the running thread to reach user pages, until dropped.
///
/// Nests: the guard restores what it found rather than clearing, so a copy
/// inside a copy leaves the outer one's permission alone. The restore happens
/// on the thread that opened it, whenever that thread next runs — which is the
/// whole point of the scheduler carrying the bit.
pub struct Window {
    previous: bool,
}

impl Window {
    /// Opens the window.
    ///
    /// # Safety
    ///
    /// The caller must have validated the range it is about to touch against
    /// the mappings of the process whose pages it will reach
    /// (`crate::syscall::validate_user_range`). This lifts a hardware check
    /// against dereferencing a stray user pointer; it does not lift the
    /// obligation the check was standing in for.
    pub unsafe fn open() -> Self {
        if !is_installed() {
            UNPROTECTED.bump();
        }
        let previous = get();
        set(true);
        Self { previous }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        set(self.previous);
    }
}

#[cfg(test)]
#[path = "tests/useraccess.rs"]
mod tests;
