// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Repairing a user fault: the step between "the hardware trapped" and "the
//! thread runs again", shared by every port.
//!
//! A port's trap handler owns three things this module cannot know — how to
//! read the faulting address, how to tell a write from a read, and which
//! process was running — and nothing else about a fault is port-specific. The
//! classification is [`crate::vm::AddressSpace::resolve_fault`]'s, and what to
//! *do* with each answer is the same everywhere, so it is written once here
//! rather than once per port. x86-64 had the only copy and it was reachable
//! only from that kernel's `main.rs`; the other four ports treated every fault
//! as fatal, which is why a lazily-mapped page could not exist outside x86-64.
//!
//! **Two answers are returned rather than acted on.** [`Repair::NeedsPageIn`]
//! needs a channel and a scheduler to forward a request and block the faulter,
//! and this module has neither — the caller does that (budget B10).
//! [`Repair::Fatal`] is the exception path, which is per-port by construction.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Fault Taxonomy",
//! "Page-In Flow")
//! Budget: B8 (demand fill), B9 (copy-on-write)

use crate::object::ObjectId;
use crate::vm::{AddressSpace, FaultOutcome};
use tessera_karch::{AddressSpaceOps, FrameSource, VirtAddr};

/// What a port's trap handler must do next, having asked this module to repair
/// a fault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Repair {
    /// A lazy anonymous page was demand-filled — resume the faulting
    /// instruction (budget B8).
    Filled,
    /// A copy-on-write page was copied private and remapped writable — resume
    /// (budget B9).
    Copied,
    /// A write to a present, read-only pager-backed page whose mapping grants
    /// write: the page-table half of the software dirty-bit transition is done
    /// and the store may proceed.
    ///
    /// **The dirty accounting is not done here**, and saying so is the point:
    /// [`crate::pager::ObjectCache::mark_dirty`] is what records the page and
    /// throttles a writer past the object's dirty bound, and nothing calls it
    /// on this path yet. Until it does, a write through a mapped pager page is
    /// granted and never written back — which is why a file object must not be
    /// mapped writable before that is wired.
    WriteGranted { object: ObjectId, offset: u64 },
    /// A pager-backed page is not resident. The caller forwards a page request
    /// to the object's pager, blocks the faulting thread, and resumes it once
    /// the page is installed (budget B10).
    NeedsPageIn { object: ObjectId, offset: u64 },
    /// Not repairable — a genuine protection violation, an unmapped address, or
    /// a repair that failed. The caller escalates to its exception path.
    Fatal,
}

impl Repair {
    /// Whether the faulting instruction can be resumed immediately.
    ///
    /// The three repaired outcomes answer `true` and the two that need
    /// somebody else answer `false`, so a port that has no pager yet — every
    /// port but x86-64 — can treat this as the whole decision.
    pub fn resumes(&self) -> bool {
        matches!(
            self,
            Repair::Filled | Repair::Copied | Repair::WriteGranted { .. }
        )
    }
}

/// Repairs the fault at `va` in `space`, if it is one of the repairable kinds.
///
/// `write` is whether the access that faulted was a store; a port reads it out
/// of its own syndrome register (x86-64 `#PF` error-code bit 1, AArch64 `ESR`
/// `WnR`). `alloc` supplies the frame a demand fill or a copy-on-write copy
/// needs, and is the only thing here that can fail for want of memory — a
/// failed repair is [`Repair::Fatal`], never a silently skipped page.
pub fn repair<A: AddressSpaceOps>(
    space: &mut AddressSpace<A>,
    va: VirtAddr,
    write: bool,
    alloc: &mut dyn FrameSource,
) -> Repair {
    match space.resolve_fault(va, write, alloc) {
        FaultOutcome::Filled => Repair::Filled,
        FaultOutcome::Copied => Repair::Copied,
        FaultOutcome::NeedsPageIn { object, offset } => Repair::NeedsPageIn { object, offset },
        FaultOutcome::WriteToClean { object, offset } => {
            // The mapping grants write and the page is present read-only, so
            // this cannot fail for want of memory — but a failure is still
            // reported rather than resumed, because resuming a store the page
            // tables still refuse would fault again at the same address for
            // ever.
            match space.grant_write(va) {
                Ok(()) => Repair::WriteGranted { object, offset },
                Err(_) => Repair::Fatal,
            }
        }
        FaultOutcome::Unresolvable => Repair::Fatal,
    }
}

#[cfg(test)]
#[path = "tests/fault.rs"]
mod tests;
