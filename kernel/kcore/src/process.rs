// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The process object: an isolation container that owns a virtual address
//! space, a per-process handle table, and a set of threads
//! (docs/architecture/01-system-architecture.md, "Core Object Model": a
//! process is "an execution container with address spaces and handles"). A
//! process runs in ring 3; its threads reach the kernel only through the
//! validated syscall boundary (`syscall.rs`).
//!
//! v0 is single-address-space and built in-kernel from an embedded ring-3
//! image; the three-phase create/populate/start *syscalls*, multiple address
//! spaces, jobs, and an ELF loader are deferred (build/README.md, D25). Fixed
//! pools throughout — no general allocator (cf. D15).
//!
//! Normative: docs/kernel/01-kernel-model.md ("Handle And Rights System"),
//! docs/architecture/01-system-architecture.md ("Core Object Model"),
//! docs/kernel/05-jobs-containment-and-resource-control.md (deterministic
//! reclaim — `remove` frees an exited process's slot),
//! docs/kernel/06-capability-revocation.md ("killing the process or job
//! reclaims" its handles)
//! Budget: none (creation path)

use crate::handle::HandleTable;
use crate::object::ObjectId;
use crate::vm::AddressSpace;
use tessera_karch::{AddressSpaceOps, FRAME_SIZE, KError, VirtAddr};

/// Threads a single process may hold this milestone.
pub const MAX_THREADS_PER_PROCESS: usize = 8;
/// Processes the table holds.
pub const MAX_PROCESSES: usize = 16;

/// Device register windows one process may hold open at once. A driver maps
/// its own device and little else; a device *manager* maps every device it
/// enumerates, which is what sizes this.
pub const MAX_DEVICE_WINDOWS: usize = 8;

/// One register window a process holds: which device it belongs to, where it
/// was mapped, and how far it reaches.
///
/// The extent is part of the record because a window is not a page — see
/// [`Process::record_device_window`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceWindow {
    pub object: ObjectId,
    pub va: u64,
    pub pages: u64,
}

/// How a device capability left the process that held its register window —
/// the two routes `revoke_device_windows_unless_held` documents, reported in a
/// `DEVICE_WINDOW_REVOKED` event so a revocation can be told apart from a
/// close after the fact. The values are ABI (`kernel_event.isl`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum WindowRevokeReason {
    /// The capability was transferred to another process.
    Transferred = 1,
    /// The last handle naming the device was closed.
    HandleClosed = 2,
    /// The holder is gone — it died, or was torn down.
    ///
    /// Unreachable for a device window, which dies with the address space and
    /// therefore needs no revocation on this route. A **memory** grant does:
    /// its frames are refcounted and outlive the space, so the reference the
    /// mapping holds has to be dropped by somebody.
    HolderGone = 3,
    /// The **device** is gone, and the holder had no say in it.
    ///
    /// The only reason on this list that is not a consequence of something the
    /// holder did. The other three describe a capability leaving a process;
    /// this describes the thing the capability named ceasing to exist, which
    /// is why it is the one that can arrive while the holder is running and
    /// using it.
    Removed = 4,
}

/// Memory grants one process may hold mapped at once.
///
/// Larger than the device-window bound, because a driver maps one device and
/// may hold a buffer per outstanding request.
pub const MAX_MEMORY_MAPPINGS: usize = 8;

/// One memory object's pages, mapped into a process.
///
/// The extent is recorded rather than recomputed for the same reason
/// [`DeviceWindow`]'s is, and one more: revocation goes through
/// `AddressSpace::reclaim_range`, which requires an **exact** base and length.
/// A length derived later from the object could disagree with what was mapped,
/// and the reclaim would simply not find it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryMapping {
    pub object: ObjectId,
    pub va: u64,
    pub pages: u64,
}

/// A process's lifecycle state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessState {
    /// Created and being populated; not yet started.
    Created,
    /// Started; at least one thread has run.
    Running,
    /// Terminated with an exit code (clean exit, or contained fault → the
    /// default-policy terminate, D23).
    Exited(i32),
}

/// A process: its address space, handle table, threads (by scheduler index),
/// and lifecycle state. The `ObjectId` is its entry in the global object table
/// (`ObjectType::Process`).
///
/// **Invariant — a dropped `Process` must not release its handles' object
/// references.** `Process` holds no reference to the `ObjectTable`, `HandleTable`
/// entries are plain data, and neither type has a `Drop` impl, so dropping a
/// process *forgets* its handles without calling [`ObjectTable::release`]. Only an
/// explicit [`HandleTable::close`] releases. Driver-host restart conservation
/// (M21/D51) depends on this: a device capability installed into a host stays live
/// at refcount 1 across install → reclaim (drop) → re-install, forever. Adding a
/// `Drop for Process`/`HandleTable` that releases handles — or making
/// `insert`/`install` retain — would silently break restart conservation; the
/// `dropping_a_process_does_not_release_its_handles_objects` test guards it.
pub struct Process<A: AddressSpaceOps> {
    id: ObjectId,
    space: AddressSpace<A>,
    handles: HandleTable,
    threads: [Option<usize>; MAX_THREADS_PER_PROCESS],
    state: ProcessState,
    /// The job this process belongs to (docs/kernel/05: every process belongs
    /// to exactly one job). `None` until placed in a job.
    job: Option<ObjectId>,
    /// Device register windows this process has mapped, as
    /// `(device object, page-aligned VA)`.
    ///
    /// This exists so a device capability can take its mapping with it when it
    /// leaves. `MapDevice` grants access to registers *because* the caller
    /// holds the capability; if the capability moves to another process and the
    /// window stays behind, the grant has been copied rather than transferred —
    /// the old holder keeps everything that mattered while the new one believes
    /// it has exclusive use. Recording the window is what makes revocation
    /// possible at all, and nothing else in the kernel needs this list.
    device_windows: [Option<DeviceWindow>; MAX_DEVICE_WINDOWS],
    /// Memory grants this process has mapped, as `(object, VA, pages)`.
    ///
    /// The memory twin of [`Self::device_windows`], and it exists for the same
    /// reason: the authority behind a mapping is the capability, so the
    /// mapping must go when the capability does. What differs is what
    /// revocation has to *do* — a device window is untracked and its frames
    /// belong to hardware, while these frames are refcounted RAM and the
    /// mapping holds one reference to each.
    memory_mappings: [Option<MemoryMapping>; MAX_MEMORY_MAPPINGS],
}

impl<A: AddressSpaceOps> Process<A> {
    /// Creates a `Created` process owning `space` and a fresh (empty) handle
    /// table. Threads are added with [`add_thread`](Self::add_thread) as they
    /// are spawned into it.
    pub fn new(id: ObjectId, space: AddressSpace<A>) -> Self {
        Self {
            id,
            space,
            handles: HandleTable::new(),
            threads: [None; MAX_THREADS_PER_PROCESS],
            state: ProcessState::Created,
            job: None,
            device_windows: [None; MAX_DEVICE_WINDOWS],
            memory_mappings: [None; MAX_MEMORY_MAPPINGS],
        }
    }

    /// Records that this process mapped `object`'s registers at `va`, spanning
    /// `pages`.
    ///
    /// The extent is recorded, not recomputed at revocation time: the graph's
    /// window may have been re-registered since, and revoking a different
    /// number of pages than were mapped would either leave some reachable or
    /// unmap something else. One record per *window* rather than per page,
    /// which is also what keeps one `DEVICE_WINDOW_MAPPED` record per grant —
    /// the event summary reads a device granted twice as a rebind, and a
    /// four-page window counted four times would make one mapping look like
    /// four.
    ///
    /// A full table returns [`KError::LimitExceeded`] and the caller must fail
    /// the mapping: silently forgetting a window would leave one that
    /// revocation could never find, which is precisely the hole this table
    /// closes (docs/lifecycle/04, "No Silent Fallback").
    pub fn record_device_window(
        &mut self,
        object: ObjectId,
        va: u64,
        pages: u64,
    ) -> Result<(), KError> {
        let slot = self
            .device_windows
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(KError::LimitExceeded)?;
        *slot = Some(DeviceWindow { object, va, pages });
        Ok(())
    }

    /// Forgets one window this process recorded at `va` on `object`, without
    /// unmapping anything.
    ///
    /// The undo half of [`Self::record_device_window`], for a mapping that was
    /// recorded and then failed to install. Deliberately **one** window and not
    /// every window on the object: a process may hold several, and a failed
    /// mapping must not make the kernel forget the ones that are live — those
    /// would stay mapped with nothing left to revoke them.
    pub fn forget_device_window(&mut self, object: ObjectId, va: u64) {
        for slot in self.device_windows.iter_mut() {
            if let Some(window) = *slot
                && window.object == object
                && window.va == va
            {
                *slot = None;
                return;
            }
        }
    }

    /// Removes and returns every window this process holds on `object` — what
    /// a capability's departure has to undo. A device may legitimately be
    /// mapped more than once, so this drains all of them rather than the first.
    pub fn take_device_windows(
        &mut self,
        object: ObjectId,
    ) -> [Option<DeviceWindow>; MAX_DEVICE_WINDOWS] {
        let mut out = [None; MAX_DEVICE_WINDOWS];
        let mut found = 0;
        for slot in self.device_windows.iter_mut() {
            if let Some(window) = *slot
                && window.object == object
            {
                out[found] = Some(window);
                found += 1;
                *slot = None;
            }
        }
        out
    }

    /// Revokes this process's register windows on `object` — **unless it still
    /// holds a capability naming it**.
    ///
    /// The authority behind a device window is "I hold this capability", so the
    /// window must go when the capability does, by whatever route: transferred
    /// to another process, or simply closed. What it must *not* do is go when
    /// only one of two handles to the same device left; a process that
    /// duplicated its capability and gave one copy away still has the
    /// authority, and unmapping under it would break a driver that did nothing
    /// wrong.
    ///
    /// Process teardown deliberately needs no call here: the address space is
    /// destroyed with the process, and a device window is untracked, so
    /// `AddressSpace::teardown` cannot return its MMIO frame to the allocator
    /// (it walks only tracked mappings). The window dies with the space.
    /// Returns whether the capability actually **departed** — `false` when the
    /// process still holds another handle naming the device and nothing was
    /// revoked. The caller needs this because a register window is not the only
    /// thing that follows a capability out: a DMA lease does too, and it lives
    /// where this method cannot reach it (in the IOMMU, via the executive).
    /// Deciding "did it leave?" twice, in two places, is how the two halves
    /// would come to disagree.
    pub fn revoke_device_windows_unless_held(
        &mut self,
        object: ObjectId,
        reason: WindowRevokeReason,
    ) -> bool {
        if self.handles.holds(object) {
            return false;
        }
        for window in self.take_device_windows(object).into_iter().flatten() {
            let va = window.va;
            // A recorded-but-unmapped window cannot happen (they are installed
            // together), so a failure here would mean the two had drifted;
            // there is nothing to unwind and the departure is still correct.
            // The result is *reported* rather than swallowed, so that
            // impossible case is observable if it ever stops being impossible.
            // Every page of it, not just the first: a window that came down
            // partly would leave a driver reaching registers it no longer holds
            // the capability for.
            let outcome = self.space.unmap_device_page(VirtAddr::new(va));
            self.space
                .unmap_device_pages(VirtAddr::new(va + FRAME_SIZE), window.pages - 1);
            crate::event::emit(
                crate::event::EventKind::DeviceWindowRevoked,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [
                    object.raw() as u64,
                    va,
                    reason as u64,
                    outcome.err().map_or(0, |e| e as u64),
                ],
            );
        }
        true
    }

    /// Records that this process mapped memory object `object` at `va`,
    /// spanning `pages`.
    ///
    /// A full table returns [`KError::LimitExceeded`] and the caller must fail
    /// the mapping — and, unlike the device-window path, must **undo** it
    /// rather than merely forget it: the mapping has already taken one
    /// reference per page, and forgetting the record strands every one of
    /// them. [`Self::forget_memory_mapping`] exists for the case where nothing
    /// was mapped yet.
    pub fn record_memory_mapping(
        &mut self,
        object: ObjectId,
        va: u64,
        pages: u64,
    ) -> Result<(), KError> {
        let slot = self
            .memory_mappings
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(KError::LimitExceeded)?;
        *slot = Some(MemoryMapping { object, va, pages });
        Ok(())
    }

    /// Forgets one recorded mapping without unmapping anything — the undo for
    /// a record made before a mapping that then failed.
    pub fn forget_memory_mapping(&mut self, object: ObjectId, va: u64) {
        for slot in self.memory_mappings.iter_mut() {
            if let Some(mapping) = *slot
                && mapping.object == object
                && mapping.va == va
            {
                *slot = None;
                return;
            }
        }
    }

    /// Revokes this process's mappings of memory object `object` — **unless it
    /// still holds a capability naming it**.
    ///
    /// The memory twin of [`Self::revoke_device_windows_unless_held`], and it
    /// differs in the two places that matter:
    ///
    /// **It reclaims rather than unmaps.** A device window is untracked and
    /// its frames belong to hardware, so taking one down is a page-table edit
    /// and nothing else. These frames are refcounted RAM and the mapping holds
    /// one reference to each, so revocation must go through
    /// [`crate::vm::AddressSpace::reclaim_range`], which unmaps, drops the
    /// reference, and clears the space's own record together.
    ///
    /// **It keeps the record when the reclaim fails.** The device version
    /// drains its records first and merely reports a failed unmap, which is
    /// safe for something the address space never knew about. Doing that here
    /// would leave the space's tracked mapping in place with nothing left to
    /// revoke it — and `teardown` would then free the same frames a second
    /// time. So a failed reclaim keeps the record, reports the error, and
    /// leaves the frames owned by exactly one thing.
    ///
    /// Returns whether the capability actually **departed** — `false` when the
    /// process still holds another handle naming the object, in which case
    /// nothing is revoked. That is the same guard the device path uses, and it
    /// is why "the sender's handle and mappings are gone on send"
    /// (`docs/kernel/04`) is true of the *last* handle rather than of any.
    pub fn revoke_memory_mappings_unless_held(
        &mut self,
        object: ObjectId,
        reason: WindowRevokeReason,
        alloc: &mut dyn tessera_karch::FrameSource,
    ) -> bool {
        if self.handles.holds(object) {
            return false;
        }
        // Snapshotted first so the space and the record array are not borrowed
        // at once; the records are cleared below, individually, and only where
        // the reclaim succeeded.
        let mut found = [None; MAX_MEMORY_MAPPINGS];
        for (slot, mapping) in self.memory_mappings.iter().enumerate() {
            if matches!(mapping, Some(m) if m.object == object) {
                found[slot] = *mapping;
            }
        }
        for (slot, mapping) in found.iter().enumerate() {
            let Some(mapping) = mapping else {
                continue;
            };
            let outcome = self.space.reclaim_range(
                VirtAddr::new(mapping.va),
                mapping.pages * FRAME_SIZE,
                alloc,
            );
            if outcome.is_ok() {
                self.memory_mappings[slot] = None;
            }
            crate::event::emit(
                crate::event::EventKind::MemoryGrantRevoked,
                crate::event::Severity::Notice,
                crate::event::Component::Memory,
                [
                    object.raw() as u64,
                    mapping.va,
                    reason as u64,
                    outcome.err().map_or(0, |e| e as u64),
                ],
            );
        }
        true
    }

    /// Every memory object this process has mapped, in `out`; returns how
    /// many. The sweep a departing process's teardown walks.
    pub fn mapped_memory_objects(&self, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for mapping in self.memory_mappings.iter().flatten() {
            if n == out.len() {
                break;
            }
            if out[..n].contains(&mapping.object) {
                continue;
            }
            out[n] = mapping.object;
            n += 1;
        }
        n
    }

    /// Memory mappings currently recorded — for tests and for the boot checks
    /// that assert a revocation actually happened.
    pub fn memory_mapping_count(&self) -> usize {
        self.memory_mappings.iter().flatten().count()
    }

    /// Windows currently recorded — for tests and for the boot checks that
    /// assert a revocation actually happened.
    pub fn device_window_count(&self) -> usize {
        self.device_windows.iter().flatten().count()
    }

    pub fn id(&self) -> ObjectId {
        self.id
    }

    /// The job this process belongs to, if placed in one.
    pub fn job(&self) -> Option<ObjectId> {
        self.job
    }

    /// Records the owning job (docs/kernel/05: every process belongs to exactly
    /// one job).
    pub fn set_job(&mut self, job: ObjectId) {
        self.job = Some(job);
    }

    pub fn space(&self) -> &AddressSpace<A> {
        &self.space
    }

    pub fn space_mut(&mut self) -> &mut AddressSpace<A> {
        &mut self.space
    }

    pub fn handles(&self) -> &HandleTable {
        &self.handles
    }

    pub fn handles_mut(&mut self) -> &mut HandleTable {
        &mut self.handles
    }

    /// Records a thread (by its scheduler table index) as belonging to this
    /// process. `OutOfMemory` if the per-process thread set is full.
    pub fn add_thread(&mut self, thread_index: usize) -> Result<(), KError> {
        let slot = self
            .threads
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.threads[slot] = Some(thread_index);
        Ok(())
    }

    /// Whether `thread_index` is one of this process's threads.
    /// Drops `thread_index` from this process's thread list.
    ///
    /// A reaped thread frees its **scheduler slot**, which the next spawn will
    /// reuse — but the process that owned it still claims the index, and
    /// [`ProcessTable::process_of_thread`](crate::process::ProcessTable::process_of_thread)
    /// answers with the *first* process that claims one. So a supervisor that
    /// reaps a dead service's thread and then starts a replacement hands the
    /// replacement a recycled index, and its syscalls are attributed to the
    /// corpse: they run against the dead process's handle table and address
    /// space. The failure is silent and misleading — the replacement's own
    /// stack pointer is not mapped there, so it surfaces as `AccessDenied` on
    /// a pointer the caller can see is perfectly valid.
    ///
    /// Reaping a thread and forgetting it are therefore two halves of one
    /// operation, split only because the scheduler and the process table are
    /// separate structures with no reference to each other.
    pub fn forget_thread(&mut self, thread_index: usize) {
        for slot in self.threads.iter_mut() {
            if *slot == Some(thread_index) {
                *slot = None;
            }
        }
    }

    pub fn owns_thread(&self, thread_index: usize) -> bool {
        self.threads.iter().flatten().any(|&t| t == thread_index)
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }

    /// Marks the process started.
    pub fn set_running(&mut self) {
        self.state = ProcessState::Running;
    }

    /// Terminates the process with `code`. Idempotent-safe; the scheduler stops
    /// resuming its threads.
    pub fn exit(&mut self, code: i32) {
        self.state = ProcessState::Exited(code);
    }

    /// Whether the process has terminated.
    pub fn is_exited(&self) -> bool {
        matches!(self.state, ProcessState::Exited(_))
    }
}

/// A fixed pool of processes (parallels `ObjectTable`). Dense indices; no
/// generations (a process index is kernel-internal, never handed to user code).
pub struct ProcessTable<A: AddressSpaceOps> {
    slots: [Option<Process<A>>; MAX_PROCESSES],
}

impl<A: AddressSpaceOps> ProcessTable<A> {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_PROCESSES],
        }
    }

    /// Inserts `process`, returning its dense table index, or `OutOfMemory`.
    pub fn insert(&mut self, process: Process<A>) -> Result<usize, KError> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.slots[index] = Some(process);
        Ok(index)
    }

    /// Removes and returns the process at dense `index`, freeing the slot for
    /// reuse (docs/kernel/05, deterministic reclaim); `None` if the slot is
    /// empty. The index is kernel-internal with no generations, so a stale
    /// index simply finds an empty (or unrelated) slot — never a use-after-free
    /// handed to user code. The returned `Process` owns its `AddressSpace`; the
    /// caller tears it down (`space_mut().teardown`) before dropping it.
    pub fn remove(&mut self, index: usize) -> Option<Process<A>> {
        self.slots.get_mut(index).and_then(Option::take)
    }

    /// Dense index of the live process whose object id is `id` — the companion
    /// to [`process_of_id`](Self::process_of_id) that lets an exit site
    /// [`remove`](Self::remove) the child by id.
    pub fn index_of_id(&self, id: ObjectId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| matches!(slot, Some(p) if p.id() == id))
    }

    pub fn get(&self, index: usize) -> Option<&Process<A>> {
        self.slots.get(index).and_then(Option::as_ref)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Process<A>> {
        self.slots.get_mut(index).and_then(Option::as_mut)
    }

    /// The process that owns scheduler thread `thread_index`, if any — how a
    /// syscall resolves the caller's process from the running thread.
    pub fn process_of_thread(&mut self, thread_index: usize) -> Option<&mut Process<A>> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|p| p.owns_thread(thread_index))
    }

    /// Drops `thread_index` from whichever process claims it — the companion a
    /// supervisor calls immediately after `Scheduler::reap`, so the freed
    /// scheduler slot cannot be recycled into a live thread that the dead
    /// process still claims. See [`Process::forget_thread`] for what goes
    /// wrong without it.
    pub fn forget_thread(&mut self, thread_index: usize) {
        for process in self.slots.iter_mut().flatten() {
            process.forget_thread(thread_index);
        }
    }

    /// The process whose object id is `id`, if live — how a syscall resolves a
    /// *process handle* to its target process (the caller looks the handle up in
    /// its handle table to get the `ObjectId`, then finds the process here). A
    /// linear scan over the fixed pool; the id is the process's `ObjectType::Process`
    /// entry, so this is the handle→process bridge for the loader syscalls.
    pub fn process_of_id(&mut self, id: ObjectId) -> Option<&mut Process<A>> {
        self.slots.iter_mut().flatten().find(|p| p.id() == id)
    }
}

impl<A: AddressSpaceOps> Default for ProcessTable<A> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/process.rs"]
mod tests;
