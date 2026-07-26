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
use tessera_karch::{AddressSpaceOps, KError};

/// Threads a single process may hold this milestone.
pub const MAX_THREADS_PER_PROCESS: usize = 8;
/// Processes the table holds.
pub const MAX_PROCESSES: usize = 16;

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
        }
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
mod tests {
    use super::*;
    use crate::object::{ObjectTable, ObjectType};
    use crate::rights::Rights;
    use crate::vm::{AddressSpace, Asid};
    use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

    fn space() -> AddressSpace<MockAddressSpace> {
        let mut frames = MockFrameSource::new(0x40_0000, 64);
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
            .expect("space")
    }

    #[test]
    fn process_lifecycle_and_thread_membership() {
        let mut process = Process::new(ObjectId::from_raw(1), space());
        assert_eq!(process.state(), ProcessState::Created);
        assert!(!process.is_exited());
        process.add_thread(4).expect("add thread");
        assert!(process.owns_thread(4));
        assert!(!process.owns_thread(5));
        process.set_running();
        assert_eq!(process.state(), ProcessState::Running);
        process.exit(7);
        assert_eq!(process.state(), ProcessState::Exited(7));
        assert!(process.is_exited());
    }

    #[test]
    fn table_resolves_process_by_thread() {
        let mut table = ProcessTable::<MockAddressSpace>::new();
        let mut a = Process::new(ObjectId::from_raw(1), space());
        a.add_thread(2).expect("add");
        let mut b = Process::new(ObjectId::from_raw(2), space());
        b.add_thread(9).expect("add");
        let ia = table.insert(a).expect("insert a");
        let _ib = table.insert(b).expect("insert b");
        assert_eq!(
            table.process_of_thread(2).map(|p| p.id()),
            table.get(ia).map(|p| p.id())
        );
        assert!(table.process_of_thread(9).is_some());
        assert!(table.process_of_thread(100).is_none());
    }

    #[test]
    fn table_resolves_process_by_id() {
        let mut table = ProcessTable::<MockAddressSpace>::new();
        table
            .insert(Process::new(ObjectId::from_raw(11), space()))
            .expect("insert a");
        table
            .insert(Process::new(ObjectId::from_raw(22), space()))
            .expect("insert b");
        assert_eq!(
            table.process_of_id(ObjectId::from_raw(22)).map(|p| p.id()),
            Some(ObjectId::from_raw(22))
        );
        assert!(table.process_of_id(ObjectId::from_raw(11)).is_some());
        assert!(table.process_of_id(ObjectId::from_raw(99)).is_none());
    }

    #[test]
    fn thread_set_is_bounded() {
        let mut process = Process::new(ObjectId::from_raw(1), space());
        for i in 0..MAX_THREADS_PER_PROCESS {
            process.add_thread(i).expect("add");
        }
        assert_eq!(process.add_thread(99), Err(KError::OutOfMemory));
    }

    #[test]
    fn remove_returns_process_and_frees_slot() {
        let mut table = ProcessTable::<MockAddressSpace>::new();
        let i0 = table
            .insert(Process::new(ObjectId::from_raw(1), space()))
            .expect("insert 0");
        let _i1 = table
            .insert(Process::new(ObjectId::from_raw(2), space()))
            .expect("insert 1");

        let removed = table.remove(i0).expect("remove returns the process");
        assert_eq!(removed.id(), ObjectId::from_raw(1));
        assert!(table.get(i0).is_none(), "slot cleared");
        // Removing an empty or stale index is a harmless None.
        assert!(table.remove(i0).is_none());
        assert!(table.remove(999).is_none());
        // The freed slot is reused by the next insert (dense, first-free).
        let reused = table
            .insert(Process::new(ObjectId::from_raw(3), space()))
            .expect("insert reuses freed slot");
        assert_eq!(reused, i0, "first-free slot is the one just removed");
    }

    #[test]
    fn index_of_id_locates_the_removable_slot() {
        let mut table = ProcessTable::<MockAddressSpace>::new();
        table
            .insert(Process::new(ObjectId::from_raw(11), space()))
            .expect("insert a");
        let ib = table
            .insert(Process::new(ObjectId::from_raw(22), space()))
            .expect("insert b");
        assert_eq!(table.index_of_id(ObjectId::from_raw(22)), Some(ib));
        assert_eq!(table.index_of_id(ObjectId::from_raw(99)), None);
        // index_of_id then remove is the exit-site pattern.
        let idx = table.index_of_id(ObjectId::from_raw(22)).expect("found");
        assert_eq!(
            table.remove(idx).map(|p| p.id()),
            Some(ObjectId::from_raw(22))
        );
        assert_eq!(table.index_of_id(ObjectId::from_raw(22)), None);
    }

    /// Guards the M21/D51 device-capability conservation invariant: a dropped
    /// `Process` must not release the object references its handle table holds.
    /// `install`/`insert` are refcount-neutral and there is no `Drop for Process`
    /// / `HandleTable`, so a device object installed into a driver host stays live
    /// at refcount 1 across install → reclaim (drop) → re-install. A `Drop` that
    /// released handles, or an `insert` that started retaining, would break restart
    /// conservation — this test catches either.
    #[test]
    fn dropping_a_process_does_not_release_its_handles_objects() {
        let mut objects = ObjectTable::new();
        let dev = objects.create(ObjectType::Device).expect("device object");
        assert_eq!(objects.refcount(dev), Some(1));

        // Model the driver-host restart loop: build a host, install the shared
        // device capability, reclaim the host's own process object, drop the host.
        for _ in 0..3 {
            let proc_obj = objects.create(ObjectType::Process).expect("process object");
            let mut host = Process::new(proc_obj, space());
            host.handles_mut()
                .insert(dev, Rights::READ)
                .expect("install device handle");
            // `install` adopts an existing reference — refcount-neutral.
            assert_eq!(
                objects.refcount(dev),
                Some(1),
                "install must not retain the device"
            );
            // Reclaim releases the host's *own* process object (rc 1 → destroyed)
            // and drops the host; the host's handle table — which still holds the
            // device handle — is forgotten, not released.
            assert_eq!(
                objects.release(proc_obj),
                Ok(true),
                "the host's process object is destroyed"
            );
            drop(host);
            assert!(objects.is_live(dev), "the device survives the host drop");
            assert_eq!(
                objects.refcount(dev),
                Some(1),
                "dropping the host must not release the device"
            );
        }
    }
}
