// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The per-process handle table: the capability surface. A handle is a dense
//! id into this table; each entry binds an object reference to a rights mask.
//! Every operation enforces the one invariant — rights only narrow — so a
//! duplicate or replace may drop rights but never add them
//! (docs/security/01-security-model.md, "Rights Catalog").
//!
//! Lookup and the rights query are reads that write no shared state, matching
//! the syscall-path property required of handle tables
//! (docs/kernel/08-multicore-scalability.md: per-process, lock-free lookup, no
//! shared writes on the check path). The table is single-core this milestone
//! (deviation D14); its access pattern is kept shared-write-free so a
//! multi-core, epoch-reclaimed table drops in without an API change. Handles
//! are dense — index in the low 16 bits, generation in the high 16 — so a
//! stale handle is caught, not aliased. Each entry reserves a `scope` field for
//! revocation, which stays `None` (unscoped, O(1)) until scopes land.
//!
//! Lock discipline: mutation synchronizes only within the owning process; a
//! `HandleTable` is owned by exactly one process and never shared across cores.
//!
//! Normative: docs/kernel/01-kernel-model.md ("Handle And Rights System"),
//! docs/kernel/08-multicore-scalability.md ("Read-Mostly Concurrency")
//! Budget: B2 (handle op: query rights) — `rights`/`lookup`; unmeasured until
//! the perf rig lands (build/README.md, deviation D9)

use crate::object::{ObjectId, ObjectTable};
use crate::rights::Rights;
use tessera_karch::KError;

/// Maximum handles per process this milestone.
pub const MAX_HANDLES: usize = 1024;

/// A handle: a reference to a rights-bearing object reference. Index in the low
/// 16 bits, generation in the high 16.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Handle(u32);

impl Handle {
    fn new(index: usize, generation: u16) -> Self {
        Handle(((generation as u32) << 16) | (index as u32 & 0xffff))
    }

    fn index(self) -> usize {
        (self.0 & 0xffff) as usize
    }

    fn generation(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// The raw packed value (for tracing/accounting).
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Rebuilds a handle from its raw packed value — the form a user program
    /// passes across the syscall boundary. A stale or out-of-range value fails
    /// the generation/bounds check in [`lookup`](HandleTable::lookup), so this
    /// never bypasses validation.
    pub const fn from_raw(raw: u32) -> Self {
        Handle(raw)
    }
}

/// A reference to a revocation scope. Reserved for the revocation milestone;
/// unscoped handles carry `None` and cost nothing extra (docs/kernel/06).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ScopeRef(pub u32);

struct Entry {
    object: ObjectId,
    rights: Rights,
    /// Reserved: the revocation scope this handle belongs to, if any.
    scope: Option<ScopeRef>,
}

/// A process's handle table.
pub struct HandleTable {
    slots: [Option<Entry>; MAX_HANDLES],
    generations: [u16; MAX_HANDLES],
}

impl HandleTable {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_HANDLES],
            generations: [0; MAX_HANDLES],
        }
    }

    /// Installs a handle that *adopts* one reference to `object` (the caller
    /// transfers a reference it already holds — e.g. the creation reference
    /// from [`ObjectTable::create`], or one produced by
    /// [`retain`](ObjectTable::retain)). On failure the caller still owns the
    /// reference.
    pub fn insert(&mut self, object: ObjectId, rights: Rights) -> Result<Handle, KError> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.slots[index] = Some(Entry {
            object,
            rights,
            scope: None,
        });
        Ok(Handle::new(index, self.generations[index]))
    }

    /// The object and rights a handle names. A read with no shared writes.
    pub fn lookup(&self, handle: Handle) -> Result<(ObjectId, Rights), KError> {
        let entry = self.entry(handle)?;
        Ok((entry.object, entry.rights))
    }

    /// The object a handle names.
    pub fn object(&self, handle: Handle) -> Result<ObjectId, KError> {
        Ok(self.entry(handle)?.object)
    }

    /// The rights a handle carries (the B2 query path).
    pub fn rights(&self, handle: Handle) -> Result<Rights, KError> {
        Ok(self.entry(handle)?.rights)
    }

    /// The revocation scope this handle belongs to, if any. Always `None` until
    /// revocation scopes land (the reserved seam the liveness check will read).
    pub fn scope(&self, handle: Handle) -> Result<Option<ScopeRef>, KError> {
        Ok(self.entry(handle)?.scope)
    }

    /// Duplicates a handle with a reduced rights set. `new_rights` must be a
    /// subset of the handle's current rights, else [`KError::AccessDenied`] —
    /// duplication can only narrow authority, never expand it. The new handle
    /// references the same object (one additional reference).
    pub fn duplicate(
        &mut self,
        objects: &mut ObjectTable,
        handle: Handle,
        new_rights: Rights,
    ) -> Result<Handle, KError> {
        let (object, current) = self.lookup(handle)?;
        if !new_rights.is_subset_of(current) {
            return Err(KError::AccessDenied);
        }
        objects.retain(object)?;
        match self.insert(object, new_rights) {
            Ok(new_handle) => Ok(new_handle),
            Err(err) => {
                // Table full: undo the reference we just took.
                let _ = objects.release(object);
                Err(err)
            }
        }
    }

    /// Replaces a handle's rights in place with a reduced set. `new_rights`
    /// must be a subset of the current rights, else [`KError::AccessDenied`].
    pub fn replace_rights(&mut self, handle: Handle, new_rights: Rights) -> Result<(), KError> {
        let entry = self.entry_mut(handle)?;
        if !new_rights.is_subset_of(entry.rights) {
            return Err(KError::AccessDenied);
        }
        entry.rights = new_rights;
        Ok(())
    }

    /// Removes a handle for transfer, returning its object reference and rights
    /// **without releasing the reference** — the reference is *conserved* and
    /// handed to the caller (an in-flight message), keeping the object alive
    /// between send and receive. Requires the [`Rights::TRANSFER`] right.
    ///
    /// The object refcount is unchanged: the reference moves from this table to
    /// the message, and later to the receiver's table via [`install`](Self::install).
    pub fn take(&mut self, handle: Handle) -> Result<(ObjectId, Rights), KError> {
        let rights = self.lookup(handle)?.1;
        self.take_narrowed(handle, rights)
    }

    /// Removes a handle for transfer, reducing the rights it travels with to
    /// `to` — the transferred half of "rights can be reduced when handles are
    /// duplicated or transferred" (docs/kernel/01, "Handle And Rights System").
    ///
    /// `to` must be a subset of what this table holds on `handle`, else
    /// [`KError::AccessDenied`] — the same rule and the same error as
    /// [`duplicate`](Self::duplicate) and [`replace_rights`](Self::replace_rights),
    /// so narrowing means one thing everywhere. The source handle still needs
    /// [`Rights::TRANSFER`]: reducing what a capability arrives with is not a
    /// way to acquire the authority to send it.
    ///
    /// **Dropping `TRANSFER` here is the point.** Moving a handle requires that
    /// right, so before narrowing existed every capability that could be
    /// transferred at all necessarily arrived able to be transferred onward —
    /// there was no way to grant a device a driver could not pass to a third
    /// party, and duplicating first could not help, because the duplicate had
    /// to keep `TRANSFER` to be sendable.
    ///
    /// A refusal leaves the handle **in place**: the slot is vacated only after
    /// both checks pass, so a rejected transfer costs the sender nothing.
    pub fn take_narrowed(
        &mut self,
        handle: Handle,
        to: Rights,
    ) -> Result<(ObjectId, Rights), KError> {
        let (object, rights) = self.lookup(handle)?;
        if !rights.contains(Rights::TRANSFER) || !to.is_subset_of(rights) {
            return Err(KError::AccessDenied);
        }
        let index = handle.index();
        self.slots[index] = None;
        self.generations[index] = self.generations[index].wrapping_add(1);
        Ok((object, to))
    }

    /// Installs a conserved object reference (from [`take`](Self::take) on
    /// another table) as a new handle, adopting the reference. Rights follow the
    /// transferred handle. The refcount is unchanged — the reference moves from
    /// the message into this table.
    pub fn install(&mut self, object: ObjectId, rights: Rights) -> Result<Handle, KError> {
        self.insert(object, rights)
    }

    /// Removes a handle and returns the object it named, **touching no object
    /// table**.
    ///
    /// The same shape as [`reclaim`](Self::reclaim), for the same reason: the
    /// object table counts *references*, and three of the five ports have none
    /// because they fabricate object ids rather than allocate them. A close
    /// path that needed one would work on one port.
    ///
    /// What a caller actually has to know after a close is whether *this
    /// process* still holds the object — [`holds`](Self::holds) answers that,
    /// per-process and without a table. What is genuinely lost is "was that the
    /// last reference anywhere", which for a memory object is a question
    /// ownership already answers.
    ///
    /// The slot's generation is bumped as usual, so the handle value the caller
    /// just closed is stale rather than dangling if it is presented again.
    pub fn drop_handle(&mut self, handle: Handle) -> Result<ObjectId, KError> {
        let object = self.entry(handle)?.object;
        let index = handle.index();
        self.slots[index] = None;
        self.generations[index] = self.generations[index].wrapping_add(1);
        Ok(object)
    }

    /// Closes a handle, dropping its reference to the object. Returns whether
    /// the object was destroyed (its last reference dropped).
    ///
    /// The **object-table** form, for the one port that has one. Everything
    /// else closes through [`drop_handle`](Self::drop_handle).
    pub fn close(&mut self, objects: &mut ObjectTable, handle: Handle) -> Result<bool, KError> {
        let object = self.entry(handle)?.object;
        let index = handle.index();
        self.slots[index] = None;
        self.generations[index] = self.generations[index].wrapping_add(1);
        objects.release(object)
    }

    /// Removes every handle naming one of `wanted`, reporting each with the
    /// rights it carried, and returns how many were taken.
    ///
    /// Unlike [`take`](Self::take) this does **not** require
    /// `Rights::TRANSFER`. That right governs a *process* handing a capability
    /// on; this is the kernel taking one back from a process that is being
    /// destroyed, which no right of the dead process can permit or forbid. The
    /// distinction matters: a driver granted a device without TRANSFER must
    /// still not strand it by dying.
    ///
    /// Slot generations are bumped as usual, so any handle value the dead
    /// process's peers still hold is stale rather than dangling.
    pub fn reclaim(&mut self, wanted: &[ObjectId], out: &mut [(ObjectId, Rights)]) -> usize {
        let mut n = 0;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if n == out.len() {
                break;
            }
            let Some(entry) = slot else { continue };
            if !wanted.contains(&entry.object) {
                continue;
            }
            out[n] = (entry.object, entry.rights);
            n += 1;
            *slot = None;
            self.generations[index] = self.generations[index].wrapping_add(1);
        }
        n
    }

    /// Whether any live handle in this table names `object`.
    ///
    /// A process may legitimately hold two handles to one object — `duplicate`
    /// exists — so "did this capability leave?" is a question about the table,
    /// not about one slot. Revocation asks it before taking anything away.
    pub fn holds(&self, object: ObjectId) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|entry| entry.object == object)
    }

    /// Number of live handles.
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    fn entry(&self, handle: Handle) -> Result<&Entry, KError> {
        let index = handle.index();
        if self.generations.get(index) == Some(&handle.generation()) {
            self.slots[index].as_ref().ok_or(KError::BadHandle)
        } else {
            Err(KError::BadHandle)
        }
    }

    fn entry_mut(&mut self, handle: Handle) -> Result<&mut Entry, KError> {
        let index = handle.index();
        if self.generations.get(index) == Some(&handle.generation()) {
            self.slots[index].as_mut().ok_or(KError::BadHandle)
        } else {
            Err(KError::BadHandle)
        }
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectTable, ObjectType};

    /// Creates an object and a first handle adopting its creation reference.
    fn new_object_handle(
        objects: &mut ObjectTable,
        handles: &mut HandleTable,
        rights: Rights,
    ) -> (ObjectId, Handle) {
        let id = objects.create(ObjectType::Test).unwrap();
        let handle = handles.insert(id, rights).unwrap();
        (id, handle)
    }

    #[test]
    fn insert_lookup_and_query_rights() {
        let mut objects = ObjectTable::new();
        let mut handles = HandleTable::new();
        let rights = Rights::READ | Rights::WRITE | Rights::DUPLICATE;
        let (id, handle) = new_object_handle(&mut objects, &mut handles, rights);
        assert_eq!(handles.object(handle), Ok(id));
        assert_eq!(handles.rights(handle), Ok(rights));
        assert_eq!(handles.scope(handle), Ok(None)); // unscoped by default
        assert_eq!(objects.refcount(id), Some(1)); // the handle holds the one reference
    }

    #[test]
    fn duplicate_narrows_and_rejects_expansion() {
        let mut objects = ObjectTable::new();
        let mut handles = HandleTable::new();
        let full = Rights::READ | Rights::WRITE | Rights::DUPLICATE;
        let (id, handle) = new_object_handle(&mut objects, &mut handles, full);

        // Narrowing to a subset is allowed and adds a reference.
        let ro = handles
            .duplicate(&mut objects, handle, Rights::READ)
            .unwrap();
        assert_eq!(handles.rights(ro), Ok(Rights::READ));
        assert_eq!(objects.refcount(id), Some(2));

        // Asking for a right the source lacks is an expansion — rejected, with
        // no new reference taken.
        let expand = Rights::READ | Rights::EXECUTE;
        assert_eq!(
            handles.duplicate(&mut objects, ro, expand),
            Err(KError::AccessDenied)
        );
        assert_eq!(objects.refcount(id), Some(2));
    }

    #[test]
    fn replace_rights_only_narrows() {
        let mut objects = ObjectTable::new();
        let mut handles = HandleTable::new();
        let (_, handle) =
            new_object_handle(&mut objects, &mut handles, Rights::READ | Rights::WRITE);
        handles.replace_rights(handle, Rights::READ).unwrap();
        assert_eq!(handles.rights(handle), Ok(Rights::READ));
        // Cannot re-add WRITE.
        assert_eq!(
            handles.replace_rights(handle, Rights::READ | Rights::WRITE),
            Err(KError::AccessDenied)
        );
    }

    #[test]
    fn object_lives_until_last_handle_closes() {
        let mut objects = ObjectTable::new();
        let mut handles = HandleTable::new();
        let (id, h1) = new_object_handle(&mut objects, &mut handles, Rights::all_core());
        let h2 = handles.duplicate(&mut objects, h1, Rights::READ).unwrap();
        assert_eq!(objects.refcount(id), Some(2));

        assert_eq!(handles.close(&mut objects, h1), Ok(false)); // one reference left
        assert!(objects.is_live(id));
        assert_eq!(handles.close(&mut objects, h2), Ok(true)); // destroyed at last close
        assert!(!objects.is_live(id));
        assert_eq!(handles.count(), 0);
    }

    #[test]
    fn transfer_moves_a_handle_and_conserves_the_reference() {
        let mut objects = ObjectTable::new();
        // A source table (sender) and a destination table (receiver).
        let mut sender = HandleTable::new();
        let mut receiver = HandleTable::new();

        let id = objects.create(ObjectType::Test).unwrap();
        let handle = sender.insert(id, Rights::READ | Rights::TRANSFER).unwrap();
        assert_eq!(objects.refcount(id), Some(1));

        // Take from the sender (reference conserved — refcount unchanged).
        let (object, rights) = sender.take(handle).unwrap();
        assert_eq!(object, id);
        assert_eq!(objects.refcount(id), Some(1));
        assert_eq!(sender.rights(handle), Err(KError::BadHandle)); // gone from sender

        // Install into the receiver (reference adopted — still one reference).
        let installed = receiver.install(object, rights).unwrap();
        assert_eq!(objects.refcount(id), Some(1));
        assert_eq!(receiver.rights(installed), Ok(rights));
        assert!(objects.is_live(id));
    }

    #[test]
    fn transfer_requires_the_transfer_right() {
        let mut objects = ObjectTable::new();
        let mut sender = HandleTable::new();
        let id = objects.create(ObjectType::Test).unwrap();
        // No TRANSFER right.
        let handle = sender.insert(id, Rights::READ | Rights::WRITE).unwrap();
        assert_eq!(sender.take(handle), Err(KError::AccessDenied));
        // The handle is untouched by the failed take.
        assert!(sender.rights(handle).is_ok());
    }

    /// The transferred half of "rights can be reduced when handles are
    /// duplicated or transferred" (docs/kernel/01).
    #[test]
    fn transfer_narrows_and_rejects_expansion() {
        let mut objects = ObjectTable::new();
        let mut sender = HandleTable::new();
        let mut receiver = HandleTable::new();
        let id = objects.create(ObjectType::Test).unwrap();
        let handle = sender
            .insert(id, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .unwrap();

        // Asking for more than the sender holds is refused, and costs the
        // sender nothing — the handle is still there afterwards.
        assert_eq!(
            sender.take_narrowed(handle, Rights::READ | Rights::WRITE),
            Err(KError::AccessDenied)
        );
        assert!(sender.rights(handle).is_ok());

        // Narrowing succeeds and the receiver gets exactly what was asked for.
        let (object, rights) = sender
            .take_narrowed(handle, Rights::READ | Rights::MAP)
            .unwrap();
        assert_eq!(rights, Rights::READ | Rights::MAP);
        assert_eq!(sender.rights(handle), Err(KError::BadHandle));
        let installed = receiver.install(object, rights).unwrap();
        assert_eq!(
            receiver.rights(installed).unwrap(),
            Rights::READ | Rights::MAP
        );
    }

    /// The point of narrowing on transfer, and the thing that was impossible
    /// before it: a capability the receiver cannot hand on. `TRANSFER` is
    /// required to *send*, and rights used to pass through unchanged, so every
    /// capability that could be given away necessarily arrived able to be
    /// given away again.
    #[test]
    fn a_grant_can_be_made_non_delegable() {
        let mut objects = ObjectTable::new();
        let mut sender = HandleTable::new();
        let mut receiver = HandleTable::new();
        let id = objects.create(ObjectType::Test).unwrap();
        let handle = sender
            .insert(id, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .unwrap();

        let (object, rights) = sender
            .take_narrowed(handle, Rights::READ | Rights::MAP)
            .unwrap();
        let installed = receiver.install(object, rights).unwrap();

        // The receiver holds a working capability...
        assert!(receiver.rights(installed).unwrap().contains(Rights::MAP));
        // ...and cannot pass it to anyone.
        assert_eq!(receiver.take(installed), Err(KError::AccessDenied));
        // Nor can it launder one through a duplicate: rights only narrow, so
        // the duplicate cannot acquire the TRANSFER the original lacks.
        assert_eq!(
            receiver.duplicate(&mut objects, installed, Rights::READ | Rights::TRANSFER),
            Err(KError::AccessDenied)
        );
    }

    /// Narrowing does not substitute for the authority to send. A handle
    /// without `TRANSFER` cannot be moved however modest the request.
    #[test]
    fn narrowing_does_not_grant_the_right_to_send() {
        let mut objects = ObjectTable::new();
        let mut sender = HandleTable::new();
        let id = objects.create(ObjectType::Test).unwrap();
        let handle = sender.insert(id, Rights::READ | Rights::MAP).unwrap();
        assert_eq!(
            sender.take_narrowed(handle, Rights::READ),
            Err(KError::AccessDenied)
        );
        assert_eq!(
            sender.take_narrowed(handle, Rights::none()),
            Err(KError::AccessDenied)
        );
        assert!(sender.rights(handle).is_ok());
    }

    /// An empty rights set is a legal narrowing: useless, but not dangerous,
    /// and refusing it would be a special case with nothing behind it.
    #[test]
    fn narrowing_to_no_rights_is_allowed() {
        let mut objects = ObjectTable::new();
        let mut sender = HandleTable::new();
        let id = objects.create(ObjectType::Test).unwrap();
        let handle = sender.insert(id, Rights::READ | Rights::TRANSFER).unwrap();
        let (_, rights) = sender.take_narrowed(handle, Rights::none()).unwrap();
        assert!(rights.is_empty());
    }

    #[test]
    fn stale_and_absent_handles_are_rejected() {
        let mut objects = ObjectTable::new();
        let mut handles = HandleTable::new();
        let (_, handle) = new_object_handle(&mut objects, &mut handles, Rights::READ);
        handles.close(&mut objects, handle).unwrap();
        // The closed handle is stale.
        assert_eq!(handles.rights(handle), Err(KError::BadHandle));
        assert_eq!(
            handles.duplicate(&mut objects, handle, Rights::READ),
            Err(KError::BadHandle)
        );
    }
}
