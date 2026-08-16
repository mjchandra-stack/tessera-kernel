// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Kernel objects and their lifetime. Every object a handle can reference is a
//! typed, reference-counted entry in the object table; the object is destroyed
//! when its last reference drops (docs/kernel/06-capability-revocation.md:
//! objects are freed when their references drop). Handles hold references, so
//! closing the last handle to an object destroys it.
//!
//! `ObjectId` packs a table index and a generation, so a stale id — one whose
//! slot has since been reused — is detected rather than silently aliased. The
//! table is a fixed-capacity pool (no general kernel allocator yet, deviation
//! D15) and is accessed through `&mut` on one core, so refcounts are plain
//! integers; per-CPU sharding lands with SMP.
//!
//! Normative: docs/architecture/01-system-architecture.md ("Core Object
//! Model"), docs/kernel/01-kernel-model.md ("Handle And Rights System")
//! Budget: none (creation/lifetime paths)

use tessera_karch::KError;

/// Maximum live kernel objects this milestone.
pub const MAX_OBJECTS: usize = 256;

/// The class of a kernel object. The v0 subset of the full object model
/// (docs/architecture/01); the remaining classes join as their subsystems land.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    Process,
    Thread,
    AddressSpace,
    Job,
    Channel,
    Port,
    /// A memory object: a range of backable pages. A service-backed memory
    /// object names a pager that supplies its pages on demand
    /// (docs/kernel/03-paging-faults-and-exceptions.md, "External Pager
    /// Protocol").
    Memory,
    /// A device-I/O capability: possession authorizes a driver host to access a
    /// device's registers through the `DeviceIo` syscalls. The device's I/O range
    /// `(base, len)` is the object's resource-graph payload, held in the
    /// `Executive`'s `DeviceTable` (the Process/Channel/Port side-table pattern —
    /// this `Entry` stays a pure typed-refcount token) and enforced per access
    /// (build/README.md, D47).
    Device,
    /// A generic object used to exercise the handle machinery in tests and the
    /// boot self-check before the richer object classes exist.
    Test,
}

/// A reference to a kernel object: table index in the low 16 bits, generation
/// in the high 16 bits. The generation makes a reused slot's old id stale.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ObjectId(u32);

impl ObjectId {
    fn new(index: usize, generation: u16) -> Self {
        ObjectId(((generation as u32) << 16) | (index as u32 & 0xffff))
    }

    fn index(self) -> usize {
        (self.0 & 0xffff) as usize
    }

    fn generation(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// The raw packed value (for accounting/tracing).
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Reconstructs an id from its raw packed value — used by the IPC transport
    /// to carry a conserved object reference through a message.
    pub const fn from_raw(raw: u32) -> Self {
        ObjectId(raw)
    }
}

struct Entry {
    object_type: ObjectType,
    refcount: usize,
}

/// A fixed-capacity pool of live kernel objects.
pub struct ObjectTable {
    slots: [Option<Entry>; MAX_OBJECTS],
    /// Per-slot generation, bumped each time a slot is freed, so ids into a
    /// reused slot are distinguishable from the previous occupant's.
    generations: [u16; MAX_OBJECTS],
}

impl ObjectTable {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_OBJECTS],
            generations: [0; MAX_OBJECTS],
        }
    }

    /// Creates an object of `object_type` with one reference, returning its id,
    /// or [`KError::OutOfMemory`] if the pool is full.
    pub fn create(&mut self, object_type: ObjectType) -> Result<ObjectId, KError> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.slots[index] = Some(Entry {
            object_type,
            refcount: 1,
        });
        Ok(ObjectId::new(index, self.generations[index]))
    }

    /// Adds a reference. `BadHandle` if the id is stale or absent.
    pub fn retain(&mut self, id: ObjectId) -> Result<(), KError> {
        let entry = self.entry_mut(id)?;
        entry.refcount += 1;
        Ok(())
    }

    /// Drops a reference, destroying the object (and freeing its slot) when the
    /// count reaches zero. Returns whether the object was destroyed. `BadHandle`
    /// if the id is stale or absent.
    pub fn release(&mut self, id: ObjectId) -> Result<bool, KError> {
        let entry = self.entry_mut(id)?;
        entry.refcount -= 1;
        if entry.refcount == 0 {
            let index = id.index();
            self.slots[index] = None;
            self.generations[index] = self.generations[index].wrapping_add(1);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// The object's type, or `None` if the id is stale or absent.
    pub fn object_type(&self, id: ObjectId) -> Option<ObjectType> {
        self.entry(id).map(|e| e.object_type)
    }

    /// The object's current reference count, or `None` if stale or absent.
    pub fn refcount(&self, id: ObjectId) -> Option<usize> {
        self.entry(id).map(|e| e.refcount)
    }

    /// Whether the id currently refers to a live object.
    pub fn is_live(&self, id: ObjectId) -> bool {
        self.entry(id).is_some()
    }

    /// Number of live objects.
    pub fn live_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    fn entry(&self, id: ObjectId) -> Option<&Entry> {
        let index = id.index();
        if self.generations.get(index) == Some(&id.generation()) {
            self.slots[index].as_ref()
        } else {
            None
        }
    }

    fn entry_mut(&mut self, id: ObjectId) -> Result<&mut Entry, KError> {
        let index = id.index();
        if self.generations.get(index) == Some(&id.generation()) {
            self.slots[index].as_mut().ok_or(KError::BadHandle)
        } else {
            Err(KError::BadHandle)
        }
    }
}

impl Default for ObjectTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/object.rs"]
mod tests;
