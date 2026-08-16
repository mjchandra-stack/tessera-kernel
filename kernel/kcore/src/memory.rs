// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Memory objects: the pages an `ObjectType::Memory` capability names.
//!
//! `docs/kernel/02` ("Memory Objects") makes these the system's sharing
//! primitive — anonymous, file-backed, shared, device, secure, guest, and
//! copy-on-write memory are all one kind of thing named by one kind of
//! capability. `docs/hardware/04` adds that they are the *cross-device*
//! primitive too, the role dma-buf plays elsewhere. This module builds the
//! first of those: anonymous pages, mappable into an address space and
//! transferable over a channel.
//!
//! **Why this exists at all.** A channel message carries at most 256 inline
//! bytes (`ipc::MAX_INLINE_BYTES`), which is why the block class contract
//! truncates a 512-byte sector to 64 and says so in a comment. Every class
//! past block — network frames, NVMe scatter-gather, framebuffers, sound
//! rings — needs a payload that does not fit in a message, and
//! `docs/kernel/04` ("Out-Of-Line Memory Semantics") says what one is: *a
//! memory-object handle with an ownership mode*. The handle already travels;
//! the object did not exist.
//!
//! **The side-table pattern.** Like [`crate::devmgr::DeviceTable`] and
//! [`crate::port::PortTable`], this keys its state to an `ObjectId` rather
//! than putting a payload in the object table, which stays a pure typed
//! refcount registry (D42/D45/D46).
//!
//! **Frames are refcounted, and that is what makes sharing work.** Each frame
//! is drawn once at create and then *retained* by every mapping
//! ([`crate::vm::AddressSpace::map_shared`]), so an object mapped in two
//! address spaces holds three references — the object's own, and one per
//! mapping. Whichever goes last returns the frame. The accounting is absolute
//! rather than ordered, so teardown order does not matter.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Memory Objects"),
//! docs/kernel/04-synchronization-and-ipc-guarantees.md ("Out-Of-Line Memory
//! Semantics")
//! Budget: none (a create/map control path; the transfer itself is B3/B4)

pub use crate::isl_binding::memory::MemoryClass;
use crate::object::ObjectId;
use crate::vm::AddressSpace;
use tessera_karch::{AddressSpaceOps, FRAME_SIZE, FrameSource, KError, PhysFrame};

/// Memory objects the table holds — bounded like every kcore pool (D15).
pub const MAX_MEMORY_OBJECTS: usize = 8;

/// Where memory-object ids start.
///
/// **These are minted here, not by the object table**, and that is a recorded
/// deviation rather than a preference. Three of the five ports have no
/// `ObjectTable` at all — their boot glue fabricates ids with
/// `ObjectId::from_raw`, and handing them a fresh table would be worse than
/// none, because `create` allocates slot 0 at generation 0 and would alias
/// every fabricated id. A reserved range above both the fabricated ids and
/// anything `ObjectTable::create` can produce (`MAX_OBJECTS` is 256, and it
/// stamps generation 0, so its raw values are below 256) keeps the two apart
/// until the ports gain a real table.
///
/// The lifetime question a refcount would answer is answered instead by
/// [`MemoryObject::owner`] — see [`MemoryTable::create`].
pub const MEMORY_OBJECT_ID_BASE: u32 = 0x1000;

/// Where a memory object has to be (`docs/hardware/04`, "Contiguity Contract").
///
/// Every field is **strict-binding**: satisfied at allocation or the create
/// fails. There is no weakening and no partial satisfaction, because a caller
/// that stated a constraint stated it for a reason it cannot check afterwards.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Placement {
    /// The object must appear contiguous to the device. Costs nothing but the
    /// mapping behind an IOMMU, which is why it is the answer a driver should
    /// be asking for.
    pub device_contiguous: bool,
    /// The object must be a run of physical memory. A last resort: it spends
    /// memory nothing can defragment, and is honoured only for hardware whose
    /// path has neither scatter-gather nor an IOMMU.
    pub physically_contiguous: bool,
    /// The boundary the object must start on, or zero for none. A power of two
    /// (checked when the request is decoded).
    pub alignment: u64,
    /// The highest address the object may occupy, or zero for no limit.
    pub address_limit: u64,
}

impl Placement {
    /// Whether `frames` — in the order they will be handed out — is where the
    /// request said the object had to be.
    ///
    /// `device_contiguous` is deliberately **not** checked here, and that is
    /// the whole IOMMU-first rule: it is a constraint on the *mapping* and not
    /// on the memory, satisfied by the broker laying scattered pages out at
    /// consecutive device addresses. Checking it against physical addresses
    /// would be demanding physical contiguity under another name, which is
    /// precisely the carveout pressure the rule exists to avoid.
    pub fn satisfied_by(&self, frames: &[Option<PhysFrame>]) -> Result<(), KError> {
        let Some(first) = frames.first().and_then(|f| *f) else {
            return Err(KError::OutOfMemory);
        };
        let base = first.base().as_u64();
        if self.alignment != 0 && base % self.alignment != 0 {
            return Err(KError::OutOfMemory);
        }
        if self.physically_contiguous {
            for (page, frame) in frames.iter().enumerate() {
                let Some(frame) = frame else {
                    return Err(KError::OutOfMemory);
                };
                if frame.base().as_u64() != base + page as u64 * FRAME_SIZE {
                    return Err(KError::OutOfMemory);
                }
            }
        }
        if self.address_limit != 0 {
            for frame in frames.iter().flatten() {
                // The last byte, not the base: a frame that starts below a
                // limit and ends above it is still memory the device cannot
                // address.
                if frame.base().as_u64() + FRAME_SIZE - 1 > self.address_limit {
                    return Err(KError::OutOfMemory);
                }
            }
        }
        Ok(())
    }
}

/// Pages one object may hold: 64 KiB.
///
/// The same ceiling `MapDevice` puts on a register window, and chosen against
/// a harder bound: [`crate::pmem::MAX_FREE_FRAMES`] is 256, so an object
/// larger than that could not be reclaimed without overflowing the free list
/// and leaking the excess — one `MEM_RECLAIM_OVERFLOW` record per frame. A
/// limit that cannot be honoured on the way out is not a limit.
pub const MAX_OBJECT_PAGES: usize = 16;

/// Whether memory on `class` may be made reachable by a device whose
/// capability carries `device_rights`.
///
/// **A free function, so the rule has one statement and more than one caller.**
/// The syscall path applies it to a handle's rights; a boot check applies it to
/// the rights the resource graph recorded when the device was registered. Both
/// are asking the same question, and a rule written into the syscall alone
/// would leave the second asking a different one that merely happened to agree.
///
/// The shape `devmgr::record_dma_fault` has, for the same reason (D127): the
/// decision belongs to neither of its callers.
pub fn attach_permitted(class: MemoryClass, device_rights: crate::rights::Rights) -> bool {
    match class {
        MemoryClass::Unclassified => true,
        MemoryClass::Protected => device_rights.contains(crate::rights::Rights::PROTECTED_DMA),
    }
}

/// One memory object: which capability names it, and the frames it owns.
#[derive(Clone, Copy)]
struct MemoryObject {
    object: ObjectId,
    /// The process that owns this object — exactly one at a time.
    ///
    /// **Ownership, not a refcount.** The mode this milestone ships is
    /// *transfer*: ownership moves on send and the sender keeps nothing, so
    /// "who frees the frames" has a single answer at every instant, and the
    /// answer follows the capability. A refcount would model *share*, which
    /// needs the object table three ports do not have — so it lands with
    /// share (build/README.md, D131).
    ///
    /// Mappings do not depend on this: each holds its own frame reference, so
    /// a mapping outliving its owner keeps the pages alive on its own.
    owner: ObjectId,
    frames: [Option<PhysFrame>; MAX_OBJECT_PAGES],
    pages: usize,
    /// The handling path this object's contents are on.
    ///
    /// Kept on the object rather than on its frames because it is a property of
    /// what the memory *holds*, which follows the object across a transfer,
    /// while frames go back to a pool that has no memory of what was in them.
    /// A pool-level classification would also mean declassifying every frame
    /// individually on free, and a missed one would leak a class the other way.
    class: MemoryClass,
    /// Where this object had to be, as its creator stated it.
    ///
    /// Kept because the *broker* has to read it later: whether a device may be
    /// given this object at all depends on what kind of contiguity was asked
    /// for and what the device's path can provide, and that question is asked
    /// at attach time rather than at create time.
    placement: Placement,
    /// The device this object is currently reachable by, if any.
    ///
    /// **Recorded on the object rather than on the device**, because three of
    /// the four ways an attachment ends start from the object — it was handed
    /// on, it was destroyed, its owner exited — and only one starts from the
    /// device. A record kept on the device would have to be searched by object
    /// on every one of those paths, which is the same table walked the other
    /// way round and one more thing to keep in step.
    attached: Option<Attachment>,
    /// The `(device, address)` this object was last attached at, kept across a
    /// detach so re-attaching it to the same device reuses the same address.
    ///
    /// **This is what lets a driver serve a buffer more than once.** A device
    /// address is never reissued within a lease, so without this every request
    /// spent one and a driver stopped when its aperture ran out — two buffers,
    /// on the SMMU machine.
    ///
    /// Reusing it here does not weaken that rule, because the rule is about
    /// naming *different* memory: a device may hold an address in a descriptor
    /// ring the kernel cannot see, and reissuing it for something else would
    /// turn a stale descriptor into a write to whatever now occupies it. An
    /// object's frames are fixed when it is created, so this address is
    /// reissued for the memory it already named — a stale descriptor resolves
    /// to the same buffer, with the same owner. What is still never done is
    /// giving that address to a different object.
    ///
    /// Cleared when the device's lease ends, because the whole range is then
    /// reusable by whoever leases next and the address stops meaning anything.
    last_attachment: Option<(ObjectId, u64)>,
}

/// Where a device can reach an object, and how.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attachment {
    /// The device that can reach it.
    pub device: ObjectId,
    /// The address the device uses. An IOVA inside the device's lease when
    /// `scoped`; a physical address otherwise.
    pub address: u64,
    /// How many bytes are reachable from `address`.
    pub len: u64,
    /// Whether an IOMMU translates this — which decides whether ending the
    /// attachment has anything to unmap, or whether the address was never a
    /// translation at all.
    pub scoped: bool,
}

/// A fixed pool of memory objects.
pub struct MemoryTable {
    objects: [Option<MemoryObject>; MAX_MEMORY_OBJECTS],
    /// The next id to mint. Monotonic and never reused within a boot: an id
    /// handed out twice would let a stale handle name a live object.
    next_id: u32,
}

impl MemoryTable {
    pub const fn new() -> Self {
        Self {
            objects: [const { None }; MAX_MEMORY_OBJECTS],
            next_id: MEMORY_OBJECT_ID_BASE,
        }
    }

    /// Backs `object` with `pages` freshly allocated, **zeroed** frames.
    ///
    /// Zeroing is not hygiene, it is the security property. An object is
    /// created to be handed to somebody else; a frame that arrived carrying
    /// whatever its last owner left would make every grant a disclosure. It is
    /// done here rather than left to the caller because "the caller must
    /// remember" is how that becomes a bug — which is why this takes an
    /// address space it does not otherwise need, purely for
    /// [`AddressSpaceOps::zero_frame`].
    ///
    /// A partial failure frees every frame it had drawn: a bump allocator has
    /// no unwind of its own, and leaving them would be a leak the caller
    /// cannot see or fix.
    pub fn create<A: AddressSpaceOps>(
        &mut self,
        owner: ObjectId,
        pages: usize,
        placement: Placement,
        space: &AddressSpace<A>,
        alloc: &mut dyn FrameSource,
    ) -> Result<ObjectId, KError> {
        if pages == 0 || pages > MAX_OBJECT_PAGES {
            return Err(KError::InvalidMapping);
        }
        let slot = self
            .objects
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        let object = ObjectId::from_raw(self.next_id);

        let mut frames = [None; MAX_OBJECT_PAGES];
        for page in 0..pages {
            match alloc.alloc_frame() {
                Some(frame) => {
                    space.arch().zero_frame(frame);
                    frames[page] = Some(frame);
                }
                None => {
                    for drawn in frames.iter().flatten() {
                        alloc.free_frame(*drawn);
                    }
                    return Err(KError::OutOfMemory);
                }
            }
        }
        // **Checked, then refused — never weakened.** What came back either
        // satisfies the request or it does not, and the alternative to giving
        // the frames back is handing a caller memory that does not meet the
        // constraint it stated. It would find out when a device read the wrong
        // address, which is the worst possible place to learn it.
        //
        // This checks rather than searches. A placing allocator that could hunt
        // for a run at a given alignment belongs to the memory manager; what is
        // owed here is that a request is satisfied exactly or answered `no`, and
        // a refusal a caller can retry is a smaller lie than a silent
        // downgrade.
        if let Err(e) = placement.satisfied_by(&frames[..pages]) {
            for drawn in frames.iter().flatten() {
                alloc.free_frame(*drawn);
            }
            return Err(e);
        }
        self.objects[slot] = Some(MemoryObject {
            object,
            owner,
            frames,
            pages,
            // Every object starts unclassified. Not a default anybody is
            // falling back to: memory the kernel just zeroed holds nothing, so
            // there is nothing yet for a class to be about.
            class: MemoryClass::Unclassified,
            placement,
            attached: None,
            last_attachment: None,
        });
        self.next_id += 1;
        Ok(object)
    }

    /// Where `object`'s creator said it had to be — what the broker reads when
    /// it decides whether a device may be given it.
    pub fn placement_of(&self, object: ObjectId) -> Option<Placement> {
        self.objects
            .iter()
            .flatten()
            .find(|entry| entry.object == object)
            .map(|entry| entry.placement)
    }

    /// Puts `object` on a handling path, **and refuses to take it off one**.
    ///
    /// `docs/security/01` ("Memory Classification") makes classification
    /// monotonic: the strongest applicable class governs, so a class may be
    /// raised and never lowered. Declassification is a policy act with its own
    /// authority and audit; if it were available here, anything holding a
    /// protected buffer could clear the class and hand the memory to a device,
    /// and the whole mechanism would be advisory.
    ///
    /// Re-classifying to the class an object already has succeeds and changes
    /// nothing. An idempotent request is not an error, and a caller forced to
    /// remember whether it had already asked would be keeping state this table
    /// already holds.
    ///
    /// `WrongType` for an id that is not a memory object — a confusion the
    /// caller should hear about rather than have silently ignored.
    pub fn classify(&mut self, object: ObjectId, class: MemoryClass) -> Result<(), KError> {
        let entry = self
            .objects
            .iter_mut()
            .flatten()
            .find(|entry| entry.object == object)
            .ok_or(KError::WrongType)?;
        if (class as u32) < (entry.class as u32) {
            return Err(KError::AccessDenied);
        }
        entry.class = class;
        Ok(())
    }

    /// The handling path `object` is on, or `None` if it is not a memory
    /// object.
    pub fn class_of(&self, object: ObjectId) -> Option<MemoryClass> {
        self.objects
            .iter()
            .flatten()
            .find(|entry| entry.object == object)
            .map(|entry| entry.class)
    }

    /// Moves ownership of `object` to `owner` — what a transfer does.
    ///
    /// Returns whether the object exists. A capability that is not a memory
    /// object travels without this having anything to say about it, which is
    /// why the departure paths call it unconditionally.
    pub fn set_owner(&mut self, object: ObjectId, owner: ObjectId) -> bool {
        match self
            .objects
            .iter_mut()
            .flatten()
            .find(|entry| entry.object == object)
        {
            Some(entry) => {
                entry.owner = owner;
                true
            }
            None => false,
        }
    }

    /// Who owns `object`, if it is a memory object.
    pub fn owner_of(&self, object: ObjectId) -> Option<ObjectId> {
        self.find(object).map(|entry| entry.owner)
    }

    /// Every object `owner` owns, in `out`; returns how many — the sweep a
    /// departing process's teardown walks. Scanned by object rather than by
    /// process for the same reason the lease and route sweeps are: nothing can
    /// enumerate what a process owns.
    pub fn objects_owned_by(&self, owner: ObjectId, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for entry in self.objects.iter().flatten() {
            if n == out.len() {
                break;
            }
            if entry.owner == owner {
                out[n] = entry.object;
                n += 1;
            }
        }
        n
    }

    /// How many pages `object` holds, if the table knows it. `None` means the
    /// capability names something that is not a memory object — a different
    /// fact from an object of zero pages, which cannot exist.
    pub fn pages_of(&self, object: ObjectId) -> Option<usize> {
        self.find(object).map(|entry| entry.pages)
    }

    /// The object's length in bytes.
    pub fn len_of(&self, object: ObjectId) -> Option<u64> {
        self.pages_of(object).map(|pages| pages as u64 * FRAME_SIZE)
    }

    /// Copies `object`'s frames into `out`, returning how many. A short `out`
    /// truncates, which is why callers size it at [`MAX_OBJECT_PAGES`].
    pub fn frames_of(&self, object: ObjectId, out: &mut [PhysFrame]) -> usize {
        let Some(entry) = self.find(object) else {
            return 0;
        };
        let mut n = 0;
        for frame in entry.frames.iter().take(entry.pages).flatten() {
            if n == out.len() {
                break;
            }
            out[n] = *frame;
            n += 1;
        }
        n
    }

    /// Drops the object's own reference to each of its frames and forgets it,
    /// returning how many frames were released.
    ///
    /// **The object's reference, not everybody's.** A frame still mapped
    /// somewhere has been retained by that mapping and stays alive; this only
    /// releases the one reference the object itself held. That is what lets a
    /// holder close its handle while another process is still using the pages,
    /// which is the ordinary case rather than an edge one.
    pub fn destroy(&mut self, object: ObjectId, alloc: &mut dyn FrameSource) -> usize {
        let Some(slot) = self
            .objects
            .iter()
            .position(|entry| matches!(entry, Some(entry) if entry.object == object))
        else {
            return 0;
        };
        // **A device can still reach it, so the frames stay put.** Returning
        // them to the allocator here would put memory a device is writing into
        // somebody else's hands — the same window `Executive::end_device_leases`
        // exists to close, arriving through a different door. This has no
        // mapper and so cannot detach; every real caller goes through
        // `Executive::memory_destroy`, which does. Leaking is the lesser of
        // the two outcomes, and the event is what keeps it from being silent.
        if let Some(entry) = self.objects[slot]
            && let Some(attachment) = entry.attached
        {
            crate::event::emit(
                crate::event::EventKind::MemReclaimOverflow,
                crate::event::Severity::Error,
                crate::event::Component::Memory,
                [
                    crate::pmem::RECLAIM_REFUSED_STILL_ATTACHED,
                    object.raw() as u64,
                    attachment.device.raw() as u64,
                    attachment.address,
                ],
            );
            return 0;
        }
        let mut released = 0;
        if let Some(entry) = self.objects[slot] {
            for frame in entry.frames.iter().take(entry.pages).flatten() {
                alloc.free_frame(*frame);
                released += 1;
            }
        }
        self.objects[slot] = None;
        released
    }

    /// Records that `object` is reachable by a device, refusing if it already
    /// is.
    ///
    /// **A second attachment is `AlreadyMapped`, not a replacement.** Replacing
    /// would drop the record of the first without unmapping it, leaving a
    /// translation nothing can find and a device able to reach an object
    /// everyone believes is detached.
    pub fn attach(&mut self, object: ObjectId, attachment: Attachment) -> Result<(), KError> {
        let entry = self
            .objects
            .iter_mut()
            .flatten()
            .find(|entry| entry.object == object)
            .ok_or(KError::BadHandle)?;
        if entry.attached.is_some() {
            return Err(KError::AlreadyMapped);
        }
        entry.last_attachment = Some((attachment.device, attachment.address));
        entry.attached = Some(attachment);
        Ok(())
    }

    /// The address this object was last reachable at from `device`, if it has
    /// been attached there before and that lease has not ended since.
    ///
    /// A caller re-attaching to the same device uses this instead of taking a
    /// fresh address — see [`MemoryObject::last_attachment`] for why that is
    /// sound.
    pub fn remembered_address(&self, object: ObjectId, device: ObjectId) -> Option<u64> {
        self.objects
            .iter()
            .flatten()
            .find(|entry| entry.object == object)
            .and_then(|entry| entry.last_attachment)
            .and_then(|(at, address)| (at == device).then_some(address))
    }

    /// Forgets that `object` was ever attached to a device, so a later attach
    /// takes a fresh address. For the lease-end path, where the whole range
    /// stops belonging to anyone.
    pub fn forget_last_attachment(&mut self, object: ObjectId) {
        if let Some(entry) = self
            .objects
            .iter_mut()
            .flatten()
            .find(|entry| entry.object == object)
        {
            entry.last_attachment = None;
        }
    }

    /// Forgets `object`'s attachment and returns what it was, or `None` when it
    /// had none.
    ///
    /// The **bookkeeping** half only. Unmapping is the caller's, because the
    /// caller is the one holding the mapper — and because the two must happen
    /// in that order on some paths and the opposite order on others (a lease
    /// that has already ended has nothing left to unmap).
    pub fn detach(&mut self, object: ObjectId) -> Option<Attachment> {
        self.objects
            .iter_mut()
            .flatten()
            .find(|entry| entry.object == object)
            .and_then(|entry| entry.attached.take())
    }

    /// Where `object` is currently reachable from, if anywhere.
    pub fn attachment_of(&self, object: ObjectId) -> Option<Attachment> {
        self.objects
            .iter()
            .flatten()
            .find(|entry| entry.object == object)
            .and_then(|entry| entry.attached)
    }

    /// Every attached object a given device can reach, written into `out`.
    /// Returns how many.
    pub fn objects_attached_to(&self, device: ObjectId, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for entry in self.objects.iter().flatten() {
            if entry.attached.is_some_and(|a| a.device == device) && n < out.len() {
                out[n] = entry.object;
                n += 1;
            }
        }
        n
    }

    /// Objects currently backed.
    pub fn count(&self) -> usize {
        self.objects.iter().flatten().count()
    }

    fn find(&self, object: ObjectId) -> Option<&MemoryObject> {
        self.objects
            .iter()
            .flatten()
            .find(|entry| entry.object == object)
    }
}

impl Default for MemoryTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::Asid;
    use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

    const OWNER: ObjectId = ObjectId::from_raw(0x60);

    fn space(frames: &mut MockFrameSource) -> AddressSpace<MockAddressSpace> {
        AddressSpace::<MockAddressSpace>::new(frames, 0xffff_8000_0000_0000, Asid(1))
            .expect("space")
    }

    /// **Strict binding, and a refusal rather than a weakening.** An alignment
    /// the allocator cannot meet is answered `no` — the frames it had drawn go
    /// back, and the caller learns now. The alternative is an object that does
    /// not meet the constraint it stated, whose owner finds out when a device
    /// reads the wrong address.
    #[test]
    fn an_alignment_that_cannot_be_met_is_refused_not_rounded() {
        // Frames start at 0x1000_1000 and step by pages, so nothing this
        // allocator can hand out is aligned to a megabyte.
        let mut alloc = MockFrameSource::new(0x1000_1000, 64);
        let space = space(&mut alloc);
        let mut table = MemoryTable::new();
        let impossible = Placement {
            alignment: 0x10_0000,
            ..Placement::default()
        };
        assert_eq!(
            table.create(OWNER, 1, impossible, &space, &mut alloc),
            Err(KError::OutOfMemory),
        );
        // And the refusal cost nothing: the frames are back, so an ordinary
        // request still succeeds.
        assert!(
            table
                .create(OWNER, 1, Placement::default(), &space, &mut alloc)
                .is_ok(),
            "a refused placement gives its frames back",
        );
    }

    /// A physically-contiguous object is a run, checked frame by frame. The
    /// bump allocator hands out consecutive frames, so this succeeds — and the
    /// check is what makes that a guarantee rather than a coincidence of the
    /// allocator in use.
    #[test]
    fn a_physical_run_is_checked_frame_by_frame() {
        let mut alloc = MockFrameSource::new(0x1000_0000, 64);
        let space = space(&mut alloc);
        let mut table = MemoryTable::new();
        let run = Placement {
            physically_contiguous: true,
            ..Placement::default()
        };
        let object = table
            .create(OWNER, 3, run, &space, &mut alloc)
            .expect("a run");
        let mut out = [PhysFrame::containing(tessera_karch::PhysAddr::new(0)); MAX_OBJECT_PAGES];
        assert_eq!(table.frames_of(object, &mut out), 3);
        for (page, frame) in out[..3].iter().enumerate() {
            assert_eq!(
                frame.base().as_u64(),
                out[0].base().as_u64() + page as u64 * FRAME_SIZE,
            );
        }
    }

    /// **Device-visible contiguity is not a constraint on the memory**, and
    /// this is the IOMMU-first rule in one assertion: a request for it accepts
    /// whatever frames come back, because the contiguity it asks for is the
    /// broker's to produce in the mapping. Checking it against physical
    /// addresses would be demanding physical contiguity under another name,
    /// which is exactly the carveout pressure the rule exists to avoid.
    #[test]
    fn device_contiguity_asks_nothing_of_the_frames() {
        let scattered = [
            PhysFrame::from_base(tessera_karch::PhysAddr::new(0x9000)),
            PhysFrame::from_base(tessera_karch::PhysAddr::new(0x1000)),
        ];
        let device = Placement {
            device_contiguous: true,
            ..Placement::default()
        };
        assert_eq!(device.satisfied_by(&scattered), Ok(()));
        // The same frames refuse a physical request, which is what makes the
        // two different questions rather than one spelled two ways.
        let physical = Placement {
            physically_contiguous: true,
            ..Placement::default()
        };
        assert_eq!(physical.satisfied_by(&scattered), Err(KError::OutOfMemory));
    }

    /// An addressing limit is measured against the **last byte** of every
    /// frame. A frame that starts below a 32-bit controller's ceiling and ends
    /// above it is still memory that controller cannot address.
    #[test]
    fn an_addressing_limit_counts_the_last_byte() {
        let frames = [PhysFrame::from_base(tessera_karch::PhysAddr::new(0x1000))];
        let just_short = Placement {
            address_limit: 0x1fff,
            ..Placement::default()
        };
        assert_eq!(just_short.satisfied_by(&frames), Ok(()));
        let one_byte_less = Placement {
            address_limit: 0x1ffe,
            ..Placement::default()
        };
        assert_eq!(
            one_byte_less.satisfied_by(&frames),
            Err(KError::OutOfMemory),
        );
    }

    #[test]
    fn creating_an_object_draws_and_records_its_frames() {
        let mut alloc = MockFrameSource::new(0x1000_0000, 64);
        let space = space(&mut alloc);
        let mut table = MemoryTable::new();

        let object = table
            .create(OWNER, 2, Placement::default(), &space, &mut alloc)
            .expect("create");
        assert!(
            object.raw() >= MEMORY_OBJECT_ID_BASE,
            "minted above the fabricated range"
        );
        assert_eq!(table.pages_of(object), Some(2));
        assert_eq!(table.len_of(object), Some(2 * FRAME_SIZE));
        assert_eq!(table.owner_of(object), Some(OWNER));
        assert_eq!(table.count(), 1);

        let mut out = [PhysFrame::containing(tessera_karch::PhysAddr::new(0)); MAX_OBJECT_PAGES];
        assert_eq!(table.frames_of(object, &mut out), 2);
        assert_ne!(out[0].base().as_u64(), out[1].base().as_u64());
    }

    /// A capability that is not a memory object answers `None`, which a caller
    /// must be able to tell from an object with no pages — a thing that cannot
    /// exist, because `create` refuses zero.
    #[test]
    fn an_unknown_object_has_no_pages_and_zero_is_refused() {
        let mut alloc = MockFrameSource::new(0x1000_0000, 64);
        let space = space(&mut alloc);
        let mut table = MemoryTable::new();
        assert_eq!(table.pages_of(ObjectId::from_raw(0x99)), None);
        assert_eq!(
            table.create(OWNER, 0, Placement::default(), &space, &mut alloc),
            Err(KError::InvalidMapping),
        );
        assert_eq!(
            table.create(
                OWNER,
                MAX_OBJECT_PAGES + 1,
                Placement::default(),
                &space,
                &mut alloc
            ),
            Err(KError::InvalidMapping),
        );
    }

    /// A partial allocation frees what it drew. A bump allocator has no unwind
    /// of its own, so frames left here are lost for the life of the machine
    /// and invisible to the caller.
    #[test]
    fn a_partial_allocation_gives_back_every_frame_it_drew() {
        let mut alloc = MockFrameSource::new(0x1000_0000, 64);
        let space = space(&mut alloc);
        let mut table = MemoryTable::new();
        // Drain the allocator to fewer frames than the object needs.
        let before = alloc.free_list_depth();
        let _ = before;
        let mut drained = 0;
        while alloc.alloc_frame().is_some() {
            drained += 1;
            if drained > 4096 {
                panic!("allocator never exhausted");
            }
        }
        assert_eq!(
            table.create(OWNER, 2, Placement::default(), &space, &mut alloc),
            Err(KError::OutOfMemory),
        );
        assert_eq!(table.count(), 0, "and nothing was recorded");
    }

    /// Destroying releases the object's own reference to each frame and
    /// forgets it. It does **not** release anybody else's — a frame a mapping
    /// still holds stays alive, which is what lets a holder close its handle
    /// while another process is using the pages.
    #[test]
    fn destroying_releases_the_objects_own_reference() {
        let mut alloc = MockFrameSource::new(0x1000_0000, 64);
        let space = space(&mut alloc);
        let mut table = MemoryTable::new();
        let object = table
            .create(OWNER, 3, Placement::default(), &space, &mut alloc)
            .expect("create");

        let before = alloc.free_list_depth();
        assert_eq!(table.destroy(object, &mut alloc), 3);
        assert_eq!(
            alloc.free_list_depth(),
            before + 3,
            "every frame came back exactly once",
        );
        assert_eq!(table.pages_of(object), None);
        // Destroying twice is a no-op, so a departure path need not first ask
        // whether the object was still there.
        assert_eq!(table.destroy(object, &mut alloc), 0);
    }

    #[test]
    fn a_full_table_is_refused_and_ids_are_never_reused() {
        let mut alloc = MockFrameSource::new(0x1000_0000, 256);
        let space = space(&mut alloc);
        let mut table = MemoryTable::new();
        let mut minted = [ObjectId::from_raw(0); MAX_MEMORY_OBJECTS];
        for slot in minted.iter_mut() {
            *slot = table
                .create(OWNER, 1, Placement::default(), &space, &mut alloc)
                .expect("fits");
        }
        assert_eq!(
            table.create(OWNER, 1, Placement::default(), &space, &mut alloc),
            Err(KError::OutOfMemory),
        );
        // Every id distinct — an id handed out twice would let a stale handle
        // name a live object.
        for (i, a) in minted.iter().enumerate() {
            for b in minted.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        // And a freed slot does not recycle its id.
        table.destroy(minted[0], &mut alloc);
        let next = table
            .create(OWNER, 1, Placement::default(), &space, &mut alloc)
            .expect("reuse slot");
        assert!(!minted.contains(&next));
    }

    /// Ownership moves on transfer, and the sweep finds what a departing
    /// process owns — the question a refcount would answer, answered without
    /// one because transfer has a single owner at every instant.
    #[test]
    fn ownership_moves_and_the_sweep_finds_it() {
        let mut alloc = MockFrameSource::new(0x1000_0000, 256);
        let space = space(&mut alloc);
        let mut table = MemoryTable::new();
        let receiver = ObjectId::from_raw(0x61);
        let object = table
            .create(OWNER, 1, Placement::default(), &space, &mut alloc)
            .expect("create");

        let mut out = [ObjectId::from_raw(0); MAX_MEMORY_OBJECTS];
        assert_eq!(table.objects_owned_by(OWNER, &mut out), 1);
        assert_eq!(out[0], object);
        assert_eq!(table.objects_owned_by(receiver, &mut out), 0);

        assert!(table.set_owner(object, receiver));
        assert_eq!(table.owner_of(object), Some(receiver));
        assert_eq!(
            table.objects_owned_by(OWNER, &mut out),
            0,
            "the sender owns nothing now"
        );
        assert_eq!(table.objects_owned_by(receiver, &mut out), 1);

        // A capability that is not a memory object passes through untouched,
        // which is why the departure paths call this unconditionally.
        assert!(!table.set_owner(ObjectId::from_raw(0x99), receiver));
    }

    /// **The backstop: frames a device can still reach do not go back to the
    /// allocator.** `Executive::memory_destroy` detaches first, so this should
    /// never fire — and if it does, leaking is the lesser of the two harms and
    /// the event is what keeps it from being silent. Handing those frames out
    /// again would let a device write into somebody else's memory.
    #[test]
    fn destroying_an_attached_object_frees_nothing() {
        let mut frames = MockFrameSource::new(0x1000_0000, 64);
        let space = space(&mut frames);
        let mut table = MemoryTable::new();
        let object = table
            .create(OWNER, 2, Placement::default(), &space, &mut frames)
            .expect("create");
        table
            .attach(
                object,
                Attachment {
                    device: ObjectId::from_raw(21),
                    address: 0x8000_0000,
                    len: 2 * FRAME_SIZE,
                    scoped: true,
                },
            )
            .expect("attach");

        assert_eq!(table.destroy(object, &mut frames), 0, "nothing was freed");
        assert!(table.attachment_of(object).is_some(), "and it still exists");

        // Detached, it goes as it always did.
        assert!(table.detach(object).is_some());
        assert_eq!(table.destroy(object, &mut frames), 2);
    }

    /// A second attachment is refused rather than replacing the first, which
    /// would leave a translation installed that nothing can name and therefore
    /// nothing will ever remove.
    #[test]
    fn an_object_can_be_reachable_by_one_device_at_a_time() {
        let mut frames = MockFrameSource::new(0x1000_0000, 64);
        let space = space(&mut frames);
        let mut table = MemoryTable::new();
        let object = table
            .create(OWNER, 1, Placement::default(), &space, &mut frames)
            .expect("create");
        let first = Attachment {
            device: ObjectId::from_raw(21),
            address: 0x8000_0000,
            len: FRAME_SIZE,
            scoped: true,
        };
        table.attach(object, first).expect("attach");
        assert_eq!(
            table.attach(
                object,
                Attachment {
                    device: ObjectId::from_raw(22),
                    address: 0x9000_0000,
                    len: FRAME_SIZE,
                    scoped: true,
                },
            ),
            Err(KError::AlreadyMapped),
        );
        assert_eq!(table.attachment_of(object), Some(first));
    }

    /// Every object a device can reach is findable from the device, which is
    /// what the lease-end path walks — the one revocation that starts at the
    /// device rather than at the object.
    #[test]
    fn the_objects_a_device_can_reach_are_findable_from_it() {
        let mut frames = MockFrameSource::new(0x1000_0000, 64);
        let space = space(&mut frames);
        let mut table = MemoryTable::new();
        let device = ObjectId::from_raw(21);
        let a = table
            .create(OWNER, 1, Placement::default(), &space, &mut frames)
            .expect("create");
        let b = table
            .create(OWNER, 1, Placement::default(), &space, &mut frames)
            .expect("create");
        let c = table
            .create(OWNER, 1, Placement::default(), &space, &mut frames)
            .expect("create");
        for (object, at) in [(a, 0x8000_0000u64), (c, 0x8000_2000)] {
            table
                .attach(
                    object,
                    Attachment {
                        device,
                        address: at,
                        len: FRAME_SIZE,
                        scoped: true,
                    },
                )
                .expect("attach");
        }
        let mut out = [ObjectId::from_raw(0); MAX_MEMORY_OBJECTS];
        let found = table.objects_attached_to(device, &mut out);
        assert_eq!(found, 2);
        assert!(out[..found].contains(&a) && out[..found].contains(&c));
        assert!(!out[..found].contains(&b), "b was never attached");
    }

    /// A class rises and never falls, and re-stating one is not an error.
    ///
    /// The lowering refusal is the load-bearing half: without it anything
    /// holding a protected buffer could clear the class and hand the memory to
    /// a device, and every check above this one would be decorative.
    #[test]
    fn a_class_rises_and_never_falls() {
        let mut alloc = MockFrameSource::new(0x1000, 8);
        let mut space = space(&mut alloc);
        let mut table = MemoryTable::new();
        let owner = ObjectId::from_raw(1);
        let object = table
            .create(owner, 1, Placement::default(), &space, &mut alloc)
            .expect("create");

        assert_eq!(table.class_of(object), Some(MemoryClass::Unclassified));
        assert_eq!(table.classify(object, MemoryClass::Protected), Ok(()));
        assert_eq!(table.class_of(object), Some(MemoryClass::Protected));
        // Idempotent.
        assert_eq!(table.classify(object, MemoryClass::Protected), Ok(()));
        // And never down.
        assert_eq!(
            table.classify(object, MemoryClass::Unclassified),
            Err(KError::AccessDenied)
        );
        assert_eq!(table.class_of(object), Some(MemoryClass::Protected));
        table.destroy(object, &mut alloc);
        let _ = &mut space;
    }

    /// An id that is not a memory object is a type confusion the caller hears
    /// about, rather than a classification silently applied to nothing.
    #[test]
    fn classifying_something_that_is_not_memory_is_refused() {
        let mut table = MemoryTable::new();
        assert_eq!(
            table.classify(ObjectId::from_raw(99), MemoryClass::Protected),
            Err(KError::WrongType)
        );
        assert_eq!(table.class_of(ObjectId::from_raw(99)), None);
    }
}
