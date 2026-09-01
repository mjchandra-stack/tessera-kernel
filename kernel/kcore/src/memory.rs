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
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_MEMORY_OBJECTS;

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

/// How many processes may hold one memory object at once.
///
/// **Four, and bounded like every kcore pool** (D15). Two is what a shared
/// buffer between a service and a driver needs; four leaves room for a
/// pipeline without making the per-object cost interesting. A share past this
/// is refused with `Exhausted` rather than silently dropping a holder, because
/// a holder the kernel forgot is memory freed while somebody is still reading
/// it.
pub const MAX_HOLDERS: usize = 4;

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
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_FRAME_SLOTS;
pub use crate::config::MAX_OBJECT_PAGES;

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
    /// The processes that hold this object, oldest first, `None` past the end.
    ///
    /// **A set rather than one owner, which is what `SHARE` needed** (D286).
    /// Under `TRANSFER` alone there was exactly one at every instant and the
    /// answer to "who frees the frames" followed the capability; under `SHARE`
    /// two processes hold the same object and the frames go when the *last*
    /// one lets go. D131 deferred this on the grounds that counting references
    /// needs the object table three of the five ports lacked — but the count
    /// that matters is per memory object and per process, and this is where
    /// both are already known. No object table is involved.
    ///
    /// **Membership is per process, not per handle.** A process holding two
    /// handles to one object appears once, and stops holding it when its last
    /// handle goes — which is the question `HandleTable::holds` already
    /// answers, and the one `handle_close` was already asking.
    ///
    /// Mappings do not depend on this: each holds its own frame reference, so
    /// a mapping outliving every holder keeps the pages alive on its own.
    holders: [Option<ObjectId>; MAX_HOLDERS],
    /// Where this object's run of frame slots begins in [`MemoryTable::slots`].
    ///
    /// **An index rather than the frames themselves** (D308). Holding them
    /// inline made every object cost the largest object's storage; the run is
    /// contiguous so a page is still `slots[base + page]` and the page-in path
    /// does not walk.
    base: usize,
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
    /// The pager this object's pages come from, if it has one.
    ///
    /// `None` is a kernel-backed object: every page was allocated when it was
    /// created and is resident for as long as it exists. `Some` is
    /// service-backed (docs/kernel/03, "External Pager Protocol") — the frames
    /// start absent and arrive one at a time from the named endpoint, which is
    /// what makes the array below a *cache* rather than an allocation.
    ///
    /// Kept here rather than in a side table because every question anybody
    /// asks about it starts from the object: who supplies this page, may this
    /// caller supply it, is this object one whose holes mean "not yet" rather
    /// than "corrupt".
    pager: Option<ObjectId>,
    /// The **process** that answers for this object's contents.
    ///
    /// Separate from `owner`, and it has to be: ownership answers *who frees
    /// the frames* and moves when the capability is handed on, while this
    /// answers *who supplies them* and does not. A filesystem service that
    /// creates a file's object and sends it to a reader stops being the owner
    /// the moment the reader receives it — and is still the only thing that can
    /// fill in a page. Reading the pager's handle out of the owner's table
    /// looked right and found the reader's, which holds no authority to supply.
    served_by: Option<ObjectId>,
    /// Whether this object's pager has failed to answer for it.
    faulted: bool,
    /// Which of this object's resident pages have been written since they were
    /// supplied, and the bound past which a writer is throttled.
    ///
    /// **A second record of residency, deliberately.** `frames` above is the
    /// authority on *where* a page is; this is the authority on whether it has
    /// been changed. Keeping the dirty bit in `frames` would mean widening the
    /// entry every port's mapping code reads, and re-deriving the throttle rule
    /// that [`crate::pager::ObjectCache`] already states and tests. The two are
    /// written in the same functions — a page becomes resident and installed
    /// together, and is forgotten together — so they cannot drift apart
    /// without the compiler noticing a missing call.
    cache: crate::pager::ObjectCache,
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

/// A fixed pool of memory objects, over a **shared pool of frame slots**.
///
/// **The frames used to live in the object** — `[Option<PhysFrame>;
/// MAX_OBJECT_PAGES]`, inline — which meant every object cost the largest
/// object's worth of storage whether it held one page or all of them. Two
/// limits came out of that and both were reached: the table could not grow
/// wide, because each entry was hundreds of bytes; and it could not grow
/// *deep*, because raising `MAX_OBJECT_PAGES` multiplied by the number of
/// objects. A 151 KB program could not be opened at all, and a composed
/// filesystem path ran out of objects with room to spare in every other pool
/// (D304, D307; fixed in D308).
///
/// Now an object names a **run of slots** and costs what it uses. The two
/// budgets are independent: [`MAX_MEMORY_OBJECTS`] is how many objects may
/// exist, `MAX_FRAME_SLOTS` is how many pages they may hold between them, and
/// `MAX_OBJECT_PAGES` is a per-object cap rather than a per-object price.
///
/// **Runs are contiguous, so a page is still an index.** `frame_at` is on the
/// page-in path and is `slots[base + page]`; a linked list would have made it
/// a walk, and the pages of a large object are exactly what a fault touches
/// most. The cost is that a run has to be *found*, which is a first-fit scan
/// on create — rare, and bounded by the slot count.
pub struct MemoryTable {
    objects: [Option<MemoryObject>; MAX_MEMORY_OBJECTS],
    /// Every object's frames, back to back. A slot inside a live run holds
    /// `None` until its page is supplied, which is the ordinary state of a
    /// paged object — so a slot's contents cannot say whether it is taken.
    slots: [Option<PhysFrame>; MAX_FRAME_SLOTS],
    /// Which slots belong to a live run. Separate from `slots` for the reason
    /// above: `None` means "not yet supplied", not "free".
    taken: [bool; MAX_FRAME_SLOTS],
    /// The next id to mint. Monotonic and never reused within a boot: an id
    /// handed out twice would let a stale handle name a live object.
    next_id: u32,
}

impl MemoryTable {
    pub const fn new() -> Self {
        Self {
            objects: [const { None }; MAX_MEMORY_OBJECTS],
            slots: [const { None }; MAX_FRAME_SLOTS],
            taken: [false; MAX_FRAME_SLOTS],
            next_id: MEMORY_OBJECT_ID_BASE,
        }
    }

    /// Takes a contiguous run of `pages` slots, or `None` if the pool has no
    /// run that long.
    ///
    /// First fit. Best fit would cost a full scan to buy a fragmentation
    /// improvement nobody has been able to show reliably, and the runs here are
    /// created and destroyed whole rather than resized.
    fn take_run(&mut self, pages: usize) -> Option<usize> {
        if pages == 0 || pages > MAX_FRAME_SLOTS {
            return None;
        }
        let mut at = 0usize;
        while at + pages <= MAX_FRAME_SLOTS {
            match (at..at + pages).find(|i| self.taken[*i]) {
                // A taken slot inside the window: the next run cannot start
                // before it ends, so skip past it rather than stepping one.
                Some(busy) => at = busy + 1,
                None => {
                    for i in at..at + pages {
                        self.taken[i] = true;
                        self.slots[i] = None;
                    }
                    return Some(at);
                }
            }
        }
        None
    }

    /// Gives a run back. The slots are cleared as well as freed: a stale frame
    /// left in a free slot would be handed to the next object as though it had
    /// been supplied.
    fn free_run(&mut self, base: usize, pages: usize) {
        for i in base..(base + pages).min(MAX_FRAME_SLOTS) {
            self.taken[i] = false;
            self.slots[i] = None;
        }
    }

    /// How many frame slots are in use, for a caller that wants to know how
    /// close the pool is rather than finding out by being refused.
    #[must_use]
    pub fn slots_in_use(&self) -> usize {
        self.taken.iter().filter(|t| **t).count()
    }

    /// How many objects exist.
    #[must_use]
    pub fn objects_in_use(&self) -> usize {
        self.objects.iter().flatten().count()
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
        // The run comes before the frames, so a pool with no room refuses
        // before anything is drawn — and the refusal is the one that names the
        // pool that is full.
        let base = self.take_run(pages).ok_or(KError::OutOfFrameSlots)?;
        let object = ObjectId::from_raw(self.next_id);

        // **Filled in place rather than staged in a local** (D308). With
        // `MAX_OBJECT_PAGES` at 256 an array of them is four kilobytes, and a
        // syscall runs on a ring-3 thread's kernel stack — which is the shape
        // that has overflowed one before. The slots are the storage; there is
        // nowhere else to put them anyway.
        for page in 0..pages {
            match alloc.alloc_frame() {
                Some(frame) => {
                    space.arch().zero_frame(frame);
                    self.slots[base + page] = Some(frame);
                }
                None => {
                    for i in base..base + pages {
                        if let Some(drawn) = self.slots[i] {
                            alloc.free_frame(drawn);
                        }
                    }
                    self.free_run(base, pages);
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
        if let Err(e) = placement.satisfied_by(&self.slots[base..base + pages]) {
            for i in base..base + pages {
                if let Some(drawn) = self.slots[i] {
                    alloc.free_frame(drawn);
                }
            }
            self.free_run(base, pages);
            return Err(e);
        }
        self.objects[slot] = Some(MemoryObject {
            object,
            holders: {
                let mut holders = [None; MAX_HOLDERS];
                holders[0] = Some(owner);
                holders
            },
            base,
            pages,
            // Every object starts unclassified. Not a default anybody is
            // falling back to: memory the kernel just zeroed holds nothing, so
            // there is nothing yet for a class to be about.
            class: MemoryClass::Unclassified,
            placement,
            attached: None,
            last_attachment: None,
            pager: None,
            served_by: None,
            faulted: false,
            cache: crate::pager::ObjectCache::new(Self::DIRTY_LIMIT),
        });
        self.next_id += 1;
        Ok(object)
    }

    /// Creates a **service-backed** object: `pages` pages that do not exist
    /// yet, supplied on demand by `pager`.
    ///
    /// The difference from [`create`](Self::create) is the whole point — it
    /// draws no frames. An object of a hundred pages costs nothing until
    /// somebody reads one, which is what a page cache is for, and it is why
    /// this cannot simply be `create` with a flag: `create`'s contract is that
    /// it either returns fully-backed memory or fails, and half of that
    /// sentence is false here.
    ///
    /// `placement` is deliberately absent. A placement constraint is a promise
    /// about physical addresses, and there are no physical addresses yet — a
    /// paged object cannot be handed to a device, and the refusal belongs where
    /// the attach is asked for rather than as a constraint nobody can check.
    pub fn create_paged(
        &mut self,
        owner: ObjectId,
        pages: usize,
        pager: ObjectId,
    ) -> Result<ObjectId, KError> {
        if pages == 0 || pages > MAX_OBJECT_PAGES {
            return Err(KError::InvalidMapping);
        }
        let slot = self
            .objects
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        // **A paged object reserves its slots up front** even though it draws
        // no frames: a page arriving later needs somewhere to go, and finding
        // the pool full at supply time would fail a fault rather than a create.
        // It is the create that a caller can do something about.
        let base = self.take_run(pages).ok_or(KError::OutOfFrameSlots)?;
        let object = ObjectId::from_raw(self.next_id);
        self.objects[slot] = Some(MemoryObject {
            object,
            holders: {
                let mut holders = [None; MAX_HOLDERS];
                holders[0] = Some(owner);
                holders
            },
            base,
            pages,
            class: MemoryClass::Unclassified,
            placement: Placement::default(),
            attached: None,
            last_attachment: None,
            pager: Some(pager),
            // The creator serves it. Recorded now because it is the only
            // moment the two are the same process.
            served_by: Some(owner),
            faulted: false,
            cache: crate::pager::ObjectCache::new(Self::DIRTY_LIMIT),
        });
        self.next_id += 1;
        Ok(object)
    }

    /// The endpoint that supplies `object`'s pages, or `None` if it is
    /// kernel-backed.
    pub fn pager_of(&self, object: ObjectId) -> Option<ObjectId> {
        self.find(object).and_then(|entry| entry.pager)
    }

    /// The process that answers for `object`'s contents — its creator, which
    /// does not change when the capability is handed on.
    pub fn served_by(&self, object: ObjectId) -> Option<ObjectId> {
        self.find(object).and_then(|entry| entry.served_by)
    }

    /// Puts `object` into the faulted state: its pager failed to answer for it,
    /// so nothing will ask again (docs/kernel/03, "Ownership, Resize, And
    /// Revocation" — bound objects transition to faulted on pager failure).
    ///
    /// **Resident pages stay readable.** The spec is explicit that existing
    /// clean mappings may go on reading cached pages; what ends is the
    /// expectation that a *missing* page will ever arrive. A reader that has
    /// what it needs is not punished for a page it never asked for.
    pub fn set_faulted(&mut self, object: ObjectId) {
        if let Some(entry) = self.find_mut(object) {
            entry.faulted = true;
        }
    }

    /// A clean resident page of `object` that could be dropped, or `None` if
    /// every resident page is dirty.
    ///
    /// Never a dirty one: a dirty page holds the only copy of a write, and
    /// dropping it loses that write. Reclaim takes clean pages and write-back
    /// is what turns a dirty page into one (docs/kernel/03, "Write-Back And
    /// Eviction Flow").
    pub fn evict_candidate(&self, object: ObjectId) -> Option<u64> {
        self.find(object)
            .and_then(|entry| entry.cache.evict_candidate())
    }

    /// Some object with a page that can be dropped, and which page.
    ///
    /// Only service-backed objects: a kernel-backed object's pages are its
    /// whole existence, and dropping one would leave a hole nothing can fill —
    /// there is no pager to ask for it back.
    pub fn any_evictable(&self) -> Option<(ObjectId, u64)> {
        self.objects.iter().flatten().find_map(|entry| {
            if entry.pager.is_none() || entry.faulted {
                return None;
            }
            entry
                .cache
                .evict_candidate()
                .map(|offset| (entry.object, offset))
        })
    }

    /// Some object with a dirty page, and which page — what reclaim writes back
    /// when nothing clean is left to take.
    pub fn any_dirty(&self) -> Option<(ObjectId, u64)> {
        let mut offsets = [0u64; MAX_OBJECT_PAGES];
        self.objects.iter().flatten().find_map(|entry| {
            if entry.pager.is_none() || entry.faulted {
                return None;
            }
            let n = entry.cache.dirty_offsets(&mut offsets);
            offsets[..n].first().map(|offset| (entry.object, *offset))
        })
    }

    /// Drops `object`'s page at `offset` from the cache, handing back the frame
    /// the object was holding it in.
    ///
    /// **Refused for a dirty page.** The caller is expected to have checked,
    /// and checking again here is cheap next to losing a write: this is the
    /// last place that can tell, and every caller above it has more to think
    /// about.
    pub fn evict(&mut self, object: ObjectId, offset: u64) -> Option<PhysFrame> {
        let page = (offset / FRAME_SIZE) as usize;
        let entry = self.find_mut(object)?;
        if entry.cache.is_dirty(offset) || page >= entry.pages {
            return None;
        }
        // The run is read off the entry and the slot taken from the pool: both
        // live on `self`, so the entry's borrow ends before the pool's begins.
        let base = entry.base;
        let frame = self.slots[base + page].take()?;
        let entry = self.find_mut(object)?;
        // Forgotten from both records together, as they were installed
        // together: a page left in one is a page the other cannot account for.
        entry.cache.forget(offset);
        Some(frame)
    }

    /// Whether `object`'s pager has failed it.
    pub fn is_faulted(&self, object: ObjectId) -> bool {
        self.find(object)
            .map(|entry| entry.faulted)
            .unwrap_or(false)
    }

    /// Dirty pages one object may hold before its writers are throttled.
    ///
    /// Half its pages: enough that an ordinary write pattern never meets the
    /// bound, few enough that a writer racing ahead of its pager meets it while
    /// there is still clean memory to reclaim. A bound equal to the object
    /// would never throttle anybody and would not be a bound.
    const DIRTY_LIMIT: u32 = (MAX_OBJECT_PAGES / 2) as u32;

    /// Records `frame` as `object`'s page `page`.
    ///
    /// Refused for a kernel-backed object, for a page past its end, and for a
    /// page that is **already there**. That last one is the one worth stating:
    /// overwriting would drop the old frame's only reference on the floor, and
    /// a pager that supplied the same page twice would leak a frame per
    /// duplicate while the mapping went on using the first.
    pub fn supply(
        &mut self,
        object: ObjectId,
        page: usize,
        frame: PhysFrame,
    ) -> Result<(), KError> {
        let Some(entry) = self.find_mut(object) else {
            return Err(KError::BadHandle);
        };
        if entry.pager.is_none() {
            return Err(KError::InvalidMapping);
        }
        if page >= entry.pages {
            return Err(KError::InvalidArgument);
        }
        let base = entry.base;
        if self.slots[base + page].is_some() {
            return Err(KError::AlreadyMapped);
        }
        self.slots[base + page] = Some(frame);
        let Some(entry) = self.find_mut(object) else {
            return Err(KError::BadHandle);
        };
        // Residency recorded in both places, in one function, so the two cannot
        // disagree about which pages exist.
        entry.cache.install(page as u64 * FRAME_SIZE)?;
        Ok(())
    }

    /// Records that `object`'s page at `offset` has been written, or refuses
    /// when the object is already at its dirty bound.
    ///
    /// [`DirtyOutcome::Throttle`](crate::pager::DirtyOutcome::Throttle) is not
    /// a failure of the write — it is the write being held back until a
    /// write-back drains what is already dirty (docs/kernel/03, "Write-Back
    /// Under Memory Pressure").
    pub fn mark_dirty(&mut self, object: ObjectId, offset: u64) -> crate::pager::DirtyOutcome {
        match self.find_mut(object) {
            Some(entry) => entry.cache.mark_dirty(offset),
            // An object nobody can find cannot be dirtied, and saying "marked"
            // would have a caller grant a write to a page with no owner.
            None => crate::pager::DirtyOutcome::Throttle,
        }
    }

    /// Marks `object`'s page at `offset` clean — only ever after its pager has
    /// acknowledged the write-back that persisted it.
    pub fn mark_clean(&mut self, object: ObjectId, offset: u64) {
        if let Some(entry) = self.find_mut(object) {
            entry.cache.mark_clean(offset);
        }
    }

    /// Opens a write-back window over `object`'s page at `offset`: from here
    /// until [`end_write_back`](Self::end_write_back), a store to the page is
    /// recorded as having overtaken the request.
    pub fn begin_write_back(&mut self, object: ObjectId, offset: u64) {
        if let Some(entry) = self.find_mut(object) {
            entry.cache.begin_write_back(offset);
        }
    }

    /// Closes the window, reporting whether a store landed inside it.
    ///
    /// `true` means the page must stay dirty: what the service was handed is
    /// no longer what the page holds.
    pub fn end_write_back(&mut self, object: ObjectId, offset: u64) -> bool {
        match self.find_mut(object) {
            Some(entry) => entry.cache.end_write_back(offset),
            // The object went away while the request was out; there is nothing
            // left to keep dirty.
            None => false,
        }
    }

    /// Whether `object`'s page at `offset` has been written since it was
    /// supplied or last written back.
    pub fn is_dirty(&self, object: ObjectId, offset: u64) -> bool {
        self.find(object)
            .map(|entry| entry.cache.is_dirty(offset))
            .unwrap_or(false)
    }

    /// How many of `object`'s pages are dirty.
    pub fn dirty_count(&self, object: ObjectId) -> u32 {
        self.find(object)
            .map(|entry| entry.cache.dirty_count())
            .unwrap_or(0)
    }

    /// Fills `out` with the offsets of `object`'s dirty pages, ascending, and
    /// returns how many — the dirty-range query a coordinated flush walks.
    pub fn dirty_offsets(&self, object: ObjectId, out: &mut [u64]) -> usize {
        self.find(object)
            .map(|entry| entry.cache.dirty_offsets(out))
            .unwrap_or(0)
    }

    /// The frame holding `object`'s page `page`, or `None` if it is not
    /// resident.
    pub fn frame_at(&self, object: ObjectId, page: usize) -> Option<PhysFrame> {
        let entry = self.find(object)?;
        if page >= entry.pages {
            return None;
        }
        self.slots[entry.base + page]
    }

    /// How many of `object`'s pages are resident right now.
    pub fn resident_pages(&self, object: ObjectId) -> usize {
        self.find(object)
            .map(|entry| {
                self.slots[entry.base..entry.base + entry.pages]
                    .iter()
                    .flatten()
                    .count()
            })
            .unwrap_or(0)
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
    pub fn set_sole_holder(&mut self, object: ObjectId, owner: ObjectId) -> bool {
        match self
            .objects
            .iter_mut()
            .flatten()
            .find(|entry| entry.object == object)
        {
            Some(entry) => {
                // **Every previous holder is replaced, not appended to.** This
                // is `TRANSFER` arriving: the sender's handle was taken before
                // the message was delivered, so it is not a holder any more,
                // and leaving it in the set would keep the frames alive behind
                // a capability nobody has.
                entry.holders = [None; MAX_HOLDERS];
                entry.holders[0] = Some(owner);
                true
            }
            None => false,
        }
    }

    /// Adds `holder` to `object`'s holders — what a `SHARE` does.
    ///
    /// **Idempotent**, because a process may be sent the same object twice and
    /// holding it twice is not a different fact from holding it once: the set
    /// is per process, and a second entry would have to be removed twice
    /// before the frames could go.
    ///
    /// `LimitExceeded` when the set is full — a bounded kernel pool refusing,
    /// which is what it is. The caller must not have taken anything from the
    /// sender before asking: a share refused after the sender's handle was
    /// narrowed away would lose the capability.
    pub fn add_holder(&mut self, object: ObjectId, holder: ObjectId) -> Result<(), KError> {
        let Some(entry) = self
            .objects
            .iter_mut()
            .flatten()
            .find(|entry| entry.object == object)
        else {
            return Err(KError::BadHandle);
        };
        if entry.holders.iter().flatten().any(|h| *h == holder) {
            return Ok(());
        }
        match entry.holders.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(holder);
                Ok(())
            }
            None => Err(KError::LimitExceeded),
        }
    }

    /// Removes `holder` from `object`, and says whether **anybody still holds
    /// it**.
    ///
    /// `false` means this was the last one and the frames are now nobody's, so
    /// the caller destroys. It is the only question a close or a teardown has
    /// to ask, which is why it is the return value rather than a count.
    pub fn remove_holder(&mut self, object: ObjectId, holder: ObjectId) -> bool {
        let Some(entry) = self
            .objects
            .iter_mut()
            .flatten()
            .find(|entry| entry.object == object)
        else {
            return false;
        };
        for slot in entry.holders.iter_mut() {
            if *slot == Some(holder) {
                *slot = None;
            }
        }
        // Closed up, so "the first empty slot" stays the end of the set and a
        // hole left by a departing holder does not cap it below `MAX_HOLDERS`.
        let mut kept = [None; MAX_HOLDERS];
        let mut n = 0;
        for held in entry.holders.iter().flatten() {
            kept[n] = Some(*held);
            n += 1;
        }
        entry.holders = kept;
        n > 0
    }

    /// Whether `holder` holds `object`.
    pub fn is_held_by(&self, object: ObjectId, holder: ObjectId) -> bool {
        self.find(object)
            .is_some_and(|entry| entry.holders.iter().flatten().any(|h| *h == holder))
    }

    /// How many processes hold `object`. `None` if it is not a memory object.
    pub fn holder_count(&self, object: ObjectId) -> Option<usize> {
        self.find(object)
            .map(|entry| entry.holders.iter().flatten().count())
    }

    /// The first holder, which under `TRANSFER` is the only one.
    ///
    /// **Kept for the questions that are about being a memory object at all**
    /// — `None` means "not one" — rather than about who owns it. A caller
    /// asking whether a particular process holds it wants
    /// [`is_held_by`](Self::is_held_by), which is a different question the
    /// moment two processes can answer yes.
    pub fn owner_of(&self, object: ObjectId) -> Option<ObjectId> {
        self.find(object)
            .and_then(|entry| entry.holders.iter().flatten().next().copied())
    }

    /// Every object `holder` holds, in `out`; returns how many — the sweep a
    /// departing process's teardown walks. Scanned by object rather than by
    /// process for the same reason the lease and route sweeps are: nothing can
    /// enumerate what a process holds.
    pub fn objects_held_by(&self, holder: ObjectId, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for entry in self.objects.iter().flatten() {
            if n == out.len() {
                break;
            }
            if entry.holders.iter().flatten().any(|h| *h == holder) {
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
        for frame in self.slots[entry.base..entry.base + entry.pages]
            .iter()
            .flatten()
        {
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
            for frame in self.slots[entry.base..entry.base + entry.pages]
                .iter()
                .flatten()
            {
                alloc.free_frame(*frame);
                released += 1;
            }
            // **The run goes back with the object** (D308). The frames returning
            // to the allocator says nothing about the slots that described them:
            // a destroy that freed the one and kept the other would leak the
            // pool this change exists to make big enough, and leak it in the way
            // that is hardest to see — capacity that never comes back, with
            // every frame accounted for.
            self.free_run(entry.base, entry.pages);
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

    fn find_mut(&mut self, object: ObjectId) -> Option<&mut MemoryObject> {
        self.objects
            .iter_mut()
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
#[path = "tests/memory.rs"]
mod tests;
