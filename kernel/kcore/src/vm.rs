// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel's `AddressSpace` object: architecture-independent bookkeeping
//! over a porting-layer page table. It grants mappings with rights that are
//! tracked *separately from any backing object's ownership rights*
//! (docs/kernel/02-scheduling-memory-ipc.md, "Memory Objects"), carries an
//! ASID and an active-core mask so single-core code needs no rework for SMP
//! TLB tracking (docs/kernel/08-multicore-scalability.md), and enforces the
//! write-XOR-execute rule before ever reaching the port.
//!
//! Memory is served four ways, all resolving through
//! [`resolve_fault`](AddressSpace::resolve_fault): **eager** anonymous
//! (`map_anonymous`, every page zero-filled at map time — kernel mappings,
//! which must never fault), **lazy** anonymous (`map_anonymous_demand`, faulted
//! in on first touch — budget B8), **copy-on-write** (`snapshot_cow`, shared
//! read-only until a write copies — budget B9), and **pager-backed**
//! (`map_object`, whose non-resident pages are supplied by an external pager
//! and installed with [`supply_page`](AddressSpace::supply_page) — budget B10;
//! `resolve_fault` returns [`FaultOutcome::NeedsPageIn`] for the caller to
//! forward, since the classifier cannot block). The live-mapping table is a
//! fixed capacity because the kernel has no general allocator yet — a bounded
//! kernel VMAR, generous for Stage 0.
//!
//! Generic over `AddressSpaceOps`, so it is exercised on the host against
//! `tessera-karch-mock` (every rejection path included) as well as on real
//! page tables.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Memory Model",
//! killable/reclaimable memory),
//! docs/kernel/03-paging-faults-and-exceptions.md ("Fault Taxonomy",
//! "External Pager Protocol", "Write-XOR-Execute"),
//! docs/kernel/05-jobs-containment-and-resource-control.md (deterministic
//! reclaim — `teardown`/`reclaim_range` return an exited space's frames)
//! Budget: B8 (anonymous fault), B9 (copy-on-write fault), B10 (pager page-in)
//! — the fault-resolve path; unmeasured until the perf rig lands
//! (build/README.md, D30/D33)

use crate::atomic::AtomicU64;
use crate::object::ObjectId;
use core::sync::atomic::Ordering;
use tessera_karch::{
    AddressSpaceOps, FRAME_SIZE, FrameSource, KError, PageFlags, PhysAddr, PhysFrame, VirtAddr,
};

/// Address-space identifier (the hardware ASID/PCID tag). Present on every
/// space from day one so SMP TLB tagging needs no object change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Asid(pub u16);

/// What backs a mapping — how [`resolve_fault`](AddressSpace::resolve_fault)
/// repairs a fault in it. File/object-backed memory (served by an external
/// pager) will join as a further variant (D27).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backing {
    /// Anonymous zero-filled memory, eagerly populated at map time. Every page
    /// is resident, so a fault here is genuine (kernel mappings).
    Anonymous,
    /// Anonymous zero-filled memory, populated lazily — a page is mapped on the
    /// first access that faults on it (budget B8; user mappings).
    AnonymousDemand,
    /// Copy-on-write: the range's pages are shared read-only; a write faults and
    /// the page is copied private (budget B9).
    Cow,
    /// Service-backed: the range's pages are supplied on demand by a pager
    /// (docs/kernel/03, "External Pager Protocol"). `base_offset` is the byte
    /// offset of the mapping's base within the memory object, so a fault page's
    /// object offset is `fault_page - mapping_base + base_offset` (budget B10).
    Object { object: ObjectId, base_offset: u64 },
    /// A **memory object's** pages, mapped from frames the object already
    /// owns. Every page is resident from the moment the mapping exists, and
    /// the frames are refcounted (`FrameSource::retain_frame`), so the same
    /// object can be mapped in more than one address space and each mapping
    /// holds exactly one reference.
    ///
    /// Deliberately not [`Backing::Object`], which means *pager-backed*: a
    /// non-resident page there is a page-in request, and a memory object has
    /// no pager to send one to. Sharing the variant would have a fault on a
    /// shared page forwarded to a service that does not exist; here it is
    /// [`FaultOutcome::Unresolvable`], which is the truth — every page was
    /// mapped up front, so a fault means the mapping and the tables have
    /// drifted.
    Shared { object: ObjectId, base_offset: u64 },
}

/// The outcome of [`resolve_fault`](AddressSpace::resolve_fault).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultOutcome {
    /// A lazy page was demand-filled (allocated, zeroed, mapped) — resume.
    Filled,
    /// A copy-on-write page was copied private and remapped writable — resume.
    Copied,
    /// A pager-backed page is not resident: the caller must forward a page
    /// request for `object` at `offset` to the pager, block the faulting
    /// thread, and resume it once the pager supplies the page (the classifier
    /// cannot block itself — it has no scheduler). Budget B10.
    NeedsPageIn { object: ObjectId, offset: u64 },
    /// A write to a **present, read-only, pager-backed** page whose mapping
    /// grants write — the software dirty-bit transition. The caller records the
    /// page dirty in the object cache (throttling the writer if the object is at
    /// its dirty bound), then [`grant_write`](AddressSpace::grant_write) before
    /// resuming (docs/kernel/03, "Dirty tracking"). Pages are supplied
    /// read-only precisely so this write faults.
    WriteToClean { object: ObjectId, offset: u64 },
    /// Not a resolvable fault (genuine protection violation, unmapped address,
    /// or resolution failed) — the caller escalates to the exception path.
    Unresolvable,
}

/// One live mapping: its virtual extent, the rights granted at map time, and
/// what backs it. `rights` is the mapping's own grant, independent of any
/// object's ownership rights.
#[derive(Clone, Copy)]
struct Mapping {
    base: u64,
    len: u64,
    rights: PageFlags,
    backing: Backing,
}

/// Bounded kernel VMAR capacity (see the module note on the missing general
/// allocator).
const MAX_MAPPINGS: usize = 64;

/// A read-only view of `rights`: read (always) plus user/execute where present,
/// with write stripped. Used to supply pager pages read-only (software dirty
/// tracking) and to strip write for a copy-on-write snapshot.
fn read_only(rights: PageFlags) -> PageFlags {
    let mut ro = PageFlags::none().read();
    if rights.is_user() {
        ro = ro.user();
    }
    if rights.executable() {
        ro = ro.execute();
    }
    ro
}

/// A virtual address space: a porting-layer page table plus the kernel's
/// mapping bookkeeping.
pub struct AddressSpace<A: AddressSpaceOps> {
    arch: A,
    asid: Asid,
    active_core_mask: AtomicU64,
    mappings: [Option<Mapping>; MAX_MAPPINGS],
    mapping_count: usize,
    mapped_bytes: u64,
}

impl<A: AddressSpaceOps> AddressSpace<A> {
    /// Wraps an already-constructed architecture space (e.g. the kernel
    /// space built at boot), recording which cores it is already active on.
    pub fn from_arch(arch: A, asid: Asid, active_core_mask: u64) -> Self {
        Self {
            arch,
            asid,
            active_core_mask: AtomicU64::new(active_core_mask),
            mappings: [None; MAX_MAPPINGS],
            mapping_count: 0,
            mapped_bytes: 0,
        }
    }

    /// Builds a fresh, empty space (a new top-level table) drawing table
    /// frames from `alloc`. Physical frames are reached at `direct_map_base`.
    pub fn new(
        alloc: &mut dyn FrameSource,
        direct_map_base: u64,
        asid: Asid,
    ) -> Result<Self, KError> {
        let arch = A::new(alloc, direct_map_base)?;
        Ok(Self::from_arch(arch, asid, 0))
    }

    pub fn asid(&self) -> Asid {
        self.asid
    }

    pub fn active_core_mask(&self) -> u64 {
        self.active_core_mask.load(Ordering::Relaxed)
    }

    /// Total bytes currently mapped in this space.
    pub fn mapped_bytes(&self) -> u64 {
        self.mapped_bytes
    }

    /// Number of live mappings.
    pub fn mapping_count(&self) -> usize {
        self.mapping_count
    }

    /// The rights granted at `virt`, if it falls in a live mapping.
    pub fn rights_at(&self, virt: VirtAddr) -> Option<PageFlags> {
        self.mapping_covering(virt).map(|m| m.rights)
    }

    /// What backs the mapping at `virt`, if any.
    pub fn backing_at(&self, virt: VirtAddr) -> Option<Backing> {
        self.mapping_covering(virt).map(|m| m.backing)
    }

    fn mapping_covering(&self, virt: VirtAddr) -> Option<&Mapping> {
        let v = virt.as_u64();
        self.live().find(|m| v >= m.base && v < m.base + m.len)
    }

    /// Borrows the underlying architecture space (for activation sequencing
    /// by the boot/scheduler code).
    pub fn arch(&self) -> &A {
        &self.arch
    }

    /// Mutable access to the architecture space beneath this one.
    ///
    /// For the architecture-conformance battery, which tests the *porting
    /// layer* and so must reach it directly. Mapping through here bypasses
    /// this type's mapping table and rights bookkeeping, so a caller must
    /// confine itself to addresses this space does not manage and must undo
    /// whatever it changes. Ordinary mapping goes through `map_anonymous` and
    /// friends, which keep the bookkeeping honest.
    pub fn arch_mut(&mut self) -> &mut A {
        &mut self.arch
    }

    /// Installs this space as active on core `core_id` and records it in the
    /// active-core mask.
    ///
    /// # Safety
    ///
    /// This space must map the code, stack, and data the calling core is
    /// executing on, at their current virtual addresses.
    pub unsafe fn activate(&self, core_id: u32) {
        self.active_core_mask
            .fetch_or(1u64 << core_id, Ordering::Relaxed);
        // SAFETY: forwarded to the caller's contract that this space maps the
        // running execution context; loading the page-table base then cannot
        // fault.
        unsafe { self.arch.activate() }
    }

    /// Maps `[base, base + len)` as anonymous zero-filled memory with
    /// `rights`. `base` must be page-aligned and `len` a nonzero multiple of
    /// the frame size. On any failure the space is left unchanged (partial
    /// work is rolled back). Frames are drawn from `alloc`.
    pub fn map_anonymous(
        &mut self,
        base: VirtAddr,
        len: u64,
        rights: PageFlags,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        if !base.is_aligned(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        if len == 0 || !len.is_multiple_of(FRAME_SIZE) {
            return Err(KError::InvalidMapping);
        }
        if rights.is_wx() {
            return Err(KError::WXViolation);
        }
        if self.overlaps(base.as_u64(), len) {
            return Err(KError::AlreadyMapped);
        }
        if self.mapping_count >= MAX_MAPPINGS {
            return Err(KError::OutOfMemory);
        }

        let pages = len / FRAME_SIZE;
        let mut done = 0u64;
        while done < pages {
            let va = VirtAddr::new(base.as_u64() + done * FRAME_SIZE);
            let frame = match alloc.alloc_frame() {
                Some(frame) => frame,
                None => {
                    self.rollback(base, done);
                    return Err(KError::OutOfMemory);
                }
            };
            self.arch.zero_frame(frame);
            if let Err(err) = self.arch.map(va, frame, rights, alloc) {
                // The just-allocated frame is unreachable (the bump
                // allocator has no free path); undo the prior maps so the
                // space is unchanged.
                self.rollback(base, done);
                return Err(err);
            }
            done += 1;
        }

        self.record(base.as_u64(), len, rights, Backing::Anonymous);
        self.mapped_bytes += len;
        Ok(())
    }

    /// Maps `frames` — pages a memory object already owns — into this space at
    /// `base`, taking one reference to each.
    ///
    /// The out-of-line buffer primitive (`docs/kernel/02`, "Memory Objects";
    /// build/README.md D131). Four things it deliberately does **not** do that
    /// [`Self::map_anonymous`] does, each of which would be a bug here:
    ///
    /// 1. **It does not allocate.** The frames belong to the object; this only
    ///    takes a reference to each, so the last mapping to go is what returns
    ///    them.
    /// 2. **It does not zero.** The whole point is that the other holder's
    ///    bytes are visible. Zeroing would erase the payload being handed over.
    /// 3. **It checks the mapping table before touching anything.** `record`
    ///    silently does nothing when full and does not raise `mapping_count`,
    ///    so a mapping installed past the bound would exist in the page tables
    ///    with no record: invisible to `teardown`, unrevocable, and its frames
    ///    leaked for the life of the machine.
    /// 4. **Its rollback frees what it retained.** `map_anonymous`'s rollback
    ///    only unmaps, because a bump-allocated frame it just drew has nowhere
    ///    to go back to. Here every page retained is a reference that must be
    ///    dropped, or a partial failure strands one per page.
    pub fn map_shared(
        &mut self,
        base: VirtAddr,
        rights: PageFlags,
        object: ObjectId,
        base_offset: u64,
        frames: &[PhysFrame],
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        if !base.is_aligned(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        if frames.is_empty() {
            return Err(KError::InvalidMapping);
        }
        if rights.is_wx() {
            return Err(KError::WXViolation);
        }
        let len = frames.len() as u64 * FRAME_SIZE;
        let end = base
            .as_u64()
            .checked_add(len)
            .ok_or(KError::InvalidMapping)?;
        let _ = end;
        if self.overlaps(base.as_u64(), len) {
            return Err(KError::AlreadyMapped);
        }
        // Before anything is mapped or retained — see the note above.
        if self.mapping_count >= MAX_MAPPINGS {
            return Err(KError::OutOfMemory);
        }

        for (page, frame) in frames.iter().enumerate() {
            let va = VirtAddr::new(base.as_u64() + page as u64 * FRAME_SIZE);
            alloc.retain_frame(*frame);
            if let Err(err) = self.arch.map(va, *frame, rights, alloc) {
                // Undo this page's retain and every earlier one. `arch.map`
                // draws intermediate table frames from `alloc`, so failing
                // part-way through is a real path rather than a theoretical
                // one.
                alloc.free_frame(*frame);
                self.unmap_and_release(base, page as u64, frames, alloc);
                return Err(err);
            }
        }

        self.record(
            base.as_u64(),
            len,
            rights,
            Backing::Shared {
                object,
                base_offset,
            },
        );
        self.mapped_bytes += len;
        Ok(())
    }

    /// Unmaps the first `pages` of a shared mapping and drops the reference
    /// each held — the rollback half of [`Self::map_shared`].
    fn unmap_and_release(
        &mut self,
        base: VirtAddr,
        pages: u64,
        frames: &[PhysFrame],
        alloc: &mut dyn FrameSource,
    ) {
        for page in 0..pages {
            let va = VirtAddr::new(base.as_u64() + page * FRAME_SIZE);
            // The page was mapped a moment ago, so a failure here cannot be
            // acted on; the reference is dropped either way, because the
            // retain happened before the map.
            let _ = self.arch.unmap(va);
            if let Some(frame) = frames.get(page as usize) {
                alloc.free_frame(*frame);
            }
        }
    }

    /// Maps one physical device page at `va` as user-accessible Device memory
    /// (the MapDevice syscall's mapping primitive, D79). Deliberately
    /// **untracked**: no `Mapping` entry is recorded, so `teardown` frees the
    /// space's table frames but never this device physical page (the kernel
    /// does not own it), and `validate_user_range` never accepts the range for
    /// a kernel copy (device registers are read by the ring-3 driver's own
    /// loads, never by the kernel on its behalf). Tracked `Backing::Device`
    /// bookkeeping stays deferred (build/README.md, D77 → D79).
    pub fn map_device_page(
        &mut self,
        va: VirtAddr,
        frame: PhysFrame,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        self.arch
            .map(va, frame, PageFlags::rw().user().device(), alloc)
    }

    /// Maps a device's whole register window: `pages` consecutive physical
    /// device pages from `first`, at `va` onwards.
    ///
    /// A window is not a page. A virtio-mmio slot is 0x200 bytes and fits in
    /// one, but a PCI BAR routinely does not — QEMU's virtio-blk-pci keeps its
    /// configuration structures across four — and a driver handed only the
    /// first page of its own device can reach a quarter of it.
    ///
    /// **Rolls back to nothing on partial failure.** A half-installed window is
    /// worse than none: the caller sees an error and reasonably assumes it has
    /// no mapping, while some pages are live and the window record does not
    /// describe them. Unlike [`Self::map_anonymous`]'s rollback this frees
    /// nothing, and that is the point — every frame here names MMIO, and
    /// handing one to the allocator would put device registers in the pool the
    /// kernel serves anonymous memory from.
    pub fn map_device_range(
        &mut self,
        va: VirtAddr,
        first: PhysFrame,
        pages: u64,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        for page in 0..pages {
            let at = VirtAddr::new(va.as_u64() + page * FRAME_SIZE);
            let Some(frame) =
                PhysFrame::from_base(PhysAddr::new(first.base().as_u64() + page * FRAME_SIZE))
            else {
                self.unmap_device_pages(va, page);
                return Err(KError::Unaligned);
            };
            if let Err(e) = self.map_device_page(at, frame, alloc) {
                self.unmap_device_pages(va, page);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Takes down `pages` device pages from `va`, best-effort.
    ///
    /// Best-effort because both callers are already committed: a rollback has
    /// an error to report that matters more, and a revocation must remove what
    /// it can rather than stop at the first page that was not there. A page
    /// that is missing is a page that is not reachable, which is the outcome
    /// wanted either way.
    pub fn unmap_device_pages(&mut self, va: VirtAddr, pages: u64) {
        for page in 0..pages {
            let _ = self.unmap_device_page(VirtAddr::new(va.as_u64() + page * FRAME_SIZE));
        }
    }

    /// Removes a device register window previously installed by
    /// [`map_device_page`](Self::map_device_page).
    ///
    /// The frame the unmap hands back is **deliberately discarded**. It names
    /// MMIO, not RAM: it was never drawn from the frame allocator and handing
    /// it there would put a device's registers into the pool the kernel serves
    /// anonymous memory from, which is about the worst outcome available. That
    /// asymmetry is why this is its own operation rather than a caller of the
    /// ordinary unmap path — the usual rule is "unmap returns the frame so the
    /// caller can reclaim it", and here the correct reclaim is none.
    ///
    /// Returns [`KError::NotMapped`] if nothing is mapped at `va`.
    pub fn unmap_device_page(&mut self, va: VirtAddr) -> Result<(), KError> {
        self.arch.unmap(va).map(|_frame| ())
    }

    /// Reserves `[base, base + len)` as **lazily** anonymous memory: the mapping
    /// is recorded but no page is populated. Each page is zero-filled and mapped
    /// on the first access that faults on it, through
    /// [`resolve_fault`](Self::resolve_fault) (budget B8). Same validation as
    /// [`map_anonymous`](Self::map_anonymous); no frames are drawn until a fault.
    pub fn map_anonymous_demand(
        &mut self,
        base: VirtAddr,
        len: u64,
        rights: PageFlags,
    ) -> Result<(), KError> {
        if !base.is_aligned(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        if len == 0 || !len.is_multiple_of(FRAME_SIZE) {
            return Err(KError::InvalidMapping);
        }
        if rights.is_wx() {
            return Err(KError::WXViolation);
        }
        if self.overlaps(base.as_u64(), len) {
            return Err(KError::AlreadyMapped);
        }
        if self.mapping_count >= MAX_MAPPINGS {
            return Err(KError::OutOfMemory);
        }
        self.record(base.as_u64(), len, rights, Backing::AnonymousDemand);
        Ok(())
    }

    /// Maps `[base, base + len)` as **pager-backed** memory: the mapping is
    /// recorded against memory object `object` (starting at `base_offset` within
    /// it) and populates nothing. A fault on a non-resident page returns
    /// [`FaultOutcome::NeedsPageIn`] so the caller forwards a page request to the
    /// pager, which supplies the page via [`supply_page`](Self::supply_page)
    /// (budget B10). Same validation as [`map_anonymous`](Self::map_anonymous).
    pub fn map_object(
        &mut self,
        base: VirtAddr,
        len: u64,
        rights: PageFlags,
        object: ObjectId,
        base_offset: u64,
    ) -> Result<(), KError> {
        if !base.is_aligned(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        if len == 0 || !len.is_multiple_of(FRAME_SIZE) {
            return Err(KError::InvalidMapping);
        }
        if rights.is_wx() {
            return Err(KError::WXViolation);
        }
        if self.overlaps(base.as_u64(), len) {
            return Err(KError::AlreadyMapped);
        }
        if self.mapping_count >= MAX_MAPPINGS {
            return Err(KError::OutOfMemory);
        }
        self.record(
            base.as_u64(),
            len,
            rights,
            Backing::Object {
                object,
                base_offset,
            },
        );
        Ok(())
    }

    /// Installs a **pager-supplied** frame at `va` with the covering mapping's
    /// rights — the kernel side of a `supply` (docs/kernel/03, "Page-In Flow"
    /// step 4). The frame is provided already filled by the pager (no zero-fill,
    /// an ownership transfer, not a copy). `NotMapped` if `va` is not in a live
    /// mapping.
    pub fn supply_page(
        &mut self,
        va: VirtAddr,
        frame: PhysFrame,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        let page = VirtAddr::new(va.as_u64() & !(FRAME_SIZE - 1));
        let rights = match self.mapping_covering(va) {
            Some(mapping) => mapping.rights,
            None => return Err(KError::NotMapped),
        };
        // Supplied read-only even for a writable mapping: the first write then
        // faults, which is how the kernel tracks the page dirty in software
        // (docs/kernel/03, "Dirty tracking"; the flip is `grant_write`).
        self.arch.map(page, frame, read_only(rights), alloc)?;
        self.mapped_bytes += FRAME_SIZE;
        Ok(())
    }

    /// Grants write to a present pager-backed page after its clean→dirty write
    /// fault ([`WriteToClean`](FaultOutcome::WriteToClean)); the mapping's own
    /// rights (which include write) are restored so the write can complete.
    pub fn grant_write(&mut self, va: VirtAddr) -> Result<(), KError> {
        let page = VirtAddr::new(va.as_u64() & !(FRAME_SIZE - 1));
        let rights = self
            .mapping_covering(va)
            .map(|m| m.rights)
            .ok_or(KError::NotMapped)?;
        self.arch.protect(page, rights)
    }

    /// Re-protects a page read-only — used after a write-back so the snapshot
    /// stays stable and the next write re-faults to re-dirty it.
    pub fn reprotect_ro(&mut self, va: VirtAddr) -> Result<(), KError> {
        let page = VirtAddr::new(va.as_u64() & !(FRAME_SIZE - 1));
        let rights = self
            .mapping_covering(va)
            .map(|m| m.rights)
            .ok_or(KError::NotMapped)?;
        self.arch.protect(page, read_only(rights))
    }

    /// Evicts a resident page: unmaps it and frees its frame, reverting it to
    /// non-resident so the next access re-faults through the page-in path
    /// (docs/kernel/03, "Write-Back And Eviction Flow" — clean-page reclaim).
    /// The caller must only evict a clean page (a dirty one is written back
    /// first).
    pub fn evict_page(&mut self, va: VirtAddr, alloc: &mut dyn FrameSource) -> Result<(), KError> {
        let page = VirtAddr::new(va.as_u64() & !(FRAME_SIZE - 1));
        let (frame, _) = self.arch.translate(page).ok_or(KError::NotMapped)?;
        self.arch.unmap(page)?;
        alloc.free_frame(frame);
        self.mapped_bytes = self.mapped_bytes.saturating_sub(FRAME_SIZE);
        Ok(())
    }

    /// Attempts to repair the fault at `virt` (a `write` or read access) by
    /// consulting the covering mapping — the resolvable half of the fault
    /// taxonomy (docs/kernel/03). A lazy anonymous page not yet present is
    /// **demand-filled**; a present read-only copy-on-write page under a write
    /// is **copied** private. Anything else is [`Unresolvable`](FaultOutcome).
    /// On success the caller resumes the faulting instruction.
    pub fn resolve_fault(
        &mut self,
        virt: VirtAddr,
        write: bool,
        alloc: &mut dyn FrameSource,
    ) -> FaultOutcome {
        let page = VirtAddr::new(virt.as_u64() & !(FRAME_SIZE - 1));
        let (backing, rights, mapping_base) = match self.mapping_covering(virt) {
            Some(mapping) => (mapping.backing, mapping.rights, mapping.base),
            None => return FaultOutcome::Unresolvable,
        };
        match backing {
            Backing::AnonymousDemand => {
                // A lazy page faults because it is not present; a fault on an
                // already-present page here is a genuine protection violation.
                if self.arch.translate(page).is_some() {
                    return FaultOutcome::Unresolvable;
                }
                self.demand_fill(page, rights, alloc)
            }
            Backing::Cow if write => self.cow_copy(page, rights, alloc),
            Backing::Object {
                object,
                base_offset,
            } => {
                let offset = (page.as_u64() - mapping_base) + base_offset;
                match self.arch.translate(page) {
                    // Not resident → page it in.
                    None => FaultOutcome::NeedsPageIn { object, offset },
                    // Present but read-only, written, and the mapping grants
                    // write: the software dirty-bit transition (pages are
                    // supplied read-only for exactly this). Anything else on a
                    // present page (a read fault, or an already-writable page)
                    // is a genuine violation.
                    Some((_frame, flags)) if write && !flags.writable() && rights.writable() => {
                        FaultOutcome::WriteToClean { object, offset }
                    }
                    Some(_) => FaultOutcome::Unresolvable,
                }
            }
            // A shared mapping is fully resident from the moment it exists, so
            // a fault on one means the record and the page tables have
            // drifted — not something to resolve.
            Backing::Cow | Backing::Anonymous | Backing::Shared { .. } => {
                FaultOutcome::Unresolvable
            }
        }
    }

    /// Demand-fills one lazy page: allocate, zero, map with the mapping's rights.
    fn demand_fill(
        &mut self,
        page: VirtAddr,
        rights: PageFlags,
        alloc: &mut dyn FrameSource,
    ) -> FaultOutcome {
        let Some(frame) = alloc.alloc_frame() else {
            return FaultOutcome::Unresolvable;
        };
        self.arch.zero_frame(frame);
        if self.arch.map(page, frame, rights, alloc).is_err() {
            alloc.free_frame(frame);
            return FaultOutcome::Unresolvable;
        }
        self.mapped_bytes += FRAME_SIZE;
        FaultOutcome::Filled
    }

    /// Copies one shared copy-on-write page private on a write fault: allocate a
    /// fresh frame, copy the shared page into it, remap the fault page to the
    /// private frame with the mapping's (writable) rights, and release this
    /// space's reference to the shared frame (freed if it was the last).
    fn cow_copy(
        &mut self,
        page: VirtAddr,
        rights: PageFlags,
        alloc: &mut dyn FrameSource,
    ) -> FaultOutcome {
        let Some((shared, flags)) = self.arch.translate(page) else {
            return FaultOutcome::Unresolvable;
        };
        // A write fault on an already-writable page is not a COW fault.
        if flags.writable() {
            return FaultOutcome::Unresolvable;
        }
        let Some(private) = alloc.alloc_frame() else {
            return FaultOutcome::Unresolvable;
        };
        self.arch.copy_frame(private, shared);
        if self.arch.unmap(page).is_err() || self.arch.map(page, private, rights, alloc).is_err() {
            alloc.free_frame(private);
            return FaultOutcome::Unresolvable;
        }
        alloc.free_frame(shared);
        FaultOutcome::Copied
    }

    /// Creates a **copy-on-write snapshot** of the resident region
    /// `[src_base, src_base + len)` at `dst_base`: both ranges then share the
    /// same physical frames read-only (one extra reference per frame), and both
    /// become [`Cow`](Backing::Cow), so a write through *either* faults and
    /// copies its page private (budget B9). The source region must be an exact,
    /// fully-resident mapping; `dst_base` must be free. The recorded rights stay
    /// the source's (writable) rights, so a copy remaps writable.
    pub fn snapshot_cow(
        &mut self,
        src_base: VirtAddr,
        dst_base: VirtAddr,
        len: u64,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        if !src_base.is_aligned(FRAME_SIZE) || !dst_base.is_aligned(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        if len == 0 || !len.is_multiple_of(FRAME_SIZE) {
            return Err(KError::InvalidMapping);
        }
        let src_idx = self
            .find_exact(src_base.as_u64(), len)
            .ok_or(KError::NotMapped)?;
        if self.overlaps(dst_base.as_u64(), len) {
            return Err(KError::AlreadyMapped);
        }
        if self.mapping_count >= MAX_MAPPINGS {
            return Err(KError::OutOfMemory);
        }
        let rights = match &self.mappings[src_idx] {
            Some(mapping) => mapping.rights,
            None => return Err(KError::NotMapped),
        };
        // Read-only view of the source rights (strip write; keep user/execute).
        let ro = read_only(rights);

        let pages = len / FRAME_SIZE;
        for i in 0..pages {
            let src_page = VirtAddr::new(src_base.as_u64() + i * FRAME_SIZE);
            let dst_page = VirtAddr::new(dst_base.as_u64() + i * FRAME_SIZE);
            let (frame, _) = self.arch.translate(src_page).ok_or(KError::NotMapped)?;
            alloc.retain_frame(frame);
            // Source becomes read-only so its own writes fault and copy too; the
            // snapshot shares the same frame read-only.
            self.arch.protect(src_page, ro)?;
            self.arch.map(dst_page, frame, ro, alloc)?;
        }
        if let Some(mapping) = self.mappings[src_idx].as_mut() {
            mapping.backing = Backing::Cow;
        }
        self.record(dst_base.as_u64(), len, rights, Backing::Cow);
        self.mapped_bytes += len;
        Ok(())
    }

    /// Unmaps a range previously mapped as one anonymous region (exact base
    /// and length). Backing frames are not reclaimed this milestone (the
    /// bump allocator has no free path).
    pub fn unmap_range(&mut self, base: VirtAddr, len: u64) -> Result<(), KError> {
        let idx = self
            .find_exact(base.as_u64(), len)
            .ok_or(KError::NotMapped)?;
        let pages = len / FRAME_SIZE;
        for i in 0..pages {
            let va = VirtAddr::new(base.as_u64() + i * FRAME_SIZE);
            self.arch.unmap(va)?;
        }
        self.mappings[idx] = None;
        self.mapping_count -= 1;
        self.mapped_bytes -= len;
        Ok(())
    }

    /// Deterministic whole-space reclaim (docs/kernel/05): unmaps every live
    /// mapping and frees each *resident* backing frame to `alloc` — the
    /// [`evict_page`](Self::evict_page) mechanism applied to the whole space —
    /// then frees the page-table frames this space owns via
    /// [`free_tables`](AddressSpaceOps::free_tables). After this the space holds
    /// no mappings and **must not be reused**; it is the address-space half of
    /// process teardown. Non-resident lazy/pager pages (recorded but never
    /// faulted in) have no frame to free and are simply dropped from the table.
    pub fn teardown(&mut self, alloc: &mut dyn FrameSource) {
        for slot in self.mappings.iter_mut() {
            let Some(mapping) = slot.take() else { continue };
            let pages = mapping.len / FRAME_SIZE;
            for i in 0..pages {
                let va = VirtAddr::new(mapping.base + i * FRAME_SIZE);
                // A resident page returns its frame to free; a never-faulted
                // lazy/pager page returns NotMapped and is skipped.
                if let Ok(frame) = self.arch.unmap(va) {
                    alloc.free_frame(frame);
                    self.mapped_bytes = self.mapped_bytes.saturating_sub(FRAME_SIZE);
                }
            }
            self.mapping_count -= 1;
        }
        self.arch.free_tables(alloc);
    }

    /// Reclaims one exact anonymous region in a **shared** space (e.g. a child
    /// thread's kernel stack living in the kernel VMAR, which whole-space
    /// `teardown` must not touch): unmaps `[base, base + len)` and frees each
    /// resident frame to `alloc` — like [`unmap_range`](Self::unmap_range) but
    /// it *does* free. `base`/`len` must name an exact live mapping, else
    /// `NotMapped`.
    pub fn reclaim_range(
        &mut self,
        base: VirtAddr,
        len: u64,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        let idx = self
            .find_exact(base.as_u64(), len)
            .ok_or(KError::NotMapped)?;
        let pages = len / FRAME_SIZE;
        for i in 0..pages {
            let va = VirtAddr::new(base.as_u64() + i * FRAME_SIZE);
            if let Ok(frame) = self.arch.unmap(va) {
                alloc.free_frame(frame);
                self.mapped_bytes = self.mapped_bytes.saturating_sub(FRAME_SIZE);
            }
        }
        self.mappings[idx] = None;
        self.mapping_count -= 1;
        Ok(())
    }

    /// Changes the rights of an existing anonymous region (exact base and
    /// length), rejecting a writable+executable result.
    pub fn protect_range(
        &mut self,
        base: VirtAddr,
        len: u64,
        rights: PageFlags,
    ) -> Result<(), KError> {
        if rights.is_wx() {
            return Err(KError::WXViolation);
        }
        let idx = self
            .find_exact(base.as_u64(), len)
            .ok_or(KError::NotMapped)?;
        let pages = len / FRAME_SIZE;
        for i in 0..pages {
            let va = VirtAddr::new(base.as_u64() + i * FRAME_SIZE);
            self.arch.protect(va, rights)?;
        }
        if let Some(mapping) = self.mappings[idx].as_mut() {
            mapping.rights = rights;
        }
        Ok(())
    }

    /// Copies `src` into this space starting at page-aligned `dst`, writing
    /// through the port's direct physical map — so a user-space loader can
    /// populate a **not-yet-active** child address space without switching CR3
    /// (the `AddressSpaceMap` loader operation, docs/api/01, D44). Each covered
    /// page must already be mapped and present (e.g. by a prior
    /// [`map_anonymous`](Self::map_anonymous)); a hole returns
    /// [`KError::NotMapped`] and the copy stops there. Bytes beyond `src` are
    /// left as they were (zero, from `map_anonymous`).
    pub fn copy_in(&self, dst: VirtAddr, src: &[u8]) -> Result<(), KError> {
        if !dst.is_aligned(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        let mut written = 0usize;
        while written < src.len() {
            let va = VirtAddr::new(dst.as_u64() + written as u64);
            let (frame, _) = self.arch.translate(va).ok_or(KError::NotMapped)?;
            let chunk = core::cmp::min(src.len() - written, FRAME_SIZE as usize);
            self.arch
                .write_bytes_to_frame(frame, 0, &src[written..written + chunk]);
            written += chunk;
        }
        Ok(())
    }

    fn live(&self) -> impl Iterator<Item = &Mapping> {
        self.mappings.iter().flatten()
    }

    fn overlaps(&self, base: u64, len: u64) -> bool {
        let end = base + len;
        self.live().any(|m| base < m.base + m.len && m.base < end)
    }

    fn find_exact(&self, base: u64, len: u64) -> Option<usize> {
        self.mappings
            .iter()
            .position(|slot| matches!(slot, Some(m) if m.base == base && m.len == len))
    }

    fn record(&mut self, base: u64, len: u64, rights: PageFlags, backing: Backing) {
        for slot in self.mappings.iter_mut() {
            if slot.is_none() {
                *slot = Some(Mapping {
                    base,
                    len,
                    rights,
                    backing,
                });
                self.mapping_count += 1;
                return;
            }
        }
    }

    fn rollback(&mut self, base: VirtAddr, pages_done: u64) {
        for i in 0..pages_done {
            let va = VirtAddr::new(base.as_u64() + i * FRAME_SIZE);
            // Best-effort: the pages were just mapped, so unmap cannot fail
            // for a reason we can act on here.
            let _ = self.arch.unmap(va);
        }
    }
}

#[cfg(test)]
#[path = "tests/vm.rs"]
mod tests;
