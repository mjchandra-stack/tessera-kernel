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
    AddressSpaceOps, FRAME_SIZE, FrameSource, KError, PageFlags, PhysFrame, VirtAddr,
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
            Backing::Cow | Backing::Anonymous => FaultOutcome::Unresolvable,
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
mod tests {
    use super::*;
    use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

    const BASE: u64 = 0xffff_c000_0000_0000;

    fn space() -> AddressSpace<MockAddressSpace> {
        let mut frames = MockFrameSource::new(0x10_0000, 1024);
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
            .expect("empty space")
    }

    #[test]
    fn maps_and_records_rights_then_unmaps() {
        let mut frames = MockFrameSource::new(0x20_0000, 1024);
        let mut vm = space();
        let rights = PageFlags::rw();
        vm.map_anonymous(VirtAddr::new(BASE), 2 * FRAME_SIZE, rights, &mut frames)
            .expect("map");
        assert_eq!(vm.mapping_count(), 1);
        assert_eq!(vm.mapped_bytes(), 2 * FRAME_SIZE);
        // Rights and backing are recorded and readable inside the range.
        assert_eq!(vm.rights_at(VirtAddr::new(BASE + FRAME_SIZE)), Some(rights));
        assert_eq!(
            vm.backing_at(VirtAddr::new(BASE + FRAME_SIZE)),
            Some(Backing::Anonymous)
        );
        vm.unmap_range(VirtAddr::new(BASE), 2 * FRAME_SIZE)
            .expect("unmap");
        assert_eq!(vm.mapping_count(), 0);
        assert_eq!(vm.mapped_bytes(), 0);
        assert_eq!(vm.rights_at(VirtAddr::new(BASE)), None);
    }

    #[test]
    fn map_device_page_is_untracked() {
        let mut frames = MockFrameSource::new(0x20_0000, 1024);
        let mut vm = space();
        let device = PhysFrame::from_base(tessera_karch::PhysAddr::new(0x0a00_0000))
            .expect("aligned device page");
        vm.map_device_page(VirtAddr::new(BASE), device, &mut frames)
            .expect("map device page");
        // The arch mapping exists, but the wrapper records nothing: rights_at
        // consults only the tracked table, and teardown will not touch the
        // device physical page.
        assert!(vm.arch().translate(VirtAddr::new(BASE)).is_some());
        assert_eq!(vm.rights_at(VirtAddr::new(BASE)), None);
        assert_eq!(vm.mapping_count(), 0);
        assert_eq!(vm.mapped_bytes(), 0);
    }

    #[test]
    fn copy_in_walks_mapped_pages_and_rejects_holes() {
        let mut frames = MockFrameSource::new(0x20_0000, 1024);
        let mut vm = space();
        // Two mapped pages the loader will populate.
        vm.map_anonymous(
            VirtAddr::new(BASE),
            2 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames,
        )
        .expect("map");
        // A source spanning a page boundary walks both frames (mock write is a
        // no-op; this exercises the translate/offset/chunk plumbing).
        let src = [0xabu8; FRAME_SIZE as usize + 16];
        assert_eq!(vm.copy_in(VirtAddr::new(BASE), &src), Ok(()));
        // A short source in the first page succeeds.
        assert_eq!(vm.copy_in(VirtAddr::new(BASE), &[1, 2, 3]), Ok(()));
        // Unaligned destination is rejected before any write.
        assert_eq!(
            vm.copy_in(VirtAddr::new(BASE + 1), &[0u8]),
            Err(KError::Unaligned)
        );
        // A source that runs off the end of the mapped region hits an unmapped
        // page and reports it.
        let over = [0u8; 3 * FRAME_SIZE as usize];
        assert_eq!(
            vm.copy_in(VirtAddr::new(BASE), &over),
            Err(KError::NotMapped)
        );
        // Empty source is a no-op success.
        assert_eq!(vm.copy_in(VirtAddr::new(BASE), &[]), Ok(()));
    }

    #[test]
    fn lazy_anon_demand_fills_page_by_page() {
        let mut frames = MockFrameSource::new(0x20_0000, 1024);
        let mut vm = space();
        let rights = PageFlags::rw().user();
        vm.map_anonymous_demand(VirtAddr::new(BASE), 2 * FRAME_SIZE, rights)
            .expect("reserve");
        // Recorded lazily: no page is present and nothing is resident yet.
        assert_eq!(vm.mapping_count(), 1);
        assert_eq!(vm.mapped_bytes(), 0);
        assert!(vm.arch().flags_at(VirtAddr::new(BASE)).is_none());
        assert_eq!(
            vm.backing_at(VirtAddr::new(BASE)),
            Some(Backing::AnonymousDemand)
        );

        // A fault anywhere in the first page demand-fills exactly that page.
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE + 0x40), true, &mut frames),
            FaultOutcome::Filled
        );
        let flags = vm
            .arch()
            .flags_at(VirtAddr::new(BASE))
            .expect("present after fill");
        assert!(flags.writable() && flags.is_user());
        assert_eq!(vm.mapped_bytes(), FRAME_SIZE);
        // The second page stays absent until its own fault.
        assert!(
            vm.arch()
                .flags_at(VirtAddr::new(BASE + FRAME_SIZE))
                .is_none()
        );
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE + FRAME_SIZE), false, &mut frames),
            FaultOutcome::Filled
        );
        assert!(
            vm.arch()
                .flags_at(VirtAddr::new(BASE + FRAME_SIZE))
                .is_some()
        );
        assert_eq!(vm.mapped_bytes(), 2 * FRAME_SIZE);
    }

    #[test]
    fn cow_snapshot_shares_then_copies_each_side_on_write() {
        let mut frames = MockFrameSource::new(0x20_0000, 1024);
        let mut vm = space();
        let rights = PageFlags::rw().user();
        const SRC: u64 = BASE;
        const DST: u64 = BASE + 0x1000_0000;
        vm.map_anonymous(VirtAddr::new(SRC), FRAME_SIZE, rights, &mut frames)
            .expect("map source");
        let orig = vm.arch().translate(VirtAddr::new(SRC)).expect("present").0;

        // Snapshot: both sides share `orig` read-only, both Cow.
        vm.snapshot_cow(
            VirtAddr::new(SRC),
            VirtAddr::new(DST),
            FRAME_SIZE,
            &mut frames,
        )
        .expect("snapshot");
        let (sf, sflags) = vm
            .arch()
            .translate(VirtAddr::new(SRC))
            .expect("src present");
        let (df, dflags) = vm
            .arch()
            .translate(VirtAddr::new(DST))
            .expect("dst present");
        assert!(!sflags.writable() && !dflags.writable(), "both read-only");
        assert_eq!(sf.base().as_u64(), orig.base().as_u64());
        assert_eq!(df.base().as_u64(), orig.base().as_u64(), "shared frame");
        assert_eq!(vm.backing_at(VirtAddr::new(SRC)), Some(Backing::Cow));
        assert_eq!(vm.backing_at(VirtAddr::new(DST)), Some(Backing::Cow));

        // Write through the source: copy private, remap writable; `orig` still
        // held by the snapshot, so it is not reclaimed yet.
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(SRC), true, &mut frames),
            FaultOutcome::Copied
        );
        let (sf2, sflags2) = vm
            .arch()
            .translate(VirtAddr::new(SRC))
            .expect("src present");
        assert!(sflags2.writable());
        assert_ne!(sf2.base().as_u64(), orig.base().as_u64(), "private copy");
        assert_eq!(
            vm.arch()
                .translate(VirtAddr::new(DST))
                .expect("dst present")
                .0
                .base()
                .as_u64(),
            orig.base().as_u64(),
            "snapshot still shares the original"
        );
        assert_eq!(frames.free_list_depth(), 0, "original still referenced");

        // Write through the snapshot: the original's last reference drops and it
        // is reclaimed to the free-list.
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(DST), true, &mut frames),
            FaultOutcome::Copied
        );
        assert!(
            vm.arch()
                .translate(VirtAddr::new(DST))
                .expect("dst present")
                .1
                .writable()
        );
        assert_eq!(
            frames.free_list_depth(),
            1,
            "original reclaimed after last sharer copied"
        );
    }

    #[test]
    fn fault_outside_any_mapping_is_unresolvable() {
        let mut frames = MockFrameSource::new(0x20_0000, 16);
        let mut vm = space();
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(0x1_0000_0000), true, &mut frames),
            FaultOutcome::Unresolvable
        );
    }

    #[test]
    fn object_backed_fault_needs_page_in_then_supply_resolves() {
        let mut frames = MockFrameSource::new(0x20_0000, 64);
        let mut vm = space();
        let object = ObjectId::from_raw(7);
        let rights = PageFlags::rw().user();
        vm.map_object(VirtAddr::new(BASE), 2 * FRAME_SIZE, rights, object, 0)
            .expect("map_object");
        assert_eq!(
            vm.backing_at(VirtAddr::new(BASE)),
            Some(Backing::Object {
                object,
                base_offset: 0
            })
        );
        // Non-resident second page → a page-in request at the right offset.
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE + FRAME_SIZE + 0x40), false, &mut frames),
            FaultOutcome::NeedsPageIn {
                object,
                offset: FRAME_SIZE
            }
        );
        // Supply the page (pager-provided frame) → resident but **read-only**
        // (software dirty tracking supplies read-only so a write faults), and a
        // read fault is now a genuine protection violation.
        let frame = frames.alloc_frame().expect("frame");
        vm.supply_page(VirtAddr::new(BASE + FRAME_SIZE), frame, &mut frames)
            .expect("supply");
        let flags = vm
            .arch()
            .translate(VirtAddr::new(BASE + FRAME_SIZE))
            .expect("resident")
            .1;
        assert!(!flags.writable() && flags.is_user(), "supplied read-only");
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE + FRAME_SIZE), false, &mut frames),
            FaultOutcome::Unresolvable
        );
    }

    #[test]
    fn writing_a_supplied_object_page_faults_write_to_clean_then_grant_write() {
        let mut frames = MockFrameSource::new(0x20_0000, 64);
        let mut vm = space();
        let object = ObjectId::from_raw(9);
        let rights = PageFlags::rw().user();
        vm.map_object(VirtAddr::new(BASE), FRAME_SIZE, rights, object, 0)
            .expect("map_object");
        let frame = frames.alloc_frame().expect("frame");
        vm.supply_page(VirtAddr::new(BASE), frame, &mut frames)
            .expect("supply");

        // A write to the read-only, present, pager-backed page is the software
        // dirty-bit transition — not a hard fault.
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE + 0x40), true, &mut frames),
            FaultOutcome::WriteToClean { object, offset: 0 }
        );
        // The kernel grants write; the page is now writable and a further write
        // no longer faults.
        vm.grant_write(VirtAddr::new(BASE)).expect("grant");
        assert!(
            vm.arch()
                .translate(VirtAddr::new(BASE))
                .expect("resident")
                .1
                .writable()
        );
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE), true, &mut frames),
            FaultOutcome::Unresolvable
        );
        // Re-protecting read-only makes the next write re-dirty (fault again).
        vm.reprotect_ro(VirtAddr::new(BASE)).expect("reprotect");
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE), true, &mut frames),
            FaultOutcome::WriteToClean { object, offset: 0 }
        );
    }

    #[test]
    fn evicting_a_supplied_page_frees_it_and_the_next_access_pages_in() {
        let mut frames = MockFrameSource::new(0x20_0000, 64);
        let mut vm = space();
        let object = ObjectId::from_raw(11);
        vm.map_object(
            VirtAddr::new(BASE),
            FRAME_SIZE,
            PageFlags::rw().user(),
            object,
            0,
        )
        .expect("map_object");
        let frame = frames.alloc_frame().expect("frame");
        vm.supply_page(VirtAddr::new(BASE), frame, &mut frames)
            .expect("supply");
        assert_eq!(vm.mapped_bytes(), FRAME_SIZE);
        let before = frames.free_list_depth();

        vm.evict_page(VirtAddr::new(BASE), &mut frames)
            .expect("evict");
        // The frame returned to the allocator and the mapping dropped a page.
        assert_eq!(frames.free_list_depth(), before + 1);
        assert_eq!(vm.mapped_bytes(), 0);
        assert!(vm.arch().translate(VirtAddr::new(BASE)).is_none());
        // The next access re-classifies as a page-in (non-resident again).
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE), false, &mut frames),
            FaultOutcome::NeedsPageIn { object, offset: 0 }
        );
    }

    #[test]
    fn supply_page_rejects_uncovered_address() {
        let mut frames = MockFrameSource::new(0x20_0000, 16);
        let mut vm = space();
        let frame = frames.alloc_frame().expect("frame");
        assert_eq!(
            vm.supply_page(VirtAddr::new(0x1_0000_0000), frame, &mut frames),
            Err(KError::NotMapped)
        );
    }

    #[test]
    fn fault_on_eager_anonymous_is_unresolvable() {
        // Eager pages are always present, so a fault on one is genuine.
        let mut frames = MockFrameSource::new(0x20_0000, 16);
        let mut vm = space();
        vm.map_anonymous(
            VirtAddr::new(BASE),
            FRAME_SIZE,
            PageFlags::rw().user(),
            &mut frames,
        )
        .expect("map");
        assert_eq!(
            vm.resolve_fault(VirtAddr::new(BASE), true, &mut frames),
            FaultOutcome::Unresolvable
        );
    }

    #[test]
    fn rejects_writable_executable() {
        let mut frames = MockFrameSource::new(0x20_0000, 16);
        let mut vm = space();
        let wx = PageFlags::rw().execute(); // read + write + execute
        assert!(wx.is_wx());
        assert_eq!(
            vm.map_anonymous(VirtAddr::new(BASE), FRAME_SIZE, wx, &mut frames),
            Err(KError::WXViolation)
        );
        // Nothing was mapped by the rejected request.
        assert_eq!(vm.mapping_count(), 0);
    }

    #[test]
    fn rejects_unaligned_and_bad_length() {
        let mut frames = MockFrameSource::new(0x20_0000, 16);
        let mut vm = space();
        assert_eq!(
            vm.map_anonymous(
                VirtAddr::new(BASE + 1),
                FRAME_SIZE,
                PageFlags::rw(),
                &mut frames
            ),
            Err(KError::Unaligned)
        );
        assert_eq!(
            vm.map_anonymous(
                VirtAddr::new(BASE),
                FRAME_SIZE - 1,
                PageFlags::rw(),
                &mut frames
            ),
            Err(KError::InvalidMapping)
        );
        assert_eq!(
            vm.map_anonymous(VirtAddr::new(BASE), 0, PageFlags::rw(), &mut frames),
            Err(KError::InvalidMapping)
        );
    }

    #[test]
    fn rejects_overlap() {
        let mut frames = MockFrameSource::new(0x20_0000, 64);
        let mut vm = space();
        vm.map_anonymous(
            VirtAddr::new(BASE),
            2 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames,
        )
        .expect("first map");
        // Overlapping the second page must be rejected without side effects.
        assert_eq!(
            vm.map_anonymous(
                VirtAddr::new(BASE + FRAME_SIZE),
                2 * FRAME_SIZE,
                PageFlags::rw(),
                &mut frames
            ),
            Err(KError::AlreadyMapped)
        );
        assert_eq!(vm.mapping_count(), 1);
    }

    #[test]
    fn protect_changes_recorded_rights() {
        let mut frames = MockFrameSource::new(0x20_0000, 16);
        let mut vm = space();
        vm.map_anonymous(
            VirtAddr::new(BASE),
            FRAME_SIZE,
            PageFlags::rw(),
            &mut frames,
        )
        .expect("map");
        vm.protect_range(VirtAddr::new(BASE), FRAME_SIZE, PageFlags::ro())
            .expect("protect");
        assert_eq!(vm.rights_at(VirtAddr::new(BASE)), Some(PageFlags::ro()));
    }

    #[test]
    fn out_of_frames_rolls_back() {
        // Only one frame available, but two pages requested: the first page
        // maps, the second fails, and the whole request is rolled back.
        let mut frames = MockFrameSource::new(0x20_0000, 1);
        let mut vm = space();
        assert_eq!(
            vm.map_anonymous(
                VirtAddr::new(BASE),
                2 * FRAME_SIZE,
                PageFlags::rw(),
                &mut frames
            ),
            Err(KError::OutOfMemory)
        );
        assert_eq!(vm.mapping_count(), 0);
        assert_eq!(vm.mapped_bytes(), 0);
        // The address space is clean: a later single-page map succeeds.
        let mut more = MockFrameSource::new(0x30_0000, 4);
        vm.map_anonymous(VirtAddr::new(BASE), FRAME_SIZE, PageFlags::rw(), &mut more)
            .expect("clean remap");
    }

    #[test]
    fn teardown_frees_every_leaf_and_returns_to_baseline() {
        let mut frames = MockFrameSource::new(0x20_0000, 1024);
        let mut vm = space();
        // Two eager regions (5 pages total) draw real frames; one lazy region
        // that is never faulted draws none but is recorded.
        vm.map_anonymous(
            VirtAddr::new(BASE),
            3 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames,
        )
        .expect("map A");
        vm.map_anonymous(
            VirtAddr::new(BASE + 0x1000_0000),
            2 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames,
        )
        .expect("map B");
        vm.map_anonymous_demand(
            VirtAddr::new(BASE + 0x2000_0000),
            FRAME_SIZE,
            PageFlags::rw(),
        )
        .expect("map lazy");
        let drawn = frames.handed_out();
        assert_eq!(drawn, 5, "five resident pages drawn");
        assert_eq!(vm.mapping_count(), 3);

        vm.teardown(&mut frames);

        // Every mapping is gone and every resident frame returned to the
        // free-list; the never-faulted lazy region freed nothing but cleared.
        assert_eq!(vm.mapping_count(), 0, "all mappings cleared");
        assert_eq!(vm.mapped_bytes(), 0);
        assert_eq!(frames.free_list_depth(), drawn, "all resident frames freed");
        // The freed frames are reused before any new frame is drawn.
        let mut vm2 = space();
        vm2.map_anonymous(
            VirtAddr::new(BASE),
            drawn as u64 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames,
        )
        .expect("remap reuses freed frames");
        assert_eq!(frames.handed_out(), drawn, "reuse, not fresh draws");
        assert_eq!(frames.free_list_depth(), 0);
    }

    #[test]
    fn teardown_of_cow_snapshot_reclaims_shared_frame_once() {
        let mut frames = MockFrameSource::new(0x20_0000, 1024);
        let mut vm = space();
        let rights = PageFlags::rw().user();
        const SRC: u64 = BASE;
        const DST: u64 = BASE + 0x1000_0000;
        vm.map_anonymous(VirtAddr::new(SRC), FRAME_SIZE, rights, &mut frames)
            .expect("map source");
        vm.snapshot_cow(
            VirtAddr::new(SRC),
            VirtAddr::new(DST),
            FRAME_SIZE,
            &mut frames,
        )
        .expect("snapshot");
        // One physical frame, two read-only Cow mappings sharing it (refcount 2).
        assert_eq!(frames.handed_out(), 1);
        assert_eq!(frames.free_list_depth(), 0);

        vm.teardown(&mut frames);

        // Tearing down both mappings drops both references; the frame is
        // reclaimed exactly once (not double-freed).
        assert_eq!(vm.mapping_count(), 0);
        assert_eq!(frames.free_list_depth(), 1, "shared frame reclaimed once");
    }

    #[test]
    fn reclaim_range_frees_only_that_region() {
        let mut frames = MockFrameSource::new(0x20_0000, 1024);
        let mut vm = space();
        const A: u64 = BASE;
        const B: u64 = BASE + 0x1000_0000;
        vm.map_anonymous(
            VirtAddr::new(A),
            2 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames,
        )
        .expect("map A");
        vm.map_anonymous(VirtAddr::new(B), FRAME_SIZE, PageFlags::rw(), &mut frames)
            .expect("map B");

        // A wrong base/len is not an exact live mapping.
        assert_eq!(
            vm.reclaim_range(VirtAddr::new(A), FRAME_SIZE, &mut frames),
            Err(KError::NotMapped)
        );

        vm.reclaim_range(VirtAddr::new(A), 2 * FRAME_SIZE, &mut frames)
            .expect("reclaim A");
        // A's two frames freed; B untouched and still mapped.
        assert_eq!(frames.free_list_depth(), 2, "only A's frames freed");
        assert_eq!(vm.mapping_count(), 1);
        assert_eq!(vm.rights_at(VirtAddr::new(A)), None, "A gone");
        assert_eq!(
            vm.rights_at(VirtAddr::new(B)),
            Some(PageFlags::rw()),
            "B intact"
        );
    }
}
