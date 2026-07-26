// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! AArch64 stage-1 translation for EL1: four levels, 4 KiB granule, 48-bit
//! addresses. The structural counterpart of `karch-x86_64/src/paging.rs`,
//! deliberately kept parallel to it — same type names, same helper shapes —
//! so the two ports can be read against each other.
//!
//! What differs is not the structure but the hardware:
//!
//! * **Permissions are a different shape.** x86-64 has independent
//!   writable/user/NX bits; AArch64 encodes read/write *and* privilege
//!   together in `AP[2:1]`, and splits execute-never into `PXN` (EL1) and
//!   `UXN` (EL0). That split is an improvement worth using deliberately: a
//!   user page is mapped `PXN` so the kernel can never execute user memory,
//!   which on x86-64 needs the separate SMEP feature.
//! * **Memory type is indirect.** Cacheability comes from a `MAIR_EL1`
//!   attribute index rather than from bits in the descriptor, so `PageFlags`
//!   selects an index into a table this module owns.
//! * **TLB maintenance is explicit and ordered.** x86-64 needs one `invlpg`;
//!   AArch64 needs a `dsb` before the invalidate, the `tlbi` itself, a `dsb`
//!   after, and an `isb` — the write to the table is not otherwise ordered
//!   against the walk.
//!
//! **Address-space layout: the high/low split.** The kernel runs in the high
//! half out of `TTBR1_EL1`, linked at `KERNEL_VIRT_BASE + load_phys`; a direct
//! map of all RAM sits at [`DIRECT_MAP_BASE`], also high. The low half
//! (`TTBR0_EL1`) holds the identity-mapped device range and, at low virtual
//! addresses with EL0 access, user pages. This is the architecture's own
//! split — kernel in `TTBR1`, user in `TTBR0` — which is structurally better
//! than the x86-64 port's shared-PML4 arrangement (build/README.md, D21):
//! it needs no shared half, so a per-process address space swaps only the low
//! root and the kernel half is never copied or touched. Reaching it required
//! linking the kernel high and making the pre-MMU entry path
//! position-independent: [`build_boot_tables`] installs a coarse cover, the
//! entry stub branches to the high half, and the real per-section W^X tables
//! ([`build_high_space`]/[`build_low_space`]) then replace it via
//! [`switch_tables`].
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Memory Model"),
//! docs/kernel/03-paging-faults-and-exceptions.md ("Write-XOR-Execute")
//! Budget: none in this milestone (mapping paths are budgeted per-arch)

use core::arch::asm;
use tessera_karch::{
    AddressSpaceOps, FrameSource, KError, PageFlags, PhysAddr, PhysFrame, VirtAddr,
};

/// Base of the direct physical map: physical `p` is readable at
/// `DIRECT_MAP_BASE + p`. A high-half (`TTBR1`) address: the kernel lives in
/// the high half, so its direct map does too, sitting at the top of the
/// kernel's `TTBR1` range.
pub const DIRECT_MAP_BASE: u64 = 0xffff_8000_0000_0000;

/// Low-48-bit (physical) part of a high-half kernel virtual address:
/// `virt = phys | KERNEL_VIRT_BASE`, so `phys = virt & PHYS_MASK`. The kernel
/// is linked at `KERNEL_VIRT_BASE + load_phys`, and a high VA maps to the
/// physical frame named by its low 48 bits.
pub const PHYS_MASK: u64 = 0x0000_ffff_ffff_ffff;

// Descriptor bits, shared by table, block, and page descriptors.
const VALID: u64 = 1 << 0;
/// At levels 0-2 this bit means "table"; at level 3 it means "page". A level
/// 1-2 descriptor with `VALID` but not this bit is a block.
const TABLE_OR_PAGE: u64 = 1 << 1;
const ATTR_INDX_SHIFT: u64 = 2;
const AP_SHIFT: u64 = 6;
const SH_INNER: u64 = 0b11 << 8;
const AF: u64 = 1 << 10;
const NG: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

/// Output-address field of a descriptor: bits 47:12.
const OUTPUT_MASK: u64 = 0x0000_ffff_ffff_f000;

/// `AP[2:1]` encodings. Bit 0 of the field grants EL0 access; bit 1 makes
/// the mapping read-only.
const AP_RW_EL1: u64 = 0b00;
const AP_RW_ALL: u64 = 0b01;
const AP_RO_EL1: u64 = 0b10;
const AP_RO_ALL: u64 = 0b11;

/// `MAIR_EL1` attribute indices this module defines.
const ATTR_DEVICE: u64 = 0; // Device-nGnRnE
const ATTR_NORMAL: u64 = 1; // Normal, write-back, read/write-allocate

/// `MAIR_EL1` value: attribute 0 is Device-nGnRnE (0x00), attribute 1 is
/// Normal inner/outer write-back non-transient with read and write allocate
/// (0xff).
pub const MAIR_VALUE: u64 = 0xff << 8;

/// `SCTLR_EL1` bits raised to bring the MMU up: translation, and data and
/// instruction cacheability.
pub const SCTLR_ENABLE: u64 = SCTLR_M | SCTLR_C | SCTLR_I;

/// `TCR_EL1` without the IPS field (which is read from the CPU at enable
/// time). Both halves use a 48-bit range (`T0SZ = T1SZ = 16`) and the 4 KiB
/// granule, with `TTBR1` walks enabled (`EPD1 = 0`) and `TTBR0` naming the
/// ASID (`A1 = 0`). The granule field is encoded differently per half —
/// `TG0 = 0b00`, `TG1 = 0b10` both select 4 KiB — a classic footgun this
/// constant fixes once.
pub const TCR_BASE: u64 = 16                    // T0SZ = 16 (48-bit TTBR0)
    | (0b01 << 8)                               // IRGN0: WB, RW-allocate
    | (0b01 << 10)                              // ORGN0: WB, RW-allocate
    | (0b11 << 12)                              // SH0: inner shareable
    | (0b00 << 14)                              // TG0: 4 KiB
    | (16 << 16)                                // T1SZ = 16 (48-bit TTBR1)
    | (0b01 << 24)                              // IRGN1: WB, RW-allocate
    | (0b01 << 26)                              // ORGN1: WB, RW-allocate
    | (0b11 << 28)                              // SH1: inner shareable
    | (0b10 << 30); // TG1: 4 KiB (note the encoding differs from TG0)

// Attribute words for the coarse initial page tables the entry stub installs
// to reach the high half; each is OR'd with a physical output address. They
// are deliberately expressed from the same descriptor-bit constants the real
// leaf attributes use, so the two cannot drift.

/// A table descriptor: points a level 0/1 entry at the next-level table.
pub const BOOT_TABLE_DESC: u64 = VALID | TABLE_OR_PAGE;

/// A 1 GiB Device-nGnRnE block, kernel read/write, never executable — for the
/// identity map of the device range during the transition.
pub const BOOT_DEVICE_BLOCK: u64 = VALID | AF | PXN | UXN | (ATTR_DEVICE << ATTR_INDX_SHIFT);

/// A 1 GiB Normal block, kernel read/write/execute (EL1), never executable at
/// EL0 — coarse cover for the kernel image and the boot direct map until the
/// real fine-grained W^X tables replace it.
pub const BOOT_NORMAL_BLOCK: u64 = VALID | AF | SH_INNER | (ATTR_NORMAL << ATTR_INDX_SHIFT) | UXN;

const ENTRIES: usize = 512;
const PAGE_4K: u64 = 4096;
const PAGE_2M: u64 = 2 * 1024 * 1024;

/// Level shifts for a 4 KiB granule, 48-bit walk: level 0 indexes bits
/// 47:39, level 1 bits 38:30, level 2 bits 29:21, level 3 bits 20:12.
const SHIFT_TO_L1: u32 = 39;
const SHIFT_TO_L2: u32 = 30;
const SHIFT_TO_L3: u32 = 21;
const SHIFT_PAGE: u32 = 12;

// SCTLR_EL1 bits enabled when the MMU comes up.
const SCTLR_M: u64 = 1 << 0; // MMU enable
const SCTLR_C: u64 = 1 << 2; // data cacheability
const SCTLR_I: u64 = 1 << 12; // instruction cacheability

/// One region of the kernel image and the permissions it must carry once the
/// kernel owns its page tables.
pub struct KernelSection {
    pub virt_start: u64,
    pub virt_end: u64,
    pub flags: PageFlags,
}

/// A page-table hierarchy rooted at one level-0 table frame. Table frames are
/// reached through a direct physical map at `access_base` — the identity map
/// while the tables are under construction with the MMU off, then the
/// kernel's own direct map once it is active. `set_access_base` moves it
/// across that switch.
///
/// `asid` tags this space's `TTBR0` on [`activate`](AddressSpaceOps::activate)
/// so a per-process switch flushes only this space's non-global entries, never
/// the global kernel/device ones. It is 0 for the shared boot/kernel low space.
pub struct KernelAddressSpace {
    root: PhysAddr,
    access_base: u64,
    asid: u16,
}

/// Bit position of the 8-bit ASID field in `TTBR0_EL1` (`TCR_EL1.AS = 0`).
const TTBR_ASID_SHIFT: u64 = 48;

/// Translates neutral page flags into leaf-descriptor attribute bits (the
/// type bits are added by the caller, which knows whether it is writing a
/// level-3 page or a level-2 block).
fn leaf_attributes(flags: PageFlags) -> Result<u64, KError> {
    if flags.is_wx() {
        return Err(KError::WXViolation);
    }
    if !flags.readable() {
        // AArch64's AP field has no "no access" leaf encoding; an unreadable
        // mapping is expressed by not mapping the page.
        return Err(KError::InvalidMapping);
    }
    if flags.is_device() && flags.executable() {
        // Device memory is speculation-hostile and must never be fetched
        // from. Refusing beats quietly clearing the execute bit, which would
        // hand back a mapping the caller did not ask for.
        return Err(KError::InvalidMapping);
    }

    // The access flag is set up front: leaving it clear costs an access-flag
    // fault on first touch, and nothing in this kernel uses that fault yet.
    let mut bits = AF;

    bits |= match (flags.writable(), flags.is_user()) {
        (true, false) => AP_RW_EL1,
        (true, true) => AP_RW_ALL,
        (false, false) => AP_RO_EL1,
        (false, true) => AP_RO_ALL,
    } << AP_SHIFT;

    // Execute permission is per-privilege-level here, so each mapping denies
    // execution at the level that has no business executing it: the kernel
    // can never execute a user page, and EL0 can never execute a kernel one.
    if flags.is_user() {
        bits |= PXN;
        if !flags.executable() {
            bits |= UXN;
        }
    } else {
        bits |= UXN;
        if !flags.executable() {
            bits |= PXN;
        }
    }

    if flags.is_device() {
        bits |= ATTR_DEVICE << ATTR_INDX_SHIFT;
        // Shareability is ignored for Device memory, so it is left clear.
    } else {
        bits |= (ATTR_NORMAL << ATTR_INDX_SHIFT) | SH_INNER;
    }

    // nG is the inverse of the neutral flag: AArch64 marks mappings
    // *non*-global, where the neutral request names the global ones.
    if !flags.is_global() {
        bits |= NG;
    }

    Ok(bits)
}

/// Reconstructs neutral page flags from a live leaf descriptor — the inverse
/// of [`leaf_attributes`], for reporting what a fault address maps to.
fn flags_from_leaf(entry: u64) -> PageFlags {
    let mut flags = PageFlags::none().read();
    let ap = (entry >> AP_SHIFT) & 0b11;
    let user = ap & 0b01 != 0;
    if ap & 0b10 == 0 {
        flags = flags.write();
    }
    if user {
        flags = flags.user();
    }
    // Execute is reported for the level the mapping is actually reachable
    // from, which is the one whose execute-never bit is meaningful.
    let executable = if user {
        entry & UXN == 0
    } else {
        entry & PXN == 0
    };
    if executable {
        flags = flags.execute();
    }
    if entry & NG == 0 {
        flags = flags.global();
    }
    if (entry >> ATTR_INDX_SHIFT) & 0b111 == ATTR_DEVICE {
        flags = flags.device();
    }
    flags
}

impl KernelAddressSpace {
    /// Pointer to entry `idx` of the table at physical `table_phys`, via the
    /// current access base. Computing the pointer touches no memory.
    fn entry_ptr(&self, table_phys: u64, idx: usize) -> *mut u64 {
        (self.access_base + table_phys + (idx as u64) * 8) as *mut u64
    }

    /// Redirects table access to a new direct-map base — used once, after the
    /// kernel installs its own tables, to move off the identity map used
    /// while the MMU was off and onto the kernel's direct map.
    ///
    /// # Safety
    ///
    /// `base` must be the virtual base of an active direct map covering all
    /// physical memory (i.e. the just-installed kernel tables' direct map).
    pub unsafe fn set_access_base(&mut self, base: u64) {
        self.access_base = base;
    }

    /// Assigns the ASID this space's `TTBR0` carries when
    /// [`activate`](AddressSpaceOps::activate)d, so its non-global user pages
    /// are TLB-tagged distinctly from every other space's. Distinct per live
    /// process; 0 is reserved for the shared boot/kernel low space.
    pub fn set_asid(&mut self, asid: u16) {
        self.asid = asid;
    }

    /// Wraps an already-live page-table root as an address space that *aliases*
    /// it — it neither allocates nor owns the tables. Used to hand the active
    /// kernel high-half to a kcore `AddressSpace` so a user thread's kernel
    /// stack can be mapped into the real kernel tables the EL1 vector uses.
    ///
    /// # Safety
    ///
    /// `root` must be a live level-0 table reachable at `access_base + root`,
    /// and the result must **never** be torn down
    /// ([`free_tables`](AddressSpaceOps::free_tables)) — it does not own the
    /// tables it references, and freeing them would unmap the running kernel.
    pub unsafe fn from_root(root: PhysAddr, access_base: u64) -> Self {
        Self {
            root,
            access_base,
            asid: 0,
        }
    }

    fn read_entry(&self, table_phys: u64, idx: usize) -> u64 {
        // SAFETY: `table_phys` is a live page-table frame and the direct map
        // covers all physical memory, so this is a valid aligned `u64`.
        unsafe { self.entry_ptr(table_phys, idx).read_volatile() }
    }

    fn write_entry(&self, table_phys: u64, idx: usize, value: u64) {
        // SAFETY: as `read_entry`; the target is an aligned, writable `u64`
        // in a page-table frame this address space owns.
        unsafe { self.entry_ptr(table_phys, idx).write_volatile(value) }
    }

    fn clear_frame(&self, phys: u64) {
        // SAFETY: `phys` is a caller-owned frame mapped by the direct map;
        // writing 512 aligned zero words stays inside the 4 KiB frame.
        unsafe {
            let base = self.entry_ptr(phys, 0);
            for i in 0..ENTRIES {
                base.add(i).write_volatile(0);
            }
        }
    }

    /// Descends from `self.root` through the levels named by `shifts`,
    /// allocating any missing intermediate table, and returns the physical
    /// address of the table one level below the last shift.
    fn walk_to(
        &self,
        virt: u64,
        shifts: &[u32],
        alloc: &mut dyn FrameSource,
    ) -> Result<u64, KError> {
        let mut table = self.root.as_u64();
        for &shift in shifts {
            let idx = ((virt >> shift) & 0x1ff) as usize;
            let entry = self.read_entry(table, idx);
            table = if entry & VALID != 0 {
                if entry & TABLE_OR_PAGE == 0 {
                    // A block already covers this range; descending into it
                    // would mistake its output address for a table.
                    return Err(KError::AlreadyMapped);
                }
                entry & OUTPUT_MASK
            } else {
                let frame = alloc.alloc_frame().ok_or(KError::OutOfMemory)?;
                let next = frame.base().as_u64();
                self.clear_frame(next);
                // Table descriptors carry no permissions here: the optional
                // hierarchical attributes (APTable/UXNTable/PXNTable) are
                // left clear so the leaf's own bits are solely authoritative,
                // which is the same property the x86-64 port gets by setting
                // USER on every intermediate level.
                self.write_entry(table, idx, next | VALID | TABLE_OR_PAGE);
                next
            };
        }
        Ok(table)
    }

    /// Maps a 4 KiB page. `attributes` come from [`leaf_attributes`].
    fn map_4k(
        &mut self,
        virt: u64,
        phys: u64,
        attributes: u64,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        if !virt.is_multiple_of(PAGE_4K) || !phys.is_multiple_of(PAGE_4K) {
            return Err(KError::Unaligned);
        }
        let table = self.walk_to(virt, &[SHIFT_TO_L1, SHIFT_TO_L2, SHIFT_TO_L3], alloc)?;
        let idx = ((virt >> SHIFT_PAGE) & 0x1ff) as usize;
        if self.read_entry(table, idx) & VALID != 0 {
            return Err(KError::AlreadyMapped);
        }
        self.write_entry(table, idx, phys | attributes | VALID | TABLE_OR_PAGE);
        Ok(())
    }

    /// Maps a 2 MiB block (used for the direct physical map and for device
    /// ranges). A block descriptor is `VALID` *without* the table bit.
    fn map_2m(
        &mut self,
        virt: u64,
        phys: u64,
        attributes: u64,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        if !virt.is_multiple_of(PAGE_2M) || !phys.is_multiple_of(PAGE_2M) {
            return Err(KError::Unaligned);
        }
        let table = self.walk_to(virt, &[SHIFT_TO_L1, SHIFT_TO_L2], alloc)?;
        let idx = ((virt >> SHIFT_TO_L3) & 0x1ff) as usize;
        if self.read_entry(table, idx) & VALID != 0 {
            return Err(KError::AlreadyMapped);
        }
        self.write_entry(table, idx, phys | attributes | VALID);
        Ok(())
    }

    /// Maps `[virt, virt + len)` to `[phys, phys + len)` in 2 MiB blocks.
    /// All three must be 2 MiB aligned.
    pub fn map_block_range(
        &mut self,
        virt: u64,
        phys: u64,
        len: u64,
        flags: PageFlags,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        let attributes = leaf_attributes(flags)?;
        let mut offset = 0u64;
        while offset < len {
            self.map_2m(virt + offset, phys + offset, attributes, alloc)?;
            offset += PAGE_2M;
        }
        Ok(())
    }

    /// Descends to the existing level-3 descriptor for `virt`, returning
    /// `(table_phys, index)`, or `NotMapped` if any level is absent or a
    /// block descriptor terminates the walk early.
    fn find_4k(&self, virt: u64) -> Result<(u64, usize), KError> {
        let mut table = self.root.as_u64();
        for &shift in &[SHIFT_TO_L1, SHIFT_TO_L2, SHIFT_TO_L3] {
            let idx = ((virt >> shift) & 0x1ff) as usize;
            let entry = self.read_entry(table, idx);
            if entry & VALID == 0 || entry & TABLE_OR_PAGE == 0 {
                return Err(KError::NotMapped);
            }
            table = entry & OUTPUT_MASK;
        }
        Ok((table, ((virt >> SHIFT_PAGE) & 0x1ff) as usize))
    }

    /// Recursively frees the table frame at `table_phys` and every table
    /// beneath it, `level` being this table's level (1, 2, or 3). Leaf data
    /// frames are *not* freed here — they are the caller's responsibility via
    /// `unmap` — so a level-3 table only frees itself. Frames are freed
    /// bottom-up, so the walk never touches a freed frame.
    fn free_subtree(&self, table_phys: u64, level: u32, alloc: &mut dyn FrameSource) {
        if level < 3 {
            for idx in 0..ENTRIES {
                let entry = self.read_entry(table_phys, idx);
                // Only table descriptors have children; a block has none.
                if entry & VALID != 0 && entry & TABLE_OR_PAGE != 0 {
                    self.free_subtree(entry & OUTPUT_MASK, level + 1, alloc);
                }
            }
        }
        if let Some(frame) = PhysFrame::from_base(PhysAddr::new(table_phys)) {
            alloc.free_frame(frame);
        }
    }
}

impl AddressSpaceOps for KernelAddressSpace {
    // `TTBR0_EL1` covers 48 bits, because `enable_mmu` programs
    // `TCR_EL1.T0SZ = 16`. If that ever changes, this must change with it —
    // the two are one decision stated in two places, which is the price of
    // the bound being a compile-time constant.
    const USER_ADDRESS_MAX: u64 = 0x0000_8000_0000_0000;

    fn new(alloc: &mut dyn FrameSource, direct_map_base: u64) -> Result<Self, KError> {
        let root = alloc.alloc_frame().ok_or(KError::OutOfMemory)?.base();
        let space = Self {
            root,
            access_base: direct_map_base,
            asid: 0,
        };
        space.clear_frame(root.as_u64());
        Ok(space)
    }

    fn map(
        &mut self,
        virt: VirtAddr,
        frame: PhysFrame,
        flags: PageFlags,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        let attributes = leaf_attributes(flags)?;
        self.map_4k(virt.as_u64(), frame.base().as_u64(), attributes, alloc)?;
        invalidate_page(virt.as_u64());
        Ok(())
    }

    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, KError> {
        let (table, idx) = self.find_4k(virt.as_u64())?;
        let entry = self.read_entry(table, idx);
        if entry & VALID == 0 {
            return Err(KError::NotMapped);
        }
        self.write_entry(table, idx, 0);
        invalidate_page(virt.as_u64());
        PhysFrame::from_base(PhysAddr::new(entry & OUTPUT_MASK)).ok_or(KError::InvalidMapping)
    }

    fn zero_frame(&self, frame: PhysFrame) {
        self.clear_frame(frame.base().as_u64());
    }

    fn fill_frame(&self, frame: PhysFrame, byte: u8) {
        // SAFETY: `frame` is a caller-owned frame reachable through the direct
        // map at `access_base`; writing 4 KiB stays inside the frame.
        unsafe {
            let base = (self.access_base + frame.base().as_u64()) as *mut u8;
            core::ptr::write_bytes(base, byte, PAGE_4K as usize);
        }
    }

    fn protect(&mut self, virt: VirtAddr, flags: PageFlags) -> Result<(), KError> {
        let attributes = leaf_attributes(flags)?;
        let (table, idx) = self.find_4k(virt.as_u64())?;
        let entry = self.read_entry(table, idx);
        if entry & VALID == 0 {
            return Err(KError::NotMapped);
        }
        self.write_entry(
            table,
            idx,
            (entry & OUTPUT_MASK) | attributes | VALID | TABLE_OR_PAGE,
        );
        invalidate_page(virt.as_u64());
        Ok(())
    }

    fn translate(&self, virt: VirtAddr) -> Option<(PhysFrame, PageFlags)> {
        // `find_4k` validates the intermediate levels but returns the leaf
        // slot whether or not the leaf itself is live, so check it here.
        let (table, idx) = self.find_4k(virt.as_u64()).ok()?;
        let entry = self.read_entry(table, idx);
        if entry & VALID == 0 {
            return None;
        }
        let frame = PhysFrame::from_base(PhysAddr::new(entry & OUTPUT_MASK))?;
        Some((frame, flags_from_leaf(entry)))
    }

    fn copy_frame(&self, dst: PhysFrame, src: PhysFrame) {
        // SAFETY: both frames are caller-owned and reachable through the direct
        // map at `access_base`; the copy stays within one 4 KiB frame each and
        // they do not overlap (distinct physical frames).
        unsafe {
            let src_ptr = (self.access_base + src.base().as_u64()) as *const u8;
            let dst_ptr = (self.access_base + dst.base().as_u64()) as *mut u8;
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, PAGE_4K as usize);
        }
    }

    fn write_bytes_to_frame(&self, frame: PhysFrame, offset: usize, src: &[u8]) {
        debug_assert!(offset + src.len() <= PAGE_4K as usize);
        // SAFETY: `frame` is a caller-owned frame reachable through the direct
        // map at `access_base`; the caller guarantees `offset + src.len()`
        // stays within the 4 KiB frame, so the destination range is inside the
        // frame and disjoint from `src` (a buffer in another region).
        unsafe {
            let dst = (self.access_base + frame.base().as_u64() + offset as u64) as *mut u8;
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
    }

    fn sync_instruction_cache(&self, virt: VirtAddr, len: u64) {
        // This is the operation x86-64 gets for free and this architecture
        // does not. Instructions written through a data mapping sit in the
        // data cache; the instruction fetch path does not see them until each
        // line is cleaned to the point of unification and the corresponding
        // instruction-cache line is invalidated.
        //
        // Both loops step by the *cache line size the hardware reports*
        // (CTR_EL0), not by a constant: DminLine and IminLine are independent,
        // can differ from each other, and a too-large stride would silently
        // skip lines — leaving exactly the stale-instruction bug this exists
        // to prevent, on some machines only.
        let ctr: u64;
        // SAFETY: `CTR_EL0` is a read-only cache-type register readable at
        // EL1; the read has no side effects.
        unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
        // Both fields are log2 of the line size in *words*.
        let data_line = 4u64 << ((ctr >> 16) & 0xf);
        let instruction_line = 4u64 << (ctr & 0xf);

        let start = virt.as_u64() & !(data_line - 1);
        let end = virt.as_u64() + len;

        let mut at = start;
        while at < end {
            // SAFETY: `dc cvau` cleans a data cache line by virtual address;
            // it moves no data the program can observe and faults only if the
            // address is unmapped, which the caller's range is not.
            unsafe {
                asm!("dc cvau, {addr}", addr = in(reg) at, options(nostack, preserves_flags))
            };
            at += data_line;
        }
        // The cleans must complete before any invalidate can be meaningful.
        // SAFETY: a barrier; no memory effects of its own.
        unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };

        let mut at = virt.as_u64() & !(instruction_line - 1);
        while at < end {
            // SAFETY: `ic ivau` invalidates an instruction cache line by
            // virtual address across the inner-shareable domain; it discards
            // only cached instruction state.
            unsafe {
                asm!("ic ivau, {addr}", addr = in(reg) at, options(nostack, preserves_flags))
            };
            at += instruction_line;
        }
        // Complete the invalidates, then resynchronize this core's own
        // fetch, which may already have prefetched past this point.
        // SAFETY: barriers; no memory effects of their own.
        unsafe { asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
    }

    // SAFETY: the caller guarantees this space maps the running code, the
    // active stack, and touched data at their current virtual addresses.
    // Unlike x86-64's single CR3 write, the base register change must be
    // bracketed: `dsb ish` retires outstanding table writes before the walker
    // can see the new root, and `isb` keeps instructions after this point
    // from having been fetched under the old translation.
    //
    // The root is tagged with this space's ASID (in `TTBR0`'s high bits), and
    // only that ASID's entries are invalidated (`tlbi aside1`). Global kernel
    // and device mappings (`nG = 0`, and in `TTBR1` besides) are left valid, so
    // a per-process switch neither disturbs them nor pays a full flush; the
    // ASID keeps one process's non-global user entries from matching another's.
    unsafe fn activate(&self) {
        let tagged_root = self.root.as_u64() | ((self.asid as u64) << TTBR_ASID_SHIFT);
        let asid_arg = (self.asid as u64) << TTBR_ASID_SHIFT;
        // SAFETY: per the caller contract above; `tagged_root` is this space's
        // root with its ASID in the reserved high bits, and the sequence is the
        // architecturally required base-register-change bracket.
        unsafe {
            asm!(
                "dsb ish",
                "msr ttbr0_el1, {root}",
                "isb",
                "tlbi aside1, {asid}",
                "dsb nsh",
                "isb",
                root = in(reg) tagged_root,
                asid = in(reg) asid_arg,
                options(nostack, preserves_flags),
            );
        }
    }

    fn root_phys(&self) -> PhysAddr {
        self.root
    }

    fn free_tables(&mut self, alloc: &mut dyn FrameSource) {
        // Every table under this root belongs to this space, and with the
        // high/low split each root is a single half — the high-half kernel
        // root and each low-half root are disjoint, sharing no table — so
        // freeing a root's subtrees frees only that half. This is exactly why
        // the split is the better arrangement: the kernel half is never a
        // shared sub-tree that a per-process teardown must avoid.
        for idx in 0..ENTRIES {
            let entry = self.read_entry(self.root.as_u64(), idx);
            if entry & VALID != 0 && entry & TABLE_OR_PAGE != 0 {
                self.free_subtree(entry & OUTPUT_MASK, 1, alloc);
            }
        }
        if let Some(root) = PhysFrame::from_base(self.root) {
            alloc.free_frame(root);
        }
    }
}

/// Invalidates one page's TLB entries across the inner-shareable domain.
///
/// The barriers are load-bearing, and are the part with no x86-64 analogue: a
/// descriptor write is an ordinary store, so without the leading `dsb ishst`
/// the invalidate can be observed before the store it is meant to publish;
/// without the trailing `dsb ish` the invalidate may not have completed when
/// the next access translates; and without the `isb` this instruction stream
/// may already have been fetched under the stale mapping.
fn invalidate_page(virt: u64) {
    // SAFETY: `tlbi`/`dsb`/`isb` only affect translation caching and
    // instruction ordering; they touch no memory and are permitted at EL1.
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vaae1is, {page}",
            "dsb ish",
            "isb",
            page = in(reg) virt >> SHIFT_PAGE,
            options(nostack, preserves_flags),
        );
    }
}

/// Builds the kernel's high-half (`TTBR1`) tables: the direct physical map and
/// the kernel image at its true per-section permissions. The device range and
/// user pages belong to the low half (`TTBR0`) and are not here — this root is
/// the one that stays resident across every process switch.
///
/// Table frames are written through `access_base`, the direct map at
/// [`DIRECT_MAP_BASE`]; the MMU is already on (the entry stub's coarse tables
/// installed that same direct map), so `access_base` is `DIRECT_MAP_BASE`
/// throughout — there is no identity-then-direct-map handoff any more.
///
/// The kernel image is mapped at its high virtual address, backed by the
/// physical frame named by the low 48 bits of that address
/// (`virt & PHYS_MASK`); the direct map covers the same frames a second time,
/// which is how a pager writes to a frame holding someone else's code.
pub fn build_high_space(
    alloc: &mut dyn FrameSource,
    access_base: u64,
    sections: &[KernelSection],
    ram_range: (u64, u64),
) -> Result<KernelAddressSpace, KError> {
    let mut space = KernelAddressSpace::new(alloc, access_base)?;

    // Direct physical map: every RAM frame reachable at DIRECT_MAP_BASE +
    // phys, with the *same* offset everywhere so translation stays a single
    // addition.
    //
    // It deliberately spans RAM only, not physical zero upwards. Covering
    // the hole below RAM would map device registers as Normal memory, where
    // the architecture permits speculative reads — a load the program never
    // issued could then hit a register with a read side effect. Devices get
    // Device-nGnRnE mappings in the low half, and only those.
    let (ram_start, ram_end) = ram_range;
    let ram_start = ram_start & !(PAGE_2M - 1);
    let ram_end = (ram_end + PAGE_2M - 1) & !(PAGE_2M - 1);
    space.map_block_range(
        DIRECT_MAP_BASE + ram_start,
        ram_start,
        ram_end - ram_start,
        PageFlags::rw().global(),
        alloc,
    )?;

    // Kernel image, one section at a time, 4 KiB pages at real permissions —
    // the write-XOR-execute split the image's own segments already declare.
    // Each high virtual page maps its own physical frame (the low 48 bits).
    for section in sections {
        let attributes = leaf_attributes(section.flags)?;
        let mut virt = section.virt_start & !(PAGE_4K - 1);
        let end = (section.virt_end + PAGE_4K - 1) & !(PAGE_4K - 1);
        while virt < end {
            space.map_4k(virt, virt & PHYS_MASK, attributes, alloc)?;
            virt += PAGE_4K;
        }
    }

    Ok(space)
}

/// Builds the low-half (`TTBR0`) tables: the platform's device range,
/// identity-mapped so the console keeps working. User pages are mapped into
/// this same root later, at low virtual addresses with EL0 access; this is the
/// half a per-process address space will eventually own and swap.
pub fn build_low_space(
    alloc: &mut dyn FrameSource,
    access_base: u64,
    device_range: (u64, u64),
) -> Result<KernelAddressSpace, KError> {
    let mut space = KernelAddressSpace::new(alloc, access_base)?;

    let (device_base, device_len) = device_range;
    space.map_block_range(
        device_base,
        device_base,
        device_len,
        PageFlags::rw().global().device(),
        alloc,
    )?;

    Ok(space)
}

/// Fills the five reserved boot page-table frames with the coarse mapping the
/// entry stub needs to reach the high half: a low-half identity of the first
/// two 1 GiB regions (device + kernel/DTB) for the instants between enabling
/// the MMU and branching high, and a high-half cover of the kernel image and a
/// direct map so the first high-half code and the real table build can run.
///
/// This is deliberately position-independent — it reads no static and calls
/// nothing, touching only its pointer arguments and integer constants — so it
/// is correct while executing at the physical load address with translation
/// off, where a high (linked) address would fault.
///
/// # Safety
///
/// The five arguments must be the physical addresses of five distinct, zeroed,
/// 4 KiB-aligned reserved table frames. Called once, on the boot CPU, MMU off.
pub unsafe fn build_boot_tables(
    ttbr0_root: u64,
    l1_low: u64,
    ttbr1_root: u64,
    l1_high_kernel: u64,
    l1_high_direct: u64,
) {
    // SAFETY: each argument is a distinct zeroed 4 KiB table frame per the
    // contract; every index written is < 512, so every store stays inside its
    // frame. 1 GiB block outputs are 1 GiB-aligned as the descriptor requires.
    // The direct-map writes are unrolled and every offset uses `wrapping_add`
    // so the whole function is call-free and panic-free — nothing here can
    // branch to a static-touching panic path while translation is off.
    unsafe {
        // Low half (TTBR0): [0] -> l1_low; l1_low[0] device 0..1G, l1_low[1]
        // Normal 1G..2G (kernel image + DTB), an identity for the transition.
        write_descriptor(ttbr0_root, 0, l1_low | BOOT_TABLE_DESC);
        write_descriptor(l1_low, 0, BOOT_DEVICE_BLOCK); // phys 0
        write_descriptor(l1_low, 1, 0x4000_0000 | BOOT_NORMAL_BLOCK);

        // High half (TTBR1): [0] -> kernel-image L1 (VA 0xffff_0000_4000_0000
        // has level-0 index 0), [256] -> direct-map L1 (DIRECT_MAP_BASE has
        // level-0 index 256).
        write_descriptor(ttbr1_root, 0, l1_high_kernel | BOOT_TABLE_DESC);
        write_descriptor(ttbr1_root, 256, l1_high_direct | BOOT_TABLE_DESC);

        // Kernel image: the 1 GiB block at level-1 index 1 (VA bits 38:30 of
        // 0xffff_0000_4000_0000) outputs phys 0x4000_0000, covering the image
        // loaded at 0x4008_0000.
        write_descriptor(l1_high_kernel, 1, 0x4000_0000 | BOOT_NORMAL_BLOCK);

        // Direct map: DIRECT_MAP_BASE + phys -> phys. Within the level-0 [256]
        // subtree the level-1 index is phys >> 30, so blocks at indices 1..=3
        // cover phys 1..4 GiB — generous headroom over the RAM the allocator
        // draws table frames from. The real direct map replaces this.
        write_descriptor(l1_high_direct, 1, (1 << 30) | BOOT_NORMAL_BLOCK);
        write_descriptor(l1_high_direct, 2, (2 << 30) | BOOT_NORMAL_BLOCK);
        write_descriptor(l1_high_direct, 3, (3 << 30) | BOOT_NORMAL_BLOCK);
    }
}

/// Writes one 64-bit descriptor at `index` in the table at physical address
/// `table_phys` — a raw, non-volatile store through the argument address,
/// ordered before the MMU comes on by the `dsb` in [`enable_mmu_raw`]. Uses
/// `wrapping_add` so it lowers to a bare store with no bounds or overflow
/// check, keeping it position-independent and panic-free for the MMU-off path.
///
/// # Safety
///
/// `table_phys` must address a live table frame and `index` must be `< 512`;
/// the frame must be reachable at its physical address (MMU off, or an
/// identity/direct mapping present).
#[inline(always)]
unsafe fn write_descriptor(table_phys: u64, index: u64, descriptor: u64) {
    let addr = table_phys.wrapping_add(index << 3);
    // SAFETY: the caller guarantees a live table frame and an in-range index,
    // so `addr` lies inside the frame and is 8-byte aligned.
    unsafe { *(addr as *mut u64) = descriptor };
}

/// Turns on the MMU with the two coarse boot roots active, `TTBR0_EL1` mapping
/// the low-half identity (so the currently executing physical code stays valid
/// for the instant before the branch to the high half) and `TTBR1_EL1` mapping
/// the kernel's high half.
///
/// Programs `MAIR_EL1`, `TCR_EL1` (both halves, `TTBR1` walks enabled), both
/// translation bases, and finally `SCTLR_EL1.{M,C,I}`. The output-address size
/// is taken from `ID_AA64MMFR0_EL1.PARange`, capped at the 48 bits four levels
/// describe.
///
/// Position-independent — arguments, constants, and `asm!` only — so it runs
/// correctly at the physical load address with translation still off.
///
/// # Safety
///
/// `ttbr0_root` must map the currently executing code, its stack, and its
/// devices at their physical addresses; `ttbr1_root` must map the kernel's
/// high half. The MMU comes on between one instruction and the next, and a gap
/// is unrecoverable. Called once, on the boot CPU, MMU off.
pub unsafe fn enable_mmu_raw(ttbr0_root: u64, ttbr1_root: u64) {
    let parange: u64;
    // SAFETY: `ID_AA64MMFR0_EL1` is a read-only identification register
    // readable at EL1; the read has no side effects.
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) parange, options(nomem, nostack)) };
    // Clamp to 48-bit (5), the most four levels reach — written as a branch
    // rather than `.min()` so this MMU-off path makes no call at all.
    let parange = parange & 0xf;
    let ips = if parange > 5 { 5 } else { parange };
    let tcr = TCR_BASE | (ips << 32);

    // SAFETY: the caller guarantees the roots map this code, its stack, and
    // its devices. The sequence is ordered as the architecture requires:
    // system registers are programmed and made visible with `isb` before the
    // walker can use them, every stale translation is invalidated, and the
    // final `isb` ensures no instruction after the enable was fetched under
    // the old regime.
    unsafe {
        asm!(
            "msr mair_el1, {mair}",
            "msr tcr_el1, {tcr}",
            "msr ttbr0_el1, {t0}",
            "msr ttbr1_el1, {t1}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            "mrs {scratch}, sctlr_el1",
            "orr {scratch}, {scratch}, {enable}",
            "msr sctlr_el1, {scratch}",
            "isb",
            mair = in(reg) MAIR_VALUE,
            tcr = in(reg) tcr,
            t0 = in(reg) ttbr0_root,
            t1 = in(reg) ttbr1_root,
            enable = in(reg) SCTLR_ENABLE,
            scratch = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// Replaces both translation roots with the kernel's real split tables, once
/// they are built: `TTBR0_EL1` with the low-half (device + user) root and
/// `TTBR1_EL1` with the high-half (kernel) root. The coarse boot tables are
/// abandoned after this.
///
/// # Safety
///
/// Called with the MMU already on, executing from the high half. `ttbr1_root`
/// must map the currently executing code and the active stack identically to
/// the boot high-half root, or the instruction after the switch faults;
/// `ttbr0_root` must map every device still in use.
pub unsafe fn switch_tables(ttbr0_root: PhysAddr, ttbr1_root: PhysAddr) {
    // SAFETY: the caller guarantees both roots are live and that the new high
    // half maps the running code and stack. Barriers order the base-register
    // writes before the TLB flush and the flush before the next fetch.
    unsafe {
        asm!(
            "msr ttbr0_el1, {t0}",
            "msr ttbr1_el1, {t1}",
            "dsb ish",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            t0 = in(reg) ttbr0_root.as_u64(),
            t1 = in(reg) ttbr1_root.as_u64(),
            options(nostack, preserves_flags),
        );
    }
}
