// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! x86-64 4-level paging: the kernel's own page tables, replacing the
//! bootloader's. Builds a fresh PML4 that maps the kernel image with true
//! per-section permissions (text RX, rodata RO, data RW+NX) and a direct
//! physical map, then loads it into CR3. Also the runtime `AddressSpaceOps`
//! implementation the kernel core drives to map, unmap, and reprotect
//! anonymous memory.
//!
//! This is the single place that translates the architecture-neutral
//! `PageFlags` into hardware PTE bits and enforces write-XOR-execute
//! (docs/kernel/03-paging-faults-and-exceptions.md, "Write-XOR-Execute"):
//! any request that is both writable and executable is rejected, and every
//! non-executable mapping sets the NX bit.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md,
//! docs/kernel/02-scheduling-memory-ipc.md ("Memory Model")
//! Budget: B7 (address-space switch), B8 (anonymous fault) — mapping and
//! CR3 paths; the perf rig that measures them is a later deliverable
//! (build/README.md, deviation D9).

use core::arch::asm;
use tessera_karch::{
    AddressSpaceOps, FrameSource, KError, PageFlags, PhysAddr, PhysFrame, VirtAddr,
};

// Page-table entry bits (Intel SDM Vol. 3A, 4.5 "4-Level Paging").
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
const HUGE: u64 = 1 << 7;
const GLOBAL: u64 = 1 << 8;
const NO_EXECUTE: u64 = 1 << 63;

/// Physical-address field of a PTE (bits 12..52).
const PHYS_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Entries per table and the sizes each paging level covers.
const ENTRIES: usize = 512;
const PAGE_4K: u64 = 4096;
const PAGE_2M: u64 = 2 * 1024 * 1024;

/// The MSR and bit that enable the NX page-table bit.
const IA32_EFER: u32 = 0xC000_0080;
const EFER_NXE: u32 = 1 << 11;
/// CR4.PGE enables global pages.
const CR4_PGE: u64 = 1 << 7;

/// One kernel-image section to map, with its intended permissions.
pub struct KernelSection {
    pub virt_start: u64,
    pub virt_end: u64,
    pub flags: PageFlags,
}

/// A page-table hierarchy rooted at one PML4 frame. Table frames are reached
/// through a direct physical map at `access_base` — the bootloader HHDM while
/// the kernel tables are under construction, then the kernel's own (possibly
/// randomized) direct map once it is active. `set_access_base` moves it across
/// that switch.
pub struct KernelAddressSpace {
    root: PhysAddr,
    access_base: u64,
}

/// Translates neutral page flags into leaf-PTE bits, rejecting a
/// writable+executable request. `PRESENT` is always set for a live mapping;
/// absence of the executable flag sets NX.
fn leaf_bits(flags: PageFlags) -> Result<u64, KError> {
    if flags.is_wx() {
        return Err(KError::WXViolation);
    }
    if !flags.readable() {
        // x86-64 has no read-disable bit; a live mapping is always readable.
        return Err(KError::InvalidMapping);
    }
    let mut bits = PRESENT;
    if flags.writable() {
        bits |= WRITABLE;
    }
    if !flags.executable() {
        bits |= NO_EXECUTE;
    }
    if flags.is_user() {
        bits |= USER;
    }
    if flags.is_global() {
        bits |= GLOBAL;
    }
    if flags.is_device() {
        bits |= WRITE_THROUGH | CACHE_DISABLE;
    }
    Ok(bits)
}

/// Reconstructs neutral page flags from a present leaf PTE — the inverse of
/// [`leaf_bits`], for reporting what a fault address maps to. A present page is
/// always readable; execute is the absence of NX.
fn flags_from_leaf(entry: u64) -> PageFlags {
    let mut flags = PageFlags::none().read();
    if entry & WRITABLE != 0 {
        flags = flags.write();
    }
    if entry & NO_EXECUTE == 0 {
        flags = flags.execute();
    }
    if entry & USER != 0 {
        flags = flags.user();
    }
    if entry & GLOBAL != 0 {
        flags = flags.global();
    }
    if entry & (WRITE_THROUGH | CACHE_DISABLE) == (WRITE_THROUGH | CACHE_DISABLE) {
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
    /// kernel installs its own tables, to move off the bootloader HHDM and
    /// onto the kernel's own (possibly randomized) direct map.
    ///
    /// # Safety
    ///
    /// `base` must be the virtual base of an active direct map covering all
    /// physical memory (i.e. the just-installed kernel tables' direct map).
    pub unsafe fn set_access_base(&mut self, base: u64) {
        self.access_base = base;
    }

    /// Maps `[virt, virt + len)` to `[phys, phys + len)` in 2 MiB pages as
    /// read-write, non-executable, global memory. Used to keep the boot stack
    /// reachable at the bootloader HHDM base after the direct map is
    /// randomized. `virt`, `phys`, and `len` must be 2 MiB aligned.
    pub fn map_direct_2m_range(
        &mut self,
        virt: u64,
        phys: u64,
        len: u64,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        let bits = leaf_bits(PageFlags::rw().global())?;
        let mut offset = 0u64;
        while offset < len {
            self.map_2m(virt + offset, phys + offset, bits, alloc)?;
            offset += PAGE_2M;
        }
        Ok(())
    }

    /// Creates a fresh user address space that shares this (kernel) space's
    /// higher-half mappings. The new PML4's upper 256 entries are copied from
    /// the kernel PML4, so kernel code, kernel stacks, and the direct map stay
    /// addressable under the user CR3 — a syscall or fault taken in ring 3 runs
    /// kernel code without a CR3 switch (build/README.md, D21: no KPTI). The
    /// lower 256 entries start empty; ring-3 mappings live in the low half.
    pub fn new_user(&self, alloc: &mut dyn FrameSource) -> Result<Self, KError> {
        let root = alloc.alloc_frame().ok_or(KError::OutOfMemory)?.base();
        let space = Self {
            root,
            access_base: self.access_base,
        };
        space.clear_frame(root.as_u64());
        // Copy the kernel's higher-half PML4 entries (indices 256..512) so the
        // kernel is mapped in this address space; the low half stays user-owned.
        for idx in (ENTRIES / 2)..ENTRIES {
            space.write_entry(root.as_u64(), idx, self.read_entry(self.root.as_u64(), idx));
        }
        Ok(space)
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
            table = if entry & PRESENT != 0 {
                entry & PHYS_MASK
            } else {
                let frame = alloc.alloc_frame().ok_or(KError::OutOfMemory)?;
                let next = frame.base().as_u64();
                self.clear_frame(next);
                // Intermediate tables are writable (the CPU sets A/D bits),
                // never carry NX (leaf NX alone governs execute), and carry the
                // USER bit so a ring-3 leaf under this path is reachable — the
                // effective privilege is the AND of U/S across all levels, so
                // the leaf's U/S stays authoritative and kernel leaves remain
                // kernel-only.
                self.write_entry(table, idx, next | PRESENT | WRITABLE | USER);
                next
            };
        }
        Ok(table)
    }

    /// Maps a 4 KiB page. `bits` are prebuilt leaf bits from [`leaf_bits`].
    fn map_4k(
        &mut self,
        virt: u64,
        phys: u64,
        bits: u64,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        if virt & (PAGE_4K - 1) != 0 || phys & (PAGE_4K - 1) != 0 {
            return Err(KError::Unaligned);
        }
        let pt = self.walk_to(virt, &[39, 30, 21], alloc)?;
        let idx = ((virt >> 12) & 0x1ff) as usize;
        if self.read_entry(pt, idx) & PRESENT != 0 {
            return Err(KError::AlreadyMapped);
        }
        self.write_entry(pt, idx, phys | bits);
        Ok(())
    }

    /// Maps a 2 MiB page (used for the direct physical map).
    fn map_2m(
        &mut self,
        virt: u64,
        phys: u64,
        bits: u64,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        if virt & (PAGE_2M - 1) != 0 || phys & (PAGE_2M - 1) != 0 {
            return Err(KError::Unaligned);
        }
        let pd = self.walk_to(virt, &[39, 30], alloc)?;
        let idx = ((virt >> 21) & 0x1ff) as usize;
        if self.read_entry(pd, idx) & PRESENT != 0 {
            return Err(KError::AlreadyMapped);
        }
        self.write_entry(pd, idx, phys | bits | HUGE);
        Ok(())
    }

    /// Descends to the existing 4 KiB PTE for `virt`, returning
    /// `(table_phys, index)`, or `NotMapped` if any level is absent or the
    /// leaf is a huge page.
    fn find_4k(&self, virt: u64) -> Result<(u64, usize), KError> {
        let mut table = self.root.as_u64();
        for &shift in &[39u32, 30, 21] {
            let idx = ((virt >> shift) & 0x1ff) as usize;
            let entry = self.read_entry(table, idx);
            if entry & PRESENT == 0 || entry & HUGE != 0 {
                return Err(KError::NotMapped);
            }
            table = entry & PHYS_MASK;
        }
        Ok((table, ((virt >> 12) & 0x1ff) as usize))
    }

    /// Recursively frees the page-table frame at `table_phys` and every table
    /// beneath it, `level` being this table's paging level (3 = PDPT, 2 = PD,
    /// 1 = PT). Leaf (4 KiB data) frames are *not* freed here — they are the
    /// caller's responsibility via `unmap` — so a level-1 table only frees
    /// itself. Present huge entries (a 2 MiB/1 GiB leaf) have no child table
    /// and are skipped; the user (lower) half has only 4 KiB leaves, so this is
    /// a defensive guard. Frames are freed bottom-up: a parent is read to find
    /// its children before it is itself released, so the walk never touches a
    /// freed frame.
    fn free_subtree(&self, table_phys: u64, level: u32, alloc: &mut dyn FrameSource) {
        if level > 1 {
            for idx in 0..ENTRIES {
                let entry = self.read_entry(table_phys, idx);
                if entry & PRESENT != 0 && entry & HUGE == 0 {
                    self.free_subtree(entry & PHYS_MASK, level - 1, alloc);
                }
            }
        }
        if let Some(frame) = PhysFrame::from_base(PhysAddr::new(table_phys)) {
            alloc.free_frame(frame);
        }
    }
}

impl AddressSpaceOps for KernelAddressSpace {
    // Four-level paging: the low half runs to 2^47, where the non-canonical
    // hole begins. Five-level paging (LA57) would move this to 2^56, which is
    // why it is stated per-port rather than assumed.
    const USER_ADDRESS_MAX: u64 = 0x0000_8000_0000_0000;

    fn new(alloc: &mut dyn FrameSource, direct_map_base: u64) -> Result<Self, KError> {
        let root = alloc.alloc_frame().ok_or(KError::OutOfMemory)?.base();
        let space = Self {
            root,
            access_base: direct_map_base,
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
        let bits = leaf_bits(flags)?;
        self.map_4k(virt.as_u64(), frame.base().as_u64(), bits, alloc)?;
        invlpg(virt.as_u64());
        Ok(())
    }

    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, KError> {
        let (pt, idx) = self.find_4k(virt.as_u64())?;
        let entry = self.read_entry(pt, idx);
        if entry & PRESENT == 0 {
            return Err(KError::NotMapped);
        }
        self.write_entry(pt, idx, 0);
        invlpg(virt.as_u64());
        PhysFrame::from_base(PhysAddr::new(entry & PHYS_MASK)).ok_or(KError::InvalidMapping)
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
        let bits = leaf_bits(flags)?;
        let (pt, idx) = self.find_4k(virt.as_u64())?;
        let entry = self.read_entry(pt, idx);
        if entry & PRESENT == 0 {
            return Err(KError::NotMapped);
        }
        self.write_entry(pt, idx, (entry & PHYS_MASK) | bits);
        invlpg(virt.as_u64());
        Ok(())
    }

    fn translate(&self, virt: VirtAddr) -> Option<(PhysFrame, PageFlags)> {
        // `find_4k` validates the intermediate levels but returns the leaf slot
        // whether or not the leaf itself is present, so check the leaf here.
        let (pt, idx) = self.find_4k(virt.as_u64()).ok()?;
        let entry = self.read_entry(pt, idx);
        if entry & PRESENT == 0 {
            return None;
        }
        let frame = PhysFrame::from_base(PhysAddr::new(entry & PHYS_MASK))?;
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
        // map at `access_base`; the caller guarantees `offset + src.len()` stays
        // within the 4 KiB frame, so the destination range is inside the frame
        // and disjoint from `src` (a user buffer in another region).
        unsafe {
            let dst = (self.access_base + frame.base().as_u64() + offset as u64) as *mut u8;
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
    }

    fn sync_instruction_cache(&self, _virt: VirtAddr, _len: u64) {
        // Nothing to do, and that is a property of the hardware rather than
        // an omission: x86-64's instruction cache is coherent with data
        // writes, so instructions stored through a data mapping are visible
        // to a fetch without any maintenance. The operation exists at the
        // interface anyway, because assuming this everywhere is precisely
        // what docs/kernel/03 forbids — the AArch64 port has real work here.
    }

    // SAFETY: the caller guarantees this space maps the running code, the
    // active stack, and touched data at their current virtual addresses, so
    // loading CR3 switches tables without faulting.
    unsafe fn activate(&self) {
        unsafe {
            asm!("mov cr3, {}", in(reg) self.root.as_u64(), options(nostack, preserves_flags));
        }
    }

    fn root_phys(&self) -> PhysAddr {
        self.root
    }

    fn free_tables(&mut self, alloc: &mut dyn FrameSource) {
        // Only the lower half [0, ENTRIES/2) is user-owned: `new_user` copies
        // the kernel's upper 256 PML4 entries by value, so those point at
        // shared kernel tables that other spaces still use — never free them.
        // Freeing the lower-half PDPT subtrees plus the PML4 root reclaims
        // exactly this space's own tables.
        for idx in 0..(ENTRIES / 2) {
            let entry = self.read_entry(self.root.as_u64(), idx);
            if entry & PRESENT != 0 && entry & HUGE == 0 {
                self.free_subtree(entry & PHYS_MASK, 3, alloc);
            }
        }
        if let Some(root) = PhysFrame::from_base(self.root) {
            alloc.free_frame(root);
        }
    }
}

/// Flushes one page's TLB entry.
fn invlpg(virt: u64) {
    // SAFETY: `invlpg` only invalidates a TLB entry; it touches no memory
    // and has no effect other than the flush.
    unsafe {
        asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags));
    }
}

/// Enables the NX page-table bit (EFER.NXE) and global pages (CR4.PGE).
/// Must run once on each CPU before it loads a CR3 that uses NX or global
/// mappings.
///
/// # Safety
///
/// Call once on the boot CPU during paging bring-up; changes CPU-global
/// paging feature state.
pub unsafe fn enable_paging_features() {
    // SAFETY: reads EFER, sets NXE, writes it back, then sets CR4.PGE.
    // Both are standard long-mode features; enabling them has no effect on
    // existing mappings beyond honoring NX and global bits.
    unsafe {
        let mut lo: u32;
        let hi: u32;
        asm!("rdmsr", in("ecx") IA32_EFER, out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
        lo |= EFER_NXE;
        asm!("wrmsr", in("ecx") IA32_EFER, in("eax") lo, in("edx") hi, options(nostack, preserves_flags));

        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= CR4_PGE;
        asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    }
}

/// Builds the kernel's page tables: the direct physical map over
/// `[0, max_phys)` as 2 MiB pages (RW, NX, global) at `direct_map_base`, plus
/// each kernel-image section at its true permissions, and returns the space
/// ready to [`activate`](AddressSpaceOps::activate). Table frames are written
/// through `access_base` (the direct map active *now* — the bootloader HHDM),
/// while the new tables map physical memory at `direct_map_base` (which may be
/// randomized away from the HHDM). After activation the caller redirects
/// access with [`set_access_base`](KernelAddressSpace::set_access_base).
pub fn build_kernel_address_space(
    alloc: &mut dyn FrameSource,
    access_base: u64,
    direct_map_base: u64,
    kernel_phys_base: u64,
    kernel_virt_base: u64,
    sections: &[KernelSection],
    max_phys: u64,
) -> Result<KernelAddressSpace, KError> {
    let mut space = KernelAddressSpace::new(alloc, access_base)?;

    // Direct physical map: every frame reachable at direct_map_base + phys.
    let dm_bits = leaf_bits(PageFlags::rw().global())?;
    let mut phys = 0u64;
    while phys < max_phys {
        space.map_2m(direct_map_base + phys, phys, dm_bits, alloc)?;
        phys += PAGE_2M;
    }

    // Kernel image, one section at a time, 4 KiB pages at real permissions.
    for section in sections {
        let bits = leaf_bits(section.flags)?;
        let mut virt = section.virt_start & !(PAGE_4K - 1);
        let end = (section.virt_end + PAGE_4K - 1) & !(PAGE_4K - 1);
        while virt < end {
            let page_phys = kernel_phys_base + (virt - kernel_virt_base);
            space.map_4k(virt, page_phys, bits, alloc)?;
            virt += PAGE_4K;
        }
    }

    Ok(space)
}
