// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Sv39 paging: a three-level page-table hierarchy, the kernel address space
//! built over it, and the `satp` switch that makes it live.
//!
//! # Why this port looks simpler than the other two, and where it does not
//!
//! **It boots with translation already off, not merely disabled.** RISC-V
//! enters S-mode with `satp` in Bare mode, where every address is physical.
//! There is no window in which the kernel executes at one address and is
//! linked at another, so — unlike the AArch64 port, which must build coarse
//! boot tables with the MMU off using position-independent code before it can
//! reach its own linked addresses — this port builds its real tables as
//! ordinary Rust with a working stack and console, and turns translation on
//! once. That is why there is no `build_boot_tables` here and no reserved
//! table frames in the linker script.
//!
//! **The kernel is identity-mapped, deliberately, for now.** The image is
//! linked at its physical load address and every kernel virtual address
//! equals its physical one, which makes `access_base` — the window through
//! which table frames are edited — zero and constant. The higher-half split
//! (kernel above `0xffff_ffc0_0000_0000`, user below) is the next milestone on
//! this port, exactly as it was a separate milestone on AArch64. Until then
//! `USER_ADDRESS_MAX` still reports Sv39's true user/kernel boundary rather
//! than a number chosen to match the current layout, so nothing downstream
//! encodes the temporary arrangement.
//!
//! **There is no device-memory page attribute.** AArch64 encodes
//! Device-nGnRnE in the PTE; on RISC-V whether a physical range is I/O or
//! normal memory is a property of the platform's physical memory attributes,
//! which the page table cannot override. So [`PageFlags::device`] carries no
//! PTE bit here. It is not ignored: a device mapping that also asks for
//! execute is refused, because speculatively fetching from a register block
//! is exactly as wrong on this architecture as on the other one, and the
//! ordering that AArch64 gets from the memory type comes from explicit
//! `fence` instructions instead (`crate::mmio::fence_io`).
//!
//! **The instruction cache is genuinely incoherent**, which makes
//! [`sync_instruction_cache`](AddressSpaceOps::sync_instruction_cache) load-
//! bearing rather than ceremonial. RISC-V requires `fence.i` between writing
//! instructions as data and fetching them; this is the architecture the
//! porting-layer operation was put there for.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md,
//! docs/kernel/02-scheduling-memory-ipc.md ("Memory Model")
//! Budget: none (mapping paths are init-time in this milestone)

use core::arch::asm;
use tessera_karch::{
    AddressSpaceOps, FrameSource, KError, PageFlags, PhysAddr, PhysFrame, VirtAddr,
};

/// Page sizes Sv39 can map at each level.
pub const PAGE_4K: u64 = 4096;
pub const PAGE_2M: u64 = 2 * 1024 * 1024;
pub const PAGE_1G: u64 = 1024 * 1024 * 1024;

/// Entries per table — 512 at every level (9 index bits, 8-byte entries).
const ENTRIES: usize = 512;

/// Virtual base at which physical memory is reachable while this port is
/// identity-mapped. Named rather than spelled `0` at every use so the higher-
/// half milestone has one place to change.
pub const DIRECT_MAP_BASE: u64 = 0;

// PTE bits.
const PTE_V: u64 = 1 << 0; // valid
const PTE_R: u64 = 1 << 1; // readable
const PTE_W: u64 = 1 << 2; // writable
const PTE_X: u64 = 1 << 3; // executable
const PTE_U: u64 = 1 << 4; // user-accessible
const PTE_G: u64 = 1 << 5; // global (not flushed on ASID switch)
const PTE_A: u64 = 1 << 6; // accessed
const PTE_D: u64 = 1 << 7; // dirty

/// Permission bits; a PTE with none of them is a pointer to the next level.
const PTE_PERMISSIONS: u64 = PTE_R | PTE_W | PTE_X;

/// Bit position of the physical page number inside a PTE.
const PTE_PPN_SHIFT: u64 = 10;

/// `satp.MODE` value selecting Sv39.
const SATP_MODE_SV39: u64 = 8 << 60;
/// Bit position of `satp.ASID`.
const SATP_ASID_SHIFT: u64 = 44;

/// One region of the kernel image and the permissions it must carry once the
/// kernel owns its page tables.
pub struct KernelSection {
    pub virt_start: u64,
    pub virt_end: u64,
    pub flags: PageFlags,
}

/// A page-table hierarchy rooted at one level-2 table frame. Table frames are
/// reached at `access_base + phys`, which is zero-based while this port is
/// identity-mapped.
///
/// `asid` tags this space in `satp` on
/// [`activate`](AddressSpaceOps::activate) so a per-process switch can flush
/// only this space's non-global entries. It is 0 for the kernel space.
pub struct KernelAddressSpace {
    root: PhysAddr,
    access_base: u64,
    asid: u16,
}

/// Sv39 virtual addresses must be sign-extended from bit 38: the usable space
/// is `[0, 2^38)` and `[2^64 - 2^38, 2^64)`, and anything else faults rather
/// than aliasing. Every mapping operation checks this instead of truncating,
/// so a bad address is a reported error and not a mapping somewhere else.
const fn is_canonical(virt: u64) -> bool {
    let top = virt >> 38;
    top == 0 || top == 0x3ff_ffff
}

/// Index of `virt` into the table at `level` (2 = root, 0 = leaf).
const fn index(virt: u64, level: u32) -> usize {
    ((virt >> (12 + 9 * level)) & 0x1ff) as usize
}

/// Page size mapped by a leaf at `level`.
const fn level_size(level: u32) -> u64 {
    PAGE_4K << (9 * level)
}

/// Translates neutral page flags into leaf-PTE bits.
fn leaf_bits(flags: PageFlags) -> Result<u64, KError> {
    if flags.is_wx() {
        return Err(KError::WXViolation);
    }
    if !flags.readable() {
        // Sv39 encodes write-without-read as a *reserved* combination, and a
        // leaf with no permission bits at all is a pointer to the next level,
        // not a mapping. An unreadable mapping is therefore expressed by not
        // mapping the page, exactly as on AArch64.
        return Err(KError::InvalidMapping);
    }
    if flags.is_device() && flags.executable() {
        // Refusing beats quietly clearing the execute bit, which would hand
        // back a mapping the caller did not ask for.
        return Err(KError::InvalidMapping);
    }

    // The accessed bit is set up front: leaving it clear costs a fault on
    // first touch under Svade, and nothing in this kernel uses that fault yet.
    // The dirty bit is set only where a store is possible at all, so the flag
    // keeps meaning something.
    let mut bits = PTE_V | PTE_R | PTE_A;
    if flags.writable() {
        bits |= PTE_W | PTE_D;
    }
    if flags.executable() {
        bits |= PTE_X;
    }
    if flags.is_user() {
        bits |= PTE_U;
    }
    if flags.is_global() {
        bits |= PTE_G;
    }
    Ok(bits)
}

/// Rebuilds neutral flags from a leaf PTE, for [`translate`](
/// AddressSpaceOps::translate). `device` is not recovered because it was never
/// stored — see the module header.
fn flags_from_leaf(pte: u64) -> PageFlags {
    let mut flags = PageFlags::none();
    if pte & PTE_R != 0 {
        flags = flags.read();
    }
    if pte & PTE_W != 0 {
        flags = flags.write();
    }
    if pte & PTE_X != 0 {
        flags = flags.execute();
    }
    if pte & PTE_U != 0 {
        flags = flags.user();
    }
    if pte & PTE_G != 0 {
        flags = flags.global();
    }
    flags
}

/// Physical address a PTE points at (a table at a non-leaf, a page at a leaf).
const fn pte_phys(pte: u64) -> u64 {
    ((pte >> PTE_PPN_SHIFT) & 0xfff_ffff_ffff) << 12
}

/// Builds a PTE naming `phys` with `bits`.
const fn make_pte(phys: u64, bits: u64) -> u64 {
    ((phys >> 12) << PTE_PPN_SHIFT) | bits
}

/// Flushes the whole local TLB. Sv39 has per-address and per-ASID forms; the
/// coarse one is used here because every caller in this milestone changes the
/// kernel's own global mappings, where the narrower forms would still have to
/// be paired with the global-entry rules.
fn flush_tlb() {
    // SAFETY: `sfence.vma` with no operands orders prior page-table writes
    // against later translations and invalidates the local TLB. It has no
    // memory effect of its own and cannot fault at S-mode.
    unsafe { asm!("sfence.vma", options(nostack, preserves_flags)) };
}

impl KernelAddressSpace {
    /// Reads the entry at `slot` of the table at physical `table`.
    fn read_entry(&self, table: u64, slot: usize) -> u64 {
        // SAFETY: `table` is a page-table frame owned by this space and
        // reachable at `access_base + table`; `slot` is masked to 0..512 by
        // every caller (`index` returns 9 bits), so the access is in bounds.
        unsafe { ((self.access_base + table) as *const u64).add(slot).read() }
    }

    /// Writes the entry at `slot` of the table at physical `table`.
    fn write_entry(&self, table: u64, slot: usize, value: u64) {
        // SAFETY: as `read_entry`; this space owns the table frame exclusively
        // and no other CPU walks it (single core, D8).
        unsafe {
            ((self.access_base + table) as *mut u64)
                .add(slot)
                .write(value)
        }
    }

    /// Zeroes a freshly allocated table frame.
    fn clear_table(&self, table: u64) {
        for slot in 0..ENTRIES {
            self.write_entry(table, slot, 0);
        }
    }

    /// Walks from the root to the table one level below `level`, creating
    /// intermediate tables from `alloc`. Returns the physical address of the
    /// table that holds `virt`'s entry at `level`.
    ///
    /// Fails with [`KError::AlreadyMapped`] if a *larger* leaf already covers
    /// `virt` — splitting a superpage is a distinct operation with distinct
    /// invalidation rules, and silently doing it here would let a 4 KiB
    /// mapping quietly change the permissions of the megabytes around it.
    fn table_for(
        &mut self,
        virt: u64,
        level: u32,
        alloc: &mut dyn FrameSource,
    ) -> Result<u64, KError> {
        let mut table = self.root.as_u64();
        let mut current = 2u32;
        while current > level {
            let slot = index(virt, current);
            let entry = self.read_entry(table, slot);
            if entry & PTE_V == 0 {
                let frame = alloc.alloc_frame().ok_or(KError::OutOfMemory)?;
                let next = frame.base().as_u64();
                self.clear_table(next);
                // A non-leaf PTE carries no permission bits; that is what
                // distinguishes it from a leaf at this level.
                self.write_entry(table, slot, make_pte(next, PTE_V));
                table = next;
            } else if entry & PTE_PERMISSIONS != 0 {
                return Err(KError::AlreadyMapped);
            } else {
                table = pte_phys(entry);
            }
            current -= 1;
        }
        Ok(table)
    }

    /// Installs one leaf of `level_size(level)` bytes at `virt`.
    fn map_at_level(
        &mut self,
        virt: u64,
        phys: u64,
        bits: u64,
        level: u32,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        let size = level_size(level);
        if virt & (size - 1) != 0 || phys & (size - 1) != 0 {
            return Err(KError::Unaligned);
        }
        if !is_canonical(virt) {
            return Err(KError::InvalidMapping);
        }
        let table = self.table_for(virt, level, alloc)?;
        let slot = index(virt, level);
        if self.read_entry(table, slot) & PTE_V != 0 {
            return Err(KError::AlreadyMapped);
        }
        self.write_entry(table, slot, make_pte(phys, bits));
        Ok(())
    }

    /// Maps `[virt, virt + len)` to `[phys, phys + len)` using the largest
    /// leaves the alignment allows, stepping down a level wherever something
    /// is already mapped and skipping only the individual pages that are.
    ///
    /// The step-down is what makes composition work rather than a fallback.
    /// The caller maps the kernel image at its true per-section permissions
    /// *first*, then covers RAM with this: a 2 MiB leaf cannot be installed
    /// over the megabyte the image sits in, so the cover descends to 4 KiB
    /// there, leaves the image's own pages with the permissions they were
    /// given, and still maps the frames around them — which the frame
    /// allocator hands out immediately, so leaving them unmapped would fault
    /// on the first allocation.
    ///
    /// Only genuinely-occupied 4 KiB pages are skipped, and the count is
    /// returned rather than discarded: it should equal the image's page count,
    /// and is worth seeing rather than assuming.
    fn map_range(
        &mut self,
        virt: u64,
        phys: u64,
        len: u64,
        flags: PageFlags,
        alloc: &mut dyn FrameSource,
    ) -> Result<u64, KError> {
        let bits = leaf_bits(flags)?;
        let mut skipped = 0u64;
        let mut offset = 0u64;
        while offset < len {
            let (v, p, remaining) = (virt + offset, phys + offset, len - offset);
            // Largest level whose size divides both addresses and fits.
            let mut level = 2u32;
            while level > 0 {
                let size = level_size(level);
                if v & (size - 1) == 0 && p & (size - 1) == 0 && remaining >= size {
                    break;
                }
                level -= 1;
            }
            loop {
                match self.map_at_level(v, p, bits, level, alloc) {
                    Ok(()) => {
                        offset += level_size(level);
                        break;
                    }
                    // Something occupies part of this span. At a superpage
                    // level that is a finer mapping underneath, so try again
                    // one level down; at 4 KiB there is nothing finer and the
                    // page belongs to whoever mapped it first.
                    Err(KError::AlreadyMapped) if level > 0 => level -= 1,
                    Err(KError::AlreadyMapped) => {
                        skipped += 1;
                        offset += PAGE_4K;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(skipped)
    }

    /// Finds the leaf entry covering `virt`, returning the table holding it,
    /// its slot, and the level. `None` when no leaf is present.
    fn find_leaf(&self, virt: u64) -> Option<(u64, usize, u32)> {
        if !is_canonical(virt) {
            return None;
        }
        let mut table = self.root.as_u64();
        for level in (0..=2u32).rev() {
            let slot = index(virt, level);
            let entry = self.read_entry(table, slot);
            if entry & PTE_V == 0 {
                return None;
            }
            if entry & PTE_PERMISSIONS != 0 {
                return Some((table, slot, level));
            }
            table = pte_phys(entry);
        }
        None
    }

    /// Byte-wise view of a frame through the access window.
    fn frame_bytes(&self, frame: PhysFrame) -> *mut u8 {
        (self.access_base + frame.base().as_u64()) as *mut u8
    }

    /// Frees every table frame below `slot` of the root, then the root itself.
    fn free_subtree(&self, table: u64, level: u32, alloc: &mut dyn FrameSource) {
        if level > 0 {
            for slot in 0..ENTRIES {
                let entry = self.read_entry(table, slot);
                if entry & PTE_V != 0 && entry & PTE_PERMISSIONS == 0 {
                    self.free_subtree(pte_phys(entry), level - 1, alloc);
                }
            }
        }
        if let Some(frame) = PhysFrame::from_base(PhysAddr::new(table)) {
            alloc.free_frame(frame);
        }
    }
}

impl AddressSpaceOps for KernelAddressSpace {
    /// Sv39's user half is `[0, 2^38)`; everything at or above belongs to the
    /// kernel. This is the architecture's boundary, not this milestone's
    /// layout — see the module header.
    const USER_ADDRESS_MAX: u64 = 1 << 38;

    fn new(alloc: &mut dyn FrameSource, direct_map_base: u64) -> Result<Self, KError> {
        let frame = alloc.alloc_frame().ok_or(KError::OutOfMemory)?;
        let space = Self {
            root: frame.base(),
            access_base: direct_map_base,
            asid: 0,
        };
        space.clear_table(space.root.as_u64());
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
        self.map_at_level(virt.as_u64(), frame.base().as_u64(), bits, 0, alloc)?;
        flush_tlb();
        Ok(())
    }

    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, KError> {
        let (table, slot, level) = self.find_leaf(virt.as_u64()).ok_or(KError::NotMapped)?;
        let entry = self.read_entry(table, slot);
        // The frame the caller gets back is the one containing `virt`, which
        // for a superpage is not the leaf's base. Reporting anything else
        // would hand the caller a frame it does not own.
        let size = level_size(level);
        let within = virt.as_u64() & (size - 1) & !(PAGE_4K - 1);
        let frame = PhysFrame::from_base(PhysAddr::new(pte_phys(entry) + within))
            .ok_or(KError::InvalidMapping)?;
        self.write_entry(table, slot, 0);
        flush_tlb();
        Ok(frame)
    }

    fn zero_frame(&self, frame: PhysFrame) {
        // SAFETY: the caller owns `frame` exclusively, and the access window
        // makes it addressable at `access_base + phys` for exactly one frame.
        unsafe { core::ptr::write_bytes(self.frame_bytes(frame), 0, PAGE_4K as usize) };
    }

    fn fill_frame(&self, frame: PhysFrame, byte: u8) {
        // SAFETY: as `zero_frame`.
        unsafe { core::ptr::write_bytes(self.frame_bytes(frame), byte, PAGE_4K as usize) };
    }

    fn protect(&mut self, virt: VirtAddr, flags: PageFlags) -> Result<(), KError> {
        let bits = leaf_bits(flags)?;
        let (table, slot, _) = self.find_leaf(virt.as_u64()).ok_or(KError::NotMapped)?;
        let entry = self.read_entry(table, slot);
        self.write_entry(table, slot, make_pte(pte_phys(entry), bits));
        flush_tlb();
        Ok(())
    }

    fn translate(&self, virt: VirtAddr) -> Option<(PhysFrame, PageFlags)> {
        let (table, slot, level) = self.find_leaf(virt.as_u64())?;
        let entry = self.read_entry(table, slot);
        let size = level_size(level);
        let within = virt.as_u64() & (size - 1) & !(PAGE_4K - 1);
        let frame = PhysFrame::from_base(PhysAddr::new(pte_phys(entry) + within))?;
        Some((frame, flags_from_leaf(entry)))
    }

    fn copy_frame(&self, dst: PhysFrame, src: PhysFrame) {
        // SAFETY: the caller owns both frames exclusively; they are distinct
        // (a caller copying a frame onto itself has nothing to copy) and each
        // is addressable for one frame through the access window.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.frame_bytes(src),
                self.frame_bytes(dst),
                PAGE_4K as usize,
            )
        };
    }

    fn write_bytes_to_frame(&self, frame: PhysFrame, offset: usize, src: &[u8]) {
        let len = src.len().min((PAGE_4K as usize).saturating_sub(offset));
        // SAFETY: the caller owns `frame` exclusively and guarantees the write
        // fits; `len` is clamped to the frame regardless, so the destination
        // range is inside the frame the access window addresses.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.frame_bytes(frame).add(offset), len)
        };
    }

    /// `fence.i` — and on this architecture that is the whole operation, not a
    /// formality. RISC-V does not require the instruction cache to observe
    /// stores, so bytes written as data are not fetchable until a `fence.i`
    /// retires on the hart that will fetch them.
    ///
    /// Two limits are worth stating rather than leaving to be discovered.
    /// `fence.i` is **per-hart**: making writes fetchable on another hart
    /// needs an IPI to that hart, which arrives with SMP (D8 — this kernel is
    /// single-core). And it is **not range-based**, so `virt`/`len` are
    /// accepted to satisfy the interface and deliberately unused; a narrower
    /// instruction does not exist in the base ISA.
    fn sync_instruction_cache(&self, _virt: VirtAddr, _len: u64) {
        // SAFETY: `fence.i` orders this hart's stores against its own
        // instruction fetches. It has no memory effect of its own.
        unsafe { asm!("fence.i", options(nostack, preserves_flags)) };
    }

    // SAFETY: see the `AddressSpaceOps::activate` contract — the space must
    // map the running code, stack, and everything touched before the next
    // switch, at their current virtual addresses.
    unsafe fn activate(&self) {
        let satp =
            SATP_MODE_SV39 | (u64::from(self.asid) << SATP_ASID_SHIFT) | (self.root.as_u64() >> 12);
        // SAFETY: `satp` is the supervisor address-translation register. The
        // leading `sfence.vma` retires this space's table writes before the
        // walker can see the new root; the trailing one drops every stale
        // translation from the previous regime. The caller's contract
        // guarantees the new tables map the instruction after this one.
        unsafe {
            asm!(
                "sfence.vma",
                "csrw satp, {satp}",
                "sfence.vma",
                satp = in(reg) satp,
                options(nostack, preserves_flags),
            );
        }
    }

    fn root_phys(&self) -> PhysAddr {
        self.root
    }

    fn free_tables(&mut self, alloc: &mut dyn FrameSource) {
        // Only the user half is uniquely owned; kernel-half entries are shared
        // with every other space and must survive this teardown. On this port
        // no space shares tables yet, but the rule is the one that will hold
        // when they do, and encoding it now costs nothing.
        let user_slots = (Self::USER_ADDRESS_MAX >> 30) as usize;
        let root = self.root.as_u64();
        for slot in 0..user_slots.min(ENTRIES) {
            let entry = self.read_entry(root, slot);
            if entry & PTE_V != 0 && entry & PTE_PERMISSIONS == 0 {
                self.free_subtree(pte_phys(entry), 1, alloc);
            }
            self.write_entry(root, slot, 0);
        }
        if let Some(frame) = PhysFrame::from_base(self.root) {
            alloc.free_frame(frame);
        }
    }
}

/// Builds the kernel's address space: the platform's device range, the kernel
/// image at its true per-section permissions, and a direct map of RAM.
///
/// Order is load-bearing. The image's sections are mapped **before** RAM is
/// covered, so the write-XOR-execute permissions the image's own segments
/// declare are the ones that survive; the RAM cover then fills in around them
/// (see [`KernelAddressSpace::map_range`] on why a collision is skipped rather
/// than overwritten). The count of pages the cover skipped is returned so the
/// caller can report it — a number that should equal the image's page count
/// and is worth seeing rather than assuming.
pub fn build_kernel_space(
    alloc: &mut dyn FrameSource,
    access_base: u64,
    sections: &[KernelSection],
    ram_range: (u64, u64),
    device_range: (u64, u64),
) -> Result<(KernelAddressSpace, u64), KError> {
    let mut space = KernelAddressSpace::new(alloc, access_base)?;

    // Device registers. Read-write, never executable; no cache or ordering
    // attribute, because on this architecture the page table does not carry
    // one (module header).
    let (device_base, device_len) = device_range;
    space.map_range(
        device_base,
        device_base,
        device_len,
        PageFlags::rw().global().device(),
        alloc,
    )?;

    // Kernel image, one section at a time, 4 KiB pages at real permissions.
    for section in sections {
        let start = section.virt_start & !(PAGE_4K - 1);
        let end = (section.virt_end + PAGE_4K - 1) & !(PAGE_4K - 1);
        let mut virt = start;
        while virt < end {
            space.map_at_level(virt, virt, leaf_bits(section.flags)?, 0, alloc)?;
            virt += PAGE_4K;
        }
    }

    // Direct map of RAM: every frame reachable at `access_base + phys`, which
    // is what lets a pager write to a frame holding someone else's code.
    let (ram_start, ram_end) = ram_range;
    let skipped = space.map_range(
        access_base + ram_start,
        ram_start,
        ram_end - ram_start,
        PageFlags::rw().global(),
        alloc,
    )?;

    Ok((space, skipped))
}
