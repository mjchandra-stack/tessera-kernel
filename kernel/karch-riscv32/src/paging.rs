// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Sv32 paging: a two-level page-table hierarchy, the kernel address space
//! built over it, and the `satp` switch that makes it live.
//!
//! # Sv32 is not Sv39 with a level removed
//!
//! **A physical address is wider than a pointer.** Sv32's PTE carries a
//! 22-bit physical page number, so it addresses **34 bits** of physical
//! memory behind a 32-bit virtual address space. This is the case
//! `docs/hardware/01` warns about, and it is why `PhysAddr` is a fixed 64-bit
//! type across the whole system rather than a pointer-sized one: on this
//! architecture, narrowing a physical address to a pointer loses real
//! addresses on real hardware, not just in principle.
//!
//! The consequence for *this* port is a limit it must state rather than
//! assume. The kernel is identity-mapped, so the window through which page
//! tables and frames are reached is the pointer itself — which can only name
//! the low 4 GiB. A machine with RAM above that is not something this port
//! silently mishandles: [`build_kernel_space`] **rejects the memory map**,
//! once, where an error can still be returned. Every narrowing below is sound
//! because of that one check, and says so.
//!
//! **The index is 10 bits, not 9**, so a table holds 1024 entries and a
//! megapage is 4 MiB. **The user/kernel boundary is policy, not
//! architecture**: Sv32's address space is flat, with none of the
//! sign-extension hole that makes Sv39's boundary a hardware fact. See
//! [`KernelAddressSpace::USER_ADDRESS_MAX`].
//!
//! What is unchanged from the 64-bit port: translation is off at entry
//! (`satp` starts in Bare mode) so the tables are built as ordinary Rust with
//! a working console and turned on once; there is no device-memory page
//! attribute, so `PageFlags::device` carries no PTE bit and a device mapping
//! that also asks for execute is refused; and the instruction cache is
//! incoherent, so `fence.i` is load-bearing.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md,
//! docs/hardware/01-platform-and-cpu-support.md ("Endianness And Word Size")
//! Budget: none (mapping paths are init-time in this milestone)

use core::arch::asm;
use tessera_karch::{
    AddressSpaceOps, FrameSource, KError, PageFlags, PhysAddr, PhysFrame, VirtAddr,
};

/// Page sizes Sv32 can map at each level.
pub const PAGE_4K: u64 = 4096;
pub const PAGE_4M: u64 = 4 * 1024 * 1024;

/// Entries per table — 1024 at both levels (10 index bits, 4-byte entries).
const ENTRIES: usize = 1024;

/// Virtual base at which physical memory is reachable while this port is
/// identity-mapped.
pub const DIRECT_MAP_BASE: u64 = 0;

/// The highest physical address the identity access window can name. See the
/// module header: this is the limit `build_kernel_space` enforces.
const WINDOW_LIMIT: u64 = 1 << 32;

// PTE bits.
const PTE_V: u32 = 1 << 0; // valid
const PTE_R: u32 = 1 << 1; // readable
const PTE_W: u32 = 1 << 2; // writable
const PTE_X: u32 = 1 << 3; // executable
const PTE_U: u32 = 1 << 4; // user-accessible
const PTE_G: u32 = 1 << 5; // global (not flushed on ASID switch)
const PTE_A: u32 = 1 << 6; // accessed
const PTE_D: u32 = 1 << 7; // dirty

/// Permission bits; a PTE with none of them is a pointer to the next level.
const PTE_PERMISSIONS: u32 = PTE_R | PTE_W | PTE_X;

/// Bit position of the physical page number inside a PTE.
const PTE_PPN_SHIFT: u32 = 10;

/// `satp.MODE` value selecting Sv32 (bit 31, not a four-bit field as on the
/// 64-bit modes).
const SATP_MODE_SV32: u32 = 1 << 31;
/// Bit position of `satp.ASID` — 9 bits here, against Sv39's 16.
const SATP_ASID_SHIFT: u32 = 22;

/// One region of the kernel image and the permissions it must carry once the
/// kernel owns its page tables.
pub struct KernelSection {
    pub virt_start: u64,
    pub virt_end: u64,
    pub flags: PageFlags,
}

/// A page-table hierarchy rooted at one level-1 table frame.
pub struct KernelAddressSpace {
    root: PhysAddr,
    access_base: u64,
    asid: u16,
}

/// Sv32's virtual address space is a flat 32 bits — there is no
/// sign-extension hole to fall into — so the only thing that makes an address
/// non-canonical is not fitting.
const fn is_canonical(virt: u64) -> bool {
    virt <= u32::MAX as u64
}

/// Index of `virt` into the table at `level` (1 = root, 0 = leaf).
const fn index(virt: u64, level: u32) -> usize {
    ((virt >> (12 + 10 * level)) & 0x3ff) as usize
}

/// Page size mapped by a leaf at `level`.
const fn level_size(level: u32) -> u64 {
    PAGE_4K << (10 * level)
}

/// Translates neutral page flags into leaf-PTE bits.
fn leaf_bits(flags: PageFlags) -> Result<u32, KError> {
    if flags.is_wx() {
        return Err(KError::WXViolation);
    }
    if !flags.readable() {
        // Write-without-read is a reserved encoding, and a leaf with no
        // permission bits is a pointer to the next level rather than a
        // mapping. An unreadable mapping is expressed by not mapping.
        return Err(KError::InvalidMapping);
    }
    if flags.is_device() && flags.executable() {
        return Err(KError::InvalidMapping);
    }

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

/// Rebuilds neutral flags from a leaf PTE. `device` is not recovered because
/// it was never stored — see the module header.
fn flags_from_leaf(pte: u32) -> PageFlags {
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

/// Physical address a PTE points at. The result is up to 34 bits, which is
/// why it is a `u64` and not a `usize`.
const fn pte_phys(pte: u32) -> u64 {
    ((pte >> PTE_PPN_SHIFT) as u64) << 12
}

/// Builds a PTE naming `phys` with `bits`. `phys >> 12` is at most 22 bits,
/// so it fits the PPN field.
const fn make_pte(phys: u64, bits: u32) -> u32 {
    (((phys >> 12) as u32) << PTE_PPN_SHIFT) | bits
}

/// Flushes the whole local TLB.
fn flush_tlb() {
    // SAFETY: `sfence.vma` with no operands orders prior page-table writes
    // against later translations and invalidates the local TLB. It has no
    // memory effect of its own and cannot fault at S-mode.
    unsafe { asm!("sfence.vma", options(nostack, preserves_flags)) };
}

impl KernelAddressSpace {
    /// Narrows a physical address to a pointer for the identity access window.
    ///
    /// This is the one place the port converts a 34-bit-capable physical
    /// address into a 32-bit pointer, and it is exact rather than truncating
    /// because [`build_kernel_space`] rejected any memory map reaching past
    /// [`WINDOW_LIMIT`] before this space was ever used. The invariant is
    /// checked once, where a failure can be reported, so that it holds
    /// everywhere it is relied on.
    fn window(&self, phys: u64) -> usize {
        (self.access_base + phys) as usize
    }

    /// Reads the entry at `slot` of the table at physical `table`.
    fn read_entry(&self, table: u64, slot: usize) -> u32 {
        // SAFETY: `table` is a page-table frame owned by this space and
        // reachable through the identity window; `slot` is masked to 0..1024
        // by every caller (`index` returns 10 bits), so the access is in
        // bounds.
        unsafe { (self.window(table) as *const u32).add(slot).read() }
    }

    /// Writes the entry at `slot` of the table at physical `table`.
    fn write_entry(&self, table: u64, slot: usize, value: u32) {
        // SAFETY: as `read_entry`; this space owns the table frame exclusively
        // and no other hart walks it (single core, D8).
        unsafe { (self.window(table) as *mut u32).add(slot).write(value) }
    }

    /// Zeroes a freshly allocated table frame.
    fn clear_table(&self, table: u64) {
        for slot in 0..ENTRIES {
            self.write_entry(table, slot, 0);
        }
    }

    /// Walks from the root to the table one level below `level`, creating
    /// intermediate tables from `alloc`. Fails with [`KError::AlreadyMapped`]
    /// if a larger leaf already covers `virt` — splitting a superpage is a
    /// distinct operation with distinct invalidation rules.
    fn table_for(
        &mut self,
        virt: u64,
        level: u32,
        alloc: &mut dyn FrameSource,
    ) -> Result<u64, KError> {
        let mut table = self.root.as_u64();
        let mut current = 1u32;
        while current > level {
            let slot = index(virt, current);
            let entry = self.read_entry(table, slot);
            if entry & PTE_V == 0 {
                let frame = alloc.alloc_frame().ok_or(KError::OutOfMemory)?;
                let next = frame.base().as_u64();
                if next >= WINDOW_LIMIT {
                    return Err(KError::InvalidMapping);
                }
                self.clear_table(next);
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
        bits: u32,
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
    /// The step-down is what makes composition work: a 4 MiB leaf cannot be
    /// installed over the megabytes the kernel image sits in, so the RAM cover
    /// descends to 4 KiB there, leaves the image's own pages with the
    /// permissions they were given, and still maps the frames around them —
    /// which the frame allocator hands out immediately.
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
            let mut level = 1u32;
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

    /// Finds the leaf entry covering `virt`: the table holding it, its slot,
    /// and the level. `None` when no leaf is present.
    fn find_leaf(&self, virt: u64) -> Option<(u64, usize, u32)> {
        if !is_canonical(virt) {
            return None;
        }
        let mut table = self.root.as_u64();
        for level in (0..=1u32).rev() {
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
        self.window(frame.base().as_u64()) as *mut u8
    }

    /// Frees every table frame below `table`, then `table` itself.
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
    /// Where the user half ends.
    ///
    /// Unlike every other port in the tree this is a **policy** number, not an
    /// architectural one. x86-64 has a canonical hole, AArch64 has two
    /// translation-base registers, and Sv39 sign-extends from bit 38 — each of
    /// those makes the boundary a hardware fact. Sv32's address space is flat
    /// and 32 bits wide with no hole anywhere, so the kernel must simply
    /// choose. This picks 2 GiB, which is where RAM begins on the reference
    /// machine, so the split coincides with the memory layout instead of
    /// cutting across it.
    ///
    /// While the kernel is identity-mapped that has one visible oddity: the
    /// platform's device registers sit below 2 GiB and are therefore in the
    /// nominal user half. Nothing can reach them — there is no unprivileged
    /// level on this port yet — and the higher-half milestone moves them, but
    /// it is stated here rather than left to be discovered.
    const USER_ADDRESS_MAX: u64 = 0x8000_0000;

    fn new(alloc: &mut dyn FrameSource, direct_map_base: u64) -> Result<Self, KError> {
        let frame = alloc.alloc_frame().ok_or(KError::OutOfMemory)?;
        if frame.base().as_u64() >= WINDOW_LIMIT {
            return Err(KError::InvalidMapping);
        }
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
        // for a superpage is not the leaf's base.
        let size = level_size(level);
        let within = virt.as_u64() & (size - 1) & !(PAGE_4K - 1);
        let frame = PhysFrame::from_base(PhysAddr::new(pte_phys(entry) + within))
            .ok_or(KError::InvalidMapping)?;
        self.write_entry(table, slot, 0);
        flush_tlb();
        Ok(frame)
    }

    fn zero_frame(&self, frame: PhysFrame) {
        // SAFETY: the caller owns `frame` exclusively, and the identity window
        // makes it addressable for exactly one frame (see `window`).
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
        // and each is addressable for one frame through the identity window.
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
        // range is inside the frame the window addresses.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.frame_bytes(frame).add(offset), len)
        };
    }

    /// `fence.i` — per-hart and not range-based, exactly as on the 64-bit
    /// port. RISC-V does not require the instruction cache to observe stores,
    /// so this is the operation that makes freshly written bytes fetchable.
    fn sync_instruction_cache(&self, _virt: VirtAddr, _len: u64) {
        // SAFETY: `fence.i` orders this hart's stores against its own
        // instruction fetches. It has no memory effect of its own.
        unsafe { asm!("fence.i", options(nostack, preserves_flags)) };
    }

    // SAFETY: see the `AddressSpaceOps::activate` contract — the space must
    // map the running code, stack, and everything touched before the next
    // switch, at their current virtual addresses.
    unsafe fn activate(&self) {
        // The root is below WINDOW_LIMIT (checked in `new`), so `>> 12` fits
        // satp's 22-bit PPN field.
        let satp = SATP_MODE_SV32
            | (u32::from(self.asid) << SATP_ASID_SHIFT)
            | ((self.root.as_u64() >> 12) as u32);
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
        // with every other space and must survive this teardown.
        let user_slots = (Self::USER_ADDRESS_MAX >> 22) as usize;
        let root = self.root.as_u64();
        for slot in 0..user_slots.min(ENTRIES) {
            let entry = self.read_entry(root, slot);
            if entry & PTE_V != 0 && entry & PTE_PERMISSIONS == 0 {
                self.free_subtree(pte_phys(entry), 0, alloc);
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
/// This is also where the port's one hard limit is enforced. The identity
/// access window is a 32-bit pointer, so a machine whose RAM reaches past
/// 4 GiB — which Sv32's 34-bit physical addresses permit — cannot be served by
/// this arrangement. Rejecting the map here, once, is what lets every
/// narrowing in this module be exact instead of truncating; the alternative
/// would be a kernel that silently addressed the wrong frame.
pub fn build_kernel_space(
    alloc: &mut dyn FrameSource,
    access_base: u64,
    sections: &[KernelSection],
    ram_range: (u64, u64),
    device_range: (u64, u64),
) -> Result<(KernelAddressSpace, u64), KError> {
    let (ram_start, ram_end) = ram_range;
    if ram_end > WINDOW_LIMIT || access_base != 0 {
        return Err(KError::InvalidMapping);
    }

    let mut space = KernelAddressSpace::new(alloc, access_base)?;

    // Device registers. Read-write, never executable; no cache or ordering
    // attribute, because on this architecture the page table does not carry
    // one.
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

    // Direct map of RAM.
    let skipped = space.map_range(
        access_base + ram_start,
        ram_start,
        ram_end - ram_start,
        PageFlags::rw().global(),
        alloc,
    )?;

    Ok((space, skipped))
}
