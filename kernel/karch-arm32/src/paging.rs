// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! LPAE paging: a three-level long-descriptor hierarchy, the kernel address
//! space built over it, and the `TTBR0` switch that makes it live.
//!
//! # LPAE is AArch64's format wearing a 32-bit address
//!
//! The descriptor is the *same* 64-bit long descriptor the AArch64 port
//! writes — type bits at [1:0], `AttrIndx` at [4:2], `AP[2:1]` at [7:6], `SH`
//! at [9:8], the access flag at 10, output address at [39:12], `PXN` at 53
//! and `XN` at 54. Anyone who has read `karch-aarch64/src/paging.rs` can read
//! this. That is the whole reason LPAE is the format this port uses rather
//! than the ARMv7 short descriptor, which is a different, older, two-level
//! format with 32-bit entries and no execute-never at page granularity — and
//! which `docs/hardware/01` rules out anyway by putting non-LPAE ARMv7 on the
//! wrong side of "Modern Hardware Only".
//!
//! What the 32-bit address changes is the *top* of the walk. A 4 KiB granule
//! resolves 9 bits per level, and a 32-bit virtual address has only 2 bits
//! left after three of them — so **the level-1 table has four entries**, not
//! five hundred and twelve. Thirty-two bytes of table, and the register that
//! points at it is correspondingly picky about alignment. This is the single
//! most surprising thing about LPAE and the easiest to write a subtly wrong
//! loop over.
//!
//! **Physical addresses are 40 bits** — wider than a pointer, as on Sv32 and
//! for the same reason the porting layer's `PhysAddr` is a fixed 64-bit type.
//! The identity access window is a 32-bit pointer, so, exactly as the RISC-V
//! 32 port does, [`build_kernel_space`] **rejects a memory map reaching past
//! 4 GiB** once, where an error can still be returned; every narrowing below
//! is exact because of that check.
//!
//! Unlike RISC-V and like AArch64, memory *type* is in the page table here —
//! `AttrIndx` selects an entry of `MAIR0`/`MAIR1` — so a device mapping is
//! genuinely Device-nGnRnE rather than a promise kept by explicit barriers.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md,
//! docs/hardware/01-platform-and-cpu-support.md ("Modern Hardware Only",
//! "Endianness And Word Size")
//! Budget: none (mapping paths are init-time in this milestone)

use core::arch::asm;
use tessera_karch::{
    AddressSpaceOps, FrameSource, KError, PageFlags, PhysAddr, PhysFrame, VirtAddr,
};

/// Page sizes LPAE can map at each level with a 4 KiB granule.
pub const PAGE_4K: u64 = 4096;
pub const PAGE_2M: u64 = 2 * 1024 * 1024;
pub const PAGE_1G: u64 = 1024 * 1024 * 1024;

/// Entries in the level-1 table. **Four**, not 512 — a 32-bit virtual address
/// has two bits left above three 9-bit levels.
const ENTRIES_L1: usize = 4;
/// Entries in the level-2 and level-3 tables.
const ENTRIES: usize = 512;

/// Virtual base at which physical memory is reachable while this port is
/// identity-mapped.
pub const DIRECT_MAP_BASE: u64 = 0;

/// The highest physical address the identity access window can name.
const WINDOW_LIMIT: u64 = 1 << 32;

// Descriptor bits, shared with the AArch64 long-descriptor format.
const DESC_TABLE: u64 = 0b11;
const DESC_BLOCK: u64 = 0b01;
const DESC_PAGE: u64 = 0b11;
const DESC_VALID: u64 = 0b01;

const AF: u64 = 1 << 10;
const AP_SHIFT: u64 = 6;
const AP_RW_PL1: u64 = 0b00;
const AP_RW_ALL: u64 = 0b01;
const AP_RO_PL1: u64 = 0b10;
const AP_RO_ALL: u64 = 0b11;
const SH_INNER: u64 = 0b11 << 8;
/// Privileged execute never — bit 53, as on AArch64.
const PXN: u64 = 1 << 53;
/// Execute never — bit 54, and **not** what the same bit means on AArch64.
///
/// This is the one place the two long-descriptor formats disagree, and it is
/// silent if you assume otherwise. On AArch64 bit 54 is `UXN`: *unprivileged*
/// execute never, so a kernel page sets it to keep user mode from executing
/// kernel text. On ARMv7-A the same bit is plain `XN`, applying to **both**
/// privilege levels — so setting it on kernel text makes the kernel
/// unexecutable by itself. That is not a subtle degradation: the first
/// instruction fetched after the MMU comes on takes a permission fault, which
/// vectors to a table that is also unexecutable, and the machine spins on a
/// recursive prefetch abort forever.
///
/// Here the rule is therefore: `XN` iff the mapping is not executable at all,
/// and `PXN` iff it is a *user* mapping (so privileged code can never execute
/// user pages). Keeping user mode out of kernel pages is `AP`'s job at this
/// width, not `XN`'s.
const XN: u64 = 1 << 54;

/// `MAIR0` attribute indices, programmed by [`enable_mmu`].
const ATTR_DEVICE: u64 = 0 << 2;
const ATTR_NORMAL: u64 = 1 << 2;

/// Output-address mask: bits [39:12], the 40 physical address bits LPAE
/// carries.
const ADDR_MASK: u64 = 0x0000_00ff_ffff_f000;

/// One region of the kernel image and the permissions it must carry.
pub struct KernelSection {
    pub virt_start: u64,
    pub virt_end: u64,
    pub flags: PageFlags,
}

/// A page-table hierarchy rooted at one level-1 table.
pub struct KernelAddressSpace {
    root: PhysAddr,
    access_base: u64,
    asid: u16,
}

/// A 32-bit virtual address space is flat: the only thing that makes an
/// address non-canonical is not fitting.
const fn is_canonical(virt: u64) -> bool {
    virt <= u32::MAX as u64
}

/// Index of `virt` into the table at `level` (1 = root, 3 = leaf).
const fn index(virt: u64, level: u32) -> usize {
    match level {
        1 => ((virt >> 30) & 0x3) as usize,
        2 => ((virt >> 21) & 0x1ff) as usize,
        _ => ((virt >> 12) & 0x1ff) as usize,
    }
}

/// Page size mapped by a leaf at `level`.
const fn level_size(level: u32) -> u64 {
    match level {
        1 => PAGE_1G,
        2 => PAGE_2M,
        _ => PAGE_4K,
    }
}

/// Translates neutral page flags into leaf-descriptor attribute bits (the
/// type bits are added by the caller, which knows the level).
fn leaf_attributes(flags: PageFlags) -> Result<u64, KError> {
    if flags.is_wx() {
        return Err(KError::WXViolation);
    }
    if !flags.readable() {
        // The AP field has no "no access" leaf encoding; an unreadable
        // mapping is expressed by not mapping the page, as on AArch64.
        return Err(KError::InvalidMapping);
    }
    if flags.is_device() && flags.executable() {
        // Device memory is speculation-hostile and must never be fetched
        // from. Refusing beats quietly clearing the execute bit.
        return Err(KError::InvalidMapping);
    }

    let mut bits = AF;
    bits |= match (flags.writable(), flags.is_user()) {
        (true, false) => AP_RW_PL1,
        (true, true) => AP_RW_ALL,
        (false, false) => AP_RO_PL1,
        (false, true) => AP_RO_ALL,
    } << AP_SHIFT;

    // See the note on `XN`: it means "never, at either level" here, so it is
    // set purely from whether the mapping is executable at all. `PXN` is what
    // stops privileged code executing a user page; user access to a kernel
    // page is already denied by `AP`.
    if !flags.executable() {
        bits |= XN;
    }
    if flags.is_user() {
        bits |= PXN;
    }

    if flags.is_device() {
        bits |= ATTR_DEVICE;
    } else {
        bits |= ATTR_NORMAL | SH_INNER;
    }
    Ok(bits)
}

/// Rebuilds neutral flags from a leaf descriptor.
fn flags_from_leaf(descriptor: u64) -> PageFlags {
    let mut flags = PageFlags::none().read();
    let ap = (descriptor >> AP_SHIFT) & 0b11;
    if ap == AP_RW_PL1 || ap == AP_RW_ALL {
        flags = flags.write();
    }
    if ap == AP_RW_ALL || ap == AP_RO_ALL {
        flags = flags.user();
    }
    // One bit decides it at this width, for both levels — see the note on
    // `XN`.
    if descriptor & XN == 0 {
        flags = flags.execute();
    }
    if descriptor & ATTR_NORMAL == 0 {
        flags = flags.device();
    }
    flags
}

/// Physical address a descriptor points at — up to 40 bits, which is why it
/// is a `u64` and not a `usize`.
const fn descriptor_phys(descriptor: u64) -> u64 {
    descriptor & ADDR_MASK
}

/// Invalidates the whole local TLB and publishes prior table writes to the
/// walker.
fn flush_tlb() {
    // SAFETY: `DSB` orders the table writes before the invalidate, `TLBIALL`
    // (CP15 c8, c7, 0) drops every local entry, and `ISB` keeps later
    // instructions from having been fetched under the old regime. None has a
    // memory effect of its own.
    unsafe {
        asm!(
            "dsb ish",
            "mcr p15, 0, {zero}, c8, c7, 0",
            "dsb ish",
            "isb",
            zero = in(reg) 0u32,
            options(nostack, preserves_flags),
        );
    }
}

impl KernelAddressSpace {
    /// Narrows a physical address to a pointer for the identity access
    /// window. Exact rather than truncating because [`build_kernel_space`]
    /// rejected any memory map reaching past [`WINDOW_LIMIT`] before this
    /// space was ever used.
    fn window(&self, phys: u64) -> usize {
        (self.access_base + phys) as usize
    }

    fn read_entry(&self, table: u64, slot: usize) -> u64 {
        // SAFETY: `table` is a page-table frame owned by this space and
        // reachable through the identity window; `slot` is bounded by the
        // level's entry count at every caller.
        unsafe { (self.window(table) as *const u64).add(slot).read() }
    }

    fn write_entry(&self, table: u64, slot: usize, value: u64) {
        // SAFETY: as `read_entry`; this space owns the table frame
        // exclusively and no other core walks it (single core, D8).
        unsafe { (self.window(table) as *mut u64).add(slot).write(value) }
    }

    /// Zeroes a freshly allocated table frame. Always a whole frame, even for
    /// the four-entry level-1 table: the allocator's unit is a frame, and
    /// leaving the tail of it as whatever the previous owner wrote would make
    /// a later widening of the root silently inherit garbage.
    fn clear_table(&self, table: u64) {
        for slot in 0..ENTRIES {
            self.write_entry(table, slot, 0);
        }
    }

    /// Walks from the root to the table one level below `level`, creating
    /// intermediate tables from `alloc`.
    fn table_for(
        &mut self,
        virt: u64,
        level: u32,
        alloc: &mut dyn FrameSource,
    ) -> Result<u64, KError> {
        let mut table = self.root.as_u64();
        let mut current = 1u32;
        while current < level {
            let slot = index(virt, current);
            let entry = self.read_entry(table, slot);
            if entry & DESC_VALID == 0 {
                let frame = alloc.alloc_frame().ok_or(KError::OutOfMemory)?;
                let next = frame.base().as_u64();
                if next >= WINDOW_LIMIT {
                    return Err(KError::InvalidMapping);
                }
                self.clear_table(next);
                self.write_entry(table, slot, next | DESC_TABLE);
                table = next;
            } else if entry & 0b11 == DESC_BLOCK {
                // A larger leaf already covers this address; splitting a
                // block is a distinct operation with distinct invalidation
                // rules, and doing it silently here would change the
                // permissions of the megabytes around the target.
                return Err(KError::AlreadyMapped);
            } else {
                table = descriptor_phys(entry);
            }
            current += 1;
        }
        Ok(table)
    }

    /// Installs one leaf of `level_size(level)` bytes at `virt`.
    fn map_at_level(
        &mut self,
        virt: u64,
        phys: u64,
        attributes: u64,
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
        if self.read_entry(table, slot) & DESC_VALID != 0 {
            return Err(KError::AlreadyMapped);
        }
        let kind = if level == 3 { DESC_PAGE } else { DESC_BLOCK };
        self.write_entry(table, slot, phys | attributes | kind);
        Ok(())
    }

    /// Maps `[virt, virt + len)` using the largest leaves the alignment
    /// allows, stepping down a level wherever something is already mapped and
    /// skipping only the individual pages that are. See the RISC-V ports'
    /// equivalent: the step-down is what lets a blanket RAM cover compose
    /// with the kernel image's own per-section permissions.
    fn map_range(
        &mut self,
        virt: u64,
        phys: u64,
        len: u64,
        flags: PageFlags,
        alloc: &mut dyn FrameSource,
    ) -> Result<u64, KError> {
        let attributes = leaf_attributes(flags)?;
        let mut skipped = 0u64;
        let mut offset = 0u64;
        while offset < len {
            let (v, p, remaining) = (virt + offset, phys + offset, len - offset);
            let mut level = 1u32;
            while level < 3 {
                let size = level_size(level);
                if v & (size - 1) == 0 && p & (size - 1) == 0 && remaining >= size {
                    break;
                }
                level += 1;
            }
            loop {
                match self.map_at_level(v, p, attributes, level, alloc) {
                    Ok(()) => {
                        offset += level_size(level);
                        break;
                    }
                    Err(KError::AlreadyMapped) if level < 3 => level += 1,
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

    /// Finds the leaf covering `virt`: the table holding it, its slot, and
    /// the level.
    fn find_leaf(&self, virt: u64) -> Option<(u64, usize, u32)> {
        if !is_canonical(virt) {
            return None;
        }
        let mut table = self.root.as_u64();
        for level in 1..=3u32 {
            let slot = index(virt, level);
            let entry = self.read_entry(table, slot);
            if entry & DESC_VALID == 0 {
                return None;
            }
            if level == 3 || entry & 0b11 == DESC_BLOCK {
                return Some((table, slot, level));
            }
            table = descriptor_phys(entry);
        }
        None
    }

    fn frame_bytes(&self, frame: PhysFrame) -> *mut u8 {
        self.window(frame.base().as_u64()) as *mut u8
    }

    fn free_subtree(&self, table: u64, level: u32, alloc: &mut dyn FrameSource) {
        if level < 3 {
            let count = if level == 1 { ENTRIES_L1 } else { ENTRIES };
            for slot in 0..count {
                let entry = self.read_entry(table, slot);
                if entry & DESC_VALID != 0 && entry & 0b11 == DESC_TABLE {
                    self.free_subtree(descriptor_phys(entry), level + 1, alloc);
                }
            }
        }
        if let Some(frame) = PhysFrame::from_base(PhysAddr::new(table)) {
            alloc.free_frame(frame);
        }
    }
}

impl AddressSpaceOps for KernelAddressSpace {
    /// Where the user half ends. As on Sv32 this is a **policy** number: a
    /// 32-bit address space is flat, and LPAE's `TTBCR` can split it anywhere
    /// (or not at all, which is what this milestone does — one `TTBR0`
    /// covering everything). 2 GiB is chosen because it is where RAM begins
    /// on the reference machine, so the split coincides with the layout.
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
        let attributes = leaf_attributes(flags)?;
        self.map_at_level(virt.as_u64(), frame.base().as_u64(), attributes, 3, alloc)?;
        flush_tlb();
        Ok(())
    }

    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, KError> {
        let (table, slot, level) = self.find_leaf(virt.as_u64()).ok_or(KError::NotMapped)?;
        let entry = self.read_entry(table, slot);
        let size = level_size(level);
        let within = virt.as_u64() & (size - 1) & !(PAGE_4K - 1);
        let frame = PhysFrame::from_base(PhysAddr::new(descriptor_phys(entry) + within))
            .ok_or(KError::InvalidMapping)?;
        self.write_entry(table, slot, 0);
        flush_tlb();
        Ok(frame)
    }

    fn zero_frame(&self, frame: PhysFrame) {
        // SAFETY: the caller owns `frame` exclusively, and the identity window
        // makes it addressable for exactly one frame.
        unsafe { core::ptr::write_bytes(self.frame_bytes(frame), 0, PAGE_4K as usize) };
    }

    fn fill_frame(&self, frame: PhysFrame, byte: u8) {
        // SAFETY: as `zero_frame`.
        unsafe { core::ptr::write_bytes(self.frame_bytes(frame), byte, PAGE_4K as usize) };
    }

    fn protect(&mut self, virt: VirtAddr, flags: PageFlags) -> Result<(), KError> {
        let attributes = leaf_attributes(flags)?;
        let (table, slot, level) = self.find_leaf(virt.as_u64()).ok_or(KError::NotMapped)?;
        let entry = self.read_entry(table, slot);
        let kind = if level == 3 { DESC_PAGE } else { DESC_BLOCK };
        self.write_entry(table, slot, descriptor_phys(entry) | attributes | kind);
        flush_tlb();
        Ok(())
    }

    fn translate(&self, virt: VirtAddr) -> Option<(PhysFrame, PageFlags)> {
        let (table, slot, level) = self.find_leaf(virt.as_u64())?;
        let entry = self.read_entry(table, slot);
        let size = level_size(level);
        let within = virt.as_u64() & (size - 1) & !(PAGE_4K - 1);
        let frame = PhysFrame::from_base(PhysAddr::new(descriptor_phys(entry) + within))?;
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
        // fits; `len` is clamped to the frame regardless.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.frame_bytes(frame).add(offset), len)
        };
    }

    /// Publishes freshly written bytes to the instruction stream.
    ///
    /// This is a real operation on this architecture, as on AArch64 and both
    /// RISC-V ports: the data and instruction caches are not coherent, so the
    /// written lines must be cleaned to the point of unification and the
    /// instruction cache invalidated before a fetch will see them. The range
    /// is walked by cache line rather than flushed wholesale, because
    /// `DCCMVAU` is per-address and the whole point is to avoid a full flush.
    fn sync_instruction_cache(&self, virt: VirtAddr, len: u64) {
        // A 32-byte line is the smallest any ARMv7-A implementation uses, so
        // stepping by it is correct on every one of them; reading `CTR` to
        // find the real size would be an optimisation, not a correction.
        const LINE: u64 = 32;
        let start = virt.as_u64() & !(LINE - 1);
        let end = virt.as_u64() + len;
        let mut address = start;
        while address < end {
            // SAFETY: `DCCMVAU` (CP15 c7, c11, 1) cleans one data-cache line
            // by virtual address to the point of unification. It touches no
            // memory the caller does not already own and cannot fault on an
            // unmapped address at this privilege level.
            unsafe { asm!("mcr p15, 0, {}, c7, c11, 1", in(reg) address as u32, options(nostack)) };
            address += LINE;
        }
        // SAFETY: `DSB` retires the cleans, `ICIALLU` (c7, c5, 0) invalidates
        // the whole instruction cache, and `ISB` flushes the pipeline so the
        // next fetch sees the new bytes.
        unsafe {
            asm!(
                "dsb ish",
                "mcr p15, 0, {zero}, c7, c5, 0",
                "dsb ish",
                "isb",
                zero = in(reg) 0u32,
                options(nostack),
            );
        }
    }

    // SAFETY: see the `AddressSpaceOps::activate` contract — the space must
    // map the running code, stack, and everything touched before the next
    // switch, at their current virtual addresses.
    unsafe fn activate(&self) {
        let root = self.root.as_u64();
        let low = root as u32;
        // The ASID lives in TTBR0[55:48], which is the high word's bits 23:16.
        let high = ((root >> 32) as u32) | (u32::from(self.asid) << 16);
        // SAFETY: `TTBR0` is 64 bits and therefore written with `mcrr`, a
        // register-pair move — the same shape as reading the counter. The
        // surrounding barriers are the architecturally required
        // base-register-change bracket: `DSB` retires table writes before the
        // walker sees the new root, the invalidate drops stale translations,
        // and `ISB` keeps later instructions from having been fetched under
        // the old regime.
        unsafe {
            asm!(
                "dsb ish",
                "mcrr p15, 0, {low}, {high}, c2",
                "isb",
                "mcr p15, 0, {zero}, c8, c7, 0",
                "dsb ish",
                "isb",
                low = in(reg) low,
                high = in(reg) high,
                zero = in(reg) 0u32,
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
        let user_slots = (Self::USER_ADDRESS_MAX >> 30) as usize;
        let root = self.root.as_u64();
        for slot in 0..user_slots.min(ENTRIES_L1) {
            let entry = self.read_entry(root, slot);
            if entry & DESC_VALID != 0 && entry & 0b11 == DESC_TABLE {
                self.free_subtree(descriptor_phys(entry), 2, alloc);
            }
            self.write_entry(root, slot, 0);
        }
        if let Some(frame) = PhysFrame::from_base(self.root) {
            alloc.free_frame(frame);
        }
    }
}

/// Builds the kernel's address space and turns the MMU on.
///
/// Returns the space and the number of pages the RAM cover skipped because
/// the kernel image already occupied them — a number that should equal the
/// image's page count and is worth seeing rather than assuming.
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

    let (device_base, device_len) = device_range;
    space.map_range(
        device_base,
        device_base,
        device_len,
        PageFlags::rw().global().device(),
        alloc,
    )?;

    for section in sections {
        let attributes = leaf_attributes(section.flags)?;
        let start = section.virt_start & !(PAGE_4K - 1);
        let end = (section.virt_end + PAGE_4K - 1) & !(PAGE_4K - 1);
        let mut virt = start;
        while virt < end {
            space.map_at_level(virt, virt, attributes, 3, alloc)?;
            virt += PAGE_4K;
        }
    }

    let skipped = space.map_range(
        access_base + ram_start,
        ram_start,
        ram_end - ram_start,
        PageFlags::rw().global(),
        alloc,
    )?;

    Ok((space, skipped))
}

/// Programs the memory attributes and translation control, installs `space`
/// as `TTBR0`, and enables the MMU.
///
/// # Safety
///
/// `space` must map the currently executing code, the active stack, and the
/// console's device registers at their current addresses; otherwise the CPU
/// faults on the instruction after the enable.
pub unsafe fn enable_mmu(space: &KernelAddressSpace) {
    // MAIR0 attribute 0 = Device-nGnRnE (0x00), attribute 1 = Normal
    // write-back read/write-allocate (0xff) — the same two the AArch64 port
    // programs, in the same order, so `ATTR_DEVICE`/`ATTR_NORMAL` mean the
    // same thing in both.
    const MAIR0: u32 = 0x0000_ff00;
    // TTBCR.EAE selects the long-descriptor format. T0SZ = 0 gives TTBR0 the
    // whole 32-bit address space, which is what makes the level-1 table four
    // entries.
    const TTBCR_EAE: u32 = 1 << 31;

    // SAFETY: these are this core's own translation-control registers, all
    // written with interrupts masked before translation is enabled.
    unsafe {
        asm!(
            "mcr p15, 0, {mair0}, c10, c2, 0",
            "mcr p15, 0, {zero}, c10, c2, 1",
            "mcr p15, 0, {ttbcr}, c2, c0, 2",
            "isb",
            mair0 = in(reg) MAIR0,
            zero = in(reg) 0u32,
            ttbcr = in(reg) TTBCR_EAE,
            options(nostack),
        );
        space.activate();
        // SCTLR: enable the MMU (M), data cache (C) and instruction cache (I).
        // Read-modify-write so the reserved bits firmware set survive.
        let mut sctlr: u32;
        asm!("mrc p15, 0, {}, c1, c0, 0", out(reg) sctlr, options(nomem, nostack));
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12);
        asm!(
            "mcr p15, 0, {sctlr}, c1, c0, 0",
            "isb",
            sctlr = in(reg) sctlr,
            options(nostack),
        );
    }
}
