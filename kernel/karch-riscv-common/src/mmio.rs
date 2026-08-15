// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Memory-mapped device register access. Like AArch64 and unlike x86-64,
//! RISC-V has no separate I/O address space: a device register is a normal
//! load or store, so the primitive is a volatile access rather than an
//! `in`/`out` instruction.
//!
//! Ordering differs from AArch64 in a way worth stating rather than
//! inheriting. AArch64 expresses "this is a device register" in the page
//! table, as the Device-nGnRnE memory *attribute*. RISC-V has no such PTE
//! bit: whether a physical range is I/O or normal memory is a property of the
//! physical memory attributes (PMAs), fixed by the platform, not by the
//! mapping. So there is nothing for the paging module to encode, and ordering
//! against surrounding accesses comes from explicit `fence` instructions
//! instead — which is why [`fence_io`] exists here and has no AArch64
//! counterpart in this crate.
//!
//! Normative: docs/hardware/04-device-memory-and-unified-memory.md
//! Budget: none (init and driver paths)

/// Reads a 32-bit device register.
///
/// # Safety
///
/// `addr` must be a 4-byte-aligned, currently-mapped device register the
/// caller is entitled to read, and reading it must have no side effect the
/// caller is not prepared for.
#[inline]
pub unsafe fn read32(addr: usize) -> u32 {
    // SAFETY: forwarded from the caller — `addr` is a live, aligned device
    // register. `read_volatile` is the only access form that guarantees the
    // compiler will not elide, duplicate, or reorder the load.
    unsafe { (addr as *const u32).read_volatile() }
}

/// Writes a 32-bit device register.
///
/// # Safety
///
/// `addr` must be a 4-byte-aligned, currently-mapped device register the
/// caller exclusively owns; the write's device-side effect is the caller's
/// responsibility.
#[inline]
pub unsafe fn write32(addr: usize, value: u32) {
    // SAFETY: forwarded from the caller — `addr` is a live, aligned device
    // register owned by the caller.
    unsafe { (addr as *mut u32).write_volatile(value) }
}

/// Reads an 8-bit device register. The `virt` machine's NS16550A presents
/// byte-wide registers, so the console needs this width and not only the
/// 32-bit one.
///
/// # Safety
///
/// As [`read32`], for a 1-byte register.
#[inline]
pub unsafe fn read8(addr: usize) -> u8 {
    // SAFETY: forwarded from the caller — `addr` is a live device register.
    unsafe { (addr as *const u8).read_volatile() }
}

/// Writes an 8-bit device register.
///
/// # Safety
///
/// As [`write32`], for a 1-byte register.
#[inline]
pub unsafe fn write8(addr: usize, value: u8) {
    // SAFETY: forwarded from the caller — `addr` is a live device register
    // owned by the caller.
    unsafe { (addr as *mut u8).write_volatile(value) }
}

/// Orders every prior device access before every later one.
///
/// `fence io, io` is the RISC-V way to say what a Device-nGnRnE mapping says
/// on AArch64: the accesses either side of it may not be reordered across it.
/// A driver that needs a register write to have reached the device before it
/// reads a status register puts one of these between them.
#[inline]
pub fn fence_io() {
    // SAFETY: `fence` is an ordering barrier. It has no memory effect of its
    // own and cannot fault; `nomem` would be a lie (its whole purpose is to
    // constrain memory ordering), so it is deliberately not claimed.
    unsafe { core::arch::asm!("fence io, io", options(nostack, preserves_flags)) };
}
