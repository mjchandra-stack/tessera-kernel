// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Memory-mapped device register access — AArch64's counterpart to the
//! x86-64 port's port-I/O primitives (`karch-x86_64/src/io.rs`). There is no
//! separate I/O address space on this architecture: every device register is
//! a normal load or store to a Device-mapped page, so the primitive is a
//! volatile access rather than an `in`/`out` instruction.
//!
//! Ordering: Device-nGnRnE memory (attribute index 0, set up by the paging
//! module) makes these accesses non-gathering, non-reordering and
//! non-early-acknowledging, which is what device registers require. Before
//! the MMU is enabled all memory is Device-nGnRnE by default, so early
//! console output is correctly ordered without additional barriers.
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
