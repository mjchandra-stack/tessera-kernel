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

use core::sync::atomic::{AtomicUsize, Ordering};

/// The offset added to a fixed platform-device physical address to reach it
/// through the current kernel address space.
///
/// The two ARM ports answer this differently, which is the whole reason it is
/// a variable. AArch64 keeps the platform's device identity map in `TTBR0`
/// alongside its high kernel, so a device register's physical address is
/// still a valid address and the offset is zero. ARM 32-bit empties its user
/// half — that is what makes a per-process `TTBR0` mean anything — so the
/// same register is reached only through the kernel's direct map, at
/// `DIRECT_MAP_BASE + phys`.
///
/// It is *not* a per-device mapping base: a driver whose registers come from
/// a capability gets its window from the address space. This covers only the
/// handful of devices whose addresses are properties of the machine and are
/// mapped once, by boot, for the life of the kernel.
static DEVICE_ACCESS_BASE: AtomicUsize = AtomicUsize::new(0);

/// Points fixed-address device access at `base + phys`.
///
/// Called once by a port whose kernel space does not also carry the devices
/// at their physical addresses. A port that leaves it alone gets the identity
/// behaviour, which is why AArch64 never calls it.
///
/// # Safety
///
/// `base` must be the base of a live mapping covering the platform's device
/// range with kernel read-write access, and must stay live for as long as the
/// kernel runs.
pub unsafe fn set_device_access_base(base: usize) {
    DEVICE_ACCESS_BASE.store(base, Ordering::Relaxed);
}

/// The address at which the fixed-address device at physical `phys` is
/// currently reachable.
///
/// Relaxed is the right ordering: the value is written once during boot,
/// before interrupts are enabled and before any other core exists, so there
/// is no release/acquire pairing to establish — only the atomicity that makes
/// a shared mutable `usize` legal at all.
#[inline]
pub fn device_addr(phys: usize) -> usize {
    DEVICE_ACCESS_BASE.load(Ordering::Relaxed) + phys
}

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
