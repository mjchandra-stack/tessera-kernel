// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! x86 port I/O primitives. Everything device-facing in this crate goes
//! through these two functions.

use core::arch::asm;

/// Writes `value` to I/O port `port`.
///
/// # Safety
///
/// Port I/O has device-defined side effects; the caller must own the device
/// behind `port` and uphold its programming contract.
pub(crate) unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the instruction touches only the named port; the caller's
    // contract covers the device side effects.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Reads a byte from I/O port `port`.
///
/// # Safety
///
/// As for [`outb`]: reads can also have device side effects (FIFO pops,
/// status clears).
pub(crate) unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: as above — single port read under the caller's device
    // ownership contract.
    unsafe {
        asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

/// Reads a byte from a device register, for the capability-gated `DeviceIo`
/// syscall: a driver host with a Device capability accesses `port` (= the
/// resource-graph node's `base` + a validated offset).
///
/// # Safety
///
/// The caller (the syscall) must hold a Device capability whose resource-graph
/// node authorizes `port` — i.e. the offset is bounded by the node's `len` and
/// `port` = `base + offset`. Port reads can have device side effects.
pub unsafe fn device_in(port: u16) -> u8 {
    // SAFETY: the syscall bounds `port` to the granted device's register span.
    unsafe { inb(port) }
}

/// Writes a byte to a device register, for the capability-gated `DeviceIo`
/// syscall. Same authorization contract as [`device_in`].
///
/// # Safety
///
/// As for [`device_in`]: `port` must lie within the caller's granted device
/// range; the write has device-defined side effects.
pub unsafe fn device_out(port: u16, value: u8) {
    // SAFETY: the syscall bounds `port` to the granted device's register span.
    unsafe { outb(port, value) }
}
