// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The I/O interrupt controller: where a device line becomes a vector on a
//! chosen CPU.
//!
//! # What it replaced
//!
//! The 8259 pair had a mask register and an end-of-interrupt command, and
//! delivered whatever it delivered to whichever CPU the chipset had wired it
//! to. This has a redirection table instead: one entry per input line, and each
//! entry names the vector, the delivery mode, the polarity, the trigger, and —
//! the part with no 8259 analogue — *which CPU* is to take it. That last field
//! is why the legacy pair could not survive SMP: it has no way to express the
//! question.
//!
//! # The indirect register window
//!
//! Two registers, not a register file: write an index to the selector and the
//! data appears in the window sixteen bytes later. Every access is therefore
//! two writes or a write and a read, and they are not independent — a second
//! CPU interleaving its own selector write between this CPU's two would read or
//! write the wrong entry. Nothing in this milestone touches it from more than
//! one CPU, and when something does, this is the register that needs the lock.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Interrupt
//! controller interface"), build/README.md D87
//! Budget: none (init and mask/unmask paths)

use core::sync::atomic::{AtomicU64, Ordering};

/// The index selector.
const IOREGSEL: usize = 0x00;
/// The data window the selector opens onto.
const IOWIN: usize = 0x10;

/// Version register; its bits 23:16 are the highest redirection entry.
const REG_VERSION: u32 = 0x01;
/// The first redirection entry. Each takes two registers, low then high.
const REG_REDIRECTION: u32 = 0x10;

/// Redirection entry, low word: the entry is masked.
const ENTRY_MASKED: u32 = 1 << 16;

/// Redirection entry, high word: this entry is in the remappable format — bit
/// 48 of the entry, which is bit 16 of its high word.
const ENTRY_REMAPPABLE: u32 = 1 << 16;

/// Where the register window is mapped, or zero before the boot glue says.
static BASE: AtomicU64 = AtomicU64::new(0);
/// How many input lines this controller has, once known.
static LINES: AtomicU64 = AtomicU64::new(0);

/// Records where the boot glue mapped the controller and masks every line.
///
/// Returns how many input lines it has, or `None` when the device does not
/// describe a usable number — an absent device reads as all-ones, and a
/// controller with 255 lines is that, not a large machine.
///
/// Masking everything is the point of the boot pass: the reset state of these
/// entries is not architecturally specified, and firmware has been here first.
///
/// # Safety
///
/// `base` must be this controller's register window, mapped as uncached device
/// memory, for the life of the kernel.
pub unsafe fn init(base: u64) -> Option<u64> {
    BASE.store(base, Ordering::Release);
    // SAFETY: the caller's contract — `base` is the mapped register window.
    let version = unsafe { read(REG_VERSION) };
    let lines = u64::from((version >> 16) & 0xff) + 1;
    if lines <= 1 || lines > 240 {
        BASE.store(0, Ordering::Release);
        return None;
    }
    LINES.store(lines, Ordering::Release);
    for line in 0..lines as u32 {
        // SAFETY: as above; `line` is below the count just read.
        unsafe {
            write(REG_REDIRECTION + line * 2, ENTRY_MASKED);
            write(REG_REDIRECTION + line * 2 + 1, 0);
        }
    }
    Some(lines)
}

/// Routes input `line` to `vector` on the CPU whose local-controller
/// identifier is `dest`, and unmasks it.
///
/// Left at the reset polarity and trigger — active high, edge — which is what
/// the ISA lines this port routes are. A line that needed level triggering
/// would need this to say so; none does, and inventing a parameter no caller
/// can set correctly would be worse than the assumption stated here.
///
/// Returns `false` when there is no such line.
///
/// # Safety
///
/// `vector` must be present in the interrupt descriptor table of the CPU named
/// by `dest`, and that CPU's local controller must be enabled.
pub unsafe fn route(line: u8, vector: u8, dest: u32) -> bool {
    if !exists(line) {
        return false;
    }
    // SAFETY: the caller's contract, and `line` is within the count. The high
    // word is written first: it names the destination, and an entry unmasked
    // before its destination was set would deliver to whoever the reset value
    // named.
    unsafe {
        write(REG_REDIRECTION + u32::from(line) * 2 + 1, dest << 24);
        write(REG_REDIRECTION + u32::from(line) * 2, u32::from(vector));
    }
    true
}

/// Routes input `line` to `handle` in a remapping unit's interrupt table, and
/// unmasks it.
///
/// **The entry stops naming a vector and starts naming an index.** In this
/// format the controller writes a *handle* into the interrupt window instead of
/// a destination and a vector, and which CPU takes it and on which vector is
/// whatever the remapping unit's table says — so the two fields this kernel
/// used to choose here are chosen there instead, in memory a device cannot
/// write. Bit 48 is what tells the controller which format its entry is in,
/// bits 63:49 carry the handle's low fifteen bits and bit 11 its sixteenth.
///
/// The vector field is still written, and is still this kernel's convention for
/// the line: hardware ignores it in this format, and leaving it correct means
/// an entry read back says which line it is without having to consult the
/// remapping table.
///
/// Returns `false` when there is no such line.
///
/// # Safety
///
/// As [`route`], and `handle` must be an entry a remapping unit holds for this
/// controller — one naming a vector present in the destination CPU's table.
pub unsafe fn route_remapped(line: u8, vector: u8, handle: u16) -> bool {
    if !exists(line) {
        return false;
    }
    let low = u32::from(vector) | (u32::from(handle >> 15) << 11);
    let high = (u32::from(handle & 0x7fff) << 17) | ENTRY_REMAPPABLE;
    // SAFETY: the caller's contract, and `line` is within the count. The high
    // word first, for `route`'s reason: it carries the format bit and most of
    // the handle, and an entry unmasked before them is one delivered as if it
    // were in the old format.
    unsafe {
        write(REG_REDIRECTION + u32::from(line) * 2 + 1, high);
        write(REG_REDIRECTION + u32::from(line) * 2, low);
    }
    true
}

/// Masks input `line`, so nothing is delivered from it.
///
/// # Safety
///
/// The controller must be initialized.
pub unsafe fn mask(line: u8) {
    if !exists(line) {
        return;
    }
    // SAFETY: the caller's contract; a read-modify-write of one entry's low
    // word, which disturbs no other line.
    unsafe {
        let entry = read(REG_REDIRECTION + u32::from(line) * 2);
        write(REG_REDIRECTION + u32::from(line) * 2, entry | ENTRY_MASKED);
    }
}

/// Unmasks input `line`, which [`route`] must have aimed somewhere first.
///
/// # Safety
///
/// As [`route`], for whatever this line was last routed to.
pub unsafe fn unmask(line: u8) {
    if !exists(line) {
        return;
    }
    // SAFETY: as `mask`.
    unsafe {
        let entry = read(REG_REDIRECTION + u32::from(line) * 2);
        write(REG_REDIRECTION + u32::from(line) * 2, entry & !ENTRY_MASKED);
    }
}

/// Whether the controller is initialized and has this input line.
fn exists(line: u8) -> bool {
    BASE.load(Ordering::Acquire) != 0 && u64::from(line) < LINES.load(Ordering::Acquire)
}

/// # Safety
///
/// [`BASE`] must hold a mapped register window.
unsafe fn read(index: u32) -> u32 {
    let base = BASE.load(Ordering::Acquire) as *mut u32;
    // SAFETY: the caller's contract. The selector write is what makes the
    // window read meaningful, and the two are one operation.
    unsafe {
        base.byte_add(IOREGSEL).write_volatile(index);
        base.byte_add(IOWIN).read_volatile()
    }
}

/// # Safety
///
/// As [`read`], and the write must be one this controller accepts.
unsafe fn write(index: u32, value: u32) {
    let base = BASE.load(Ordering::Acquire) as *mut u32;
    // SAFETY: the caller's contract.
    unsafe {
        base.byte_add(IOREGSEL).write_volatile(index);
        base.byte_add(IOWIN).write_volatile(value);
    }
}
