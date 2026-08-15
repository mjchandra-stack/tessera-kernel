// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! GICv2 interrupt controller: distributor plus per-CPU interface.
//!
//! The x86-64 port's counterpart is the 8259 PIC (`karch-x86_64/src/timer.rs`),
//! and the shapes are not comparable the way paging and context switching
//! were. A PIC has a mask register and an end-of-interrupt command. A GIC
//! splits into a *distributor* that decides which CPU an interrupt goes to
//! and a *CPU interface* that the local core acknowledges through, and the
//! acknowledge itself returns the interrupt number rather than the core
//! having to ask. That is why this is its own module here and a few functions
//! there.
//!
//! Priority is not a decoration on this controller: an interrupt whose
//! priority is not strictly below the CPU interface's mask is never
//! delivered, so `PRIORITY_MASK` and the per-interrupt priority set here have
//! to agree or the timer simply never fires — silently, with everything else
//! working.
//!
//! GICv2 is pinned rather than probed. Version 3 replaces the CPU interface
//! with system registers (`ICC_*`) and is a different driver, so the smoke
//! test names `gic-version=2` explicitly instead of taking QEMU's default,
//! which would otherwise change under us between releases.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Interrupt
//! controller interface"), docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (interrupt entry is budgeted with the tick path)

use crate::mmio::{device_addr, read32, write32};

/// Distributor and CPU-interface bases on the QEMU `virt` machine.
/// The distributor's **physical** base. Every derived address below is
/// physical too, and each access site converts through [`device_addr`],
/// because the two ARM ports reach the GIC through different windows: AArch64
/// keeps the device identity map in `TTBR0`, ARM 32-bit empties it.
const GICD: usize = 0x0800_0000;
const GICC: usize = 0x0801_0000;

// Distributor registers.
const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_IPRIORITYR: usize = 0x400;

// CPU-interface registers.
const GICC_CTLR: usize = 0x00;
const GICC_PMR: usize = 0x04;
const GICC_IAR: usize = 0x0c;
const GICC_EOIR: usize = 0x10;

/// Priority mask: the CPU interface delivers only interrupts whose priority
/// value is numerically *lower* than this. Interrupts are configured at
/// [`INTERRUPT_PRIORITY`], which is below it.
const PRIORITY_MASK: u32 = 0xf0;
const INTERRUPT_PRIORITY: u8 = 0xa0;

/// Interrupt IDs at or above this are the architecture's "no interrupt
/// pending" replies (1020-1023, chiefly the spurious 1023). They are the one
/// acknowledge that must *not* be followed by an end-of-interrupt.
const SPURIOUS_FLOOR: u32 = 1020;

/// The interrupt ID field of an acknowledgement.
const INTID_MASK: u32 = 0x3ff;

/// Brings up the distributor and this CPU's interface.
///
/// # Safety
///
/// The GIC's registers must be mapped as device memory at the addresses
/// above, and this must run once on the boot CPU before interrupts are
/// unmasked.
pub unsafe fn init() {
    // SAFETY: the caller guarantees the distributor and CPU interface are
    // mapped device memory; these writes touch only their own registers.
    unsafe {
        // Distributor off while it is reconfigured, then on.
        write32(device_addr(GICD + GICD_CTLR), 0);
        // Accept any priority at this core, then enable the interface.
        write32(device_addr(GICC + GICC_PMR), PRIORITY_MASK);
        write32(device_addr(GICC + GICC_CTLR), 1);
        write32(device_addr(GICD + GICD_CTLR), 1);
    }
}

/// Routes `intid` to this CPU and enables it.
///
/// # Safety
///
/// [`init`] must have run, and the caller must be entitled to take this
/// interrupt.
pub unsafe fn enable(intid: u32) {
    // SAFETY: mapped device memory, per `init`'s contract. The priority write
    // is byte-wide because IPRIORITYR is a byte-per-interrupt array; the
    // enable is a write-1-to-set bit, so it disturbs no other interrupt.
    unsafe {
        let priority = device_addr(GICD + GICD_IPRIORITYR + intid as usize) as *mut u8;
        priority.write_volatile(INTERRUPT_PRIORITY);
        let bank = (intid / 32) as usize * 4;
        write32(device_addr(GICD + GICD_ISENABLER + bank), 1 << (intid % 32));
    }
}

/// Disables `intid` at the distributor.
///
/// # Safety
///
/// [`init`] must have run.
pub unsafe fn disable(intid: u32) {
    // SAFETY: mapped device memory; ICENABLER is write-1-to-clear, so this
    // disturbs no other interrupt.
    unsafe {
        let bank = (intid / 32) as usize * 4;
        write32(device_addr(GICD + GICD_ICENABLER + bank), 1 << (intid % 32));
    }
}

/// Acknowledges the highest-priority pending interrupt, returning the raw
/// acknowledgement. Pass it back to [`end_of_interrupt`] unchanged — it
/// carries the source CPU alongside the ID, and the controller wants both.
///
/// # Safety
///
/// Call only from interrupt context on a core whose interface is initialized.
pub unsafe fn acknowledge() -> u32 {
    // SAFETY: mapped device memory. Reading IAR has the side effect of
    // acknowledging, which is exactly the intent here.
    unsafe { read32(device_addr(GICC + GICC_IAR)) }
}

/// Signals completion of the interrupt `acknowledgement` identified.
///
/// # Safety
///
/// `acknowledgement` must be a value [`acknowledge`] returned on this core,
/// and must not be a spurious reply (see [`intid`]).
pub unsafe fn end_of_interrupt(acknowledgement: u32) {
    // SAFETY: mapped device memory; writing EOIR completes the interrupt the
    // caller acknowledged.
    unsafe { write32(device_addr(GICC + GICC_EOIR), acknowledgement) }
}

/// The interrupt ID an acknowledgement names.
pub const fn intid(acknowledgement: u32) -> u32 {
    acknowledgement & INTID_MASK
}

/// True when an acknowledgement means "nothing to handle" — the case where
/// no end-of-interrupt may be issued.
pub const fn is_spurious(acknowledgement: u32) -> bool {
    intid(acknowledgement) >= SPURIOUS_FLOOR
}
