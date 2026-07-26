// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Legacy 8259 PIC and 8253/8254 PIT: the minimal honest timer tick for
//! the boot CPU. The local APIC and a paravirtual clock replace these with
//! the SMP and time-subsystem milestones; everything here is confined to
//! this file so that swap is local.
//!
//! Unexpected interrupts are counted, never silently dropped
//! (docs/lifecycle/04, "No Silent Fallback").
//!
//! Normative: docs/kernel/01-kernel-model.md ("Time"),
//! docs/hardware/01-platform-and-cpu-support.md
//! Budget: none (init path; tick handler is counting only)

use crate::io::{inb, outb};
use core::sync::atomic::{AtomicU64, Ordering};
use tessera_karch::TimerControl;

/// Exception vectors end at 31; the PICs are remapped directly above.
pub(crate) const IRQ_BASE: u64 = 32;
pub(crate) const IRQ_COUNT: u64 = 16;
const TIMER_VECTOR: u64 = IRQ_BASE;

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xa0;
const PIC2_DATA: u16 = 0xa1;
const EOI: u8 = 0x20;

const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_HZ: u64 = 1_193_182;

static TICKS: AtomicU64 = AtomicU64::new(0);
static UNEXPECTED_IRQS: AtomicU64 = AtomicU64::new(0);

/// Remaps the PICs above the exception vectors and masks every line
/// except the timer (IRQ0).
pub fn init_pic() {
    // SAFETY: the canonical 8259 ICW1-ICW4 initialization sequence; this
    // module owns both PICs, and interrupts are still disabled.
    unsafe {
        outb(PIC1_CMD, 0x11); // ICW1: init, expect ICW4
        outb(PIC2_CMD, 0x11);
        outb(PIC1_DATA, IRQ_BASE as u8); // ICW2: vector offsets
        outb(PIC2_DATA, IRQ_BASE as u8 + 8);
        outb(PIC1_DATA, 1 << 2); // ICW3: slave on line 2
        outb(PIC2_DATA, 2);
        outb(PIC1_DATA, 0x01); // ICW4: 8086 mode
        outb(PIC2_DATA, 0x01);
        outb(PIC1_DATA, 0xfe); // mask all but IRQ0
        outb(PIC2_DATA, 0xff);
    }
}

/// The PIT as the boot CPU's periodic tick source.
pub struct Pit;

impl TimerControl for Pit {
    fn start_periodic(hz: u32) {
        let divisor = (PIT_HZ / u64::from(hz.max(19))).min(0xffff) as u16;
        // SAFETY: channel 0, rate generator, lo/hi byte access — the
        // documented PIT programming sequence; this module owns the PIT.
        unsafe {
            outb(PIT_COMMAND, 0x34);
            outb(PIT_CHANNEL0, divisor as u8);
            outb(PIT_CHANNEL0, (divisor >> 8) as u8);
        }
    }

    fn ticks() -> u64 {
        TICKS.load(Ordering::Relaxed)
    }
}

/// IRQs masked at the PIC that fired anyway (spurious or misrouted).
pub fn unexpected_irqs() -> u64 {
    UNEXPECTED_IRQS.load(Ordering::Relaxed)
}

/// Unmasks (enables delivery of) PIC line `line` (0..16). For a slave line
/// (8..16) the master's cascade input (IRQ2) is unmasked too. This is how a
/// driver host's device interrupt is turned on beyond the timer.
pub fn unmask_irq(line: u8) {
    // SAFETY: read-modify-write of the PIC interrupt mask register (the data
    // port reads back the IMR); this module owns both PICs.
    unsafe {
        if line < 8 {
            let mask = inb(PIC1_DATA);
            outb(PIC1_DATA, mask & !(1 << line));
        } else {
            let mask = inb(PIC2_DATA);
            outb(PIC2_DATA, mask & !(1 << (line - 8)));
            let cascade = inb(PIC1_DATA);
            outb(PIC1_DATA, cascade & !(1 << 2));
        }
    }
}

/// Masks (disables delivery of) PIC line `line` (0..16).
pub fn mask_irq(line: u8) {
    // SAFETY: read-modify-write of the PIC interrupt mask register.
    unsafe {
        if line < 8 {
            let mask = inb(PIC1_DATA);
            outb(PIC1_DATA, mask | (1 << line));
        } else {
            let mask = inb(PIC2_DATA);
            outb(PIC2_DATA, mask | (1 << (line - 8)));
        }
    }
}

/// Called from the trap dispatcher for vectors in the PIC range.
pub(crate) fn handle_irq(vector: u64) {
    if vector == TIMER_VECTOR {
        TICKS.fetch_add(1, Ordering::Relaxed);
    } else {
        UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: acknowledging the interrupt we are inside of; slave lines
    // need both controllers acknowledged.
    unsafe {
        if vector >= IRQ_BASE + 8 {
            outb(PIC2_CMD, EOI);
        }
        outb(PIC1_CMD, EOI);
    }
}
