// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The platform-level interrupt controller: this architecture's answer to the
//! GIC and the APIC.
//!
//! The PLIC's model is narrower than either, and the narrowness is what makes
//! it simple. It routes only *external* device interrupts — timer and
//! software interrupts never pass through it, they are CSR bits — and it does
//! so through a claim/complete handshake rather than an acknowledge/EOI pair
//! over a priority stack. A hart reads the claim register, which atomically
//! returns the highest-priority pending source and marks it in-flight; when
//! the driver is done the hart writes the same number back, and only then can
//! that source fire again.
//!
//! Two consequences worth stating. Reading the claim register is not a query
//! — it *takes* the interrupt, so it must not be done speculatively. And a
//! claim of zero means "nothing pending", which is why source 0 is reserved
//! and never assigned to a device.
//!
//! A **context** is a (hart, privilege level) pair, and each has its own
//! enable bits, threshold, and claim register. This kernel runs supervisor
//! mode on the boot hart, which is context 1 on the `virt` machine (context 0
//! is that hart's machine mode, which belongs to firmware). Contexts become
//! interesting with SMP; until then one is addressed and the rest are left
//! exactly as firmware set them.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Interrupt
//! controller interface")
//! Budget: none (interrupt path counted with the tick)

use crate::mmio::{device_addr, read32, write32};

/// The `virt` machine's PLIC — its **physical** base. Every derived address
/// below is physical too, and each access site converts through
/// [`device_addr`], because the two ports reach it through different windows.
const PLIC_BASE: usize = 0x0c00_0000;

/// Per-source priority registers, one 32-bit word each, indexed by source.
const PRIORITY_BASE: usize = PLIC_BASE;

/// Per-context enable bitmaps, 0x80 bytes apart.
const ENABLE_BASE: usize = PLIC_BASE + 0x2000;
const ENABLE_STRIDE: usize = 0x80;

/// Per-context threshold and claim/complete block, 0x1000 bytes apart.
const CONTEXT_BASE: usize = PLIC_BASE + 0x20_0000;
const CONTEXT_STRIDE: usize = 0x1000;
const THRESHOLD_OFFSET: usize = 0;
const CLAIM_OFFSET: usize = 4;

/// Supervisor context of hart 0 on the `virt` machine.
const SUPERVISOR_CONTEXT: usize = 1;

/// Priority given to every enabled source. The PLIC compares against the
/// context threshold, and this kernel does not yet rank devices against each
/// other; one non-zero level for everything is the honest encoding of that,
/// rather than a hierarchy nothing chooses.
const DEFAULT_PRIORITY: u32 = 1;

/// Opens this hart's supervisor context: threshold to zero, so any source
/// with a non-zero priority passes. Individual sources stay masked until
/// [`enable`] names them.
///
/// This is the whole of the device's part in coming up. Permitting external
/// interrupts to *reach* the hart at all is a write to `sie`, which is
/// architectural state of the register's width, so it belongs to the port and
/// not here (see the crate header).
///
/// # Safety
///
/// Called once, on the boot hart, with the PLIC mapped read-write and
/// interrupts masked.
pub unsafe fn open_context() {
    // SAFETY: the threshold register belongs to this hart's supervisor
    // context, which this kernel owns; zero means "deliver anything with a
    // priority above zero".
    unsafe {
        write32(
            device_addr(CONTEXT_BASE + SUPERVISOR_CONTEXT * CONTEXT_STRIDE + THRESHOLD_OFFSET),
            0,
        )
    };
}

/// Routes `source` to this hart's supervisor context.
///
/// # Safety
///
/// The PLIC must be mapped read-write, and `source` must be a real interrupt
/// source of this platform (source 0 is reserved and can never fire).
pub unsafe fn enable(source: u32) {
    if source == 0 {
        return;
    }
    let word =
        device_addr(ENABLE_BASE + SUPERVISOR_CONTEXT * ENABLE_STRIDE + (source as usize / 32) * 4);
    // SAFETY: the priority and enable words for this source and context are
    // owned by this kernel; the read-modify-write is safe because this hart is
    // the only writer (single core, D8).
    unsafe {
        write32(
            device_addr(PRIORITY_BASE + source as usize * 4),
            DEFAULT_PRIORITY,
        );
        let bits = read32(word);
        write32(word, bits | (1 << (source % 32)));
    }
}

/// Removes `source` from this hart's supervisor context.
///
/// # Safety
///
/// As [`enable`].
pub unsafe fn disable(source: u32) {
    if source == 0 {
        return;
    }
    let word =
        device_addr(ENABLE_BASE + SUPERVISOR_CONTEXT * ENABLE_STRIDE + (source as usize / 32) * 4);
    // SAFETY: as `enable`.
    unsafe {
        let bits = read32(word);
        write32(word, bits & !(1 << (source % 32)));
    }
}

/// Takes the highest-priority pending source, or `None` if nothing is
/// pending. The caller **must** pass whatever it receives to [`complete`],
/// or that source never fires again.
pub fn claim() -> Option<u32> {
    // SAFETY: the claim register belongs to this hart's supervisor context.
    // The read has a side effect by design — it marks the source in-flight —
    // which is why nothing reads it except this function, called only from the
    // external-interrupt arm of the trap path.
    let source = unsafe {
        read32(device_addr(
            CONTEXT_BASE + SUPERVISOR_CONTEXT * CONTEXT_STRIDE + CLAIM_OFFSET,
        ))
    };
    if source == 0 { None } else { Some(source) }
}

/// Returns a claimed source to the controller, re-arming it.
pub fn complete(source: u32) {
    // SAFETY: as `claim`; writing the claimed number back is the documented
    // completion handshake.
    unsafe {
        write32(
            device_addr(CONTEXT_BASE + SUPERVISOR_CONTEXT * CONTEXT_STRIDE + CLAIM_OFFSET),
            source,
        )
    };
}
