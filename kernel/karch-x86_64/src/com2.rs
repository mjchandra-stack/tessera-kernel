// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! COM2 (0x2f8) 16550 UART as an M16 driver-host device — distinct from the
//! COM1 early console (`uart.rs`), so the kernel's own logging is unaffected.
//! Configured for internal loopback (MCR bit 4) so a byte written to THR loops
//! back to RBR and raises IRQ3, giving a deterministic device interrupt with no
//! external serial input (the CI boot has no serial stdin). The ring-3 driver
//! host drives this device through the capability-gated `DeviceIo` syscall;
//! this module is the thin register-access primitive behind that capability.
//!
//! Normative: docs/drivers/01-driver-framework.md ("User-Space Driver Hosts"),
//! docs/hardware/01-platform-and-cpu-support.md ("Virtual Platform Support")
//! Budget: none (device bring-up + single-byte I/O)

use crate::io::{inb, outb};

/// COM2 I/O port base.
pub const BASE: u16 = 0x2f8;
/// Number of byte-wide registers in the device's I/O span.
pub const SPAN: u8 = 8;

// 16550 register offsets from `BASE` (offset 0 is RBR on read / THR on write).
const IER: u16 = 1;
const FIFO_CTRL: u16 = 2;
const LINE_CTRL: u16 = 3;
const MODEM_CTRL: u16 = 4;

/// Programs COM2 for 8N1 at 115200, FIFOs off (one RX interrupt per byte),
/// internal loopback (MCR LOOP), OUT2 gating the IRQ line, and the
/// receive-data-available interrupt enabled — so a write to THR loops to RBR
/// and raises IRQ3.
pub fn init_loopback() {
    // SAFETY: this module owns COM2 (0x2f8); the sequence follows the 16550
    // datasheet and touches only this device's registers. COM2 is separate from
    // the COM1 console (`uart.rs`), so kernel logging is unaffected.
    unsafe {
        outb(BASE + LINE_CTRL, 0x80); // DLAB on
        outb(BASE, 0x01); // divisor low = 1 -> 115200 baud
        outb(BASE + IER, 0x00); // divisor high = 0
        outb(BASE + LINE_CTRL, 0x03); // 8N1, DLAB off
        outb(BASE + FIFO_CTRL, 0x00); // FIFO off: one RX interrupt per byte
        outb(BASE + MODEM_CTRL, 0x1b); // LOOP | OUT2 | RTS | DTR
        outb(BASE + IER, 0x01); // enable receive-data-available interrupt
    }
}

/// Reads register `offset` (masked to the device's 8-register span) of COM2.
pub fn read(offset: u8) -> u8 {
    let offset = u16::from(offset & (SPAN - 1));
    // SAFETY: COM2 ownership; `offset` is bounded to the device's register span.
    unsafe { inb(BASE + offset) }
}

/// Writes `value` to register `offset` (masked to the device's span) of COM2.
pub fn write(offset: u8, value: u8) {
    let offset = u16::from(offset & (SPAN - 1));
    // SAFETY: COM2 ownership; `offset` is bounded to the device's register span.
    unsafe { outb(BASE + offset, value) }
}
