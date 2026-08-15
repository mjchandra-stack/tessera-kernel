// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! PL011 UART early console, polled TX only. This is the boot and panic
//! output channel; interrupt-driven serial belongs to a driver host in user
//! space, never here (docs/kernel/01, "What the kernel does NOT do"). The
//! x86-64 port's 16550 (`karch-x86_64/src/uart.rs`) is the same role on the
//! other machine.
//!
//! The base address is the QEMU `virt` machine's first PL011. Discovering it
//! from the device tree rather than hard-coding it is the platform-support-
//! package job (docs/hardware/01, "Platform Support Package"); the early
//! console must work *before* the device tree is parsed, so it starts from
//! the virtual platform profile's documented address and the discovered one
//! supersedes it later.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Virtual
//! Platform Support")
//! Budget: none (init and panic paths)

use crate::mmio::{read32, write32};
use tessera_karch::EarlyConsole;

/// First PL011 on the QEMU `virt` machine.
const PL011_VIRT: usize = 0x0900_0000;

// Register offsets from the peripheral base.
const DR: usize = 0x00; // data
const FR: usize = 0x18; // flag
const IBRD: usize = 0x24; // integer baud rate divisor
const FBRD: usize = 0x28; // fractional baud rate divisor
const LCRH: usize = 0x2c; // line control
const CR: usize = 0x30; // control
const IMSC: usize = 0x38; // interrupt mask set/clear
const ICR: usize = 0x44; // interrupt clear

const FR_TXFF: u32 = 1 << 5; // transmit FIFO full

const LCRH_FEN: u32 = 1 << 4; // FIFO enable
const LCRH_WLEN_8: u32 = 0b11 << 5; // 8 data bits

const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;

const ICR_ALL: u32 = 0x7ff;

// 115200 8N1 from the 24 MHz UARTCLK the `virt` machine supplies:
// 24_000_000 / (16 * 115_200) = 13.0208..., so the integer divisor is 13 and
// the fractional divisor is round(0.0208... * 64) = 1.
const IBRD_115200: u32 = 13;
const FBRD_115200: u32 = 1;

pub struct Pl011 {
    base: usize,
    initialized: bool,
}

impl Pl011 {
    /// The QEMU `virt` machine's first PL011, at its physical address.
    pub const fn virt() -> Self {
        Self::at(PL011_VIRT)
    }

    /// Its physical base, for a port that must name the same device at a
    /// different virtual address.
    pub const VIRT_BASE: usize = PL011_VIRT;

    /// The same device reached at `base`.
    ///
    /// A kernel that moves into a higher half leaves the physical alias
    /// behind, so the console it had before the switch and the one it has
    /// after are two different addresses for one device — and, because the
    /// pre-switch one is only valid while translation is off, two different
    /// values of this type rather than one with a mutable base.
    pub const fn at(base: usize) -> Self {
        Self {
            base,
            initialized: false,
        }
    }

    /// Programs 115200 8N1 with FIFOs enabled and interrupts off.
    pub fn init(&mut self) {
        // SAFETY: this type owns the PL011 at `base` (a single instance
        // created by the boot path); the sequence follows the PL011 TRM —
        // disable, clear pending interrupts, program the divisors and line
        // control, mask every interrupt, then re-enable — and touches only
        // this device's registers.
        unsafe {
            write32(self.base + CR, 0); // disable while reprogramming
            write32(self.base + ICR, ICR_ALL); // clear pending interrupts
            write32(self.base + IBRD, IBRD_115200);
            write32(self.base + FBRD, FBRD_115200);
            write32(self.base + LCRH, LCRH_WLEN_8 | LCRH_FEN);
            write32(self.base + IMSC, 0); // no interrupts, polled only
            write32(self.base + CR, CR_UARTEN | CR_TXE | CR_RXE);
        }
        self.initialized = true;
    }

    fn write_byte(&mut self, byte: u8) {
        if !self.initialized {
            return;
        }
        // SAFETY: device ownership as in `init`; polling the flag register
        // until the TX FIFO has room and then writing the data register is
        // the documented polled-TX sequence.
        unsafe {
            while read32(self.base + FR) & FR_TXFF != 0 {
                core::hint::spin_loop();
            }
            write32(self.base + DR, u32::from(byte));
        }
    }
}

impl EarlyConsole for Pl011 {
    fn write_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            // Serial terminals expect CRLF.
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}
