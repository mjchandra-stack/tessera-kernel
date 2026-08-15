// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! NS16550A UART early console, polled TX only. This is the boot and panic
//! output channel; interrupt-driven serial belongs to a driver host in user
//! space, never here (docs/kernel/01, "What the kernel does NOT do"). It is
//! the same role the AArch64 port's PL011 and the x86-64 port's 16550 fill,
//! and — because the `virt` machine wires up a 16550 too — the same device
//! family as x86-64's, reached by MMIO instead of port I/O.
//!
//! The base address is the QEMU `virt` machine's `serial@10000000`.
//! Discovering it from the device tree rather than hard-coding it is the
//! platform-support-package job (docs/hardware/01, "Platform Support
//! Package"); the early console must work *before* the device tree is parsed,
//! so it starts from the virtual platform profile's documented address and
//! the discovered one supersedes it later.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Virtual
//! Platform Support")
//! Budget: none (init and panic paths)

use crate::mmio::{read8, write8};
use tessera_karch::EarlyConsole;

/// The `virt` machine's NS16550A.
const NS16550_VIRT: usize = 0x1000_0000;

// Register offsets. The `virt` machine uses a register shift of 0, so each
// register is one byte at its natural offset.
const THR: usize = 0; // transmit holding (write, DLAB=0)
const IER: usize = 1; // interrupt enable (DLAB=0)
const DLL: usize = 0; // divisor latch low (DLAB=1)
const DLM: usize = 1; // divisor latch high (DLAB=1)
const FCR: usize = 2; // FIFO control (write)
const LCR: usize = 3; // line control
const LSR: usize = 5; // line status (read)

const LCR_8N1: u8 = 0b11; // 8 data bits, 1 stop bit, no parity
const LCR_DLAB: u8 = 1 << 7; // divisor latch access

const FCR_ENABLE: u8 = 1 << 0;
const FCR_CLEAR_RX: u8 = 1 << 1;
const FCR_CLEAR_TX: u8 = 1 << 2;

const LSR_THRE: u8 = 1 << 5; // transmit holding register empty

// 115200 8N1 from the 1.8432 MHz reference clock the 16550 divides by 16:
// 1_843_200 / (16 * 115_200) = 1. QEMU does not model baud timing, but
// programming the divisor is part of the documented init sequence and a real
// 16550 needs it.
const DIVISOR_115200: u16 = 1;

pub struct Ns16550a {
    base: usize,
    initialized: bool,
}

impl Ns16550a {
    /// Physical base of the `virt` machine's first NS16550A, for a port that
    /// needs to name the same device at a different virtual address.
    pub const VIRT_BASE: usize = NS16550_VIRT;

    /// The QEMU `virt` machine's first NS16550A, at its physical address.
    pub const fn virt() -> Self {
        Self::at(NS16550_VIRT)
    }

    /// The same device reached at `base`.
    ///
    /// A kernel that moves into a higher half leaves the physical alias behind
    /// — the console has to be re-opened at wherever the device is reachable
    /// now. Marked `initialized` on the assumption a caller naming an explicit
    /// base is re-opening a device already programmed; a fresh device still
    /// needs [`init`](Self::init).
    pub const fn at(base: usize) -> Self {
        Self {
            base,
            initialized: true,
        }
    }

    /// Programs 115200 8N1 with FIFOs enabled and interrupts off.
    pub fn init(&mut self) {
        // SAFETY: this type owns the UART at `base` (a single instance created
        // by the boot path); the sequence follows the 16550 datasheet — mask
        // interrupts, open the divisor latch, program the divisor, close the
        // latch with the line format, reset the FIFOs — and touches only this
        // device's registers.
        unsafe {
            write8(self.base + IER, 0); // no interrupts, polled only
            write8(self.base + LCR, LCR_DLAB);
            write8(self.base + DLL, DIVISOR_115200 as u8);
            write8(self.base + DLM, (DIVISOR_115200 >> 8) as u8);
            write8(self.base + LCR, LCR_8N1); // latch closed, 8N1
            write8(self.base + FCR, FCR_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX);
        }
        self.initialized = true;
    }

    fn write_byte(&mut self, byte: u8) {
        if !self.initialized {
            return;
        }
        // SAFETY: device ownership as in `init`; polling the line-status
        // register until the holding register is empty and then writing it is
        // the documented polled-TX sequence.
        unsafe {
            while read8(self.base + LSR) & LSR_THRE == 0 {
                core::hint::spin_loop();
            }
            write8(self.base + THR, byte);
        }
    }
}

impl EarlyConsole for Ns16550a {
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
