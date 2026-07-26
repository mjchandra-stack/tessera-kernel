// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! 16550 UART early console, polled TX only. This is the boot and panic
//! output channel; interrupt-driven serial belongs to a driver host in
//! user space, never here (docs/kernel/01, "What the kernel does NOT do").
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Virtual
//! Platform Support")
//! Budget: none (init and panic paths)

use crate::io::{inb, outb};
use tessera_karch::EarlyConsole;

const COM1: u16 = 0x3f8;

// Register offsets from the port base.
const DATA: u16 = 0;
const INT_ENABLE: u16 = 1;
const FIFO_CTRL: u16 = 2;
const LINE_CTRL: u16 = 3;
const MODEM_CTRL: u16 = 4;
const LINE_STATUS: u16 = 5;

const LSR_THR_EMPTY: u8 = 1 << 5;

pub struct Uart16550 {
    base: u16,
    initialized: bool,
}

impl Uart16550 {
    /// The classic COM1 port, present on the QEMU q35 machine.
    pub const fn com1() -> Self {
        Self {
            base: COM1,
            initialized: false,
        }
    }

    /// Programs 115200 8N1 with FIFOs enabled and interrupts off.
    pub fn init(&mut self) {
        // SAFETY: this type owns the UART at `base` (single instance
        // created by the boot path); the sequence follows the 16550
        // datasheet and touches only this device's registers.
        unsafe {
            outb(self.base + INT_ENABLE, 0x00); // no interrupts, polled only
            outb(self.base + LINE_CTRL, 0x80); // DLAB on
            outb(self.base + DATA, 0x01); // divisor 1 -> 115200 baud
            outb(self.base + INT_ENABLE, 0x00); // divisor high byte
            outb(self.base + LINE_CTRL, 0x03); // 8N1, DLAB off
            outb(self.base + FIFO_CTRL, 0xc7); // FIFO on, clear, 14-byte
            outb(self.base + MODEM_CTRL, 0x03); // DTR | RTS
        }
        self.initialized = true;
    }

    fn write_byte(&mut self, byte: u8) {
        if !self.initialized {
            return;
        }
        // SAFETY: device ownership as in `init`; LSR polling then THR write
        // is the documented polled-TX sequence.
        unsafe {
            while inb(self.base + LINE_STATUS) & LSR_THR_EMPTY == 0 {
                core::hint::spin_loop();
            }
            outb(self.base + DATA, byte);
        }
    }
}

impl EarlyConsole for Uart16550 {
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
