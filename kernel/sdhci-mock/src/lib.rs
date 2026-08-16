// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A mock SD host controller, so the divider arithmetic, the command word's bit
//! layout, the interrupt-status handshake and the byte order a block arrives in
//! are exercised on the host without any hardware.
//!
//! The mock has a card that can be **taken out**, which is the case this
//! transport exists to handle and the one no other transport in this tree can
//! produce — QEMU's `sdhci-pci` reports a card present in an empty slot, so no
//! machine available here can make a card leave.
//!
//! **One model, two tiers.** This is a crate rather than a test module because
//! two things need it: the transport core, which turns an empty slot into
//! [`tessera_sdhci::Error::NoCard`], and the ring-3 SD driver, which turns that
//! into the block class's `NO_MEDIUM`. A second mock written for the second
//! tier could disagree with this one about when a card is gone, and both suites
//! would still pass while describing different hardware.
//!
//! Test-only: nothing that ships depends on this, and its Bazel target is
//! visible to the two test targets alone.
//!
//! Core-only (fixed arrays and `RefCell`), matching the transport's `no_std`
//! stance.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage")

#![no_std]
#![forbid(unsafe_code)]

use core::cell::RefCell;
use tessera_sdhci::{
    ACMD_SEND_OP_COND, BLOCK_LEN, CMD_ALL_SEND_CID, CMD_SEND_IF_COND, CMD_SEND_RELATIVE_ADDR,
    CMD_WRITE_BLOCK, OP_COND_READY, Registers, irq, present, reg,
};

/// The mock's base clock: 50 MHz, which is what QEMU's sdhci reports.
pub const BASE_MHZ: u32 = 50;
/// The same clock in hertz, which is what a bring-up reports back.
pub const BASE_HZ: u64 = 50_000_000;

/// What the mock's card holds at block zero, before the ramp.
pub const CARD_MAGIC: [u8; 8] = *b"TESSERAS";

/// The byte block zero holds at `index`: the magic, then a recognisable ramp.
///
/// A ramp rather than a magic throughout, because a driver that read the right
/// bytes in the wrong order would pass a magic check on a symmetric value and
/// fail on real data.
pub fn card_byte(index: usize) -> u8 {
    if index < CARD_MAGIC.len() {
        CARD_MAGIC[index]
    } else {
        (index % 251) as u8
    }
}

struct State {
    argument: u32,
    response: [u32; 4],
    status: u32,
    clock_control: u32,
    host_control: u32,
    /// Where the block read is up to, in bytes.
    read_at: usize,
    /// What the last write left on the card, and how far it has got.
    written: [u8; BLOCK_LEN],
    write_at: usize,
    /// Whether a card is in the slot, and whether the controller should fail
    /// the next command.
    card: bool,
    fail_next: Option<u16>,
    /// Commands the mock saw, in order — what a test checks a bring-up
    /// sequence against.
    seen: [u8; 16],
    seen_count: usize,
}

/// A controller with one card in it, which can be taken out.
pub struct MockSdhci {
    state: RefCell<State>,
}

impl Default for MockSdhci {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSdhci {
    /// A controller with a card in the slot and no failure armed.
    pub fn new() -> Self {
        Self {
            state: RefCell::new(State {
                argument: 0,
                response: [0; 4],
                status: 0,
                clock_control: 0,
                host_control: 0,
                read_at: 0,
                written: [0; BLOCK_LEN],
                write_at: 0,
                card: true,
                fail_next: None,
                seen: [0; 16],
                seen_count: 0,
            }),
        }
    }

    /// Takes the card out, as a `device_del` does on the real machine.
    pub fn remove_card(&self) {
        let mut st = self.state.borrow_mut();
        st.card = false;
        st.status |= irq::CARD_REMOVAL;
    }

    /// Puts a card back in.
    ///
    /// A card pulled and pushed back is a **different card**, and the latched
    /// insertion event is how a driver is told that rather than being left to
    /// compare a presence bit against itself.
    pub fn insert_card(&self) {
        let mut st = self.state.borrow_mut();
        st.card = true;
        st.status |= irq::CARD_INSERTION;
    }

    /// Makes the next command fail with `errors` in the error-status half.
    pub fn fail_next_command(&self, errors: u16) {
        self.state.borrow_mut().fail_next = Some(errors);
    }

    /// The commands this controller was issued, in order.
    pub fn commands(&self) -> ([u8; 16], usize) {
        let st = self.state.borrow();
        (st.seen, st.seen_count)
    }

    /// The host-control register, which carries bus power and voltage.
    pub fn host_control(&self) -> u32 {
        self.state.borrow().host_control
    }

    /// The clock-control register, which carries the divider.
    pub fn clock_control(&self) -> u32 {
        self.state.borrow().clock_control
    }

    /// The block the last write left on the card.
    pub fn written(&self) -> [u8; BLOCK_LEN] {
        self.state.borrow().written
    }
}

impl Registers for MockSdhci {
    fn read32(&self, offset: usize) -> u32 {
        let st = self.state.borrow();
        match offset {
            reg::CAPABILITIES => BASE_MHZ << 8,
            reg::PRESENT_STATE => {
                let mut state = 0;
                if st.card {
                    state |= present::CARD_INSERTED;
                }
                if st.status & irq::BUFFER_READ_READY != 0 {
                    // Bit 11 of the present state: the buffer holds data the
                    // driver may read. Modelled here rather than named in the
                    // core, which waits on the interrupt bit — the two say the
                    // same thing and a driver needs only one of them.
                    state |= 1 << 11;
                }
                state
            }
            // The internal clock reads back stable the moment it is enabled,
            // which is what a controller with nothing to spin up does.
            reg::CLOCK_CONTROL => {
                if st.clock_control & 1 != 0 {
                    st.clock_control | 0b10
                } else {
                    st.clock_control
                }
            }
            reg::HOST_CONTROL => st.host_control,
            reg::INT_STATUS => st.status,
            reg::RESPONSE0 => st.response[0],
            o if o == reg::RESPONSE0 + 4 => st.response[1],
            o if o == reg::RESPONSE0 + 8 => st.response[2],
            o if o == reg::RESPONSE0 + 12 => st.response[3],
            reg::BUFFER => {
                drop(st);
                let mut st = self.state.borrow_mut();
                let at = st.read_at;
                st.read_at += 4;
                let mut word = [0u8; 4];
                for (i, byte) in word.iter_mut().enumerate() {
                    *byte = card_byte(at + i);
                }
                if st.read_at >= BLOCK_LEN {
                    st.status |= irq::TRANSFER_COMPLETE;
                    st.status &= !irq::BUFFER_READ_READY;
                }
                u32::from_le_bytes(word)
            }
            _ => 0,
        }
    }

    fn write32(&self, offset: usize, value: u32) {
        let mut st = self.state.borrow_mut();
        match offset {
            reg::CLOCK_CONTROL => {
                // A software reset clears itself, as a controller with nothing
                // to unwind does.
                st.clock_control = value & 0xffff;
            }
            reg::HOST_CONTROL => st.host_control = value,
            reg::ARGUMENT => st.argument = value,
            reg::BUFFER => {
                let at = st.write_at;
                for (i, byte) in value.to_le_bytes().iter().enumerate() {
                    if at + i < BLOCK_LEN {
                        st.written[at + i] = *byte;
                    }
                }
                st.write_at += 4;
                if st.write_at >= BLOCK_LEN {
                    st.status |= irq::TRANSFER_COMPLETE;
                    st.status &= !irq::BUFFER_WRITE_READY;
                }
            }
            reg::INT_STATUS => st.status &= !value,
            reg::COMMAND => {
                let command = (value >> 16) as u16;
                let index = (command >> 8) as u8;
                let data = command & (1 << 5) != 0;
                if st.seen_count < st.seen.len() {
                    let at = st.seen_count;
                    st.seen[at] = index;
                    st.seen_count += 1;
                }
                if let Some(errors) = st.fail_next.take() {
                    st.status |= irq::ERROR | (u32::from(errors) << 16);
                    return;
                }
                // What the card answers, per command.
                st.response = [0; 4];
                match index {
                    CMD_SEND_IF_COND => st.response[0] = st.argument,
                    ACMD_SEND_OP_COND => st.response[0] = OP_COND_READY | 0x00ff_8000,
                    CMD_ALL_SEND_CID => st.response = [1, 2, 3, 4],
                    CMD_SEND_RELATIVE_ADDR => st.response[0] = 0xaaaa_0000,
                    _ => st.response[0] = 0x0000_0900,
                }
                st.status |= irq::COMMAND_COMPLETE;
                match index {
                    _ if !data => {}
                    CMD_WRITE_BLOCK => {
                        st.write_at = 0;
                        st.status |= irq::BUFFER_WRITE_READY;
                    }
                    _ => {
                        st.read_at = 0;
                        st.status |= irq::BUFFER_READ_READY;
                    }
                }
            }
            _ => {}
        }
    }
}
