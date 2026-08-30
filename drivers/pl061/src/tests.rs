// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A mock PL061, written so that the mistake this transport invites is
//! **visible** rather than harmless.
//!
//! The data register is addressed by mask, so a driver that wrote a single pin
//! through offset zero would write all eight — and the pin it meant to change
//! would change, which is what makes the bug survive a casual test. This mock
//! models the masking exactly, so the neighbours it clobbers can be asserted
//! on.
//!
//! Core-only (`RefCell`), matching the crate's `no_std` stance.

use super::*;
use core::cell::RefCell;

#[derive(Default)]
struct State {
    dir: u32,
    is: u32,
    ibe: u32,
    iev: u32,
    ie: u32,
    /// What the driver has driven onto the output pins.
    out: u8,
    /// What the world is driving onto the input pins.
    input: u8,
    /// Lines currently asserting, before the mask.
    raw: u8,
    /// Whether this window holds a PrimeCell at all.
    present: bool,
    /// The part number its identification registers report.
    part: u32,
}

struct MockPl061 {
    state: RefCell<State>,
}

impl MockPl061 {
    fn new() -> MockPl061 {
        MockPl061 {
            state: RefCell::new(State {
                present: true,
                part: PL061_PART,
                ..State::default()
            }),
        }
    }

    /// The world pulls a line, as a button wired to it would.
    fn drive_input(&self, line: u8, level: bool) {
        let mut st = self.state.borrow_mut();
        let mask = 1u8 << line;
        if level {
            st.input |= mask;
            // An edge on a line configured for it latches in the raw status.
            if u32::from(mask) & st.is == 0 {
                st.raw |= mask;
            }
        } else {
            st.input &= !mask;
        }
        // A level-sensed line asserts while the level is there.
        for line in 0..LINES {
            let mask = 1u8 << line;
            if u32::from(mask) & st.is != 0 {
                let high = st.input & mask != 0;
                let wants_high = u32::from(mask) & st.iev != 0;
                if high == wants_high {
                    st.raw |= mask;
                } else {
                    st.raw &= !mask;
                }
            }
        }
    }

    /// What the pins read as: outputs read back what was driven, inputs read
    /// the world.
    fn pins(st: &State) -> u8 {
        (st.out & st.dir as u8) | (st.input & !(st.dir as u8))
    }
}

impl Registers for MockPl061 {
    fn read32(&self, offset: usize) -> u32 {
        let st = self.state.borrow();
        if offset < 0x400 {
            // The data window: address bits 9:2 are the mask, and only those
            // pins come back.
            let mask = (offset >> 2) as u8;
            return u32::from(MockPl061::pins(&st) & mask);
        }
        match offset {
            reg::DIR => st.dir,
            reg::IS => st.is,
            reg::IBE => st.ibe,
            reg::IEV => st.iev,
            reg::IE => st.ie,
            reg::RIS => u32::from(st.raw),
            reg::MIS => u32::from(st.raw) & st.ie,
            o if (reg::PCELL_ID0..reg::PCELL_ID0 + 16).contains(&o) => {
                if !st.present {
                    return 0;
                }
                (PRIMECELL_SIGNATURE >> (((o - reg::PCELL_ID0) / 4) * 8)) & 0xff
            }
            reg::PERIPH_ID0 => st.part & 0xff,
            o if o == reg::PERIPH_ID0 + 4 => (st.part >> 8) & 0xf,
            _ => 0,
        }
    }

    fn write32(&self, offset: usize, value: u32) {
        let mut st = self.state.borrow_mut();
        if offset < 0x400 {
            // **Only the masked pins change.** A write through offset zero has
            // a mask of zero and touches nothing; a write through 0x3fc has a
            // mask of 0xff and touches everything.
            let mask = (offset >> 2) as u8;
            st.out = (st.out & !mask) | (value as u8 & mask);
            return;
        }
        match offset {
            reg::DIR => st.dir = value,
            reg::IS => st.is = value,
            reg::IBE => st.ibe = value,
            reg::IEV => st.iev = value,
            reg::IE => st.ie = value,
            reg::IC => st.raw &= !(value as u8),
            _ => {}
        }
    }
}

/// **The mistake this transport invites, made visible.** A single-pin write
/// through the masked address changes that pin and nothing else. Through offset
/// zero it would reach every pin — and the pin the caller meant would still
/// change, which is exactly why the bug survives a test that only checks the
/// pin it asked about.
#[test]
fn a_single_pin_write_cannot_reach_its_neighbours() {
    let device = MockPl061::new();
    let gpio = Controller::probe(&device).expect("probe");
    for line in 0..LINES {
        gpio.set_direction(line, Direction::Output).expect("dir");
    }
    // Everything high.
    for line in 0..LINES {
        gpio.write(line, true).expect("write");
    }
    assert_eq!(gpio.read_port(), 0xff);

    // Now pull one line down.
    gpio.write(3, false).expect("write");
    assert_eq!(gpio.read_port(), 0xf7, "line 3 down and nothing else moved");
    assert!(!gpio.read(3).expect("read"));
    assert!(gpio.read(4).expect("read"), "its neighbour is untouched");

    // And the address that carries it: the mask is in bits 9:2, so line 3's
    // data lives at 0x20 and not at zero.
    assert_eq!(data_offset(1 << 3), 0x20);
    assert_eq!(data_offset(0xff), 0x3fc);
    assert_eq!(data_offset(0), 0, "a mask of nothing addresses nothing");
}

/// An output reads back what was driven and an input reads the world, which is
/// what makes a loopback test of an output meaningful at all.
#[test]
fn an_output_reads_back_and_an_input_reads_the_world() {
    let device = MockPl061::new();
    let gpio = Controller::probe(&device).expect("probe");
    gpio.set_direction(1, Direction::Output).expect("dir");
    gpio.set_direction(2, Direction::Input).expect("dir");
    assert_eq!(gpio.direction(1).expect("dir"), Direction::Output);
    assert_eq!(gpio.direction(2).expect("dir"), Direction::Input);

    gpio.write(1, true).expect("write");
    assert!(gpio.read(1).expect("read"));
    assert!(!gpio.read(2).expect("read"));
    device.drive_input(2, true);
    assert!(gpio.read(2).expect("read"), "the world moved it");
    // Driving an input goes nowhere, which is the honest behaviour of a pin
    // pointed the other way.
    gpio.write(2, false).expect("write");
    assert!(gpio.read(2).expect("read"));
}

/// A line this controller does not have is an answer, not a read of whatever
/// the arithmetic lands on.
#[test]
fn a_line_that_does_not_exist_is_refused() {
    let device = MockPl061::new();
    let gpio = Controller::probe(&device).expect("probe");
    assert_eq!(gpio.read(LINES), Err(Error::NoSuchLine));
    assert_eq!(gpio.write(LINES, true), Err(Error::NoSuchLine));
    assert_eq!(
        gpio.set_direction(200, Direction::Input),
        Err(Error::NoSuchLine)
    );
    assert_eq!(
        gpio.configure_interrupt(LINES, Trigger::RisingEdge),
        Err(Error::NoSuchLine),
    );
    assert_eq!(gpio.unmask(LINES), Err(Error::NoSuchLine));
}

/// **The three interrupt registers are one decision.** Both-edges means nothing
/// on a level-sensed line and the event bit means nothing when both edges are
/// selected, so a driver writing them separately can leave a line configured
/// for something no caller asked for and no single register reports.
#[test]
fn a_trigger_is_one_decision_across_three_registers() {
    let device = MockPl061::new();
    let gpio = Controller::probe(&device).expect("probe");
    let bits = |offset: usize| device.state.borrow().dir_of(offset);

    gpio.configure_interrupt(2, Trigger::RisingEdge)
        .expect("cfg");
    assert_eq!(bits(reg::IS) & 0b100, 0, "edge");
    assert_eq!(bits(reg::IBE) & 0b100, 0, "one of them");
    assert_ne!(bits(reg::IEV) & 0b100, 0, "the rising one");

    // Changing the same line to a level leaves nothing of the old trigger
    // behind — which is the failure a per-register API produces.
    gpio.configure_interrupt(2, Trigger::LowLevel).expect("cfg");
    assert_ne!(bits(reg::IS) & 0b100, 0, "level");
    assert_eq!(bits(reg::IBE) & 0b100, 0);
    assert_eq!(bits(reg::IEV) & 0b100, 0, "the low one");

    gpio.configure_interrupt(2, Trigger::BothEdges)
        .expect("cfg");
    assert_eq!(bits(reg::IS) & 0b100, 0);
    assert_ne!(bits(reg::IBE) & 0b100, 0);

    // And a line configured is a line still masked: unmasking is its own step,
    // because reconfiguring a level-sensed line asserts it on the way past.
    assert_eq!(bits(reg::IE) & 0b100, 0);
    gpio.unmask(2).expect("unmask");
    assert_ne!(bits(reg::IE) & 0b100, 0);
}

/// **Masked status, not raw.** The raw register says what every line is doing,
/// including the ones deliberately masked off; a driver demultiplexing from it
/// would wake watchers for edges nobody asked about.
#[test]
fn only_unmasked_lines_are_pending() {
    let device = MockPl061::new();
    let gpio = Controller::probe(&device).expect("probe");
    for line in [3u8, 5] {
        gpio.set_direction(line, Direction::Input).expect("dir");
        gpio.configure_interrupt(line, Trigger::RisingEdge)
            .expect("cfg");
    }
    // Only one of them is let through.
    gpio.unmask(3).expect("unmask");

    device.drive_input(3, true);
    device.drive_input(5, true);
    assert_eq!(gpio.raw_pending(), 0b0010_1000, "both lines saw an edge");
    assert_eq!(gpio.pending(), 0b0000_1000, "and one of them is asserting");

    // Acknowledged by name, and only the named one goes away.
    gpio.clear(0b0000_1000);
    assert_eq!(gpio.pending(), 0);
    assert_eq!(gpio.raw_pending(), 0b0010_0000, "line 5 is still latched");
}

/// A level-sensed line asserts while the level is there and stops when it goes,
/// which is what makes clearing one without deasserting it a loop rather than
/// an acknowledgement.
#[test]
fn a_level_line_follows_the_level() {
    let device = MockPl061::new();
    let gpio = Controller::probe(&device).expect("probe");
    gpio.set_direction(1, Direction::Input).expect("dir");
    gpio.configure_interrupt(1, Trigger::HighLevel)
        .expect("cfg");
    gpio.unmask(1).expect("unmask");

    device.drive_input(1, true);
    assert_eq!(gpio.pending(), 0b10);
    // Clearing it while it is still high does not make it go away.
    gpio.clear(0b10);
    device.drive_input(1, true);
    assert_eq!(gpio.pending(), 0b10, "still high, still asserting");
    device.drive_input(1, false);
    assert_eq!(gpio.pending(), 0);
}

/// **A platform device says what it is in its own registers, and nowhere
/// else.** There is no configuration space to read it out of and no bus to ask,
/// so the identification registers are the only source — and a window with
/// nothing in it must not be mistaken for one.
#[test]
fn a_primecell_is_identified_by_its_own_registers() {
    let device = MockPl061::new();
    assert_eq!(identify(&device), Some(PL061_PART));
    assert!(Controller::probe(&device).is_ok());

    // A window with no device in it reads as zeros, which do not spell the
    // signature every PrimeCell has.
    device.state.borrow_mut().present = false;
    assert_eq!(identify(&device), None);
    assert_eq!(
        Controller::probe(&device).map(|_| ()),
        Err(Error::NotAPl061),
    );

    // A PrimeCell that is a different peripheral answers the first question and
    // fails the second, which is the distinction worth having: "there is a
    // device here" and "it is the one I drive" are separate facts.
    {
        let mut st = device.state.borrow_mut();
        st.present = true;
        st.part = 0x011; // a PL011 UART
    }
    assert_eq!(identify(&device), Some(0x011));
    assert_eq!(
        Controller::probe(&device).map(|_| ()),
        Err(Error::NotAPl061),
    );
}

impl State {
    /// One of the configuration registers, for a test that wants to look at
    /// what a call wrote rather than at what the controller reports.
    fn dir_of(&self, offset: usize) -> u32 {
        match offset {
            reg::DIR => self.dir,
            reg::IS => self.is,
            reg::IBE => self.ibe,
            reg::IEV => self.iev,
            reg::IE => self.ie,
            _ => 0,
        }
    }
}
