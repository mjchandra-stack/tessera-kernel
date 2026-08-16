// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The PL061 GPIO transport core: direction, level, the interrupt
//! configuration, and the PrimeCell identification registers.
//!
//! Register access goes through the [`Registers`] trait, so the parts that are
//! logic — which offset a pin's data lives at, how an interrupt is configured,
//! and which lines a status word names — are exercised by a mock on the host.
//! The caller supplies the real volatile access; this crate forbids `unsafe`.
//!
//! # The one thing this transport gets wrong more often than the others
//!
//! **The data register is addressed by mask.** `GPIODATA` is not one word: it
//! occupies 256 bytes, and address bits 9:2 are a *pin mask*. A read at offset
//! `mask << 2` returns only those pins; a write there changes only those pins
//! and leaves the rest alone.
//!
//! A driver that used offset zero for a single-pin write would write **every**
//! pin on the port. The failure is silent in the worst way: the pin it meant to
//! change does change, so the write looks like it worked, and the damage is to
//! the seven lines it was not talking about — which on real hardware are
//! somebody else's chip selects and resets.
//!
//! # The other one
//!
//! An interrupt is configured by three registers, not one. `GPIOIS` chooses
//! level or edge, `GPIOIBE` chooses one edge or both, and `GPIOIEV` chooses
//! which. They are not independent: `GPIOIBE` means nothing on a level-sensed
//! line and `GPIOIEV` means nothing when both edges are selected, so a driver
//! setting them one at a time from separate calls can leave a line configured
//! for something no caller asked for. [`Trigger`] is one value for that reason.
//!
//! Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
//! ("GPIO And Pin Control")
//! Budget: none (driven from ring 3)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(test)]
mod tests;

/// Lines one PL061 has. Fixed by the hardware, not a policy bound.
pub const LINES: u8 = 8;

/// What can go wrong. Every variant is a fact about the controller or about
/// what was asked of it, never a programming error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// A line number this controller does not have.
    NoSuchLine,
    /// The controller's identification registers do not say PL061.
    NotAPl061,
}

/// Controller registers, as 32-bit words from the start of the register window.
pub trait Registers {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&self, offset: usize, value: u32);
}

/// Register offsets.
pub mod reg {
    /// Direction: a set bit is an output.
    pub const DIR: usize = 0x400;
    /// Interrupt sense: set for level, clear for edge.
    pub const IS: usize = 0x404;
    /// Interrupt both edges: set to interrupt on either.
    pub const IBE: usize = 0x408;
    /// Interrupt event: set for rising or high, clear for falling or low.
    pub const IEV: usize = 0x40c;
    /// Interrupt mask: set to let a line reach the interrupt output.
    pub const IE: usize = 0x410;
    /// Raw interrupt status — what the lines are doing, mask or no mask.
    pub const RIS: usize = 0x414;
    /// Masked interrupt status: the lines that are actually asserting the
    /// controller's one interrupt output.
    pub const MIS: usize = 0x418;
    /// Interrupt clear, write-one-to-clear.
    pub const IC: usize = 0x41c;
    /// The PrimeCell peripheral identification registers, one byte each in the
    /// low bits of four words.
    pub const PERIPH_ID0: usize = 0xfe0;
    /// The PrimeCell identification registers, which say "this is a PrimeCell"
    /// rather than which one.
    pub const PCELL_ID0: usize = 0xff0;
}

/// The four bytes `PCELLID0..3` spell on any PrimeCell.
pub const PRIMECELL_SIGNATURE: u32 = 0xb105_f00d;
/// The part number in `PERIPHID0..1` for a PL061.
pub const PL061_PART: u32 = 0x061;

/// The address of a pin's data, which is the pin mask shifted into the
/// register's address bits.
///
/// **This is the whole of the data register's oddity in one function.** Bits
/// 9:2 of the offset are the mask, so the pin's own bit position becomes part
/// of the address rather than part of the value.
pub fn data_offset(mask: u8) -> usize {
    (mask as usize) << 2
}

/// How a line's interrupt is triggered.
///
/// One value rather than three registers, because the three are not
/// independent: both-edges means nothing on a level-sensed line, and the event
/// bit means nothing when both edges are selected. A driver that wrote them
/// separately could leave a line configured for something no caller asked for
/// and no register says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trigger {
    RisingEdge,
    FallingEdge,
    BothEdges,
    HighLevel,
    LowLevel,
}

impl Trigger {
    /// The `(sense, both_edges, event)` bits this trigger sets for a line.
    fn bits(self) -> (bool, bool, bool) {
        match self {
            Trigger::RisingEdge => (false, false, true),
            Trigger::FallingEdge => (false, false, false),
            Trigger::BothEdges => (false, true, false),
            Trigger::HighLevel => (true, false, true),
            Trigger::LowLevel => (true, false, false),
        }
    }
}

/// Which way a line faces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Input,
    Output,
}

/// A PL061, and the register window it was found at.
pub struct Controller<'r, R: Registers> {
    regs: &'r R,
}

impl<'r, R: Registers> Controller<'r, R> {
    /// Takes a controller **after checking it is one**.
    ///
    /// A platform device has no configuration space and no magic word: what it
    /// is lives in its own identification registers, which is the only place
    /// it exists. Reading them is the same question PCI asks of config space
    /// and virtio-mmio asks of its magic — asked of the third kind of bus.
    pub fn probe(regs: &'r R) -> Result<Self, Error> {
        if identify(regs) != Some(PL061_PART) {
            return Err(Error::NotAPl061);
        }
        Ok(Controller { regs })
    }

    /// Takes a controller without asking what it is — for a caller that has
    /// already identified it.
    pub fn new(regs: &'r R) -> Self {
        Controller { regs }
    }

    fn check(line: u8) -> Result<u8, Error> {
        if line >= LINES {
            return Err(Error::NoSuchLine);
        }
        Ok(1 << line)
    }

    /// Points a line in or out.
    pub fn set_direction(&self, line: u8, direction: Direction) -> Result<(), Error> {
        let mask = Self::check(line)?;
        let dir = self.regs.read32(reg::DIR);
        let next = match direction {
            Direction::Output => dir | u32::from(mask),
            Direction::Input => dir & !u32::from(mask),
        };
        self.regs.write32(reg::DIR, next);
        Ok(())
    }

    pub fn direction(&self, line: u8) -> Result<Direction, Error> {
        let mask = Self::check(line)?;
        if self.regs.read32(reg::DIR) & u32::from(mask) != 0 {
            Ok(Direction::Output)
        } else {
            Ok(Direction::Input)
        }
    }

    /// Reads one line.
    ///
    /// Through the masked address, so what comes back is that pin and nothing
    /// else — a read at offset zero would return all eight and leave the caller
    /// to mask, which is the same arithmetic done in the wrong place.
    pub fn read(&self, line: u8) -> Result<bool, Error> {
        let mask = Self::check(line)?;
        Ok(self.regs.read32(data_offset(mask)) & u32::from(mask) != 0)
    }

    /// Drives one line, and **only** that line.
    ///
    /// The pin's mask is in the address, so the write cannot reach its
    /// neighbours however wrong the value is. That is the property this
    /// function exists to hold: a driver told to set line 3 must not be able to
    /// clear line 4 by arithmetic.
    pub fn write(&self, line: u8, level: bool) -> Result<(), Error> {
        let mask = Self::check(line)?;
        let value = if level { u32::from(mask) } else { 0 };
        self.regs.write32(data_offset(mask), value);
        Ok(())
    }

    /// Reads every line at once, for a caller that wants the port.
    pub fn read_port(&self) -> u8 {
        self.regs.read32(data_offset(0xff)) as u8
    }

    /// Configures how a line interrupts, and leaves it **masked**.
    ///
    /// Configuring and unmasking are separate on purpose. A line whose trigger
    /// is being changed can assert on the way past — a level-sensed line
    /// switched to the other polarity is asserting the instant it is written —
    /// and a driver that unmasked in the same call would take an interrupt for
    /// a change it made itself.
    pub fn configure_interrupt(&self, line: u8, trigger: Trigger) -> Result<(), Error> {
        let mask = Self::check(line)?;
        let (sense, both, event) = trigger.bits();
        self.set_bit(reg::IE, mask, false);
        self.set_bit(reg::IS, mask, sense);
        self.set_bit(reg::IBE, mask, both);
        self.set_bit(reg::IEV, mask, event);
        // Anything the reconfiguration itself latched is not news.
        self.regs.write32(reg::IC, u32::from(mask));
        Ok(())
    }

    /// Lets a configured line reach the controller's interrupt output.
    pub fn unmask(&self, line: u8) -> Result<(), Error> {
        let mask = Self::check(line)?;
        self.set_bit(reg::IE, mask, true);
        Ok(())
    }

    pub fn mask(&self, line: u8) -> Result<(), Error> {
        let mask = Self::check(line)?;
        self.set_bit(reg::IE, mask, false);
        Ok(())
    }

    /// The lines that are asserting the interrupt output.
    ///
    /// **Masked status, not raw.** The raw register says what every line is
    /// doing, including lines nobody asked about; a driver that demultiplexed
    /// from it would wake watchers for edges on lines that were deliberately
    /// masked off.
    pub fn pending(&self) -> u8 {
        self.regs.read32(reg::MIS) as u8
    }

    /// What the lines are doing regardless of the mask — for a driver deciding
    /// whether a line it has not enabled is worth enabling.
    pub fn raw_pending(&self) -> u8 {
        self.regs.read32(reg::RIS) as u8
    }

    /// Acknowledges exactly the lines named.
    ///
    /// Write-one-to-clear, so the argument is the lines being handled and never
    /// a read-modify-write: writing back what was read would acknowledge a line
    /// that asserted between the read and the write, and nobody would ever be
    /// told about it.
    pub fn clear(&self, lines: u8) {
        self.regs.write32(reg::IC, u32::from(lines));
    }

    fn set_bit(&self, offset: usize, mask: u8, set: bool) {
        let current = self.regs.read32(offset);
        let next = if set {
            current | u32::from(mask)
        } else {
            current & !u32::from(mask)
        };
        self.regs.write32(offset, next);
    }
}

/// The part number in a PrimeCell's identification registers, or `None` when
/// the four `PCELLID` bytes do not spell the signature every PrimeCell has.
///
/// Two questions rather than one. The cell id says "this is a PrimeCell", which
/// is what distinguishes a register window holding a device from one holding
/// nothing; the peripheral id says *which*, which is what a manager needs to
/// classify it. A window with no device in it reads as zeros or as ones, and
/// neither spells the signature.
pub fn identify<R: Registers>(regs: &R) -> Option<u32> {
    let mut signature = 0u32;
    for index in 0..4 {
        let byte = regs.read32(reg::PCELL_ID0 + index * 4) & 0xff;
        signature |= byte << (index * 8);
    }
    if signature != PRIMECELL_SIGNATURE {
        return None;
    }
    let low = regs.read32(reg::PERIPH_ID0) & 0xff;
    let high = regs.read32(reg::PERIPH_ID0 + 4) & 0xf;
    Some((high << 8) | low)
}
