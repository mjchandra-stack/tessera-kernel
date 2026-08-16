// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The SD host controller transport core: reset, bus power, the clock divider,
//! command issue and response collection, card presence, and a single-block
//! read through the buffer data port.
//!
//! Register access goes through the [`Registers`] trait, so the fragile parts —
//! the divider arithmetic, the command word's bit layout, the interrupt-status
//! handshake and the byte order a block arrives in — are ordinary logic a mock
//! exercises on the host. The caller supplies the real volatile access; this
//! crate forbids `unsafe`.
//!
//! # What is different about this transport
//!
//! Every other transport in this tree talks to a device that is *there*. An SD
//! host controller talks to a slot, and the card in it can leave. So presence
//! is a first-class question this core answers rather than an assumption it
//! makes, and every command path reports "no card" as its own outcome rather
//! than as a timeout — a distinction a driver has to make, because one means
//! the medium is gone and the other means the controller is wedged.
//!
//! # Why the clock is arithmetic and not a constant
//!
//! A card is identified at 400 kHz and read at whatever it and the controller
//! can both manage. The divider that produces those from the controller's base
//! clock is where the mistakes are: an off-by-one runs a card at twice its
//! identification rate, which works on some cards and not others. It is a pure
//! function here, and the *actual* rate is reported rather than assumed,
//! because a divider can rarely hit a target exactly.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage"),
//! docs/drivers/04-embedded-buses-power-and-timekeeping.md ("Clock Controller")
//! Budget: none (driven from ring 3)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// What can go wrong. Every variant is a fact about the controller or the card,
/// never a programming error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// There is no card in the slot. **Its own outcome and not a timeout**: one
    /// means the medium is gone and the other means the controller is wedged,
    /// and a driver's response to them differs.
    NoCard,
    /// The controller did not finish within the bounded wait.
    Timeout,
    /// The controller reported an error interrupt; the payload is the error
    /// status register, so a driver can say which.
    CommandError(u16),
    /// A reset did not complete.
    ResetFailed,
    /// The controller reports a base clock of zero, which no divider can work
    /// from.
    NoBaseClock,
    /// A buffer handed in is not one block long.
    BadLength,
}

impl Error {
    /// A stable number for reporting, with a command error's status packed
    /// above it.
    ///
    /// The payload travels because it is the controller's own explanation, and
    /// a driver that reduced every failure to "an error" would leave whoever
    /// reads its report unable to tell a CRC failure from a card that timed
    /// out on the bus.
    pub fn code(self) -> u64 {
        match self {
            Error::NoCard => 1,
            Error::Timeout => 2,
            Error::CommandError(status) => 3 | (u64::from(status) << 8),
            Error::ResetFailed => 4,
            Error::NoBaseClock => 5,
            Error::BadLength => 6,
        }
    }
}

/// Controller registers this crate reads and writes, as 32-bit words from the
/// start of the controller's register window.
pub trait Registers {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&self, offset: usize, value: u32);
}

/// Register offsets.
pub mod reg {
    pub const ARGUMENT: usize = 0x08;
    /// Block size in 15:0, block count in 31:16.
    pub const BLOCK: usize = 0x04;
    /// Transfer mode in 15:0, command in 31:16.
    pub const COMMAND: usize = 0x0c;
    pub const RESPONSE0: usize = 0x10;
    pub const BUFFER: usize = 0x20;
    pub const PRESENT_STATE: usize = 0x24;
    /// Host control in 7:0, power control in 15:8.
    pub const HOST_CONTROL: usize = 0x28;
    /// Clock control in 15:0, timeout in 23:16, software reset in 31:24.
    pub const CLOCK_CONTROL: usize = 0x2c;
    /// Normal interrupt status in 15:0, error status in 31:16.
    pub const INT_STATUS: usize = 0x30;
    pub const INT_ENABLE: usize = 0x34;
    pub const INT_SIGNAL: usize = 0x38;
    /// Capabilities, low word: the base clock is in bits 15:8, in MHz.
    pub const CAPABILITIES: usize = 0x40;
}

/// `PRESENT_STATE` bits.
///
/// Public for the same reason [`reg`] is: a controller model that stands in for
/// this hardware has to set the bits this core reads, and one that named them
/// itself would be free to disagree with the core about which bit means a card
/// is in the slot — the single fact everything about removable media rests on.
pub mod present {
    pub const CMD_INHIBIT: u32 = 1;
    pub const DAT_INHIBIT: u32 = 1 << 1;
    pub const CARD_INSERTED: u32 = 1 << 16;
}

/// Normal interrupt status bits, in the low half of `INT_STATUS`.
///
/// Public for the reason [`present`] is.
pub mod irq {
    pub const COMMAND_COMPLETE: u32 = 1;
    pub const TRANSFER_COMPLETE: u32 = 1 << 1;
    pub const BUFFER_WRITE_READY: u32 = 1 << 4;
    pub const BUFFER_READ_READY: u32 = 1 << 5;
    pub const CARD_INSERTION: u32 = 1 << 6;
    pub const CARD_REMOVAL: u32 = 1 << 7;
    pub const ERROR: u32 = 1 << 15;
}

/// Bytes in one block, and the only block size this core uses.
///
/// A card may be told a different length, and none of the ones this drives
/// benefits: 512 is the native size of every SDHC card, and a driver that made
/// it configurable would be offering a knob whose only settings are worse.
pub const BLOCK_LEN: usize = 512;

/// How many times a wait polls before giving up. A count and not a duration,
/// because this crate has no clock — what the bound buys is that a controller
/// which never answers produces an error rather than a hang.
const POLL_LIMIT: u32 = 1_000_000;

/// What kind of response a command returns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResponseKind {
    None,
    /// 48-bit, with CRC and index checked.
    Short,
    /// 48-bit with no CRC — what `ACMD41` returns, since its response carries
    /// no CRC to check and a controller told to check one would report every
    /// reply as corrupt.
    ShortNoCrc,
    /// 48-bit, and the card holds the data line low while it is busy.
    ShortBusy,
    /// 136-bit — a card's CID or CSD.
    Long,
}

impl ResponseKind {
    /// The command register's response-type field, and whether CRC and index
    /// are checked.
    fn bits(self) -> u16 {
        match self {
            ResponseKind::None => 0,
            ResponseKind::Long => 0b01 | (1 << 3),
            ResponseKind::Short => 0b10 | (1 << 3) | (1 << 4),
            ResponseKind::ShortNoCrc => 0b10,
            ResponseKind::ShortBusy => 0b11 | (1 << 3) | (1 << 4),
        }
    }
}

/// Which way a command's block moves.
///
/// A direction and not a flag, because the transfer-mode register encodes it
/// and a command that named data without saying which way would have the
/// controller pick — which on a write means the card holds the bus waiting for
/// bytes the controller is trying to read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transfer {
    Read,
    Write,
}

/// A card's answer. Long responses fill all four words; short ones fill the
/// first.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Response(pub [u32; 4]);

/// SD command indices this core names.
pub const CMD_GO_IDLE: u8 = 0;
pub const CMD_ALL_SEND_CID: u8 = 2;
pub const CMD_SEND_RELATIVE_ADDR: u8 = 3;
pub const CMD_SELECT_CARD: u8 = 7;
pub const CMD_SEND_IF_COND: u8 = 8;
pub const CMD_SET_BLOCKLEN: u8 = 16;
pub const CMD_READ_SINGLE_BLOCK: u8 = 17;
pub const CMD_WRITE_BLOCK: u8 = 24;
pub const CMD_APP: u8 = 55;
pub const ACMD_SEND_OP_COND: u8 = 41;

/// `CMD8`'s check pattern: 2.7–3.6 V and a byte a card echoes back. Echoing it
/// is how a card says it understood the command at all — a card that does not
/// answer is pre-2.0 and a card that answers with something else is not
/// answering this question.
pub const IF_COND_ARG: u32 = 0x1aa;

/// `ACMD41`'s argument: host capacity support, and a 3.2–3.4 V window.
pub const OP_COND_ARG: u32 = 0x4030_0000;

/// The bit a card sets in its `ACMD41` response once it has finished powering
/// up. Until then the response is a card saying "ask again".
pub const OP_COND_READY: u32 = 1 << 31;

/// The divider field and the rate it actually produces for `target_hz` from a
/// controller whose base clock is `base_hz`.
///
/// **Rounds the rate down, never up.** A divider chosen to get closest to the
/// target can overshoot it, and overshooting a card's identification rate is
/// how a driver works on the card it was written against and not on the next
/// one. The actual rate is returned because a divider can rarely hit a target
/// exactly, and a caller that assumed it had would be reporting a speed the
/// card is not running at.
///
/// The field is the 8-bit divided-clock-mode selector: `N` there means
/// `base / (2 * N)`, and `N = 0` means the base clock undivided.
pub fn divider_for(base_hz: u64, target_hz: u64) -> Result<(u16, u64), Error> {
    if base_hz == 0 {
        return Err(Error::NoBaseClock);
    }
    if target_hz >= base_hz {
        return Ok((0, base_hz));
    }
    // The smallest power of two whose division brings the base at or under the
    // target. Powers of two because that is what the eight-bit field selects in
    // the mode every controller supports.
    let mut n: u64 = 1;
    while base_hz / (2 * n) > target_hz {
        let Some(next) = n.checked_mul(2) else {
            return Err(Error::NoBaseClock);
        };
        n = next;
        if n > 0x80 {
            // Past what the field can express. The slowest this controller can
            // go is reported rather than a wrapped divider that would run the
            // card fast.
            return Ok((0x80, base_hz / 0x100));
        }
    }
    Ok((n as u16, base_hz / (2 * n)))
}

/// A live controller.
pub struct Host<'r, R: Registers> {
    regs: &'r R,
    /// The controller's base clock, read once from its capabilities.
    base_hz: u64,
}

impl<'r, R: Registers> Host<'r, R> {
    /// Resets the controller, powers the bus, and leaves it ready to issue
    /// commands at `initial_hz`.
    ///
    /// The order is the specification's: reset before anything, because a
    /// controller carries whatever the last driver left in it; power before
    /// clock, because a card clocked without power is a card that never
    /// answers; and the clock last, because everything above needs it stable.
    pub fn reset_and_enable(regs: &'r R, initial_hz: u64) -> Result<Self, Error> {
        // Software reset all, and wait for it to clear itself.
        regs.write32(reg::CLOCK_CONTROL, 1 << 24);
        let mut settled = false;
        for _ in 0..POLL_LIMIT {
            if regs.read32(reg::CLOCK_CONTROL) & (1 << 24) == 0 {
                settled = true;
                break;
            }
        }
        if !settled {
            return Err(Error::ResetFailed);
        }

        let base_mhz = u64::from((regs.read32(reg::CAPABILITIES) >> 8) & 0xff);
        if base_mhz == 0 {
            return Err(Error::NoBaseClock);
        }
        let host = Host {
            regs,
            base_hz: base_mhz * 1_000_000,
        };

        // Bus power on at 3.3 V: the voltage select in bits 3:1 of the power
        // control byte, then the power-on bit. Written together because a
        // controller that saw the enable before the voltage would apply
        // whatever the field held.
        let control = regs.read32(reg::HOST_CONTROL) & !0xff00;
        regs.write32(reg::HOST_CONTROL, control | (0b111 << 9) | (1 << 8));

        // Every status bit enabled, and none of them signalled. A driver here
        // polls the status register; signalling would raise an interrupt line
        // nobody has routed yet, and the milestone that routes one can turn it
        // on rather than inherit it.
        regs.write32(reg::INT_ENABLE, 0xffff_ffff);
        regs.write32(reg::INT_SIGNAL, 0);

        host.set_clock(initial_hz)?;
        Ok(host)
    }

    /// The controller's base clock.
    pub fn base_hz(&self) -> u64 {
        self.base_hz
    }

    /// Sets the bus clock as close to `target_hz` as the divider allows without
    /// going over, and returns the rate now in effect.
    pub fn set_clock(&self, target_hz: u64) -> Result<u64, Error> {
        let (divider, actual) = divider_for(self.base_hz, target_hz)?;
        // Stop the clock before changing the divider: a controller whose
        // divider moves under a running clock puts a glitch on the bus, which
        // a card is entitled to interpret as anything at all.
        let control = self.regs.read32(reg::CLOCK_CONTROL) & !0xffff;
        self.regs.write32(reg::CLOCK_CONTROL, control);
        let field = (divider & 0xff) << 8;
        self.regs
            .write32(reg::CLOCK_CONTROL, control | u32::from(field) | 1);
        // Wait for the internal clock to say it is stable before letting it out
        // to the card.
        let mut stable = false;
        for _ in 0..POLL_LIMIT {
            if self.regs.read32(reg::CLOCK_CONTROL) & 0b10 != 0 {
                stable = true;
                break;
            }
        }
        if !stable {
            return Err(Error::Timeout);
        }
        self.regs
            .write32(reg::CLOCK_CONTROL, control | u32::from(field) | 0b111);
        Ok(actual)
    }

    /// Whether a card is in the slot.
    ///
    /// Asked rather than assumed, and asked again rather than remembered: this
    /// is the one transport here whose device can leave while its driver is
    /// running.
    pub fn card_present(&self) -> bool {
        self.regs.read32(reg::PRESENT_STATE) & present::CARD_INSERTED != 0
    }

    /// Takes and clears whichever of insertion and removal the controller has
    /// latched since this was last called.
    ///
    /// Returned as a pair rather than as "the current state", because both can
    /// have happened: a card pulled and pushed back between two polls is a
    /// different card, and a driver told only the state would see nothing
    /// changed.
    pub fn take_card_events(&self) -> (bool, bool) {
        let status = self.regs.read32(reg::INT_STATUS);
        let inserted = status & irq::CARD_INSERTION != 0;
        let removed = status & irq::CARD_REMOVAL != 0;
        if inserted || removed {
            self.regs.write32(
                reg::INT_STATUS,
                status & (irq::CARD_INSERTION | irq::CARD_REMOVAL),
            );
        }
        (inserted, removed)
    }

    /// Issues one command and collects its response.
    ///
    /// `data` says the command brings a block back, which changes what the
    /// controller waits for; the block itself is read with
    /// [`read_block`](Self::read_block).
    pub fn command(
        &self,
        index: u8,
        argument: u32,
        response: ResponseKind,
        data: Option<Transfer>,
    ) -> Result<Response, Error> {
        if !self.card_present() {
            return Err(Error::NoCard);
        }
        // The controller will not accept a command while the last one is still
        // occupying the bus. Waited on rather than assumed: a driver that
        // wrote anyway would have its command silently dropped.
        let inhibit = present::CMD_INHIBIT
            | if data.is_some() || response == ResponseKind::ShortBusy {
                present::DAT_INHIBIT
            } else {
                0
            };
        self.wait_while(reg::PRESENT_STATE, inhibit)?;

        // Clear whatever the last command left latched, so what is read below
        // is this command's answer and not the previous one's.
        let stale = self.regs.read32(reg::INT_STATUS);
        self.regs.write32(reg::INT_STATUS, stale);

        if data.is_some() {
            self.regs.write32(reg::BLOCK, BLOCK_LEN as u32 | (1 << 16));
        }
        self.regs.write32(reg::ARGUMENT, argument);
        let command =
            u32::from(u16::from(index) << 8 | response.bits() | u16::from(data.is_some()) << 5);
        // Transfer mode in the low half: a single block, and bit 4 says card to
        // host. A write leaves it clear — the direction is the card's business
        // and getting it wrong deadlocks the bus, with the card waiting for
        // bytes the controller is trying to read.
        let mode = match data {
            Some(Transfer::Read) => 1 << 4,
            Some(Transfer::Write) => 0,
            None => 0,
        };
        self.regs.write32(reg::COMMAND, (command << 16) | mode);

        self.wait_for(irq::COMMAND_COMPLETE)?;
        let mut words = [0u32; 4];
        match response {
            ResponseKind::None => {}
            ResponseKind::Long => {
                for (i, word) in words.iter_mut().enumerate() {
                    *word = self.regs.read32(reg::RESPONSE0 + i * 4);
                }
            }
            _ => words[0] = self.regs.read32(reg::RESPONSE0),
        }
        Ok(Response(words))
    }

    /// Reads the block a data command brought back.
    ///
    /// The buffer must be exactly one block: a short one would leave the
    /// controller holding bytes nobody read, and the next command would find
    /// them.
    pub fn read_block(&self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() != BLOCK_LEN {
            return Err(Error::BadLength);
        }
        self.wait_for(irq::BUFFER_READ_READY)?;
        for chunk in out.chunks_mut(4) {
            let word = self.regs.read32(reg::BUFFER);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        self.wait_for(irq::TRANSFER_COMPLETE)
    }

    /// Writes the block a data command is waiting for.
    ///
    /// The mirror of [`read_block`](Self::read_block), and bounded the same
    /// way: a buffer that is not one block would leave the controller waiting
    /// for bytes nobody is going to send, with the card holding the bus.
    pub fn write_block(&self, data: &[u8]) -> Result<(), Error> {
        if data.len() != BLOCK_LEN {
            return Err(Error::BadLength);
        }
        self.wait_for(irq::BUFFER_WRITE_READY)?;
        for chunk in data.chunks(4) {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            self.regs.write32(reg::BUFFER, u32::from_le_bytes(word));
        }
        self.wait_for(irq::TRANSFER_COMPLETE)
    }

    /// Waits until every bit of `mask` is clear in the register at `offset`.
    fn wait_while(&self, offset: usize, mask: u32) -> Result<(), Error> {
        for _ in 0..POLL_LIMIT {
            if self.regs.read32(offset) & mask == 0 {
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    /// Waits for a normal-status bit, and **fails on the error bit first**.
    ///
    /// The order matters: a command that failed sets its error bit and never
    /// sets the completion bit, so a wait that looked only for completion would
    /// spend its whole budget and report a timeout for something the controller
    /// had already explained.
    fn wait_for(&self, bit: u32) -> Result<(), Error> {
        for _ in 0..POLL_LIMIT {
            let status = self.regs.read32(reg::INT_STATUS);
            if status & irq::ERROR != 0 {
                let errors = (status >> 16) as u16;
                // Clear it, so the next command's wait does not find this one's
                // failure and report it again.
                self.regs.write32(reg::INT_STATUS, status);
                return Err(Error::CommandError(errors));
            }
            if status & bit != 0 {
                self.regs.write32(reg::INT_STATUS, bit);
                return Ok(());
            }
            // A card that left mid-command will never complete it, and saying
            // so beats spending the budget to report a timeout.
            if !self.card_present() {
                return Err(Error::NoCard);
            }
        }
        Err(Error::Timeout)
    }
}
