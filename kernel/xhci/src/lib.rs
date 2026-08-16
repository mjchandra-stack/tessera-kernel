// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The xHCI transport core: register discovery, controller bring-up, the
//! command and transfer rings, the event ring and its cycle bit, and port
//! status.
//!
//! Register access goes through the [`Registers`] trait, so the parts that are
//! logic — where the operational registers actually are, how a ring wraps, and
//! which events are this lap's — are exercised by a mock on the host. The
//! caller supplies the real volatile access; this crate forbids `unsafe`.
//!
//! # Three things this transport gets wrong more often than the others
//!
//! **Nothing is at a fixed offset.** The operational registers begin at a byte
//! count the controller reports, the doorbells and the runtime registers at
//! offsets it reports, and the port registers at a stride from the operational
//! base. A driver with a table of constants works on the controller it was
//! written against.
//!
//! **A ring wraps through a link.** A producer ring does not simply run off its
//! end: its last entry is a Link TRB pointing back at the start, and crossing it
//! **toggles the producer's cycle bit**. A driver that wrapped by resetting an
//! index would hand the controller entries it has already consumed.
//!
//! **Nothing in an event says it is new.** One bit does, and the controller
//! flips it every lap. This is the same shape as NVMe's phase tag and the same
//! failure: a reader that ignored it would process the previous lap's events
//! again on every wrap, which looks exactly like a controller completing work
//! twice.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("USB")
//! Budget: none (driven from ring 3)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(test)]
mod tests;

/// What can go wrong. Every variant is a fact about the controller or about
/// what it reported, never a programming error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The controller did not reset, stop or start within the bounded wait.
    NotReady,
    /// The controller reports a capability length or register offset that
    /// cannot be right — zero, or past what a caller mapped.
    BadLayout,
    /// A ring smaller than the two entries a wrap needs, or not a size the
    /// controller can address.
    RingSize,
    /// A completion the controller posted with a code other than success; the
    /// payload is that code, so a driver can say which.
    Completion(u8),
    /// A buffer handed in is too small for the structure it must hold.
    ShortBuffer,
    /// The port named does not exist on this controller.
    NoSuchPort,
}

/// Controller registers, as 32-bit words from the start of the register window.
pub trait Registers {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&self, offset: usize, value: u32);
}

/// Capability register offsets, which are the only ones at fixed positions.
pub mod cap {
    /// Capability length in bits 7:0, interface version in 31:16.
    pub const LENGTH_VERSION: usize = 0x00;
    /// Max device slots 7:0, max interrupters 18:8, max ports 31:24.
    pub const HCSPARAMS1: usize = 0x04;
    /// Max scratchpad buffers: high bits 25:21, low bits 31:27.
    pub const HCSPARAMS2: usize = 0x08;
    /// 64-bit addressing in bit 0, context size in bit 2.
    pub const HCCPARAMS1: usize = 0x10;
    /// Doorbell array offset.
    pub const DBOFF: usize = 0x14;
    /// Runtime register space offset.
    pub const RTSOFF: usize = 0x18;
}

/// Operational register offsets, from the operational base.
mod op {
    pub const USBCMD: usize = 0x00;
    pub const USBSTS: usize = 0x04;
    /// Command ring control, 64-bit.
    pub const CRCR: usize = 0x18;
    /// Device context base address array pointer, 64-bit.
    pub const DCBAAP: usize = 0x30;
    /// Max device slots enabled in bits 7:0.
    pub const CONFIG: usize = 0x38;
    /// The first port's status and control register.
    pub const PORTSC: usize = 0x400;
    /// Bytes between one port's registers and the next.
    pub const PORT_STRIDE: usize = 0x10;
}

/// `USBCMD` bits.
mod cmd {
    pub const RUN: u32 = 1;
    pub const RESET: u32 = 1 << 1;
    pub const INTERRUPTER_ENABLE: u32 = 1 << 2;
}

/// `USBSTS` bits.
mod sts {
    pub const HALTED: u32 = 1;
    /// Controller not ready: set while it is still coming out of reset.
    pub const NOT_READY: u32 = 1 << 11;
}

/// Runtime register offsets, from the runtime base. Interrupter zero's, which
/// is the only one this core uses.
mod rt {
    pub const IMAN: usize = 0x20;
    /// Event ring segment table size.
    pub const ERSTSZ: usize = 0x28;
    /// Event ring segment table base, 64-bit.
    pub const ERSTBA: usize = 0x30;
    /// Event ring dequeue pointer, 64-bit.
    pub const ERDP: usize = 0x38;
}

/// `PORTSC` bits.
pub mod port {
    /// Current connect status: something is plugged in.
    pub const CONNECTED: u32 = 1;
    /// Port enabled — set by the controller when a reset succeeds.
    pub const ENABLED: u32 = 1 << 1;
    /// Port reset, written to start one and cleared by the controller.
    pub const RESET: u32 = 1 << 4;
    /// Port power.
    pub const POWER: u32 = 1 << 9;
    /// Connect status change, write-one-to-clear.
    pub const CONNECT_CHANGED: u32 = 1 << 17;
    /// Port reset change, write-one-to-clear.
    pub const RESET_CHANGED: u32 = 1 << 21;
    /// The bits that are write-one-to-clear, which every read-modify-write of
    /// this register must mask off — writing a one back to a change bit that
    /// happens to be set clears a notification nobody has acted on.
    pub const CHANGE_BITS: u32 =
        CONNECT_CHANGED | RESET_CHANGED | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 22);
}

/// Bytes in one transfer request block.
pub const TRB_LEN: usize = 16;

/// TRB types, in bits 15:10 of a TRB's control word.
pub mod trb {
    pub const NORMAL: u32 = 1;
    pub const SETUP: u32 = 2;
    pub const DATA: u32 = 3;
    pub const STATUS: u32 = 4;
    pub const LINK: u32 = 6;
    pub const ENABLE_SLOT: u32 = 9;
    pub const ADDRESS_DEVICE: u32 = 11;
    pub const CONFIGURE_ENDPOINT: u32 = 12;
    pub const TRANSFER_EVENT: u32 = 32;
    pub const COMMAND_COMPLETION: u32 = 33;
    pub const PORT_STATUS_CHANGE: u32 = 34;
}

/// The completion code a controller reports for work that succeeded.
pub const COMPLETION_SUCCESS: u8 = 1;
/// What it reports for a short transfer — fewer bytes than asked for, which is
/// an outcome and not a failure.
pub const COMPLETION_SHORT_PACKET: u8 = 13;

/// One transfer request block: four 32-bit words.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    /// The TRB's type, out of bits 15:10 of its control word.
    pub fn kind(&self) -> u32 {
        (self.control >> 10) & 0x3f
    }

    /// The completion code an event carries, out of bits 31:24 of its status.
    pub fn completion_code(&self) -> u8 {
        (self.status >> 24) as u8
    }

    /// The slot an event or command names, out of bits 31:24 of its control.
    pub fn slot(&self) -> u8 {
        (self.control >> 24) as u8
    }

    /// Whether an event says the work it reports succeeded.
    ///
    /// A short packet counts. It means the device sent less than was asked for,
    /// which on a bulk endpoint is how a device says "that is all there was" —
    /// and a driver that treated it as a failure would report an error for
    /// every read that reached the end of a file.
    pub fn is_success(&self) -> bool {
        matches!(
            self.completion_code(),
            COMPLETION_SUCCESS | COMPLETION_SHORT_PACKET
        )
    }

    /// Bytes the controller did **not** transfer, out of bits 23:0 of an
    /// event's status. What a short packet's length is computed from.
    pub fn residual(&self) -> u32 {
        self.status & 0xff_ffff
    }

    /// Writes this TRB into `out`, which must be one TRB long.
    pub fn write(&self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() < TRB_LEN {
            return Err(Error::ShortBuffer);
        }
        out[0..8].copy_from_slice(&self.parameter.to_le_bytes());
        out[8..12].copy_from_slice(&self.status.to_le_bytes());
        out[12..16].copy_from_slice(&self.control.to_le_bytes());
        Ok(())
    }

    /// Reads a TRB out of `bytes`.
    pub fn read(bytes: &[u8]) -> Result<Trb, Error> {
        if bytes.len() < TRB_LEN {
            return Err(Error::ShortBuffer);
        }
        let mut parameter = [0u8; 8];
        parameter.copy_from_slice(&bytes[0..8]);
        let mut status = [0u8; 4];
        status.copy_from_slice(&bytes[8..12]);
        let mut control = [0u8; 4];
        control.copy_from_slice(&bytes[12..16]);
        Ok(Trb {
            parameter: u64::from_le_bytes(parameter),
            status: u32::from_le_bytes(status),
            control: u32::from_le_bytes(control),
        })
    }
}

/// Builds a command or transfer TRB of `kind` with no parameter.
pub fn command(kind: u32, slot: u8) -> Trb {
    Trb {
        parameter: 0,
        status: 0,
        control: (kind << 10) | (u32::from(slot) << 24),
    }
}

/// Builds a command carrying a pointer — `Address Device` and `Configure
/// Endpoint` both name an input context this way.
pub fn command_with_context(kind: u32, slot: u8, context: u64) -> Trb {
    Trb {
        parameter: context,
        status: 0,
        control: (kind << 10) | (u32::from(slot) << 24),
    }
}

/// The three TRBs of a control transfer.
///
/// Built together rather than one at a time because they are one transaction:
/// a setup stage without its status stage leaves the endpoint waiting, and a
/// driver assembling them separately is a driver that can get the direction of
/// the middle one wrong. `length` of zero omits the data stage.
pub fn control_transfer(
    setup: [u8; 8],
    buffer: u64,
    length: u32,
    device_to_host: bool,
) -> [Trb; 3] {
    let mut request = [0u8; 8];
    request.copy_from_slice(&setup);
    let setup_param = u64::from_le_bytes(request);
    // Transfer type in bits 17:16 of the setup stage's control word: 2 is an
    // OUT data stage and 3 an IN one, 0 no data at all.
    let transfer_type = if length == 0 {
        0
    } else if device_to_host {
        3
    } else {
        2
    };
    let setup_trb = Trb {
        parameter: setup_param,
        // A setup stage always carries eight bytes, and says so.
        status: 8,
        control: (trb::SETUP << 10) | (1 << 6) | (transfer_type << 16),
    };
    let data_trb = Trb {
        parameter: buffer,
        status: length,
        control: (trb::DATA << 10) | (u32::from(device_to_host) << 16),
    };
    // The status stage runs the *other* way from the data stage, which is the
    // one thing about a control transfer that cannot be derived from the
    // request alone — and getting it backwards stalls the endpoint.
    let status_trb = Trb {
        parameter: 0,
        status: 0,
        control: (trb::STATUS << 10) | (1 << 5) | (u32::from(length == 0 || !device_to_host) << 16),
    };
    [setup_trb, data_trb, status_trb]
}

/// Builds a normal TRB — one bulk or interrupt transfer.
pub fn normal(buffer: u64, length: u32) -> Trb {
    Trb {
        parameter: buffer,
        status: length,
        // Interrupt on completion, so the transfer produces an event.
        control: (trb::NORMAL << 10) | (1 << 5),
    }
}

/// Device and endpoint context sizes, and the layout of what goes in them.
///
/// A context is not a register window: it is memory the *driver* writes and the
/// controller reads, and everything about a device that is not in a TRB is
/// here. Which is why it is in this crate — it is the same class of fragile
/// arithmetic as a ring, it needs no hardware to get wrong, and getting it
/// wrong produces a device that addresses successfully and then transfers
/// nothing.
///
/// **Contexts come in two sizes and the controller says which.** A driver that
/// assumed 32 bytes on a controller using 64 would write every context after
/// the first into the middle of the one before it. The size is a parameter
/// here rather than a constant for exactly that reason.
pub mod context {
    use super::{Error, Registers};

    /// Endpoint types, as the endpoint context's `EP Type` field encodes them.
    /// The direction is part of the value rather than beside it, which is how
    /// the specification writes it and why a bulk-in and a bulk-out are two
    /// numbers and not one number and a flag.
    pub const ISOCH_OUT: u8 = 1;
    pub const BULK_OUT: u8 = 2;
    pub const INTERRUPT_OUT: u8 = 3;
    pub const CONTROL: u8 = 4;
    pub const ISOCH_IN: u8 = 5;
    pub const BULK_IN: u8 = 6;
    pub const INTERRUPT_IN: u8 = 7;

    /// Link speeds, as `PORTSC` reports them in bits 13:10 and as a slot
    /// context repeats them in bits 23:20.
    pub const SPEED_FULL: u8 = 1;
    pub const SPEED_LOW: u8 = 2;
    pub const SPEED_HIGH: u8 = 3;
    pub const SPEED_SUPER: u8 = 4;

    /// The control endpoint's packet size for a link of this speed, before the
    /// device has been asked.
    ///
    /// A driver has to address a device before it can read a descriptor, and it
    /// has to name a packet size to address it — so the first value comes from
    /// the speed and not from the device. Low and full speed devices may use
    /// eight and are asked afterwards; high speed is fixed at 64 by the
    /// specification, and super speed encodes 512 as an exponent.
    pub fn default_packet_size(speed: u8) -> u16 {
        match speed {
            SPEED_LOW | SPEED_FULL => 8,
            SPEED_SUPER => 512,
            _ => 64,
        }
    }

    /// Bytes one context occupies, read from the controller rather than
    /// assumed: `HCCPARAMS1` bit 2 selects 64 over 32.
    pub fn size_of<R: Registers>(regs: &R) -> usize {
        if regs.read32(super::cap::HCCPARAMS1) & (1 << 2) != 0 {
            64
        } else {
            32
        }
    }

    /// Writes `value` as four little-endian words at `at`.
    fn put(out: &mut [u8], at: usize, words: [u32; 4]) -> Result<(), Error> {
        if out.len() < at + 16 {
            return Err(Error::ShortBuffer);
        }
        for (index, word) in words.iter().enumerate() {
            let off = at + index * 4;
            out[off..off + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(())
    }

    /// The input control context, which is the first context of an input
    /// context and says which of the ones after it the controller should read.
    ///
    /// **A command that adds nothing changes nothing**, and silently: the
    /// controller reads the flags, finds no context selected, and reports
    /// success. So the add mask is the argument rather than being implied by
    /// what the caller filled in.
    pub fn write_input_control(
        out: &mut [u8],
        add: u32,
        drop: u32,
        configuration: u8,
    ) -> Result<(), Error> {
        put(out, 0, [drop, add, 0, 0])?;
        // Words four through seven; the last carries the configuration value a
        // `Configure Endpoint` command applies.
        put(out, 16, [0, 0, 0, u32::from(configuration)])
    }

    /// Writes a slot context at `at`.
    ///
    /// `route` is the **path through the hubs**, four bits per tier, and it is
    /// how a controller reaches a device it has no port of its own for. A
    /// driver that left it zero for a device behind a hub would be describing
    /// the hub's own port on the root controller — and the transfers would go
    /// to the hub.
    ///
    /// `tt` is the transaction translator: the hub's slot and the port on it,
    /// required when a low or full speed device sits behind a high speed hub
    /// because the hub is what speaks to it at its own speed. `None` for a
    /// device on a root port, or one running at the hub's speed.
    #[allow(clippy::too_many_arguments)]
    pub fn write_slot(
        out: &mut [u8],
        at: usize,
        route: u32,
        speed: u8,
        entries: u8,
        root_port: u8,
        tt: Option<(u8, u8)>,
    ) -> Result<(), Error> {
        let (tt_slot, tt_port) = tt.unwrap_or((0, 0));
        put(
            out,
            at,
            [
                (route & 0xf_ffff) | (u32::from(speed) << 20) | (u32::from(entries) << 27),
                u32::from(root_port) << 16,
                u32::from(tt_slot) | (u32::from(tt_port) << 8),
                0,
            ],
        )
    }

    /// Writes an endpoint context at `at`.
    ///
    /// The dequeue pointer carries the ring's **cycle state** in bit 0, for the
    /// reason the command ring's does: the controller has to start on the same
    /// lap as the producer, and a pointer with the bit clear against a ring
    /// producing ones would leave the controller waiting for work it can see.
    #[allow(clippy::too_many_arguments)]
    pub fn write_endpoint(
        out: &mut [u8],
        at: usize,
        kind: u8,
        max_packet: u16,
        ring: u64,
        cycle: bool,
        interval: u8,
    ) -> Result<(), Error> {
        let dequeue = ring | u64::from(cycle);
        put(
            out,
            at,
            [
                u32::from(interval) << 16,
                // Three error retries, the endpoint type, and the packet size
                // the device asked for.
                (3 << 1) | (u32::from(kind) << 3) | (u32::from(max_packet) << 16),
                dequeue as u32,
                (dequeue >> 32) as u32,
            ],
        )?;
        // The average TRB length, which the controller uses for bandwidth
        // arithmetic. Non-zero because zero is not a length, and a controller
        // budgeting from it would budget nothing.
        put(out, at + 16, [u32::from(max_packet), 0, 0, 0])
    }

    /// Where context `index` begins, for contexts of `size` bytes.
    ///
    /// Index zero of an input context is the input control context and index
    /// one the slot context, so an endpoint's context index — the one
    /// `Endpoint::context_index` computes from its address — lands one further
    /// along here than it does in a device context.
    pub fn at(index: usize, size: usize) -> usize {
        index * size
    }
}

/// A producer ring: where the driver puts work for the controller.
///
/// Holds the cycle bit rather than deriving it, because it is not a property of
/// the position — the ring toggles it every lap, so the same slot means "new" on
/// one pass and "already consumed" on the next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ring {
    /// The address the controller reads this ring from.
    base: u64,
    /// Entries, including the Link TRB that occupies the last one.
    entries: u16,
    enqueue: u16,
    cycle: bool,
}

impl Ring {
    /// A ring of `entries`, with its Link TRB written into the last slot.
    ///
    /// **Two entries is the minimum**, and one of them is the link: a ring with
    /// only a link has nowhere to put work, and a ring with none does not wrap.
    pub fn new(base: u64, entries: u16, memory: &mut [u8]) -> Result<Ring, Error> {
        if entries < 2 {
            return Err(Error::RingSize);
        }
        if memory.len() < usize::from(entries) * TRB_LEN {
            return Err(Error::ShortBuffer);
        }
        for slot in memory[..usize::from(entries) * TRB_LEN].iter_mut() {
            *slot = 0;
        }
        let mut ring = Ring {
            base,
            entries,
            enqueue: 0,
            cycle: true,
        };
        ring.write_link(memory)?;
        Ok(ring)
    }

    /// Writes the Link TRB in the last slot: back to the base, with the toggle
    /// bit that tells the controller its own cycle flips here.
    fn write_link(&mut self, memory: &mut [u8]) -> Result<(), Error> {
        let link = Trb {
            parameter: self.base,
            status: 0,
            // Toggle cycle in bit 1, and the link's own cycle bit matches the
            // producer's so the controller follows it on this lap.
            control: (trb::LINK << 10) | (1 << 1) | u32::from(self.cycle),
        };
        let at = usize::from(self.entries - 1) * TRB_LEN;
        link.write(&mut memory[at..at + TRB_LEN])
    }

    /// The address of the slot the next `push` will use — what a command's
    /// completion event names, and how a driver matches an answer to a request.
    pub fn enqueue_address(&self) -> u64 {
        self.base + u64::from(self.enqueue) * TRB_LEN as u64
    }

    /// Puts one TRB on the ring, and returns the address it landed at.
    ///
    /// **Wrapping goes through the link**, and crossing it toggles the cycle
    /// bit. A ring that wrapped by resetting an index would hand the controller
    /// entries it has already consumed, with a cycle bit that says they are new.
    pub fn push(&mut self, mut entry: Trb, memory: &mut [u8]) -> Result<u64, Error> {
        entry.control = (entry.control & !1) | u32::from(self.cycle);
        let at = usize::from(self.enqueue) * TRB_LEN;
        if memory.len() < at + TRB_LEN {
            return Err(Error::ShortBuffer);
        }
        entry.write(&mut memory[at..at + TRB_LEN])?;
        let address = self.enqueue_address();
        self.enqueue += 1;
        if self.enqueue == self.entries - 1 {
            // The last slot is the link. Rewrite it with this lap's cycle so
            // the controller follows it, then start again with the cycle
            // flipped.
            self.write_link(memory)?;
            self.enqueue = 0;
            self.cycle = !self.cycle;
        }
        Ok(address)
    }

    /// The cycle this ring is producing at — what a test checks a wrap by.
    pub fn cycle(&self) -> bool {
        self.cycle
    }
}

/// A consumer ring: where the controller puts events.
///
/// Separate from [`Ring`] because the two are not the same thing with the
/// direction reversed. A producer wraps through a link it writes; a consumer
/// wraps by counting to the end of a segment somebody else described, and its
/// cycle bit is the controller's rather than its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventRing {
    base: u64,
    entries: u16,
    dequeue: u16,
    cycle: bool,
}

impl EventRing {
    pub fn new(base: u64, entries: u16) -> Result<EventRing, Error> {
        if entries == 0 {
            return Err(Error::RingSize);
        }
        Ok(EventRing {
            base,
            entries,
            dequeue: 0,
            // The ring is zeroed before the controller runs, so the first lap's
            // events carry a set cycle bit.
            cycle: true,
        })
    }

    /// Where the driver has read up to — what the dequeue pointer is told.
    pub fn dequeue_address(&self) -> u64 {
        self.base + u64::from(self.dequeue) * TRB_LEN as u64
    }

    /// Where in the segment the next event would be.
    ///
    /// Exposed because a driver reading device-written memory has to read it
    /// **volatilely**, one entry at a time: the whole segment is written by the
    /// controller while the driver looks at it, and a slice handed to a
    /// compiler that may cache is a slice that answers with what was there
    /// before the device replied.
    pub fn dequeue_offset(&self) -> usize {
        usize::from(self.dequeue) * TRB_LEN
    }

    /// Takes an event read from [`Self::dequeue_offset`], or gives it back as
    /// `None` when its cycle bit says it belongs to the previous lap.
    ///
    /// The cycle check and the wrap live here rather than in the caller because
    /// they are the same thing: the lap changes exactly where the segment does.
    pub fn accept(&mut self, event: Trb) -> Option<Trb> {
        if (event.control & 1 != 0) != self.cycle {
            return None;
        }
        self.dequeue += 1;
        if self.dequeue == self.entries {
            self.dequeue = 0;
            self.cycle = !self.cycle;
        }
        Some(event)
    }

    /// The next event, or `None` when the controller has not posted one.
    pub fn poll(&mut self, memory: &[u8]) -> Result<Option<Trb>, Error> {
        let at = self.dequeue_offset();
        if memory.len() < at + TRB_LEN {
            return Err(Error::ShortBuffer);
        }
        let event = Trb::read(&memory[at..at + TRB_LEN])?;
        Ok(self.accept(event))
    }
}

/// How many times a bring-up step polls before giving up. A count and not a
/// duration: this crate has no clock, and what the bound buys is that a
/// controller which never answers produces an error rather than a hang.
const POLL_LIMIT: u32 = 1_000_000;

/// A live controller, and the four register bases it reported.
pub struct Controller<'r, R: Registers> {
    regs: &'r R,
    op: usize,
    runtime: usize,
    doorbells: usize,
    max_slots: u8,
    max_ports: u8,
}

impl<'r, R: Registers> Controller<'r, R> {
    /// Reads where everything is, without touching the controller.
    ///
    /// **Nothing here is at a fixed offset.** A driver with a table of
    /// constants works on the controller it was written against and no other,
    /// which is why this is the first thing done and its own step.
    pub fn discover(regs: &'r R) -> Result<Self, Error> {
        let length = (regs.read32(cap::LENGTH_VERSION) & 0xff) as usize;
        let params = regs.read32(cap::HCSPARAMS1);
        let doorbells = (regs.read32(cap::DBOFF) & !0x3) as usize;
        let runtime = (regs.read32(cap::RTSOFF) & !0x1f) as usize;
        let max_slots = (params & 0xff) as u8;
        let max_ports = (params >> 24) as u8;
        if length == 0 || doorbells == 0 || runtime == 0 || max_slots == 0 || max_ports == 0 {
            return Err(Error::BadLayout);
        }
        Ok(Controller {
            regs,
            op: length,
            runtime,
            doorbells,
            max_slots,
            max_ports,
        })
    }

    pub fn max_slots(&self) -> u8 {
        self.max_slots
    }

    pub fn max_ports(&self) -> u8 {
        self.max_ports
    }

    /// How many scratchpad pages the controller wants for its own use.
    ///
    /// Memory the driver allocates and never reads: it belongs to the
    /// controller, which needs somewhere to put internal state. A driver that
    /// ignored a non-zero count would leave the first entry of the device
    /// context array pointing at nothing, and the controller would write there.
    pub fn scratchpad_count(&self) -> u32 {
        let params = self.regs.read32(cap::HCSPARAMS2);
        (((params >> 21) & 0x1f) << 5) | ((params >> 27) & 0x1f)
    }

    /// The link speed a port negotiated, out of `PORTSC` bits 13:10.
    pub fn port_speed(&self, port: u8) -> Result<u8, Error> {
        Ok(((self.port_status(port)? >> 10) & 0xf) as u8)
    }

    /// Resets the controller and starts it, with the rings the caller has
    /// prepared.
    ///
    /// The order is the specification's and every step of it matters: the
    /// controller must be halted before it is reset, and out of reset before
    /// any pointer is written — the registers below are only sampled while it
    /// is stopped, so writing them to a running controller sets nothing.
    pub fn reset_and_run(
        &self,
        dcbaa: u64,
        command_ring: &Ring,
        erst: u64,
        event_ring: &EventRing,
    ) -> Result<(), Error> {
        // Stop it, then reset it.
        let running = self.regs.read32(self.op + op::USBCMD);
        self.regs.write32(self.op + op::USBCMD, running & !cmd::RUN);
        self.wait_status(sts::HALTED, true)?;
        self.regs.write32(self.op + op::USBCMD, cmd::RESET);
        for _ in 0..POLL_LIMIT {
            let command = self.regs.read32(self.op + op::USBCMD);
            let status = self.regs.read32(self.op + op::USBSTS);
            if command & cmd::RESET == 0 && status & sts::NOT_READY == 0 {
                break;
            }
        }
        if self.regs.read32(self.op + op::USBCMD) & cmd::RESET != 0 {
            return Err(Error::NotReady);
        }

        // Every slot this controller has. Asked for in full rather than by
        // count, because a driver that enabled fewer would find a device on a
        // port it could not address and have nothing to say about why.
        self.regs
            .write32(self.op + op::CONFIG, u32::from(self.max_slots));
        self.write64(self.op + op::DCBAAP, dcbaa);
        // The command ring's cycle bit travels with its address: the controller
        // has to agree with the producer about which lap it is on.
        self.write64(
            self.op + op::CRCR,
            command_ring.base | u64::from(command_ring.cycle),
        );

        // One event ring segment.
        self.regs.write32(self.runtime + rt::ERSTSZ, 1);
        self.write64(self.runtime + rt::ERDP, event_ring.dequeue_address());
        // The base last: the controller reads the segment table when this is
        // written, so a table it read before the size was set would describe a
        // ring of no segments.
        self.write64(self.runtime + rt::ERSTBA, erst);
        self.regs.write32(self.runtime + rt::IMAN, 0b10);

        self.regs
            .write32(self.op + op::USBCMD, cmd::RUN | cmd::INTERRUPTER_ENABLE);
        self.wait_status(sts::HALTED, false)
    }

    /// Rings a doorbell: slot zero is the command ring, and any other is an
    /// endpoint on that slot.
    pub fn doorbell(&self, slot: u8, endpoint: u32) {
        self.regs
            .write32(self.doorbells + usize::from(slot) * 4, endpoint);
    }

    /// Tells the controller how far the driver has consumed the event ring.
    ///
    /// Bit 3 is the busy flag, written back as a one to clear it — a driver
    /// that left it set would have the controller believe the interrupter is
    /// still being serviced and raise nothing further.
    pub fn set_event_dequeue(&self, event_ring: &EventRing) {
        self.write64(
            self.runtime + rt::ERDP,
            event_ring.dequeue_address() | 0b1000,
        );
    }

    /// One port's status register.
    pub fn port_status(&self, port: u8) -> Result<u32, Error> {
        if port == 0 || port > self.max_ports {
            return Err(Error::NoSuchPort);
        }
        Ok(self
            .regs
            .read32(self.op + op::PORTSC + usize::from(port - 1) * op::PORT_STRIDE))
    }

    /// Powers a port and resets whatever is attached, leaving it enabled.
    ///
    /// **Every write masks the change bits off.** They are write-one-to-clear,
    /// so a read-modify-write that put them back would clear a notification
    /// nobody had acted on — and the device that arrived would never be
    /// enumerated.
    pub fn reset_port(&self, port: u8) -> Result<(), Error> {
        let at = self.op
            + op::PORTSC
            + usize::from(port.checked_sub(1).ok_or(Error::NoSuchPort)?) * op::PORT_STRIDE;
        if port > self.max_ports {
            return Err(Error::NoSuchPort);
        }
        let current = self.regs.read32(at) & !port::CHANGE_BITS;
        self.regs.write32(at, current | port::POWER);
        let current = self.regs.read32(at) & !port::CHANGE_BITS;
        self.regs.write32(at, current | port::RESET);
        for _ in 0..POLL_LIMIT {
            let status = self.regs.read32(at);
            if status & port::RESET == 0 && status & port::ENABLED != 0 {
                // Acknowledge the change bits this reset raised, and only
                // those.
                self.regs
                    .write32(at, (status & !port::CHANGE_BITS) | port::RESET_CHANGED);
                return Ok(());
            }
        }
        Err(Error::NotReady)
    }

    /// Waits for a `USBSTS` bit to reach `want`.
    fn wait_status(&self, bit: u32, want: bool) -> Result<(), Error> {
        for _ in 0..POLL_LIMIT {
            if (self.regs.read32(self.op + op::USBSTS) & bit != 0) == want {
                return Ok(());
            }
        }
        Err(Error::NotReady)
    }

    /// Writes a 64-bit register as two halves, low first.
    ///
    /// Low first because the high half is what the controller latches on: a
    /// pointer whose high word arrived before its low one names an address that
    /// existed for an instant and was never meant.
    fn write64(&self, offset: usize, value: u64) {
        self.regs.write32(offset, value as u32);
        self.regs.write32(offset + 4, (value >> 32) as u32);
    }
}

impl Ring {
    /// The address the controller reads this ring from.
    pub fn base(&self) -> u64 {
        self.base
    }
}
