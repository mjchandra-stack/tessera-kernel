// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The NVMe transport core: controller bring-up, the admin and I/O queue pair
//! protocol, the command encodings, and completion-queue parsing.
//!
//! Register access goes through the [`Registers`] trait, so the fragile parts —
//! the enable handshake, the doorbell arithmetic, the 64-byte command layout and
//! the phase tag that says whether a completion is this pass's or the last
//! one's — are ordinary logic a mock exercises on the host. The caller supplies
//! the real volatile access and the memory the controller reads; this crate
//! forbids `unsafe`.
//!
//! **Everything the controller reports is external input.** A completion naming
//! a command nobody submitted, a queue size larger than the controller
//! supports, a status field the specification does not define: each is a typed
//! [`Error`], never a panic and never a silently truncated value.
//!
//! # Why the phase tag is the interesting part
//!
//! A completion queue is a ring the controller writes and the driver reads, and
//! nothing in an entry says "this is new". What says so is one bit, flipped
//! every time the controller wraps. A driver that read the queue without
//! tracking it would process the previous pass's completions again on every
//! wrap — which looks exactly like a device completing work twice, and is the
//! one bug in this protocol that a test can provoke on demand and a machine
//! almost never will.
//!
//! # What this crate deliberately does not do
//!
//! It allocates nothing and maps nothing. Queues, PRP pages and the addresses
//! the controller is told are the caller's, because on this system they come
//! from capabilities — a ring-3 driver's memory objects and DMA attachments —
//! and a transport core that allocated would have to know which of those it was
//! running under.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage"),
//! docs/hardware/04-device-memory-and-unified-memory.md
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
    /// The controller did not become ready, or did not go un-ready, within the
    /// bounded wait. Reported rather than waited on forever: a controller that
    /// never answers is a machine fault, and a driver spinning on it is one
    /// that never says so.
    NotReady,
    /// The controller set `CSTS.CFS` — a fatal status it raises when it cannot
    /// continue. Distinct from [`Self::NotReady`] because it is the controller
    /// saying something went wrong rather than saying nothing at all.
    ControllerFatal,
    /// A queue size of zero, not a power of two where one is required, or
    /// larger than the controller's `CAP.MQES` allows.
    QueueSize,
    /// A buffer handed in is too small for the structure it must hold.
    ShortBuffer,
    /// A completion entry named a queue or a command that cannot be right.
    BadCompletion,
    /// The controller reports a memory page size minimum this driver cannot
    /// meet — it works in 4 KiB pages and nothing else.
    UnsupportedPageSize,
}

/// Controller registers this crate reads and writes. Offsets are from the start
/// of the controller's register window (BAR 0 on a PCI function).
///
/// 32-bit access only, and the 64-bit registers are read and written as two
/// halves. That is what the specification permits and what a ring-3 driver
/// holding a mapped window can actually do without assuming the width of a
/// single store the compiler chose for it.
pub trait Registers {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&self, offset: usize, value: u32);
}

/// Controller register offsets.
pub mod reg {
    /// Controller capabilities, 64-bit.
    pub const CAP: usize = 0x00;
    pub const CAP_HIGH: usize = 0x04;
    /// Version.
    pub const VS: usize = 0x08;
    /// Controller configuration.
    pub const CC: usize = 0x14;
    /// Controller status.
    pub const CSTS: usize = 0x1c;
    /// Admin queue attributes: submission size in 11:0, completion in 27:16,
    /// both as entries minus one.
    pub const AQA: usize = 0x24;
    /// Admin submission queue base, 64-bit.
    pub const ASQ: usize = 0x28;
    pub const ASQ_HIGH: usize = 0x2c;
    /// Admin completion queue base, 64-bit.
    pub const ACQ: usize = 0x30;
    pub const ACQ_HIGH: usize = 0x34;
    /// Where the doorbell registers start.
    pub const DOORBELL_BASE: usize = 0x1000;
}

/// `CC` fields.
mod cc {
    pub const ENABLE: u32 = 1;
    /// I/O submission queue entry size, as a power of two, in bits 19:16. A
    /// command is 64 bytes.
    pub const IOSQES_SHIFT: u32 = 16;
    /// I/O completion queue entry size, bits 23:20. A completion is 16 bytes.
    pub const IOCQES_SHIFT: u32 = 20;
}

/// `CSTS` fields.
mod csts {
    pub const READY: u32 = 1;
    /// Controller fatal status.
    pub const FATAL: u32 = 1 << 1;
}

/// Bytes in one submission queue entry.
pub const COMMAND_LEN: usize = 64;
/// Bytes in one completion queue entry.
pub const COMPLETION_LEN: usize = 16;
/// The page size this driver works in, and the only one it claims to support.
pub const PAGE_SIZE: u64 = 4096;

/// Admin command opcodes.
pub const ADMIN_CREATE_IO_SQ: u8 = 0x01;
pub const ADMIN_CREATE_IO_CQ: u8 = 0x05;
pub const ADMIN_IDENTIFY: u8 = 0x06;

/// NVM command opcodes.
pub const NVM_WRITE: u8 = 0x01;
pub const NVM_READ: u8 = 0x02;

/// `Identify` CNS values: the controller itself, and one namespace.
pub const CNS_NAMESPACE: u8 = 0x00;
pub const CNS_CONTROLLER: u8 = 0x01;

/// How many times a bring-up step polls before giving up.
///
/// A count and not a duration, because this crate has no clock — the caller
/// does, and one that wants a real timeout wraps this. What the bound buys is
/// that a controller which never answers produces an error rather than a hang,
/// which is the difference between a machine that reports a fault and one that
/// stops.
const READY_POLLS: u32 = 1_000_000;

/// The physical addresses of one queue pair's two rings.
///
/// Physical, because these are what the *controller* is told, and it has no
/// address space of its own to resolve anything in. On a machine with an IOMMU
/// they are device addresses; the difference is the caller's and deliberately
/// not this crate's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QueuePair {
    pub submission: u64,
    pub completion: u64,
    /// Entries in each ring. Both rings of a pair are the same length here,
    /// which is not required by the specification and is what every driver
    /// does: a completion queue shorter than its submission queue can be
    /// overrun by the commands the driver is entitled to have outstanding.
    pub entries: u16,
}

/// A live controller: the register window, and the two facts read out of `CAP`
/// that everything afterwards depends on.
pub struct Controller<'r, R: Registers> {
    regs: &'r R,
    /// `CAP.DSTRD`, as the shift the specification defines it to be.
    doorbell_stride: u32,
    /// `CAP.MQES + 1` — the largest queue the controller will accept.
    max_entries: u16,
}

impl<'r, R: Registers> Controller<'r, R> {
    /// Takes the controller through reset and enable with `admin` as its admin
    /// queue pair, leaving it ready to accept admin commands.
    ///
    /// The order is the specification's and every step of it matters: the
    /// controller must be observed *not* ready before its queue registers are
    /// written, because they are only sampled while it is disabled, and a
    /// driver that wrote them to a running controller would enable it against
    /// whatever the last one left behind.
    pub fn reset_and_enable(regs: &'r R, admin: QueuePair) -> Result<Self, Error> {
        let cap_low = regs.read32(reg::CAP);
        let cap_high = regs.read32(reg::CAP_HIGH);
        let max_entries = ((cap_low & 0xffff) as u16).saturating_add(1);
        let doorbell_stride = cap_high & 0xf;
        // `CAP.MPSMIN` is in bits 51:48 — bits 19:16 of the high word — as
        // `2^(12 + n)`. Anything but zero is a controller whose smallest page
        // is larger than the one this driver works in, and there is nothing to
        // negotiate: the PRP entries it would build would be the wrong size.
        if (cap_high >> 16) & 0xf != 0 {
            return Err(Error::UnsupportedPageSize);
        }
        if admin.entries == 0 || admin.entries > max_entries {
            return Err(Error::QueueSize);
        }

        // Disable, and wait for the controller to say it has stopped.
        regs.write32(reg::CC, 0);
        Self::wait_ready(regs, false)?;

        regs.write32(
            reg::AQA,
            u32::from(admin.entries - 1) | (u32::from(admin.entries - 1) << 16),
        );
        regs.write32(reg::ASQ, admin.submission as u32);
        regs.write32(reg::ASQ_HIGH, (admin.submission >> 32) as u32);
        regs.write32(reg::ACQ, admin.completion as u32);
        regs.write32(reg::ACQ_HIGH, (admin.completion >> 32) as u32);

        // Entry sizes are powers of two: 64-byte commands and 16-byte
        // completions. Memory page size, arbitration and command set all take
        // their zero values, which are 4 KiB, round-robin and NVM — the ones
        // this driver is written for and the ones `CAP` was just checked to
        // allow.
        let config = cc::ENABLE | (6 << cc::IOSQES_SHIFT) | (4 << cc::IOCQES_SHIFT);
        regs.write32(reg::CC, config);
        Self::wait_ready(regs, true)?;

        Ok(Controller {
            regs,
            doorbell_stride,
            max_entries,
        })
    }

    /// Spins until `CSTS.RDY` matches `want`, or the bound is spent.
    ///
    /// A fatal status ends the wait early and on its own error: a controller
    /// that has given up will never become ready, and waiting out the full
    /// bound would report "no answer" for something that answered.
    fn wait_ready(regs: &R, want: bool) -> Result<(), Error> {
        for _ in 0..READY_POLLS {
            let status = regs.read32(reg::CSTS);
            if status & csts::FATAL != 0 {
                return Err(Error::ControllerFatal);
            }
            if (status & csts::READY != 0) == want {
                return Ok(());
            }
        }
        Err(Error::NotReady)
    }

    /// A view of a controller that is **already enabled**, for the doorbell
    /// arithmetic alone.
    ///
    /// Ringing a bell needs only what `CAP` says — the stride — and a driver
    /// that has already brought the controller up must not take it through
    /// reset again to send a command. Separate from
    /// [`reset_and_enable`](Self::reset_and_enable) rather than a flag on it,
    /// because the two differ in whether they may destroy the queues the caller
    /// is holding, and that is not a difference to hide behind an argument.
    pub fn attach(regs: &'r R) -> Self {
        let cap_low = regs.read32(reg::CAP);
        let cap_high = regs.read32(reg::CAP_HIGH);
        Controller {
            regs,
            doorbell_stride: cap_high & 0xf,
            max_entries: ((cap_low & 0xffff) as u16).saturating_add(1),
        }
    }

    /// The largest queue this controller accepts.
    pub fn max_queue_entries(&self) -> u16 {
        self.max_entries
    }

    /// The controller's version register, as it reports it.
    pub fn version(&self) -> u32 {
        self.regs.read32(reg::VS)
    }

    /// Where queue `qid`'s doorbell is, in bytes from the register window's
    /// start. `completion` selects the completion queue's head doorbell over
    /// the submission queue's tail.
    ///
    /// The stride is the controller's to choose and is why this is arithmetic
    /// rather than a table: a controller may space its doorbells out so that
    /// each lands on its own page, which is exactly what lets one queue be
    /// granted to one process without granting the rest.
    pub fn doorbell_offset(&self, qid: u16, completion: bool) -> usize {
        let index = usize::from(qid) * 2 + usize::from(completion);
        reg::DOORBELL_BASE + index * (4usize << self.doorbell_stride)
    }

    /// Tells the controller that `tail` is the next free slot in queue `qid`'s
    /// submission ring — the write that makes a command visible to it.
    pub fn ring_submission(&self, qid: u16, tail: u16) {
        self.regs
            .write32(self.doorbell_offset(qid, false), u32::from(tail));
    }

    /// Tells the controller how far the driver has consumed queue `qid`'s
    /// completion ring, freeing those slots for reuse.
    pub fn ring_completion(&self, qid: u16, head: u16) {
        self.regs
            .write32(self.doorbell_offset(qid, true), u32::from(head));
    }

    /// Checks a queue size against what the controller accepts. Refused rather
    /// than clamped: a driver that asked for more entries than it got would
    /// submit past the end of a ring the controller is reading.
    pub fn check_queue_size(&self, entries: u16) -> Result<(), Error> {
        if entries == 0 || entries > self.max_entries {
            return Err(Error::QueueSize);
        }
        Ok(())
    }
}

/// Writes a little-endian u32 at `at` in `entry`.
fn put_u32(entry: &mut [u8], at: usize, value: u32) {
    entry[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// Reads a little-endian u32 at `at`.
fn get_u32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

/// Writes a little-endian u64 at `at`.
fn put_u64(entry: &mut [u8], at: usize, value: u64) {
    entry[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Clears `entry` and writes the fields every command shares: the opcode, the
/// command identifier, the namespace, and the first PRP entry.
///
/// **Cleared first, and that is not hygiene.** A submission ring is reused, so
/// every slot holds the last command that occupied it; a builder that wrote
/// only the fields it cared about would leave the previous command's
/// namespace, its second PRP entry and its command-specific dwords in place,
/// and the controller would act on them.
fn begin(entry: &mut [u8], opcode: u8, cid: u16, nsid: u32, prp1: u64) -> Result<(), Error> {
    if entry.len() < COMMAND_LEN {
        return Err(Error::ShortBuffer);
    }
    entry[..COMMAND_LEN].fill(0);
    put_u32(entry, 0, u32::from(opcode) | (u32::from(cid) << 16));
    put_u32(entry, 4, nsid);
    put_u64(entry, 24, prp1);
    Ok(())
}

/// Builds an `Identify` command, whose result the controller writes into the
/// 4 KiB page at `prp1`.
pub fn write_identify(
    entry: &mut [u8],
    cid: u16,
    prp1: u64,
    cns: u8,
    nsid: u32,
) -> Result<(), Error> {
    begin(entry, ADMIN_IDENTIFY, cid, nsid, prp1)?;
    put_u32(entry, 40, u32::from(cns));
    Ok(())
}

/// Builds `Create I/O Completion Queue`.
///
/// `vector` is the MSI-X vector this queue's completions will raise, and
/// interrupts are enabled here rather than left to a later call — a completion
/// queue created with them off is one whose first completion arrives silently,
/// and a driver waiting on an interrupt for it would wait forever.
pub fn write_create_completion_queue(
    entry: &mut [u8],
    cid: u16,
    prp1: u64,
    qid: u16,
    entries: u16,
    vector: u16,
) -> Result<(), Error> {
    if entries == 0 {
        return Err(Error::QueueSize);
    }
    begin(entry, ADMIN_CREATE_IO_CQ, cid, 0, prp1)?;
    put_u32(entry, 40, u32::from(qid) | (u32::from(entries - 1) << 16));
    // Physically contiguous, interrupts enabled, and the vector.
    put_u32(entry, 44, 0b11 | (u32::from(vector) << 16));
    Ok(())
}

/// Builds `Create I/O Submission Queue`, bound to completion queue `cqid`.
pub fn write_create_submission_queue(
    entry: &mut [u8],
    cid: u16,
    prp1: u64,
    qid: u16,
    entries: u16,
    cqid: u16,
) -> Result<(), Error> {
    if entries == 0 {
        return Err(Error::QueueSize);
    }
    begin(entry, ADMIN_CREATE_IO_SQ, cid, 0, prp1)?;
    put_u32(entry, 40, u32::from(qid) | (u32::from(entries - 1) << 16));
    // Physically contiguous, medium priority, and which completion queue this
    // one's completions go to.
    put_u32(entry, 44, 0b1 | (u32::from(cqid) << 16));
    Ok(())
}

/// Builds a read of `blocks` logical blocks starting at `lba`, into the buffer
/// the controller reaches at `prp1`.
///
/// **One PRP entry and no list.** A PRP list exists because a controller cannot
/// follow a scattered buffer; on a machine whose devices sit behind an IOMMU
/// the broker hands out one contiguous device address over scattered pages, so
/// a single entry covers the whole transfer. `blocks` is refused above what one
/// entry can describe rather than silently truncated, because a driver told it
/// read more than it did would return a buffer with a stale tail.
pub fn write_read(
    entry: &mut [u8],
    cid: u16,
    nsid: u32,
    prp1: u64,
    lba: u64,
    blocks: u16,
    block_size: u64,
) -> Result<(), Error> {
    if blocks == 0 {
        return Err(Error::ShortBuffer);
    }
    // One PRP entry addresses from `prp1` to the end of its page, and the
    // specification requires the *first* entry to be page-aligned for a
    // transfer this simple.
    if !prp1.is_multiple_of(PAGE_SIZE) || u64::from(blocks) * block_size > PAGE_SIZE {
        return Err(Error::ShortBuffer);
    }
    begin(entry, NVM_READ, cid, nsid, prp1)?;
    put_u64(entry, 40, lba);
    put_u32(entry, 48, u32::from(blocks - 1));
    Ok(())
}

/// Builds a write of `blocks` logical blocks at `lba`, out of the buffer the
/// controller reaches at `prp1`.
///
/// The same shape as [`write_read`] and the same bounds, because on this
/// transport they are the same command with one opcode changed — which is worth
/// keeping visible rather than hiding behind a direction flag, since the
/// *consequences* of getting the bounds wrong are not symmetric: a short read
/// returns stale bytes, and a short write leaves a sector half-written.
pub fn write_write(
    entry: &mut [u8],
    cid: u16,
    nsid: u32,
    prp1: u64,
    lba: u64,
    blocks: u16,
    block_size: u64,
) -> Result<(), Error> {
    if blocks == 0 {
        return Err(Error::ShortBuffer);
    }
    if !prp1.is_multiple_of(PAGE_SIZE) || u64::from(blocks) * block_size > PAGE_SIZE {
        return Err(Error::ShortBuffer);
    }
    begin(entry, NVM_WRITE, cid, nsid, prp1)?;
    put_u64(entry, 40, lba);
    put_u32(entry, 48, u32::from(blocks - 1));
    Ok(())
}

/// One completion the controller posted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Completion {
    /// The command this answers, as the driver identified it.
    pub cid: u16,
    /// Which submission queue it came from.
    pub sqid: u16,
    /// How far the controller has consumed that submission queue.
    pub sq_head: u16,
    /// Status type and status code, packed as `(SCT << 8) | SC`. Zero is
    /// success; everything else is the controller declining, and the pair is
    /// carried rather than reduced to a boolean because a driver's response to
    /// "the namespace is gone" is not its response to "that LBA is out of
    /// range".
    pub status: u16,
}

impl Completion {
    /// Whether the command succeeded.
    pub fn is_success(&self) -> bool {
        self.status == 0
    }
}

/// A driver's view of one completion ring: how far it has read, and which pass
/// it is on.
///
/// The phase is the whole reason this is a type rather than a function. Nothing
/// in a completion entry says it is new; what says so is one bit, which the
/// controller flips every time it wraps. A reader that did not track it would
/// see the previous pass's completions again on every wrap and report work
/// completing twice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompletionRing {
    entries: u16,
    head: u16,
    /// The phase value that marks an entry as belonging to this pass. Starts
    /// `true`: the ring is zeroed before the controller is enabled, so the
    /// first entries it writes carry a set phase bit.
    phase: bool,
}

impl CompletionRing {
    /// A fresh view of a ring of `entries`, positioned before the first one.
    pub fn new(entries: u16) -> Result<Self, Error> {
        if entries == 0 {
            return Err(Error::QueueSize);
        }
        Ok(CompletionRing {
            entries,
            head: 0,
            phase: true,
        })
    }

    /// How far this reader has consumed the ring — what its doorbell is told.
    pub fn head(&self) -> u16 {
        self.head
    }

    /// The next completion, or `None` when the controller has not posted one
    /// since the last call.
    ///
    /// Advances the head and flips the phase on a wrap, so a caller that polls
    /// in a loop drains exactly what arrived and stops.
    pub fn poll(&mut self, ring: &[u8]) -> Result<Option<Completion>, Error> {
        let at = usize::from(self.head) * COMPLETION_LEN;
        if ring.len() < at + COMPLETION_LEN {
            return Err(Error::ShortBuffer);
        }
        let status_word = get_u32(ring, at + 12);
        if (status_word & (1 << 16) != 0) != self.phase {
            return Ok(None);
        }
        let queues = get_u32(ring, at + 8);
        let completion = Completion {
            cid: (status_word & 0xffff) as u16,
            sqid: (queues >> 16) as u16,
            sq_head: (queues & 0xffff) as u16,
            status: (status_word >> 17) as u16,
        };
        // A completion whose submission-queue head points past the end of a
        // ring is a controller describing a queue that cannot exist. Reported
        // rather than used: the head is what a driver frees slots against, and
        // acting on this one would free slots it still has commands in.
        if completion.sq_head > self.entries {
            return Err(Error::BadCompletion);
        }
        self.head += 1;
        if self.head == self.entries {
            self.head = 0;
            self.phase = !self.phase;
        }
        Ok(Some(completion))
    }
}
