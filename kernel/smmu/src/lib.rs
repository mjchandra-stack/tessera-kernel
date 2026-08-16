// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! SMMUv3: the stream table, its queues, and stage-2 translation — what puts
//! a device's DMA behind an address space instead of loose in physical memory.
//!
//! `docs/drivers/01` ("DMA Safety") requires mappings "scoped to a device";
//! until this, a driver programmed a device with a physical address and the
//! device was obeyed. The unit of scoping here is the **stream**: the bus
//! gives each function a stream id, the stream table says what that stream may
//! reach, and a transaction the table does not cover is aborted by hardware
//! rather than by anyone's good behaviour.
//!
//! Everything in this crate is **encoding**, not poking: descriptor layouts,
//! queue index arithmetic, and event decoding, all behind a [`Registers`]
//! trait the caller implements. That division is the same one `kernel/pci` and
//! `kernel/virtio` use, and it exists because encoding is the part a mock can
//! check — a stream-table entry with a field in the wrong place produces a
//! device that appears configured and translates wrongly.
//!
//! **The event queue is not decoration.** When the SMMU refuses a
//! transaction it records *why*, for which stream, and at which address. That
//! turns "the DMA did not arrive" — which a misconfiguration produces just as
//! readily as a correct refusal — into evidence naming one or the other.
//!
//! Field positions are from the Arm SMMUv3 architecture specification
//! (IHI 0070), chapter 5 for the stream table and context descriptors and
//! chapter 4 for the queues; stage-2 descriptors are VMSAv8-64 (DDI 0487,
//! D8.3). Each is encoded in exactly one place here so a wrong bit is wrong
//! once and a test can pin it.
//!
//! Normative: docs/drivers/01-driver-framework.md ("DMA Safety"),
//! docs/hardware/04-device-memory-and-unified-memory.md
//! Budget: none (boot-time configuration)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// What can go wrong configuring the SMMU. Every variant is a fact about the
/// hardware or about what the caller asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The stream id is wider than the stream table the caller sized.
    StreamOutOfRange,
    /// A structure the hardware reads was not aligned as it requires.
    Unaligned,
    /// The address to map, or the frame backing it, is not page aligned.
    UnalignedMapping,
    /// The aperture's translation tables cannot express this address with the
    /// levels the caller provided.
    ApertureTooSmall,
    /// The command queue is full — the caller must consume before issuing.
    QueueFull,
    /// The SMMU did not acknowledge an enable within the caller's bound.
    NotAcknowledged,
}

/// 32-bit and 64-bit register access to the SMMU's own register page. The
/// only hardware-touching surface; an implementation performs the volatile
/// access and is where the `unsafe` lives.
pub trait Registers {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
    fn read64(&self, offset: usize) -> u64;
    fn write64(&mut self, offset: usize, value: u64);
}

/// Register offsets in the SMMU page (IHI 0070, chapter 6).
pub mod reg {
    pub const IDR0: usize = 0x000;
    pub const IDR1: usize = 0x004;
    pub const CR0: usize = 0x020;
    pub const CR0ACK: usize = 0x024;
    pub const CR1: usize = 0x028;
    pub const CR2: usize = 0x02c;
    /// Which of the unit's own interrupts it may raise, and the acknowledge
    /// register that says the setting took.
    pub const IRQ_CTRL: usize = 0x050;
    pub const IRQ_CTRLACK: usize = 0x054;
    pub const GBPA: usize = 0x044;
    pub const STRTAB_BASE: usize = 0x080;
    pub const STRTAB_BASE_CFG: usize = 0x088;
    pub const CMDQ_BASE: usize = 0x090;
    pub const CMDQ_PROD: usize = 0x098;
    pub const CMDQ_CONS: usize = 0x09c;
    pub const EVENTQ_BASE: usize = 0x0a0;
    /// The event queue's producer and consumer indices live in the *second*
    /// 64 KiB page on an implementation with two pages; QEMU places them at
    /// these page-0 aliases, which is what this crate uses.
    pub const EVENTQ_PROD: usize = 0x100a8;
    pub const EVENTQ_CONS: usize = 0x100ac;
}

/// `CR0` bits.
pub mod cr0 {
    /// Enable the SMMU. Until this is set every stream bypasses, which is why
    /// the tables must be in place before it goes on.
    pub const SMMUEN: u32 = 1 << 0;
    pub const EVENTQEN: u32 = 1 << 2;
    pub const CMDQEN: u32 = 1 << 3;
}

/// `IRQ_CTRL` bits — which of the unit's own interrupts it may raise.
///
/// **`EVENTQ` is what turns the event queue from a log into a report.** The
/// queue records every refusal whether or not this is set; without it nothing
/// tells the kernel a record has arrived, so faults are only ever seen by a
/// reader that happened to look — which is a fault harvest that works during a
/// boot check and not on a running system.
pub mod irq_ctrl {
    /// Raise an interrupt when a record is written to the event queue.
    pub const EVENTQ: u32 = 1 << 2;
    /// Raise one for a PRI queue record (no consumer here).
    pub const PRIQ: u32 = 1 << 1;
    /// Raise one for a global error (no consumer here).
    pub const GERROR: u32 = 1 << 0;
}

/// `GBPA` bits — what happens to a stream the table does not describe.
pub mod gbpa {
    /// Write-enable for the register: `GBPA` only takes the other fields when
    /// this is set in the same write.
    pub const UPDATE: u32 = 1 << 31;
    /// Abort unmatched streams rather than letting them bypass. Without this
    /// an SMMU with an empty table is indistinguishable from no SMMU at all.
    pub const ABORT: u32 = 1 << 20;
}

/// Bytes in one stream table entry.
pub const STE_SIZE: usize = 64;
/// Bytes in one command-queue entry.
pub const CMD_SIZE: usize = 16;
/// Bytes in one event-queue record.
pub const EVENT_SIZE: usize = 32;

/// `STE.Config` — what the entry does with a transaction.
pub mod ste_config {
    /// Abort every transaction from this stream.
    pub const ABORT: u64 = 0b000;
    /// Pass transactions through untranslated.
    pub const BYPASS: u64 = 0b100;
    /// Bypass stage 1, translate through stage 2. What an aperture uses:
    /// there is no guest here, so stage 1 has nothing to say.
    pub const S2_TRANSLATE: u64 = 0b110;
}

/// Builds the eight words of a stream table entry that translates through
/// stage 2.
///
/// `s2ttb` is the physical address of the stage-2 table root, `vmid`
/// identifies the address space for TLB purposes, and `t0sz` is the same
/// size field the table itself was built for — passing one that disagrees
/// with the table produces a walk that starts at the wrong level, which the
/// hardware reports as a translation fault and no amount of staring at the
/// table explains.
pub fn stream_table_entry_s2(s2ttb: u64, vmid: u16, t0sz: u32, start_level: u32) -> [u64; 8] {
    let mut ste = [0u64; 8];
    // Word 0: valid, and the configuration.
    ste[0] = 1 | (ste_config::S2_TRANSLATE << 1);
    // Word 2: the stage-2 translation control. Fields, in the order the
    // specification lists them: VMID at 0, T0SZ at 32, SL0 at 38, IRGN/ORGN
    // (write-back cacheable) at 40/42, SH (inner shareable) at 44, TG at 46,
    // PS (40-bit physical) at 48, AA64 at 51, and R/S2PTW left clear.
    //
    // TG is **not** written: its 4 KiB granule encoding is `0b00`, so the term
    // would be a no-op that reads like a setting. The granule is still a
    // decision — `stage2_page_descriptor` and `level_index` encode the same
    // one — and this is where it is recorded.
    ste[2] = u64::from(vmid)
        | (u64::from(t0sz) << 32)
        | (u64::from(start_level) << 38)
        | (0b01 << 40)
        | (0b01 << 42)
        | (0b11 << 44)
        | (0b010 << 48)
        | (1 << 51)
        // S2R at 58: **record** stage-2 faults in the event queue. Without it
        // a fault is terminated silently, which is indistinguishable from a
        // transaction that never happened — and an aperture whose refusals
        // cannot be observed is an aperture nobody can verify.
        | (1 << 58);
    // Word 3: the table root. The low bits are not part of the address.
    ste[3] = s2ttb & !0xfff;
    ste
}

/// The entry an unconfigured stream gets: not valid, so the SMMU aborts and
/// records why. Written explicitly rather than left as whatever the frame
/// held — an uninitialised stream table is a table of undefined behaviour.
pub fn stream_table_entry_abort() -> [u64; 8] {
    [0u64; 8]
}

/// Command opcodes (IHI 0070, chapter 4).
pub mod cmd {
    pub const CFGI_STE: u64 = 0x03;
    pub const CFGI_ALL: u64 = 0x04;
    pub const TLBI_NSNH_ALL: u64 = 0x30;
    pub const SYNC: u64 = 0x46;
}

/// A command-queue entry: two 64-bit words.
pub type Command = [u64; 2];

/// `CFGI_STE`: tell the SMMU a stream table entry changed.
///
/// Without it the SMMU may keep using a configuration it cached earlier, so
/// the table in memory and the behaviour observed disagree — a discrepancy
/// that looks like a wrong entry and is not one.
pub fn cmd_cfgi_ste(stream: u32) -> Command {
    // Opcode at 0, StreamID at 32; Leaf (bit 0 of word 1) set because a
    // linear table has no intermediate level to invalidate.
    [cmd::CFGI_STE | (u64::from(stream) << 32), 1]
}

/// `CFGI_ALL`: invalidate every cached configuration.
pub fn cmd_cfgi_all() -> Command {
    // Range covers the whole stream space.
    [cmd::CFGI_ALL, 31]
}

/// `TLBI_NSNH_ALL`: drop every non-secure, non-hypervisor TLB entry.
pub fn cmd_tlbi_nsnh_all() -> Command {
    [cmd::TLBI_NSNH_ALL, 0]
}

/// `SYNC`: complete when everything queued before it has taken effect. The
/// only way to know a configuration change is live.
pub fn cmd_sync() -> Command {
    // CS = 0 (no interrupt, signal by CONS advancing), MSH/MSIATTR clear.
    [cmd::SYNC, 0]
}

/// A queue's producer/consumer index: an index plus a wrap bit above it.
///
/// The wrap bit is what distinguishes full from empty — both have equal index
/// fields — and forgetting it is the classic way a ring buffer silently drops
/// or replays entries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QueueIndex {
    /// Log2 of the queue's entry count.
    pub log2_entries: u32,
    pub raw: u32,
}

impl QueueIndex {
    pub const fn new(log2_entries: u32, raw: u32) -> Self {
        Self { log2_entries, raw }
    }

    /// The entry this index names.
    pub const fn index(self) -> u32 {
        self.raw & ((1 << self.log2_entries) - 1)
    }

    /// The wrap bit, which flips each time the index passes the end.
    pub const fn wrap(self) -> u32 {
        (self.raw >> self.log2_entries) & 1
    }

    /// The next index, carrying into the wrap bit.
    pub const fn next(self) -> Self {
        Self {
            log2_entries: self.log2_entries,
            raw: self.raw.wrapping_add(1) & ((1 << (self.log2_entries + 1)) - 1),
        }
    }

    /// Whether a producer at `self` would overrun a consumer at `cons`:
    /// same index, different wrap.
    pub const fn would_overrun(self, cons: QueueIndex) -> bool {
        self.next().index() == cons.index() && self.next().wrap() != cons.wrap()
    }

    /// Whether the queue is empty — indices and wrap both equal.
    pub const fn is_empty(self, other: QueueIndex) -> bool {
        self.raw == other.raw
    }
}

/// Event record types this milestone distinguishes (IHI 0070, chapter 7).
pub mod event {
    /// The stream id is outside the table, or its entry is not valid.
    pub const C_BAD_STREAMID: u8 = 0x02;
    /// The stream table entry itself is malformed.
    pub const C_BAD_STE: u8 = 0x04;
    /// A stage-2 translation fault: the address is not mapped. **This is the
    /// one an aperture's boundary produces**, and telling it apart from the
    /// two above is what distinguishes "correctly refused" from
    /// "misconfigured".
    pub const F_TRANSLATION: u8 = 0x10;
    /// A stage-2 permission fault.
    pub const F_PERMISSION: u8 = 0x0c;
}

/// What a refusal *means*, independent of the code the unit used to say it.
///
/// This is the seam between an SMMU's own event vocabulary and a kernel that
/// must not learn it. The classification lives here — with the constants it
/// reads and the tests that pin them — rather than in the boot glue, because
/// which code means "the aperture said no" and which means "this stream was
/// never configured" is a fact about the architecture specification and
/// belongs where the specification is already being encoded.
///
/// The distinction the whole thing exists for is [`Self::Unmapped`] versus
/// [`Self::UnknownStream`]: identical symptoms — a device's DMA did not land —
/// and opposite causes. The first is an aperture doing its job; the second is
/// the kernel's own stream table being wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultClass {
    /// The address has no translation for this stream.
    Unmapped,
    /// The address translates, but not for what the device tried to do.
    Permission,
    /// The unit has no valid configuration for this stream at all.
    UnknownStream,
    /// The configuration exists and is malformed — the kernel's own bug.
    BadConfiguration,
    /// A record type this crate does not classify. Reported rather than
    /// dropped: an unrecognized fault is still a fault, and a caller that
    /// silently ignored it would lose the one record saying the unit is
    /// unhappy in a way nobody anticipated.
    Other,
}

/// A decoded event record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Event {
    pub kind: u8,
    pub stream: u32,
    /// The address the device asked for, for the fault types that report one.
    pub address: u64,
}

impl Event {
    /// What this record means.
    pub const fn class(self) -> FaultClass {
        match self.kind {
            event::F_TRANSLATION => FaultClass::Unmapped,
            event::F_PERMISSION => FaultClass::Permission,
            event::C_BAD_STREAMID => FaultClass::UnknownStream,
            event::C_BAD_STE => FaultClass::BadConfiguration,
            _ => FaultClass::Other,
        }
    }
}

/// Decodes one 32-byte event record from its four words.
pub fn decode_event(words: [u64; 4]) -> Event {
    Event {
        kind: (words[0] & 0xff) as u8,
        stream: (words[0] >> 32) as u32,
        // The input address is word 3 for the fault records this crate reads.
        address: words[3],
    }
}

// --- Stage-2 translation tables ---

/// Bits per level index with a 4 KiB granule.
const LEVEL_BITS: u32 = 9;
/// Bytes a leaf entry covers.
pub const PAGE_SIZE: u64 = 4096;

/// A stage-2 leaf descriptor for a page at `frame`, readable and writable by
/// the device.
///
/// **Stage 2 is not stage 1 with different flags.** Where stage 1 has `AP` at
/// bits 7:6 selecting privilege, stage 2 has `S2AP`, where `0b11` is
/// read-write *for the device*; and where stage 1 indexes `MAIR` through
/// `AttrIndx`, stage 2 carries the attributes directly in `MemAttr` at 5:2.
/// Encoding one with the other's rules yields a descriptor that looks
/// plausible and translates wrongly, which is why this does not reuse the
/// kernel's stage-1 attribute helper.
pub fn stage2_page_descriptor(frame: u64) -> u64 {
    const VALID_PAGE: u64 = 0b11;
    // MemAttr = 0b1111: normal, inner and outer write-back cacheable.
    const MEM_ATTR: u64 = 0b1111 << 2;
    // S2AP = 0b11: the device may read and write.
    const S2AP_RW: u64 = 0b11 << 6;
    // SH = 0b11 inner shareable, AF = 1 (never faulted for access flag).
    const SHAREABLE: u64 = 0b11 << 8;
    const ACCESS_FLAG: u64 = 1 << 10;
    (frame & !0xfff) | VALID_PAGE | MEM_ATTR | S2AP_RW | SHAREABLE | ACCESS_FLAG
}

/// A table descriptor pointing at the next level.
pub fn stage2_table_descriptor(next: u64) -> u64 {
    (next & !0xfff) | 0b11
}

/// The index into the level-`level` table for `address`, where level 3 is the
/// leaf level.
pub fn level_index(address: u64, level: u32) -> usize {
    let shift = 12 + LEVEL_BITS * (3 - level);
    ((address >> shift) & ((1 << LEVEL_BITS) - 1)) as usize
}

/// The `T0SZ` that gives an input address space of `bits`, and the level a
/// walk starts at for it.
///
/// Returned together because they must agree: the start level is determined
/// by how much address space `T0SZ` leaves, and an entry whose `SL0` does not
/// match its `T0SZ` faults on every address with nothing in the table to
/// explain it.
pub fn t0sz_and_start_level(bits: u32) -> Result<(u32, u32), Error> {
    // With a 4 KiB granule each level resolves nine bits and the page holds
    // twelve, so a level indexes a fixed slice of the address: level 3 covers
    // bits 20:12, level 2 bits 29:21, level 1 bits 38:30. The start level is
    // the lowest one whose slice still contains the top bit of the input
    // address — starting higher would index a table with no bits to index it
    // by, which is a walk that reads entry zero for every address.
    match bits {
        31..=39 => Ok((64 - bits, 1)),
        22..=30 => Ok((64 - bits, 2)),
        13..=21 => Ok((64 - bits, 3)),
        _ => Err(Error::ApertureTooSmall),
    }
}

/// `SL0` encodings, which say which level a stage-2 walk starts at.
pub const fn start_level_to_sl0(level: u32) -> u32 {
    // The encoding is not the level number: 0b00 starts at level 2, 0b01 at
    // level 1, 0b10 at level 0, and 0b11 at level 3. Writing the level itself
    // would start the walk two levels off for every value but one.
    match level {
        0 => 0b10,
        1 => 0b01,
        2 => 0b00,
        _ => 0b11,
    }
}

#[cfg(test)]
mod tests;
