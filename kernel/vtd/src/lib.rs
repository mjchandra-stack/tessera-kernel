// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Intel VT-d: the root and context tables, second-level translation, and the
//! records a refused transaction leaves — what puts a PCI function's DMA behind
//! an address space instead of loose in physical memory.
//!
//! `docs/drivers/01` ("DMA Safety") requires mappings "scoped to a device"; on
//! the other machine the unit of scoping is an SMMUv3 **stream**, and here it
//! is the **source id** — the bus, device and function numbers a transaction
//! arrives with. The root table is indexed by bus and the context table behind
//! it by the rest, so the pair says what one function may reach and a
//! transaction outside it is aborted by hardware rather than by anyone's good
//! behaviour.
//!
//! Everything in this crate is **encoding**, not poking: table entry layouts,
//! page-table index arithmetic, and fault decoding, all behind a [`Registers`]
//! trait the caller implements. That division is `//kernel/smmu`'s, and it
//! exists for the same reason — a context entry with a field in the wrong place
//! produces a unit that appears configured and translates wrongly, which no
//! amount of running it on hardware makes obvious.
//!
//! **A fault record is not decoration.** When the unit refuses a transaction it
//! records the reason, the source id and the address. That turns "the DMA did
//! not arrive" — which a misconfiguration produces just as readily as a correct
//! refusal — into evidence naming one or the other.
//!
//! Field positions are from the Intel Virtualization Technology for Directed
//! I/O architecture specification: chapter 9 for the register set, the root and
//! context entries and the fault recording registers, and chapter 3 for
//! second-level translation. Each is encoded in exactly one place here so a
//! wrong bit is wrong once and a test can pin it.
//!
//! Normative: docs/drivers/01-driver-framework.md ("DMA Safety"),
//! docs/hardware/04-dma-and-memory-management.md
//! Budget: none (boot-time configuration)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// What can go wrong configuring the unit. Every variant is a fact about the
/// hardware or the request, never a generic failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The unit does not support an address width this kernel can build tables
    /// for. `SAGAW` says which guest address widths it accepts, and one that
    /// offers none of them is not a unit to program half-way.
    UnsupportedAddressWidth,
    /// A register did not report the state a command asked for within the
    /// bounded wait. The unit is left alone rather than driven further.
    Timeout,
    /// An address that must be page-aligned was not.
    Misaligned,
    /// The address does not fit the address space the tables describe.
    OutOfRange,
}

/// The register block, as the caller can reach it.
///
/// Thirty-two and sixty-four bit accessors both, because VT-d specifies the
/// width of each register and some of them may not be accessed as the other:
/// the global command register is 32-bit and the root-table address is 64-bit,
/// and a unit handed the wrong width answers with undefined behaviour rather
/// than an error.
pub trait Registers {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
    fn read64(&self, offset: usize) -> u64;
    fn write64(&mut self, offset: usize, value: u64);
}

/// Register offsets in the unit's page (VT-d spec, chapter 11).
pub mod reg {
    pub const VER: usize = 0x00;
    pub const CAP: usize = 0x08;
    pub const ECAP: usize = 0x10;
    pub const GCMD: usize = 0x18;
    pub const GSTS: usize = 0x1c;
    pub const RTADDR: usize = 0x20;
    pub const CCMD: usize = 0x28;
    pub const FSTS: usize = 0x34;
    pub const FECTL: usize = 0x38;
}

/// Global command bits. Written **one at a time**: the register is
/// write-to-set and the unit takes the one command whose bit changed, so a
/// value with two new bits in it is a request the hardware is not defined to
/// answer.
pub mod gcmd {
    /// Translation Enable.
    pub const TE: u32 = 1 << 31;
    /// Set Root Table Pointer.
    pub const SRTP: u32 = 1 << 30;
}

/// Global status bits, which mirror the commands above.
pub mod gsts {
    /// Translation Enable Status.
    pub const TES: u32 = 1 << 31;
    /// Root Table Pointer Status.
    pub const RTPS: u32 = 1 << 30;
}

/// Fault status bits (`FSTS`).
pub mod fsts {
    /// Primary Fault Overflow — a record was lost because the ring was full.
    pub const PFO: u32 = 1 << 0;
    /// Primary Pending Fault — at least one record is waiting to be read.
    pub const PPF: u32 = 1 << 1;
}

/// `CCMD` bit 63: invalidate context cache. Writing it starts the
/// invalidation; the unit clears it when done.
pub const CCMD_ICC: u64 = 1 << 63;
/// `CCMD` granularity 01: global.
pub const CCMD_CIRG_GLOBAL: u64 = 1 << 61;

/// `IOTLB` invalidate bit 63, and global granularity, in the register whose
/// offset `ECAP.IRO` names.
pub const IOTLB_IVT: u64 = 1 << 63;
pub const IOTLB_IIRG_GLOBAL: u64 = 1 << 60;

/// Where the fault recording registers are, and how many there are, out of
/// `CAP`.
///
/// **Read rather than assumed.** The offset is in the capability register in
/// units of sixteen bytes, and a kernel that hard-coded it would be reading
/// somebody else's register on the next unit that placed them elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultRecording {
    /// Byte offset of the first fault recording register.
    pub offset: usize,
    /// How many records the ring holds.
    pub count: usize,
}

/// Decodes the fault-recording layout out of `CAP`.
pub fn fault_recording(cap: u64) -> FaultRecording {
    // FRO is bits 33:24 in 16-byte units; NFR is bits 47:40, holding one less
    // than the number of registers.
    let fro = ((cap >> 24) & 0x3ff) as usize;
    let nfr = ((cap >> 40) & 0xff) as usize;
    FaultRecording {
        offset: fro * 16,
        count: nfr + 1,
    }
}

/// The IOTLB invalidate register's offset, out of `ECAP`.
///
/// `IRO` names the *base* of the IOTLB registers in sixteen-byte units, and the
/// invalidate register sits eight bytes into that block.
pub fn iotlb_invalidate_offset(ecap: u64) -> usize {
    (((ecap >> 8) & 0x3ff) as usize) * 16 + 8
}

/// The number of address bits the unit supports for second-level translation,
/// and the `AW` value a context entry must carry to ask for it.
///
/// `SAGAW` is a bitmap: bit 1 is a 39-bit address width (three page-table
/// levels), bit 2 is 48-bit (four). The **widest supported** is chosen, because
/// a narrower one is a smaller aperture for no benefit, and the levels follow
/// from it rather than being a separate decision anybody could get out of step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressWidth {
    /// The `AW` field of a context entry.
    pub aw: u8,
    /// How many page-table levels a walk descends.
    pub levels: u32,
    /// How many bits of input address the tables cover.
    pub bits: u32,
}

/// Chooses an address width out of `CAP.SAGAW`.
pub fn address_width(cap: u64) -> Result<AddressWidth, Error> {
    let sagaw = (cap >> 8) & 0x1f;
    // Widest first: a unit that offers both is programmed for the larger.
    if sagaw & (1 << 3) != 0 {
        return Ok(AddressWidth {
            aw: 3,
            levels: 5,
            bits: 57,
        });
    }
    if sagaw & (1 << 2) != 0 {
        return Ok(AddressWidth {
            aw: 2,
            levels: 4,
            bits: 48,
        });
    }
    if sagaw & (1 << 1) != 0 {
        return Ok(AddressWidth {
            aw: 1,
            levels: 3,
            bits: 39,
        });
    }
    Err(Error::UnsupportedAddressWidth)
}

/// A source id: the bus, device and function a transaction arrives with, packed
/// the way the tables index it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceId(pub u16);

impl SourceId {
    /// From the three numbers a PCI enumeration produces.
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self((u16::from(bus) << 8) | (u16::from(device & 0x1f) << 3) | u16::from(function & 0x7))
    }

    /// The root table is indexed by bus.
    pub fn bus(self) -> usize {
        usize::from(self.0 >> 8)
    }

    /// The context table behind it by device and function together.
    pub fn context_index(self) -> usize {
        usize::from(self.0 & 0xff)
    }
}

/// A root-table entry naming the context table for one bus.
///
/// Two words: the low one carries the present bit and the context-table
/// pointer, the high one is reserved and must be zero. Returned as a pair
/// rather than written, so a caller places it and this crate never touches
/// memory.
pub fn root_entry(context_table: u64) -> Result<[u64; 2], Error> {
    if context_table & 0xfff != 0 {
        return Err(Error::Misaligned);
    }
    Ok([context_table | 1, 0])
}

/// A context-table entry putting one function behind a second-level table.
///
/// The low word carries the present bit, the translation type — `00`, meaning
/// every request goes through second-level translation — and the table
/// pointer. The high word carries the address width and the domain id: two
/// functions given the same domain share translations and their invalidations,
/// which is why the caller names it rather than this crate inventing one.
pub fn context_entry(
    second_level_table: u64,
    address_width: AddressWidth,
    domain: u16,
) -> Result<[u64; 2], Error> {
    if second_level_table & 0xfff != 0 {
        return Err(Error::Misaligned);
    }
    Ok([
        second_level_table | 1,
        u64::from(address_width.aw) | (u64::from(domain) << 8),
    ])
}

/// A second-level entry pointing at the next table down: readable, writable,
/// and naming the table's frame.
///
/// **Read and write are the permissions the walk accumulates**, so a
/// non-leaf entry carries both and the leaf decides. An intermediate entry with
/// them clear would abort every transaction below it, which is the
/// misconfiguration that looks exactly like correct scoping.
pub fn table_entry(next: u64) -> Result<u64, Error> {
    if next & 0xfff != 0 {
        return Err(Error::Misaligned);
    }
    Ok(next | SL_READ | SL_WRITE)
}

/// A second-level leaf mapping one 4 KiB frame, readable and writable.
pub fn page_entry(frame: u64) -> Result<u64, Error> {
    if frame & 0xfff != 0 {
        return Err(Error::Misaligned);
    }
    Ok(frame | SL_READ | SL_WRITE)
}

/// Second-level entry permission bits.
pub const SL_READ: u64 = 1 << 0;
pub const SL_WRITE: u64 = 1 << 1;

/// The index a given level of the walk takes from an address.
///
/// Level 1 is the leaf table and counts up towards the root, which is the
/// order the specification numbers them in: nine bits each, starting twelve
/// bits in.
pub fn level_index(address: u64, level: u32) -> usize {
    ((address >> (12 + 9 * (level - 1))) & 0x1ff) as usize
}

/// Why a transaction was refused, as the fault record names it.
///
/// Only the reasons this kernel can produce are named; anything else is carried
/// as its number rather than folded into one of them, because a fault nobody
/// anticipated must not arrive looking like one somebody did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    /// The root entry for this bus is not present.
    RootNotPresent,
    /// The context entry for this function is not present.
    ContextNotPresent,
    /// The walk reached an entry that was not present, or one whose
    /// permissions refused the access — a device reaching outside its
    /// aperture.
    NotPresentOrPermission,
    /// Something else, carried as the hardware's own number.
    Other(u8),
}

/// One fault, as read out of a fault recording register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    /// Whether the register held a record at all.
    pub valid: bool,
    /// The source id the refused transaction arrived with.
    pub source: SourceId,
    /// The address it asked for.
    pub address: u64,
    /// Why it was refused.
    pub reason: FaultReason,
    /// Whether it was a read (`true`) or a write.
    pub read: bool,
}

/// Decodes one fault recording register's two words.
///
/// The high word carries the fault bit, the type, the reason and the source id;
/// the low word is the address, whose bottom twelve bits the hardware does not
/// record.
pub fn decode_fault(low: u64, high: u64) -> Fault {
    let reason_code = ((high >> 32) & 0xff) as u8;
    Fault {
        valid: high & (1 << 63) != 0,
        source: SourceId((high & 0xffff) as u16),
        address: low & !0xfff,
        reason: match reason_code {
            0x01 => FaultReason::RootNotPresent,
            0x02 => FaultReason::ContextNotPresent,
            0x05..=0x07 => FaultReason::NotPresentOrPermission,
            other => FaultReason::Other(other),
        },
        // Bit 62 is the type: set for a read, clear for a write.
        read: high & (1 << 62) != 0,
    }
}

/// The word that clears one fault recording register: writing the fault bit
/// back is what says the record has been read.
pub const FAULT_CLEAR_HIGH: u64 = 1 << 63;

#[cfg(test)]
mod tests;
