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
    /// Invalidation queue head, tail and address — the queued-invalidation
    /// interface, which is the *only* way to invalidate what the unit caches
    /// about interrupt remapping.
    pub const IQH: usize = 0x80;
    pub const IQT: usize = 0x88;
    pub const IQA: usize = 0x90;
    /// Interrupt remapping table address.
    pub const IRTA: usize = 0xb8;
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
    /// Queued Invalidation Enable.
    pub const QIE: u32 = 1 << 26;
    /// Interrupt Remapping Enable.
    pub const IRE: u32 = 1 << 25;
    /// Set Interrupt Remap Table Pointer.
    pub const SIRTP: u32 = 1 << 24;
    /// Compatibility Format Interrupt — permits interrupt requests in the old
    /// format to go on being delivered while remapping is enabled.
    ///
    /// **Named so it can be pointed at, never written.** An interrupt in the
    /// compatibility format carries its own vector and destination, which is
    /// exactly the forgery remapping exists to stop; a unit left with this set
    /// remaps the interrupts software asked it to and lets every other one
    /// past. It is here because "this kernel does not set it" is a claim, and a
    /// constant nobody names cannot be one.
    pub const CFI: u32 = 1 << 23;
}

/// Global status bits, which mirror the commands above.
pub mod gsts {
    /// Translation Enable Status.
    pub const TES: u32 = 1 << 31;
    /// Root Table Pointer Status.
    pub const RTPS: u32 = 1 << 30;
    /// Queued Invalidation Enable Status.
    pub const QIES: u32 = 1 << 26;
    /// Interrupt Remapping Enable Status.
    pub const IRES: u32 = 1 << 25;
    /// Interrupt Remap Table Pointer Status.
    pub const IRTPS: u32 = 1 << 24;
    /// Compatibility Format Interrupt Status — clear is the state this kernel
    /// requires, and reading it is how that is asserted rather than assumed.
    pub const CFIS: u32 = 1 << 23;
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

/// A context-table entry putting one function in **pass-through**: its
/// transactions are translated by taking the address unchanged.
///
/// **This is what makes a unit that is always on possible.** Enabling
/// translation is a property of the machine, not of one device: every
/// function's transactions start passing through the tables at once, and one
/// with no entry is aborted rather than let by. A kernel that scoped one device
/// by switching translation on would be stopping every other device on the
/// machine, so the ones it has nothing to say about are given an entry that
/// says exactly that — present, and passing the address through.
///
/// The address width is still programmed: pass-through ignores the table
/// pointer but not the width, and a unit told a width it does not support
/// refuses the entry rather than the transaction.
pub fn context_entry_passthrough(address_width: AddressWidth, domain: u16) -> [u64; 2] {
    [
        1 | (u64::from(TRANSLATION_PASSTHROUGH) << 2),
        u64::from(address_width.aw) | (u64::from(domain) << 8),
    ]
}

/// Translation types, in bits 3:2 of a context entry's low word. `00` sends
/// every request through the second-level tables; `10` passes it through.
pub const TRANSLATION_SECOND_LEVEL: u8 = 0b00;
pub const TRANSLATION_PASSTHROUGH: u8 = 0b10;

/// Whether the unit has the queued-invalidation interface (`ECAP.QI`).
///
/// **This is what interrupt remapping is gated on**, not a preference. The
/// register-based invalidation above can invalidate the context cache and the
/// IOTLB and nothing else: there is no register that invalidates what the unit
/// caches about the interrupt-remapping table. So a kernel that programs an
/// IRTE and later withdraws it has no way to make the withdrawal take effect,
/// which makes revocation unenforceable — and the specification says as much,
/// requiring queued invalidation to be enabled before remapping is.
pub fn queued_invalidation_supported(ecap: u64) -> bool {
    ecap & (1 << 1) != 0
}

/// Whether the unit remaps interrupts at all (`ECAP.IR`).
pub fn interrupt_remapping_supported(ecap: u64) -> bool {
    ecap & (1 << 3) != 0
}

/// Whether it supports the extended interrupt mode (`ECAP.EIM`) — a full
/// 32-bit destination, which is what an x2APIC machine needs to name a CPU
/// whose identifier does not fit in eight bits.
///
/// Asked rather than assumed, because the destination is encoded **differently**
/// under each: a kernel that guessed would program a table whose entries name
/// the wrong CPU, and an interrupt delivered to the wrong CPU is not an error
/// anything reports.
pub fn extended_interrupt_mode_supported(ecap: u64) -> bool {
    ecap & (1 << 4) != 0
}

/// One 128-bit invalidation descriptor, and how many fit in a 4 KiB queue.
pub const DESCRIPTOR_BYTES: u64 = 16;
pub const QUEUE_DESCRIPTORS: u64 = 4096 / DESCRIPTOR_BYTES;

/// The value `IQA` takes for a one-page queue of 128-bit descriptors.
///
/// Bit 11 is the descriptor width — clear for 128-bit, which is the only width
/// a unit without scalable mode accepts — and bits 2:0 are the size as a count
/// of 4 KiB pages expressed as a power of two, so zero is the single page this
/// kernel allocates.
pub fn queue_address(queue: u64) -> Result<u64, Error> {
    if queue & 0xfff != 0 {
        return Err(Error::Misaligned);
    }
    Ok(queue)
}

/// `IQT` and `IQH` hold a byte offset, so an index is shifted by the width of a
/// descriptor before it is written.
pub const QUEUE_INDEX_SHIFT: u32 = 4;

/// Invalidate everything the unit has cached about the context tables.
pub fn context_invalidate_descriptor() -> [u64; 2] {
    // Type 0x1, granularity 01 (global) in bits 5:4.
    [0x1 | (1 << 4), 0]
}

/// Invalidate everything it has cached about second-level translation.
pub fn iotlb_invalidate_descriptor() -> [u64; 2] {
    // Type 0x2, granularity 01 (global) in bits 5:4.
    [0x2 | (1 << 4), 0]
}

/// Invalidate everything it has cached about the interrupt-remapping table.
///
/// Global, because this kernel withdraws a handle rarely and correctness is
/// what the granularity is for: an index-ranged invalidation that named the
/// wrong index would leave a withdrawn entry live, and nothing would say so.
pub fn interrupt_entry_invalidate_descriptor() -> [u64; 2] {
    // Type 0x4; the granularity bit clear is global.
    [0x4, 0]
}

/// The descriptor that says "tell me when everything before this is done".
///
/// **A queue is asynchronous, so submitting is not completing.** The unit
/// advances the head as it *fetches*, which a kernel polling the head would
/// mistake for the work having happened. This descriptor writes `data` to
/// `status` once every earlier descriptor has completed, and that write is the
/// only signal that means what it says.
pub fn invalidate_wait_descriptor(status: u64, data: u32) -> Result<[u64; 2], Error> {
    if status & 0x3 != 0 {
        return Err(Error::Misaligned);
    }
    // Type 0x5, status-write in bit 5, the data to write in bits 63:32.
    Ok([0x5 | (1 << 5) | (u64::from(data) << 32), status])
}

/// How many entries an interrupt-remapping table of one 4 KiB page holds: each
/// entry is 128 bits.
pub const IRT_ENTRY_BYTES: u64 = 16;

/// The value `IRTA` takes for a table of `entries` entries.
///
/// Bits 3:0 hold the size as `log2(entries) - 1`, bit 11 asks for the extended
/// interrupt mode, and the rest is the table's frame.
pub fn interrupt_table_address(table: u64, entries: u32, extended: bool) -> Result<u64, Error> {
    if table & 0xfff != 0 {
        return Err(Error::Misaligned);
    }
    if !entries.is_power_of_two() || !(2..=(1 << 16)).contains(&entries) {
        return Err(Error::OutOfRange);
    }
    let size = u64::from(entries.trailing_zeros() - 1);
    Ok(table | size | if extended { 1 << 11 } else { 0 })
}

/// The largest handle a remappable interrupt request can name.
pub const MAX_INTERRUPT_HANDLE: u16 = u16::MAX;

/// An interrupt-remapping table entry: which vector, on which CPU, and — the
/// field the whole facility turns on — **which function may use it**.
///
/// **The source id is the point.** Without it an entry is a vector any device
/// that can write to the interrupt window may raise, which is the same
/// forgeable arrangement as the message format it replaces, only one level of
/// indirection further away. With it, the unit compares the requester of every
/// interrupt against the entry it is asking for and blocks the ones that do not
/// match — so a handle issued to one function is not a handle another function
/// can use.
///
/// Delivery is fixed mode, edge triggered, to a physical destination, because
/// that is what every interrupt on this port is; a kernel that needed another
/// would say so here rather than at a call site.
pub fn interrupt_entry(vector: u8, destination: u32, extended: bool, source: SourceId) -> [u64; 2] {
    // Under the extended interrupt mode the destination is the whole 32-bit
    // identifier; under the old one it is eight bits sitting at 47:40 of the
    // entry, which is bits 15:8 of the destination field.
    let destination = if extended {
        u64::from(destination)
    } else {
        u64::from(destination & 0xff) << 8
    };
    [
        IRTE_PRESENT | (u64::from(vector) << 16) | (destination << 32),
        u64::from(source.0) | (u64::from(IRTE_SVT_SOURCE) << 18),
    ]
}

/// The same entry with no source verification, for an interrupt whose requester
/// this kernel cannot name.
///
/// **A named exception rather than a default.** The I/O interrupt controller is
/// not a PCI function and the identifier its interrupt requests carry is a
/// firmware fact; on a machine whose tables do not state it, its entries are
/// issued without verification and that is reported. Nothing else is allowed to
/// use this.
pub fn interrupt_entry_unverified(vector: u8, destination: u32, extended: bool) -> [u64; 2] {
    let mut entry = interrupt_entry(vector, destination, extended, SourceId(0));
    entry[1] = 0;
    entry
}

/// An entry that is not present: the handle exists and names nothing, so a
/// request for it is blocked and recorded.
pub const INTERRUPT_ENTRY_ABSENT: [u64; 2] = [0, 0];

/// Interrupt-remapping table entry bits.
pub const IRTE_PRESENT: u64 = 1 << 0;
/// Source validation type 01: compare the requester against `SID`.
pub const IRTE_SVT_SOURCE: u8 = 0b01;

/// Where a remappable interrupt request is written, and what it says.
///
/// **On this architecture an interrupt is a memory write**, which is why
/// remapping is needed at all and why the encoding lives here rather than with
/// the local controller: the window at `0xfee0_0000` is the platform's, but
/// what the bits inside it mean is VT-d's. In the old format they were the
/// destination and the vector — chosen by whoever wrote them. In this one they
/// are a *handle*, and what it stands for is in a table only the kernel can
/// write.
///
/// Bit 4 is what distinguishes the two formats, bits 19:5 carry the handle's
/// low fifteen bits and bit 2 its sixteenth, and bit 3 says whether the data
/// word adds a sub-handle — which this kernel does not use, so the data word is
/// zero and the handle is the index by itself.
pub fn remappable_message(handle: u16) -> (u64, u32) {
    let low = u64::from(handle & 0x7fff) << 5;
    let top = u64::from(handle >> 15) << 2;
    (INTERRUPT_ADDRESS_BASE | low | REMAPPABLE_FORMAT | top, 0)
}

/// The interrupt window every message-signalled interrupt is written into.
pub const INTERRUPT_ADDRESS_BASE: u64 = 0xfee0_0000;
/// Bit 4 of that address: this request is remappable rather than compatibility
/// format.
///
/// **Bit 4 and not bit 3**, which is the one field here worth a sentence: the
/// bit beside it says whether the data word carries a sub-handle, and a message
/// with the two transposed is a *well-formed compatibility-format request* — so
/// a unit that is remapping reads it as an interrupt naming its own vector and
/// passes it straight through, with no fault, no error and no interrupt where
/// the driver was waiting.
pub const REMAPPABLE_FORMAT: u64 = 1 << 4;
/// Bit 3: the data word carries a sub-handle to add to the handle. Named
/// because it is the bit above's neighbour and the reason that one is worth
/// pinning; never set, so a handle is an index by itself.
pub const SUBHANDLE_VALID: u64 = 1 << 3;

/// Whether the unit can be asked for pass-through at all (`ECAP.PT`).
///
/// Asked rather than assumed: a unit without it cannot be left enabled while
/// devices this kernel says nothing about are doing DMA, and that is a fact
/// about the machine to report rather than to hope for.
pub fn passthrough_supported(ecap: u64) -> bool {
    ecap & (1 << 6) != 0
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
    /// An interrupt request named a handle past the end of the table.
    InterruptIndexOutOfRange,
    /// It named a handle whose entry is not present — one that was never
    /// issued, or one that has been withdrawn.
    InterruptEntryNotPresent,
    /// It named a handle that exists and belongs to somebody else: the
    /// requester did not match the entry's source id. **This is the interrupt
    /// side of an out-of-aperture DMA.**
    InterruptSourceMismatch,
    /// It was written in the old format, which carries its own vector and
    /// destination — blocked because this kernel does not set `GCMD.CFI`.
    InterruptCompatibilityBlocked,
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
            0x21 => FaultReason::InterruptIndexOutOfRange,
            0x22 => FaultReason::InterruptEntryNotPresent,
            0x25 => FaultReason::InterruptCompatibilityBlocked,
            0x26 => FaultReason::InterruptSourceMismatch,
            other => FaultReason::Other(other),
        },
        // Bit 62 is the type: set for a read, clear for a write.
        read: high & (1 << 62) != 0,
    }
}

/// The word that clears one fault recording register: writing the fault bit
/// back is what says the record has been read.
pub const FAULT_CLEAR_HIGH: u64 = 1 << 63;

impl Fault {
    /// The handle a blocked interrupt request named.
    ///
    /// **The same field, read differently.** A translation fault records the
    /// address the device wanted; an interrupt-remapping fault has no address
    /// to record and puts the index there instead, in the top sixteen bits. So
    /// this is only meaningful for the interrupt reasons, and reading it for a
    /// translation fault would answer with a slice of an address — which is
    /// why it is a method named for what it means rather than a field anybody
    /// could pick up.
    pub fn interrupt_handle(self) -> u16 {
        (self.address >> 48) as u16
    }

    /// Whether this record is about an interrupt request rather than a
    /// translation.
    pub fn is_interrupt(self) -> bool {
        matches!(
            self.reason,
            FaultReason::InterruptIndexOutOfRange
                | FaultReason::InterruptEntryNotPresent
                | FaultReason::InterruptSourceMismatch
                | FaultReason::InterruptCompatibilityBlocked
        )
    }
}

#[cfg(test)]
mod tests;
