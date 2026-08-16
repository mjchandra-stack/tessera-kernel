// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! PCI Express enumeration over ECAM: the bus walk, the identity each function
//! reports, and BAR sizing and assignment.
//!
//! Config-space access goes through the [`ConfigSpace`] trait, so the fragile
//! parts — the address arithmetic, the multi-function rules, and the
//! read-modify-restore dance that sizes a BAR — are ordinary logic a mock
//! exercises on the host. The caller (an arch boot glue) supplies the real
//! volatile access and is where the `unsafe` lives. This crate forbids it.
//!
//! **Everything a function reports is external input.** A device chooses its
//! own vendor id, header type, and BAR mask, and a malformed one is a typed
//! [`Error`] rather than a panic or a silently truncated window. The walk is
//! bounded by the ECAM window the device tree described: an address outside it
//! is refused before it reaches the caller's accessor, because the caller has
//! no way to tell a legitimate high bus number from arithmetic that ran off
//! the end.
//!
//! **BARs are unassigned on the reference machines.** QEMU's `virt` leaves
//! them zero and expects the OS to place them in the windows the device tree
//! advertises, so assignment is part of enumeration here rather than something
//! firmware did earlier (docs/hardware/02, "PCIe": the OS records BARs).
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md ("PCIe"),
//! docs/architecture/02-separation-of-concerns.md ("Device Manager Boundary")
//! Budget: none (boot-time enumeration)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// What can go wrong reading a bus. Every variant is a fact about the machine
/// or about what a device reported, never a programming error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// A config-space address fell outside the ECAM window the device tree
    /// described — the walk would have read memory that is not config space.
    OutsideEcam,
    /// The `bus-range` from the device tree does not fit what ECAM addresses
    /// can express, or is inverted.
    BadBusRange,
    /// A BAR asked for more space than its window has left.
    WindowExhausted,
    /// A BAR reported a size that is not a power of two, or is zero after
    /// masking — a device describing something the specification forbids.
    BadBarSize,
    /// More functions are present than the caller's buffer can hold. The
    /// enumeration is reported truncated rather than silently cut short.
    TooManyFunctions,
    /// A capability list did not terminate, pointed outside the 256-byte
    /// header, or revisited an offset — a device describing a loop.
    MalformedCapabilityList,
    /// An MSI-X table names a BAR the function does not have.
    BadMsixTable,
}

/// A bus/device/function address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Bdf {
    /// A bdf, or `None` if the device/function are outside their field widths
    /// (5 and 3 bits). Constructing is the only place the widths are checked,
    /// so no arithmetic downstream can produce an aliasing address.
    pub const fn new(bus: u8, device: u8, function: u8) -> Option<Self> {
        if device > 31 || function > 7 {
            return None;
        }
        Some(Self {
            bus,
            device,
            function,
        })
    }

    /// The ECAM offset of this function's config space within a window whose
    /// first bus is `first_bus`: bus in bits 27:20, device in 19:15, function
    /// in 14:12.
    ///
    /// The bus is taken relative to the window's first bus, because the window
    /// starts *at* that bus — a bridge advertising `bus-range = <4 8>` puts bus
    /// 4 at offset 0, and treating the number as absolute would read four
    /// megabytes past the end of a five-bus window.
    pub const fn ecam_offset(self, first_bus: u8) -> u64 {
        (((self.bus - first_bus) as u64) << 20)
            | ((self.device as u64) << 15)
            | ((self.function as u64) << 12)
    }
}

/// Config-space registers this crate reads. Offsets are from the start of a
/// function's 4 KiB config region.
pub mod reg {
    /// Vendor id (low half) and device id (high half).
    pub const VENDOR_DEVICE: u16 = 0x00;
    /// Command (low half) and status (high half).
    pub const COMMAND_STATUS: u16 = 0x04;
    /// Revision (byte 0) and class code (bytes 1..3: prog-if, subclass, class).
    pub const REVISION_CLASS: u16 = 0x08;
    /// Cache line size, latency timer, header type, BIST.
    pub const HEADER_TYPE: u16 = 0x0c;
    /// The first base address register of a type-0 header.
    pub const BAR0: u16 = 0x10;
    /// Offset of the first entry in the capability list, in a type-0 header.
    pub const CAPABILITY_POINTER: u16 = 0x34;
    /// Type-1 only: primary (byte 0), secondary (byte 1) and subordinate
    /// (byte 2) bus numbers, and the secondary latency timer (byte 3).
    ///
    /// **A bridge forwards nothing until these are written.** A configuration
    /// cycle for a bus is claimed by whichever bridge's secondary/subordinate
    /// range contains it, and an unprogrammed bridge's range is empty — so a
    /// device behind one does not answer, and enumeration concludes it is not
    /// there. Firmware normally writes them, and booting with `-kernel` means
    /// no firmware ran.
    pub const BUS_NUMBERS: u16 = 0x18;
    /// Type-1 only: memory base (low half) and limit (high half), each the
    /// top 12 bits of a 1 MiB-granular address.
    pub const MEMORY_BASE_LIMIT: u16 = 0x20;
}

/// Set in the status half of [`reg::COMMAND_STATUS`] when the function
/// implements a capability list. Walking without checking it would follow
/// whatever byte happens to be at 0x34.
const STATUS_CAPABILITY_LIST: u32 = 1 << 4;

/// Capability ids this crate knows.
pub const CAP_MSI: u8 = 0x05;
pub const CAP_MSIX: u8 = 0x11;
/// The PCI Express capability, which is where a root port keeps the slot
/// registers hotplug is conducted through.
pub const CAP_EXPRESS: u8 = 0x10;

/// Offsets and bits inside the PCI Express capability, for the slot a
/// hot-pluggable device sits in.
pub mod slot {
    /// Slot Control (low half) and Slot Status (high half), relative to the
    /// start of the PCI Express capability.
    pub const CONTROL_STATUS: u16 = 0x18;
    /// Slot Capabilities, whose Hot-Plug Capable bit says whether any of this
    /// means anything for a given port.
    pub const CAPABILITIES: u16 = 0x14;

    /// Slot Capabilities: this slot can be hot-plugged at all.
    pub const CAP_HOTPLUG_CAPABLE: u32 = 1 << 6;

    /// Slot Status: the attention button was pressed — which is what a request
    /// to eject looks like to a guest, whether a person pressed one or a
    /// management tool asked on their behalf.
    pub const STATUS_ATTENTION_BUTTON: u32 = 1 << 0;
    /// Slot Status: presence detect changed.
    pub const STATUS_PRESENCE_CHANGED: u32 = 1 << 3;
    /// Slot Status: something is in the slot.
    pub const STATUS_PRESENCE_DETECT: u32 = 1 << 6;
    /// The status bits this crate acts on, and clears by writing them back.
    pub const STATUS_ACKNOWLEDGED: u32 = STATUS_ATTENTION_BUTTON | STATUS_PRESENCE_CHANGED;

    /// Slot Control: power indicator control, both bits set meaning *off*.
    pub const CONTROL_POWER_INDICATOR_OFF: u32 = 0b11 << 8;
    /// Slot Control: power controller control, set meaning *off*.
    pub const CONTROL_POWER_OFF: u32 = 1 << 10;
}
/// A vendor-specific capability. Unlike the two above, a device may carry
/// **several** — virtio publishes one per configuration structure — so finding
/// them needs [`find_capability_from`] rather than a single lookup. What is
/// inside one is the vendor's business and not this crate's.
pub const CAP_VENDOR: u8 = 0x09;

/// Configuration space is 256 bytes in the legacy window, and a capability
/// must start inside it and be 4-byte aligned. Anything else is a device
/// describing something that cannot exist.
const CONFIG_HEADER_LEN: u16 = 0x100;
/// A list longer than this is a loop. There is no legitimate device with 48
/// capabilities in 256 bytes; bounding the walk is what makes a malformed one
/// an error rather than a hang.
const MAX_CAPABILITIES: usize = 48;

/// Base address registers in a type-0 (endpoint) header.
pub const MAX_BARS: usize = 6;

/// The `command` bits enumeration touches. Decoding is only ever enabled after
/// a BAR has been placed — a device left decoding an unassigned BAR would
/// answer at whatever address zero happens to be.
pub mod command {
    pub const IO_SPACE: u32 = 1 << 0;
    pub const MEMORY_SPACE: u32 = 1 << 1;
    pub const BUS_MASTER: u32 = 1 << 2;
}

/// Header type values, after masking off the multi-function bit.
const HEADER_TYPE_ENDPOINT: u32 = 0x00;
/// A PCI-to-PCI bridge's header, whose type-1 layout puts bus numbers and
/// forwarding windows where an endpoint keeps BARs.
const HEADER_TYPE_BRIDGE: u32 = 0x01;
/// What a bridge's memory window is granular to. The base and limit registers
/// hold only the top 12 bits of a 32-bit address, so a window is always a whole
/// number of megabytes starting on a megabyte — which is why a bridge's share
/// of the host window is carved at this granularity rather than at its
/// children's actual sizes.
const BRIDGE_WINDOW_GRANULARITY: u64 = 1 << 20;
/// Set in the header-type byte when a device implements more than function 0.
const HEADER_TYPE_MULTIFUNCTION: u32 = 0x80;

/// The value a read returns for an absent function. Config space is
/// pulled up, so a slot with nothing in it reads all ones.
const ABSENT: u32 = 0xffff_ffff;

/// Access to a PCI host bridge's config space. The only device-touching
/// surface: an implementation performs the actual volatile load/store (and is
/// where the `unsafe` lives).
///
/// `offset` is a byte offset from the ECAM window base and is always 4-byte
/// aligned and inside the window — this crate checks both before calling.
pub trait ConfigSpace {
    /// Reads the 32-bit config word at `offset` from the ECAM base.
    fn read32(&self, offset: u64) -> u32;
    /// Writes the 32-bit config word at `offset` from the ECAM base.
    fn write32(&mut self, offset: u64, value: u32);
}

/// A memory window the host bridge forwards, from the device tree's `ranges`.
/// BARs are assigned out of these.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Window {
    /// Address as the CPU sees it.
    pub cpu_base: u64,
    /// Address as a device behind the bridge sees it (what goes in the BAR).
    pub bus_base: u64,
    pub len: u64,
    /// Whether this window is reachable by 32-bit BARs.
    pub is_32bit: bool,
}

/// One enumerated function and what it reported.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Function {
    pub bdf: Bdf,
    pub vendor: u16,
    pub device: u16,
    /// Class, subclass and prog-if packed as the config register holds them
    /// (bits 23:16 class, 15:8 subclass, 7:0 prog-if).
    pub class_code: u32,
    /// The hardware revision — the low byte of the same register the class
    /// comes from, and a **binding input** in its own right (`docs/drivers/01`,
    /// "Driver Binding"). It was being shifted off the end of `class_code`: a
    /// driver may support a device from revision 3 onward and not before, and
    /// a manifest that could not name it would have to claim every revision or
    /// none.
    pub revision: u8,
    pub header_type: u32,
    /// Assigned memory BARs as `(cpu_address, len)`. A BAR that is unused,
    /// I/O-space, or could not be placed is `None`.
    pub bars: [Option<(u64, u64)>; MAX_BARS],
    /// The bridge this function sits behind, or `None` for one on the host
    /// bridge's own bus.
    ///
    /// **Recorded here because this is the only place the answer is free.** The
    /// walk descends through bridges, so at the moment a function is read the
    /// bridge above it is on the stack; afterwards the list is flat and the
    /// relationship can only be reconstructed by matching bus numbers against
    /// every bridge's secondary — an inference that is wrong the moment two
    /// host bridges are walked into one array.
    pub parent: Option<Bdf>,
}

impl Function {
    /// The top-level class byte — what a device manager matches on.
    pub const fn class(&self) -> u8 {
        ((self.class_code >> 16) & 0xff) as u8
    }

    /// The subclass byte.
    pub const fn subclass(&self) -> u8 {
        ((self.class_code >> 8) & 0xff) as u8
    }

    /// The first assigned memory BAR, which is where a driver's registers are
    /// if it has any.
    pub fn first_bar(&self) -> Option<(u64, u64)> {
        self.bars.iter().flatten().copied().next()
    }
}

/// The host bridge being walked: its ECAM window and the bus numbers that
/// window covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Host {
    pub ecam_base: u64,
    pub ecam_len: u64,
    pub first_bus: u8,
    pub last_bus: u8,
}

impl Host {
    /// Checks that `bdf`'s config space lies inside the ECAM window, returning
    /// its offset from the window base.
    ///
    /// This is the boundary the whole walk rests on: ECAM arithmetic is a shift
    /// and an or, so a bus number one past the end produces a perfectly
    /// plausible address that reads whatever follows the window. Refusing here
    /// means the accessor is never handed one.
    fn offset_of(&self, bdf: Bdf, register: u16) -> Result<u64, Error> {
        if bdf.bus < self.first_bus || bdf.bus > self.last_bus {
            return Err(Error::OutsideEcam);
        }
        let offset = bdf.ecam_offset(self.first_bus) + u64::from(register);
        // A whole 4-byte word must fit, not just its first byte.
        if offset.saturating_add(4) > self.ecam_len {
            return Err(Error::OutsideEcam);
        }
        Ok(offset)
    }

    /// One config-space register of `bdf`, bounds-checked against the ECAM
    /// window.
    ///
    /// Public because a capability's *payload* is the vendor's business, not
    /// this crate's: a virtio device describes its configuration structures in
    /// four dwords after a vendor capability header, and decoding those here
    /// would put virtio knowledge in a PCI crate. A caller reads the words and
    /// decodes them itself; the bounds check stays this crate's.
    pub fn read(&self, cfg: &dyn ConfigSpace, bdf: Bdf, register: u16) -> Result<u32, Error> {
        Ok(cfg.read32(self.offset_of(bdf, register)?))
    }

    fn write(
        &self,
        cfg: &mut dyn ConfigSpace,
        bdf: Bdf,
        register: u16,
        v: u32,
    ) -> Result<(), Error> {
        let offset = self.offset_of(bdf, register)?;
        cfg.write32(offset, v);
        Ok(())
    }
}

/// A bump allocator over one forwarded window, used to place BARs.
struct WindowAllocator {
    window: Window,
    next: u64,
}

impl WindowAllocator {
    fn new(window: Window) -> Self {
        Self {
            next: window.bus_base,
            window,
        }
    }

    /// Allocates `size` bytes aligned to `size` (what a BAR requires), and
    /// returns `(cpu_address, bus_address)`.
    fn allocate(&mut self, size: u64) -> Result<(u64, u64), Error> {
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::BadBarSize);
        }
        // A BAR decodes an aligned block of its own size — the low bits are
        // not part of the address, so an unaligned placement would alias.
        let bus = self.next.next_multiple_of(size);
        let end = bus.checked_add(size).ok_or(Error::WindowExhausted)?;
        if end > self.window.bus_base.saturating_add(self.window.len) {
            return Err(Error::WindowExhausted);
        }
        self.next = end;
        let cpu = self.window.cpu_base + (bus - self.window.bus_base);
        Ok((cpu, bus))
    }
}

/// Enumerates every function behind `host`, assigning memory BARs out of
/// `window`, and writes what it found into `out`.
///
/// Returns how many functions were recorded. A full `out` is
/// [`Error::TooManyFunctions`] rather than a short answer that looks complete.
pub fn enumerate(
    host: &Host,
    cfg: &mut dyn ConfigSpace,
    window: Window,
    out: &mut [Function],
) -> Result<usize, Error> {
    if host.first_bus > host.last_bus {
        return Err(Error::BadBusRange);
    }
    let mut allocator = WindowAllocator::new(window);
    let mut walk = Walk {
        next_bus: host.first_bus,
        found: 0,
        out,
    };
    scan_bus(host, cfg, host.first_bus, None, &mut allocator, &mut walk)?;
    Ok(walk.found)
}

/// What a depth-first walk carries from one bus to the next.
///
/// The three fields are one thing — where the walk is putting what it finds,
/// how much of that it has used, and the lowest bus number nobody has claimed
/// — and they were three parameters threaded through every level. Grouping
/// them is not tidying: `next_bus` is only meaningful *because* it is shared
/// across the whole recursion, since a bridge's subordinate bound is whatever
/// the calls below it took. A struct says that; three `&mut` arguments merely
/// allow it.
struct Walk<'a> {
    /// The next bus number nobody has claimed. It only ever grows, which is
    /// what makes "every bus this recursion handed out is behind me" a fact a
    /// bridge can read off it once its own descent returns.
    next_bus: u8,
    /// How much of `out` is used.
    found: usize,
    /// Where functions are recorded.
    out: &'a mut [Function],
}

/// Walks one bus, recording every function on it and **configuring every
/// bridge it finds** before descending through it.
///
/// Depth-first rather than the flat sweep over `first_bus..=last_bus` this
/// replaces, and the reason is the ordering: a bridge forwards nothing until
/// its bus numbers are written, so the bus behind it does not exist as far as
/// a configuration read is concerned until the bridge above it has been dealt
/// with. A flat loop cannot express that — it would scan bus 1 whether or not
/// anything had told a bridge that bus 1 was its.
fn scan_bus(
    host: &Host,
    cfg: &mut dyn ConfigSpace,
    bus: u8,
    parent: Option<Bdf>,
    allocator: &mut WindowAllocator,
    walk: &mut Walk<'_>,
) -> Result<(), Error> {
    for device in 0..32u8 {
        // Function 0 decides whether the rest of the slot is worth looking at:
        // a single-function device answers at every function number, so probing
        // 1..8 unconditionally would report seven phantom copies of it.
        let Some(zero) = Bdf::new(bus, device, 0) else {
            continue;
        };
        let id = host.read(cfg, zero, reg::VENDOR_DEVICE)?;
        if id == ABSENT || (id & 0xffff) == 0xffff {
            continue;
        }
        let header = host.read(cfg, zero, reg::HEADER_TYPE)?;
        let multifunction = ((header >> 16) & HEADER_TYPE_MULTIFUNCTION) != 0;
        let functions = if multifunction { 8 } else { 1 };

        for function in 0..functions {
            let Some(bdf) = Bdf::new(bus, device, function) else {
                continue;
            };
            let id = host.read(cfg, bdf, reg::VENDOR_DEVICE)?;
            if id == ABSENT || (id & 0xffff) == 0xffff {
                continue;
            }
            if walk.found == walk.out.len() {
                return Err(Error::TooManyFunctions);
            }
            let mut entry = read_function(host, cfg, bdf, id, allocator)?;
            entry.parent = parent;
            let is_bridge = entry.header_type == HEADER_TYPE_BRIDGE;
            walk.out[walk.found] = entry;
            walk.found += 1;

            if is_bridge {
                configure_bridge(host, cfg, bdf, allocator, walk)?;
            }
        }
    }
    Ok(())
}

/// Gives a bridge a bus number and a memory window, then enumerates what is
/// behind it out of that window.
///
/// **The child's BARs come from the bridge's window, not the host's.** A bridge
/// forwards a memory transaction only when the address falls inside the range
/// its base and limit registers describe, so a BAR placed anywhere else is a
/// BAR the device can never be reached at — the enumeration would succeed and
/// every access afterwards would go nowhere.
///
/// The window is carved before the far side is scanned, which means its size is
/// chosen without knowing what is behind it. One megabyte, the granularity the
/// registers can express at all: sizing it to the children would need a probing
/// pass over a bus that does not answer yet, and a bridge whose children do not
/// fit refuses here rather than silently placing one outside the window.
fn configure_bridge(
    host: &Host,
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    allocator: &mut WindowAllocator,
    walk: &mut Walk<'_>,
) -> Result<(), Error> {
    let secondary = walk.next_bus.checked_add(1).ok_or(Error::BadBusRange)?;
    if secondary > host.last_bus {
        return Err(Error::BadBusRange);
    }
    walk.next_bus = secondary;

    let (cpu, bus_addr) = allocator.allocate(BRIDGE_WINDOW_GRANULARITY)?;
    if bus_addr > u64::from(u32::MAX) {
        return Err(Error::WindowExhausted);
    }
    // **Address bits 31:20 sit in register bits 15:4**, not at the bottom.
    // The low four bits are reserved and read zero, which is what makes a
    // window written without the shift look like an address 16 times too
    // small — the bridge forwards a range that does not contain its children,
    // and every access to them goes nowhere while enumeration still succeeds,
    // because configuration cycles are claimed by the bus numbers rather than
    // by this window.
    let base = ((bus_addr >> 20) as u32 & 0xfff) << 4;
    let limit = (((bus_addr + BRIDGE_WINDOW_GRANULARITY - 1) >> 20) as u32 & 0xfff) << 4;
    host.write(cfg, bdf, reg::MEMORY_BASE_LIMIT, base | (limit << 16))?;

    // Primary is the bus this bridge sits on; secondary and subordinate bound
    // what it claims.
    //
    // **Subordinate is written twice, wide and then narrow, and the order is
    // the whole reason a tree works.** How far down this bridge reaches is not
    // known until the far side has been walked — and the far side cannot be
    // walked unless this bridge already forwards configuration cycles to it.
    // A bridge that claimed only its secondary while the scan ran would stop
    // every cycle aimed at a bus below the next bridge down, so the
    // grandchildren would not answer at all and the walk would record an empty
    // bus rather than fail. So the provisional bound is the widest the host
    // has, and it is narrowed to what was actually found once the recursion
    // returns.
    let primary = bdf.bus;
    host.write(
        cfg,
        bdf,
        reg::BUS_NUMBERS,
        u32::from(primary) | (u32::from(secondary) << 8) | (u32::from(host.last_bus) << 16),
    )?;

    // **And the bridge has to be told to decode.** `read_function` enables
    // memory space and bus mastering on an endpoint once its BARs are placed,
    // and returns before that for a bridge, whose type-1 header keeps
    // something else where the BARs would be. Without this the windows above
    // are programmed and the bridge forwards nothing through them: the far
    // side enumerates, because configuration cycles are claimed by the bus
    // numbers rather than by the memory window, and every *memory* access to
    // anything behind it goes nowhere.
    let command = host.read(cfg, bdf, reg::COMMAND_STATUS)?;
    host.write(
        cfg,
        bdf,
        reg::COMMAND_STATUS,
        command | command::MEMORY_SPACE | command::BUS_MASTER,
    )?;

    // **Now** the far side answers.
    let mut child = WindowAllocator::new(Window {
        cpu_base: cpu,
        bus_base: bus_addr,
        len: BRIDGE_WINDOW_GRANULARITY,
        is_32bit: true,
    });
    scan_bus(host, cfg, secondary, Some(bdf), &mut child, walk)?;

    // **The real subordinate.** Every bus the recursion handed out is behind
    // this bridge: `next_bus` only grows, and every number it took while the
    // call above was running went to a bridge below this one. Narrowing to it
    // matters as much as the wide bound did — a bridge left claiming buses that
    // are really its *sibling's* would answer configuration cycles aimed there,
    // and two bridges claiming one bus is a fabric that decodes ambiguously.
    host.write(
        cfg,
        bdf,
        reg::BUS_NUMBERS,
        u32::from(primary) | (u32::from(secondary) << 8) | (u32::from(walk.next_bus) << 16),
    )?;
    Ok(())
}

/// Reads one function's identity and places its BARs.
fn read_function(
    host: &Host,
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    id: u32,
    allocator: &mut WindowAllocator,
) -> Result<Function, Error> {
    let class = host.read(cfg, bdf, reg::REVISION_CLASS)?;
    let header = host.read(cfg, bdf, reg::HEADER_TYPE)?;
    let header_type = (header >> 16) & !HEADER_TYPE_MULTIFUNCTION & 0xff;

    let mut function = Function {
        bdf,
        vendor: (id & 0xffff) as u16,
        device: ((id >> 16) & 0xffff) as u16,
        class_code: class >> 8,
        revision: (class & 0xff) as u8,
        header_type,
        bars: [None; MAX_BARS],
        // Filled in by the walk, which is the only thing that knows.
        parent: None,
    };

    // Only an endpoint has six BARs; a bridge's header means something else at
    // those offsets, and reading it as a BAR would invent a window.
    if header_type != HEADER_TYPE_ENDPOINT {
        return Ok(function);
    }

    let mut index = 0usize;
    while index < MAX_BARS {
        match assign_bar(host, cfg, bdf, index, allocator)? {
            BarOutcome::Memory { cpu, len, is_64bit } => {
                function.bars[index] = Some((cpu, len));
                // A 64-bit BAR consumes the next register as its high half.
                index += if is_64bit { 2 } else { 1 };
            }
            BarOutcome::Skipped => index += 1,
        }
    }

    // Decoding is enabled only now, with every BAR placed. Bus mastering comes
    // with it because a device that cannot DMA is of no use to a driver, and
    // the two are the same decision on this machine (no IOMMU yet — D78).
    let command = host.read(cfg, bdf, reg::COMMAND_STATUS)?;
    host.write(
        cfg,
        bdf,
        reg::COMMAND_STATUS,
        command | command::MEMORY_SPACE | command::BUS_MASTER,
    )?;
    Ok(function)
}

enum BarOutcome {
    Memory { cpu: u64, len: u64, is_64bit: bool },
    Skipped,
}

/// Sizes and places one BAR.
///
/// Sizing is a write: all-ones goes in, the device replies with a mask whose
/// low clear bits are the size, and **the original value is put back before
/// anything else touches the function**. Between those two writes the BAR
/// decodes garbage, which is why memory decoding is off until every BAR is
/// placed.
fn assign_bar(
    host: &Host,
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    index: usize,
    allocator: &mut WindowAllocator,
) -> Result<BarOutcome, Error> {
    let register = reg::BAR0 + (index as u16) * 4;
    let original = host.read(cfg, bdf, register)?;

    // Bit 0 selects the space: 1 = I/O. I/O BARs are not placed — the
    // reference machines route memory windows, and a driver reaching a device
    // by port I/O is a different transport with a different capability.
    if original & 1 != 0 {
        return Ok(BarOutcome::Skipped);
    }
    let is_64bit = (original >> 1) & 0x3 == 0x2;

    host.write(cfg, bdf, register, 0xffff_ffff)?;
    let mask = host.read(cfg, bdf, register)?;
    host.write(cfg, bdf, register, original)?;

    // An unimplemented BAR reads back as zero after masking off the type bits.
    let size_bits = mask & !0xf;
    if size_bits == 0 {
        return Ok(BarOutcome::Skipped);
    }
    // The size is the low clear bits plus one; `!mask + 1` over the address
    // bits. Computed in 32 bits because that is the register's width.
    let len = u64::from(!size_bits).wrapping_add(1) & 0xffff_ffff;
    if len == 0 || !len.is_power_of_two() {
        return Err(Error::BadBarSize);
    }

    let (cpu, bus) = allocator.allocate(len)?;
    // The low four bits are type flags, not address; preserve them.
    host.write(cfg, bdf, register, (bus as u32 & !0xf) | (original & 0xf))?;
    if is_64bit {
        // A 64-bit BAR's high half lives in the next register. Everything this
        // crate places comes from a 32-bit window, so the high half is zero —
        // written explicitly rather than assumed, because the device may have
        // powered up with something in it.
        host.write(cfg, bdf, register + 4, (bus >> 32) as u32)?;
    }
    Ok(BarOutcome::Memory { cpu, len, is_64bit })
}

/// Finds the capability with id `id`, returning its offset in config space.
///
/// The list is a chain of `(id, next)` byte pairs, and `next` comes from the
/// device — so the walk is bounded three ways: the list-present status bit
/// must be set, every offset must lie inside the 256-byte header and be
/// 4-byte aligned, and the chain must terminate within [`MAX_CAPABILITIES`].
/// A device that points a capability at itself is a loop, and a loop in the
/// kernel's enumeration is a hang rather than a wrong answer.
pub fn find_capability(
    host: &Host,
    cfg: &dyn ConfigSpace,
    bdf: Bdf,
    id: u8,
) -> Result<Option<u16>, Error> {
    find_capability_from(host, cfg, bdf, id, None)
}

/// Whether `bridge`'s slot is asking for the device in it to be removed.
///
/// **This is what an eject request looks like from inside the machine.** A
/// hot-pluggable slot does not simply lose its device: the port raises a
/// request and waits, because a device may be in the middle of being used and
/// the software using it is the only thing that knows. A guest that never
/// answers is a guest the device never leaves.
///
/// `Ok(false)` for a port with no slot, or a slot that is not asking.
pub fn eject_requested(host: &Host, cfg: &dyn ConfigSpace, bridge: Bdf) -> Result<bool, Error> {
    let Some(cap) = find_capability(host, cfg, bridge, CAP_EXPRESS)? else {
        return Ok(false);
    };
    let caps = host.read(cfg, bridge, cap + slot::CAPABILITIES)?;
    if caps & slot::CAP_HOTPLUG_CAPABLE == 0 {
        return Ok(false);
    }
    let status = host.read(cfg, bridge, cap + slot::CONTROL_STATUS)? >> 16;
    Ok(status & slot::STATUS_ACKNOWLEDGED != 0)
}

/// Answers a pending eject: acknowledges the request and powers the slot down,
/// which is what actually lets the device go.
///
/// Two writes in one, and both are needed. Clearing the status bits says the
/// request was heard — they are write-one-to-clear, so writing them back is
/// what clears them, and leaving them set would make every later poll see a
/// request that had already been dealt with. Turning the power controller and
/// the indicator off is the answer itself: it is how a guest says it has
/// finished with the device and the slot may be de-energized.
///
/// After this the device is gone and its configuration space reads all-ones,
/// which is the only part of the exchange a driver notices.
pub fn acknowledge_eject(host: &Host, cfg: &mut dyn ConfigSpace, bridge: Bdf) -> Result<(), Error> {
    let Some(cap) = find_capability(host, cfg, bridge, CAP_EXPRESS)? else {
        return Err(Error::BadBusRange);
    };
    let current = host.read(cfg, bridge, cap + slot::CONTROL_STATUS)?;
    let control = (current & 0xffff) | slot::CONTROL_POWER_OFF | slot::CONTROL_POWER_INDICATOR_OFF;
    // Status is the high half and write-one-to-clear; control is the low half
    // and not. One dword carries both, so they move together.
    host.write(
        cfg,
        bridge,
        cap + slot::CONTROL_STATUS,
        control | (slot::STATUS_ACKNOWLEDGED << 16),
    )
}

/// The same walk, resumed **after** `previous`.
///
/// A device may carry more than one capability of the same id, and then the
/// first match is not the answer — it is the first of several. virtio is the
/// case in point: it publishes one vendor-specific capability per
/// configuration structure, and a driver needs all of them. Passing the offset
/// just returned continues from there; `None` starts at the head, which is what
/// [`find_capability`] does.
///
/// Resuming re-walks the chain from the head rather than trusting the caller's
/// offset as a starting point. That costs a few config reads and keeps every
/// bound in [`find_capability`] doing its job — a caller cannot hand this an
/// offset that skips the alignment and range checks, because the walk still
/// visits every link.
pub fn find_capability_from(
    host: &Host,
    cfg: &dyn ConfigSpace,
    bdf: Bdf,
    id: u8,
    previous: Option<u16>,
) -> Result<Option<u16>, Error> {
    let status = host.read(cfg, bdf, reg::COMMAND_STATUS)?;
    if (status >> 16) & STATUS_CAPABILITY_LIST == 0 {
        return Ok(None);
    }
    let mut offset = (host.read(cfg, bdf, reg::CAPABILITY_POINTER)? & 0xfc) as u16;
    let mut seen = 0usize;
    // Everything up to and including `previous` has been reported already.
    let mut skipping = previous.is_some();
    while offset != 0 {
        // Only the range is checked. Alignment cannot be: the specification
        // reserves the low two bits of every capability pointer and requires
        // software to mask them, which both reads above do — so an `offset`
        // that is not a multiple of four cannot reach here, and a guard
        // against one would be a guard that never fires. Masking is the
        // enforcement; this is the bound that is left to check.
        if !(0x40..CONFIG_HEADER_LEN).contains(&offset) {
            return Err(Error::MalformedCapabilityList);
        }
        seen += 1;
        if seen > MAX_CAPABILITIES {
            return Err(Error::MalformedCapabilityList);
        }
        let header = host.read(cfg, bdf, offset)?;
        if skipping {
            // Stop skipping *after* the link the caller named, so the next
            // match is the one after it.
            if Some(offset) == previous {
                skipping = false;
            }
        } else if (header & 0xff) as u8 == id {
            return Ok(Some(offset));
        }
        offset = ((header >> 8) & 0xfc) as u16;
    }
    Ok(None)
}

/// Where a function's MSI-X table lives and how many vectors it has.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MsixTable {
    /// Offset of the MSI-X capability in config space.
    pub capability: u16,
    /// Which BAR the table is in.
    pub bar: usize,
    /// Byte offset of the table within that BAR.
    pub offset: u32,
    /// Vectors the table holds.
    pub entries: u16,
}

/// Bytes per MSI-X table entry: address low, address high, data, control.
pub const MSIX_ENTRY_SIZE: u64 = 16;
/// Set in an entry's control word while the vector is masked.
pub const MSIX_VECTOR_MASKED: u32 = 1 << 0;
/// Set in the MSI-X message control to enable the function's MSI-X.
const MSIX_ENABLE: u32 = 1 << 15;
/// Set in the MSI message control to enable MSI.
const MSI_ENABLE: u32 = 1 << 0;
/// Set in the MSI message control when the address is 64-bit, which moves the
/// data register from +0x08 to +0x0c.
const MSI_64BIT: u32 = 1 << 7;

/// Reads an MSI-X capability: the table's BAR, offset and vector count.
pub fn msix_table(
    host: &Host,
    cfg: &dyn ConfigSpace,
    bdf: Bdf,
    capability: u16,
    function: &Function,
) -> Result<MsixTable, Error> {
    let control = host.read(cfg, bdf, capability)? >> 16;
    // The size field holds "entries minus one", so a one-vector device reads
    // zero — adding one is what the specification says and what a naive read
    // gets wrong.
    let entries = ((control & 0x7ff) as u16).saturating_add(1);
    let table = host.read(cfg, bdf, capability + 4)?;
    let bar = (table & 0x7) as usize;
    if bar >= MAX_BARS || function.bars[bar].is_none() {
        return Err(Error::BadMsixTable);
    }
    Ok(MsixTable {
        capability,
        bar,
        offset: table & !0x7,
        entries,
    })
}

/// Programs one MSI-X table entry and unmasks it.
///
/// `table` is a register window over the entry's BAR, not config space — the
/// caller maps it, which is why this takes an accessor rather than reaching
/// for one. The mask is cleared **last**: an entry is written while masked so
/// a device cannot send using a half-written address.
pub fn program_msix_entry(
    table: &mut dyn ConfigSpace,
    entry: usize,
    address: u64,
    data: u32,
) -> Result<(), Error> {
    let at = (entry as u64) * MSIX_ENTRY_SIZE;
    table.write32(at + 12, MSIX_VECTOR_MASKED);
    table.write32(at, address as u32);
    table.write32(at + 4, (address >> 32) as u32);
    table.write32(at + 8, data);
    table.write32(at + 12, 0);
    Ok(())
}

/// Enables MSI-X on a function, after its table entries are programmed.
pub fn msix_enable(
    host: &Host,
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    capability: u16,
) -> Result<(), Error> {
    let control = host.read(cfg, bdf, capability)?;
    host.write(cfg, bdf, capability, control | (MSIX_ENABLE << 16))?;
    Ok(())
}

/// Programs a function's MSI capability with `address`/`data` and enables it.
///
/// MSI keeps its address and data in config space rather than in a table, so
/// there is nothing to map — which is why it, and not MSI-X, is what a device
/// can be made to send without first bringing up its transport.
pub fn msi_program(
    host: &Host,
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    capability: u16,
    address: u64,
    data: u32,
) -> Result<(), Error> {
    let control = host.read(cfg, bdf, capability)?;
    let is_64bit = ((control >> 16) & MSI_64BIT) != 0;
    host.write(cfg, bdf, capability + 4, address as u32)?;
    let data_at = if is_64bit {
        host.write(cfg, bdf, capability + 8, (address >> 32) as u32)?;
        capability + 12
    } else {
        capability + 8
    };
    // The data register is 16 bits in a 32-bit slot; the upper half is
    // reserved and written zero rather than left as whatever was there.
    host.write(cfg, bdf, data_at, data & 0xffff)?;
    // Enabling last, for the same reason MSI-X unmasks last.
    host.write(cfg, bdf, capability, control | (MSI_ENABLE << 16))?;
    Ok(())
}

#[cfg(test)]
mod tests;
