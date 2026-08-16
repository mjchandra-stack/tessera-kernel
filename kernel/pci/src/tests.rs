// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Host tests for the enumeration walk, run against a mock config space that
//! behaves the way hardware does: absent slots read all ones, and a BAR
//! answers a size probe with its mask rather than the value written.

use super::*;

/// Config space for one bus, backed by a flat array. Only the registers the
/// walk touches are modelled; everything else reads as absent.
struct MockBus {
    /// Per-function words, indexed by `(offset / 4)`. Sized for the whole
    /// 256-byte legacy config header, because that is where a capability list
    /// lives — a 64-byte mock covers the type-0 header and nothing a
    /// capability walk would ever read.
    functions: [[u32; 64]; 32 * 8],
    /// BAR size masks a function answers with when probed with all-ones.
    bar_masks: [[u32; MAX_BARS]; 32 * 8],
    /// Whether the last write to each BAR was the all-ones size probe.
    probing: [[bool; MAX_BARS]; 32 * 8],
    writes: usize,
}

fn slot(offset: u64) -> usize {
    ((offset >> 12) & 0xff) as usize
}

impl MockBus {
    fn new() -> Self {
        Self {
            functions: [[0xffff_ffff; 64]; 32 * 8],
            bar_masks: [[0; MAX_BARS]; 32 * 8],
            probing: [[false; MAX_BARS]; 32 * 8],
            writes: 0,
        }
    }

    /// Places an endpoint at `device.function` with the given identity.
    fn endpoint(&mut self, device: u8, function: u8, vendor: u16, dev: u16, class_code: u32) {
        let index = (device as usize) * 8 + function as usize;
        self.functions[index] = [0; 64];
        self.functions[index][0] = (u32::from(dev) << 16) | u32::from(vendor);
        self.functions[index][1] = 0;
        self.functions[index][2] = class_code << 8;
        self.functions[index][3] = 0;
    }

    /// Marks function 0 of `device` as multi-function.
    fn multifunction(&mut self, device: u8) {
        let index = (device as usize) * 8;
        self.functions[index][3] |= HEADER_TYPE_MULTIFUNCTION << 16;
    }

    /// Gives an endpoint a memory BAR of `size` bytes at `index`.
    fn memory_bar(&mut self, device: u8, function: u8, index: usize, size: u32) {
        let f = (device as usize) * 8 + function as usize;
        self.bar_masks[f][index] = !(size - 1);
    }

    fn bar_of(offset: u64) -> Option<usize> {
        let register = (offset & 0xfff) as u16;
        if (reg::BAR0..reg::BAR0 + (MAX_BARS as u16) * 4).contains(&register) {
            Some(((register - reg::BAR0) / 4) as usize)
        } else {
            None
        }
    }
}

impl ConfigSpace for MockBus {
    fn read32(&self, offset: u64) -> u32 {
        let index = slot(offset);
        if let Some(bar) = Self::bar_of(offset)
            && self.probing[index][bar]
        {
            // A size probe reads back the mask, not the all-ones written.
            return self.bar_masks[index][bar];
        }
        self.functions[index][((offset & 0xfff) / 4) as usize]
    }

    fn write32(&mut self, offset: u64, value: u32) {
        let index = slot(offset);
        self.writes += 1;
        if let Some(bar) = Self::bar_of(offset) {
            self.probing[index][bar] = value == 0xffff_ffff;
            if self.probing[index][bar] {
                return;
            }
        }
        self.functions[index][((offset & 0xfff) / 4) as usize] = value;
    }
}

const HOST: Host = Host {
    ecam_base: 0x3000_0000,
    ecam_len: 0x0010_0000, // one bus
    first_bus: 0,
    last_bus: 0,
};

const WINDOW: Window = Window {
    cpu_base: 0x4000_0000,
    bus_base: 0x4000_0000,
    len: 0x0010_0000,
    is_32bit: true,
};

#[test]
fn ecam_offsets_match_the_specified_layout() {
    let bdf = Bdf::new(0, 0, 0).expect("bdf");
    assert_eq!(bdf.ecam_offset(0), 0);
    // Bus 1 is one megabyte in; device 1 is 32 KiB; function 1 is 4 KiB.
    assert_eq!(Bdf::new(1, 0, 0).expect("bdf").ecam_offset(0), 0x10_0000);
    assert_eq!(Bdf::new(0, 1, 0).expect("bdf").ecam_offset(0), 0x8000);
    assert_eq!(Bdf::new(0, 0, 1).expect("bdf").ecam_offset(0), 0x1000);
    assert_eq!(
        Bdf::new(1, 31, 7).expect("bdf").ecam_offset(0),
        0x10_0000 | (31 << 15) | (7 << 12)
    );
}

/// A window that does not start at bus 0 puts its first bus at offset 0.
/// Treating the bus number as absolute would run off the end.
#[test]
fn a_windows_first_bus_sits_at_offset_zero() {
    assert_eq!(Bdf::new(4, 0, 0).expect("bdf").ecam_offset(4), 0);
    assert_eq!(Bdf::new(5, 0, 0).expect("bdf").ecam_offset(4), 0x10_0000);
}

#[test]
fn out_of_range_device_and_function_are_rejected_at_construction() {
    assert!(Bdf::new(0, 32, 0).is_none());
    assert!(Bdf::new(0, 0, 8).is_none());
    assert!(Bdf::new(255, 31, 7).is_some());
}

#[test]
fn an_empty_bus_enumerates_nothing() {
    let mut bus = MockBus::new();
    let mut out = [FUNCTION_BLANK; 8];
    assert_eq!(
        enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk"),
        0
    );
}

const FUNCTION_BLANK: Function = Function {
    revision: 0,
    bdf: Bdf {
        bus: 0,
        device: 0,
        function: 0,
    },
    vendor: 0,
    device: 0,
    class_code: 0,
    header_type: 0,
    bars: [None; MAX_BARS],
    parent: None,
};

#[test]
fn an_endpoint_reports_its_identity() {
    let mut bus = MockBus::new();
    // virtio-blk-pci: Red Hat vendor, mass-storage class.
    bus.endpoint(1, 0, 0x1af4, 0x1042, 0x01_08_00);
    let mut out = [FUNCTION_BLANK; 8];
    let n = enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk");
    assert_eq!(n, 1);
    assert_eq!(out[0].vendor, 0x1af4);
    assert_eq!(out[0].device, 0x1042);
    assert_eq!(out[0].class(), 0x01, "mass storage");
    assert_eq!(out[0].subclass(), 0x08);
    assert_eq!(out[0].bdf.device, 1);
}

/// A single-function device answers at every function number, so probing 1..8
/// unconditionally would report seven phantom copies of it.
#[test]
fn a_single_function_device_is_reported_once() {
    let mut bus = MockBus::new();
    bus.endpoint(3, 0, 0x1af4, 0x1042, 0x01_08_00);
    // The mock answers at every function of the slot, as hardware does.
    for function in 1..8 {
        bus.endpoint(3, function, 0x1af4, 0x1042, 0x01_08_00);
    }
    let mut out = [FUNCTION_BLANK; 8];
    assert_eq!(
        enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk"),
        1
    );
}

#[test]
fn a_multifunction_device_reports_every_present_function() {
    let mut bus = MockBus::new();
    bus.endpoint(2, 0, 0x1af4, 0x1000, 0x02_00_00);
    bus.endpoint(2, 1, 0x1af4, 0x1042, 0x01_08_00);
    bus.multifunction(2);
    let mut out = [FUNCTION_BLANK; 8];
    let n = enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk");
    assert_eq!(n, 2);
    assert_eq!(out[0].class(), 0x02, "network");
    assert_eq!(out[1].class(), 0x01, "block");
}

#[test]
fn a_memory_bar_is_sized_and_placed_aligned() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1042, 0x01_08_00);
    bus.memory_bar(1, 0, 0, 0x1000);
    let mut out = [FUNCTION_BLANK; 8];
    enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk");

    let (address, len) = out[0].first_bar().expect("a placed BAR");
    assert_eq!(len, 0x1000);
    assert_eq!(address, WINDOW.cpu_base, "first allocation is at the base");
    assert_eq!(
        address % len,
        0,
        "a BAR decodes an aligned block of its size"
    );

    // The address really reached the register, with the type bits preserved.
    // Bus 0, device 1 — where `endpoint(1, 0, ..)` put it.
    let base = Bdf::new(0, 1, 0).expect("bdf").ecam_offset(0);
    let written = bus.read32(base + u64::from(reg::BAR0));
    assert_eq!(written & !0xf, WINDOW.cpu_base as u32);
}

/// Two devices must not be handed overlapping windows, and each must land on
/// its own size boundary.
#[test]
fn bars_do_not_overlap_and_stay_aligned() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1042, 0x01_08_00);
    bus.memory_bar(1, 0, 0, 0x1000);
    bus.endpoint(2, 0, 0x1af4, 0x1000, 0x02_00_00);
    bus.memory_bar(2, 0, 0, 0x10000);
    let mut out = [FUNCTION_BLANK; 8];
    enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk");

    let (a, alen) = out[0].first_bar().expect("first");
    let (b, blen) = out[1].first_bar().expect("second");
    assert_eq!(a % alen, 0);
    assert_eq!(b % blen, 0);
    assert!(a + alen <= b || b + blen <= a, "windows overlap");
}

/// Enabling decoding before the BARs are placed would leave a device answering
/// at whatever address zero happens to be.
#[test]
fn decoding_is_enabled_only_after_placement() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1042, 0x01_08_00);
    bus.memory_bar(1, 0, 0, 0x1000);
    let mut out = [FUNCTION_BLANK; 8];
    enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk");

    let base = Bdf::new(0, 1, 0).expect("bdf").ecam_offset(0);
    let command = bus.read32(base + u64::from(reg::COMMAND_STATUS));
    assert_ne!(command & command::MEMORY_SPACE, 0, "memory decoding on");
    assert_ne!(command & command::BUS_MASTER, 0, "bus mastering on");
    // And the BAR holds an address, not the all-ones probe value.
    assert_ne!(bus.read32(base + u64::from(reg::BAR0)), 0xffff_ffff);
}

#[test]
fn an_io_bar_is_skipped_rather_than_placed_in_a_memory_window() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1042, 0x01_08_00);
    // Bit 0 set marks I/O space.
    let index = 8usize;
    bus.functions[index][(reg::BAR0 / 4) as usize] = 1;
    bus.memory_bar(1, 0, 0, 0x1000);
    let mut out = [FUNCTION_BLANK; 8];
    enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk");
    assert_eq!(out[0].bars[0], None);
}

#[test]
fn a_bar_larger_than_the_window_is_refused() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1042, 0x01_08_00);
    // 2 MiB into a 1 MiB window.
    bus.memory_bar(1, 0, 0, 0x20_0000);
    let mut out = [FUNCTION_BLANK; 8];
    assert_eq!(
        enumerate(&HOST, &mut bus, WINDOW, &mut out),
        Err(Error::WindowExhausted)
    );
}

/// The boundary the whole walk rests on. ECAM arithmetic is a shift and an or,
/// so a bus past the end produces a plausible address that would read whatever
/// follows the window.
#[test]
fn a_walk_never_addresses_outside_the_ecam_window() {
    let host = Host {
        ecam_base: 0x3000_0000,
        // Half a bus: device 16 and above are outside it.
        ecam_len: 0x0008_0000,
        first_bus: 0,
        last_bus: 0,
    };
    let mut bus = MockBus::new();
    bus.endpoint(20, 0, 0x1af4, 0x1042, 0x01_08_00);
    let mut out = [FUNCTION_BLANK; 8];
    assert_eq!(
        enumerate(&host, &mut bus, WINDOW, &mut out),
        Err(Error::OutsideEcam)
    );
}

#[test]
fn an_inverted_bus_range_is_refused() {
    let host = Host {
        ecam_base: 0x3000_0000,
        ecam_len: 0x0010_0000,
        first_bus: 4,
        last_bus: 1,
    };
    let mut bus = MockBus::new();
    let mut out = [FUNCTION_BLANK; 8];
    assert_eq!(
        enumerate(&host, &mut bus, WINDOW, &mut out),
        Err(Error::BadBusRange)
    );
}

/// A full output buffer is an error, not a short answer that looks complete —
/// a caller cannot tell "four devices" from "four of the devices" otherwise.
#[test]
fn more_functions_than_fit_is_an_error() {
    let mut bus = MockBus::new();
    for device in 0..4u8 {
        bus.endpoint(device, 0, 0x1af4, 0x1042, 0x01_08_00);
    }
    let mut out = [FUNCTION_BLANK; 2];
    assert_eq!(
        enumerate(&HOST, &mut bus, WINDOW, &mut out),
        Err(Error::TooManyFunctions)
    );
}

// --- capability list, MSI-X and MSI (D117) ---

impl MockBus {
    /// Writes a config word for `device.function` at `offset`.
    fn poke(&mut self, device: u8, function: u8, offset: u16, value: u32) {
        let index = (device as usize) * 8 + function as usize;
        self.functions[index][(offset / 4) as usize] = value;
    }

    /// Marks the function as having a capability list starting at `first`.
    fn capability_list(&mut self, device: u8, function: u8, first: u16) {
        self.poke(
            device,
            function,
            reg::COMMAND_STATUS,
            STATUS_CAPABILITY_LIST << 16,
        );
        self.poke(device, function, reg::CAPABILITY_POINTER, u32::from(first));
    }

    /// Writes a capability header: id, next pointer, and message control.
    fn capability(&mut self, device: u8, function: u8, at: u16, id: u8, next: u16, control: u32) {
        self.poke(
            device,
            function,
            at,
            u32::from(id) | (u32::from(next) << 8) | (control << 16),
        );
    }
}

/// A function's config space is only 16 words in the mock, so capabilities
/// live low; the walk's own bound is exercised by the malformed tests below.
const CAP_AT: u16 = 0x40;

/// A bus where device 1 has an MSI-X capability whose table is in BAR 0.
fn msix_bus() -> (MockBus, [Function; 8]) {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1041, 0x01_08_00);
    bus.memory_bar(1, 0, 0, 0x1000);
    let mut out = [FUNCTION_BLANK; 8];
    enumerate(&HOST, &mut bus, WINDOW, &mut out).expect("walk");
    // Enumeration wrote the command register; add the capability list after.
    bus.capability_list(1, 0, CAP_AT);
    // Three vectors (size field holds entries - 1), table at offset 0 of BAR 0.
    bus.capability(1, 0, CAP_AT, CAP_MSIX, 0, 2);
    bus.poke(1, 0, CAP_AT + 4, 0);
    (bus, out)
}

#[test]
fn a_function_with_no_capability_list_reports_none() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1041, 0x01_08_00);
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    assert_eq!(find_capability(&HOST, &bus, bdf, CAP_MSIX), Ok(None));
}

#[test]
fn the_walk_finds_a_capability_by_id() {
    let (bus, _) = msix_bus();
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    assert_eq!(
        find_capability(&HOST, &bus, bdf, CAP_MSIX),
        Ok(Some(CAP_AT))
    );
    // An id the device does not implement is absent, not an error.
    assert_eq!(find_capability(&HOST, &bus, bdf, CAP_MSI), Ok(None));
}

/// A capability pointing at itself is a loop, and a loop in the kernel's
/// enumeration is a hang rather than a wrong answer.
#[test]
fn a_capability_that_points_at_itself_is_refused() {
    let (mut bus, _) = msix_bus();
    bus.capability(1, 0, CAP_AT, 0xaa, CAP_AT, 0);
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    assert_eq!(
        find_capability(&HOST, &bus, bdf, CAP_MSIX),
        Err(Error::MalformedCapabilityList)
    );
}

/// A pointer below the header or outside config space describes something
/// that cannot exist.
#[test]
fn a_capability_outside_config_space_is_refused() {
    let (mut bus, _) = msix_bus();
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    bus.capability_list(1, 0, 0x10);
    assert_eq!(
        find_capability(&HOST, &bus, bdf, CAP_MSIX),
        Err(Error::MalformedCapabilityList)
    );
}

#[test]
fn the_msix_table_is_located_and_its_size_is_entries_not_entries_minus_one() {
    let (bus, functions) = msix_bus();
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    let table = msix_table(&HOST, &bus, bdf, CAP_AT, &functions[0]).expect("table");
    assert_eq!(table.bar, 0);
    assert_eq!(table.offset, 0);
    // The control field held 2; the table has three vectors.
    assert_eq!(table.entries, 3);
}

/// An MSI-X table in a BAR the function never had is a device describing a
/// window nothing placed.
#[test]
fn an_msix_table_in_an_absent_bar_is_refused() {
    let (mut bus, functions) = msix_bus();
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    bus.poke(1, 0, CAP_AT + 4, 3); // BIR = 3, which has no BAR
    assert_eq!(
        msix_table(&HOST, &bus, bdf, CAP_AT, &functions[0]),
        Err(Error::BadMsixTable)
    );
}

/// A flat register window standing in for a mapped MSI-X table.
struct MockTable {
    words: [u32; 16],
    /// Every write in order, so the test can check that the mask came down
    /// only after the address and data were in place.
    order: [(u64, u32); 16],
    writes: usize,
}

impl ConfigSpace for MockTable {
    fn read32(&self, offset: u64) -> u32 {
        self.words[(offset / 4) as usize]
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.words[(offset / 4) as usize] = value;
        if self.writes < self.order.len() {
            self.order[self.writes] = (offset, value);
        }
        self.writes += 1;
    }
}

#[test]
fn programming_an_entry_writes_the_address_and_data_and_unmasks_last() {
    let mut table = MockTable {
        words: [0; 16],
        order: [(0, 0); 16],
        writes: 0,
    };
    program_msix_entry(&mut table, 0, 0x0802_0040, 42).expect("program");

    assert_eq!(table.words[0], 0x0802_0040, "address low");
    assert_eq!(table.words[1], 0, "address high");
    assert_eq!(table.words[2], 42, "data");
    assert_eq!(table.words[3], 0, "unmasked");

    // The entry is masked first and unmasked last, so a device cannot send
    // using a half-written address.
    assert_eq!(table.order[0], (12, MSIX_VECTOR_MASKED));
    assert_eq!(table.order[table.writes - 1], (12, 0));
}

#[test]
fn a_second_entry_lands_at_its_own_offset() {
    let mut table = MockTable {
        words: [0; 16],
        order: [(0, 0); 16],
        writes: 0,
    };
    program_msix_entry(&mut table, 1, 0x0802_0040, 43).expect("program");
    assert_eq!(table.words[0], 0, "entry 0 untouched");
    assert_eq!(table.words[4], 0x0802_0040, "entry 1 address");
    assert_eq!(table.words[6], 43, "entry 1 data");
}

#[test]
fn enabling_msix_sets_the_control_bit_without_disturbing_the_list() {
    let (mut bus, _) = msix_bus();
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    msix_enable(&HOST, &mut bus, bdf, CAP_AT).expect("enable");
    let header = bus.read32(bdf.ecam_offset(0) + u64::from(CAP_AT));
    assert_ne!(header >> 16 & 0x8000, 0, "MSI-X enabled");
    assert_eq!(header & 0xff, u32::from(CAP_MSIX), "id preserved");
}

/// MSI keeps address and data in config space, and a 64-bit-capable device
/// moves the data register — writing it at the 32-bit offset would leave the
/// device with no vector and clobber the address high half.
#[test]
fn msi_programming_respects_the_64_bit_layout() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1234, 0x11e8, 0x00_ff_00);
    bus.capability_list(1, 0, CAP_AT);
    bus.capability(1, 0, CAP_AT, CAP_MSI, 0, MSI_64BIT);
    let bdf = Bdf::new(0, 1, 0).expect("bdf");

    msi_program(&HOST, &mut bus, bdf, CAP_AT, 0x0802_0040, 77).expect("program");
    let word = |at: u16| bus.read32(bdf.ecam_offset(0) + u64::from(at));
    assert_eq!(word(CAP_AT + 4), 0x0802_0040, "address low");
    assert_eq!(word(CAP_AT + 8), 0, "address high");
    assert_eq!(word(CAP_AT + 12), 77, "data, at the 64-bit offset");
    assert_ne!(word(CAP_AT) >> 16 & 1, 0, "MSI enabled");
}

#[test]
fn msi_programming_uses_the_32_bit_layout_when_the_device_says_so() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1234, 0x11e8, 0x00_ff_00);
    bus.capability_list(1, 0, CAP_AT);
    bus.capability(1, 0, CAP_AT, CAP_MSI, 0, 0);
    let bdf = Bdf::new(0, 1, 0).expect("bdf");

    msi_program(&HOST, &mut bus, bdf, CAP_AT, 0x0802_0040, 77).expect("program");
    let word = |at: u16| bus.read32(bdf.ecam_offset(0) + u64::from(at));
    assert_eq!(word(CAP_AT + 8), 77, "data, at the 32-bit offset");
}

/// A device may carry several capabilities of one id — virtio publishes one
/// vendor-specific capability per configuration structure — and then finding
/// "the" capability is not a question with one answer. The walk must be able to
/// continue past a match, or a driver sees only the first of four and
/// configures a device it has not finished reading.
#[test]
fn the_walk_resumes_past_a_match_to_find_the_next() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1041, 0x01_08_00);
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    bus.capability_list(1, 0, 0x40);
    // Three vendor capabilities chained, with an MSI-X one in the middle so the
    // resume cannot pass by counting links.
    bus.capability(1, 0, 0x40, CAP_VENDOR, 0x48, 0);
    bus.capability(1, 0, 0x48, CAP_MSIX, 0x50, 0);
    bus.capability(1, 0, 0x50, CAP_VENDOR, 0x58, 0);
    bus.capability(1, 0, 0x58, CAP_VENDOR, 0, 0);

    let mut found = [0u16; 4];
    let mut n = 0;
    let mut at = None;
    while let Ok(Some(offset)) = find_capability_from(&HOST, &bus, bdf, CAP_VENDOR, at) {
        found[n] = offset;
        n += 1;
        at = Some(offset);
        if n == found.len() {
            break;
        }
    }
    assert_eq!(n, 3, "three vendor capabilities, not one and not four");
    assert_eq!(found[..3], [0x40, 0x50, 0x58]);
    // And the interleaved id is still reachable on its own.
    assert_eq!(find_capability(&HOST, &bus, bdf, CAP_MSIX), Ok(Some(0x48)));
}

/// Resuming from the last match ends the walk rather than wrapping to the head
/// — otherwise a caller iterating to exhaustion never terminates.
#[test]
fn resuming_past_the_last_match_reports_none() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1041, 0x01_08_00);
    let bdf = Bdf::new(0, 1, 0).expect("bdf");
    bus.capability_list(1, 0, 0x40);
    bus.capability(1, 0, 0x40, CAP_VENDOR, 0, 0);
    assert_eq!(
        find_capability_from(&HOST, &bus, bdf, CAP_VENDOR, Some(0x40)),
        Ok(None)
    );
}

/// The revision is the low byte of the register the class comes from, and it
/// was being shifted off the end.
///
/// A binding input in its own right: a driver may support a device from
/// revision 3 onward and not before, and a manifest that could not name the
/// revision would have to claim every one of them or none.
#[test]
fn a_functions_revision_is_read_alongside_its_class() {
    let mut bus = MockBus::new();
    bus.endpoint(1, 0, 0x1af4, 0x1042, 0x01_00_00);
    // The revision shares the class register's low byte.
    // Device 1, function 0 — the mock's index is `device * 8 + function`.
    let index = 8usize;
    bus.functions[index][2] |= 0x07;

    let mut functions = [FUNCTION_BLANK; 8];
    let found = enumerate(&HOST, &mut bus, WINDOW, &mut functions).expect("walk");
    let function = functions[..found]
        .iter()
        .find(|f| f.vendor == 0x1af4)
        .expect("the endpoint");
    assert_eq!(function.class(), 0x01, "mass storage");
    assert_eq!(function.revision, 0x07);
    // And the class code no longer carries it, which is what made it
    // invisible: shifting the register right by eight is what discarded it.
    assert_eq!(
        function.class_code & 0xff,
        0x00,
        "prog-if, not the revision"
    );
}

// ---------------------------------------------------------------------------
// Bus topology: a fabric of more than one bus.
//
// [`MockBus`] models a single bus, which is why nothing above this line
// exercises a bridge — and why the walk's one-level-deep bus numbering went
// unnoticed until a second level was put behind it. This mock **enforces
// forwarding**: a configuration cycle reaches a bus only if every bridge on the
// path from the root claims that bus between its secondary and subordinate.
// Without that, the numbering could be arbitrarily wrong and every test would
// still pass, because the mock would answer for a bus nothing routes to.
// ---------------------------------------------------------------------------

/// Buses this fabric models — deep enough for a root port, a switch's upstream
/// and downstream ports, and an endpoint under them.
const FABRIC_BUSES: usize = 4;
/// Devices per bus. Two, so a bus can hold a pair of siblings; the walk probes
/// all 32 and the rest read absent.
const FABRIC_DEVICES: usize = 2;
const FABRIC_SLOTS: usize = FABRIC_DEVICES * 8;

struct MockFabric {
    words: [[[u32; 64]; FABRIC_SLOTS]; FABRIC_BUSES],
    bar_masks: [[[u32; MAX_BARS]; FABRIC_SLOTS]; FABRIC_BUSES],
    probing: [[[bool; MAX_BARS]; FABRIC_SLOTS]; FABRIC_BUSES],
}

/// Where a config offset lands: `(bus, slot, word)`, or `None` for an address
/// outside what this fabric models.
fn decode(offset: u64) -> Option<(usize, usize, usize)> {
    let bus = ((offset >> 20) & 0xff) as usize;
    let device = ((offset >> 15) & 0x1f) as usize;
    let function = ((offset >> 12) & 0x7) as usize;
    if bus >= FABRIC_BUSES || device >= FABRIC_DEVICES {
        return None;
    }
    Some((bus, device * 8 + function, ((offset & 0xfff) / 4) as usize))
}

impl MockFabric {
    fn new() -> Self {
        Self {
            words: [[[0xffff_ffff; 64]; FABRIC_SLOTS]; FABRIC_BUSES],
            bar_masks: [[[0; MAX_BARS]; FABRIC_SLOTS]; FABRIC_BUSES],
            probing: [[[false; MAX_BARS]; FABRIC_SLOTS]; FABRIC_BUSES],
        }
    }

    fn slot_of(device: u8, function: u8) -> usize {
        (device as usize) * 8 + function as usize
    }

    /// Places an endpoint on `bus`.
    fn endpoint(&mut self, bus: u8, device: u8, vendor: u16, dev: u16, class_code: u32) {
        let slot = Self::slot_of(device, 0);
        self.words[bus as usize][slot] = [0; 64];
        self.words[bus as usize][slot][0] = (u32::from(dev) << 16) | u32::from(vendor);
        self.words[bus as usize][slot][2] = class_code << 8;
    }

    /// Places a type-1 bridge on `bus`. Its bus-number register starts at zero,
    /// exactly as one comes out of reset: claiming nothing, forwarding nothing.
    fn bridge(&mut self, bus: u8, device: u8) {
        let slot = Self::slot_of(device, 0);
        self.words[bus as usize][slot] = [0; 64];
        self.words[bus as usize][slot][0] = 0x0001_1b36; // Red Hat PCIe port
        self.words[bus as usize][slot][2] = 0x06_04_00 << 8; // bridge class
        self.words[bus as usize][slot][3] = HEADER_TYPE_BRIDGE << 16;
    }

    fn memory_bar(&mut self, bus: u8, device: u8, index: usize, size: u32) {
        let slot = Self::slot_of(device, 0);
        self.bar_masks[bus as usize][slot][index] = !(size - 1);
    }

    /// The `(primary, secondary, subordinate)` a bridge is currently claiming.
    fn bus_numbers(&self, bus: u8, device: u8) -> (u8, u8, u8) {
        let word =
            self.words[bus as usize][Self::slot_of(device, 0)][(reg::BUS_NUMBERS / 4) as usize];
        (word as u8, (word >> 8) as u8, (word >> 16) as u8)
    }

    /// Whether a configuration cycle aimed at `bus` gets there.
    ///
    /// Walks **down** from the root, one bridge at a time. Asking instead
    /// whether some bridge claims the bus and sits on a reachable bus would be
    /// a different and much weaker question: a cycle passes *through* every
    /// bridge above the target, so each of them has to claim it too. That
    /// distinction is exactly the defect being tested for.
    fn reaches(&self, bus: usize) -> bool {
        let mut current = 0usize;
        for _ in 0..FABRIC_BUSES {
            if current == bus {
                return true;
            }
            let mut descend = None;
            for slot in 0..FABRIC_SLOTS {
                let words = &self.words[current][slot];
                if words[0] == 0xffff_ffff || (words[3] >> 16) & 0xff != HEADER_TYPE_BRIDGE {
                    continue;
                }
                let numbers = words[(reg::BUS_NUMBERS / 4) as usize];
                let secondary = ((numbers >> 8) & 0xff) as usize;
                let subordinate = ((numbers >> 16) & 0xff) as usize;
                if secondary != 0 && (secondary..=subordinate).contains(&bus) {
                    descend = Some(secondary);
                    break;
                }
            }
            match descend {
                Some(next) => current = next,
                None => return false,
            }
        }
        false
    }

    fn bar_of(offset: u64) -> Option<usize> {
        let register = (offset & 0xfff) as u16;
        if (reg::BAR0..reg::BAR0 + (MAX_BARS as u16) * 4).contains(&register) {
            Some(((register - reg::BAR0) / 4) as usize)
        } else {
            None
        }
    }
}

impl ConfigSpace for MockFabric {
    fn read32(&self, offset: u64) -> u32 {
        let Some((bus, slot, word)) = decode(offset) else {
            return 0xffff_ffff;
        };
        if !self.reaches(bus) {
            return 0xffff_ffff;
        }
        if let Some(bar) = Self::bar_of(offset)
            && self.probing[bus][slot][bar]
        {
            return self.bar_masks[bus][slot][bar];
        }
        self.words[bus][slot][word]
    }

    fn write32(&mut self, offset: u64, value: u32) {
        let Some((bus, slot, word)) = decode(offset) else {
            return;
        };
        if !self.reaches(bus) {
            return;
        }
        if let Some(bar) = Self::bar_of(offset) {
            self.probing[bus][slot][bar] = value == 0xffff_ffff;
            if self.probing[bus][slot][bar] {
                return;
            }
        }
        self.words[bus][slot][word] = value;
    }
}

const FABRIC_HOST: Host = Host {
    ecam_base: 0x3000_0000,
    ecam_len: (FABRIC_BUSES as u64) << 20,
    first_bus: 0,
    last_bus: FABRIC_BUSES as u8 - 1,
};

/// Four megabytes, so more than one bridge can be given a window. The
/// single-bus [`WINDOW`] is exactly one bridge's worth.
const FABRIC_WINDOW: Window = Window {
    cpu_base: 0x4000_0000,
    bus_base: 0x4000_0000,
    len: (FABRIC_BUSES as u64) << 20,
    is_32bit: true,
};

/// The machine the hotplug check runs on: a root port, a switch, and a device
/// under the switch's downstream port.
fn switch_fabric() -> MockFabric {
    let mut fabric = MockFabric::new();
    fabric.bridge(0, 0); // root port
    fabric.bridge(1, 0); // switch upstream port
    fabric.bridge(2, 0); // switch downstream port
    fabric.endpoint(3, 0, 0x1af4, 0x1042, 0x01_08_00);
    fabric.memory_bar(3, 0, 0, 0x1000);
    fabric
}

#[test]
fn a_bridge_behind_a_bridge_is_walked_through_to_the_endpoint() {
    let mut fabric = switch_fabric();
    let mut out = [FUNCTION_BLANK; 8];
    let found = enumerate(&FABRIC_HOST, &mut fabric, FABRIC_WINDOW, &mut out).expect("walk");

    // **Four, and the fourth is the point.** Before the subordinate was
    // widened for the descent, the root port claimed only its secondary, so no
    // configuration cycle reached the switch's downstream bus: the walk found
    // the root port and the upstream port and reported an empty bus below
    // them, which is indistinguishable from a switch with nothing plugged in.
    assert_eq!(found, 4, "root port, both switch ports, and the endpoint");
    let endpoint = out[..found]
        .iter()
        .find(|f| f.vendor == 0x1af4)
        .expect("the endpoint below the switch");
    assert_eq!(endpoint.bdf.bus, 3);
}

#[test]
fn every_function_records_the_bridge_it_sits_behind() {
    let mut fabric = switch_fabric();
    let mut out = [FUNCTION_BLANK; 8];
    let found = enumerate(&FABRIC_HOST, &mut fabric, FABRIC_WINDOW, &mut out).expect("walk");
    let at = |bus: u8| {
        *out[..found]
            .iter()
            .find(|f| f.bdf.bus == bus)
            .expect("a function on this bus")
    };

    // The chain, read off the parent edges alone.
    assert_eq!(at(0).parent, None, "the root port is on the host's own bus");
    assert_eq!(at(1).parent, Some(at(0).bdf));
    assert_eq!(at(2).parent, Some(at(1).bdf));
    assert_eq!(at(3).parent, Some(at(2).bdf));
}

#[test]
fn a_bridges_subordinate_covers_every_bus_below_it() {
    let mut fabric = switch_fabric();
    let mut out = [FUNCTION_BLANK; 8];
    enumerate(&FABRIC_HOST, &mut fabric, FABRIC_WINDOW, &mut out).expect("walk");

    // The root port reaches all the way down; each port below it covers less.
    assert_eq!(fabric.bus_numbers(0, 0), (0, 1, 3), "root port");
    assert_eq!(fabric.bus_numbers(1, 0), (1, 2, 3), "switch upstream");
    assert_eq!(fabric.bus_numbers(2, 0), (2, 3, 3), "switch downstream");
}

#[test]
fn siblings_do_not_claim_each_others_buses() {
    // Two root ports, each with an endpoint. The wide provisional subordinate
    // the descent needs must be narrowed afterwards, or the first port goes on
    // claiming every bus the host has — including the one the second port is
    // given, and two bridges claiming one bus is a fabric that decodes
    // ambiguously.
    let mut fabric = MockFabric::new();
    fabric.bridge(0, 0);
    fabric.bridge(0, 1);
    fabric.endpoint(1, 0, 0x1af4, 0x1042, 0x01_08_00);
    fabric.endpoint(2, 0, 0x1af4, 0x1041, 0x02_00_00);

    let mut out = [FUNCTION_BLANK; 8];
    let found = enumerate(&FABRIC_HOST, &mut fabric, FABRIC_WINDOW, &mut out).expect("walk");
    assert_eq!(found, 4, "both ports and both endpoints");

    let (_, first_secondary, first_subordinate) = fabric.bus_numbers(0, 0);
    let (_, second_secondary, _) = fabric.bus_numbers(0, 1);
    assert_eq!((first_secondary, first_subordinate), (1, 1));
    assert_eq!(second_secondary, 2);
    assert!(
        first_subordinate < second_secondary,
        "the first port claims {first_secondary}..={first_subordinate}, \
         which must end before the second's bus {second_secondary}"
    );
}

#[test]
fn a_bar_below_a_switch_is_placed_inside_every_window_above_it() {
    let mut fabric = switch_fabric();
    let mut out = [FUNCTION_BLANK; 8];
    let found = enumerate(&FABRIC_HOST, &mut fabric, FABRIC_WINDOW, &mut out).expect("walk");
    let endpoint = out[..found]
        .iter()
        .find(|f| f.vendor == 0x1af4)
        .expect("the endpoint");
    let (bar, len) = endpoint.first_bar().expect("a placed BAR");

    // A bridge forwards a memory transaction only when the address falls in
    // its own window, so the endpoint's BAR has to lie inside the window of
    // every bridge between it and the host — not merely inside the host's.
    for bus in 0..3u8 {
        let words = &fabric.words[bus as usize][MockFabric::slot_of(0, 0)];
        let base_limit = words[(reg::MEMORY_BASE_LIMIT / 4) as usize];
        let base = u64::from((base_limit & 0xfff0) >> 4) << 20;
        let limit = (u64::from((base_limit >> 20) & 0xfff) << 20) | 0xf_ffff;
        assert!(
            bar >= base && bar + len - 1 <= limit,
            "BAR {bar:#x}..{:#x} is outside the window {base:#x}..={limit:#x} \
             forwarded by the bridge on bus {bus}",
            bar + len - 1
        );
    }
}
