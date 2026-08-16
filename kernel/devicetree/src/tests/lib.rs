// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

// Property name offsets into `STRINGS` below. New names append at the end
// so existing offsets stay put.
const NAME_ADDRESS_CELLS: u32 = 0;
const NAME_SIZE_CELLS: u32 = 15;
const NAME_DEVICE_TYPE: u32 = 27;
const NAME_REG: u32 = 39;
const NAME_COMPATIBLE: u32 = 43;
const NAME_INTERRUPTS: u32 = 54;
const NAME_BUS_RANGE: u32 = 65;
const NAME_RANGES: u32 = 75;
const STRINGS: &[u8] =
    b"#address-cells\0#size-cells\0device_type\0reg\0compatible\0interrupts\0bus-range\0ranges\0";

/// Minimal big-endian blob writer, so the fixtures are the real wire
/// format rather than a mock of it.
struct Writer {
    buffer: [u8; 1024],
    len: usize,
}

impl Writer {
    fn new() -> Self {
        Self {
            buffer: [0; 1024],
            len: 0,
        }
    }

    fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.buffer[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        self
    }

    fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    fn pad4(&mut self) -> &mut Self {
        while !self.len.is_multiple_of(4) {
            self.len += 1;
        }
        self
    }

    fn begin_node(&mut self, name: &[u8]) -> &mut Self {
        self.u32(FDT_BEGIN_NODE).bytes(name).bytes(b"\0").pad4()
    }

    fn end_node(&mut self) -> &mut Self {
        self.u32(FDT_END_NODE)
    }

    fn prop(&mut self, name_at: u32, value: &[u8]) -> &mut Self {
        self.u32(FDT_PROP)
            .u32(value.len() as u32)
            .u32(name_at)
            .bytes(value)
            .pad4()
    }

    fn prop_u32(&mut self, name_at: u32, value: u32) -> &mut Self {
        self.prop(name_at, &value.to_be_bytes())
    }

    fn reg(&mut self, base: u64, len: u64) -> &mut Self {
        let mut value = [0u8; 16];
        value[..8].copy_from_slice(&base.to_be_bytes());
        value[8..].copy_from_slice(&len.to_be_bytes());
        self.prop(NAME_REG, &value)
    }

    fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

/// Assembles a complete blob around a structure block.
fn blob_from(structure: &[u8], reservations: &[(u64, u64)]) -> ([u8; 2048], usize) {
    let mut reservation_bytes = Writer::new();
    for &(base, len) in reservations {
        reservation_bytes.u64(base).u64(len);
    }
    reservation_bytes.u64(0).u64(0); // terminator

    let rsvmap_at = HEADER_LEN;
    let struct_at = rsvmap_at + reservation_bytes.len;
    let strings_at = struct_at + structure.len();
    let total = strings_at + STRINGS.len();

    let mut header = Writer::new();
    header
        .u32(MAGIC)
        .u32(total as u32)
        .u32(struct_at as u32)
        .u32(strings_at as u32)
        .u32(rsvmap_at as u32)
        .u32(SUPPORTED_VERSION)
        .u32(16) // last_comp_version
        .u32(0) // boot_cpuid_phys
        .u32(STRINGS.len() as u32)
        .u32(structure.len() as u32);

    let mut blob = [0u8; 2048];
    blob[..HEADER_LEN].copy_from_slice(header.as_slice());
    blob[rsvmap_at..struct_at].copy_from_slice(reservation_bytes.as_slice());
    blob[struct_at..strings_at].copy_from_slice(structure);
    blob[strings_at..total].copy_from_slice(STRINGS);
    (blob, total)
}

/// A tree shaped like the QEMU `virt` machine's: 2/2 cells at the root,
/// one RAM bank, and a `/reserved-memory` carve-out inside it.
fn virt_like() -> ([u8; 2048], usize) {
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"memory@40000000")
        .prop(NAME_DEVICE_TYPE, b"memory\0")
        .reg(0x4000_0000, 0x2000_0000)
        .end_node()
        .begin_node(b"reserved-memory")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"framebuffer@4fff0000")
        .reg(0x4fff_0000, 0x1_0000)
        .end_node()
        .end_node()
        .end_node()
        .u32(FDT_END);
    blob_from(structure.as_slice(), &[(0x4700_0000, 0x1000)])
}

fn empty_regions() -> [MemoryRegion; 8] {
    [MemoryRegion {
        base: PhysAddr::new(0),
        len: 0,
        kind: MemoryKind::Reserved,
    }; 8]
}

#[test]
fn a_virt_like_tree_yields_its_ram_bank_and_carve_out() {
    let (blob, total) = virt_like();
    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    assert_eq!(tree.len(), total);

    let mut regions = empty_regions();
    let found = tree.memory_regions(&mut regions).expect("readable tree");
    assert_eq!(found, 2);
    assert_eq!(
        (regions[0].base.as_u64(), regions[0].len, regions[0].kind),
        (0x4000_0000, 0x2000_0000, MemoryKind::Usable)
    );
    assert_eq!(
        (regions[1].base.as_u64(), regions[1].len, regions[1].kind),
        (0x4fff_0000, 0x1_0000, MemoryKind::Reserved)
    );
}

/// **"The real-time clock" has one answer and "the transports" does not.**
/// A bus controller enumerating a machine needs the second question, and a
/// walker that could only ask the first would describe a fraction of the
/// bus it just walked.
#[test]
fn every_device_of_a_compatible_is_found_and_a_short_buffer_says_so() {
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"virtio_mmio@a000000")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .reg(0x0a00_0000, 0x200)
        .end_node()
        .begin_node(b"pl061@9030000")
        .prop(NAME_COMPATIBLE, b"arm,pl061\0arm,primecell\0")
        .reg(0x0903_0000, 0x1000)
        .end_node()
        .begin_node(b"virtio_mmio@a000200")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .reg(0x0a00_0200, 0x200)
        .end_node()
        .begin_node(b"virtio_mmio@a000400")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .reg(0x0a00_0400, 0x200)
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);
    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");

    let mut out = [MmioDevice {
        base: 0,
        size: 0,
        intid: None,
        trigger: None,
    }; 4];
    assert_eq!(
        tree.mmio_devices(b"virtio,mmio", &mut out).expect("walk"),
        3,
    );
    assert_eq!(out[0].base, 0x0a00_0000);
    assert_eq!(out[1].base, 0x0a00_0200);
    assert_eq!(out[2].base, 0x0a00_0400);

    // The second compatible string of a list, not just its first: the
    // PL061 answers to `arm,primecell` as well as to its own name.
    assert_eq!(
        tree.mmio_devices(b"arm,primecell", &mut out).expect("walk"),
        1
    );
    assert_eq!(out[0].base, 0x0903_0000);
    assert_eq!(tree.mmio_devices(b"arm,pl011", &mut out).expect("walk"), 0);

    // **A buffer too small reports the number found, not the number it
    // held.** A count clamped to the buffer would make a machine with more
    // devices than room indistinguishable from a smaller machine, and the
    // caller would have nothing to report.
    let mut small = [MmioDevice {
        base: 0,
        size: 0,
        intid: None,
        trigger: None,
    }; 2];
    assert_eq!(
        tree.mmio_devices(b"virtio,mmio", &mut small).expect("walk"),
        3,
    );
    assert_eq!(small[0].base, 0x0a00_0000);
    assert_eq!(small[1].base, 0x0a00_0200);
}

#[test]
fn virtio_mmio_nodes_are_discovered_by_compatible() {
    // Two virtio-mmio transport slots (the `virt` layout: stride 0x200)
    // plus a non-virtio device that must not be reported. The compatible
    // value carries a second string to prove the list is scanned, not just
    // its first entry compared.
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"virtio_mmio@a000000")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .reg(0x0a00_0000, 0x200)
        .end_node()
        .begin_node(b"pl011@9000000")
        .prop(NAME_COMPATIBLE, b"arm,pl011\0arm,primecell\0")
        .reg(0x0900_0000, 0x1000)
        .end_node()
        .begin_node(b"virtio_mmio@a000200")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .reg(0x0a00_0200, 0x200)
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = [MmioDevice {
        base: 0,
        size: 0,
        intid: None,
        trigger: None,
    }; 8];
    let found = tree
        .virtio_mmio_regions(&mut regions)
        .expect("readable tree");
    assert_eq!(found, 2);
    assert_eq!(
        regions[0],
        MmioDevice {
            base: 0x0a00_0000,
            size: 0x200,
            intid: None,
            trigger: None,
        }
    );
    assert_eq!(
        regions[1],
        MmioDevice {
            base: 0x0a00_0200,
            size: 0x200,
            intid: None,
            trigger: None,
        }
    );
}

#[test]
fn a_single_interrupt_cell_is_the_controller_line_itself() {
    // The RISC-V `virt` layout: a PLIC has `#interrupt-cells = <1>`, so a
    // node's `interrupts` is the source number and nothing else — no type,
    // no flags, and no offset to add. Read as a GIC descriptor it would be
    // too short and yield None, which is what this port hit.
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"rtc@101000")
        .prop(NAME_COMPATIBLE, b"google,goldfish-rtc\0")
        .prop(NAME_INTERRUPTS, &[0, 0, 0, 11])
        .reg(0x0010_1000, 0x1000)
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let found = tree
        .first_mmio_device(b"google,goldfish-rtc")
        .expect("readable tree")
        .expect("the node is present");
    assert_eq!(
        found,
        MmioDevice {
            base: 0x0010_1000,
            size: 0x1000,
            // 11, not 43: a single cell carries no SPI base to add.
            intid: Some(11),
            // A one-cell PLIC value says nothing about how the line
            // signals, and this reports that rather than inventing a
            // default.
            trigger: None,
        }
    );
}

#[test]
fn a_device_this_crate_does_not_know_is_found_by_its_compatible() {
    // `first_mmio_device` is the generic form: it must match a string the
    // crate has no special handling for, scan past nodes that do not match,
    // and report nothing rather than something wrong when none does.
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"virtio_mmio@a000000")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .reg(0x0a00_0000, 0x200)
        .end_node()
        .begin_node(b"serial@10000000")
        .prop(NAME_COMPATIBLE, b"ns16550a\0ns16550\0")
        .reg(0x1000_0000, 0x100)
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    // Matched on the *second* entry of the compatible list, and after a
    // node that did not match.
    assert_eq!(
        tree.first_mmio_device(b"ns16550")
            .expect("readable tree")
            .expect("the node is present")
            .base,
        0x1000_0000
    );
    assert_eq!(
        tree.first_mmio_device(b"nothing,here")
            .expect("readable tree"),
        None
    );
}

#[test]
fn a_virtio_node_with_a_gic_spi_interrupt_reports_its_intid() {
    // The `virt` layout: `interrupts = <GIC_SPI n flags>` — three
    // big-endian cells; SPI 16 maps to GIC INTID 48. A second node with a
    // PPI-type descriptor (type 1) must yield None, not a wrong INTID.
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"virtio_mmio@a000000")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .prop(
            NAME_INTERRUPTS,
            &[0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 1], // <SPI 16 edge>
        )
        .reg(0x0a00_0000, 0x200)
        .end_node()
        .begin_node(b"virtio_mmio@a000200")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .prop(
            NAME_INTERRUPTS,
            &[0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 4], // <PPI 9 level>
        )
        .reg(0x0a00_0200, 0x200)
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = [MmioDevice {
        base: 0,
        size: 0,
        intid: None,
        trigger: None,
    }; 8];
    let found = tree
        .virtio_mmio_regions(&mut regions)
        .expect("readable tree");
    assert_eq!(found, 2);
    assert_eq!(regions[0].intid, Some(48));
    assert_eq!(regions[0].trigger, Some(IrqTrigger::Edge));
    assert_eq!(regions[1].intid, None);
    // No line, so nothing to say about how it signals.
    assert_eq!(regions[1].trigger, None);
}

/// A GIC descriptor's flags cell says how the line signals, and getting it
/// wrong is silent: a controller configured level-sensitive latches
/// nothing from an edge-triggered device, and the interrupt simply never
/// arrives with no error anywhere to say why.
#[test]
fn a_gic_descriptors_flags_cell_says_how_the_line_signals() {
    let read = |flags: u32| {
        let mut structure = Writer::new();
        let f = flags.to_be_bytes();
        structure
            .begin_node(b"")
            .prop_u32(NAME_ADDRESS_CELLS, 2)
            .prop_u32(NAME_SIZE_CELLS, 2)
            .begin_node(b"virtio_mmio@a000000")
            .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
            .prop(
                NAME_INTERRUPTS,
                &[0, 0, 0, 0, 0, 0, 0, 16, f[0], f[1], f[2], f[3]],
            )
            .reg(0x0a00_0000, 0x200)
            .end_node()
            .end_node()
            .u32(FDT_END);
        let (blob, total) = blob_from(structure.as_slice(), &[]);
        let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
        let mut regions = [MmioDevice {
            base: 0,
            size: 0,
            intid: None,
            trigger: None,
        }; 2];
        assert_eq!(
            tree.virtio_mmio_regions(&mut regions)
                .expect("readable tree"),
            1
        );
        regions[0].trigger
    };
    // Rising and falling edge; high and low level.
    assert_eq!(read(1), Some(IrqTrigger::Edge));
    assert_eq!(read(2), Some(IrqTrigger::Edge));
    assert_eq!(read(4), Some(IrqTrigger::Level));
    assert_eq!(read(8), Some(IrqTrigger::Level));
    // Nothing said, and something contradictory said, are both reported as
    // "this reader does not know" rather than as a default it invented.
    assert_eq!(read(0), None);
    assert_eq!(read(5), None);
    // Bits above the sense nibble are not part of the answer.
    assert_eq!(read(0xff0 | 1), Some(IrqTrigger::Edge));
}

#[test]
fn the_reservation_block_is_read_up_to_its_terminator() {
    let (blob, total) = virt_like();
    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");

    let mut regions = empty_regions();
    let found = tree.reserved_regions(&mut regions).expect("readable block");
    assert_eq!(found, 1);
    assert_eq!(
        (regions[0].base.as_u64(), regions[0].len, regions[0].kind),
        (0x4700_0000, 0x1000, MemoryKind::Reserved)
    );
}

#[test]
fn the_reserved_memory_node_itself_is_not_a_region() {
    // `/reserved-memory` may carry its own `reg`; only its children
    // describe actual carve-outs.
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"reserved-memory")
        .reg(0x1000, 0x1000)
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = empty_regions();
    assert_eq!(tree.memory_regions(&mut regions), Ok(0));
}

#[test]
fn reg_is_read_with_the_parents_cell_counts() {
    // Root declares 1/1, so each `reg` cell pair is 32-bit.
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 1)
        .prop_u32(NAME_SIZE_CELLS, 1)
        .begin_node(b"memory@80000000")
        .prop(NAME_DEVICE_TYPE, b"memory\0")
        .prop(NAME_REG, &[0x80, 0, 0, 0, 0x10, 0, 0, 0])
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = empty_regions();
    assert_eq!(tree.memory_regions(&mut regions), Ok(1));
    assert_eq!(
        (regions[0].base.as_u64(), regions[0].len),
        (0x8000_0000, 0x1000_0000)
    );
}

#[test]
fn multiple_banks_in_one_reg_are_all_reported() {
    let mut value = [0u8; 32];
    value[..8].copy_from_slice(&0x4000_0000u64.to_be_bytes());
    value[8..16].copy_from_slice(&0x1000_0000u64.to_be_bytes());
    value[16..24].copy_from_slice(&0x8000_0000u64.to_be_bytes());
    value[24..].copy_from_slice(&0x1000_0000u64.to_be_bytes());

    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"memory@40000000")
        .prop(NAME_DEVICE_TYPE, b"memory\0")
        .prop(NAME_REG, &value)
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = empty_regions();
    assert_eq!(tree.memory_regions(&mut regions), Ok(2));
    assert_eq!(regions[1].base.as_u64(), 0x8000_0000);
}

#[test]
fn properties_may_precede_the_device_type_that_qualifies_them() {
    // `reg` before `device_type` must still be recognized — the reason
    // the walk defers interpretation to the node's close.
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"memory@40000000")
        .reg(0x4000_0000, 0x1000)
        .prop(NAME_DEVICE_TYPE, b"memory\0")
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = empty_regions();
    assert_eq!(tree.memory_regions(&mut regions), Ok(1));
}

#[test]
fn a_bad_magic_is_rejected_before_anything_else_is_read() {
    let (mut blob, total) = virt_like();
    blob[0] ^= 0xff;
    assert_eq!(
        DeviceTree::parse(&blob[..total]).err(),
        Some(FdtError::BadMagic)
    );
}

#[test]
fn a_future_structure_version_is_rejected() {
    let (mut blob, total) = virt_like();
    blob[OFF_LAST_COMP_VERSION..OFF_LAST_COMP_VERSION + 4]
        .copy_from_slice(&(SUPPORTED_VERSION + 1).to_be_bytes());
    assert_eq!(
        DeviceTree::parse(&blob[..total]).err(),
        Some(FdtError::UnsupportedVersion)
    );
}

#[test]
fn a_blob_shorter_than_its_own_totalsize_is_truncated() {
    let (blob, total) = virt_like();
    assert_eq!(
        DeviceTree::parse(&blob[..total - 1]).err(),
        Some(FdtError::Truncated)
    );
}

#[test]
fn an_output_slice_too_small_reports_rather_than_truncating() {
    let (blob, total) = virt_like();
    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = [MemoryRegion {
        base: PhysAddr::new(0),
        len: 0,
        kind: MemoryKind::Reserved,
    }; 1];
    assert_eq!(
        tree.memory_regions(&mut regions),
        Err(FdtError::TooManyRegions)
    );
}

#[test]
fn a_reg_needing_more_than_64_bits_is_refused_not_silently_narrowed() {
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 3)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"memory@0")
        .prop(NAME_DEVICE_TYPE, b"memory\0")
        .prop(NAME_REG, &[0u8; 20])
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = empty_regions();
    assert_eq!(
        tree.memory_regions(&mut regions),
        Err(FdtError::UnsupportedCellCount)
    );
}

#[test]
fn an_unterminated_node_is_malformed() {
    let mut structure = Writer::new();
    structure.begin_node(b"").u32(FDT_END); // never closed
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = empty_regions();
    assert_eq!(tree.memory_regions(&mut regions), Err(FdtError::Malformed));
}

#[test]
fn an_unknown_token_is_malformed() {
    let mut structure = Writer::new();
    structure.u32(0xdead);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = empty_regions();
    assert_eq!(tree.memory_regions(&mut regions), Err(FdtError::Malformed));
}

#[test]
fn nesting_past_the_depth_bound_is_malformed() {
    let mut structure = Writer::new();
    for _ in 0..=MAX_DEPTH {
        structure.begin_node(b"n");
    }
    structure.u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let mut regions = empty_regions();
    assert_eq!(tree.memory_regions(&mut regions), Err(FdtError::Malformed));
}

#[test]
fn the_reader_never_panics_on_arbitrary_input() {
    // A seeded LCG producing both random soup and single-byte mutations
    // of a valid blob; every path must return an error, never panic
    // (docs/lifecycle/04, fuzz target for parsers of external input; a
    // libfuzzer target is deferred, D12).
    let (valid, total) = virt_like();
    let mut state: u64 = 0x0f1e_2d3c_4b5a_6978;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state >> 33
    };

    let mut regions = empty_regions();
    for round in 0..20_000u32 {
        let mut blob = valid;
        let len = if round % 2 == 0 {
            // Mutate a valid blob: keeps the walk reaching deep code.
            for _ in 0..1 + next() % 4 {
                let at = (next() as usize) % total;
                blob[at] ^= (next() as u8) | 1;
            }
            total
        } else {
            // Arbitrary bytes, arbitrary length.
            let len = (next() as usize) % blob.len();
            for byte in blob.iter_mut().take(len) {
                *byte = next() as u8;
            }
            len
        };

        let _ = total_size(&blob[..len.min(HEADER_LEN)]);
        if let Ok(tree) = DeviceTree::parse(&blob[..len]) {
            let _ = tree.memory_regions(&mut regions);
            let _ = tree.reserved_regions(&mut regions);
            // The PCI accessor reads the same untrusted blob and must be
            // as unwilling to panic on it as the rest.
            let _ = tree.pci_host();
        }
    }
}

/// A `ranges` entry, as the specification lays it out: 3 child cells
/// (flags, then a 64-bit PCI address), 2 parent cells (the CPU address),
/// 2 size cells.
fn pci_range(flags: u32, bus: u64, cpu: u64, len: u64) -> [u8; 28] {
    let mut out = [0u8; 28];
    out[0..4].copy_from_slice(&flags.to_be_bytes());
    out[4..12].copy_from_slice(&bus.to_be_bytes());
    out[12..20].copy_from_slice(&cpu.to_be_bytes());
    out[20..28].copy_from_slice(&len.to_be_bytes());
    out
}

/// The RISC-V `virt` layout: ECAM at 0x3000_0000, buses 0..=255, and a
/// 32-bit memory window at 0x4000_0000.
fn pci_tree(ranges: &[u8], bus_range: Option<[u8; 8]>) -> ([u8; 2048], usize) {
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"pci@30000000")
        .prop(NAME_COMPATIBLE, b"pci-host-ecam-generic\0");
    if let Some(value) = bus_range {
        structure.prop(NAME_BUS_RANGE, &value);
    }
    structure
        .prop(NAME_RANGES, ranges)
        .reg(0x3000_0000, 0x1000_0000)
        .end_node()
        .end_node()
        .u32(FDT_END);
    blob_from(structure.as_slice(), &[])
}

#[test]
fn a_pci_host_bridge_reports_its_ecam_window_and_bus_range() {
    let ranges = pci_range(0x0200_0000, 0x4000_0000, 0x4000_0000, 0x1000_0000);
    let mut bus_range = [0u8; 8];
    bus_range[3] = 0;
    bus_range[7] = 255;
    let (blob, total) = pci_tree(&ranges, Some(bus_range));

    let tree = DeviceTree::parse(&blob[..total]).expect("well-formed blob");
    let host = tree.pci_host().expect("readable").expect("a host bridge");
    assert_eq!(host.ecam_base, 0x3000_0000);
    assert_eq!(host.ecam_len, 0x1000_0000);
    assert_eq!(host.first_bus, 0);
    assert_eq!(host.last_bus, 255);
    assert_eq!(
        host.memory,
        Some(PciWindow {
            cpu_base: 0x4000_0000,
            bus_base: 0x4000_0000,
            len: 0x1000_0000,
        })
    );
}

/// A bridge whose window starts above bus 0 — the case that makes ECAM
/// offsets relative rather than absolute.
#[test]
fn a_bus_range_that_does_not_start_at_zero_is_reported_as_given() {
    let ranges = pci_range(0x0200_0000, 0x4000_0000, 0x4000_0000, 0x1000_0000);
    let mut bus_range = [0u8; 8];
    bus_range[3] = 4;
    bus_range[7] = 8;
    let (blob, total) = pci_tree(&ranges, Some(bus_range));
    let host = DeviceTree::parse(&blob[..total])
        .expect("blob")
        .pci_host()
        .expect("readable")
        .expect("a host bridge");
    assert_eq!((host.first_bus, host.last_bus), (4, 8));
}

/// I/O and prefetchable windows are a different transport and a different
/// use; reporting one as the memory window would place a register block
/// somewhere the bridge does not forward it the same way.
#[test]
fn only_the_non_prefetchable_32_bit_memory_window_is_reported() {
    let mut ranges = [0u8; 28 * 3];
    // I/O space.
    ranges[..28].copy_from_slice(&pci_range(0x0100_0000, 0, 0x3000_0000, 0x1_0000));
    // 32-bit memory, but prefetchable (bit 30).
    ranges[28..56].copy_from_slice(&pci_range(
        0x4200_0000,
        0x8000_0000,
        0x8000_0000,
        0x1000_0000,
    ));
    // 32-bit memory, non-prefetchable — the one that must be picked.
    ranges[56..].copy_from_slice(&pci_range(
        0x0200_0000,
        0x4000_0000,
        0x4000_0000,
        0x1000_0000,
    ));
    let (blob, total) = pci_tree(&ranges, None);
    let host = DeviceTree::parse(&blob[..total])
        .expect("blob")
        .pci_host()
        .expect("readable")
        .expect("a host bridge");
    assert_eq!(host.memory.expect("a memory window").cpu_base, 0x4000_0000);
}

/// The CPU and bus addresses are separate cells and are not assumed equal.
#[test]
fn a_window_whose_bus_and_cpu_addresses_differ_keeps_both() {
    let ranges = pci_range(0x0200_0000, 0x1000_0000, 0x4000_0000, 0x1000_0000);
    let (blob, total) = pci_tree(&ranges, None);
    let window = DeviceTree::parse(&blob[..total])
        .expect("blob")
        .pci_host()
        .expect("readable")
        .expect("a host bridge")
        .memory
        .expect("a memory window");
    assert_eq!(window.bus_base, 0x1000_0000);
    assert_eq!(window.cpu_base, 0x4000_0000);
}

/// A `ranges` that is not a whole number of entries is malformed input,
/// not something to read as far as it goes.
#[test]
fn a_partial_ranges_entry_is_refused() {
    let ranges = [0u8; 20];
    let (blob, total) = pci_tree(&ranges, None);
    assert_eq!(
        DeviceTree::parse(&blob[..total]).expect("blob").pci_host(),
        Err(FdtError::Malformed)
    );
}

#[test]
fn a_machine_with_no_pci_host_bridge_reports_none() {
    let mut structure = Writer::new();
    structure
        .begin_node(b"")
        .prop_u32(NAME_ADDRESS_CELLS, 2)
        .prop_u32(NAME_SIZE_CELLS, 2)
        .begin_node(b"virtio_mmio@10001000")
        .prop(NAME_COMPATIBLE, b"virtio,mmio\0")
        .reg(0x1000_1000, 0x200)
        .end_node()
        .end_node()
        .u32(FDT_END);
    let (blob, total) = blob_from(structure.as_slice(), &[]);
    assert_eq!(
        DeviceTree::parse(&blob[..total])
            .expect("blob")
            .pci_host()
            .expect("readable"),
        None
    );
}
