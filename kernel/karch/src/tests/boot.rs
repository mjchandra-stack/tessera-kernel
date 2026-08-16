// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `karch::boot`.

use super::*;

fn region(base: u64, len: u64, kind: MemoryKind) -> MemoryRegion {
    MemoryRegion {
        base: PhysAddr::new(base),
        len,
        kind,
    }
}

/// Runs the normalizer with generously sized scratch and output.
fn normalize(input: &[MemoryRegion]) -> Result<[MemoryRegion; 16], KError> {
    let mut edges = [0u64; 64];
    let mut out = [region(0, 0, MemoryKind::Reserved); 16];
    let filled = normalize_memory_map(input, &mut edges, &mut out)?;
    // Every test below asserts on a prefix; blank the tail so a stale
    // entry cannot be mistaken for a produced one.
    for slot in out.iter_mut().skip(filled) {
        *slot = region(0, 0, MemoryKind::Reserved);
    }
    Ok(out)
}

#[test]
fn unsorted_input_comes_back_sorted() {
    let out = normalize(&[
        region(0x3000, 0x1000, MemoryKind::Reserved),
        region(0x1000, 0x1000, MemoryKind::Usable),
    ])
    .expect("well-formed map");

    assert_eq!(out[0].base.as_u64(), 0x1000);
    assert_eq!(out[1].base.as_u64(), 0x3000);
    // The gap between them is a hole, not an invented region.
    assert_eq!(out[2].len, 0);
}

#[test]
fn the_kernel_image_is_carved_out_of_the_ram_bank_around_it() {
    // The case that matters: firmware says the whole bank is RAM, and
    // the kernel is sitting in the middle of it.
    let out = normalize(&[
        region(0x4000_0000, 0x2000_0000, MemoryKind::Usable),
        region(0x4008_0000, 0x2_0000, MemoryKind::KernelAndModules),
    ])
    .expect("well-formed map");

    assert_eq!(
        (out[0].base.as_u64(), out[0].len, out[0].kind),
        (0x4000_0000, 0x8_0000, MemoryKind::Usable)
    );
    assert_eq!(
        (out[1].base.as_u64(), out[1].len, out[1].kind),
        (0x4008_0000, 0x2_0000, MemoryKind::KernelAndModules)
    );
    assert_eq!(
        (out[2].base.as_u64(), out[2].len, out[2].kind),
        (0x400a_0000, 0x1ff6_0000, MemoryKind::Usable)
    );
    assert_eq!(out[3].len, 0);

    // The whole bank is still covered exactly once.
    let total: u64 = out.iter().map(|r| r.len).sum();
    assert_eq!(total, 0x2000_0000);
}

#[test]
fn a_carve_out_at_the_very_start_leaves_no_empty_region() {
    let out = normalize(&[
        region(0x4000_0000, 0x1000_0000, MemoryKind::Usable),
        region(0x4000_0000, 0x1000, MemoryKind::Reserved),
    ])
    .expect("well-formed map");

    assert_eq!(
        (out[0].base.as_u64(), out[0].kind),
        (0x4000_0000, MemoryKind::Reserved)
    );
    assert_eq!(out[0].len, 0x1000);
    assert_eq!(
        (out[1].base.as_u64(), out[1].kind),
        (0x4000_1000, MemoryKind::Usable)
    );
    assert_eq!(out[2].len, 0);
}

#[test]
fn adjacent_regions_of_one_kind_coalesce() {
    let out = normalize(&[
        region(0x1000, 0x1000, MemoryKind::Usable),
        region(0x2000, 0x1000, MemoryKind::Usable),
        region(0x3000, 0x1000, MemoryKind::Usable),
    ])
    .expect("well-formed map");

    assert_eq!((out[0].base.as_u64(), out[0].len), (0x1000, 0x3000));
    assert_eq!(out[1].len, 0);
}

#[test]
fn overlapping_reservations_resolve_to_the_stronger_kind() {
    let out = normalize(&[
        region(0x1000, 0x3000, MemoryKind::BootloaderReclaimable),
        region(0x2000, 0x1000, MemoryKind::Bad),
    ])
    .expect("well-formed map");

    assert_eq!(out[1].kind, MemoryKind::Bad);
    assert_eq!((out[1].base.as_u64(), out[1].len), (0x2000, 0x1000));
}

#[test]
fn zero_length_regions_are_dropped() {
    let out = normalize(&[
        region(0x1000, 0, MemoryKind::Usable),
        region(0x2000, 0x1000, MemoryKind::Usable),
    ])
    .expect("well-formed map");

    assert_eq!((out[0].base.as_u64(), out[0].len), (0x2000, 0x1000));
    assert_eq!(out[1].len, 0);
}

#[test]
fn a_region_wrapping_the_address_space_is_rejected() {
    let input = [region(u64::MAX - 0xfff, 0x2000, MemoryKind::Usable)];
    let mut edges = [0u64; 8];
    let mut out = [region(0, 0, MemoryKind::Reserved); 8];
    assert_eq!(
        normalize_memory_map(&input, &mut edges, &mut out),
        Err(KError::InvalidMapping)
    );
}

#[test]
fn undersized_buffers_report_rather_than_truncate() {
    let input = [
        region(0x1000, 0x1000, MemoryKind::Usable),
        region(0x3000, 0x1000, MemoryKind::Reserved),
    ];

    let mut small_edges = [0u64; 2];
    let mut out = [region(0, 0, MemoryKind::Reserved); 8];
    assert_eq!(
        normalize_memory_map(&input, &mut small_edges, &mut out),
        Err(KError::LimitExceeded)
    );

    let mut edges = [0u64; 8];
    let mut small_out = [region(0, 0, MemoryKind::Reserved); 1];
    assert_eq!(
        normalize_memory_map(&input, &mut edges, &mut small_out),
        Err(KError::LimitExceeded)
    );
}

#[test]
fn an_empty_map_normalizes_to_nothing() {
    let mut edges = [0u64; 4];
    let mut out = [region(0, 0, MemoryKind::Reserved); 4];
    assert_eq!(normalize_memory_map(&[], &mut edges, &mut out), Ok(0));
}
