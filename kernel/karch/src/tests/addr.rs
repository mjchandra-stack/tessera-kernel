// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `karch::addr`.

use super::*;

#[test]
fn align_math() {
    let a = PhysAddr::new(0x1234);
    assert_eq!(a.align_down(0x1000).as_u64(), 0x1000);
    assert_eq!(a.align_up(0x1000).map(PhysAddr::as_u64), Some(0x2000));
    assert!(PhysAddr::new(0x2000).is_aligned(0x1000));
    assert!(!a.is_aligned(0x1000));
    // Already-aligned addresses stay put on align_up.
    assert_eq!(
        PhysAddr::new(0x2000).align_up(0x1000).map(PhysAddr::as_u64),
        Some(0x2000)
    );
}

#[test]
fn align_up_overflow_is_none() {
    assert_eq!(PhysAddr::new(u64::MAX).align_up(0x1000), None);
    assert_eq!(VirtAddr::new(u64::MAX).checked_add(1), None);
}

#[test]
fn frames() {
    assert_eq!(PhysFrame::from_base(PhysAddr::new(0x1234)), None);
    let f = PhysFrame::containing(PhysAddr::new(0x1234));
    assert_eq!(f.base().as_u64(), 0x1000);
    assert_eq!(f.number(), 1);
    assert_eq!(
        PhysFrame::from_number(2).map(|f| f.base().as_u64()),
        Some(0x2000)
    );
    assert_eq!(PhysFrame::from_number(u64::MAX), None);
}
