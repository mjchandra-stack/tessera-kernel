// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::rights`.

use super::*;

#[test]
fn core_bit_values_are_stable_abi() {
    // These values are ABI; the ISL `bits Rights` schema mirrors them.
    assert_eq!(Rights::READ.bits(), 0x1);
    assert_eq!(Rights::WRITE.bits(), 0x2);
    assert_eq!(Rights::MAP.bits(), 0x4);
    assert_eq!(Rights::EXECUTE.bits(), 0x8);
    assert_eq!(Rights::DUPLICATE.bits(), 0x40);
    assert_eq!(Rights::TRANSFER.bits(), 0x80);
    assert_eq!(Rights::ADMIN.bits(), 0x400);
    assert_eq!(Rights::all_core().bits(), 0x7ff);
    assert_eq!(Rights::KILL.bits(), 1 << 21);
    assert_eq!(Rights::REVOKE.bits(), 1 << 33);
    assert_eq!(Rights::WAKE.bits(), 1 << 36);
    assert_eq!(Rights::SLEEP.bits(), 1 << 37);
}

/// The bits that mean different things must not be the same bit. Written
/// as a scan rather than as pairs, so a right added at a position already
/// taken is caught by the test that exists rather than by one nobody
/// remembered to extend.
#[test]
fn no_two_rights_share_a_bit() {
    const ALL: [(&str, Rights); 25] = [
        ("READ", Rights::READ),
        ("WRITE", Rights::WRITE),
        ("MAP", Rights::MAP),
        ("EXECUTE", Rights::EXECUTE),
        ("SIGNAL", Rights::SIGNAL),
        ("WAIT", Rights::WAIT),
        ("DUPLICATE", Rights::DUPLICATE),
        ("TRANSFER", Rights::TRANSFER),
        ("CONFIGURE", Rights::CONFIGURE),
        ("BIND", Rights::BIND),
        ("ADMIN", Rights::ADMIN),
        ("CREATE_PROCESS", Rights::CREATE_PROCESS),
        ("CREATE_JOB", Rights::CREATE_JOB),
        ("SET_POLICY", Rights::SET_POLICY),
        ("SET_LIMITS", Rights::SET_LIMITS),
        ("SUSPEND", Rights::SUSPEND),
        ("KILL", Rights::KILL),
        ("SUPPLY", Rights::SUPPLY),
        ("WRITEBACK", Rights::WRITEBACK),
        ("EVICT", Rights::EVICT),
        ("EXCEPTION", Rights::EXCEPTION),
        ("READ_STATE", Rights::READ_STATE),
        ("WRITE_STATE", Rights::WRITE_STATE),
        ("DERIVE", Rights::DERIVE),
        ("REVOKE", Rights::REVOKE),
    ];
    let mut seen = 0u64;
    for (name, right) in ALL {
        assert_eq!(right.bits().count_ones(), 1, "{name} is not one bit");
        assert_eq!(seen & right.bits(), 0, "{name} reuses a bit");
        seen |= right.bits();
    }
    // The power rights last and by hand, because the array above is 25
    // long and the point of the scan is that adding a right means adding
    // it here too.
    assert_eq!(seen & Rights::WAKE.bits(), 0, "WAKE reuses a bit");
    seen |= Rights::WAKE.bits();
    assert_eq!(seen & Rights::SLEEP.bits(), 0, "SLEEP reuses a bit");
}

#[test]
fn subset_and_reduction() {
    let rw = Rights::READ | Rights::WRITE;
    assert!(Rights::READ.is_subset_of(rw));
    assert!(rw.contains(Rights::READ));
    assert!(!Rights::READ.contains(rw));
    // Reduction to a subset is allowed.
    let reduced = rw.intersection(Rights::READ);
    assert_eq!(reduced, Rights::READ);
    assert!(reduced.is_subset_of(rw));
}

#[test]
fn expansion_is_detectable() {
    let ro = Rights::READ;
    let rw = Rights::READ | Rights::WRITE;
    // Asking for WRITE that `ro` does not have is not a subset — an
    // expansion, which the handle ops must reject.
    assert!(!rw.is_subset_of(ro));
}

#[test]
fn empty_and_union() {
    assert!(Rights::none().is_empty());
    assert!(Rights::none().is_subset_of(Rights::all_core()));
    assert_eq!(
        (Rights::READ | Rights::WRITE).bits(),
        Rights::READ.bits() | Rights::WRITE.bits()
    );
}
