// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

const PLAIN: Declared = Declared {
    configure: false,
    derive: false,
    domain: 1,
};

fn held(object: u32, rights: u64) -> Held {
    Held { object, rights }
}

#[test]
fn a_driver_holding_its_baseline_is_compliant() {
    let verdict = check(
        &PLAIN,
        &[
            held(1, right::READ | right::MAP | right::TRANSFER),
            held(2, right::WRITE),
        ],
    );
    assert!(verdict.is_compliant(), "{verdict:?}");
    assert_eq!(verdict.undeclared, 0);
    assert_eq!(verdict.examined, 2);
}

/// **The failure this exists for.** Nothing errored, nothing was refused,
/// and the driver can reach configuration space its manifest said it could
/// not.
#[test]
fn a_right_the_manifest_never_granted_is_caught() {
    let verdict = check(
        &PLAIN,
        &[
            held(1, right::READ | right::MAP),
            held(2, right::READ | right::CONFIGURE),
        ],
    );
    assert!(!verdict.is_compliant());
    assert_eq!(verdict.undeclared, right::CONFIGURE);
    assert_eq!(verdict.offending_object, 2, "which capability carried it");
}

/// The same bit, declared, is fine — which is what makes the check a policy
/// comparison rather than a blanket ban.
#[test]
fn the_same_right_is_fine_when_the_manifest_granted_it() {
    let allowed = Declared {
        configure: true,
        ..PLAIN
    };
    let verdict = check(&allowed, &[held(2, right::READ | right::CONFIGURE)]);
    assert!(verdict.is_compliant());
}

/// A right outside the catalog entirely — a bit nobody declared anywhere —
/// is undeclared like any other, which is why this crate holds rights as a
/// plain `u64`.
#[test]
fn a_right_no_catalog_defines_is_still_undeclared() {
    let verdict = check(&PLAIN, &[held(3, 1 << 55)]);
    assert!(!verdict.is_compliant());
    assert_eq!(verdict.undeclared, 1 << 55);
}

/// **Authority over something other than this driver's own device** is
/// never baseline, however ordinary it looks next to the rights that are.
#[test]
fn the_rights_that_reach_past_a_driver_are_not_baseline() {
    for (name, bit) in [
        ("ADMIN", right::ADMIN),
        ("REVOKE", right::REVOKE),
        ("FIRMWARE", right::FIRMWARE),
        ("WAKE", right::WAKE),
        ("PROTECTED_DMA", right::PROTECTED_DMA),
    ] {
        assert_eq!(BASELINE & bit, 0, "{name} is in the baseline");
        let verdict = check(&PLAIN, &[held(1, bit)]);
        assert!(!verdict.is_compliant(), "{name} passed as ordinary");
    }
}

/// A process holding nothing satisfies a subset test and has shown nothing.
#[test]
fn a_driver_holding_no_capabilities_proves_nothing() {
    let verdict = check(&PLAIN, &[]);
    assert_eq!(verdict.undeclared, 0, "nothing was over-granted");
    assert!(!verdict.is_compliant(), "and nothing was examined");
}

/// Holding less than the allowance is fine, and worth reporting.
#[test]
fn taking_less_than_the_allowance_is_compliant_and_visible() {
    let generous = Declared {
        configure: true,
        derive: true,
        ..PLAIN
    };
    let verdict = check(&generous, &[held(1, right::READ)]);
    assert!(verdict.is_compliant());
    assert!(
        !verdict.used_its_whole_allowance(&generous),
        "a manifest allowing far more than anyone holds is worth revisiting",
    );
}
