// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::firmware`.

use super::*;

/// Points the loader at a container built by a test, behind anchors that
/// container measures to.
///
/// Lives here rather than beside the loader: it is a fixture, and a fixture in
/// a production module is a `cfg(test)` item a reader has to step over on the
/// way to the code that ships. `super` reaches the private store because a
/// `#[path]` test module is still a child of the module it tests.
pub(crate) fn set_test_store(
    region: &'static [u8],
    anchors: &'static [tessera_image_store::Anchor],
) {
    *super::SYSTEM_STORE.lock() = super::Source { region, anchors };
}

/// The floor is above zero. A floor of zero is a system that has retired
/// nothing, which is a legitimate state and *not* this one — and it is a
/// state reachable by deleting a digit, with no test failing.
#[test]
fn the_floor_retires_something() {
    const { assert!(ROLLBACK_FLOOR > 0) };
    assert_eq!(POLICY.rollback_floor, ROLLBACK_FLOOR);
}

/// A policy refusal and a missing image report different kernel errors and
/// different refusal values. Collapsing either pair would make a caller
/// unable to tell "the system retired this version" from "there is no such
/// image", which are opposite situations.
#[test]
fn the_two_kinds_of_refusal_stay_apart() {
    let refused = Image {
        svn: 2,
        image_version: 3,
    };
    let policy = LoadError::Policy(Refusal::RollbackBlocked, refused);
    let missing = LoadError::Store(StoreError::NotFound);
    assert_eq!(policy.code(), KError::PolicyRefused);
    assert_eq!(missing.code(), KError::InvalidArgument);
    assert_eq!(policy.refusal(), FirmwareRefusal::RollbackBlocked);
    assert_eq!(missing.refusal(), FirmwareRefusal::None);
    // The refused version travels with the refusal: a rollback that would
    // not say what it refused could not be checked against any floor.
    assert_eq!(policy.image(), Some(refused));
    assert_eq!(missing.image(), None);
}

/// Both policy refusals survive the trip to the wire distinctly.
#[test]
fn both_policy_refusals_reach_the_wire() {
    let blank = Image {
        svn: 0,
        image_version: 0,
    };
    assert_eq!(
        LoadError::Policy(Refusal::VersionTooOld, blank).refusal(),
        FirmwareRefusal::VersionTooOld
    );
    assert_ne!(
        LoadError::Policy(Refusal::VersionTooOld, blank).refusal(),
        LoadError::Policy(Refusal::RollbackBlocked, blank).refusal()
    );
}
