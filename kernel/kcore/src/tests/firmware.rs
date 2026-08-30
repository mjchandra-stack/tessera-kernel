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

// --- The store a component hands over (D291) -----------------------------

/// Resets the one-shot latch, so a second test can install again.
///
/// There is no such thing at run time — that is the whole point of the latch —
/// and a test that could not reset it could only ever check the first call.
fn forget_installed() {
    *super::INSTALLED.lock() = false;
    super::SYSTEM_STORE.lock().region = &[];
}

/// The container `//store` builds, near enough: two blobs and a real anchor.
///
/// Anchored on its own measurement, because what these tests are about is the
/// *install* path — whether a caller's bytes are copied, checked and latched —
/// and not the arithmetic `api/image-store` already proves.
fn deliverable(buffer: &mut [u8]) -> usize {
    let entries = [tessera_image_store::BuildEntry {
        name: "firmware.bin",
        svn: 7,
        image_version: 3,
        flags: 0,
        bytes: &[0x11; 64],
    }];
    tessera_image_store::build_into(
        buffer,
        crate::store::SYSTEM_STORE_ANCHOR_ID,
        &entries,
        false,
    )
    .map(|built| built.len)
    .unwrap_or_default()
}

/// **A store this kernel does not vouch for is refused, and nothing is
/// installed.**
///
/// The container is well-formed and measures perfectly to an anchor nobody
/// holds — which is the case that matters, because a malformed one would be
/// refused by the parser and prove nothing about the anchor check.
#[test]
fn a_store_the_anchors_do_not_cover_is_refused() {
    forget_installed();
    let mut buffer = [0u8; 512];
    let len = deliverable(&mut buffer);
    assert!(len > 0);
    assert_eq!(
        super::install_system_store(&buffer[..len]),
        Err(KError::AccessDenied),
    );
    assert!(
        super::system_store().is_empty(),
        "a refused store must leave nothing installed",
    );
}

/// **Installed once.** A second call is refused whether or not it would
/// verify: a root of trust that can be replaced while the system runs is one
/// whose replacement is the attack.
#[test]
fn a_second_install_is_refused() {
    forget_installed();
    // The container this build actually signs is not reachable from a unit
    // test, so the latch is exercised by installing an empty-but-latched state
    // directly: what is under test is the latch, not the verification beside
    // it.
    *super::INSTALLED.lock() = true;
    let mut buffer = [0u8; 512];
    let len = deliverable(&mut buffer);
    assert_eq!(
        super::install_system_store(&buffer[..len]),
        Err(KError::AlreadyMapped),
    );
}

/// A container larger than the kernel's buffer is refused rather than
/// truncated: half a store measures to nothing, and the refusal says which of
/// the two problems it is.
#[test]
fn an_oversized_store_is_refused() {
    forget_installed();
    let oversized = [0u8; super::MAX_DELIVERED_STORE + 1];
    assert_eq!(
        super::install_system_store(&oversized),
        Err(KError::InvalidArgument),
    );
    assert_eq!(
        super::install_system_store(&[]),
        Err(KError::InvalidArgument)
    );
}

/// **The positive path, and the copy is what it proves.**
///
/// The container is installed, and then the caller's buffer is scribbled on:
/// what `system_store()` returns is unchanged, because the kernel kept a copy.
/// A store read through the caller's memory would follow the scribble, which
/// is the validate-then-use race this copy exists to close.
#[test]
fn an_installed_store_is_the_kernels_own_copy() {
    forget_installed();
    let mut buffer = [0u8; 512];
    let len = deliverable(&mut buffer);
    assert!(len > 0);
    let anchors = [tessera_image_store::Anchor {
        id: crate::store::SYSTEM_STORE_ANCHOR_ID,
        trust: tessera_image_store::Trust::Digest(
            tessera_image_store::measure(&buffer[..len]).unwrap_or([0; 32]),
        ),
    }];
    assert_eq!(
        super::install_system_store_against(&buffer[..len], &anchors),
        Ok(len),
    );
    let installed = super::system_store();
    assert_eq!(installed.len(), len);
    let before = installed[64 + 4 + 4];

    buffer[64 + 4 + 4] ^= 0xff;
    assert_eq!(
        super::system_store()[64 + 4 + 4],
        before,
        "the kernel followed the caller's memory instead of its own copy",
    );
}

/// **A container vouched for by the wrong anchor is refused.**
///
/// Every anchor this kernel holds is a real one, so without this a store signed
/// for one purpose would be installable for another — the machine's program
/// store offered as its firmware source.
#[test]
fn a_store_under_another_anchor_is_refused() {
    forget_installed();
    let mut buffer = [0u8; 512];
    let entries = [tessera_image_store::BuildEntry {
        name: "firmware.bin",
        svn: 7,
        image_version: 3,
        flags: 0,
        bytes: &[0x11; 64],
    }];
    let built = tessera_image_store::build_into(
        &mut buffer,
        crate::store::PROGRAM_STORE_ANCHOR_ID,
        &entries,
        false,
    )
    .expect("build");
    let anchors = [tessera_image_store::Anchor {
        id: crate::store::PROGRAM_STORE_ANCHOR_ID,
        trust: tessera_image_store::Trust::Digest(
            tessera_image_store::measure(&buffer[..built.len]).unwrap_or([0; 32]),
        ),
    }];
    assert_eq!(
        super::install_system_store_against(&buffer[..built.len], &anchors),
        Err(KError::AccessDenied),
        "a container vouched for by another anchor is not this store",
    );
    assert!(super::system_store().is_empty());
}
