// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The kernel's program-store anchor is the public half of the key the build
//! signs with**, and nothing derives one from the other.
//!
//! `build/rules/components.bzl` holds a signing seed; `kcore::store` holds a
//! public key. A build that computed the second from the first would authorize
//! whatever it happened to sign, which is the same objection the system store's
//! pinned measurement answers — so they are two constants, and this is what
//! holds them together (D290).
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Trust Anchors And Signing Infrastructure")

use tessera_image_store::{Anchor, Store, Trust};
use tessera_kcore::store::{PROGRAM_STORE_ANCHOR_ID, TRUSTED_ANCHORS};

/// Runfiles path of the container this build produced. The same shape
/// `//store:anchor_test` uses, and for the same reason: a data dependency is
/// found under the runfiles root, not at the path the build rule named.
const CONTAINER: &str = "_main/components/aarch64_programs.bin";

fn container() -> Vec<u8> {
    let root = std::env::var("RUNFILES_DIR")
        .ok()
        .or_else(|| std::env::var("TEST_SRCDIR").ok())
        .unwrap_or_else(|| panic!("no runfiles directory"));
    let path = std::path::Path::new(&root).join(CONTAINER);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The whole claim: this kernel mounts the store this build produced, by
/// verifying its signature.
#[test]
fn the_kernel_verifies_the_program_store_this_build_signed() {
    let bytes = container();
    let store = Store::mount(&bytes, &TRUSTED_ANCHORS).unwrap_or_else(|e| {
        panic!(
            "\n\nThe kernel will not verify the program store this build signed: {e:?}\n\
             Either the signing seed in build/rules/components.bzl changed, or the\n\
             public key in kcore::store::TRUSTED_ANCHORS did. Print the matching\n\
             key with:\n\n    bazel run //tools/mkstore -- pubkey --sign-key <seed>\n\n\
             and paste it. Doing it by hand is the point: a build that derived the\n\
             anchor from its own key would be authorizing its own output.\n"
        )
    });
    assert_eq!(store.anchor_id(), PROGRAM_STORE_ANCHOR_ID);
    assert!(!store.is_empty(), "a machine with no programs is not one");
}

/// **A container changed after it was signed is refused**, which is the whole
/// reason the programs moved into a store rather than staying thirty symbols.
///
/// The flipped byte is in the first entry's `flags`: a length or a name fails
/// the parse and never reaches the signature, so a test written that way would
/// pass with verification removed entirely (D289).
#[test]
fn a_program_store_changed_after_signing_is_refused() {
    let mut bytes = container();
    let first_entry_flags = 64 + 4 + 4;
    bytes[first_entry_flags] ^= 0xff;
    assert!(
        Store::mount(&bytes, &TRUSTED_ANCHORS).is_err(),
        "the kernel accepted a program store that was altered after signing",
    );
}

/// And it is a **key**, not a measurement. A pinned digest here would be a
/// constant nobody could keep current: this container changes whenever any
/// program does.
#[test]
fn the_program_anchor_is_a_key() {
    let anchor = TRUSTED_ANCHORS
        .iter()
        .find(|anchor| anchor.id == PROGRAM_STORE_ANCHOR_ID)
        .unwrap_or_else(|| panic!("no anchor for id {PROGRAM_STORE_ANCHOR_ID}"));
    assert!(
        matches!(anchor.trust, Trust::Key(_)),
        "the program store's anchor must be a key, not a pinned measurement",
    );
    // And the two anchors are distinct ids, or one container could be accepted
    // where the other was meant.
    let ids: Vec<u32> = TRUSTED_ANCHORS.iter().map(|a: &Anchor| a.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids.len(), sorted.len(), "two anchors share an id");
}
