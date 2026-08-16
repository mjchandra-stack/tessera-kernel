// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The anchor gate**: the container this build produced measures to the
//! anchor the kernel is compiled to trust.
//!
//! `kcore::store::TRUSTED_ANCHORS` is checked-in kernel source rather than a
//! build output, because a build that emitted both the artifact and the digest
//! it is checked against would authorize anything it happened to produce (see
//! `kernel/kcore/src/store.rs`). The price of that is a build that can drift
//! out of agreement with itself, and this test is what makes the drift cheap:
//! it fails here, in `bazel test`, with the value to paste — instead of in a
//! QEMU run that refuses to mount and says only that it did.
//!
//! Normative: docs/security/01-security-model.md ("Boot Security")

use tessera_image_store::measure;
use tessera_kcore::store::{SYSTEM_STORE_ANCHOR_ID, TRUSTED_ANCHORS};

/// Runfiles path of the container this build produced.
const CONTAINER: &str = "_main/store/system_store.bin";

fn container() -> Vec<u8> {
    // Bazel puts data deps under the runfiles directory; the test's own path
    // is the anchor for finding it when RUNFILES_DIR is not set.
    let root = std::env::var("RUNFILES_DIR")
        .ok()
        .or_else(|| std::env::var("TEST_SRCDIR").ok())
        .unwrap_or_else(|| panic!("no runfiles directory"));
    let path = std::path::Path::new(&root).join(CONTAINER);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn hex(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .map(|byte| format!("0x{byte:02x}, "))
        .collect()
}

#[test]
fn the_built_container_measures_to_the_trusted_anchor() {
    let bytes = container();
    let measured =
        measure(&bytes).unwrap_or_else(|e| panic!("the built container is not a store: {e:?}"));
    let trusted = TRUSTED_ANCHORS
        .iter()
        .find(|anchor| anchor.id == SYSTEM_STORE_ANCHOR_ID)
        .unwrap_or_else(|| panic!("no anchor for id {SYSTEM_STORE_ANCHOR_ID}"));

    assert_eq!(
        trusted.digest,
        measured,
        "\n\nThe system store changed and the kernel's anchor did not.\n\
         Paste this into TRUSTED_ANCHORS in kernel/kcore/src/store.rs:\n\n{}\n\n\
         Doing it by hand is the point: the anchor is what this kernel trusts,\n\
         and a build that updated it would be authorizing its own output.\n",
        hex(&measured)
    );
}

/// A container that mounts against those anchors, through the kernel's own
/// path — so the gate covers the *decision* and not only the arithmetic.
#[test]
fn the_kernel_mounts_what_the_build_produced() {
    let bytes = container();
    let store = tessera_kcore::store::mount(&bytes).expect("the kernel refuses its own store");
    assert_eq!(store.len(), 4);
    assert_eq!(store.anchor_id(), SYSTEM_STORE_ANCHOR_ID);

    // **The versions the BUILD file states are the versions that arrive**, and
    // the two that differ between images are the two the firmware policy reads.
    // A build rule that lost them would leave every policy refusal downstream
    // testing the same image against itself.
    let firmware = store.open("firmware.bin").expect("firmware.bin");
    assert_eq!(firmware.bytes.len(), 4096);
    assert_eq!((firmware.svn, firmware.image_version), (7, 3));

    let old = store.open("firmware-old.bin").expect("firmware-old.bin");
    assert_eq!((old.svn, old.image_version), (2, 3));

    let v1 = store.open("firmware-v1.bin").expect("firmware-v1.bin");
    assert_eq!((v1.svn, v1.image_version), (7, 1));

    let platform = store.open("platform.bin").expect("platform.bin");
    assert_eq!(platform.bytes.len(), 512);

    // The two refusable images are *different bytes*: an image refused for its
    // metadata while being byte-identical to the one that loads would make the
    // whole set one image wearing three labels.
    assert_ne!(firmware.digest, old.digest);
    assert_ne!(firmware.digest, v1.digest);
}
