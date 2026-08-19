// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Cargo build script (host-only): builds the ext2 image the tests read.
//!
//! Bazel builds the same image with a genrule and hands it to the test through
//! `TESSERA_EXT2_IMAGE`; both run `testdata/mkimage.sh`, so the bytes a host
//! unit test reads and the bytes a boot check mounts come from one script —
//! the argument `//tools/kconfig` makes for the configuration surface.

use std::path::Path;
use std::process::Command;

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let script = Path::new(&manifest).join("testdata/mkimage.sh");
    println!("cargo::rerun-if-changed={}", script.display());

    let image = Path::new(&out_dir).join("ext2_test.img");
    // `mke2fs` and `debugfs` live in /usr/sbin, which is not on a login PATH
    // on every distribution.
    let path = std::env::var("PATH").unwrap_or_default();
    let status = Command::new("bash")
        .arg(&script)
        .arg(&image)
        .env("PATH", format!("/usr/sbin:/sbin:{path}"))
        .status()
        .unwrap_or_else(|e| panic!("run {}: {e}", script.display()));
    assert!(status.success(), "{} failed: {status}", script.display());
}
