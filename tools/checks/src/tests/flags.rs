// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Unit tests for the codegen-flag agreement gate.
//!
//! Disagreements are exercised against temporary trees, because the real tables
//! agree. That the parsers understand the real files is asserted in
//! `tools/checks/tests/flags.rs`, which is the run that has the tree.

use super::*;
use std::path::PathBuf;

const KERNEL_BZL: &str = r#"
_COMMON_FLAGS = [
    "-Crelocation-model=static",
    "-Clink-arg=--gc-sections",
]

_ARCHITECTURES = {
    "x86_64": struct(
        cpu = "@platforms//cpu:x86_64",
        platform = "//build/platforms:x86_64-kernel",
        flags = ["-Ccode-model=kernel"],
    ),
    "aarch64": struct(
        cpu = "@platforms//cpu:aarch64",
        platform = "//build/platforms:aarch64-kernel",
        flags = [],
    ),
}

def tessera_kernel_binary(
        name,
        srcs,
        arch = "x86_64",
        deps = []):
    pass
"#;

const CARGO_TOML: &str = r#"
[target.x86_64-unknown-none]
rustflags = [
    "-Ccode-model=kernel",
    "-Crelocation-model=static",
    "-Clink-arg=--gc-sections",
    "-Clink-arg=-Tkernel/kernel/linker.ld",
]
"#;

const KERNEL_BUILD: &str = "tessera_kernel_binary(\n    name = \"kernel\",\n    \
                            srcs = glob([\"src/**/*.rs\"]),\n    \
                            linker_script = \"linker.ld\",\n    rustc_flags = [\n        \
                            \"--cfg=has_root_task\",\n    ],\n)\n\nfilegroup(\n    \
                            name = \"srcs\",\n    srcs = glob([\"**\"]),\n)\n";

const USERSPACE_BZL: &str = r#"
_ARCHITECTURES = {
    "x86_64": struct(
        cpu = "@platforms//cpu:x86_64",
        platform = "//build/platforms:x86_64-kernel",
        flags = [],
    ),
}
"#;

/// Writes the four files the gate reads, with the caller's cargo block.
fn tree(name: &str, cargo: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tessera-flag-gate-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("build/rules")).expect("temp tree");
    std::fs::create_dir_all(dir.join(".cargo")).expect("temp tree");
    std::fs::create_dir_all(dir.join("kernel/kernel")).expect("temp tree");
    std::fs::write(dir.join("build/rules/kernel.bzl"), KERNEL_BZL).expect("kernel.bzl");
    std::fs::write(dir.join("build/rules/userspace.bzl"), USERSPACE_BZL).expect("userspace.bzl");
    std::fs::write(dir.join(".cargo/config.toml"), cargo).expect("cargo config");
    std::fs::write(dir.join("kernel/kernel/BUILD.bazel"), KERNEL_BUILD).expect("kernel build");
    dir
}

#[test]
fn agreeing_tables_are_clean() {
    let dir = tree("agree", CARGO_TOML);
    assert_eq!(check(&dir), Vec::new());
}

#[test]
fn a_flag_the_inner_loop_lacks_is_a_violation() {
    let dir = tree(
        "missing",
        &CARGO_TOML.replace("    \"-Ccode-model=kernel\",\n", ""),
    );
    let violations = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(
        violations[0]
            .reason
            .contains("missing `-Ccode-model=kernel`")
    );
}

#[test]
fn a_flag_only_the_inner_loop_has_is_a_violation() {
    let dir = tree(
        "extra",
        &CARGO_TOML.replace(
            "    \"-Ccode-model=kernel\",\n",
            "    \"-Ccode-model=kernel\",\n    \"-Cpanic=unwind\",\n",
        ),
    );
    let violations = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].reason.contains("adds `-Cpanic=unwind`"));
}

#[test]
fn a_kernel_the_inner_loop_cannot_build_is_a_violation() {
    let dir = tree(
        "nolink",
        &CARGO_TOML.replace("kernel/kernel/linker.ld", "kernel/other/linker.ld"),
    );
    let violations = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].reason.contains("no [target.*] block links"));
}

#[test]
fn feature_flags_are_outside_the_comparison() {
    // The kernel BUILD carries `--cfg=has_root_task` and the cargo block does
    // not; that is the design (the inner loop builds without the embedded
    // ring-3 images), so it must not be reported.
    assert!(!is_compared("--cfg=has_root_task"));
    assert!(!is_compared("--check-cfg=cfg(has_root_task)"));
    assert!(!is_compared("-Clink-arg=-Tkernel/kernel/linker.ld"));
    assert!(is_compared("-Ccode-model=kernel"));
}

#[test]
fn the_two_tables_must_name_one_platform_per_arch() {
    let dir = tree("platform", CARGO_TOML);
    std::fs::write(
        dir.join("build/rules/userspace.bzl"),
        USERSPACE_BZL.replace("x86_64-kernel", "x86_64-userland"),
    )
    .expect("userspace.bzl");
    let violations = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].reason.contains("platform"));
}
