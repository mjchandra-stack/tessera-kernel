// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: the Bazel graph and the cargo inner loop build each kernel with
//! the same codegen flags.
//!
//! The assertions before the gate itself are its premise: a parser that quietly
//! stops understanding `kernel.bzl` returns an empty table, and an empty table
//! compares clean against anything.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use tessera_checks::{assert_no_violations, flags, walk};

#[test]
fn the_flag_tables_agree() {
    let root = walk::source_root();

    let arch = std::fs::read_to_string(root.join(flags::ARCH_TABLE)).expect("arch.bzl");
    let bzl = std::fs::read_to_string(root.join(flags::KERNEL_RULES)).expect("kernel.bzl");
    let table = flags::architectures(&arch);
    assert_eq!(
        table.len(),
        5,
        "expected five architectures in {}, found {:?}",
        flags::ARCH_TABLE,
        table.keys().collect::<Vec<_>>()
    );
    for (name, entry) in &table {
        assert!(!entry.cpu.is_empty(), "arch `{name}` parsed with no cpu");
        assert!(
            !entry.platform.is_empty(),
            "arch `{name}` parsed with no platform"
        );
    }
    assert_eq!(
        flags::common_flags(&arch),
        vec![
            "-Crelocation-model=static".to_owned(),
            "-Clink-arg=--gc-sections".to_owned(),
        ],
        "the common flag list parsed as something else"
    );

    let default = flags::default_arch(&bzl).expect("tessera_kernel_binary has a default arch");
    let binaries = flags::kernel_binaries(&root, &default);
    let mut arches: Vec<&str> = binaries.iter().map(|b| b.arch.as_str()).collect();
    arches.sort_unstable();
    assert_eq!(
        arches,
        vec!["aarch64", "arm32", "riscv32", "riscv64", "x86_64"],
        "one kernel binary per architecture is the premise of this gate"
    );

    let toml = std::fs::read_to_string(root.join(flags::CARGO_CONFIG)).expect("cargo config");
    let targets = flags::cargo_targets(&toml);
    assert_eq!(
        targets.len(),
        5,
        "expected five [target.*] blocks, found {:?}",
        targets.keys().collect::<Vec<_>>()
    );

    assert_no_violations("flags", &flags::check(&root));
}
