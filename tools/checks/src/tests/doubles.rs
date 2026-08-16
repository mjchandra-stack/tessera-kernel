// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::doubles`.

use super::*;

const BINARY: &str = "rust_binary(\n    name = \"driver\",\n    srcs = [\"src/main.rs\"],\n    deps = [\n        \"//userspace/sdk:sdk\",\n%s    ],\n)\n";

#[test]
fn a_binary_with_no_double_is_clean() {
    assert_eq!(
        check_file("a/BUILD.bazel", &BINARY.replace("%s", "")),
        Vec::new()
    );
}

#[test]
fn a_binary_on_a_mock_is_a_violation() {
    let src = BINARY.replace("%s", "        \"//kernel/sdhci-mock:sdhci_mock\",\n");
    let v = check_file("a/BUILD.bazel", &src);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].reason.contains("sdhci-mock"));
    assert!(v[0].reason.contains("driver"));
}

#[test]
fn a_binary_on_a_simulator_is_a_violation() {
    let src = BINARY.replace("%s", "        \"//userspace/sdk-sim:sdk_sim\",\n");
    assert_eq!(check_file("a/BUILD.bazel", &src).len(), 1);
}

/// A test may depend on a double — that is what doubles are for.
#[test]
fn a_test_on_a_double_is_left_alone() {
    let src =
        "rust_test(\n    name = \"t\",\n    deps = [\"//kernel/sdhci-mock:sdhci_mock\"],\n)\n";
    assert_eq!(check_file("a/BUILD.bazel", src), Vec::new());
}

#[test]
fn the_kernel_and_user_binary_macros_are_covered() {
    for rule in ["tessera_kernel_binary(", "tessera_user_binary("] {
        let src = format!(
            "{rule}\n    name = \"k\",\n    deps = [\"//kernel/karch-mock:karch-mock\"],\n)\n"
        );
        assert_eq!(check_file("a/BUILD.bazel", &src).len(), 1, "{rule}");
    }
}

#[test]
fn a_suffix_is_matched_on_the_package_not_the_target() {
    assert!(is_double("//kernel/karch-mock:karch-mock"));
    assert!(is_double("//userspace/sdk-sim:sdk_sim"));
    assert!(!is_double("//userspace/sdk:sdk"));
    // A target whose *name* merely ends in the suffix is not a double.
    assert!(!is_double("//kernel/virtio:virtio_sim"));
}

/// A `load()` naming the rule is not a call to it.
#[test]
fn a_load_statement_is_not_a_binary() {
    let src = "load(\"@rules_rust//rust:defs.bzl\", \"rust_binary\")\n";
    assert_eq!(check_file("a/BUILD.bazel", src), Vec::new());
}
