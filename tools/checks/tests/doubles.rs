// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: nothing that runs on a machine depends on a model of itself.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 1")

use tessera_checks::{assert_no_violations, doubles, walk};

#[test]
fn no_binary_depends_on_a_test_double() {
    let root = walk::source_root();
    assert!(
        root.join("kernel/karch-mock/BUILD.bazel").is_file(),
        "no packages under {} — gate misconfigured",
        root.display()
    );
    assert_no_violations("doubles", &doubles::check(&root));
}
