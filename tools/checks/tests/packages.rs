// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: every package in the tree is one `//:all_srcs` names, and every
//! package's source filegroup covers the whole package.
//!
//! What this run can prove depends on the tree it is handed. Under Bazel that
//! tree *is* `//:all_srcs`, so a package the aggregate omits contributes no
//! files and cannot be seen from here — the stale-label and filegroup checks
//! have teeth, the omitted-package check cannot (deviation D182). Under cargo
//! the gate walks the repository and all three do, which is why
//! `cargo test -p tessera-checks` is the run that closes the hole.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use tessera_checks::{assert_no_violations, packages, walk};

#[test]
fn every_package_is_gated() {
    let root = walk::source_root();
    let (violations, coverage) = packages::check(&root);
    assert!(
        coverage.listed > 0,
        "//:{} names no package under {} — gate misconfigured",
        packages::AGGREGATE,
        root.display()
    );
    assert!(
        coverage.present > 0,
        "no package found under {} — gate misconfigured",
        root.display()
    );
    assert_no_violations("packages", &violations);
}
