// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Unit tests for the package-coverage gate.
//!
//! Checked against temporary trees rather than the repository, because the
//! repository is (correctly) complete: a gate run against it proves only that
//! it does not fire, never that it can.

use super::*;

/// A package as the tree requires it: a source filegroup over everything,
/// visible to the root.
const GOOD_PACKAGE: &str = "filegroup(\n    name = \"srcs\",\n    srcs = glob([\"**\"]),\n    \
                            visibility = [\"//:__pkg__\"],\n)\n";

/// Writes a tree under a fresh temporary directory: a root `BUILD.bazel` whose
/// aggregate names `listed`, and a package directory for each of `present`.
fn tree(name: &str, listed: &[&str], present: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tessera-package-gate-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp tree");

    let mut root = String::from(
        "filegroup(\n    name = \"all_srcs\",\n    srcs = [\n        \":root_srcs\",\n",
    );
    for pkg in listed {
        root.push_str(&format!("        \"//{pkg}:srcs\",\n"));
    }
    root.push_str("    ],\n)\n");
    std::fs::write(dir.join("BUILD.bazel"), root).expect("root build");

    for (pkg, body) in present {
        let path = dir.join(pkg);
        std::fs::create_dir_all(&path).expect("package dir");
        std::fs::write(path.join("BUILD.bazel"), body).expect("package build");
    }
    dir
}

#[test]
fn a_complete_tree_is_clean() {
    let dir = tree(
        "complete",
        &["api/hash", "kernel/kcore"],
        &[("api/hash", GOOD_PACKAGE), ("kernel/kcore", GOOD_PACKAGE)],
    );
    let (violations, coverage) = check(&dir);
    assert_eq!(violations, Vec::new());
    assert_eq!(
        coverage,
        Coverage {
            present: 2,
            listed: 2
        }
    );
    assert!(!coverage.sees_beyond_the_aggregate());
}

#[test]
fn a_package_missing_from_the_aggregate_is_a_violation() {
    let dir = tree(
        "unlisted",
        &["api/hash"],
        &[("api/hash", GOOD_PACKAGE), ("api/newthing", GOOD_PACKAGE)],
    );
    let (violations, coverage) = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].path, "api/newthing/BUILD.bazel");
    assert!(violations[0].reason.contains("no tier-0 gate inspects"));
    assert!(coverage.sees_beyond_the_aggregate());
}

#[test]
fn an_aggregate_entry_with_no_package_is_a_violation() {
    let dir = tree(
        "stale",
        &["api/hash", "api/gone"],
        &[("api/hash", GOOD_PACKAGE)],
    );
    let (violations, _) = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].reason.contains("//api/gone:srcs"));
}

#[test]
fn a_narrower_srcs_glob_is_a_violation() {
    let narrow = "filegroup(\n    name = \"srcs\",\n    srcs = glob([\"src/**\"]),\n    \
                  visibility = [\"//:__pkg__\"],\n)\n";
    let dir = tree("narrow", &["api/hash"], &[("api/hash", narrow)]);
    let (violations, _) = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].reason.contains("outside every gate"));
}

#[test]
fn a_srcs_filegroup_the_root_cannot_name_is_a_violation() {
    let hidden = "filegroup(\n    name = \"srcs\",\n    srcs = glob([\"**\"]),\n    \
                  visibility = [\"//visibility:private\"],\n)\n";
    let dir = tree("hidden", &["api/hash"], &[("api/hash", hidden)]);
    let (violations, _) = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].reason.contains("//:__pkg__"));
}

#[test]
fn a_package_with_no_srcs_filegroup_is_a_violation() {
    let none = "rust_library(\n    name = \"hash\",\n)\n";
    let dir = tree("nofilegroup", &["api/hash"], &[("api/hash", none)]);
    let (violations, _) = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(
        violations[0]
            .reason
            .contains("declares no `srcs` filegroup")
    );
}

#[test]
fn an_unreadable_root_is_a_violation_rather_than_an_empty_answer() {
    let dir = std::env::temp_dir().join("tessera-package-gate-noroot");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp tree");
    let (violations, coverage) = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(coverage.present, 0);
}

#[test]
fn the_root_package_is_not_owed_a_srcs_label() {
    let dir = tree("rootonly", &["api/hash"], &[("api/hash", GOOD_PACKAGE)]);
    let present = packages_in_tree(&walk::walk_files(&dir));
    assert_eq!(present, vec!["api/hash".to_owned()]);
}
