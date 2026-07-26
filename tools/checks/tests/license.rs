// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: vendored third-party packages carry LICENSE + METADATA,
//! use allowlisted licenses only, and every vendored byte is hash-pinned.
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Dependencies")

use tessera_checks::{assert_no_violations, license, walk};

#[test]
fn third_party_is_licensed_and_pinned() {
    let root = walk::source_root();
    let files = walk::walk_files(&root);
    let violations = license::check_third_party(&files);
    assert_no_violations("license", &violations);
}
