// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: every tracked text file carries the SPDX header.
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Licensing And
//! Commits")

use tessera_checks::{assert_no_violations, spdx, walk};

#[test]
fn every_file_carries_the_spdx_header() {
    let root = walk::source_root();
    let files = walk::walk_files(&root);
    assert!(
        !files.is_empty(),
        "no files found under {} — gate misconfigured",
        root.display()
    );
    let mut violations = Vec::new();
    for (abs, rel) in &files {
        let Ok(content) = std::fs::read(abs) else {
            continue;
        };
        violations.extend(spdx::check_file(rel, &content));
    }
    assert_no_violations("spdx", &violations);
}
