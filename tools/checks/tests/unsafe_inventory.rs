// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: the unsafe-code inventory.
//!
//! Rules enforced:
//! (a) every first-party Rust file containing `unsafe` has an inventory
//!     entry — new unprovenanced unsafe fails the build;
//! (b) every inventory entry still contains `unsafe` — the list only
//!     shrinks, stale entries fail;
//! (c) every line with `unsafe` states its invariant: a `// SAFETY:`
//!     comment within the 3 preceding lines, or a `# Safety` doc section
//!     in the contiguous comment block above (unsafe fn declarations);
//! (d) crates whose root declares `#![deny(unsafe_code)]` never appear.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Unsafe Code"),
//! docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use std::collections::{BTreeMap, BTreeSet};
use tessera_checks::{Violation, assert_no_violations, inventory, scan, walk};

const MANIFEST: &str = "unsafe-inventory.toml";
const SAFETY_WINDOW: usize = 3;

#[test]
fn unsafe_code_is_inventoried_and_justified() {
    let root = walk::source_root();
    let files = walk::walk_files(&root);

    let manifest_text = match std::fs::read_to_string(root.join(MANIFEST)) {
        Ok(text) => text,
        Err(err) => panic!("cannot read {MANIFEST}: {err}"),
    };
    let (entries, mut violations) = inventory::parse(MANIFEST, &manifest_text);

    // First-party Rust sources and their unsafe lines.
    let mut unsafe_by_file: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut deny_crate_dirs: BTreeSet<String> = BTreeSet::new();

    for (abs, rel) in &files {
        if !rel.ends_with(".rs") || rel.starts_with("third_party/") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(abs) else {
            continue;
        };
        // Crate roots declaring deny(unsafe_code) mark their whole crate.
        if (rel.ends_with("src/lib.rs") || rel.ends_with("src/main.rs"))
            && scan::strip_noncode(&text).contains("#![deny(unsafe_code)]")
            && let Some(crate_dir) = rel
                .strip_suffix("src/lib.rs")
                .or(rel.strip_suffix("src/main.rs"))
        {
            deny_crate_dirs.insert(crate_dir.to_owned());
        }
        let lines = scan::unsafe_lines(&text);
        if !lines.is_empty() {
            unsafe_by_file.insert(rel.clone(), lines);
        }
        sources.insert(rel.clone(), text);
    }

    let inventoried: BTreeSet<&str> = entries.iter().map(|e| e.file.as_str()).collect();

    // (a) unsafe without an entry; (c) unsafe without a SAFETY comment.
    for (rel, lines) in &unsafe_by_file {
        if !inventoried.contains(rel.as_str()) {
            violations.push(Violation {
                path: rel.clone(),
                reason: format!("contains `unsafe` but has no entry in {MANIFEST}"),
            });
        }
        if let Some(text) = sources.get(rel) {
            for line in lines {
                if !scan::has_safety_comment(text, *line, SAFETY_WINDOW) {
                    violations.push(Violation {
                        path: format!("{rel}:{line}"),
                        reason: format!(
                            "`unsafe` without a `// SAFETY:` comment in the {SAFETY_WINDOW} preceding lines"
                        ),
                    });
                }
            }
        }
    }

    // (b) stale entries; (d) entries inside deny(unsafe_code) crates.
    for entry in &entries {
        if !unsafe_by_file.contains_key(&entry.file) {
            let reason = if sources.contains_key(&entry.file) {
                "inventory entry is stale: file no longer contains `unsafe`"
            } else {
                "inventory entry names a file that does not exist"
            };
            violations.push(Violation {
                path: format!("{MANIFEST}:{}", entry.line),
                reason: format!("{reason} ({})", entry.file),
            });
        }
        if deny_crate_dirs
            .iter()
            .any(|dir| entry.file.starts_with(dir.as_str()))
        {
            violations.push(Violation {
                path: format!("{MANIFEST}:{}", entry.line),
                reason: format!(
                    "{} is in a #![deny(unsafe_code)] crate and may not be inventoried",
                    entry.file
                ),
            });
        }
    }

    assert_no_violations("unsafe-inventory", &violations);
}
