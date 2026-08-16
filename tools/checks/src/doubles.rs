// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **test-double gate**: nothing that ships depends on a model of itself.
//!
//! A mock or a simulator is a crate here rather than a module — `karch-mock`,
//! `sdhci-mock`, `sdk-sim` — and the reason is not tidiness. A test double
//! inside the library it doubles is part of that library's public surface, so
//! every consumer can build against it, and the only thing standing between the
//! model and a shipped image is the linker's willingness to drop it.
//!
//! Naming the crates by suffix rather than listing them is deliberate: a new
//! mock added tomorrow is covered without anybody remembering this file.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 1"),
//! docs/lifecycle/04-coding-guidelines.md

use crate::{Violation, walk};
use std::path::Path;

/// Package-name suffixes that mark a crate as a model of something else.
pub const DOUBLE_SUFFIXES: [&str; 2] = ["-mock", "-sim"];

/// Rules that produce something that runs on a machine.
const BINARY_RULES: [&str; 3] = [
    "rust_binary(",
    "tessera_kernel_binary(",
    "tessera_user_binary(",
];

/// Whether `label` names a package this gate treats as a test double.
pub fn is_double(label: &str) -> bool {
    let package = label.split(':').next().unwrap_or(label);
    DOUBLE_SUFFIXES.iter().any(|s| package.ends_with(s))
}

/// Returns a violation for each binary in `content` whose `deps` name a double.
pub fn check_file(rel: &str, content: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (name, deps) in binaries(content) {
        for dep in deps.iter().filter(|d| is_double(d)) {
            out.push(Violation {
                path: rel.to_owned(),
                reason: format!(
                    "binary `{name}` depends on `{dep}`, a test double; a model must not be \
                     reachable from something that runs on a machine"
                ),
            });
        }
    }
    out
}

/// Every binary target in a BUILD file, as (name, dependency labels).
fn binaries(content: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for rule in &BINARY_RULES {
        let mut at = 0;
        while let Some(found) = content[at..].find(rule) {
            let start = at + found;
            at = start + rule.len();
            // A rule call starts a line; anything else is a `load` or prose.
            if start > 0 && content.as_bytes()[start - 1] != b'\n' {
                continue;
            }
            let Some(end) = content[start..].find("\n)").map(|e| start + e) else {
                continue;
            };
            let block = &content[start..end];
            let name = field(block, "name").unwrap_or_default();
            out.push((name, labels(block)));
        }
    }
    out
}

/// The `//…` labels in a rule's `deps` list.
fn labels(block: &str) -> Vec<String> {
    let Some(deps) = block.find("deps = [").map(|i| &block[i..]) else {
        return Vec::new();
    };
    let end = deps.find(']').unwrap_or(deps.len());
    deps[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .filter(|l| l.starts_with("//"))
        .map(str::to_owned)
        .collect()
}

/// The quoted value of `name = "…"` in a rule block.
fn field(block: &str, name: &str) -> Option<String> {
    let at = block.find(&format!("{name} = \""))? + name.len() + 4;
    let rest = &block[at..];
    rest.find('"').map(|e| rest[..e].to_owned())
}

/// Checks every BUILD file under `root`.
pub fn check(root: &Path) -> Vec<Violation> {
    let mut out = Vec::new();
    for (abs, rel) in walk::walk_files(root) {
        if !rel.ends_with("BUILD.bazel") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&abs) else {
            continue;
        };
        out.extend(check_file(&rel, &content));
    }
    out
}

#[cfg(test)]
#[path = "tests/doubles.rs"]
mod tests;
