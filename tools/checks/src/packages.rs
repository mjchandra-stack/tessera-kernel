// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **package-coverage gate**: every Bazel package in this tree is one the
//! tier-0 gates can see.
//!
//! `//:all_srcs` is the filegroup the SPDX, licence, unsafe-inventory and fuzz
//! gates all read through, and it is a hand-written list. A package missing from
//! it is not rejected — it is never inspected, so every gate reports success
//! over a tree with a hole in it. That silence is what this module exists to
//! break.
//!
//! Three checks, and they do not have the same reach:
//!
//! - **Every listed label names a real package.** Hermetic, and largely already
//!   guaranteed, since Bazel refuses an unresolvable label.
//! - **Every package in the tree is listed.** The check worth having, and the
//!   one a Bazel test cannot answer: the runfiles tree a test is handed *is*
//!   `//:all_srcs`, so an unlisted package contributes no files and is invisible
//!   by construction. Under cargo the gate walks the repository itself and this
//!   has teeth. See [`Coverage`], which reports which of the two the run was
//!   able to make, so a blind run cannot be read as a clean one.
//! - **Every package's `srcs` filegroup covers the whole package.** Hermetic and
//!   real: a filegroup globbing `["src/**"]` rather than `["**"]` leaves its own
//!   `BUILD.bazel` outside every gate — the same hole by a different route.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use crate::{Violation, walk};
use std::path::{Path, PathBuf};

/// The aggregate filegroup the tier-0 gates read through.
pub const AGGREGATE: &str = "all_srcs";

/// What a package's own source filegroup must glob, so nothing in the package
/// sits outside the gates.
const REQUIRED_SRCS_GLOB: &str = "glob([\"**\"])";

/// Who a package's source filegroup must be visible to, so the aggregate can
/// name it.
const REQUIRED_SRCS_VISIBILITY: &str = "//:__pkg__";

/// Which of the two directions a run was able to check.
///
/// Reported rather than assumed because the answer depends on the tree the gate
/// was handed, and a run that could only check one direction says something
/// weaker than one that checked both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    /// Packages the tree contains.
    pub present: usize,
    /// Packages the aggregate names.
    pub listed: usize,
}

impl Coverage {
    /// Whether the tree held a package the aggregate does not name — the only
    /// evidence that the walk saw further than the aggregate did.
    ///
    /// A runfiles tree is exactly the aggregate, so this is false there for
    /// every tree, sound or not; a repository walk makes it answerable.
    pub fn sees_beyond_the_aggregate(&self) -> bool {
        self.present > self.listed
    }
}

/// The package paths `//:all_srcs` names.
pub fn listed_packages(root_build: &str) -> Vec<String> {
    let Some(block) = filegroup_block(root_build, AGGREGATE) else {
        return Vec::new();
    };
    let mut out: Vec<String> = block
        .split('"')
        .skip(1)
        .step_by(2)
        .filter_map(|label| label.strip_prefix("//"))
        .filter_map(|label| label.strip_suffix(":srcs"))
        .map(str::to_owned)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Every package the walked tree holds: a directory carrying a `BUILD.bazel`.
///
/// The root package is not one of them — it contributes `:root_srcs` from
/// inside the aggregate rather than a `:srcs` label of its own.
pub fn packages_in_tree(files: &[(PathBuf, String)]) -> Vec<String> {
    let mut out: Vec<String> = files
        .iter()
        .filter_map(|(_, rel)| rel.strip_suffix("BUILD.bazel"))
        .filter_map(|dir| dir.strip_suffix('/'))
        .map(str::to_owned)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Checks the tree under `root`, returning the violations and what the run was
/// able to see.
pub fn check(root: &Path) -> (Vec<Violation>, Coverage) {
    let mut violations = Vec::new();
    let empty = Coverage {
        present: 0,
        listed: 0,
    };

    let Ok(text) = std::fs::read_to_string(root.join("BUILD.bazel")) else {
        violations.push(Violation {
            path: "BUILD.bazel".into(),
            reason: "unreadable — the package gate cannot tell which packages the tier-0 gates see"
                .into(),
        });
        return (violations, empty);
    };

    let listed = listed_packages(&text);
    if listed.is_empty() {
        violations.push(Violation {
            path: "BUILD.bazel".into(),
            reason: format!("`{AGGREGATE}` names no package — gate misconfigured"),
        });
        return (violations, empty);
    }

    let present = packages_in_tree(&walk::walk_files(root));

    for pkg in &listed {
        if !present.contains(pkg) {
            violations.push(Violation {
                path: "BUILD.bazel".into(),
                reason: format!("`{AGGREGATE}` names //{pkg}:srcs, which is not a package here"),
            });
        }
    }

    for pkg in &present {
        if !listed.contains(pkg) {
            violations.push(Violation {
                path: format!("{pkg}/BUILD.bazel"),
                reason: format!("not in //:{AGGREGATE}, so no tier-0 gate inspects this package"),
            });
        }
        violations.extend(check_srcs_filegroup(root, pkg));
    }

    let coverage = Coverage {
        present: present.len(),
        listed: listed.len(),
    };
    (violations, coverage)
}

/// A package's own `srcs` filegroup must cover the package and be reachable
/// from the root, or the package is named by the aggregate and still unseen.
fn check_srcs_filegroup(root: &Path, pkg: &str) -> Option<Violation> {
    let path = format!("{pkg}/BUILD.bazel");
    let Ok(text) = std::fs::read_to_string(root.join(&path)) else {
        return Some(Violation {
            path,
            reason: "unreadable".into(),
        });
    };
    let Some(block) = filegroup_block(&text, "srcs") else {
        return Some(Violation {
            path,
            reason: format!("declares no `srcs` filegroup for //:{AGGREGATE} to name"),
        });
    };
    if !block.contains(REQUIRED_SRCS_GLOB) {
        return Some(Violation {
            path,
            reason: format!(
                "`srcs` must be {REQUIRED_SRCS_GLOB}; a narrower glob leaves the rest of the \
                 package outside every gate"
            ),
        });
    }
    if !block.contains(REQUIRED_SRCS_VISIBILITY) {
        return Some(Violation {
            path,
            reason: format!(
                "`srcs` must be visible to {REQUIRED_SRCS_VISIBILITY} so //:{AGGREGATE} can name it"
            ),
        });
    }
    None
}

/// The text of the target named `name`, from its `name = ` line to the closing
/// parenthesis at the start of a line.
///
/// Buildifier puts `name` first in every rule, so scanning forward from it
/// reaches the whole body.
fn filegroup_block<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let at = text.find(&format!("name = \"{name}\","))?;
    let rest = &text[at..];
    let end = rest.find("\n)")?;
    Some(&rest[..end])
}

#[cfg(test)]
#[path = "tests/packages.rs"]
mod tests;
