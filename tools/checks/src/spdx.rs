// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! SPDX header gate: every tracked text file carries the project's SPDX
//! license identifier and copyright line near the top.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Licensing And
//! Commits")

use crate::{Violation, walk};

pub const REQUIRED_LICENSE: &str = "SPDX-License-Identifier: Apache-2.0";
pub const REQUIRED_COPYRIGHT: &str = "Copyright 2026 Jagadeesh Chandra Muddana";

/// How many leading bytes must contain the header.
const HEAD_LEN: usize = 1024;

/// Files that cannot carry a comment header: pure-data formats and
/// tool-generated lockfiles (their pinning is the point; content is not
/// authored).
const EXEMPT_BASENAMES: &[&str] = &[
    "LICENSE",
    "NOTICE",
    "Cargo.lock",
    "MODULE.bazel.lock",
    ".bazelversion",
];

/// Returns a violation if `rel` (with `content`) is missing the header.
/// `third_party/` is exempt here — the license gate owns vendored code.
pub fn check_file(rel: &str, content: &[u8]) -> Option<Violation> {
    if rel.starts_with("third_party/") {
        return None;
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    if EXEMPT_BASENAMES.contains(&base) {
        return None;
    }
    let head = &content[..content.len().min(HEAD_LEN)];
    if walk::is_binary(head) {
        return None;
    }
    let head_text = String::from_utf8_lossy(head);
    if !head_text.contains(REQUIRED_LICENSE) {
        return Some(Violation {
            path: rel.to_owned(),
            reason: format!("missing `{REQUIRED_LICENSE}` in the first {HEAD_LEN} bytes"),
        });
    }
    if !head_text.contains(REQUIRED_COPYRIGHT) {
        return Some(Violation {
            path: rel.to_owned(),
            reason: format!("missing `{REQUIRED_COPYRIGHT}` in the first {HEAD_LEN} bytes"),
        });
    }
    None
}

#[cfg(test)]
#[path = "tests/spdx.rs"]
mod tests;
