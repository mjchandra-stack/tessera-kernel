// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Parser for `unsafe-inventory.toml` — the machine-checked registry of
//! every module containing unsafe code: owner, scope, and why no safe
//! expression exists. Line-oriented TOML subset, hand-parsed to keep the
//! gate dependency-free.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Unsafe Code"),
//! docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use crate::Violation;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Entry {
    pub file: String,
    pub owner: String,
    pub scope: String,
    pub justification: String,
    /// 1-based line of the `[[entry]]` header, for error reporting.
    pub line: usize,
}

impl Entry {
    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.file.is_empty() {
            missing.push("file");
        }
        if self.owner.is_empty() {
            missing.push("owner");
        }
        if self.scope.is_empty() {
            missing.push("scope");
        }
        if self.justification.is_empty() {
            missing.push("justification");
        }
        missing
    }
}

/// Claims a justification may no longer rest on, and what to say instead.
///
/// **The kernel stopped being single-threaded** (build/README.md, D225): every
/// CPU the machine has comes online and runs threads off a run queue of its
/// own. A justification that rests on there being one thread of control was
/// true when it was written and is not now — and the dangerous case is not the
/// one that became unsound, it is the one that stayed sound *for a different
/// reason* and still says the old one. A reader auditing the second kind
/// re-derives an argument the code no longer makes.
///
/// So the phrase is banned rather than the situation. Code that only the boot
/// CPU reaches is still exclusive; it has to say *that* — which CPU, or which
/// exclusion — instead of asserting a property of the kernel that is false.
const STALE_CLAIMS: [(&str, &str); 6] = [
    (
        "single-threaded",
        "name the CPU that reaches it, or the exclusion that holds",
    ),
    (
        "single threaded",
        "name the CPU that reaches it, or the exclusion that holds",
    ),
    (
        "single-core",
        "name the CPU that reaches it, or the exclusion that holds",
    ),
    (
        "single core",
        "name the CPU that reaches it, or the exclusion that holds",
    ),
    (
        "uniprocessor",
        "name the CPU that reaches it, or the exclusion that holds",
    ),
    (
        "only one CPU",
        "name the CPU that reaches it, or the exclusion that holds",
    ),
];

/// Flags entries whose justification rests on the kernel being single-threaded.
///
/// See [`STALE_CLAIMS`]. Host tests are exempt: a test that does not spawn a
/// thread is genuinely single-threaded, and that is a statement about the test
/// rather than about the kernel.
pub fn stale_claims(manifest_rel: &str, entries: &[Entry]) -> Vec<Violation> {
    let mut violations = Vec::new();
    for entry in entries {
        if entry.file.contains("/tests/") {
            continue;
        }
        let text = entry.justification.to_ascii_lowercase();
        for (claim, remedy) in STALE_CLAIMS {
            if text.contains(claim) {
                violations.push(Violation {
                    path: format!("{manifest_rel}:{}", entry.line),
                    reason: format!(
                        "justification for {} rests on \"{claim}\", which stopped being true of this kernel (D225): {remedy}",
                        entry.file
                    ),
                });
                break;
            }
        }
    }
    violations
}

/// Flags `// SAFETY:` comments that rest on the kernel being single-threaded.
///
/// The manifest is the registry and these are the argument; a reader auditing
/// a line reads the comment, not the entry. Only `SAFETY` comments in Rust
/// sources are in scope: a doc comment may perfectly well discuss a one-CPU
/// *machine*, and prose elsewhere may quote the phrase in order to ban it —
/// this rule's own ledger entry does. It is about what a piece of unsafe code
/// claims for itself.
pub fn stale_safety_comments(rel: &str, text: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if !line.contains("SAFETY:") {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        for (claim, remedy) in STALE_CLAIMS {
            if lower.contains(claim) {
                violations.push(Violation {
                    path: format!("{rel}:{}", number + 1),
                    reason: format!(
                        "SAFETY comment rests on \"{claim}\", which stopped being true of this kernel (D225): {remedy}"
                    ),
                });
                break;
            }
        }
    }
    violations
}

/// Parses the manifest. Syntax problems are reported as violations against
/// the manifest itself; well-formed entries are returned even when other
/// lines are bad, so downstream rules still run.
pub fn parse(manifest_rel: &str, text: &str) -> (Vec<Entry>, Vec<Violation>) {
    let mut entries: Vec<Entry> = Vec::new();
    let mut violations: Vec<Violation> = Vec::new();
    let mut current: Option<Entry> = None;

    let close = |entry: Entry, violations: &mut Vec<Violation>, entries: &mut Vec<Entry>| {
        let missing = entry.missing_fields();
        if missing.is_empty() {
            entries.push(entry);
        } else {
            violations.push(Violation {
                path: format!("{manifest_rel}:{}", entry.line),
                reason: format!("entry is missing required field(s): {}", missing.join(", ")),
            });
        }
    };

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[entry]]" {
            if let Some(done) = current.take() {
                close(done, &mut violations, &mut entries);
            }
            current = Some(Entry {
                line: lineno,
                ..Entry::default()
            });
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            violations.push(Violation {
                path: format!("{manifest_rel}:{lineno}"),
                reason: format!("expected `key = \"value\"`, got `{line}`"),
            });
            continue;
        };
        let key = key.trim();
        let Some(value) = value
            .trim()
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
        else {
            violations.push(Violation {
                path: format!("{manifest_rel}:{lineno}"),
                reason: format!("value for `{key}` must be double-quoted"),
            });
            continue;
        };
        let Some(entry) = current.as_mut() else {
            violations.push(Violation {
                path: format!("{manifest_rel}:{lineno}"),
                reason: "field outside any [[entry]]".to_owned(),
            });
            continue;
        };
        match key {
            "file" => entry.file = value.to_owned(),
            "owner" => entry.owner = value.to_owned(),
            "scope" => entry.scope = value.to_owned(),
            "justification" => entry.justification = value.to_owned(),
            other => violations.push(Violation {
                path: format!("{manifest_rel}:{lineno}"),
                reason: format!("unknown field `{other}`"),
            }),
        }
    }
    if let Some(done) = current.take() {
        close(done, &mut violations, &mut entries);
    }

    (entries, violations)
}

#[cfg(test)]
#[path = "tests/inventory.rs"]
mod tests;
