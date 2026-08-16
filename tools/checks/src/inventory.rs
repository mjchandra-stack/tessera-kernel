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
