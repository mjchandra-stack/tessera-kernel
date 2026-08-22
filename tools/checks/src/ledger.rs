// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **deviation-ledger gate**: the ledger in `build/README.md` is a table
//! that parses, numbers that are unique and unbroken, and `D<n>` citations that
//! resolve.
//!
//! **Every gate in this directory exists because the tree makes a claim, and
//! the ledger is where the claims about the tree's own gaps live.** It is
//! cited from source — `tools/checks/src/config.rs` names D199, the arch-lint
//! baseline names D183 — so a number is an address, and an address that leads
//! nowhere is worse than a comment that says nothing. Nothing checked it, and
//! three defects had accumulated by the time anyone read the whole thing:
//!
//! - **65 blank lines inside the table.** A blank line ends a markdown table,
//!   so the ledger rendered as 33 rows and then 180 paragraphs of pipes. The
//!   entries were all there; the document had simply stopped being a table at
//!   D33, and every reader after that point saw prose.
//! - **Eight rows with an unescaped `|`** in prose like `bus << 8 | device <<
//!   3 | function`. A code span does not protect a pipe in a table cell, so
//!   those rows had four, five and six cells; a renderer keeps three and drops
//!   the rest, and the *last* cell is the exit criterion. The rows that most
//!   needed reading were the ones displaying a fragment of their own prose in
//!   the column that says what would close them.
//! - **One number used twice** (D199, for the configuration surface and for
//!   the ext2 read path), which makes a citation ambiguous rather than wrong —
//!   the failure mode that survives longest, because both readings look right.
//!
//! Each is invisible to a reader of the source and obvious to a parser, which
//! is the shape of every other gate here.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")
//! Budget: none (build-time tooling)

use crate::{Violation, walk};
use std::collections::BTreeMap;
use std::path::Path;

/// Where the ledger lives, repo-relative.
pub const LEDGER: &str = "build/README.md";

/// The table's header row, which is where the checked region starts.
const HEADER: &str = "| # | Deviation | Exit criterion |";

/// Extensions scanned for `D<n>` citations: the text the tree is written in.
/// A citation in anything else is not a citation.
const CITING: &[&str] = &[
    ".rs", ".md", ".bazel", ".bzl", ".sh", ".toml", ".config", ".profile", ".isl",
];

/// One row of the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: u32,
    pub line: usize,
    pub exit: String,
}

/// Splits a table row into cells, honouring `\|`.
///
/// The escape is the whole point of the gate's second rule: a pipe that is not
/// escaped is a cell boundary however much it looks like arithmetic to the
/// person who wrote it.
fn cells(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'|') {
            cur.push('\\');
            cur.push(chars.next().unwrap_or('|'));
            continue;
        }
        if c == '|' {
            out.push(cur.trim().to_string());
            cur = String::new();
            continue;
        }
        cur.push(c);
    }
    out.push(cur.trim().to_string());
    out
}

/// Checks the ledger's own structure, returning one violation per defect.
///
/// Returns the parsed entries alongside, so the citation check can be run
/// against the same reading rather than a second one that might disagree.
pub fn check_table(rel: &str, content: &str) -> (Vec<Entry>, Vec<Violation>) {
    let mut out = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    let Some(header) = lines.iter().position(|l| l.trim_end() == HEADER) else {
        out.push(Violation {
            path: rel.to_string(),
            reason: format!("no deviation table: expected a header row `{HEADER}`"),
        });
        return (Vec::new(), out);
    };
    let Some(last) = lines.iter().rposition(|l| l.starts_with("| D")) else {
        out.push(Violation {
            path: rel.to_string(),
            reason: "the deviation table has a header and no rows".to_string(),
        });
        return (Vec::new(), out);
    };

    // **A blank line ends a table, so the region has to be continuous.** This
    // is the rule that had been broken 65 times: the entries were all present
    // and the document had stopped being a table two thirds of the way up.
    for (offset, line) in lines[header..=last].iter().enumerate() {
        if !line.starts_with('|') {
            let what = if line.trim().is_empty() {
                "a blank line ends the markdown table; every row after it renders as a paragraph"
            } else {
                "a non-row line ends the markdown table; every row after it renders as a paragraph"
            };
            out.push(Violation {
                path: format!("{rel}:{}", header + offset + 1),
                reason: what.to_string(),
            });
        }
    }

    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: BTreeMap<u32, usize> = BTreeMap::new();
    for (offset, line) in lines[header..=last].iter().enumerate() {
        let number = header + offset + 1;
        if !line.starts_with("| D") {
            continue;
        }
        let c = cells(line);
        // A row is `| id | deviation | exit |`: the outer pipes give an empty
        // cell at each end, so a well-formed row splits into five.
        if c.len() != 5 || !c[0].is_empty() || !c[4].is_empty() {
            out.push(Violation {
                path: format!("{rel}:{number}"),
                reason: format!(
                    "row has {} cells, not 3 — an unescaped `|` in the prose (write `\\|`); \
                     a renderer keeps the first three and drops the rest, and the exit \
                     criterion is the one that goes",
                    c.len().saturating_sub(2)
                ),
            });
            continue;
        }
        let Some(id) = c[1].strip_prefix('D').and_then(|n| n.parse::<u32>().ok()) else {
            out.push(Violation {
                path: format!("{rel}:{number}"),
                reason: format!("`{}` is not a deviation number of the form D<n>", c[1]),
            });
            continue;
        };
        if let Some(first) = seen.insert(id, number) {
            out.push(Violation {
                path: format!("{rel}:{number}"),
                reason: format!(
                    "D{id} is already used at line {first}; a number is an address, and one \
                     used twice makes every citation of it ambiguous"
                ),
            });
        }
        if c[3].is_empty() {
            out.push(Violation {
                path: format!("{rel}:{number}"),
                reason: format!(
                    "D{id} has no exit criterion; a deviation with no way to close it is a \
                     decision, not a deviation"
                ),
            });
        }
        entries.push(Entry {
            id,
            line: number,
            exit: c[3].clone(),
        });
    }

    // **No gaps.** A missing number is an entry that was removed, and the
    // ledger's own rule is that a deviation is never silently absorbed.
    if let Some(&max) = seen.keys().next_back() {
        let missing: Vec<u32> = (1..=max).filter(|n| !seen.contains_key(n)).collect();
        if !missing.is_empty() {
            out.push(Violation {
                path: rel.to_string(),
                reason: format!(
                    "no row for {}; a number with no entry is one that was removed, and a \
                     deviation is never silently absorbed",
                    missing
                        .iter()
                        .map(|n| format!("D{n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }

    (entries, out)
}

/// Every `D<n>` cited in `content`, as (byte offset, number).
///
/// Word-bounded on both sides, so `0xD1` and `SD130` are not citations. A
/// citation is a bare number in prose or a comment, which is how the tree
/// writes them everywhere.
pub fn citations(content: &str) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    let b = content.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'D' {
            i += 1;
            continue;
        }
        let before_is_word = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        let digits = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || before_is_word {
            i += 1;
            continue;
        }
        let end = i + 1 + digits;
        let after_is_word = b
            .get(end)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
        if !after_is_word && let Ok(n) = content[i + 1..end].parse::<u32>() {
            out.push((i, n));
        }
        i = end;
    }
    out
}

/// Checks the ledger and every citation of it in the tree.
pub fn check(root: &Path) -> Vec<Violation> {
    let ledger_path = root.join(LEDGER);
    let Ok(content) = std::fs::read_to_string(&ledger_path) else {
        return std::vec![Violation {
            path: LEDGER.to_string(),
            reason: "the deviation ledger is missing".to_string(),
        }];
    };
    let (entries, mut out) = check_table(LEDGER, &content);
    // A ledger that did not parse cannot say what resolves; reporting every
    // citation as dangling on top of that would bury the one real fault.
    if !out.is_empty() {
        return out;
    }
    let known: std::collections::BTreeSet<u32> = entries.iter().map(|e| e.id).collect();

    for (abs, rel) in walk::walk_files(root) {
        if !CITING.iter().any(|ext| rel.ends_with(ext)) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&abs) else {
            continue;
        };
        for (at, id) in citations(&text) {
            if known.contains(&id) {
                continue;
            }
            let line = text[..at].lines().count();
            out.push(Violation {
                path: format!("{rel}:{line}"),
                reason: format!("D{id} is cited here and has no entry in {LEDGER}"),
            });
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/ledger.rs"]
mod tests;
