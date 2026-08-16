// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **log-line length gate**: no `kprint!`/`kprintln!` format string longer
//! than [`MAX_LINE`].
//!
//! This is the cheap half of the rule. What a person reads is the *rendered*
//! line — the format string plus the `[<ticks> <module>] ` envelope plus
//! whatever the values expand to — and no static check can know that, so every
//! boot check asserts it against the serial log the machine actually produced.
//! This gate catches the same defect one build earlier, where the fix is
//! obvious and does not need an emulator.
//!
//! A format string this long is not a long *message*: it is prose that has been
//! put on the wire instead of in a comment. `docs/lifecycle/04` already says
//! where prose belongs.
//!
//! Normative: docs/observability/01-debugging-monitoring-tracing-logging.md,
//! docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use crate::{Violation, walk};
use std::path::Path;

/// The longest a log line may be. The boot checks hold the rendered line to the
/// same number.
pub const MAX_LINE: usize = 150;

/// Returns a violation for each over-long format string in `content`.
pub fn check_file(rel: &str, content: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (index, literal) in format_literals(content) {
        if literal.chars().count() > MAX_LINE {
            let line = content[..index].lines().count();
            out.push(Violation {
                path: format!("{rel}:{line}"),
                reason: format!(
                    "log format string is {} characters (max {MAX_LINE}); the prose belongs \
                     in a comment and the message stays minimal",
                    literal.chars().count()
                ),
            });
        }
    }
    out
}

/// Every `kprint!`/`kprintln!` format string in `content`, as (byte offset,
/// literal). The format string is the first string literal after the macro
/// name, which is where `format_args!` requires it.
///
/// Skips string literals, character literals and comments while looking for the
/// macro name — the gate's own source contains `"kprintln!("` as data, and a
/// scanner that cannot tell code from text reports on itself.
fn format_literals(content: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let b = content.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                i += content[i..].find('\n').map_or(content.len() - i, |n| n + 1);
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += content[i + 2..]
                    .find("*/")
                    .map_or(content.len() - i, |n| n + 4);
            }
            b'r' if matches!(b.get(i + 1), Some(&b'"') | Some(&b'#')) => {
                let hashes = content[i + 1..].bytes().take_while(|c| *c == b'#').count();
                let open = i + 1 + hashes;
                if b.get(open) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                i = content[open + 1..]
                    .find(&close)
                    .map_or(content.len(), |n| open + 1 + n + close.len());
            }
            b'"' => {
                i = closing_quote(content, i + 1).map_or(content.len(), |e| e + 1);
            }
            b'\'' => {
                // A character literal must be stepped over whole: `b'"'` holds a
                // double quote, and landing on it would open a string that never
                // closes. Anything else is a lifetime, which is one character.
                i += match (b.get(i + 1), b.get(i + 2), b.get(i + 3)) {
                    (Some(&b'\\'), _, Some(&b'\'')) => 4,
                    (_, Some(&b'\''), _) => 3,
                    _ => 1,
                };
            }
            b'k' if is_call(content, i) => {
                let open = i + content[i..].find('(').unwrap_or(0) + 1;
                match next_quote(content, open)
                    .and_then(|q| closing_quote(content, q + 1).map(|e| (q, e)))
                {
                    Some((q, e)) => {
                        out.push((q, &content[q + 1..e]));
                        i = e + 1;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Whether a `kprint!`/`kprintln!` call starts at `at`, and not the tail of a
/// longer identifier.
fn is_call(content: &str, at: usize) -> bool {
    let rest = &content[at..];
    if !(rest.starts_with("kprintln!(") || rest.starts_with("kprint!(")) {
        return false;
    }
    let before = content.as_bytes().get(at.wrapping_sub(1));
    at == 0 || !matches!(before, Some(c) if c.is_ascii_alphanumeric() || *c == b'_')
}

/// The next `"` at or after `from`, skipping whitespace only — anything else
/// means the call does not open with a literal (a variable, a nested macro),
/// and this gate has nothing to say about it.
fn next_quote(content: &str, from: usize) -> Option<usize> {
    content[from..]
        .char_indices()
        .find(|(_, c)| !c.is_whitespace())
        .filter(|(_, c)| *c == '"')
        .map(|(i, _)| from + i)
}

/// The closing `"` of a literal opened at `from`, honouring `\"`.
fn closing_quote(content: &str, from: usize) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in content[from..].char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(from + i);
        }
    }
    None
}

/// Checks every Rust source under `root`.
pub fn check(root: &Path) -> Vec<Violation> {
    let mut out = Vec::new();
    for (abs, rel) in walk::walk_files(root) {
        if !rel.ends_with(".rs") {
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
#[path = "tests/logging.rs"]
mod tests;
