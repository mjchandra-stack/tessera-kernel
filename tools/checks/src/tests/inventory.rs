// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::inventory`.

use super::*;

const GOOD: &str = r#"
# comment
[[entry]]
file = "kernel/x/src/a.rs"
owner = "someone@example.com"
scope = "MMIO access"
justification = "hardware registers have no safe expression"
"#;

#[test]
fn parses_complete_entry() {
    let (entries, violations) = parse("unsafe-inventory.toml", GOOD);
    assert!(violations.is_empty(), "{violations:?}");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file, "kernel/x/src/a.rs");
}

#[test]
fn reports_missing_fields_and_bad_lines() {
    let (entries, violations) = parse(
        "unsafe-inventory.toml",
        "[[entry]]\nfile = \"a.rs\"\nnonsense\n",
    );
    assert!(entries.is_empty());
    assert!(violations.iter().any(|v| v.reason.contains("nonsense")));
    assert!(
        violations
            .iter()
            .any(|v| v.reason.contains("missing required"))
    );
}

#[test]
fn field_outside_entry_is_an_error() {
    let (_, violations) = parse("unsafe-inventory.toml", "file = \"a.rs\"\n");
    assert!(violations.iter().any(|v| v.reason.contains("outside")));
}
