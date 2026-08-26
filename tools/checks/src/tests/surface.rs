// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::surface` — the parsers the gate reads the tree with.
//! The gate itself runs against the real tree in `tests/surface.rs`; these
//! pin what it does with shapes the tree does not currently contain, which is
//! the only way to know it would catch them.

use super::*;

#[test]
fn reads_variants_their_numbers_and_their_docs() {
    let src = "\
pub enum SyscallNumber {
    /// Validated no-op.
    Null = 0,
    /// Write a buffer.
    /// Two lines of description.
    DebugWrite = 1,
    Undocumented = 2,
}
";
    let (calls, violations) = parse_rust_calls(src);
    assert_eq!(violations, Vec::new());
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].name, "Null");
    assert_eq!(calls[0].number, 0);
    assert_eq!(calls[0].doc_lines, 1);
    assert_eq!(calls[1].doc_lines, 2);
    // Counted, not judged: whether an undocumented variant is a finding is the
    // agreement's decision, not the parser's.
    assert_eq!(calls[2].doc_lines, 0);
}

/// A call number is ABI. An implicit discriminant is a number nobody wrote,
/// and the next variant inserted above it renumbers every call after it.
#[test]
fn an_implicit_discriminant_is_a_finding() {
    let (calls, violations) =
        parse_rust_calls("pub enum SyscallNumber {\n    Null,\n    A = 1,\n}\n");
    assert_eq!(calls.len(), 1);
    assert!(
        violations
            .iter()
            .any(|v| v.reason.contains("explicit discriminant")),
        "{violations:?}"
    );
}

/// The gate must fail loudly when it is looking at the wrong shape. A parser
/// that finds nothing and reports clean is worse than no gate: it reads as a
/// passing check for ever.
#[test]
fn finding_no_enum_is_itself_a_finding() {
    let (calls, violations) = parse_rust_calls("pub enum Something Else {}\n");
    assert!(calls.is_empty());
    assert!(
        violations
            .iter()
            .any(|v| v.reason.contains("reading the wrong shape")),
        "{violations:?}"
    );
}

#[test]
fn a_family_states_its_status_on_the_line_below_its_heading() {
    let doc = "\
## System Call Families

### Process And Thread

**Status: partial.** Create, start and exit exist.

- Create process.

### Virtualization

**Status: designed.** Nothing implements this.

- Create VM.

## ABI Rules

### Not A Family
";
    let (families, violations) = check_families("doc.md", doc);
    assert_eq!(violations, Vec::new());
    assert_eq!(families.len(), 2, "{families:?}");
    assert_eq!(families[0].status.as_deref(), Some("partial"));
    assert_eq!(families[1].status.as_deref(), Some("designed"));
}

#[test]
fn a_family_without_a_status_is_a_finding() {
    let doc = "## System Call Families\n\n### Memory\n\n- Create memory object.\n";
    let (families, violations) = check_families("doc.md", doc);
    assert_eq!(families.len(), 1);
    assert_eq!(families[0].status, None);
    assert!(
        violations
            .iter()
            .any(|v| v.reason.contains("does not say whether it exists")),
        "{violations:?}"
    );
}

/// A word outside the vocabulary is not a status. "Mostly done" cannot be
/// filtered on, which is the whole point of asking for one.
#[test]
fn a_status_outside_the_vocabulary_is_a_finding() {
    let doc = "## System Call Families\n\n### Memory\n\n**Status: mostly.** Some of it.\n";
    let (_, violations) = check_families("doc.md", doc);
    assert!(
        !violations.is_empty(),
        "an invented status word was accepted"
    );
}

#[test]
fn a_family_heading_immediately_followed_by_another_is_a_finding() {
    let doc = "## System Call Families\n\n### First\n\n### Second\n\n**Status: designed.** x\n";
    let (families, violations) = check_families("doc.md", doc);
    assert_eq!(families.len(), 2);
    assert_eq!(families[0].status, None);
    assert_eq!(violations.len(), 1, "{violations:?}");
}

#[test]
fn camel_case_becomes_the_enums_spelling() {
    assert_eq!(screaming_snake("HandleDuplicate"), "HANDLE_DUPLICATE");
    assert_eq!(screaming_snake("Null"), "NULL");
    assert_eq!(screaming_snake("DmaAlloc"), "DMA_ALLOC");
}
