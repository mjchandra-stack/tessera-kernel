// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the ABI gate.

use super::*;

const SCHEMA: &str = "library tessera.demo;\n\n// A structured argument.\n@abi\n\
                      struct Args {\n    size: uint32;\n    version: uint32;\n    \
                      flags: uint64;\n    first: uint32;\n    second: uint64;\n};\n";

fn locked(entries: &[(&str, &str)], version: u32) -> Lock {
    let schemas: BTreeMap<String, String> = entries
        .iter()
        .map(|(n, d)| ((*n).to_owned(), (*d).to_owned()))
        .collect();
    Lock {
        version: Some(version),
        surface: Some(surface_digest(&schemas)),
        schemas,
    }
}

#[test]
fn a_lock_that_matches_the_tree_is_clean() {
    let digest = schema_digest(SCHEMA).expect("the schema compiles");
    let tree: BTreeMap<String, String> = [("demo".to_owned(), digest.clone())].into();
    assert_eq!(compare(&locked(&[("demo", &digest)], 1), &tree), Vec::new());
}

/// The claim the gate is for: a layout change is a different ABI. The two
/// fields have different widths, so swapping them moves an offset rather than
/// only a name — the change a diff over source text can see but cannot tell
/// apart from a rename.
#[test]
fn reordering_two_fields_changes_the_digest() {
    let swapped = SCHEMA.replace(
        "    first: uint32;\n    second: uint64;\n",
        "    second: uint64;\n    first: uint32;\n",
    );
    assert_ne!(schema_digest(SCHEMA), schema_digest(&swapped));
}

/// And the other half of "compiled IR, not source text": prose is not ABI, so
/// rewrapping a comment must leave the published surface alone. A digest over
/// source text fails this, which is why `docs/api/03` specifies the IR.
#[test]
fn rewriting_a_doc_comment_does_not_change_the_digest() {
    let reworded = SCHEMA.replace(
        "// A structured argument.",
        "// A structured argument, in rather more words than before.",
    );
    assert_eq!(schema_digest(SCHEMA), schema_digest(&reworded));
}

#[test]
fn a_changed_schema_is_reported_by_name() {
    let digest = schema_digest(SCHEMA).expect("the schema compiles");
    let tree: BTreeMap<String, String> = [("demo".to_owned(), digest)].into();
    let found = compare(&locked(&[("demo", &"0".repeat(64))], 1), &tree);
    assert!(
        found
            .iter()
            .any(|v| v.reason.contains("schema `demo`") && v.reason.contains("the ABI changed")),
        "{found:?}"
    );
}

#[test]
fn a_schema_the_lock_does_not_know_is_a_violation() {
    let digest = schema_digest(SCHEMA).expect("the schema compiles");
    let tree: BTreeMap<String, String> = [("demo".to_owned(), digest)].into();
    let found = compare(&locked(&[], 1), &tree);
    assert!(
        found
            .iter()
            .any(|v| v.reason.contains("in the tree and not in the lock")),
        "{found:?}"
    );
}

/// A published interface is not withdrawn by deleting the file that defines it.
#[test]
fn a_schema_only_the_lock_knows_is_a_violation() {
    let found = compare(&locked(&[("demo", &"0".repeat(64))], 1), &BTreeMap::new());
    assert!(
        found
            .iter()
            .any(|v| v.reason.contains("in the lock and not in the tree")),
        "{found:?}"
    );
}

#[test]
fn a_surface_digest_that_does_not_cover_the_schemas_is_a_violation() {
    let digest = schema_digest(SCHEMA).expect("the schema compiles");
    let tree: BTreeMap<String, String> = [("demo".to_owned(), digest.clone())].into();
    let mut lock = locked(&[("demo", &digest)], 1);
    lock.surface = Some("f".repeat(64));
    let found = compare(&lock, &tree);
    assert!(
        found
            .iter()
            .any(|v| v.reason.contains("the surface digest")),
        "{found:?}"
    );
}

#[test]
fn a_lock_with_no_version_is_a_violation() {
    let mut lock = locked(&[], 1);
    lock.version = None;
    assert!(
        compare(&lock, &BTreeMap::new())
            .iter()
            .any(|v| v.reason.contains("abi-version")),
    );
}

#[test]
fn the_lock_format_parses() {
    let text = "# a comment\nabi-version = 3\nsurface = abc\n\ndemo 0123\nother 4567\n";
    let lock = parse_lock(text);
    assert_eq!(lock.version, Some(3));
    assert_eq!(lock.surface.as_deref(), Some("abc"));
    assert_eq!(lock.schemas.get("demo").map(String::as_str), Some("0123"));
    assert_eq!(lock.schemas.get("other").map(String::as_str), Some("4567"));
}

#[test]
fn the_version_a_program_was_built_against_is_read() {
    let source = "//! doc\npub const ABI_VERSION: u32 = 7;\n";
    assert_eq!(uabi_version(source), Some(7));
    assert_eq!(uabi_version("pub const OTHER: u32 = 7;\n"), None);
}
