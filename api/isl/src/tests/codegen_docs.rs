// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `isl::codegen_docs`.

use crate::compile;

fn page(src: &str) -> String {
    let (ir, diags) = compile(src);
    assert!(!diags.has_errors(), "{diags:?}");
    super::emit(&ir.expect("ir"))
}

/// The page is a build output regenerated on every build, so a byte-unstable
/// one would show up as a spurious diff for ever.
#[test]
fn the_page_is_deterministic() {
    let src = include_str!("../../examples/syscall_abi.isl");
    assert_eq!(page(src), page(src));
}

/// The call surface reaches the page: number, status, register frame, the
/// prose written above the declaration, and the rights the handle demands.
#[test]
fn a_call_reaches_the_page_whole() {
    let out = page(
        "library t.sys;\n\
         // Raise a software edge on a port.\n\
         //\n\
         // The first thing SIGNAL gates.\n\
         @status(implemented)\n\
         @available(added = 3)\n\
         syscall PortSignal = 44 {\n\
           // The port to signal.\n\
           arg0: handle<Object, {SIGNAL}>;\n\
           // The source to raise.\n\
           arg1: uint64;\n\
           // Always zero.\n\
           returns: uint64;\n\
         };\n",
    );
    assert!(out.contains("### `PortSignal` — call 44"), "{out}");
    assert!(
        out.contains("**Implemented.** Since interface version 3."),
        "{out}"
    );
    assert!(out.contains("The first thing SIGNAL gates."), "{out}");
    assert!(
        out.contains("| `arg0` | `handle<Object, {SIGNAL}>` | The port to signal. |"),
        "{out}"
    );
    assert!(out.contains("**Requires** `{SIGNAL}` on `arg0`"), "{out}");
    assert!(out.contains("**Returns** `uint64` — Always zero."), "{out}");
}

/// The summary table's links have to land. A page of fifty calls whose links
/// all miss is worse than a page with none, because it looks navigable.
#[test]
fn the_summary_links_match_the_headings() {
    let out = page(
        "library t.sys;\n\
         // A call.\n\
         @status(implemented)\n\
         syscall DmaAlloc = 24 {\n\
           arg0: uint64;\n\
         };\n",
    );
    assert!(out.contains("[`DmaAlloc`](#dmaalloc--call-24)"), "{out}");
    let heading = "### `DmaAlloc` — call 24";
    assert!(out.contains(heading), "{out}");
    // The anchor a renderer derives from that heading: punctuation dropped,
    // spaces hyphenated, lowercased.
    let derived: String = heading
        .trim_start_matches("# ")
        .trim_start_matches('#')
        .trim_start()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ' ' || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase()
        .replace(' ', "-");
    assert_eq!(derived, "dmaalloc--call-24");
}

/// A pipe inside a doc comment must not split the row it lands in. Eight rows
/// of the deviation ledger lost their last cell to exactly this, and the cell
/// that goes missing is the last one.
#[test]
fn a_pipe_in_prose_does_not_split_a_row() {
    let out = page(
        "library t.sys;\n\
         // A flag set.\n\
         bits F : uint32 {\n\
           // Set when `a | b` holds.\n\
           A = 0x1;\n\
         };\n",
    );
    let row = out
        .lines()
        .find(|l| l.contains("`A`"))
        .expect("the member's row");
    assert!(row.contains("\\|"), "the pipe was not escaped: {row}");
    assert_eq!(
        row.matches('|').count() - row.matches("\\|").count(),
        4,
        "row has the wrong number of cells: {row}"
    );
}

/// Every schema gets a page, not only the ones written with one in mind. This
/// is the argument for a backend over a hand-written document: the other
/// thirty-one schemas cost nothing.
#[test]
fn a_service_protocol_gets_its_page_too() {
    let out = page(include_str!("../../examples/block_driver.isl"));
    assert!(out.contains("## Protocol `BlockDevice`"), "{out}");
    assert!(out.contains("| 2 | `Read` | call |"), "{out}");
}
