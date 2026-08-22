// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Unit tests for the deviation-ledger gate. Each case is a defect the ledger
//! actually had, reduced to the smallest table that carries it.

use super::*;

/// A well-formed two-row ledger.
fn good() -> String {
    std::format!(
        "# Build Graph\n\n## Deviation Ledger\n\n\
         {HEADER}\n|---|-----------|----------------|\n\
         | D1 | first gap | closed when the first thing lands |\n\
         | D2 | second gap | closed when the second thing lands |\n"
    )
}

#[test]
fn a_well_formed_ledger_is_clean() {
    let (entries, v) = check_table("l.md", &good());
    assert_eq!(v, Vec::new());
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].id, 1);
    assert_eq!(entries[1].exit, "closed when the second thing lands");
}

#[test]
fn a_blank_line_inside_the_table_is_a_violation() {
    // The defect that hid 180 rows: everything below renders as paragraphs.
    let src = good().replace("| D2 |", "\n| D2 |");
    let v = check_table("l.md", &src).1;
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].reason.contains("blank line ends the markdown table"));
}

#[test]
fn a_non_row_line_inside_the_table_is_a_violation() {
    let src = good().replace("| D2 |", "some prose\n| D2 |");
    let v = check_table("l.md", &src).1;
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].reason.contains("non-row line"));
}

#[test]
fn an_unescaped_pipe_is_a_violation_and_names_the_escape() {
    // `bus << 8 | device << 3 | function` — a code span does not protect a
    // pipe, so this row has five cells and renders as three.
    let src = good().replace("| D2 | second gap |", "| D2 | `a | b | c` |");
    let v = check_table("l.md", &src).1;
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].reason.contains("5 cells"), "{}", v[0].reason);
    assert!(v[0].reason.contains("\\|"));
}

#[test]
fn an_escaped_pipe_is_not_a_cell_boundary() {
    let src = good().replace("| D2 | second gap |", "| D2 | `a \\| b \\| c` |");
    let (entries, v) = check_table("l.md", &src);
    assert_eq!(v, Vec::new());
    assert_eq!(entries[1].exit, "closed when the second thing lands");
}

#[test]
fn a_number_used_twice_is_a_violation() {
    let src = good().replace("| D2 |", "| D1 |");
    let v = check_table("l.md", &src).1;
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].reason.contains("already used at line"));
}

#[test]
fn a_gap_in_the_numbering_is_a_violation() {
    let src = good().replace("| D2 |", "| D4 |");
    let v = check_table("l.md", &src).1;
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].reason.contains("D2, D3"), "{}", v[0].reason);
}

#[test]
fn an_empty_exit_criterion_is_a_violation() {
    let src = good().replace("closed when the second thing lands", "");
    let v = check_table("l.md", &src).1;
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].reason.contains("no exit criterion"));
}

#[test]
fn rows_out_of_order_are_not_a_violation() {
    // D54 sits beside the entry it continues, and D214 kept its position when
    // it was renumbered. Position is where a row was written; the number is
    // what it is called.
    let src = good()
        .replace("| D1 | first gap", "| D2 | second gap")
        .replace(
            "| D2 | second gap | closed when the second thing lands |",
            "| D1 | first gap | closed when the first thing lands |",
        );
    assert_eq!(check_table("l.md", &src).1, Vec::new());
}

#[test]
fn a_ledger_with_no_table_is_a_violation() {
    let v = check_table("l.md", "# Build Graph\n\nno table here\n").1;
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].reason.contains("no deviation table"));
}

#[test]
fn citations_are_word_bounded() {
    let found: Vec<u32> = citations("see D79 and D183, not 0xD1 or SD130 or D1a")
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert_eq!(found, std::vec![79, 183]);
}

#[test]
fn a_citation_at_the_start_of_the_text_is_found() {
    let found: Vec<u32> = citations("D5 opens this line")
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert_eq!(found, std::vec![5]);
}

#[test]
fn a_bare_d_is_not_a_citation() {
    assert_eq!(citations("the D register, and D."), Vec::new());
}
