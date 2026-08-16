// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Unit tests for the log-line length gate.

use super::*;

fn long(n: usize) -> String {
    "x".repeat(n)
}

#[test]
fn a_short_line_is_clean() {
    let src = format!("fn f() {{ kprintln!(\"{}\"); }}\n", long(10));
    assert_eq!(check_file("a.rs", &src), Vec::new());
}

#[test]
fn a_line_at_the_limit_is_clean() {
    let src = format!("kprintln!(\"{}\");\n", long(MAX_LINE));
    assert_eq!(check_file("a.rs", &src), Vec::new());
}

#[test]
fn one_character_over_is_a_violation() {
    let src = format!("kprintln!(\"{}\");\n", long(MAX_LINE + 1));
    let v = check_file("a.rs", &src);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(
        v[0].reason
            .contains(&format!("{} characters", MAX_LINE + 1))
    );
}

#[test]
fn the_violation_names_the_line() {
    let src = format!(
        "fn f() {{\n\n    kprintln!(\n        \"{}\"\n    );\n}}\n",
        long(200)
    );
    let v = check_file("k/m.rs", &src);
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].path, "k/m.rs:4");
}

#[test]
fn the_multi_line_call_form_is_found() {
    let src = format!("kprintln!(\n    \"{}\",\n    value\n);\n", long(200));
    assert_eq!(check_file("a.rs", &src).len(), 1);
}

#[test]
fn kprint_without_ln_is_checked_too() {
    let src = format!("kprint!(\"{}\");\n", long(200));
    assert_eq!(check_file("a.rs", &src).len(), 1);
}

/// An escaped quote does not end the literal, so a line carrying one is still
/// measured whole.
#[test]
fn an_escaped_quote_does_not_end_the_literal() {
    let src = format!("kprintln!(\"a\\\"b{}\");\n", long(200));
    assert_eq!(check_file("a.rs", &src).len(), 1);
}

/// A call whose first argument is not a literal is something this gate cannot
/// measure; it must stay quiet rather than guess.
#[test]
fn a_non_literal_format_is_left_alone() {
    assert_eq!(check_file("a.rs", "kprintln!(fmt);\n"), Vec::new());
}

/// `kprintln` inside a longer identifier is not a call.
#[test]
fn a_longer_identifier_is_not_a_call() {
    let src = format!("fn my_kprintln_helper() {{}} // \"{}\"\n", long(200));
    assert_eq!(check_file("a.rs", &src), Vec::new());
}
