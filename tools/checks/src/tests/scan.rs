// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::scan`.

use super::*;

#[test]
fn finds_unsafe_block_fn_impl_attr() {
    let src = "unsafe fn f() {}\nfn g() { unsafe { h() } }\nunsafe impl Send for X {}\n#[unsafe(no_mangle)]\nfn i() {}\n";
    assert_eq!(unsafe_lines(src), vec![1, 2, 3, 4]);
}

#[test]
fn ignores_comments_strings_and_identifiers() {
    let src = "// unsafe in a comment\n/* unsafe */\nlet s = \"unsafe\";\nlet r = r#\"unsafe\"#;\n#![deny(unsafe_code)]\nlet unsafe_flag = 1;\n";
    assert_eq!(unsafe_lines(src), Vec::<usize>::new());
}

#[test]
fn lifetimes_do_not_open_literals() {
    let src = "fn f<'a>(x: &'a str) { unsafe { g(x) } }\n";
    assert_eq!(unsafe_lines(src), vec![1]);
}

#[test]
fn char_literals_are_stripped() {
    let src = "let c = 'u'; let d = '\\n';\nunsafe { f() }\n";
    assert_eq!(unsafe_lines(src), vec![2]);
}

#[test]
fn safety_comment_window() {
    let src = "// SAFETY: the invariant holds because reasons.\n#[unsafe(no_mangle)]\nfn f() {}\n";
    assert!(has_safety_comment(src, 2, 3));
    let no_comment = "fn a() {}\nunsafe { f() }\n";
    assert!(!has_safety_comment(no_comment, 2, 3));
    // Beyond the window with plain code in between: not associated.
    let far = "// SAFETY: too far away.\nfn a() {}\nfn b() {}\nfn c() {}\nunsafe { f() }\n";
    assert!(!has_safety_comment(far, 5, 3));
}

#[test]
fn safety_doc_section_covers_unsafe_fn_declarations() {
    let src = "/// Does things.\n///\n/// # Safety\n///\n/// Caller must own the region.\n/// More prose.\n/// Even more prose.\npub unsafe fn init() {}\n";
    assert!(has_safety_comment(src, 8, 3));
    // Plain code between the doc block and the unsafe line breaks it.
    let broken = "/// # Safety\nfn other() {}\nfn more() {}\nfn yet_more() {}\nunsafe fn f() {}\n";
    assert!(!has_safety_comment(broken, 5, 3));
}

#[test]
fn nested_block_comments() {
    let src = "/* outer /* unsafe */ still comment */\nunsafe { f() }\n";
    assert_eq!(unsafe_lines(src), vec![2]);
}

/// A backslash line-continuation inside a string literal must not swallow the
/// newline, or every line number after it shifts.
///
/// `skip_string` steps over an escape with `i += 2`, which is right for `\n`
/// the two-character escape and wrong for a backslash that is followed by an
/// actual newline: the newline is consumed without being written out, the
/// stripped text has one fewer line than the source, and every `unsafe` below
/// is reported one line early.
#[test]
fn a_line_continuation_in_a_string_keeps_its_line() {
    let src = "let s = \"a \\\n    b\";\nunsafe { f() }\n";
    assert_eq!(
        unsafe_lines(src),
        vec![3],
        "the unsafe is on line 3 of the source and must be reported there",
    );
}

/// The direction that matters: the shift does not merely misreport a line, it
/// asks about the wrong one — so a real unannotated `unsafe` can be shifted
/// onto somebody else's SAFETY comment and pass the gate silently.
///
/// The fixture is built for exactly that. Line 7 is unannotated: the nearest
/// SAFETY comment is on line 3, four lines up, outside the window. Shift every
/// site one line early and line 7 is asked about as line 6 — which *is* within
/// three lines of that comment, and passes. Before the fix this reported one
/// violation on line 3, the annotated site, and none on line 7.
#[test]
fn a_line_continuation_cannot_hide_an_unannotated_unsafe() {
    let src = concat!(
        "let s = \"a \\\n",                     // 1: a string with a line continuation...
        "    b\";\n",                           // 2: ...closing here
        "// SAFETY: the call below is fine.\n", // 3
        "unsafe { g() }\n",                     // 4: annotated
        "let a = 1;\n",                         // 5
        "let b = 2;\n",                         // 6
        "unsafe { h() }\n",                     // 7: NOT annotated
    );
    let sites = unsafe_lines(src);
    assert_eq!(
        sites,
        vec![4, 7],
        "sites are reported at their source lines"
    );
    let unannotated: Vec<usize> = sites
        .into_iter()
        .filter(|&line| !has_safety_comment(src, line, 3))
        .collect();
    assert_eq!(
        unannotated,
        vec![7],
        "an unsafe with no SAFETY comment must be caught, not shifted onto one",
    );
}
