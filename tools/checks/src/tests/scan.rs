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
