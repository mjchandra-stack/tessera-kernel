// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `isl::lexer`.

use super::*;

fn kinds(src: &str) -> Vec<TokenKind> {
    let (tokens, diags) = tokenize(src);
    assert!(diags.is_empty(), "unexpected diagnostics: {diags:?}");
    tokens.into_iter().map(|t| t.kind).collect()
}

#[test]
fn lexes_keywords_idents_ints_punct() {
    let ks = kinds("struct Foo { a: uint32 = 0x1F; }");
    assert_eq!(ks[0], TokenKind::Keyword(Kw::Struct));
    assert_eq!(ks[1], TokenKind::Ident("Foo".into()));
    assert_eq!(ks[2], TokenKind::LBrace);
    assert_eq!(ks[3], TokenKind::Ident("a".into()));
    assert_eq!(ks[4], TokenKind::Colon);
    assert_eq!(ks[5], TokenKind::Keyword(Kw::Uint32));
    assert_eq!(ks[6], TokenKind::Eq);
    assert_eq!(ks[7], TokenKind::Int(0x1F));
    assert_eq!(ks[8], TokenKind::Semi);
    assert_eq!(ks[9], TokenKind::RBrace);
    assert_eq!(ks[10], TokenKind::Eof);
}

#[test]
fn keeps_comments_and_lexes_arrow() {
    let ks = kinds("// a comment\n->");
    assert_eq!(
        ks,
        vec![
            TokenKind::Doc("a comment".into()),
            TokenKind::Arrow,
            TokenKind::Eof
        ]
    );
}

/// Adjacent comment lines are one run; a blank line starts another. This is
/// what separates a declaration's own documentation from a remark that
/// happens to sit above it, and the parser drops the detached one.
#[test]
fn a_blank_line_ends_a_comment_run() {
    let ks = kinds("// first\n// still first\n\n// second\nstruct");
    assert_eq!(
        ks,
        vec![
            TokenKind::Doc("first\nstill first".into()),
            TokenKind::Doc("second".into()),
            TokenKind::Keyword(Kw::Struct),
            TokenKind::Eof
        ]
    );
}

/// `///` is the same comment as `//`, so a schema may mark a doc comment
/// explicitly without the compiler treating the two spellings as different
/// kinds of thing. An empty comment line inside a run is a paragraph break,
/// not the end of the run.
#[test]
fn triple_slash_and_empty_lines_are_part_of_the_run() {
    let ks = kinds("/// one\n//\n/// two\nstruct");
    assert_eq!(ks[0], TokenKind::Doc("one\n\ntwo".into()));
}

#[test]
fn underscores_in_ints() {
    let ks = kinds("1_000");
    assert_eq!(ks[0], TokenKind::Int(1000));
}

#[test]
fn unexpected_char_is_a_diagnostic_not_a_panic() {
    let (_, diags) = tokenize("struct % Foo");
    assert!(diags.has(Code::UnexpectedChar));
}

#[test]
fn overflowing_int_is_a_diagnostic() {
    let (_, diags) = tokenize("0xFFFFFFFFFFFFFFFFFF");
    assert!(diags.has(Code::InvalidNumber));
}
