// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ISL lexer: turns source text into a token stream, accumulating a
//! diagnostic (never panicking) for anything it cannot lex. Comments are
//! `//` to end of line; identifiers are ASCII; integers are decimal or `0x`
//! hex.
//!
//! **Comments are kept.** They used to be skipped, which was right while the
//! only artifacts generated from a schema were code: a binding does not need
//! the prose. Reference documentation does, and it is generated from the same
//! definition (docs/api/03, "Generated Artifacts"), so the prose has to
//! survive lexing to reach it. Adjacent comment lines are joined into one
//! [`TokenKind::Doc`]; a blank line ends a run, which is what separates a
//! declaration's own documentation from a remark that happens to sit above it.
//! The parser strips these from the stream, so no production sees one.
//!
//! Normative: docs/api/03-interface-schema-language.md

use crate::diag::{Code, Diagnostics, Span};
use crate::token::{Kw, Token, TokenKind};

/// Lexes `src` into tokens (always ending in `Eof`) plus any diagnostics. On a
/// lexical error the offending byte is skipped and lexing continues, so one
/// run reports as many problems as possible.
pub fn tokenize(src: &str) -> (Vec<Token>, Diagnostics) {
    let bytes = src.as_bytes();
    let mut pos = 0;
    let mut tokens = Vec::new();
    let mut diags = Diagnostics::new();
    // Newlines seen since the last comment line ended. One means the next
    // comment line sits directly below the last and continues its run; two or
    // more means a blank line separated them, and the run is over.
    let mut newlines = usize::MAX;

    while pos < bytes.len() {
        let c = bytes[pos];
        match c {
            b'\n' => {
                newlines = newlines.saturating_add(1);
                pos += 1;
            }
            b' ' | b'\t' | b'\r' => pos += 1,
            b'/' if bytes.get(pos + 1) == Some(&b'/') => {
                let start = pos;
                pos += 2;
                // `///` is accepted as the same thing, so a schema may mark a
                // doc comment explicitly without the compiler treating the two
                // spellings as different kinds of comment.
                if bytes.get(pos) == Some(&b'/') {
                    pos += 1;
                }
                let text_start = pos;
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
                let text = src[text_start..pos].trim_end();
                push_comment(&mut tokens, text, start, pos, newlines);
                newlines = 0;
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let start = pos;
                while pos < bytes.len() && is_ident_byte(bytes[pos]) {
                    pos += 1;
                }
                let text = &src[start..pos];
                let kind = match Kw::from_ident(text) {
                    Some(kw) => TokenKind::Keyword(kw),
                    None => TokenKind::Ident(text.to_owned()),
                };
                tokens.push(Token {
                    kind,
                    span: Span::new(start, pos),
                });
            }
            b'0'..=b'9' => {
                let start = pos;
                let (value, next) = lex_number(src, bytes, pos, &mut diags);
                pos = next;
                tokens.push(Token {
                    kind: TokenKind::Int(value),
                    span: Span::new(start, pos),
                });
            }
            b'-' if bytes.get(pos + 1) == Some(&b'>') => {
                tokens.push(punct(TokenKind::Arrow, pos, pos + 2));
                pos += 2;
            }
            _ => {
                if let Some(kind) = single_punct(c) {
                    tokens.push(punct(kind, pos, pos + 1));
                    pos += 1;
                } else {
                    diags.error(
                        Code::UnexpectedChar,
                        Span::new(pos, pos + 1),
                        format!("unexpected character {:?}", c as char),
                    );
                    pos += 1;
                }
            }
        }
    }

    tokens.push(Token {
        kind: TokenKind::Eof,
        span: Span::point(bytes.len()),
    });
    (tokens, diags)
}

/// Appends a comment line, continuing the previous [`TokenKind::Doc`] when it
/// is the line directly above and starting a new one otherwise.
fn push_comment(tokens: &mut Vec<Token>, text: &str, start: usize, end: usize, newlines: usize) {
    let text = text.strip_prefix(' ').unwrap_or(text);
    if newlines <= 1
        && let Some(last) = tokens.last_mut()
        && let TokenKind::Doc(existing) = &mut last.kind
    {
        existing.push('\n');
        existing.push_str(text);
        last.span = Span::new(last.span.start, end);
        return;
    }
    tokens.push(Token {
        kind: TokenKind::Doc(text.to_owned()),
        span: Span::new(start, end),
    });
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn punct(kind: TokenKind, start: usize, end: usize) -> Token {
    Token {
        kind,
        span: Span::new(start, end),
    }
}

fn single_punct(c: u8) -> Option<TokenKind> {
    let kind = match c {
        b';' => TokenKind::Semi,
        b':' => TokenKind::Colon,
        b',' => TokenKind::Comma,
        b'.' => TokenKind::Dot,
        b'{' => TokenKind::LBrace,
        b'}' => TokenKind::RBrace,
        b'(' => TokenKind::LParen,
        b')' => TokenKind::RParen,
        b'<' => TokenKind::Lt,
        b'>' => TokenKind::Gt,
        b'=' => TokenKind::Eq,
        b'@' => TokenKind::At,
        b'?' => TokenKind::Question,
        _ => return None,
    };
    Some(kind)
}

/// Lexes an integer literal (decimal or `0x` hex) starting at `pos`. On
/// overflow or a malformed literal it reports a diagnostic and yields 0, so
/// lexing continues.
fn lex_number(src: &str, bytes: &[u8], pos: usize, diags: &mut Diagnostics) -> (u64, usize) {
    let start = pos;
    let mut end = pos;
    let (radix, digits_start) = if bytes[pos] == b'0' && bytes.get(pos + 1) == Some(&b'x') {
        (16, pos + 2)
    } else {
        (10, pos)
    };
    end = end.max(digits_start);
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    let digits: String = src[digits_start..end]
        .chars()
        .filter(|&c| c != '_')
        .collect();
    let value = if digits.is_empty() {
        report_bad_number(diags, start, end);
        0
    } else {
        match u64::from_str_radix(&digits, radix) {
            Ok(v) => v,
            Err(_) => {
                report_bad_number(diags, start, end);
                0
            }
        }
    };
    (value, end)
}

fn report_bad_number(diags: &mut Diagnostics, start: usize, end: usize) {
    diags.error(
        Code::InvalidNumber,
        Span::new(start, end),
        "malformed or out-of-range integer literal",
    );
}

#[cfg(test)]
#[path = "tests/lexer.rs"]
mod tests;
