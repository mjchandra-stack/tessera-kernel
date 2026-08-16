// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ISL lexer: turns source text into a token stream, accumulating a
//! diagnostic (never panicking) for anything it cannot lex. Comments are
//! `//` to end of line; identifiers are ASCII; integers are decimal or `0x`
//! hex.
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

    while pos < bytes.len() {
        let c = bytes[pos];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => pos += 1,
            b'/' if bytes.get(pos + 1) == Some(&b'/') => {
                pos += 2;
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
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
