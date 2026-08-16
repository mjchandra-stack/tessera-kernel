// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Lexer-lite scan for `unsafe` occurrences in Rust source: comments and
//! string/char literals are stripped (so prose about unsafety never
//! counts), then the keyword is matched on identifier boundaries. This is a
//! gate, not a compiler — it is deliberately conservative and simple; the
//! compiler remains the authority on what is actually `unsafe`.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Unsafe Code")

/// Replaces comments and string/char literal contents with spaces,
/// preserving line structure so line numbers survive.
pub fn strip_noncode(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if bytes[i..].starts_with(b"//") {
            i = skip_line_comment(bytes, &mut out, i);
        } else if bytes[i..].starts_with(b"/*") {
            i = skip_block_comment(bytes, &mut out, i);
        } else if b == b'"' {
            i = skip_string(bytes, &mut out, i);
        } else if is_raw_string_start(bytes, i) {
            i = skip_raw_string(bytes, &mut out, i);
        } else if b == b'\'' {
            i = skip_char_or_lifetime(bytes, &mut out, i);
        } else {
            out[i] = b;
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn skip_line_comment(bytes: &[u8], _out: &mut [u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment(bytes: &[u8], out: &mut [u8], mut i: usize) -> usize {
    let mut depth = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
        }
        if bytes[i..].starts_with(b"/*") {
            depth += 1;
            i += 2;
        } else if bytes[i..].starts_with(b"*/") {
            depth = depth.saturating_sub(1);
            i += 2;
            if depth == 0 {
                break;
            }
        } else {
            i += 1;
        }
    }
    i
}

fn skip_string(bytes: &[u8], out: &mut [u8], mut i: usize) -> usize {
    i += 1; // opening quote
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => {
                i += 1;
                break;
            }
            b'\n' => {
                out[i] = b'\n';
                i += 1;
            }
            _ => i += 1,
        }
    }
    i
}

/// Matches `r"`, `r#"`, `br"`, `br##"` … at position `i`.
fn is_raw_string_start(bytes: &[u8], mut i: usize) -> bool {
    if bytes.get(i) == Some(&b'b') {
        i += 1;
    }
    if bytes.get(i) != Some(&b'r') {
        return false;
    }
    i += 1;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    bytes.get(i) == Some(&b'"')
}

fn skip_raw_string(bytes: &[u8], out: &mut [u8], mut i: usize) -> usize {
    if bytes.get(i) == Some(&b'b') {
        i += 1;
    }
    i += 1; // 'r'
    let mut hashes = 0usize;
    while bytes.get(i) == Some(&b'#') {
        hashes += 1;
        i += 1;
    }
    i += 1; // opening quote
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if bytes[i] == b'"' {
            let mut j = i + 1;
            let mut seen = 0usize;
            while seen < hashes && bytes.get(j) == Some(&b'#') {
                seen += 1;
                j += 1;
            }
            i = j;
            if seen == hashes {
                break;
            }
        } else {
            i += 1;
        }
    }
    i
}

/// A `'` is a char literal only if it closes within a short window
/// (`'a'`, `'\n'`, `'\u{7fff}'`); otherwise it is a lifetime and code
/// scanning continues.
fn skip_char_or_lifetime(bytes: &[u8], out: &mut [u8], i: usize) -> usize {
    let window = 12usize.min(bytes.len() - i);
    let mut j = i + 1;
    if bytes.get(j) == Some(&b'\\') {
        j += 2;
        while j < i + window && bytes.get(j).is_some_and(|b| *b != b'\'') {
            j += 1;
        }
        if bytes.get(j) == Some(&b'\'') {
            return j + 1;
        }
    } else if j < bytes.len() && bytes.get(j + 1) == Some(&b'\'') && bytes[j] != b'\'' {
        return j + 2;
    }
    // Lifetime (or malformed): emit the quote as-is and move on.
    out[i] = b'\'';
    i + 1
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// 1-based line numbers (in the original source) containing the `unsafe`
/// keyword outside comments and literals. One entry per line.
pub fn unsafe_lines(src: &str) -> Vec<usize> {
    let stripped = strip_noncode(src);
    let mut lines = Vec::new();
    for (idx, line) in stripped.lines().enumerate() {
        let bytes = line.as_bytes();
        let mut start = 0;
        while let Some(pos) = line[start..].find("unsafe") {
            let p = start + pos;
            let before_ok = p == 0 || !is_ident_byte(bytes[p - 1]);
            let after = p + "unsafe".len();
            let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
            if before_ok && after_ok {
                lines.push(idx + 1);
                break;
            }
            start = after;
        }
    }
    lines
}

/// True if 1-based `line` is annotated with its safety invariant: a
/// `SAFETY:` comment (unsafe *uses*) or a `# Safety` doc section (unsafe
/// *declarations*). The search walks the `window` lines directly above,
/// then keeps going only while inside a contiguous comment/attribute block
/// — a doc block may be long, but plain code between the annotation and
/// the `unsafe` breaks the association.
pub fn has_safety_comment(src: &str, line: usize, window: usize) -> bool {
    let all: Vec<&str> = src.lines().collect();
    let mut idx = line.saturating_sub(1); // 0-based index of the unsafe line
    let mut distance = 0usize;
    while idx > 0 {
        idx -= 1;
        distance += 1;
        let Some(text) = all.get(idx).map(|l| l.trim_start()) else {
            return false;
        };
        if text.contains("SAFETY:") || text.contains("# Safety") {
            return true;
        }
        let is_annotation =
            text.starts_with("//") || text.starts_with("#[") || text.starts_with("#!");
        if distance >= window && !is_annotation {
            return false;
        }
    }
    false
}

#[cfg(test)]
#[path = "tests/scan.rs"]
mod tests;
