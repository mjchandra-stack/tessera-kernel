// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the one part of the terminal shim that is not I/O.
//!
//! What is *not* covered: raw mode, drawing, and reading. Those need a
//! pseudo-terminal, and the module is deliberately small enough to read
//! instead — everything with a decision in it lives in [`crate::menu`], which
//! is tested by pressing keys.

use super::*;

#[test]
fn the_arrow_keys_decode() {
    assert_eq!(decode(b"\x1b[A"), Some(Key::Up));
    assert_eq!(decode(b"\x1b[B"), Some(Key::Down));
    assert_eq!(decode(b"\x1b[5~"), Some(Key::PageUp));
    assert_eq!(decode(b"\x1b[6~"), Some(Key::PageDown));
}

/// An escape sequence arrives as one read, so an arrow is decoded from the
/// buffer rather than by reading again and blocking on a terminal that has
/// nothing more to say. A lone escape is one byte, and means escape.
#[test]
fn a_lone_escape_is_escape_and_a_sequence_is_not() {
    assert_eq!(decode(b"\x1b"), Some(Key::Escape));
    assert_ne!(decode(b"\x1b[A"), Some(Key::Escape));
}

#[test]
fn enter_and_space_both_act() {
    assert_eq!(decode(b"\r"), Some(Key::Act));
    assert_eq!(decode(b"\n"), Some(Key::Act));
    assert_eq!(decode(b" "), Some(Key::Act));
}

#[test]
fn both_backspace_codes_decode() {
    assert_eq!(decode(&[0x7f]), Some(Key::Backspace));
    assert_eq!(decode(&[0x08]), Some(Key::Backspace));
}

/// Ctrl-C leaves, like it does everywhere else. A configuration editor that
/// traps it is one somebody has to find another way out of.
#[test]
fn ctrl_c_quits() {
    assert_eq!(decode(&[0x03]), Some(Key::Quit));
}

#[test]
fn a_digit_is_a_character_the_menu_can_type() {
    assert_eq!(decode(b"4"), Some(Key::Char('4')));
}

#[test]
fn nothing_read_is_no_key() {
    assert_eq!(decode(b""), None);
}

/// An unknown escape sequence must not be read as its final character — a
/// terminal sending one the browser does not know should not toggle a setting.
#[test]
fn an_unrecognised_sequence_does_not_act() {
    assert_eq!(decode(b"\x1b[3~"), Some(Key::Escape));
    assert_eq!(decode(b"\x1b[1;2D"), Some(Key::Escape));
}
