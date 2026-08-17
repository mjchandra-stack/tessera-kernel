// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the configuration browser.
//!
//! The browser enforces the same refusals the build does, at the moment an edit
//! is made. That is the property worth testing, and it is testable because the
//! state machine is separate from the terminal: these press keys and read the
//! screen.

use super::*;
use crate::declare::parse_declaration;
use crate::profile::parse_profile;

const DECL: &str = "\
[MAX_PROCESSES]
type = size
module = process
default = 16
range = 2..=256
doc = How many processes fit.
[MAX_THREADS]
type = size
module = sched
default = 16
range = 2..=256
doc = d
[MAX_WAITERS]
type = size
module = wait
default = 16
range = 1..=256
doc = d
requires = MAX_WAITERS >= MAX_THREADS
[gpu_driver]
type = component
machines = aarch64
default = y
doc = d
[gpu_client]
type = component
machines = aarch64
default = y
doc = d
requires = gpu_client -> gpu_driver
";

fn open(profile: &str) -> (crate::Declaration, crate::profile::Overrides) {
    (
        parse_declaration(DECL).expect("parses"),
        parse_profile(profile).expect("parses"),
    )
}

/// Types a number into the setting under the cursor.
fn type_number(menu: &mut Menu<'_>, digits: &str) {
    menu.press(Key::Act);
    for c in digits.chars() {
        menu.press(Key::Char(c));
    }
    menu.press(Key::Act);
}

/// Moves the cursor to a named setting, or fails the test.
///
/// Always from the top, so a helper that only walks downwards cannot make a
/// test pass or fail on the order two settings happen to be listed in.
fn go_to(menu: &mut Menu<'_>, name: &str) {
    for _ in 0..64 {
        menu.press(Key::Up);
    }
    for _ in 0..64 {
        if menu.current() == Some(name) {
            return;
        }
        menu.press(Key::Down);
    }
    panic!("never reached {name}");
}

#[test]
fn the_cursor_starts_on_a_setting_and_never_lands_on_a_heading() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    assert!(menu.current().is_some());
    for _ in 0..40 {
        menu.press(Key::Down);
        assert!(menu.current().is_some(), "the cursor left the settings");
    }
}

#[test]
fn typing_a_number_sets_it() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    type_number(&mut menu, "32");
    assert!(menu.profile_text(&[]).contains("MAX_PROCESSES = 32"));
    assert!(menu.dirty());
}

/// The refusal the build makes, made at the moment the edit is made — and the
/// value left as it was rather than pulled to the nearest bound.
#[test]
fn a_value_below_the_minimum_is_refused_on_the_screen() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    type_number(&mut menu, "1");
    let screen = menu.render(24, 100).join("\n");
    assert!(screen.contains("outside 2..=256"), "{screen}");
    assert!(
        !menu.profile_text(&[]).contains("MAX_PROCESSES"),
        "value changed"
    );
}

/// An edit the build would refuse for an invariant is refused here too, with
/// the reason on the screen rather than in a build log an hour later.
#[test]
fn an_edit_that_breaks_an_invariant_is_refused_with_its_reason() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_THREADS");
    type_number(&mut menu, "32");
    let screen = menu.render(24, 100).join("\n");
    assert!(screen.contains("MAX_WAITERS >= MAX_THREADS"), "{screen}");
    assert!(!menu.dirty(), "a refused edit still counted as a change");
}

/// The same edit is accepted once the invariant is satisfied, which is what
/// makes the refusal a statement about the configuration rather than about the
/// setting.
#[test]
fn the_same_edit_is_accepted_once_the_invariant_holds() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_WAITERS");
    type_number(&mut menu, "32");
    go_to(&mut menu, "MAX_THREADS");
    type_number(&mut menu, "32");
    let text = menu.profile_text(&[]);
    assert!(text.contains("MAX_THREADS = 32"), "{text}");
    assert!(text.contains("MAX_WAITERS = 32"), "{text}");
}

#[test]
fn a_component_toggles() {
    let (decl, overrides) = open("gpu_client = n\n");
    let mut menu = Menu::new(&decl, overrides, "small").expect("opens");
    go_to(&mut menu, "gpu_driver");
    menu.press(Key::Act);
    assert!(menu.profile_text(&[]).contains("gpu_driver = n"));
}

#[test]
fn turning_off_a_driver_a_client_needs_is_refused() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "gpu_driver");
    menu.press(Key::Act);
    let screen = menu.render(24, 100).join("\n");
    assert!(screen.contains("gpu_client"), "{screen}");
    assert!(!menu.dirty());
}

#[test]
fn resetting_restores_the_declared_default() {
    let (decl, overrides) = open("MAX_PROCESSES = 4\n");
    let mut menu = Menu::new(&decl, overrides, "small").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    menu.press(Key::Reset);
    assert!(!menu.profile_text(&[]).contains("MAX_PROCESSES"));
}

#[test]
fn resetting_something_already_default_says_so_rather_than_pretending_to_act() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    menu.press(Key::Reset);
    assert!(
        menu.render(24, 100)
            .join("\n")
            .contains("already the default")
    );
    assert!(!menu.dirty());
}

/// An edit in progress owns the keyboard, or a stray `q` while typing a number
/// would quit with a half-typed value on the screen.
#[test]
fn keys_that_would_quit_do_not_while_a_number_is_being_typed() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    menu.press(Key::Act);
    assert_eq!(menu.press(Key::Char('q')), Outcome::Continue);
    assert_eq!(menu.press(Key::Char('4')), Outcome::Continue);
    menu.press(Key::Act);
    assert!(menu.profile_text(&[]).contains("MAX_PROCESSES = 4"));
}

#[test]
fn escape_abandons_an_edit() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    menu.press(Key::Act);
    menu.press(Key::Char('4'));
    menu.press(Key::Escape);
    assert!(!menu.dirty());
    assert!(!menu.profile_text(&[]).contains("MAX_PROCESSES"));
}

#[test]
fn a_non_digit_typed_into_a_number_is_reported_and_ignored() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    menu.press(Key::Act);
    menu.press(Key::Char('x'));
    assert!(menu.render(24, 100).join("\n").contains("not a digit"));
}

/// The whole point of moving these numbers into a declaration was that each
/// carries why it is what it is; a browser that hides that has thrown it away
/// again.
#[test]
fn the_reasoning_for_the_current_setting_is_always_on_the_screen() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    assert!(
        menu.render(24, 100)
            .join("\n")
            .contains("How many processes fit."),
        "the doc pane was empty"
    );
}

#[test]
fn an_invariant_is_shown_with_the_setting_that_declares_it() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_WAITERS");
    assert!(
        menu.render(24, 100)
            .join("\n")
            .contains("requires MAX_WAITERS >= MAX_THREADS")
    );
}

#[test]
fn save_and_quit_report_themselves() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    assert_eq!(menu.press(Key::Save), Outcome::Save);
    assert_eq!(menu.press(Key::Quit), Outcome::Quit);
}

#[test]
fn saving_clears_the_modified_marker() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "MAX_PROCESSES");
    type_number(&mut menu, "32");
    assert!(menu.render(24, 100)[0].contains("(modified)"));
    menu.press(Key::Save);
    assert!(!menu.render(24, 100)[0].contains("(modified)"));
}

/// A terminal too small for a list still gets one line of it, rather than a
/// panic on an empty range.
#[test]
fn a_tiny_terminal_renders_rather_than_panicking() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    for rows in 0..12 {
        assert!(!menu.render(rows, 20).is_empty());
    }
}

#[test]
fn the_cursor_stays_in_the_viewport_when_it_scrolls() {
    let (decl, overrides) = open("");
    let mut menu = Menu::new(&decl, overrides, "default").expect("opens");
    go_to(&mut menu, "gpu_driver");
    let screen = menu.render(12, 100);
    assert!(
        screen.iter().any(|line| line.starts_with('▸')),
        "the cursor scrolled off the screen: {screen:?}"
    );
}
