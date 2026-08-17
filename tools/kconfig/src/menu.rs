// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The interactive configuration browser, as a state machine.
//!
//! **Why the state machine is separate from the terminal.** A configuration
//! editor that only exists as terminal I/O is one nothing can test, and this
//! one enforces the same refusals the build does — a value outside its range,
//! an invariant a change would break. Those refusals are the substance, so they
//! live here, where a test presses keys and reads the screen, and
//! [`crate::term`] is left holding nothing but bytes in and bytes out.
//!
//! **Every edit is a full resolution.** Pressing a key builds the profile that
//! key would produce and resolves it against the declaration, exactly as the
//! build would. An edit the build would refuse is refused here, at the moment
//! it is made, with the reason on the screen — rather than discovered later by
//! a build that has forgotten which keystroke caused it. It also means the menu
//! cannot drift from the build: there is one resolver, and this is a caller of
//! it.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md

use crate::profile::{Overrides, write_profile};
use crate::resolve::{Config, ordered, resolve};
use crate::{Declaration, Kind, Value};

/// A key press, already decoded from whatever the terminal sent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Up,
    Down,
    PageUp,
    PageDown,
    /// Enter or space: toggle an on/off setting, start or commit an edit.
    Act,
    /// A character typed into an edit.
    Char(char),
    Backspace,
    /// Escape: abandon an edit in progress.
    Escape,
    /// Restore this setting to the declared default.
    Reset,
    Save,
    Quit,
}

/// What the caller should do after a key press.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Continue,
    /// Write [`Menu::profile_text`] out.
    Save,
    Quit,
}

/// A line of the list: a group heading, or a setting the cursor can land on.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Row {
    Heading(String),
    Setting(String),
}

/// The browser's whole state.
pub struct Menu<'a> {
    declaration: &'a Declaration,
    overrides: Overrides,
    config: Config<'a>,
    rows: Vec<Row>,
    cursor: usize,
    top: usize,
    /// The digits typed so far, when a size is being edited.
    editing: Option<String>,
    /// The last refusal or confirmation, shown instead of the key hints.
    message: Option<String>,
    /// Whether anything has changed since the last save.
    dirty: bool,
}

impl<'a> Menu<'a> {
    /// Opens the browser on a resolved configuration.
    ///
    /// The starting point must already resolve: a menu that opens on a broken
    /// profile would have to describe a state it cannot represent, and the
    /// caller has a better place to report that.
    pub fn new(declaration: &'a Declaration, overrides: Overrides, profile: &str) -> Option<Self> {
        let config = resolve(declaration, &overrides, profile).ok()?;
        let mut rows = Vec::new();
        let mut group = None;
        for (name, setting) in ordered(declaration) {
            let heading = setting.group();
            if group.as_ref() != Some(&heading) {
                rows.push(Row::Heading(heading.clone()));
                group = Some(heading);
            }
            rows.push(Row::Setting(name.clone()));
        }
        let cursor = rows
            .iter()
            .position(|r| matches!(r, Row::Setting(_)))
            .unwrap_or_default();
        Some(Self {
            declaration,
            overrides,
            config,
            rows,
            cursor,
            top: 0,
            editing: None,
            message: None,
            dirty: false,
        })
    }

    /// The setting the cursor is on.
    pub fn current(&self) -> Option<&str> {
        match self.rows.get(self.cursor)? {
            Row::Setting(name) => Some(name),
            Row::Heading(_) => None,
        }
    }

    /// The profile this configuration would be saved as.
    pub fn profile_text(&self, header: &[String]) -> String {
        write_profile(&self.config, header)
    }

    /// Whether anything has changed since the last save.
    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// Handles one key press.
    pub fn press(&mut self, key: Key) -> Outcome {
        self.message = None;
        // An edit in progress owns the keyboard. Otherwise a stray `q` while
        // typing `4` would quit with a half-typed number on the screen.
        if self.editing.is_some() {
            return self.press_editing(key);
        }
        match key {
            Key::Up => self.step(-1),
            Key::Down => self.step(1),
            Key::PageUp => {
                for _ in 0..10 {
                    self.step(-1);
                }
            }
            Key::PageDown => {
                for _ in 0..10 {
                    self.step(1);
                }
            }
            Key::Act => self.act(),
            Key::Reset => self.reset(),
            Key::Save => {
                self.dirty = false;
                return Outcome::Save;
            }
            Key::Quit => return Outcome::Quit,
            Key::Char(_) | Key::Backspace | Key::Escape => {}
        }
        Outcome::Continue
    }

    fn press_editing(&mut self, key: Key) -> Outcome {
        let Some(buffer) = self.editing.as_mut() else {
            return Outcome::Continue;
        };
        match key {
            Key::Char(c) if c.is_ascii_digit() => buffer.push(c),
            Key::Char(c) => {
                self.message = Some(format!("`{c}` is not a digit"));
            }
            Key::Backspace => {
                buffer.pop();
            }
            Key::Escape => {
                self.editing = None;
            }
            Key::Act => {
                let typed = self.editing.take().unwrap_or_default();
                self.commit(&typed);
            }
            _ => {}
        }
        Outcome::Continue
    }

    /// Commits a typed size.
    fn commit(&mut self, typed: &str) {
        let Some(name) = self.current().map(str::to_owned) else {
            return;
        };
        if typed.is_empty() {
            self.message = Some("nothing typed — value unchanged".to_owned());
            return;
        }
        match typed.parse::<u64>() {
            Ok(v) => self.apply(&name, Some(Value::Int(v))),
            // Only digits can be typed, so this is a number too long for a
            // `u64` rather than a malformed one.
            Err(_) => self.message = Some(format!("{typed} is too large")),
        }
    }

    /// Toggles an on/off setting, or begins editing a size.
    fn act(&mut self) {
        let Some(name) = self.current().map(str::to_owned) else {
            return;
        };
        let Some(setting) = self.declaration.get(&name) else {
            return;
        };
        match setting.kind {
            Kind::Size { .. } => self.editing = Some(String::new()),
            Kind::Feature { .. } | Kind::Component => {
                let now = self.config.is_on(&name);
                self.apply(&name, Some(Value::Bool(!now)));
            }
        }
    }

    /// Restores the setting under the cursor to its declared default.
    fn reset(&mut self) {
        let Some(name) = self.current().map(str::to_owned) else {
            return;
        };
        if !self.overrides.contains_key(&name) {
            self.message = Some(format!("{name} is already the default"));
            return;
        }
        self.apply(&name, None);
    }

    /// Resolves the configuration this change would produce, and keeps it only
    /// if the build would have accepted it.
    fn apply(&mut self, name: &str, value: Option<Value>) {
        let mut candidate = self.overrides.clone();
        match value {
            Some(v) => {
                candidate.insert(name.to_owned(), v);
            }
            None => {
                candidate.remove(name);
            }
        }
        match resolve(self.declaration, &candidate, &self.config.profile) {
            Ok(config) => {
                self.config = config;
                self.overrides = candidate;
                self.dirty = true;
            }
            // The first refusal is the one to show. A change that breaks three
            // invariants is still one change to undo, and three lines of
            // explanation on a status line is none of them read.
            Err(errors) => {
                self.message = errors.first().map(|e| e.message.clone());
            }
        }
    }

    /// Moves the cursor by `delta` settings, skipping headings.
    fn step(&mut self, delta: isize) {
        let mut at = self.cursor;
        loop {
            let next = at as isize + delta;
            if next < 0 || next as usize >= self.rows.len() {
                return;
            }
            at = next as usize;
            if matches!(self.rows[at], Row::Setting(_)) {
                self.cursor = at;
                return;
            }
        }
    }

    /// The screen, as lines. `rows` and `cols` are the terminal's size.
    pub fn render(&mut self, rows: usize, cols: usize) -> Vec<String> {
        // Four lines of chrome above the list (title, rule) and below it (rule,
        // doc, rule, status). A terminal too small for a list still gets one
        // line of it rather than a panic on an empty range.
        const CHROME: usize = 9;
        let list_height = rows.saturating_sub(CHROME).max(1);
        self.scroll(list_height);

        let mut out = Vec::new();
        out.push(clip(
            &format!(
                "Tessera configuration — profile `{}`{}",
                self.config.profile,
                if self.dirty { " (modified)" } else { "" }
            ),
            cols,
        ));
        out.push("─".repeat(cols.min(80)));

        for index in self.top..(self.top + list_height).min(self.rows.len()) {
            out.push(clip(&self.row_text(index), cols));
        }
        for _ in self.rows.len().saturating_sub(self.top)..list_height {
            out.push(String::new());
        }

        out.push("─".repeat(cols.min(80)));
        out.extend(self.doc_pane(cols));
        out.push("─".repeat(cols.min(80)));
        out.push(clip(
            &self.message.clone().unwrap_or_else(|| {
                "↑↓ move · space edit/toggle · d default · s save · q quit".to_owned()
            }),
            cols,
        ));
        out
    }

    fn row_text(&self, index: usize) -> String {
        match &self.rows[index] {
            Row::Heading(title) => format!("  {title}"),
            Row::Setting(name) => {
                let Some(setting) = self.declaration.get(name) else {
                    return String::new();
                };
                let here = index == self.cursor;
                let value = match (here, &self.editing) {
                    (true, Some(buffer)) => format!("{buffer}_"),
                    _ => self
                        .config
                        .get(name)
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                };
                let bounds = match &setting.kind {
                    Kind::Size { min, max, .. } => format!("[{min}..={max}]"),
                    Kind::Feature { cfg } => format!("[--cfg={cfg}]"),
                    Kind::Component => "[y/n]".to_owned(),
                };
                format!(
                    "{} {name:<26} {value:>8}  {bounds:<16}{}",
                    if here { "▸" } else { " " },
                    if self.overridden(name) { "*" } else { "" }
                )
            }
        }
    }

    fn overridden(&self, name: &str) -> bool {
        self.config.overridden.contains(name)
    }

    /// The reasoning for the setting under the cursor.
    ///
    /// Always shown, never behind a key. The whole point of moving these
    /// numbers into a declaration was that each carries why it is what it is;
    /// a browser that hides that is a browser that has thrown it away again.
    fn doc_pane(&self, cols: usize) -> Vec<String> {
        const HEIGHT: usize = 4;
        let mut lines = Vec::new();
        if let Some(name) = self.current()
            && let Some(setting) = self.declaration.get(name)
        {
            lines.push(clip(&format!("{name} — default {}", setting.default), cols));
            for line in setting.doc.iter().filter(|l| !l.is_empty()) {
                lines.push(clip(&format!("  {line}"), cols));
            }
            for requirement in &setting.requires {
                lines.push(clip(&format!("  requires {requirement}"), cols));
            }
        }
        lines.truncate(HEIGHT);
        while lines.len() < HEIGHT {
            lines.push(String::new());
        }
        lines
    }

    /// Keeps the cursor inside the viewport.
    fn scroll(&mut self, height: usize) {
        if self.cursor < self.top {
            self.top = self.cursor;
        }
        // One row above the cursor, when there is one, so the group heading a
        // setting sits under stays visible while stepping into a new group.
        if self.cursor >= self.top + height {
            self.top = self.cursor + 1 - height;
        }
        self.top = self.top.min(self.rows.len().saturating_sub(height));
    }
}

/// Truncates to the terminal's width, counting characters rather than bytes.
fn clip(text: &str, cols: usize) -> String {
    if text.chars().count() <= cols {
        return text.to_owned();
    }
    text.chars().take(cols).collect()
}

#[cfg(test)]
#[path = "tests/menu.rs"]
mod tests;
