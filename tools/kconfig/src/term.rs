// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The terminal the browser runs on: bytes in, bytes out, and nothing else.
//!
//! **Why this is so thin.** Everything a reader would want tested about the
//! configuration browser — which values it accepts, which it refuses and why,
//! what it writes back out — is in [`crate::menu`], which is pure. What is left
//! here cannot be unit-tested without a pseudo-terminal, so what is left here
//! is kept small enough to read instead: put the terminal in raw mode, turn
//! bytes into [`Key`]s, and paint lines.
//!
//! **Why `stty` and not a crate.** This tree vendors no third-party code, and
//! the alternative to shelling out is `libc` and a `termios` binding — that is,
//! `unsafe`, in a host tool, to avoid running a program every terminal already
//! has. The cost is that the interactive menu needs `stty` on `PATH`; the build
//! does not, because no build step runs this module.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md

use crate::menu::Key;
use std::io::{IsTerminal, Read, Write};
use std::process::Command;

/// A terminal in raw mode, restored when it is dropped.
pub struct Terminal {
    /// What `stty -g` said before anything was changed, which is the only
    /// faithful way to put a terminal back: the settings this program did not
    /// touch are as much a part of it as the ones it did.
    saved: Option<String>,
}

/// The reason the browser cannot run.
#[derive(Debug)]
pub enum OpenError {
    /// Standard input is not a terminal, so there is nobody to browse.
    NotATerminal,
    /// `stty` could not be run or did not succeed.
    NoStty(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::NotATerminal => write!(
                f,
                "stdin is not a terminal; `menu` is interactive (try `show` or `diff`)"
            ),
            OpenError::NoStty(why) => write!(f, "cannot put the terminal in raw mode: {why}"),
        }
    }
}

impl Terminal {
    /// Puts the terminal in raw mode.
    pub fn open() -> Result<Self, OpenError> {
        if !std::io::stdin().is_terminal() {
            return Err(OpenError::NotATerminal);
        }
        let saved = stty(&["-g"]).map_err(OpenError::NoStty)?;
        // `raw` for keys as they are typed, `-echo` because the browser paints
        // every character it wants seen.
        stty(&["raw", "-echo"]).map_err(OpenError::NoStty)?;
        let mut term = Self {
            saved: Some(saved.trim().to_owned()),
        };
        term.write("\x1b[?1049h"); // the alternate screen, so the shell's scrollback survives
        Ok(term)
    }

    /// The terminal's size, falling back to a size that is always usable.
    pub fn size(&self) -> (usize, usize) {
        let Ok(text) = stty(&["size"]) else {
            return (24, 80);
        };
        let mut parts = text.split_whitespace().filter_map(|n| n.parse().ok());
        match (parts.next(), parts.next()) {
            (Some(rows), Some(cols)) => (rows, cols),
            _ => (24, 80),
        }
    }

    /// Paints the screen.
    pub fn draw(&mut self, lines: &[String]) {
        let mut screen = String::from("\x1b[H\x1b[2J");
        for line in lines {
            screen.push_str(line);
            screen.push_str("\r\n");
        }
        self.write(&screen);
    }

    /// Reads the next key, or `None` at end of input.
    ///
    /// An escape sequence arrives as one read, so an arrow key is decoded from
    /// the buffer rather than by reading again and blocking on a terminal that
    /// has nothing more to say. A lone escape is one byte, and means escape.
    pub fn key(&mut self) -> Option<Key> {
        let mut buffer = [0u8; 8];
        let read = std::io::stdin().read(&mut buffer).ok()?;
        decode(&buffer[..read])
    }

    fn write(&mut self, text: &str) {
        let mut out = std::io::stdout();
        // A terminal that will not take output is one the browser cannot run
        // on, and there is nowhere left to report that to: the report would go
        // to the same place. The next read ends the session.
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        self.write("\x1b[?1049l");
        if let Some(saved) = self.saved.take() {
            let _ = stty(&[&saved]);
        }
    }
}

/// Turns what the terminal sent into a key.
///
/// Pure, and so the one part of this module a test can reach.
pub fn decode(bytes: &[u8]) -> Option<Key> {
    match bytes {
        [] => None,
        // CSI sequences: the arrows and the page keys.
        [0x1b, b'[', rest @ ..] => match rest {
            [b'A', ..] => Some(Key::Up),
            [b'B', ..] => Some(Key::Down),
            [b'5', b'~', ..] => Some(Key::PageUp),
            [b'6', b'~', ..] => Some(Key::PageDown),
            _ => Some(Key::Escape),
        },
        [0x1b, ..] => Some(Key::Escape),
        [b'\r' | b'\n' | b' ', ..] => Some(Key::Act),
        [0x7f | 0x08, ..] => Some(Key::Backspace),
        // Ctrl-C leaves, like it does everywhere else. A configuration editor
        // that traps it is one somebody has to find another way out of.
        [0x03, ..] => Some(Key::Quit),
        [b'k', ..] => Some(Key::Up),
        [b'j', ..] => Some(Key::Down),
        [b'q', ..] => Some(Key::Quit),
        [b's', ..] => Some(Key::Save),
        [b'd', ..] => Some(Key::Reset),
        [byte, ..] => Some(Key::Char(*byte as char)),
    }
}

/// Runs `stty`, returning what it printed.
fn stty(args: &[&str]) -> Result<String, String> {
    let output = Command::new("stty")
        .args(args)
        // `stty` acts on its own standard input, which must be the terminal
        // rather than the pipe this program's output is being read through.
        .stdin(std::fs::File::open("/dev/tty").map_err(|e| format!("/dev/tty: {e}"))?)
        .output()
        .map_err(|e| format!("stty: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
#[path = "tests/term.rs"]
mod tests;
