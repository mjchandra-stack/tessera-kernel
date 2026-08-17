// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Reading a profile: `NAME = value` per line, overriding the declaration.
//!
//! A profile is Tessera's predefined configuration — the file that says what a
//! particular machine is, in the terms the declaration defines. It is sparse on
//! purpose: it names what differs from the declared defaults and nothing else,
//! so reading one tells you what somebody *chose* rather than restating three
//! dozen values they did not.
//!
//! A profile that names nothing is legal and is what `default` is — the
//! declaration's own values, written down as a profile so that "no overrides"
//! is a file somebody chose rather than the absence of one.
//!
//! Nothing here knows what a name means. A value is read by its shape (a number
//! is a size, `y`/`n` is on or off) and whether that shape suits the setting is
//! [`crate::resolve`]'s business, which is where the declaration is in hand.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md

use crate::{Error, Value, err};
use std::collections::BTreeMap;

/// What a profile says, by setting name.
pub type Overrides = BTreeMap<String, Value>;

/// Reads a profile.
pub fn parse_profile(text: &str) -> Result<Overrides, Vec<Error>> {
    let mut out = Overrides::new();
    let mut errors = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            errors.push(err(no, format!("not `NAME = value`: {line}")));
            continue;
        };
        let name = name.trim().to_owned();
        let value = value.trim();
        let parsed = match value {
            "y" => Some(Value::Bool(true)),
            "n" => Some(Value::Bool(false)),
            _ => value.parse::<u64>().ok().map(Value::Int),
        };
        match parsed {
            Some(v) => {
                // A setting given twice is a profile whose meaning depends on
                // which line the reader stopped at. Refusing is the only answer
                // that does not silently pick one.
                if out.insert(name.clone(), v).is_some() {
                    errors.push(err(no, format!("`{name}` set twice")));
                }
            }
            None => errors.push(err(
                no,
                format!("`{name}` = `{value}` is neither a number nor `y`/`n`"),
            )),
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Writes a profile: the smallest file that produces `values`.
///
/// This is `savedefconfig`. What comes back out is only what differs from the
/// declaration, so a profile written by the menu reads like one written by
/// hand, and a default that later changes moves the machines that never had an
/// opinion about it.
pub fn write_profile(config: &crate::Config, header: &[String]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for line in header {
        if line.is_empty() {
            s.push_str("#\n");
        } else {
            let _ = writeln!(s, "# {line}");
        }
    }
    let mut wrote_any = false;
    for (name, value) in &config.values {
        let Some(setting) = config.declaration.get(name) else {
            continue;
        };
        if setting.default == *value {
            continue;
        }
        if !wrote_any {
            s.push('\n');
            wrote_any = true;
        }
        let _ = writeln!(s, "{name} = {value}");
    }
    s
}

#[cfg(test)]
#[path = "tests/profile.rs"]
mod tests;
