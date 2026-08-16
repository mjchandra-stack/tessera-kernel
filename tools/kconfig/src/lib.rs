// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel's configuration surface: read the declaration, apply a profile,
//! and emit the constants the kernel core compiles against.
//!
//! **Why a format of its own.** `docs/api/03`'s schema language defines *wire*
//! boundaries, and has no construct for a defaulted, ranged scalar. Adding one
//! would change a language whose job is ABI compatibility, for values that
//! never cross a wire. So `config/kernel.config` is read here and nowhere
//! else, and the parser is strict: an unknown key, a duplicate tunable, a
//! missing field, a value outside its declared range and a profile naming a
//! tunable that does not exist are each an error naming its line.
//!
//! **A refusal, never a clamp.** A profile asking for a value the declaration
//! says is out of range is rejected rather than pulled to the nearest bound.
//! Clamping would build a kernel sized differently from the one that was asked
//! for, and nothing downstream could tell.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/lifecycle/02-build-and-test-infrastructure.md

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// One configurable value: what it sizes, what it defaults to, and the range
/// outside which the code that reads it does not work.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tunable {
    /// The `kcore` module whose table it sizes.
    pub module: String,
    /// The value with no profile applied.
    pub default: u64,
    /// Inclusive bounds. A claim about the code, not a preference.
    pub min: u64,
    pub max: u64,
    /// Why the default is the number it is, moved verbatim from the source it
    /// used to sit in.
    pub doc: Vec<String>,
}

/// The declaration, in file order by name.
pub type Declaration = BTreeMap<String, Tunable>;

/// A parse or validation failure, naming the line that caused it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Error {
    /// The line that caused it, or zero for a failure that is about a value
    /// rather than a place.
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Resolution failures are about a value, not a place: a profile line
        // and a declaration line are both implicated and neither alone is the
        // answer. They carry no line, and printing `line 0` would be a
        // location that does not exist.
        match self.line {
            0 => write!(f, "{}", self.message),
            line => write!(f, "line {line}: {}", self.message),
        }
    }
}

fn err(line: usize, message: impl Into<String>) -> Error {
    Error {
        line,
        message: message.into(),
    }
}

/// Reads `config/kernel.config`.
///
/// Every field is required. A tunable missing one is an error rather than a
/// default, because the fields are the whole content: a tunable with no range
/// is one nothing can validate, and a tunable with no doc is a number with its
/// reasoning left behind in the source it was moved out of.
pub fn parse_declaration(text: &str) -> Result<Declaration, Vec<Error>> {
    let mut out = Declaration::new();
    let mut errors = Vec::new();
    let mut current: Option<(String, usize)> = None;
    let mut module = None;
    let mut default = None;
    let mut range = None;
    let mut doc: Vec<String> = Vec::new();
    // A field that was present but unparsable has already been reported; it
    // must not also be reported as missing, or one mistake reads as two.
    let mut seen: Vec<&str> = Vec::new();

    // `finish` runs at each new section and at end of input, so the last
    // tunable is checked like every other one rather than falling off.
    macro_rules! finish {
        () => {
            if let Some((name, at)) = current.take() {
                match (module.take(), default.take(), range.take()) {
                    (Some(module), Some(default), Some((min, max))) => {
                        if doc.is_empty() {
                            errors.push(err(at, format!("[{name}] has no doc")));
                        }
                        if min > max {
                            errors.push(err(at, format!("[{name}] range is empty")));
                        } else if default < min || default > max {
                            errors.push(err(
                                at,
                                format!("[{name}] default {default} is outside {min}..={max}"),
                            ));
                        }
                        out.insert(
                            name,
                            Tunable {
                                module,
                                default,
                                min,
                                max,
                                doc: core::mem::take(&mut doc),
                            },
                        );
                    }
                    (m, d, r) => {
                        let mut missing = Vec::new();
                        if m.is_none() && !seen.contains(&"module") {
                            missing.push("module");
                        }
                        if d.is_none() && !seen.contains(&"default") {
                            missing.push("default");
                        }
                        if r.is_none() && !seen.contains(&"range") {
                            missing.push("range");
                        }
                        if !missing.is_empty() {
                            errors.push(err(
                                at,
                                format!("[{name}] is missing {}", missing.join(", ")),
                            ));
                        }
                        doc.clear();
                    }
                }
            }
        };
    }

    for (i, raw) in text.lines().enumerate() {
        let no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            finish!();
            seen.clear();
            if name.is_empty() {
                errors.push(err(no, "empty tunable name"));
            }
            if out.contains_key(name) {
                errors.push(err(no, format!("[{name}] declared twice")));
            }
            current = Some((name.to_owned(), no));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            errors.push(err(no, format!("not `key = value`: {line}")));
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if current.is_none() {
            errors.push(err(no, format!("`{key}` before any [tunable]")));
            continue;
        }
        if key != "doc" {
            seen.push(match key {
                "module" => "module",
                "default" => "default",
                "range" => "range",
                _ => "",
            });
        }
        match key {
            "module" => module = Some(value.to_owned()),
            "doc" => doc.push(value.to_owned()),
            "default" => match value.parse::<u64>() {
                Ok(v) => default = Some(v),
                Err(_) => errors.push(err(no, format!("default `{value}` is not a number"))),
            },
            "range" => match parse_range(value) {
                Some(r) => range = Some(r),
                None => errors.push(err(no, format!("range `{value}` is not `lo..=hi`"))),
            },
            other => errors.push(err(no, format!("unknown key `{other}`"))),
        }
    }
    finish!();

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn parse_range(value: &str) -> Option<(u64, u64)> {
    let (lo, hi) = value.split_once("..=")?;
    Some((lo.trim().parse().ok()?, hi.trim().parse().ok()?))
}

/// Reads a profile: `NAME = value` per line, overriding the declaration.
///
/// A profile that names nothing is legal and is what `default` is — the
/// declaration's own values, written down as a profile so that "no overrides"
/// is a file somebody chose rather than the absence of one.
pub fn parse_profile(text: &str) -> Result<BTreeMap<String, u64>, Vec<Error>> {
    let mut out = BTreeMap::new();
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
        match value.trim().parse::<u64>() {
            Ok(v) => {
                if out.insert(name.clone(), v).is_some() {
                    errors.push(err(no, format!("`{name}` set twice")));
                }
            }
            Err(_) => errors.push(err(no, format!("`{name}` is not a number"))),
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Applies a profile to a declaration, refusing anything it cannot honour.
pub fn resolve(
    decl: &Declaration,
    profile: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, u64>, Vec<Error>> {
    let mut errors = Vec::new();
    let mut out: BTreeMap<String, u64> = decl.iter().map(|(k, t)| (k.clone(), t.default)).collect();
    for (name, value) in profile {
        match decl.get(name) {
            // A profile naming a tunable that no longer exists is the failure
            // this catches: it would otherwise be silently ignored, and the
            // kernel built at a size nobody asked for.
            None => errors.push(err(0, format!("profile sets unknown tunable `{name}`"))),
            Some(t) if *value < t.min || *value > t.max => errors.push(err(
                0,
                format!("`{name}` = {value} is outside {}..={}", t.min, t.max),
            )),
            Some(_) => {
                out.insert(name.clone(), *value);
            }
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Whether the emitted file is a crate of its own or included into a module.
///
/// The one difference is `#![no_std]`. Bazel links the output as a crate into
/// a bare-metal kernel, which needs it; cargo `include!`s the same text inside
/// `kcore::config`, where an inner attribute is not valid. Two callers, one
/// emitter, and the difference named rather than papered over by
/// post-processing the file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// A standalone `no_std` crate.
    Crate,
    /// Text included into an existing module.
    Included,
}

/// Emits the constants the kernel core compiles against.
pub fn emit(
    decl: &Declaration,
    values: &BTreeMap<String, u64>,
    profile_name: &str,
    form: Form,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "// SPDX-License-Identifier: Apache-2.0");
    let _ = writeln!(
        s,
        "// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>"
    );
    let _ = writeln!(
        s,
        "// Generated from config/kernel.config, profile `{profile_name}` — do not edit."
    );
    // Plain comments, not `//!`. Under cargo this file is `include!`d inside
    // `kcore::config`, and an inner doc comment is not valid there — the same
    // reason the ISL build script strips them from its own output.
    let _ = writeln!(s, "//");
    let _ = writeln!(s, "// The kernel core's static sizing. Every value here");
    let _ = writeln!(
        s,
        "// is bounded by config/kernel.config, and a profile that asks for"
    );
    let _ = writeln!(s, "// one outside its range does not build.");
    if form == Form::Crate {
        let _ = writeln!(s, "#![no_std]");
    }
    for (name, t) in decl {
        let value = values.get(name).copied().unwrap_or(t.default);
        let _ = writeln!(s);
        for line in &t.doc {
            if line.is_empty() {
                let _ = writeln!(s, "///");
            } else {
                let _ = writeln!(s, "/// {line}");
            }
        }
        let _ = writeln!(s, "///");
        let _ = writeln!(
            s,
            "/// Sizes `kcore::{}`. Range {}..={}, default {}.",
            t.module, t.min, t.max, t.default
        );
        let _ = writeln!(s, "pub const {name}: usize = {value};");
    }
    s
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
