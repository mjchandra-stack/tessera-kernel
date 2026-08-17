// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Reading `config/kernel.config`.
//!
//! Every field a kind needs is required. A setting missing one is an error
//! rather than a default, because the fields are the whole content: a size with
//! no range is one nothing can validate, a feature with no `cfg` is one no
//! build can act on, and a setting with no doc is a decision with its reasoning
//! left behind in the source it was moved out of.
//!
//! Errors accumulate. A declaration with three mistakes should take one run to
//! fix, not three.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md

use crate::{Declaration, Error, Kind, Op, Operand, Requirement, Setting, Value, err};
use std::collections::BTreeSet;

/// One `key = value` as it was written, with the line it was on.
struct Field<'a> {
    key: &'a str,
    value: &'a str,
    line: usize,
}

/// A `[name]` section and everything under it, before it is known to be valid.
struct Section<'a> {
    name: &'a str,
    line: usize,
    fields: Vec<Field<'a>>,
}

/// Reads the declaration.
pub fn parse_declaration(text: &str) -> Result<Declaration, Vec<Error>> {
    let mut errors = Vec::new();
    let sections = split(text, &mut errors);

    let mut out = Declaration::new();
    for section in &sections {
        if out.contains_key(section.name) {
            errors.push(err(
                section.line,
                format!("[{}] declared twice", section.name),
            ));
            continue;
        }
        match setting(section, &mut errors) {
            Some(setting) => {
                out.insert(section.name.to_owned(), setting);
            }
            // `setting` has already said why. Inserting a partial one would
            // make the next check report a second failure for one mistake.
            None => continue,
        }
    }

    // Requirements name settings, and a name is only checkable once the whole
    // declaration is read — a requirement may legitimately point forwards.
    for (name, setting) in &out {
        for requirement in &setting.requires {
            check_names(name, requirement, &out, &mut errors);
        }
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Splits the text into sections, reporting anything that is neither.
fn split<'a>(text: &'a str, errors: &mut Vec<Error>) -> Vec<Section<'a>> {
    let mut out: Vec<Section<'a>> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if name.is_empty() {
                errors.push(err(no, "empty setting name"));
            }
            out.push(Section {
                name,
                line: no,
                fields: Vec::new(),
            });
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            errors.push(err(no, format!("not `key = value`: {line}")));
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match out.last_mut() {
            None => errors.push(err(no, format!("`{key}` before any [setting]"))),
            Some(section) => section.fields.push(Field {
                key,
                value,
                line: no,
            }),
        }
    }
    out
}

/// Validates one section into a [`Setting`], or says why it is not one.
fn setting(section: &Section<'_>, errors: &mut Vec<Error>) -> Option<Setting> {
    let name = section.name;
    let before = errors.len();

    // Every key that is legal for *some* kind is accepted here and checked for
    // relevance below, so a `range` on a feature is reported as the wrong field
    // for the kind rather than as an unknown key. The two mistakes want
    // different sentences.
    let mut kind_field = None;
    let mut module = None;
    let mut range = None;
    let mut cfg = None;
    let mut machines = None;
    let mut default: Option<(&str, usize)> = None;
    let mut requires = Vec::new();
    let mut doc = Vec::new();

    for field in &section.fields {
        let at = field.line;
        match field.key {
            "type" => kind_field = Some((field.value, at)),
            "module" => module = Some((field.value, at)),
            "cfg" => cfg = Some((field.value, at)),
            "default" => default = Some((field.value, at)),
            "doc" => doc.push(field.value.to_owned()),
            "machines" => {
                let set: BTreeSet<String> = field
                    .value
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(str::to_owned)
                    .collect();
                if set.is_empty() {
                    errors.push(err(at, format!("[{name}] machines is empty")));
                } else {
                    machines = Some((set, at));
                }
            }
            "range" => match parse_range(field.value) {
                Some(r) => range = Some((r, at)),
                None => errors.push(err(at, format!("range `{}` is not `lo..=hi`", field.value))),
            },
            "requires" => match parse_requirement(field.value) {
                Some(r) => requires.push(r),
                None => errors.push(err(
                    at,
                    format!(
                        "requires `{}` is not `A <op> B` (<=, <, >=, >, ==) or `A -> B`",
                        field.value
                    ),
                )),
            },
            other => errors.push(err(at, format!("unknown key `{other}`"))),
        }
    }

    if doc.is_empty() {
        errors.push(err(section.line, format!("[{name}] has no doc")));
    }

    let Some((kind_word, kind_at)) = kind_field else {
        errors.push(err(
            section.line,
            format!("[{name}] has no type (size, feature or component)"),
        ));
        return None;
    };

    // Each kind takes exactly its own fields, and every field it is missing is
    // reported together with the others: a section with two mistakes should
    // take one run to fix. A field belonging to another kind is a mistake about
    // what this setting *is*, and gets a sentence saying so rather than
    // "unknown key".
    let (wanted, unwanted): (&[&str], &[(&str, Option<usize>)]) = match kind_word {
        "size" => (
            &["module", "range", "default"],
            &[("cfg", cfg.map(|(_, at)| at))],
        ),
        "feature" => (
            &["cfg", "default"],
            &[
                ("module", module.map(|(_, at)| at)),
                ("range", range.map(|(_, at)| at)),
            ],
        ),
        "component" => (
            &["machines", "default"],
            &[
                ("module", module.map(|(_, at)| at)),
                ("range", range.map(|(_, at)| at)),
                ("cfg", cfg.map(|(_, at)| at)),
            ],
        ),
        other => {
            errors.push(err(
                kind_at,
                format!("[{name}] has type `{other}`, not size, feature or component"),
            ));
            return None;
        }
    };

    for (field, at) in unwanted {
        if let Some(at) = at {
            errors.push(err(
                *at,
                format!("[{name}] is a {kind_word} and has no `{field}`"),
            ));
        }
    }
    let present = |field: &str| match field {
        "module" => module.is_some(),
        "range" => range.is_some(),
        "cfg" => cfg.is_some(),
        "machines" => machines.is_some(),
        _ => default.is_some(),
    };
    let missing: Vec<&str> = wanted.iter().copied().filter(|f| !present(f)).collect();
    if !missing.is_empty() {
        errors.push(err(
            section.line,
            format!("[{name}] is missing {}", missing.join(", ")),
        ));
        return None;
    }

    let kind = match kind_word {
        "size" => {
            let ((min, max), range_at) = range?;
            if min > max {
                errors.push(err(range_at, format!("[{name}] range is empty")));
                return None;
            }
            Kind::Size {
                module: module?.0.to_owned(),
                min,
                max,
            }
        }
        "feature" => Kind::Feature {
            cfg: cfg?.0.to_owned(),
        },
        // A component's machine list is what says an image for it exists at
        // all, which is why it is the one kind that may not leave it out.
        _ => Kind::Component,
    };

    let (default_text, default_at) = default?;
    let default = match &kind {
        Kind::Size { min, max, .. } => match default_text.parse::<u64>() {
            Ok(v) if v < *min || v > *max => {
                errors.push(err(
                    default_at,
                    format!("[{name}] default {v} is outside {min}..={max}"),
                ));
                return None;
            }
            Ok(v) => Value::Int(v),
            Err(_) => {
                errors.push(err(
                    default_at,
                    format!("[{name}] default `{default_text}` is not a number"),
                ));
                return None;
            }
        },
        Kind::Feature { .. } | Kind::Component => match parse_bool(default_text) {
            Some(v) => Value::Bool(v),
            None => {
                errors.push(err(
                    default_at,
                    format!("[{name}] default `{default_text}` is not `y` or `n`"),
                ));
                return None;
            }
        },
    };

    // A section that produced any error is not returned even when the remaining
    // fields would build one: a half-valid setting downstream is worse than an
    // absent one, because the errors are already on their way to the caller.
    if errors.len() != before {
        return None;
    }

    Some(Setting {
        kind,
        default,
        machines: machines.map(|(set, _)| set),
        requires,
        doc,
    })
}

fn parse_range(value: &str) -> Option<(u64, u64)> {
    let (lo, hi) = value.split_once("..=")?;
    Some((lo.trim().parse().ok()?, hi.trim().parse().ok()?))
}

/// `y`/`n`, and nothing else.
///
/// Not `true`/`1`/`yes`. One spelling means a profile cannot be written two
/// ways, and a diff between two profiles is about what they say rather than how
/// they say it.
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "y" => Some(true),
        "n" => Some(false),
        _ => None,
    }
}

/// `A -> B`, or `A <op> B`.
fn parse_requirement(text: &str) -> Option<Requirement> {
    if let Some((left, right)) = text.split_once("->") {
        let (left, right) = (left.trim(), right.trim());
        if left.is_empty() || right.is_empty() {
            return None;
        }
        return Some(Requirement::Implies {
            left: left.to_owned(),
            right: right.to_owned(),
        });
    }
    // Two-character operators first: splitting on `<` would read `<=` as `<`
    // followed by a right-hand side beginning with `=`.
    for (spelling, op) in [
        ("<=", Op::Le),
        (">=", Op::Ge),
        ("==", Op::Eq),
        ("<", Op::Lt),
        (">", Op::Gt),
    ] {
        if let Some((left, right)) = text.split_once(spelling) {
            return Some(Requirement::Compare {
                left: operand(left.trim())?,
                op,
                right: operand(right.trim())?,
            });
        }
    }
    None
}

fn operand(text: &str) -> Option<Operand> {
    if text.is_empty() {
        return None;
    }
    match text.parse::<u64>() {
        Ok(v) => Some(Operand::Literal(v)),
        // Anything that is not a number is a name, and whether it is a name
        // that exists is checked once the whole declaration is read.
        Err(_) => Some(Operand::Setting(text.to_owned())),
    }
}

/// Every setting a requirement names must exist.
///
/// A requirement pointing at a renamed setting would otherwise be an invariant
/// that quietly stopped being checked — the same failure the profile check
/// catches, one level up.
fn check_names(
    owner: &str,
    requirement: &Requirement,
    decl: &Declaration,
    errors: &mut Vec<Error>,
) {
    let mut check = |name: &String| {
        if !decl.contains_key(name) {
            errors.push(err(
                0,
                format!("[{owner}] requires `{requirement}`, and `{name}` is not declared"),
            ));
        }
    };
    match requirement {
        Requirement::Compare { left, right, .. } => {
            for operand in [left, right] {
                if let Operand::Setting(name) = operand {
                    check(name);
                }
            }
        }
        Requirement::Implies { left, right } => {
            check(left);
            check(right);
        }
    }
}

#[cfg(test)]
#[path = "tests/declare.rs"]
mod tests;
