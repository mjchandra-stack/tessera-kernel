// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Applying a profile to the declaration, and refusing anything it cannot
//! honour.
//!
//! The result is a [`Config`]: every setting, its value, and where that value
//! came from. Tessera has never had this object written down — resolution
//! happened inside a genrule and a build script, and the answer reached a
//! compiler without ever reaching a file. A kernel could not say what it was
//! built with, and neither could the tree.
//!
//! Four ways a profile is refused, and none of them is a clamp:
//!
//! * it names a setting that does not exist — the failure that would otherwise
//!   be silent, and the reason the gate checks profiles nobody builds;
//! * it gives a size where an on/off setting belongs, or the reverse;
//! * it asks for a size outside the range the declaration claims the code
//!   works in;
//! * it breaks an invariant one setting declares about another.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md

use crate::profile::Overrides;
use crate::{Declaration, Error, Kind, Op, Operand, Requirement, Value, err};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// One build's configuration: the declaration it was resolved against, the
/// values, and which of them a profile chose.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config<'a> {
    pub declaration: &'a Declaration,
    /// The profile's name, for the provenance line every generated file
    /// carries.
    pub profile: String,
    pub values: BTreeMap<String, Value>,
    /// The settings the profile named. Everything else is the declared
    /// default, and the difference is what `savedefconfig` writes back out.
    pub overridden: BTreeSet<String>,
}

impl<'a> Config<'a> {
    /// The value of `name`, if the declaration has one.
    pub fn get(&self, name: &str) -> Option<Value> {
        self.values.get(name).copied()
    }

    /// Whether an on/off setting is on.
    ///
    /// A name that is not declared, and a name that is a size, both answer
    /// `false` — which suits the callers, who ask only about features and
    /// components they have already found in the declaration. Anything that
    /// must tell those two cases apart uses [`Value::on`], which refuses to
    /// guess.
    pub fn is_on(&self, name: &str) -> bool {
        self.values
            .get(name)
            .and_then(|v| v.on())
            .unwrap_or_default()
    }

    /// The settings that exist on `machine`, in name order.
    ///
    /// Sizing and features are machine-independent unless they say otherwise —
    /// one `kcore` is linked into all five kernels — so this mostly filters
    /// components down to the ones that machine has an image for.
    pub fn for_machine(&self, machine: &str) -> BTreeMap<&'a str, Value> {
        self.declaration
            .iter()
            .filter(|(_, setting)| setting.applies_to(machine))
            .filter_map(|(name, _)| self.values.get(name).map(|value| (name.as_str(), *value)))
            .collect()
    }

    /// Every component this machine carries, on or off.
    pub fn components_for(&self, machine: &str) -> BTreeMap<&'a str, bool> {
        self.declaration
            .iter()
            .filter(|(_, setting)| setting.kind == Kind::Component && setting.applies_to(machine))
            .filter_map(|(name, _)| Some((name.as_str(), self.get(name)?.on()?)))
            .collect()
    }

    /// The `--cfg=` flags a kernel built with this configuration carries.
    ///
    /// A feature that is off contributes nothing rather than a negated flag:
    /// the ports read `#[cfg(has_x)]` / `#[cfg(not(has_x))]`, so absence is
    /// already how off is spelled.
    pub fn cfg_flags(&self, machine: &str) -> Vec<String> {
        self.declaration
            .iter()
            .filter_map(|(name, setting)| match &setting.kind {
                Kind::Feature { cfg } if setting.applies_to(machine) && self.is_on(name) => {
                    Some(cfg.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// The resolved configuration as text: every value, and where it came from.
    ///
    /// This is the `.config`. It is generated, never edited and never checked
    /// in — its job is to be the artifact that says what a build actually was,
    /// so that "which configuration is this image" has an answer that is not a
    /// reconstruction.
    pub fn show(&self, machine: Option<&str>) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "# Tessera resolved configuration — generated, do not edit."
        );
        let _ = writeln!(s, "# profile: {}", self.profile);
        if let Some(machine) = machine {
            let _ = writeln!(s, "# machine: {machine}");
        }
        let _ = writeln!(
            s,
            "# Each line says where its value came from: the profile chose it, \
             or the declaration did."
        );

        let mut section = None;
        for (name, setting) in ordered(self.declaration) {
            if machine.is_some_and(|m| !setting.applies_to(m)) {
                continue;
            }
            let Some(value) = self.get(name) else {
                continue;
            };
            let heading = setting.group();
            if section.as_ref() != Some(&heading) {
                let _ = writeln!(s, "\n# --- {heading} ---");
                section = Some(heading);
            }
            let origin = if self.overridden.contains(name) {
                "profile"
            } else {
                "default"
            };
            let _ = writeln!(s, "{name} = {value}    # {origin}");
        }
        s
    }
}

/// The declaration in reading order: sizes grouped by the module they size,
/// then features, then components, each group in name order.
///
/// The declaration itself is keyed by name, and name order interleaves the
/// modules — `MAX_CHANNELS` (ipc) lands between `MAX_CACHED_PAGES` (pager) and
/// `MAX_CHILDREN_PER_JOB` (job). Anything that prints a heading per group needs
/// this order instead, or it prints the same heading several times.
pub fn ordered(decl: &Declaration) -> Vec<(&String, &crate::Setting)> {
    let mut out: Vec<_> = decl.iter().collect();
    out.sort_by(|(a_name, a), (b_name, b)| {
        (a.rank(), a.group(), *a_name).cmp(&(b.rank(), b.group(), *b_name))
    });
    out
}

/// Applies a profile to a declaration, refusing anything it cannot honour.
pub fn resolve<'a>(
    decl: &'a Declaration,
    overrides: &Overrides,
    profile: &str,
) -> Result<Config<'a>, Vec<Error>> {
    let mut errors = Vec::new();
    let mut values: BTreeMap<String, Value> =
        decl.iter().map(|(k, s)| (k.clone(), s.default)).collect();
    let mut overridden = BTreeSet::new();

    for (name, value) in overrides {
        let Some(setting) = decl.get(name) else {
            // A profile naming a setting that no longer exists is the failure
            // this catches: it would otherwise be silently ignored, and the
            // kernel built as something nobody asked for.
            errors.push(err(0, format!("profile sets unknown setting `{name}`")));
            continue;
        };
        match (&setting.kind, value) {
            (Kind::Size { min, max, .. }, Value::Int(v)) if v < min || v > max => {
                errors.push(err(0, format!("`{name}` = {v} is outside {min}..={max}")));
            }
            (Kind::Size { .. }, Value::Int(_))
            | (Kind::Feature { .. } | Kind::Component, Value::Bool(_)) => {
                values.insert(name.clone(), *value);
                overridden.insert(name.clone());
            }
            (Kind::Size { .. }, Value::Bool(_)) => errors.push(err(
                0,
                format!("`{name}` is a size and `{value}` is not a number"),
            )),
            (Kind::Feature { .. } | Kind::Component, Value::Int(_)) => errors.push(err(
                0,
                format!("`{name}` is on or off and `{value}` is neither `y` nor `n`"),
            )),
        }
    }

    let config = Config {
        declaration: decl,
        profile: profile.to_owned(),
        values,
        overridden,
    };

    // Invariants are checked against the whole resolved set, not as each
    // override lands: a profile that raises two settings together may pass
    // through a state neither of them is allowed to be in alone, and refusing
    // that would refuse a legal profile for the order its lines happen to be in.
    for (name, setting) in decl {
        for requirement in &setting.requires {
            if let Some(message) = broken(name, requirement, &config) {
                errors.push(err(0, message));
            }
        }
    }

    if errors.is_empty() {
        Ok(config)
    } else {
        Err(errors)
    }
}

/// Why `requirement` does not hold, or `None` if it does.
fn broken(owner: &str, requirement: &Requirement, config: &Config<'_>) -> Option<String> {
    match requirement {
        Requirement::Compare { left, op, right } => {
            let (l, r) = (operand(left, config)?, operand(right, config)?);
            match (l.int(), r.int()) {
                (Some(l), Some(r)) if op.holds(l, r) => None,
                (Some(l), Some(r)) => Some(format!(
                    "[{owner}] requires `{requirement}`, and {l} {} {r} is false",
                    op.spelling()
                )),
                // Comparing a size with an on/off setting is a declaration
                // mistake rather than a profile one, but it surfaces here
                // because it is only visible once both sides have values.
                _ => Some(format!(
                    "[{owner}] requires `{requirement}`, which compares {} with {}",
                    l.noun(),
                    r.noun()
                )),
            }
        }
        Requirement::Implies { left, right } => {
            let (l, r) = (config.get(left)?, config.get(right)?);
            match (l.on(), r.on()) {
                (Some(true), Some(false)) => Some(format!(
                    "[{owner}] requires `{requirement}`, and `{left}` is on while `{right}` is off"
                )),
                (Some(_), Some(_)) => None,
                _ => Some(format!(
                    "[{owner}] requires `{requirement}`, which is about on/off settings and \
                     `{left}` or `{right}` is a size"
                )),
            }
        }
    }
}

fn operand(operand: &Operand, config: &Config<'_>) -> Option<Value> {
    match operand {
        Operand::Literal(v) => Some(Value::Int(*v)),
        // A name that is not declared was already reported when the
        // declaration was read; there is nothing to add by reporting it again
        // for every profile.
        Operand::Setting(name) => config.get(name),
    }
}

impl Op {
    pub(crate) fn holds(self, left: u64, right: u64) -> bool {
        match self {
            Op::Le => left <= right,
            Op::Lt => left < right,
            Op::Ge => left >= right,
            Op::Gt => left > right,
            Op::Eq => left == right,
        }
    }

    pub(crate) fn spelling(self) -> &'static str {
        match self {
            Op::Le => "<=",
            Op::Lt => "<",
            Op::Ge => ">=",
            Op::Gt => ">",
            Op::Eq => "==",
        }
    }
}

/// What two configurations disagree about, in name order.
///
/// This is `diffconfig`, and it exists for the question a ledger entry has to
/// answer: two images boot differently, and the difference between what they
/// were built from should be one command rather than two files read side by
/// side.
pub fn diff<'a>(a: &Config<'a>, b: &Config<'a>) -> Vec<(String, Option<Value>, Option<Value>)> {
    let mut names: BTreeSet<&String> = a.values.keys().collect();
    names.extend(b.values.keys());
    names
        .into_iter()
        .filter_map(|name| {
            let (l, r) = (a.get(name), b.get(name));
            (l != r).then(|| (name.clone(), l, r))
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/resolve.rs"]
mod tests;
