// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What a resolved configuration turns into: the constants the kernel core
//! compiles against, and the crate that says which ring-3 programs an image
//! carries.
//!
//! Both are build artifacts and neither is ever committed
//! (docs/lifecycle/04-coding-guidelines.md, "Never edit or check in generated
//! code").
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md

use crate::{Config, Error, Kind, err};
use std::collections::BTreeMap;
use std::fmt::Write as _;

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

fn preamble(s: &mut String, generated_from: &str) {
    let _ = writeln!(s, "// SPDX-License-Identifier: Apache-2.0");
    let _ = writeln!(
        s,
        "// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>"
    );
    let _ = writeln!(s, "// Generated from {generated_from} — do not edit.");
}

/// Emits the sizing constants the kernel core compiles against.
///
/// Only sizes become constants. A feature is a `#[cfg]` and a component is a
/// byte slice, and neither is a number the kernel reads.
pub fn emit(config: &Config<'_>, form: Form) -> String {
    let mut s = String::new();
    preamble(
        &mut s,
        &format!("config/kernel.config, profile `{}`", config.profile),
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
    for (name, setting) in config.declaration {
        let Kind::Size { module, min, max } = &setting.kind else {
            continue;
        };
        let value = config.get(name).unwrap_or(setting.default);
        let _ = writeln!(s);
        for line in &setting.doc {
            if line.is_empty() {
                let _ = writeln!(s, "///");
            } else {
                let _ = writeln!(s, "/// {line}");
            }
        }
        let _ = writeln!(s, "///");
        let _ = writeln!(
            s,
            "/// Sizes `kcore::{module}`. Range {min}..={max}, default {}.",
            setting.default
        );
        let _ = writeln!(s, "pub const {name}: usize = {value};");
    }
    s
}

/// Emits the crate that says which ring-3 programs one machine's image carries.
///
/// `catalog` maps each program to the crate holding its bytes. Bazel must know
/// those labels statically to form the dependency edges, so the catalog stays
/// in Starlark and the *selection* comes from here — and the two are held to
/// each other: a program in the catalog that this file does not declare, or a
/// component declared for this machine that the catalog has no image for, is
/// an error rather than a program that quietly stops being configurable.
///
/// A component that is off keeps its accessor and returns an empty slice.
/// That is not a special case invented for the option: it is the state every
/// check already handles, because it is what the cargo inner loop has always
/// seen. Nothing then references the program's bytes, so the linker never pulls
/// them in and the image really does lose the program rather than only the
/// mention of it.
pub fn emit_components(
    config: &Config<'_>,
    machine: &str,
    catalog: &BTreeMap<String, String>,
) -> Result<String, Vec<Error>> {
    let declared = config.components_for(machine);
    let mut errors = Vec::new();
    for name in catalog.keys() {
        if !declared.contains_key(name.as_str()) {
            errors.push(err(
                0,
                format!(
                    "//components:{machine} carries `{name}`, which config/kernel.config does \
                     not declare as a component of {machine}"
                ),
            ));
        }
    }
    for name in declared.keys() {
        if !catalog.contains_key(*name) {
            errors.push(err(
                0,
                format!(
                    "config/kernel.config declares `{name}` a component of {machine}, and \
                     //components:{machine} has no image for it"
                ),
            ));
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut s = String::new();
    preamble(
        &mut s,
        &format!(
            "config/kernel.config and //components:{machine}, profile `{}`",
            config.profile
        ),
    );
    let _ = writeln!(s, "//! The ring-3 programs this image carries.");
    let _ = writeln!(s, "//!");
    let _ = writeln!(
        s,
        "//! A program this machine has no image for is absent from this crate,"
    );
    let _ = writeln!(
        s,
        "//! so a port naming one it cannot embed fails to compile rather than"
    );
    let _ = writeln!(
        s,
        "//! reading an empty slice at boot. A program the profile turned *off*"
    );
    let _ = writeln!(
        s,
        "//! keeps its accessor and returns nothing, which is the absence every"
    );
    let _ = writeln!(s, "//! check already reports.");
    let _ = writeln!(s, "#![no_std]");

    for (name, on) in &declared {
        let Some(krate) = catalog.get(*name) else {
            continue;
        };
        let _ = writeln!(s);
        if *on {
            let _ = writeln!(s, "/// The `{name}` program, embedded by `{krate}`.");
            let _ = writeln!(s, "pub fn {name}() -> &'static [u8] {{");
            let _ = writeln!(s, "    &{krate}::{}_ELF", name.to_uppercase());
            let _ = writeln!(s, "}}");
        } else {
            let _ = writeln!(
                s,
                "/// The `{name}` program, which profile `{}` turned off. Nothing",
                config.profile
            );
            let _ = writeln!(
                s,
                "/// references `{krate}`, so its bytes are not in this image."
            );
            let _ = writeln!(s, "pub fn {name}() -> &'static [u8] {{");
            let _ = writeln!(s, "    &[]");
            let _ = writeln!(s, "}}");
        }
    }
    Ok(s)
}

#[cfg(test)]
#[path = "tests/emit.rs"]
mod tests;
