// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **configuration gate**: the declaration and the build agree, and every
//! profile still builds.
//!
//! `config/kernel.config` owns what a build of this tree can be told to be.
//! Five ways that can quietly stop being true, and one check each:
//!
//! * a size is declared and no module re-exports it — a number nothing reads,
//!   which looks configurable and is not;
//! * a module declares a capacity of its own again — the state this migration
//!   ended, reachable by anybody adding a `MAX_…` where the others used to be;
//! * a profile names a setting that has been renamed or removed, or asks for
//!   something outside its range, or breaks an invariant — which
//!   `//tools/kconfig` refuses at build time, but only for the profile
//!   something is *built with*. A profile nobody builds today is one nobody
//!   finds out about until they need it;
//! * `//components` carries an image the declaration does not know about, or
//!   the declaration names a component for a machine that has no image for it.
//!   The build catches this too, and only for the machines something builds —
//!   this catches it for all of them;
//! * a kernel's `--cfg=` flags and the declared features disagree. This is the
//!   one that had never been checked at all: the codegen-flag gate excludes
//!   `--cfg=` from its cargo-versus-Bazel comparison by name (and rightly —
//!   the two legitimately differ), so five `BUILD.bazel` files carried feature
//!   selection that nothing compared against anything.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use crate::{Violation, flags, walk};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tessera_kconfig::{Declaration, Kind};

/// Where the declaration and the profiles live.
pub const DECLARATION: &str = "config/kernel.config";
/// The directory every profile is read from.
pub const PROFILES: &str = "config/profiles";
/// The profile a build uses when the invocation names none.
pub const DEFAULT_PROFILE: &str = "config/profiles/default.profile";
/// The crate whose modules re-export the sizes.
pub const CONSUMER: &str = "kernel/kcore/src";
/// Where each machine's ring-3 image labels are listed.
pub const COMPOSITION: &str = "components/BUILD.bazel";

fn violation(path: &str, reason: impl Into<String>) -> Violation {
    Violation {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

/// Runs every rule above against the tree at `root`.
pub fn check(root: &Path) -> Vec<Violation> {
    let mut out = Vec::new();

    let Ok(text) = std::fs::read_to_string(root.join(DECLARATION)) else {
        return vec![violation(DECLARATION, "unreadable")];
    };
    let decl = match tessera_kconfig::parse_declaration(&text) {
        Ok(d) => d,
        Err(errors) => {
            return errors
                .iter()
                .map(|e| violation(DECLARATION, e.to_string()))
                .collect();
        }
    };
    // An empty declaration compares clean against anything, so the premise is
    // asserted rather than assumed.
    if decl.is_empty() {
        return vec![violation(DECLARATION, "parsed as no settings at all")];
    }

    out.extend(check_re_exports(root, &decl));
    out.extend(check_not_redeclared(root, &decl));
    out.extend(check_profiles(root, &decl));
    out.extend(check_composition(root, &decl));
    out.extend(check_features(root, &decl));
    out
}

/// Every size is read by the module it says it sizes.
fn check_re_exports(root: &Path, decl: &Declaration) -> Vec<Violation> {
    let mut out = Vec::new();
    for (name, setting) in decl {
        let Kind::Size { module, .. } = &setting.kind else {
            continue;
        };
        let rel = format!("{CONSUMER}/{module}.rs");
        match std::fs::read_to_string(root.join(&rel)) {
            Err(_) => out.push(violation(
                &rel,
                format!("[{name}] names module `{module}`, which is not there"),
            )),
            Ok(source) => {
                if !source.contains(&format!("pub use crate::config::{name};")) {
                    out.push(violation(
                        &rel,
                        format!("[{name}] is declared but this module does not re-export it"),
                    ));
                }
            }
        }
    }
    out
}

/// No module states a declared capacity as a literal of its own.
fn check_not_redeclared(root: &Path, decl: &Declaration) -> Vec<Violation> {
    let mut out = Vec::new();
    for (path, rel) in walk::walk_files(&root.join(CONSUMER)) {
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        // `walk_files` yields the *relative path*, not the contents. Reading
        // the file is the whole check: scanning the path string matched
        // nothing and the gate passed on a tree that violated it.
        let Ok(source) = std::fs::read_to_string(&path) else {
            out.push(violation(&rel, "unreadable"));
            continue;
        };
        for name in redeclared(&source) {
            if decl.contains_key(&name) {
                out.push(violation(
                    &rel,
                    format!("`{name}` is declared here and owned by {DECLARATION}"),
                ));
            }
        }
    }
    out
}

/// Every profile on disk still resolves, including the ones nothing builds.
fn check_profiles(root: &Path, decl: &Declaration) -> Vec<Violation> {
    let mut out = Vec::new();
    let dir = root.join(PROFILES);
    let mut profiles: Vec<_> = std::fs::read_dir(&dir)
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_else(|_| Vec::new());
    profiles.sort();
    if profiles.is_empty() {
        out.push(violation(PROFILES, "no profiles, so nothing was checked"));
    }
    let mut saw_default = false;
    for path in profiles {
        let file = path.file_name().unwrap_or_default().display().to_string();
        let rel = format!("{PROFILES}/{file}");
        if file == "default.profile" {
            saw_default = true;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            out.push(violation(&rel, "unreadable"));
            continue;
        };
        let name = file.strip_suffix(".profile").unwrap_or(&file);
        match tessera_kconfig::parse_profile(&text) {
            Err(errors) => out.extend(errors.iter().map(|e| violation(&rel, e.to_string()))),
            Ok(overrides) => {
                if let Err(errors) = tessera_kconfig::resolve(decl, &overrides, name) {
                    out.extend(errors.iter().map(|e| violation(&rel, e.message.clone())));
                }
                out.extend(check_features_unchanged(&rel, decl, &overrides));
            }
        }
    }
    // `--//config:profile` falls back to `default`, and a `select` whose
    // default arm names a file that is not there fails obscurely at analysis
    // time rather than here.
    if !saw_default {
        out.push(violation(
            DEFAULT_PROFILE,
            "missing — every build falls back to it",
        ));
    }
    out
}

/// No profile changes a feature, because the build cannot yet act on it.
///
/// The honest boundary of what is wired. A profile reaches the build in two
/// ways: the sizing constants and the composition, both generated by
/// `//tools/kconfig` from the selected profile. A feature reaches it as a
/// `--cfg=` in a kernel's `BUILD.bazel` — a Starlark literal, and Starlark
/// cannot read a profile, so a `select` cannot be built from one.
///
/// So a profile that turned `SYSTEM_STORE` off would resolve, would change
/// `kconfig show` and `kconfig flags`, and would build a kernel with the store
/// still in it. That is the silent divergence this tree exists to avoid, and
/// until the flags come from the declaration it is refused here rather than
/// left to be discovered. `COMPONENTS` is the exception in practice — its
/// value is honoured by the generated crate rather than by a flag — but it is
/// refused with the others, because a rule with one exception is a rule
/// somebody has to check the exception list for.
fn check_features_unchanged(
    rel: &str,
    decl: &Declaration,
    overrides: &BTreeMap<String, tessera_kconfig::Value>,
) -> Vec<Violation> {
    let mut out = Vec::new();
    for (name, value) in overrides {
        let Some(setting) = decl.get(name) else {
            continue; // already reported as unknown by `resolve`
        };
        if matches!(setting.kind, Kind::Feature { .. }) && setting.default != *value {
            out.push(violation(
                rel,
                format!(
                    "sets feature `{name}` = {value}, and the build cannot act on that yet: a \
                     kernel's `--cfg=` flags are Starlark literals and Starlark cannot read a \
                     profile. Building this would silently produce a kernel with `{name}` at \
                     its default (build/README.md, D199)"
                ),
            ));
        }
    }
    out
}

/// Every machine's image list and the declaration name the same programs.
fn check_composition(root: &Path, decl: &Declaration) -> Vec<Violation> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(root.join(COMPOSITION)) else {
        return vec![violation(COMPOSITION, "unreadable")];
    };
    let listed = image_components(&text);
    if listed.is_empty() {
        return vec![violation(
            COMPOSITION,
            "no `tessera_image_components` call — gate misconfigured",
        )];
    }

    for (machine, programs) in &listed {
        let declared: BTreeSet<String> = decl
            .iter()
            .filter(|(_, s)| s.kind == Kind::Component && s.applies_to(machine))
            .map(|(name, _)| name.clone())
            .collect();
        for name in programs.difference(&declared) {
            out.push(violation(
                COMPOSITION,
                format!(
                    "//components:{machine} carries `{name}`, which {DECLARATION} does not \
                     declare as a component of {machine}"
                ),
            ));
        }
        for name in declared.difference(programs) {
            out.push(violation(
                DECLARATION,
                format!(
                    "[{name}] is declared a component of {machine}, and //components:{machine} \
                     has no image for it"
                ),
            ));
        }
    }

    // A machine named by a component and by no image list at all: the loop
    // above cannot see it, because it walks the lists rather than the
    // declaration.
    for (name, setting) in decl {
        if setting.kind != Kind::Component {
            continue;
        }
        let Some(machines) = &setting.machines else {
            continue;
        };
        for machine in machines {
            if !listed.contains_key(machine) {
                out.push(violation(
                    DECLARATION,
                    format!("[{name}] names machine `{machine}`, which {COMPOSITION} has no image list for"),
                ));
            }
        }
    }
    out
}

/// Every kernel's `--cfg=` flags are the features the declaration says it has.
fn check_features(root: &Path, decl: &Declaration) -> Vec<Violation> {
    let mut out = Vec::new();
    let Ok(profile_text) = std::fs::read_to_string(root.join(DEFAULT_PROFILE)) else {
        // Already reported by `check_profiles`; saying it twice would make one
        // missing file look like two problems.
        return out;
    };
    let Ok(overrides) = tessera_kconfig::parse_profile(&profile_text) else {
        return out;
    };
    let Ok(config) = tessera_kconfig::resolve(decl, &overrides, "default") else {
        return out;
    };

    let Ok(kernel_bzl) = std::fs::read_to_string(root.join(flags::KERNEL_RULES)) else {
        return vec![violation(
            flags::KERNEL_RULES,
            "unreadable — the feature gate cannot find the kernel binaries",
        )];
    };
    let default_arch = flags::default_arch(&kernel_bzl).unwrap_or_default();
    let binaries = flags::kernel_binaries(root, &default_arch);
    if binaries.is_empty() {
        return vec![violation(
            flags::KERNEL_RULES,
            "no package calls `tessera_kernel_binary` — feature gate misconfigured",
        )];
    }

    for binary in &binaries {
        let rel = format!("{}/BUILD.bazel", binary.package);
        let carried: BTreeSet<&str> = binary
            .rustc_flags
            .iter()
            .filter_map(|f| f.strip_prefix("--cfg="))
            .collect();
        let expected: BTreeSet<String> = config.cfg_flags(&binary.arch).into_iter().collect();

        for cfg in &carried {
            if !expected.contains(*cfg) {
                out.push(violation(
                    &rel,
                    format!(
                        "carries `--cfg={cfg}`, which is not a feature {DECLARATION} says \
                         {} has",
                        binary.arch
                    ),
                ));
            }
        }
        for cfg in expected.iter().filter(|c| !carried.contains(c.as_str())) {
            out.push(violation(
                &rel,
                format!(
                    "{DECLARATION} says {} has feature `{cfg}` and this kernel does not \
                     carry `--cfg={cfg}`",
                    binary.arch
                ),
            ));
        }
        // A `--cfg` the compiler has never been told to expect is a silent
        // typo: `#[cfg(has_componenst)]` is not an error, it is code that is
        // never compiled.
        for cfg in &carried {
            if !binary
                .rustc_flags
                .iter()
                .any(|f| f == &format!("--check-cfg=cfg({cfg})"))
            {
                out.push(violation(
                    &rel,
                    format!("carries `--cfg={cfg}` with no matching `--check-cfg=cfg({cfg})`"),
                ));
            }
        }
    }
    out
}

/// Each `tessera_image_components` call: the machine, and the programs it lists.
fn image_components(build: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for call in build.split("tessera_image_components(").skip(1) {
        let Some(body) = call.split_once("\n)").map(|(head, _)| head) else {
            continue;
        };
        let Some(machine) = field(body, "name") else {
            continue;
        };
        let Some(dict) = body
            .split_once("components = {")
            .and_then(|(_, rest)| rest.split_once("\n    }"))
            .map(|(dict, _)| dict)
        else {
            continue;
        };
        // Each entry is `"program": "//label",` — the program is the first
        // quoted run on its line.
        let programs = dict
            .lines()
            .filter_map(|line| {
                let (key, _) = line.trim().split_once(':')?;
                Some(key.trim().trim_matches('"').to_owned())
            })
            .filter(|p| !p.is_empty())
            .collect();
        out.insert(machine, programs);
    }
    out
}

/// The quoted value of `name = "…"` in a rule call.
fn field(body: &str, key: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let rest = line.trim().strip_prefix(key)?.trim_start();
        let rest = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
        Some(rest.split_once('"')?.0.to_owned())
    })
}

/// The names of any `const <NAME>: usize = <literal>;` in `source` that looks
/// like a capacity — the shape the declaration replaced.
///
/// Private ones count. `pmem`'s two capacities sat behind a bare `const` and
/// the migration walked straight past them, because this only looked for
/// `pub const` — so the setting that bounds `MAX_OBJECT_PAGES` was one nothing
/// could see or configure.
fn redeclared(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in source.lines() {
        let line = line.trim_start();
        let Some(rest) = line
            .strip_prefix("pub const ")
            .or_else(|| line.strip_prefix("const "))
        else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        // A derived value (`= crate::devmgr::MAX_DEVICES`) is not a
        // redeclaration: it names the setting rather than restating a number.
        if tail.trim_start().starts_with("usize")
            && tail.contains('=')
            && tail
                .rsplit('=')
                .next()
                .is_some_and(|v| v.trim().trim_end_matches(';').parse::<u64>().is_ok())
        {
            out.push(name.trim().to_owned());
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
