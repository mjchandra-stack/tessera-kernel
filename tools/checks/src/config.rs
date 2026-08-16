// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **configuration gate**: the declaration and the code agree, and every
//! profile still builds.
//!
//! `config/kernel.config` owns the kernel core's static sizing. Three ways
//! that can quietly stop being true, and one check each:
//!
//! * a tunable is declared and no module re-exports it — a number nothing
//!   reads, which looks configurable and is not;
//! * a module declares a capacity of its own again — the state this migration
//!   ended, reachable by anybody adding a `pub const MAX_…` where the others
//!   used to be;
//! * a profile names a tunable that has been renamed or removed, or asks for a
//!   value outside its range — which `//tools/kconfig` refuses at build time,
//!   but only for the profile something is *built with*. A profile nobody
//!   builds today is one nobody finds out about until they need it.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use crate::{Violation, walk};
use std::path::Path;

/// Where the declaration and the profiles live.
pub const DECLARATION: &str = "config/kernel.config";
/// The directory every profile is read from.
pub const PROFILES: &str = "config/profiles";
/// The crate whose modules re-export the tunables.
pub const CONSUMER: &str = "kernel/kcore/src";

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
        return vec![violation(DECLARATION, "parsed as no tunables at all")];
    }

    for (name, tunable) in &decl {
        let rel = format!("{CONSUMER}/{}.rs", tunable.module);
        match std::fs::read_to_string(root.join(&rel)) {
            Err(_) => out.push(violation(
                &rel,
                format!(
                    "[{name}] names module `{}`, which is not there",
                    tunable.module
                ),
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

    let dir = root.join(PROFILES);
    let mut profiles: Vec<_> = std::fs::read_dir(&dir)
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_else(|_| Vec::new());
    profiles.sort();
    if profiles.is_empty() {
        out.push(violation(PROFILES, "no profiles, so nothing was checked"));
    }
    for path in profiles {
        let rel = format!(
            "{PROFILES}/{}",
            path.file_name().unwrap_or_default().display()
        );
        let Ok(text) = std::fs::read_to_string(&path) else {
            out.push(violation(&rel, "unreadable"));
            continue;
        };
        match tessera_kconfig::parse_profile(&text) {
            Err(errors) => out.extend(errors.iter().map(|e| violation(&rel, e.to_string()))),
            Ok(overrides) => {
                if let Err(errors) = tessera_kconfig::resolve(&decl, &overrides) {
                    out.extend(errors.iter().map(|e| violation(&rel, e.message.clone())));
                }
            }
        }
    }

    out
}

/// The names of any `pub const <NAME>: usize = <literal>;` in `source` that
/// looks like a capacity — the shape the declaration replaced.
fn redeclared(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in source.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        // A derived value (`= crate::devmgr::MAX_DEVICES`) is not a
        // redeclaration: it names the tunable rather than restating a number.
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
