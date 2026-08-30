// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **ABI gate**: the published interface cannot silently stop describing
//! this tree.
//!
//! `docs/api/03` has said since it was written that *"schema changes are
//! reviewed as ABI changes, with the ABI diff tool operating on compiled schema
//! IR, not source text, so formatting changes cannot mask semantic ones"*.
//! There was no such tool. This is it, in the shape the tree already uses for
//! anything it must not be able to authorize for itself: a **checked-in lock**
//! (`api/abi/surface.lock`) recording one digest per schema and one over the
//! set, recomputed here from the schemas as the compiler understands them.
//!
//! **Compiled IR, not source text**, and the difference is the whole point.
//! The digest is over [`Ir::emit_text`] — resolved names, ordinals, syscall
//! numbers, field types with their computed offsets and sizes, protocol
//! interface IDs. Doc comments, blank lines and field *order in the file* are
//! not in it; a struct's layout is. So rewrapping a comment changes nothing
//! here, and reordering two fields changes everything, which is the correct
//! way round and the way a diff over source text gets both wrong.
//!
//! **The lock is source, not build output**, for the reason D146 gives about
//! the store's anchor: a build that emitted both the artifact and the thing
//! that certifies it would certify whatever it happened to produce. Changing
//! the ABI therefore means editing a checked-in file, which is the reviewable
//! event `docs/api/03` asks for.
//!
//! **What this gate does not decide.** Whether a change deserved a new ABI
//! version is a judgement about compatibility, and only a person knows whether
//! adding an ordinal broke a consumer. The gate holds the mechanical half: the
//! lock matches the tree, every schema is accounted for in both directions, and
//! the version user space was compiled against is the version the lock names.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Evolution Rules"),
//! docs/roadmap/03-composition-and-self-hosting.md ("Phase 4"),
//! docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use crate::Violation;
use std::collections::BTreeMap;
use std::path::Path;

/// The checked-in record of the published surface.
pub const LOCK: &str = "api/abi/surface.lock";

/// Where the schemas that define the surface live.
pub const SCHEMA_DIR: &str = "api/isl/examples";

/// The constant a user-space program carries so it can say which ABI it was
/// compiled against.
pub const UABI_SOURCE: &str = "userspace/uabi/src/lib.rs";

/// The name of that constant.
const UABI_VERSION_CONST: &str = "pub const ABI_VERSION: u32 = ";

/// What the lock says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Lock {
    /// The published ABI version.
    pub version: Option<u32>,
    /// The digest over the whole surface.
    pub surface: Option<String>,
    /// Schema stem → digest of its compiled IR.
    pub schemas: BTreeMap<String, String>,
}

/// Parses the lock's line format: `key = value` for the two scalars, and
/// `<name> <digest>` for each schema. Blank lines and `#` comments are skipped.
pub fn parse_lock(content: &str) -> Lock {
    let mut lock = Lock::default();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "abi-version" => lock.version = value.trim().parse().ok(),
                "surface" => lock.surface = Some(value.trim().to_owned()),
                _ => {}
            }
            continue;
        }
        if let Some((name, digest)) = line.split_once(char::is_whitespace) {
            lock.schemas
                .insert(name.trim().to_owned(), digest.trim().to_owned());
        }
    }
    lock
}

/// The digest of one schema: SHA-256 over its compiled IR as `islc emit-ir`
/// renders it, so a consumer holding the published artifact can recompute it
/// with `sha256sum` and no tooling from this tree.
///
/// `None` when the schema does not compile — which the ISL conformance tests
/// are what report; a broken schema is not this gate's news to break.
pub fn schema_digest(source: &str) -> Option<String> {
    let (ir, _) = tessera_isl::compile(source);
    Some(hex(&tessera_hash::sha256(ir?.emit_text().as_bytes())))
}

/// The digest over the whole surface: SHA-256 of one `name digest\n` line per
/// schema, in name order. One number that names the published ABI.
pub fn surface_digest(schemas: &BTreeMap<String, String>) -> String {
    let mut joined = String::new();
    for (name, digest) in schemas {
        joined.push_str(name);
        joined.push(' ');
        joined.push_str(digest);
        joined.push('\n');
    }
    hex(&tessera_hash::sha256(joined.as_bytes()))
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('?'));
        out.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap_or('?'));
    }
    out
}

/// The digest of every schema the tree holds.
pub fn digests_in_tree(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(root.join(SCHEMA_DIR)) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "isl") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(digest) = schema_digest(&source) {
            out.insert(name.to_owned(), digest);
        }
    }
    out
}

/// Compares a lock against the digests a tree actually produces.
pub fn compare(lock: &Lock, tree: &BTreeMap<String, String>) -> Vec<Violation> {
    let mut out = Vec::new();
    let at = |reason: String| Violation {
        path: LOCK.to_owned(),
        reason,
    };

    if lock.version.is_none_or(|v| v == 0) {
        out.push(at(
            "no `abi-version` — the published artifact has nothing to be a version of".into(),
        ));
    }

    for (name, digest) in tree {
        match lock.schemas.get(name) {
            None => out.push(at(format!(
                "schema `{name}` is in the tree and not in the lock: a surface gained a schema \
                 without anybody deciding what that did to the published ABI"
            ))),
            Some(locked) if locked != digest => out.push(at(format!(
                "schema `{name}` compiles to {digest} and the lock says {locked}: the ABI changed. \
                 Review the change as an ABI change, then update the lock"
            ))),
            Some(_) => {}
        }
    }
    for name in lock.schemas.keys().filter(|n| !tree.contains_key(*n)) {
        out.push(at(format!(
            "schema `{name}` is in the lock and not in the tree: a published interface cannot be \
             withdrawn by deleting its definition"
        )));
    }

    let computed = surface_digest(tree);
    match &lock.surface {
        Some(recorded) if *recorded == computed => {}
        Some(recorded) => out.push(at(format!(
            "the surface digest is {computed} and the lock says {recorded}"
        ))),
        None => out.push(at(
            "no `surface` digest — there is no one number naming the ABI".into(),
        )),
    }
    out
}

/// The ABI version a user-space program records having been compiled against.
pub fn uabi_version(source: &str) -> Option<u32> {
    let at = source.find(UABI_VERSION_CONST)? + UABI_VERSION_CONST.len();
    let rest = &source[at..];
    let end = rest.find(';')?;
    rest[..end].trim().parse().ok()
}

/// Checks the tree under `root`.
pub fn check(root: &Path) -> Vec<Violation> {
    let Ok(content) = std::fs::read_to_string(root.join(LOCK)) else {
        return vec![Violation {
            path: LOCK.to_owned(),
            reason: "unreadable — nothing records what the published ABI is".into(),
        }];
    };
    let lock = parse_lock(&content);
    let mut out = compare(&lock, &digests_in_tree(root));

    // The two ends of the same claim: the artifact says which ABI it publishes,
    // and a program built here says which ABI it was built against. A tree
    // where those disagree publishes one surface and compiles another.
    match std::fs::read_to_string(root.join(UABI_SOURCE)) {
        Ok(source) => match (uabi_version(&source), lock.version) {
            (Some(carried), Some(published)) if carried != published => out.push(Violation {
                path: UABI_SOURCE.to_owned(),
                reason: format!(
                    "user space is compiled against ABI {carried} and {LOCK} publishes \
                     {published}"
                ),
            }),
            (None, _) => out.push(Violation {
                path: UABI_SOURCE.to_owned(),
                reason: "no `ABI_VERSION` — a program cannot say which published ABI it was \
                         built against"
                    .into(),
            }),
            _ => {}
        },
        Err(_) => out.push(Violation {
            path: UABI_SOURCE.to_owned(),
            reason: "unreadable — the ABI a program was built against cannot be read".into(),
        }),
    }
    out
}

#[cfg(test)]
#[path = "tests/abi.rs"]
mod tests;
