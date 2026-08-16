// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **mandatory fuzz-target gate**.
//!
//! `docs/lifecycle/02` ("Tier 2"): *"parsers and binary interfaces (per the
//! security model) have mandatory fuzz targets that fail CI if absent."*
//!
//! **Absent is the word that decides the design.** Every other tier-0 gate here
//! inspects files that exist and complains about what is in them. This one has
//! to complain about something that is *not there*, which nothing can do by
//! reading its own output — a fuzz suite with a missing target looks exactly
//! like one that has always had that many. So the gate derives the population
//! it expects from somewhere else entirely: the schemas themselves, and a
//! written list of the parsers nobody generated.
//!
//! Two populations, because there are two kinds of parser here:
//!
//! - **Generated decoders.** Every schema that declares an `@abi` struct
//!   produces one, so every such schema must have a fuzz test. Derived from the
//!   schema directory rather than from a list, so adding a schema adds an
//!   obligation without anybody remembering to.
//! - **Hand-written parsers of external input.** These cannot be derived from
//!   anything — a crate does not announce that it reads bytes somebody else
//!   wrote — so they are a list, and the list is the gate's weak point. It is
//!   spelled out with the reason each entry is on it, so that a reader can
//!   judge whether something is missing; nothing here can.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 2"),
//! docs/security/01-security-model.md

use crate::Violation;
use std::path::Path;

/// The parsers in this tree that read bytes from outside it and were not
/// generated from a schema.
///
/// `(crate path, why it is here)`. Every entry must be exercised by a fuzz
/// target somewhere under `api/isl-fuzz/tests/`.
pub const HAND_WRITTEN_PARSERS: [(&str, &str); 3] = [
    (
        "kernel/devicetree",
        "firmware's description of the machine, parsed before anything is verified",
    ),
    (
        "api/image-store",
        "the container the system reads data it has to trust through",
    ),
    (
        "api/update-channel",
        "a manifest offered by whoever is distributing drivers, parsed before its signature has been believed",
    ),
];

/// Checks that every schema declaring an `@abi` struct has a generated fuzz
/// test, and that every hand-written parser has a target naming it.
pub fn check(root: &Path) -> Vec<Violation> {
    let mut violations = Vec::new();

    let build = root.join("api/isl/BUILD.bazel");
    let Ok(build_text) = std::fs::read_to_string(&build) else {
        violations.push(Violation {
            path: "api/isl/BUILD.bazel".into(),
            reason: "unreadable — the fuzz gate cannot tell which targets exist".into(),
        });
        return violations;
    };

    let examples = root.join("api/isl/examples");
    let Ok(entries) = std::fs::read_dir(&examples) else {
        violations.push(Violation {
            path: "api/isl/examples".into(),
            reason: "unreadable — the fuzz gate cannot tell which schemas exist".into(),
        });
        return violations;
    };

    let mut schemas: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("isl") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // A schema with no `@abi` struct generates no decoder, so there is
        // nothing to fuzz and no target to expect.
        if !text.lines().any(|line| line.trim() == "@abi") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            schemas.push(stem.to_string());
        }
    }
    schemas.sort();

    if schemas.is_empty() {
        violations.push(Violation {
            path: "api/isl/examples".into(),
            reason: "no schema declares an @abi struct — gate misconfigured".into(),
        });
    }

    for stem in &schemas {
        let target = format!("name = \"{stem}_fuzz_test\"");
        if !build_text.contains(&target) {
            violations.push(Violation {
                path: format!("api/isl/examples/{stem}.isl"),
                reason: format!(
                    "declares an @abi struct and has no fuzz target ({stem}_fuzz_test) in \
                     api/isl/BUILD.bazel"
                ),
            });
        }
    }

    let harness_dir = root.join("api/isl-fuzz/tests");
    let mut harnesses = String::new();
    if let Ok(entries) = std::fs::read_dir(&harness_dir) {
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                harnesses.push_str(&text);
            }
        }
    }
    for (parser, why) in HAND_WRITTEN_PARSERS {
        // The crate's Rust name, which is how a harness would name it:
        // `kernel/devicetree` is `tessera_devicetree`.
        let leaf = parser.rsplit('/').next().unwrap_or(parser);
        let crate_name = format!("tessera_{}", leaf.replace('-', "_"));
        if !harnesses.contains(&crate_name) {
            violations.push(Violation {
                path: parser.into(),
                reason: format!(
                    "parses external input ({why}) and no fuzz harness under \
                     api/isl-fuzz/tests names {crate_name}"
                ),
            });
        }
    }

    violations
}

#[cfg(test)]
#[path = "tests/fuzz_gate.rs"]
mod tests;
