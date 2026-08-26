// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: the system call surface says the same thing in all three
//! places it is written down — the kernel's `SyscallNumber`, the ISL schema
//! the reference is generated from, and the design document that describes the
//! families.
//!
//! A syscall cannot be added without an ISL entry at the same number and a
//! description, a family in `docs/api/01` cannot be added without saying
//! whether it exists, and an argument struct the schema points at cannot be
//! renamed out from under it. Before this, all three could drift and did:
//! `syscall_abi.isl` declared six calls of fifty (build/README.md, D248).
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use tessera_checks::{assert_no_violations, surface, walk};

#[test]
fn the_call_surface_agrees_with_itself() {
    let root = walk::source_root();
    for path in [
        surface::SYSCALL_SOURCE,
        surface::SYSCALL_SCHEMA,
        surface::FAMILIES_DOC,
    ] {
        assert!(
            root.join(path).is_file(),
            "no {} at {} — gate misconfigured",
            path,
            root.join(path).display()
        );
    }
    assert_no_violations("surface", &surface::check(&root));
}

/// The discriminator. A gate that parsed one variant and stopped, or that read
/// a document with no families in it, reports clean — so the counts are
/// asserted, not the absence of findings.
#[test]
fn the_gate_is_reading_the_whole_surface() {
    let root = walk::source_root();
    let src = std::fs::read_to_string(root.join(surface::SYSCALL_SOURCE)).expect("kernel source");
    let (calls, violations) = surface::parse_rust_calls(&src);
    assert_eq!(violations, Vec::new());
    assert!(
        calls.len() >= 50,
        "only {} call numbers parsed; the kernel answers more than that, so the enum is being cut \
         short",
        calls.len()
    );
    // Numbers are dense from zero: the reference prints them as a table, and a
    // hole in it is either a removed call nobody reserved or a parse that
    // skipped one.
    for (index, call) in calls.iter().enumerate() {
        assert_eq!(
            call.number, index as u64,
            "call {} is `{}`, so the numbering has a hole",
            call.number, call.name
        );
    }

    let doc = std::fs::read_to_string(root.join(surface::FAMILIES_DOC)).expect("families doc");
    let (families, violations) = surface::check_families(surface::FAMILIES_DOC, &doc);
    assert_eq!(violations, Vec::new());
    assert!(
        families.len() >= 18,
        "only {} families parsed; the document describes about twenty",
        families.len()
    );
    // And the statuses are not all one word — a document where every family
    // claims the same thing is one where the marker carries no information.
    let implemented = families
        .iter()
        .filter(|f| f.status.as_deref() == Some("implemented"))
        .count();
    assert!(
        implemented > 0 && implemented < families.len(),
        "every family claims the same status, so the marker distinguishes nothing"
    );
}
