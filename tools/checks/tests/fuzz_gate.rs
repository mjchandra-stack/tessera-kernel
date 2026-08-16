// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: every parser of external input has a fuzz target.
//!
//! The one gate here that complains about absence rather than about content,
//! which is why it derives what it expects from the schemas instead of from the
//! fuzz suite — a suite with a target missing looks exactly like one that never
//! had it.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 2")

use tessera_checks::{assert_no_violations, fuzz_gate, walk};

#[test]
fn every_parser_of_external_input_is_fuzzed() {
    let root = walk::source_root();
    assert!(
        root.join("api/isl/examples").is_dir(),
        "no schema directory under {} — gate misconfigured",
        root.display()
    );
    assert_no_violations("fuzz-gate", &fuzz_gate::check(&root));
}
