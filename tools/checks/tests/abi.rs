// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: the published ABI describes this tree.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Evolution Rules")

use tessera_checks::{abi, assert_no_violations, walk};

#[test]
fn the_published_abi_matches_the_schemas() {
    let root = walk::source_root();
    let tree = abi::digests_in_tree(&root);

    // A gate over an empty schema set passes for every tree. The lock names 33
    // schemas; a run that compiled none of them would agree with nothing.
    assert!(
        tree.len() > 30,
        "only {} schema(s) compiled under {} — gate misconfigured",
        tree.len(),
        root.display()
    );

    assert_no_violations("abi", &abi::check(&root));
}
