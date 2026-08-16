// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: the configuration declaration and the kernel agree, and every
//! profile still resolves.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use tessera_checks::{assert_no_violations, config, walk};

#[test]
fn the_declaration_and_the_kernel_agree() {
    let root = walk::source_root();

    // The premise: a parser that quietly stopped understanding the format
    // returns nothing, and nothing compares clean against everything.
    let text = std::fs::read_to_string(root.join(config::DECLARATION)).expect("declaration");
    let decl = tessera_kconfig::parse_declaration(&text).expect("declaration parses");
    assert_eq!(
        decl.len(),
        27,
        "expected the kernel core's 27 tunables, found {}",
        decl.len()
    );
    for (name, t) in &decl {
        assert!(!t.doc.is_empty(), "[{name}] carries no reasoning");
        assert!(t.min <= t.default && t.default <= t.max, "[{name}] range");
    }

    assert_no_violations("config", &config::check(&root));
}
