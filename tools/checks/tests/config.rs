// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: the configuration declaration and the build agree, and every
//! profile still resolves.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use tessera_checks::{assert_no_violations, config, walk};
use tessera_kconfig::Kind;

#[test]
fn the_declaration_and_the_build_agree() {
    let root = walk::source_root();

    // The premise: a parser that quietly stopped understanding the format
    // returns nothing, and nothing compares clean against everything. Counted
    // per kind, because a format change that dropped one kind entirely would
    // leave a total that still looked plausible.
    let text = std::fs::read_to_string(root.join(config::DECLARATION)).expect("declaration");
    let decl = tessera_kconfig::parse_declaration(&text).expect("declaration parses");
    let count = |want: fn(&Kind) -> bool| decl.values().filter(|s| want(&s.kind)).count();
    assert_eq!(
        count(|k| matches!(k, Kind::Size { .. })),
        29,
        "the kernel core's sizes"
    );
    assert_eq!(
        count(|k| matches!(k, Kind::Feature { .. })),
        2,
        "the features a kernel is built with"
    );
    assert_eq!(
        count(|k| matches!(k, Kind::Component)),
        26,
        "the ring-3 programs an image may carry"
    );

    for (name, setting) in &decl {
        assert!(!setting.doc.is_empty(), "[{name}] carries no reasoning");
        if let Kind::Size { min, max, .. } = &setting.kind {
            let value = setting.default.int().expect("a size defaults to a number");
            assert!(*min <= value && value <= *max, "[{name}] range");
        }
    }

    assert_no_violations("config", &config::check(&root));
}
