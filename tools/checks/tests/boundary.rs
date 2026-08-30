// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: no user-space package can reach the kernel tree.
//!
//! Normative: docs/roadmap/03-composition-and-self-hosting.md ("Phase 4")

use tessera_checks::{assert_no_violations, boundary, walk};

#[test]
fn no_user_space_package_reaches_the_kernel() {
    let root = walk::source_root();
    let graph = boundary::graph(&root);

    // A gate over an empty graph passes for every tree, sound or not. These
    // two say the walk saw both sides of the boundary it is judging.
    assert!(
        graph.keys().any(|p| p.starts_with(boundary::USER_TREE)),
        "no user-space packages under {} — gate misconfigured",
        root.display()
    );
    assert!(
        graph.keys().any(|p| p.starts_with(boundary::KERNEL_TREE)),
        "no kernel packages under {} — gate misconfigured",
        root.display()
    );

    assert_no_violations("boundary", &boundary::check_graph(&graph));
}
