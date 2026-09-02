// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: the Rust and C halves of the ring-3 address layout agree.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use tessera_checks::{assert_no_violations, layout, walk};

#[test]
fn the_two_languages_agree_about_where_a_program_may_map() {
    let root = walk::source_root();

    // **The premise, checked first.** A parser that quietly stopped
    // understanding either file returns nothing, and nothing compares clean
    // against everything — this gate's whole failure mode is a false pass.
    // Named constants rather than a count, so a rename is a failure here
    // rather than in whichever program mapped second.
    let rust = layout::rust_constants(
        &std::fs::read_to_string(root.join(layout::UABI_SOURCE)).expect("uabi source"),
    );
    let c = layout::c_constants(
        &std::fs::read_to_string(root.join(layout::LIBC_HEADER)).expect("libc header"),
    );
    for arch in ["x86_64", "aarch64"] {
        assert!(
            rust.contains_key(&(Some(arch.to_string()), "HEAP_BASE".to_string())),
            "uabi declares HEAP_BASE for {arch}"
        );
        assert!(
            c.contains_key(&(Some(arch.to_string()), "HEAP_BASE".to_string())),
            "the header declares HEAP_BASE for {arch}"
        );
    }
    assert!(
        c.contains_key(&(None, "HEAP_MAX_BYTES".to_string())),
        "the header declares a heap ceiling"
    );
    // Exercises the product path of the expression reader: the ceiling is
    // written `64 * 1024 * 1024` in both files, and a reader that returned
    // `None` for it would drop the constant rather than compare it.
    assert_eq!(
        c.get(&(None, "HEAP_MAX_BYTES".to_string())),
        Some(&(64 * 1024 * 1024)),
        "the heap ceiling parses as a number rather than as nothing"
    );

    assert_no_violations("layout", &layout::check(&root));
}
