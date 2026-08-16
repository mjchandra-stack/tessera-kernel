// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the configuration gate's scanner.

use super::*;

#[test]
fn a_literal_capacity_is_a_redeclaration() {
    assert_eq!(
        redeclared("pub const MAX_PORTS: usize = 32;\n"),
        ["MAX_PORTS"]
    );
}

/// The distinction the gate turns on: a value derived from a tunable names it
/// rather than restating a number, and is exactly what should stay in code.
#[test]
fn a_derived_value_is_not_a_redeclaration() {
    assert!(redeclared("pub const MAX_TRACKED: usize = crate::devmgr::MAX_DEVICES;\n").is_empty());
}

#[test]
fn a_re_export_is_not_a_redeclaration() {
    assert!(redeclared("pub use crate::config::MAX_PORTS;\n").is_empty());
}

#[test]
fn a_non_usize_constant_is_left_alone() {
    assert!(redeclared("pub const GIVEUP_CODE: u64 = 178;\n").is_empty());
}
