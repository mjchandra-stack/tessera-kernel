// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `isl::ifaceid`.

use super::*;

#[test]
fn is_deterministic_and_version_sensitive() {
    let a = interface_id("t.svc.Echo", 1);
    assert_eq!(a, interface_id("t.svc.Echo", 1), "stable across calls");
    assert_ne!(a, interface_id("t.svc.Echo", 2), "major version matters");
    assert_ne!(a, interface_id("t.svc.Other", 1), "name matters");
}

#[test]
fn matches_a_fixed_vector() {
    // Pins the derivation so an accidental algorithm change is caught:
    // first 8 bytes (little-endian) of SHA-256("t.svc.Echo@1").
    assert_eq!(interface_id("t.svc.Echo", 1), FIXED_ECHO_ID);
}

const FIXED_ECHO_ID: u64 = 0x5274_d214_e745_62ab;
