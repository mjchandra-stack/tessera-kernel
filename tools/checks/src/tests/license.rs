// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::license`.

use super::*;

#[test]
fn empty_third_party_passes() {
    assert!(check_third_party(&[]).is_empty());
}

#[test]
fn rejects_disallowed_license_and_missing_keys() {
    let violations = check_package("third_party/x", &BTreeMap::new(), "license: GPL-3.0\n");
    assert!(violations.iter().any(|v| v.reason.contains("allowlist")));
    assert!(violations.iter().any(|v| v.reason.contains("`name`")));
}
