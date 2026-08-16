// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::spdx`.

use super::*;

const GOOD: &str = "// SPDX-License-Identifier: Apache-2.0\n// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>\nfn x() {}\n";

#[test]
fn accepts_headed_file() {
    assert_eq!(check_file("a/b.rs", GOOD.as_bytes()), None);
}

#[test]
fn rejects_missing_license() {
    let v = check_file("a/b.rs", b"fn x() {}\n");
    assert!(v.is_some());
}

#[test]
fn rejects_missing_copyright() {
    let v = check_file("a/b.rs", b"// SPDX-License-Identifier: Apache-2.0\n");
    assert!(v.unwrap().reason.contains("Copyright"));
}

#[test]
fn exempts_lockfiles_third_party_and_binaries() {
    assert_eq!(check_file("Cargo.lock", b"no header"), None);
    assert_eq!(check_file("third_party/x/f.c", b"no header"), None);
    assert_eq!(check_file("a/blob.bin", b"\x7fELF\x00\x01"), None);
}
