// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

#[test]
fn console_captures_writes() {
    let mut console = MockConsole::new();
    console.write_bytes(b"hello ");
    console.write_bytes(b"kernel");
    assert_eq!(console.text(), "hello kernel");
}

#[test]
fn synthetic_map_is_sorted() {
    let map = synthetic_map(&[
        (0x100000, 0x1000, MemoryKind::Usable),
        (0x1000, 0x2000, MemoryKind::Reserved),
    ]);
    assert_eq!(map[0].base.as_u64(), 0x1000);
    assert_eq!(map[1].kind, MemoryKind::Usable);
}
