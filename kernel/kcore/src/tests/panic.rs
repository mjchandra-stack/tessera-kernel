// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::panic`.

use super::*;
use tessera_karch_mock::MockConsole;

#[test]
fn report_format_is_stable() {
    let mut console = MockConsole::new();
    let location = Location::caller();
    write_report(
        &mut console,
        format_args!("frame allocator exhausted"),
        Some(location),
        Some(9),
    );
    let text = console.text();
    assert!(
        text.starts_with("\n[9 kcore::panic] KERNEL PANIC at "),
        "{text}"
    );
    assert!(text.contains("panic.rs"));
    assert!(text.ends_with(" — frame allocator exhausted\n"), "{text}");
    // One message, one line: the report body is 2 lines only because of the
    // leading break that gets it off a partial one.
    assert_eq!(text.trim_start_matches('\n').lines().count(), 1, "{text}");
}

#[test]
fn missing_location_is_explicit() {
    let mut console = MockConsole::new();
    write_report(&mut console, format_args!("x"), None, None);
    assert!(console.text().contains("at unknown location"));
    assert!(console.text().contains("[- kcore::panic]"));
}
