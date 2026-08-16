// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::console`.

use super::*;
use tessera_karch_mock::MockConsole;

#[test]
fn write_to_formats_into_the_sink() {
    let mut console = MockConsole::new();
    let value = 42;
    write_to(&mut console, format_args!("boot: value={value:#x}\n"));
    assert_eq!(console.text(), "boot: value=0x2a\n");
}

/// The exact shape of every line the kernel prints. Pinned here because a
/// boot check reads this channel and a person reads it more often.
#[test]
fn a_line_carries_its_time_and_its_module() {
    let mut console = MockConsole::new();
    write_line(
        &mut console,
        "tessera_kcore::pmem",
        Some(1234),
        format_args!("frames: 64707 usable\n"),
    );
    assert_eq!(console.text(), "[1234 kcore::pmem] frames: 64707 usable\n");
}

/// A line emitted before any clock is installed says so rather than
/// claiming time zero.
#[test]
fn a_line_with_no_clock_shows_the_gap() {
    let mut console = MockConsole::new();
    write_line(&mut console, "kernel_bin", None, format_args!("early\n"));
    assert_eq!(console.text(), "[- kernel] early\n");
}

/// A kernel's ELF and its flat image are the same code and must not name
/// themselves differently; the build rule's suffix is what would make them.
#[test]
fn a_crate_is_named_as_a_reader_would_name_it() {
    assert_eq!(short_crate("tessera_kcore"), "kcore");
    assert_eq!(short_crate("kernel_bin"), "kernel");
    assert_eq!(short_crate("kernel_aarch64_bin"), "kernel_aarch64");
    assert_eq!(short_crate("kernel_aarch64_image_bin"), "kernel_aarch64");
    assert_eq!(short_crate("arch_conformance"), "arch_conformance");
}

#[test]
fn a_submodule_keeps_its_path_under_the_shortened_crate() {
    let mut console = MockConsole::new();
    write_line(
        &mut console,
        "kernel_aarch64_image_bin::virtio",
        Some(7),
        format_args!("x\n"),
    );
    assert_eq!(console.text(), "[7 kernel_aarch64::virtio] x\n");
}
