// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated syscall-argument ABI bindings (built
//! by the codegen genrule from `examples/syscall_abi.isl`, never committed).
//! Proves the structured syscall arguments encode to a fixed golden layout and
//! decode back — the syscall boundary is ISL-expressible and wire-stable
//! (kernel/kcore/src/syscall.rs shares these layouts by convention, D24).
//!
//! Normative: docs/api/01-system-call-interface.md ("Structured Arguments"),
//! docs/api/03-interface-schema-language.md ("Kernel ABI Subset")

use syscall_abi::{DebugWriteArgs, ProcessExitArgs, Syscall};
use tessera_isl_runtime::{decode, encode};

/// Golden encoding of the `DebugWriteArgs` value below: little-endian, 8-byte
/// aligned, 32 bytes, no padding.
const DEBUG_WRITE_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // buffer = 0x0040_0100
    0x19, 0, 0, 0, 0, 0, 0, 0, // length = 25
];

#[test]
fn debug_write_args_matches_golden_and_round_trips() {
    assert_eq!(DebugWriteArgs::WIRE_SIZE, 32);
    let value = DebugWriteArgs {
        size: 32,
        version: 1,
        flags: 0,
        buffer: 0x0040_0100,
        length: 25,
    };
    let mut buf = [0u8; 32];
    let n = encode(&value, &mut buf).unwrap();
    assert_eq!(n, 32);
    assert_eq!(buf, DEBUG_WRITE_GOLDEN);

    let decoded: DebugWriteArgs = decode(&DEBUG_WRITE_GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn process_exit_args_round_trips() {
    assert_eq!(ProcessExitArgs::WIRE_SIZE, 24);
    let value = ProcessExitArgs {
        size: 24,
        version: 1,
        flags: 0,
        code: -1,
        reserved: [0; 4],
    };
    let mut buf = [0u8; 24];
    assert_eq!(encode(&value, &mut buf).unwrap(), 24);
    let decoded: ProcessExitArgs = decode(&buf).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn syscall_numbers_match_the_kernel() {
    // The enum ordinals are the ABI syscall numbers the kernel dispatches on.
    assert_eq!(Syscall::Null as u64, 0);
    assert_eq!(Syscall::DebugWrite as u64, 1);
    assert_eq!(Syscall::HandleDuplicate as u64, 2);
    assert_eq!(Syscall::HandleQueryRights as u64, 3);
    assert_eq!(Syscall::HandleClose as u64, 4);
    assert_eq!(Syscall::ProcessExit as u64, 5);
}
