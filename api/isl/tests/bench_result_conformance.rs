// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated benchmark-result ABI bindings (built
//! by the codegen genrule from `examples/bench_result.isl`, never committed).
//! Proves a `BenchResult` encodes to a fixed golden layout and decodes back —
//! the structured-event schema the perf harness reports against
//! (docs/prototypes/01-ipc-benchmark-harness.md, "Reporting").
//!
//! Normative: docs/prototypes/01-ipc-benchmark-harness.md ("Reporting"),
//! docs/api/03-interface-schema-language.md ("Wire Format")

use bench_result::{BenchResult, Benchmark};
use tessera_isl_runtime::{decode, encode};

/// Golden encoding of the `BenchResult` value below: little-endian, 8-byte
/// aligned, 56 bytes, no padding.
const GOLDEN: [u8; 56] = [
    0x38, 0, 0, 0, // size = 56
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x03, 0, 0, 0, // benchmark = IpcRoundTrip (3)
    0x00, 0x04, 0, 0, // sample_count = 1024
    0x64, 0, 0, 0, 0, 0, 0, 0, // p50 = 100
    0xc8, 0, 0, 0, 0, 0, 0, 0, // p90 = 200
    0x2c, 0x01, 0, 0, 0, 0, 0, 0, // p99 = 300
    0xe7, 0x03, 0, 0, 0, 0, 0, 0, // max = 999
];

#[test]
fn bench_result_matches_golden_and_round_trips() {
    assert_eq!(BenchResult::WIRE_SIZE, 56);
    let value = BenchResult {
        size: 56,
        version: 1,
        flags: 0,
        benchmark: Benchmark::IpcRoundTrip,
        sample_count: 1024,
        p50: 100,
        p90: 200,
        p99: 300,
        max: 999,
    };
    let mut buf = [0u8; 56];
    assert_eq!(encode(&value, &mut buf).unwrap(), 56);
    assert_eq!(buf, GOLDEN);

    let decoded: BenchResult = decode(&GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn benchmark_ids_are_budget_numbers() {
    assert_eq!(Benchmark::NullSyscall as u32, 1);
    assert_eq!(Benchmark::HandleOp as u32, 2);
    assert_eq!(Benchmark::IpcRoundTrip as u32, 3);
    assert_eq!(Benchmark::WaitOnAddress as u32, 6);
    assert_eq!(Benchmark::ContextSwitch as u32, 7);
    assert_eq!(Benchmark::AnonFault as u32, 8);
    assert_eq!(Benchmark::CowFault as u32, 9);
    assert_eq!(Benchmark::PagerPageIn as u32, 10);
}
