// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The performance-microbenchmark result ABI, defined in ISL. `docs/prototypes/
// 01-ipc-benchmark-harness.md` ("Reporting") requires results be "structured
// events in an ISL-defined schema" carrying the benchmark ID, sample count, and
// p50/p90/p99/max. `Benchmark` numbers each result by its budget ID (B1, B2, …).
// The kernel harness reports a serial table today; these bindings are the seam
// for the eventual structured-event pipeline, generated and conformance-checked.

library tessera.perf.bench;

// The microbenchmarks, numbered by their performance budget (docs/architecture/
// 03-performance-budgets.md). External-pager page-in (B10) is measured by the
// pager-pressure harness (prototypes/02), not this suite.
strict enum Benchmark : uint32 {
    NULL_SYSCALL = 1;
    HANDLE_OP = 2;
    IPC_ROUND_TRIP = 3;
    WAIT_ON_ADDRESS = 6;
    CONTEXT_SWITCH = 7;
    ANON_FAULT = 8;
    COW_FAULT = 9;
    PAGER_PAGE_IN = 10;
};

// One benchmark's measured statistics (in the sample unit — TSC cycles).
// Percentiles are exact values from the sorted sample set (never a streaming
// estimator), per the methodology.
@abi
struct BenchResult {
    size: uint32;
    version: uint32;
    flags: uint64;
    benchmark: Benchmark;
    sample_count: uint32;
    p50: uint64;
    p90: uint64;
    p99: uint64;
    max: uint64;
};
