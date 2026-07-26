<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Performance Budgets

## Purpose

Design principle four permits in-kernel fast paths only against a documented
latency or throughput requirement, but the core primitives themselves had no
budgets, so the requirement had nothing to be measured against. This document
gives the primitives normative budgets. They are release gates, enforced by
the testing strategy in
`../lifecycle/01-development-maintenance-update-model.md`, and they are the
objective test behind every fast-path petition: a service path that cannot
meet its end-to-end budget is the documented trigger; a path that can is
denied kernel residence.

The hybrid architecture is a bet that isolated services can perform. These
numbers are the bet made falsifiable.

## Reference Hardware Classes

Budgets are stated for reference class R1 and scaled for the others:

- R1 — desktop/server: out-of-order x86-64 or AArch64 core at ≥ 3 GHz.
- R2 — mobile: mid-tier AArch64 core near 2 GHz. Budgets ×2 unless stated.
- R3 — wearable/embedded: in-order core near 1 GHz. Budgets ×5 unless stated.

Conditions: production kernel configuration, microarchitectural mitigations
enabled per profile minimums, warm caches unless stated, p50 and p99 over a
defined benchmark population. The benchmark definitions live with the
conformance suite and are versioned; changing a budget is reviewed like an ABI
change.

## Primitive Budgets (R1)

| ID  | Primitive                                                      | p50     | p99    |
| --- | -------------------------------------------------------------- | ------- | ------ |
| B1  | Null syscall (validated no-op)                                  | 150 ns  | 600 ns |
| B2  | Handle object operation (signal event, query rights)            | 250 ns  | 1 µs   |
| B3  | Same-core synchronous channel call round trip, ≤ 256 B, no handles | 2 µs | 8 µs   |
| B4  | Additional cost per transferred handle (≤ 4 handles)            | 300 ns  | —      |
| B5  | Cross-core notify: send plus port wake on another core          | 4 µs    | 15 µs  |
| B24 | Cross-core synchronous call round trip, ≤ 256 B, no handles     | 6 µs    | 20 µs  |
| B6  | Contended wake latency, wait-on-address or owner-aware lock     | 2 µs    | 10 µs  |
| B7  | Context switch, same core, different address space              | 800 ns  | 3 µs   |
| B8  | Anonymous zero-fill page fault, 4 KiB                           | 2 µs    | 10 µs  |
| B9  | Copy-on-write fault, 4 KiB                                      | 3 µs    | 12 µs  |
| B10 | External pager page-in, pager resident with data in RAM         | 15 µs   | 60 µs  |
| B11 | I/O queue submission to driver-host visibility                  | 3 µs    | 10 µs  |
| B12 | NVMe 4 KiB QD1 random read, added latency versus raw device     | 10 µs   | 25 µs  |
| B13 | NVMe QD32 random read on one submitting core                    | ≥ 90 % of device IOPS | — |
| B14 | VFS open of a warm, cached path (two service round trips)       | 8 µs    | 25 µs  |
| B15 | Revocation-scope liveness check per operation (`../kernel/06-capability-revocation.md`) | 20 ns | — |
| B16 | Small-file `fsync` via the native filesystem intent log, NVMe (`../storage/01-native-cow-filesystem.md`) | 500 µs | 2 ms |
| B17 | Snapshot creation, native filesystem subvolume                 | 5 ms    | 50 ms  |
| B18 | Contiguous allocation, 32 MiB from a lent carveout (`../hardware/04-device-memory-and-unified-memory.md`) | 5 ms | 50 ms |
| B27 | Kernel-handled VM exit round trip (inject, halt, timer) (`../virtualization/02-vmm-and-exit-model.md`) | 2 µs | 8 µs |
| B28 | VMM-handled exit round trip (MMIO emulation)                   | 10 µs   | 30 µs  |
| B29 | Paravirtual block 4 KiB QD1, added latency versus host-native  | 15 µs   | 40 µs  |
| B30 | Disposable VM boot to guest init                                | 300 ms  | 1 s    |
| B31 | Disabled tracepoint on a hot path (`../observability/02-collection-persistence-and-telemetry.md`) | 2 ns | — |
| B32 | Hardware interrupt to driver-host handler thread running        | 5 µs    | 20 µs  |

Observability overhead is otherwise budgeted by construction: the always-on
flight recorder runs during every budget measurement, so its cost is inside
B1–B30; a full trace session declares a ceiling of ≤ 10 % on the reference
workloads, verified by re-running the budget suite with the session active.

Networking: bulk TCP at ≥ 90 % of 10 GbE line rate using ≤ 1.5 cores end to
end; added one-way latency of the user-space stack versus a driver-host raw
packet path ≤ 15 µs p50; and B25 — 64-byte UDP receive-and-echo through the
full data path (`../network/01-network-stack.md`) at ≥ 1.5 Mpps per core,
the budget that exposes descriptor-path overhead bulk TCP hides.

## Scaling Budgets

Latency budgets alone cannot catch serialization: a change that adds a global
lock can pass every row above and still collapse on a many-core machine. The
following are parallel-efficiency budgets — the workload is replicated one
instance per core at full core count on R1, and the aggregate must reach the
stated fraction of core-count times the single-instance baseline. They
enforce the internal concurrency requirements in
`../kernel/08-multicore-scalability.md`.

| ID  | Parallel workload (one instance per core)                     | Required efficiency |
| --- | ------------------------------------------------------------- | ------------------- |
| B19 | Independent same-core synchronous IPC pairs (BM-3 replicated)  | ≥ 85 %              |
| B20 | Anonymous zero-fill faults on private mappings                 | ≥ 80 %              |
| B21 | Warm cached path resolution, one client per core (Stage 1)     | ≥ 70 %              |

## Power Budgets

Power budgets are judged on R2-class reference hardware under the mobile
profile (wearable multipliers set per profile), enforcing the system sleep
and attribution design in `../power/01-power-management.md`:

| ID  | Measure                                                        | p50     | p99    |
| --- | -------------------------------------------------------------- | ------- | ------ |
| B22 | System suspend entry, decision to platform sleep               | 300 ms  | 1 s    |
| B23 | Resume from suspend-to-idle to first rendered frame            | 400 ms  | 1.5 s  |

Idle floor: system-initiated wakeups at display-off idle are budgeted per
profile (mobile default ≤ 30 per hour), measured over an eight-hour tier 5
soak; every wakeup above the floor must be attributable to a named wake
source, so an idle regression arrives with its cause.

## End-To-End Budgets

- Input to photon: the platform stack (input broker, shell, compositor,
  display) adds no more than one frame period at the active refresh rate over
  the application's own latency.
- Composition (B26): full-screen composition of a representative surface
  stack (eight surfaces, one video plane, one protected surface) completes
  within 40 % of the frame interval at the display's target refresh on R2,
  p99 per frame, measured from the present-feedback events of
  `../graphics/01-surface-and-presentation.md` — headroom for client
  rendering is the budget, not a hope.
- Audio: a 128-frame buffer at 48 kHz (2.7 ms) sustains 24 hours with zero
  underruns under the critical real-time class on R1 and R2.
- Boot: embedded profile reaches first frame or service readiness ≤ 3 s from
  power-on, excluding firmware; mobile profile cold-boots to lock screen in
  5 s p50 / 10 s p99 on R2, measured from the boot-sequence events of
  `../lifecycle/03-boot-sequence-and-update-mechanics.md`.
- Driver-host crash to device rebound, virtio-class device: ≤ 500 ms with no
  kernel involvement beyond the failure model.

## The Handoff Dependency

B3 is achievable only with synchronous call handoff — direct switch to the
callee without a run-queue round trip, carrying priority and deadline, as
specified in `../kernel/04-synchronization-and-ipc-guarantees.md` "Synchronous
Call Scheduling". That mechanism is therefore not optional; it is the
load-bearing member of the entire services-outside-the-kernel bet, and B3 is
its acceptance test.

Similarly, B10 assumes the pager wake path treats the faulting thread's
priority as inherited by the pager request per the same handoff rules, and B12
assumes the shared-ring data plane from
`01-system-architecture.md` with no per-I/O copies.

## Prototype Obligations

Two harnesses must exist and pass before Stage 0 of
`../roadmap/01-sequencing-and-mvp.md` exits:

1. IPC microbenchmark suite covering B1–B7 with statistical reporting, run per
   commit on reference hardware. Specified in
   `../prototypes/01-ipc-benchmark-harness.md`.
2. Pager-under-pressure harness: drives a pager-backed working set past
   physical memory while the pager itself allocates, verifying the write-back
   reservation and dirty-throttling rules in
   `../kernel/03-paging-faults-and-exceptions.md` and budget B10 under
   pressure rather than only at idle. Specified in
   `../prototypes/02-pager-pressure-harness.md`.

## Enforcement

- The CI perf rig runs the budget suite on R1-class hardware per merge and on
  R2/R3 hardware per release candidate.
- A regression worse than 5 % against any budget blocks the release train
  until waived by the same review that owns ABI changes.
- Budget results are published with each release so vendors and application
  developers can rely on them as platform contracts, consistent with
  "Compatibility is a product feature".
