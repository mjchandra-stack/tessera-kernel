<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Pager-Under-Pressure Harness

## Purpose

The external pager contract in
`../kernel/03-paging-faults-and-exceptions.md` is where user-space
filesystems historically die: latency collapse under load, reclaim deadlock,
and unbounded dirty state. The contract has rules for all three; this harness
is the specification of how those rules are proven, plus budget B10 from
`../architecture/03-performance-budgets.md` measured under pressure rather
than at idle. It is a Stage 0 exit gate per
`../roadmap/01-sequencing-and-mvp.md` and joins the permanent tier 3 suite in
`../lifecycle/02-build-and-test-infrastructure.md`.

## Components

- Reference pager: the RAM-backed filesystem pager from Stage 0, exercised
  as-is.
- Adversarial pager: a configurable pager for hostile scenarios — response
  delay (fixed, random, or unbounded), per-writeback memory allocation of
  configurable size, a handler that deliberately faults on pageable memory,
  refusal to acknowledge write-backs, and on-command death.
- Workload generators: mapped-file readers and writers with configurable
  working-set size, access pattern (sequential, uniform random, Zipfian),
  and dirty rate; runnable as multiple processes across multiple jobs so
  attribution and per-domain throttling are observable.
- Pressure controller: sizes physical memory (boot parameter or balloon) so
  target utilization levels are reached deterministically.
- Liveness watchdog: an independent supervisor asserting global forward
  progress; any scenario that stops progressing is converted into a failure
  with a full state dump (blocked-thread wait-for graph, pager queue depths,
  dirty counts) rather than a hung CI job.

The harness observes primarily through the structured events that
`kernel/03` "Observability" already mandates — page-in latency, deadline
misses, throttle and reclaim actions, data-integrity events. Asserting on the
event stream tests the observability contract and the paging contract with
the same run.

## Scenarios

### S1 — Page-In Latency Under Pressure (B10)

Working set at 50 %, 90 %, and 99 % of physical memory; uniform random reads
against the reference pager with RAM-resident data. B10 (15 µs p50 / 60 µs
p99 on R1) must hold at every utilization level. The point is the shape of
the curve: graceful degradation is acceptable within budget; a cliff is a
failed architecture, found here instead of in a product.

### S2 — Dirty Flood

A writer dirties pager-backed memory faster than the pager's configured
write-back bandwidth. Pass requires: dirty-page throttling engages at the
write fault per `kernel/03` "Write-Back Under Memory Pressure"; dirty pages
never exceed the configured per-object and per-domain bounds; unrelated
processes in other resource domains suffer no reclaim-driven termination and
no B10 violation; every throttle event is attributed to the flooding job.

### S3 — Reclaim Deadlock Probe

The adversarial pager allocates a configurable amount of memory inside each
write-back while the pressure controller holds the system at hard memory
pressure — the classic reclaim-needs-memory deadlock. With a declared
write-back reservation covering the allocation, reclaim must make forward
progress and the scenario must complete. With allocations exceeding the
declared reservation, the pager must fail cleanly (write-back error,
faulted ranges, supervision) — degraded outcomes are acceptable; a hang is
the one forbidden outcome, enforced by the watchdog.

### S4 — Durability Ordering

Using a fault-injecting test-build hook that records the kernel's clean/dirty
transitions: run write workloads with randomized write-back acknowledgment
timing, then assert from the recorded stream that no page was marked clean
before its acknowledgment arrived, and that the write-back snapshot handed to
the pager never reflected mutations made after issue (stable pages). This is
the mechanical check behind the durability contract that
`../storage/01-native-cow-filesystem.md` builds on.

### S5 — Self-Paging Cycle

Pager A's working memory is backed by an object paged by pager B, and vice
versa; both are then forced to fault simultaneously. The kernel must detect
the cycle and fault the requests per the anti-deadlock rules — resolution by
error, not by hang. Also run degenerately with a single self-paging pager.

### S6 — Pager Death

Kill the pager while it holds dirty pages with in-flight write-backs. Pass
requires the full sequence from `kernel/03` "Ownership, Resize, And
Revocation": bound objects enter the faulted state; a data-integrity event
reports exactly the lost dirty ranges, no more and no fewer; clean cached
pages remain readable until reclaimed; every consumer receives the
object-state signal; and the supervisor restart path rebinds a fresh pager.

### S7 — Deadline Misses And Supervision

The adversarial pager delays responses past the policy deadline for a
configurable fraction of requests. Faulting threads must receive fault errors
on their exception path within deadline plus a bounded margin — never
indefinite blocking — and repeated misses must escalate through supervision
per policy, with each miss and the escalation visible as events.

### S8 — Coordinated Flush

An `fsync`-shaped sequence: dirty a scattered range set, issue dirty-range
query, request write-back, await acknowledgments. Assert the queried ranges
exactly match what was dirtied (dirty-tracking correctness, including on a
software-emulated dirty-bit configuration) and measure flush latency for the
B16 baseline that the native filesystem will later be held to.

## Pass Criteria Summary

| Scenario | Forbidden outcome           | Required evidence                          |
| -------- | --------------------------- | ------------------------------------------ |
| S1       | Budget violation, cliff     | B10 met at all utilization levels          |
| S2       | Unbounded dirty, collateral | Throttle events, bounded dirty, isolation  |
| S3       | Hang                        | Progress with reservation; clean fail past it |
| S4       | Clean-before-ack            | Recorded transition stream, stable pages   |
| S5       | Hang                        | Cycle detected, requests faulted           |
| S6       | Silent data loss            | Exact integrity events, signals, restart   |
| S7       | Indefinite blocking         | Bounded fault errors, supervision events   |
| S8       | Dirty-tracking mismatch     | Exact range match, flush latency recorded  |

## Environments

Functional scenarios (S2–S8) run in the QEMU tier 3 matrix with constrained
memory configurations (512 MiB to 2 GiB) on every supported architecture,
including the software dirty-tracking configuration. S1 latency compliance is
judged on bare-metal R1 like every budget. Scenario parameters are fixed by
configuration checked in with the harness, so a failure reproduces from a
commit hash alone.

## Exit Criteria

Stage 0 exit requires every scenario passing on every architecture in the
matrix, S1 within budget on R1, and — same rule as the IPC harness — any
contract that cannot be honored triggers architecture revision through the
roadmap's risk path. The pager contract is load-bearing for filesystems,
model stores, and compatibility layers; this harness is where it earns that
position.
