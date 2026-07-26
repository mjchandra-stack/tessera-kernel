<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# IPC Benchmark Harness

## Purpose

`../architecture/03-performance-budgets.md` makes budgets B1–B7 and B24 the
acceptance test for the services-outside-the-kernel bet, and Stage 0 of
`../roadmap/01-sequencing-and-mvp.md` cannot exit until they pass. This
document specifies the harness that measures them: what each benchmark does,
how time is measured so the numbers are trustworthy, how the harness proves
that handoff actually happened rather than merely being fast on an idle
machine, and what it reports. The harness is not a one-off experiment; it is
the permanent tier 4 suite from
`../lifecycle/02-build-and-test-infrastructure.md`, run per merge forever.

## Measurement Methodology

- Timing uses the invariant cycle counter (TSC on x86-64, CNTVCT on AArch64)
  with serialization before and after the measured region; the harness
  refuses to run if the counter is not invariant across the cores in use.
- Each benchmark collects a minimum of 1,000,000 measured iterations after a
  discarded warm-up phase of at least 10,000 iterations. Percentiles are
  computed exactly from the sorted sample set, never from streaming
  estimators. Outliers are reported with counts and maxima — never dropped.
- Two frequency configurations are run: pinned frequency for
  commit-to-commit comparability, and the production governor — the shipped
  default governor parameter set defined in
  `../power/01-power-management.md` — for honesty. Budget compliance is
  judged on the production-governor run.
- Production kernel configuration with profile-minimum microarchitectural
  mitigations enabled; a mitigations-off run may be collected for diagnosis
  but never for compliance.
- Benchmark threads are pinned; the harness records core assignments, SMT
  sibling state, and thermal state alongside every result.
- QEMU/KVM runs validate harness correctness only. Budget compliance is
  judged exclusively on bare-metal R1 reference hardware.

## Benchmarks

Each benchmark maps to exactly one budget row.

### BM-1 — Null Syscall (B1)

Tight loop invoking the validated no-op syscall. Measures pure
entry/validate/exit cost including mitigation overhead.

### BM-2 — Handle Object Operation (B2)

Signal-and-reset on an event object and query-rights on a duplicated handle,
reported separately. Measures handle-table lookup and rights-check cost above
BM-1.

### BM-3 — Synchronous Call Round Trip (B3)

A client and server pair on the same core connected by one channel. The
client issues call-with-response; the server replies immediately with the
request payload echoed. Payload sizes 64 B and 256 B, no handles. The
measured quantity is the full user-to-user round trip.

Validity checks, asserted per run:

- Exactly two context switches per round trip, confirmed from scheduler trace
  events — zero run-queue enqueues on the fast path, proving the direct
  handoff in `../kernel/04-synchronization-and-ipc-guarantees.md`
  "Synchronous Call Scheduling" occurred rather than a lucky wakeup.
- The server thread runs under the client's effective priority for the
  request duration, confirmed via the inheritance trace events.

### BM-4 — Handle Transfer Marginal Cost (B4)

BM-3 repeated with 1, 2, and 4 transferred handles per message (a duplicated
event handle each). Reported as the per-handle slope of the regression
against BM-3's baseline; the budget bounds the slope.

### BM-5 — Cross-Core Notify (B5)

A waiter blocked on a port on core B; a sender on core A signals a bound
event. Measures signal-call entry on A to waiter running in user space on B,
using the shared invariant counter. IPI delivery is included by construction.

### BM-6 — Contended Wake (B6)

A waiter blocked in wait-on-address; the owner writes and wakes. Measures
wake-call entry to waiter running. Repeated for the owner-aware lock with an
inheritance-boosted waiter to confirm the boosted path meets the same budget.

### BM-7 — Context Switch (B7)

Two threads in different address spaces alternating via directed yield.
Measures switch cost including address-space change and mitigation cost at
the boundary; reported alongside a same-address-space variant to expose the
mitigation delta.

### BM-8 — Cross-Core Call (B24)

BM-3's client/server pair with the server pinned to a different core,
exercising the remote path in
`../kernel/04-synchronization-and-ipc-guarantees.md` "Cross-Core Calls":
mailbox post, IPI, remote execution, and reply. Validity check: the caller's
priority is observed on the server core for the request duration. Reported
alongside BM-3 so the same-core/cross-core ratio is tracked explicitly —
growth in that ratio is the signal that services need sharding before the
budget fails.

### BM-9 — Interrupt To Handler (B32)

A timer-backed (or GPIO-loopback, where hardware permits) interrupt source
bound to an interrupt object; a driver-host thread waits on it. Measures
hardware interrupt assertion to the handler thread running in user space —
the microkernel-tax path for user-space drivers. Run with the waiting
thread under a server reservation, per
`../drivers/01-driver-framework.md` "Driver Unit And Hosting Model", since
that is the configuration reserved pipelines actually use.

## Load Scenarios

Idle-machine numbers alone would prove nothing about isolation. Every
benchmark runs in two conditions:

- Quiet: no competing load; establishes the floor.
- Contended: a compute-class soaker saturates every core and a
  background-class dirtier generates memory traffic. BM-3 and BM-6 run their
  client in the interactive class. Budgets apply unchanged in the contended
  condition — this is the test that priority inheritance and handoff actually
  protect latency-sensitive callers, which is the entire architectural claim
  under test.

## Scaling Condition

Isolation under load and scaling with cores are different properties; this
condition measures the second, enforcing budgets B19–B20 and the
no-hot-path-serialization rules in `../kernel/08-multicore-scalability.md`:

- BM-1, BM-2, and BM-3 are replicated as fully independent instances, one
  pinned per core (BM-3 as independent client/server pairs), plus a
  zero-fill fault loop over private mappings for B20.
- Reported metric: parallel efficiency — aggregate throughput at N cores
  divided by N times the single-instance baseline — at N = 2, half, and full
  core count, so a scaling knee is visible, not just the endpoint.
- Failure attaches a shared-cache-line profile (hardware coherence-miss
  counters) for the worst-scaling benchmark, so a serialization regression
  arrives naming the contended structure.
- B21 (parallel path resolution) joins this condition in Stage 1 when the
  VFS service exists; the harness mechanism is identical.

## Reporting

- Results are structured events in an ISL-defined schema
  (`../api/03-interface-schema-language.md`): benchmark ID, condition,
  hardware identity, sample count, p50/p90/p99/max, and environment record.
- The perf rig stores per-commit results; the 5 % regression gate from
  `../architecture/03-performance-budgets.md` is evaluated against the
  trailing baseline, and budget violations fail independently of trend.
- Every failure attaches the scheduler trace tail for the worst-percentile
  samples, so a regression arrives with its own diagnosis.

## Exit Criteria

Stage 0 exit requires: all budgets met on R1 in both conditions; the BM-3
validity checks passing (handoff proven, inheritance proven); and results
reproducible across three consecutive runs within 5 %. A budget that cannot
be met triggers the architecture-revision path in
`../roadmap/01-sequencing-and-mvp.md` "Risks Accepted" — the harness exists
to force that decision early, not to be negotiated with.
