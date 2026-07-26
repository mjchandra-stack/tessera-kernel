<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Collection, Persistence, And Telemetry

## Purpose

`01-debugging-monitoring-tracing-logging.md` and the per-subsystem
observability contracts define what is emitted. This document defines the
layer they emit into: collection architecture, persistence across crashes,
flood control, the flight recorder that other documents already reference,
the normative correlation-ID definition, and the telemetry pipeline with its
egress choke point.

## Collection Architecture

- The log service (started early in boot, now in the service roster of
  `../architecture/01-system-architecture.md`) owns collection: it harvests
  the per-CPU rings of `../kernel/08-multicore-scalability.md`, merges by
  timestamp, and maintains the on-device store. Audit records live inside it
  under the integrity floor of `../security/01-security-model.md`.
- The diagnostics and telemetry service consumes from the log service and
  owns everything that faces outward: bundles, crash clustering, fleet
  telemetry, and egress. The split is deliberate — collection must survive
  and stay simple; interpretation and export can be rich and restartable.

## Persistence

- Panic-surviving ring: the platform support package declares a reserved
  persistent-memory region. The kernel and log service continuously mirror
  the recent high-severity tail and the flight-recorder tail into it; the
  panic path (`../kernel/03-paging-faults-and-exceptions.md`
  "Kernel-Internal Exceptions") finalizes it on preallocated resources. At
  next boot it is harvested into the crash report and cleared — the seconds
  before a panic, which are the diagnosis, survive the panic. Only
  class-permitted, redacted content enters the ring, since reserved memory
  outlives lock state.
- Retention is a classification property, enforced: the store applies
  per-class retention limits from `../security/01-security-model.md` "Data
  Classification" — the strongest class in a record sets its deletion
  deadline — plus size-bounded rotation per component. Retention
  enforcement is itself an audited action.

## Flood Control

- Log and trace emission is a resource-domain-limited rate
  (`../kernel/05-jobs-containment-and-resource-control.md`), like wakeups.
  Over-quota emission is dropped at the source with a per-component drop
  counter and a rate-limited meta-event, so a chatty component silences
  itself, not the system — and the silencing is visible.
- Audit records are never silently dropped: operations that require an
  audit record fail closed if the audit path cannot accept one. Audit
  volume is inherently bounded by the audited operations themselves.

## Flight Recorder And Trace Sessions

- The flight recorder is an always-on, per-domain bounded ring recording a
  sampled low-cost event window. It is the mechanism behind every "trace
  tail" reference — driver crash capture, watchdog escalation, harness
  failure attachments. Capture on failure snapshots the ring; no session
  needs to have been running.
- Policy-started trace sessions are the rich mode: wider event selection,
  payloads under authorization. Sessions declare their overflow policy at
  start — drop-oldest by default, drop-newest by choice, always counted —
  the same explicitness ports and channels got.
- The flight recorder runs during all budget measurement
  (`../architecture/03-performance-budgets.md`), so its overhead is inside
  every budget by construction rather than measured separately and
  forgotten.

## Correlation IDs, Normatively

One definition, ending per-subsystem improvisation:

- A correlation ID is a 128-bit value minted at a causal origin: an input
  event (by the input broker), an arriving network flow or request, a timer
  program firing, a lifecycle transition, boot itself. Whoever converts the
  outside world into work mints the ID.
- Propagation is automatic where the kernel can see causality: a thread
  carries a current correlation ID; synchronous calls and reply
  delegations propagate it to the callee for the duration of handling;
  pager requests carry the faulting thread's ID; exception reports carry
  the faulting thread's ID; pipeline stages inherit the item's ID.
  Asynchronous messages carry it explicitly in the message header, and a
  receiver adopts it as it begins handling. The **kernel** stamps that
  header field from the sending thread's current ID; a sender never
  supplies one, so a cause cannot be forged and the structured argument a
  caller passes carries no correlation field at all.
- Fan-out links, not shared IDs: when one cause spawns parallel work, each
  branch mints a fresh ID and emits a link event naming the parent, so
  traces form a tree that can be joined without ambiguity about which
  branch an event belongs to.
- VM boundary: host-side events are tagged with VM identity; guest-internal
  IDs are opaque to the host. Paravirtual queue descriptors may carry a
  guest-provided ID as an opaque annotation so cooperating guests can be
  joined across the boundary, but no host semantics ever depend on it.

## Timestamps And Cross-Device Correlation

- All structured events are timestamped on the boot clock, which advances
  across suspend; suspend and resume emit epoch-marker events so
  cross-sleep traces merge unambiguously, and the monotonic-to-boot offset
  is recorded at each transition.
- Cross-device correlation makes no global-clock claim: diagnostic bundles
  carry clock-offset annotations derived from the continuity transport's
  time exchange, sufficient to align traces after the fact.

## Telemetry Pipeline And Egress

- Metrics are typed instruments — counters, gauges, histograms — declared
  in ISL like every other schema, sharded per CPU per
  `../kernel/08-multicore-scalability.md`, and harvested on intervals by
  the diagnostics service.
- The diagnostics service is the single egress choke point: it is the only
  component holding a telemetry-egress capability, so "what leaves the
  device" is one component's auditable behavior, not a property scattered
  across emitters.
- Egress enforces the data-classification rules at the choke point:
  per-class egress permissions, the AI local-only telemetry boundary
  (`../future/01-ai-and-wearable-era.md`), and consent state. Population
  metrics are aggregated on device before egress, with
  differential-privacy noise where profile policy requires it; raw records
  leave only in user-approved diagnostic bundles.

## User-Space Instrumentation Posture

Static tracepoints in components are ISL-declared and compiled in; dynamic
probing of arbitrary user code is debugger authority
(`../api/01-system-call-interface.md`), full stop. There is no
uprobes-style side door, because a probe on someone else's code is
debugging and carries debugging's policy weight. Kernel-side dynamic
instrumentation remains the verified-program framework
(`../kernel/09-verified-programs.md`).

## Budgets

Observability's production-safety claim is numeric
(`../architecture/03-performance-budgets.md`): a disabled tracepoint costs
B31 (a load and a predicted branch), the always-on flight recorder is
bounded by inclusion in every budget run, and a full trace session declares
its ceiling (≤ 10 % on the reference workloads) — so "policy-controlled
tracing in production" stays true instead of quietly becoming "tracing
disabled in production."
