<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Multicore Scalability

## Purpose

The design models CPU topology thoroughly and bypasses the kernel on data
paths, but nothing required the kernel's own structures to scale with core
count — a global runqueue lock would have satisfied every written requirement
and destroyed multicore performance. This document states the internal
concurrency requirements: per-CPU structure discipline, the read-mostly
concurrency model, scheduler structure, TLB and ASID strategy, interrupt
distribution, accounting scalability, and the concurrency expectations on
services that sit on budgeted paths. It is verified by the scaling budgets
B19–B21 in `../architecture/03-performance-budgets.md`.

## Scalability Principles

- No hot path takes a lock whose contention grows with core count. Global
  locks are permitted only on slow paths (admission, binding, configuration,
  hotplug).
- Kernel state is per-CPU by default; shared state must justify itself in
  review the way unsafe code justifies itself in the memory-safety gate.
- Read-mostly data is read without locks or shared-cache-line writes.
- Frequently written shared structures are padded and laid out so that
  logically independent fields never share a cache line; scaling regressions
  from false sharing are caught by the B19–B21 budgets rather than left to
  code review alone.

## Read-Mostly Concurrency

The structures every syscall touches — handle tables, the resource graph
view, policy and security-context state, scheduler topology — are read
overwhelmingly more than written:

- The kernel provides one epoch-based reclamation facility (the Rust
  equivalent of RCU) as the standard mechanism; ad hoc lock-free schemes are
  not accepted where it suffices.
- Handle tables are per-process with lock-free lookup; a handle check on the
  syscall path performs no shared writes. Table mutation (create, close,
  transfer) synchronizes only within the owning process.
- The resource graph, policy decisions' inputs, and topology descriptions are
  published as immutable versioned snapshots swapped atomically; readers pin
  an epoch, never a lock. Hotplug and policy changes create a new snapshot —
  they are slow paths by definition.
- Revocation-scope liveness checks (`06-capability-revocation.md`) are a
  single read of scope state under the same epoch scheme, which is how the
  B15 budget holds under parallelism.

## Scheduler Structure

- Runqueues are per core, per class. The reserved classes
  (`07-scheduler-admission-control.md`) keep an additional per-domain EDF
  structure, touched only by the cores of that domain.
- Cross-core wakeups post to a lock-free per-core mailbox and send an IPI
  only when the target may be idle or running lower-priority work; a wakeup
  never takes a remote runqueue lock.
- Synchronous call handoff (`04-synchronization-and-ipc-guarantees.md`)
  bypasses runqueues entirely on the same core — the common service-call
  case adds zero shared-structure traffic.
- Compute and background classes balance by topology-aware work stealing:
  steal order is SMT sibling, then cluster, then NUMA node, respecting
  security-domain co-tenancy rules at every step. Interactive placement
  prefers an idle core in the waker's cluster.
- Periodic load balancing exists to correct drift, not to make placement
  decisions on the wakeup path; its cadence is a per-domain policy.

## TLB And ASID Strategy

Address-space switches and unmaps must not flush the world:

- Address-space identifiers (ASID/PCID) use a generation scheme per core so
  context switches avoid full TLB flushes; generation rollover is the rare
  path that pays a flush.
- The kernel tracks an active-core mask per address space. Shootdown IPIs go
  only to cores where the address space is live; cores running kernel-only
  or idle defer invalidation to their next user return (lazy TLB).
- Invalidations are batched: one shootdown covers a range and multiple
  pending unmaps, not one IPI per page.
- SVA extends the same discipline to the IOMMU
  (`../hardware/04-device-memory-and-unified-memory.md`): device TLB
  invalidations use hardware invalidation queues where present and are
  batched with the CPU shootdown they accompany.
- Synchronous guarantees are preserved, not weakened: revocation
  (`06-capability-revocation.md`) and SVA unbind complete only after
  acknowledged invalidation — batching changes the cost, never the contract.

## Interrupt Distribution

- Interrupt objects support an affinity mechanism, gated by the controller
  capability per `../hardware/03-component-interaction-model.md`.
- Policy lives in the device manager: at binding it spreads MSI-X vectors
  across cores using the topology and the driver's queue model, steering
  each per-queue interrupt to the core that consumes that queue, so
  multi-queue storage and networking scale without cross-core completion
  traffic.
- Affinity is rebalanced on hotplug, thermal capacity loss, and power-state
  changes through the same resource-graph events as everything else;
  reserved-class and wake-capable interrupts are pinned per admission and
  power policy.

## Accounting And Event Scalability

The accounting model in `02-scheduling-memory-ipc.md` and the observability
contract must not become the global lock:

- Counters are per-CPU sharded with relaxed writes, aggregated lazily on
  read or on a periodic fold; nothing on a hot path writes a shared counter.
- Limit enforcement (`05-jobs-containment-and-resource-control.md`) charges
  against per-CPU slack replenished in batches from the domain total, so the
  hot path pays a local decrement and only exhaustion touches shared state.
- Trace and log emission writes to per-CPU ring buffers; ordering across
  CPUs is reconstructed from timestamps and correlation IDs at read time,
  never imposed at write time.

## Scalable Services

Kernel scalability is necessary but not sufficient: path resolution, packet
processing, and composition happen in services. A perfectly scaling kernel
behind a single-threaded VFS still serializes every open in the system.

- Any service on a budgeted path must meet its budget at full core count,
  not just in isolation; B21 makes this testable for the VFS path and the
  pattern generalizes.
- The supported patterns are shared-nothing sharding (per-core workers, each
  owning a partition of state, clients routed by shard) and multi-threaded
  handling over read-mostly snapshots — the same epoch discipline as the
  kernel, available to services through the runtime libraries.
- One channel endpoint serving all clients of a service is a
  contention-by-design smell; the namespace broker hands each client its own
  channel, and services scale receive-side by binding channels across
  per-core workers.
- The driver framework already assumes multi-queue devices; driver hosts
  align queue ownership with the interrupt steering above so a queue's
  interrupt, completion processing, and consumer run on the same core.

## Verification

B19–B21 in `../architecture/03-performance-budgets.md` define required
parallel efficiency for IPC, anonymous faults, and path resolution at full
core count, measured by the scaling condition of
`../prototypes/01-ipc-benchmark-harness.md`. They are release gates like
every other budget: a change that serializes a hot path fails CI on the
scaling curve even if every single-core latency budget still passes.
