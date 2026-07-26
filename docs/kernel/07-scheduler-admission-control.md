<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Scheduler Admission Control And Deadline Composition

## Purpose

`02-scheduling-memory-ipc.md` defines the scheduling classes and says of the
critical real-time class only that "admission is controlled by policy". A
guarantee without an admission test is a hope. This document defines the
reservation model, the schedulability tests, how deadlines compose across the
service call chains that this architecture makes unavoidable, and what
happens when capacity is lost. It closes the review finding that end-to-end
deadline behavior was asserted but not designed.

## Reservation Model

Guaranteed-latency work runs on reservations, not priorities alone.

- A reserved task declares a budget triple (C, T, D): worst-case execution
  budget C per period T, with relative deadline D ≤ T. Aperiodic
  bounded-latency work declares a minimum inter-arrival time as its T.
- Two disciplines share the reserved capacity:
  - Fixed-priority FIFO for short, interrupt-adjacent tasks (audio callback,
    radio deadline). Admitted by response-time analysis including blocking
    terms.
  - Earliest-deadline-first for pipeline and deadline tasks (media, sensor
    fusion). Admitted by a density test.
- Reservations are enforced as constant-bandwidth servers: a task exhausting
  C within a period is throttled to its next period, never allowed to starve
  other classes. Overruns are structured events attributed per component;
  repeated overrun can revoke admission by policy.

## Admission Tests

Admission is evaluated per scheduling domain (a core or cluster of uniform
capacity), not globally, because heterogeneous cores make global utilization
meaningless.

- Capacity normalization: each core advertises a capacity factor from the
  resource graph; budgets are normalized by the capacity of the cores the
  reservation may run on. A budget admitted on a performance core is not
  silently satisfiable on an efficiency core.
- EDF density test per domain: the sum over admitted tasks of
  C / min(D, T) must not exceed the domain's reserved-utilization bound.
- Fixed-priority tasks are admitted by response-time analysis against the
  other admitted tasks in the domain, with blocking terms below.
- The reserved-utilization bound U_rt defaults to 70 % of a domain and is a
  product-profile setting. The remainder is guaranteed headroom for the
  interactive, compute, and background classes, so reservations can never
  render a device unresponsive; background retains a small guaranteed floor
  to prevent starvation-by-reservation.
- Sustainable, not burst, capacity: admission is computed against
  thermally sustainable capacity for the domain, derated by the thermal model,
  so admitted guarantees hold through throttling rather than evaporating with
  boost clocks.

Blocking terms: owner-aware locks used by reserved tasks carry declared or
measured maximum hold times; the synchronous call-chain depth limit in
`04-synchronization-and-ipc-guarantees.md` bounds the inheritance chain, so
worst-case blocking is computable rather than open-ended.

Memory and fault terms: a page fault through a user-space pager is unbounded
relative to a reserved deadline, so admission closes that hole explicitly.
Critical real-time admission requires a declared, pinned working set — the
pin is charged against the resource domain's protected memory reservation,
and a fault outside the pinned set by an admitted critical task is a policy
violation event, not a silent deadline risk. Media-deadline tasks either pin
likewise or declare a fault-service budget that enters the schedulability
analysis. Exception handling on reserved tasks follows the handler-liveness
deadlines in `03-paging-faults-and-exceptions.md`, and policy may forbid
non-debugger exception handlers on critical tasks entirely.

## Composition With Resource Domains

Reservations draw from the CPU reservation of the job's `resource_domain`
(`05-jobs-containment-and-resource-control.md`): a child domain cannot admit
more reserved bandwidth than its ancestor reserves, mirroring the
limits-compose-downward rule. Admission requests beyond the domain's
reservation fail with a resource error; they do not queue.

## Serving Reserved Work: Server Reservations

Reserved tasks call services — that is the architecture — so services that
participate in guaranteed paths hold reservations of their own.

- A service declares a server reservation (C_s, T_s) sized for its worst-case
  per-request budget times its admitted request rate. Requests arriving under
  synchronous call handoff run on the caller's inherited priority or deadline
  but consume the server's reserved bandwidth.
- Admission of a client that will call servers checks the whole chain: each
  server on the declared path must have unclaimed server bandwidth for the
  client's request rate, or admission fails naming the saturated stage.
- A server whose reservation is exhausted fails further reserved calls fast
  with a resource error rather than silently degrading every client's
  latency. Non-reserved (best-effort) callers of the same service are simply
  scheduled in their own classes.

## End-To-End Deadline Composition

Media-deadline pipelines declare a pipeline descriptor: the ordered stages,
each stage's budget and executing domain, inter-stage queue bounds, and the
end-to-end period and deadline.

- Admission verifies each stage in its domain and that the sum of stage
  budgets, worst-case queue residence, and bounded blocking meets the
  end-to-end deadline.
- At runtime, deadline inheritance follows the pipeline: a stage runs under
  the deadline of the item it is processing, per the handoff rules in
  `04-synchronization-and-ipc-guarantees.md`.
- Deadline misses are attributed to the stage that overran its budget, not
  merely to the pipeline, so diagnosis names a component.

Accelerator stages (GPU, NPU, ISP) are admitted against accelerator queue
occupancy ceilings from `05-jobs-containment-and-resource-control.md` and
coordinated with the accelerator services; the kernel does not model
accelerator internals, it models the queue budget.

## Guests And SMT

- vCPUs receive reservations only through explicit host policy; reserved
  vCPUs are never overcommitted. Unreserved guests live in the guest class
  under proportional share.
- Admission accounts for SMT: a reservation requiring interference freedom is
  admitted only where the security-domain co-tenancy rules
  (`../security/01-security-model.md` "Microarchitectural Isolation") and an
  idle-sibling or compatible-sibling policy can be honored, and the sibling's
  lost capacity is charged against the domain.

## Capacity Loss And Revocation

Thermal emergencies, hotplug, and power policy can shrink capacity below the
admitted sum. The kernel never silently misses everyone's deadlines:

- Reservations carry an importance rank set by policy at admission.
- On capacity loss, the kernel revokes admissions lowest-rank-first until the
  remaining set is schedulable on the reduced capacity, delivering a
  revocation event to each victim so it can degrade deliberately (drop frame
  rate, reduce sample rate) rather than fail chaotically.
- Restored capacity triggers re-admission offers in rank order.

## Syscall Surface

Listed in `../api/01-system-call-interface.md` "Scheduling And Admission":
declare or modify a reservation on a thread or job, submit a pipeline
descriptor, query admission state and remaining domain bandwidth, and receive
admission-revocation events through ports.

## Defaults

| Parameter                          | Default            | Owner            |
| ---------------------------------- | ------------------ | ---------------- |
| Reserved-utilization bound U_rt    | 70 % per domain    | Product profile  |
| Background guaranteed floor        | 5 % per domain     | Product profile  |
| Synchronous call chain depth       | 8 (`kernel/04`)    | Policy, downward |
| Overruns before revocation review  | 3 per 100 periods  | Policy           |

## Observability

Admission decisions and rejections (with the failed test named), per-domain
reserved and consumed bandwidth, budget overruns, deadline misses with stage
attribution, inheritance activations on reserved paths, and every
capacity-loss revocation are structured events, so "why did audio glitch"
is answerable from the trace, per the troubleshooting workflows in
`../observability/01-debugging-monitoring-tracing-logging.md`.
