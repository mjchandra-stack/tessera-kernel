<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Jobs, Containment, And Resource Control

## Purpose

The object model in `architecture/01-system-architecture.md` introduces the
`job`, `resource_domain`, and `security_context` objects; this document is their
normative definition. `kernel/02-scheduling-memory-ipc.md` defines resource
*accounting* without resource *enforcement*. Containers, app sandboxes, and the
app-lifecycle state machine all need grouping and enforcement together. This
document specifies the job object and the resource-limit primitive, and defines
how containers compose them.

## Job Object

A `job` is a kernel object that groups processes and child jobs into a tree.

- The root job is created at boot. Every process belongs to exactly one job.
- Creating a process requires a handle to the parent job with `create-process`
  rights. Jobs may be nested to arbitrary depth.
- A job carries policy that applies to all members transitively: resource
  limits, default sandbox constraints, exception channel, and kill semantics.

Job rights include `create-process`, `create-job`, `set-policy`,
`set-limits`, `suspend`, `kill`, and `admin`.

### Bulk Lifecycle Operations

- Suspend or resume a job suspends or resumes all member threads.
- Kill a job terminates all members, innermost first, and is the primitive
  behind container teardown, app termination, and watchdog escalation.
- A job exposes a state port that signals member exit, policy violation, and
  emptiness, so a supervisor can reclaim deterministically.

Jobs are the containment unit that the failure model and app-lifecycle states in
`platforms/01-mobile-desktop-wearable-experience.md` act upon.

## Security Context

A `security_context` is the kernel object that carries a principal's identity,
sandbox, and policy state, listed in `architecture/01-system-architecture.md`
"Core Object Model". It is the enforcement anchor for the policy prose in
`../security/01-security-model.md`.

- It holds the component and user identity, the sandbox profile, the security
  domain (`../security/01-security-model.md` "Security Domains"), and the
  data-class access the principal is permitted.
- A process references one security context; a job may set a default context that
  members inherit unless narrowed.
- A security context can only be narrowed by its holder, never widened, mirroring
  the rights-reduction rule for handles. Narrowing is the derive operation in
  `../api/01-system-call-interface.md` "Security Contexts".
- The scheduler reads the security domain from the context to enforce
  microarchitectural isolation, and the policy engine reads it to make capability
  decisions.

## Resource Limits And Enforcement

Accounting answers "how much was used." Limits answer "how much is allowed."
Both attach to jobs, and where finer control is needed, to processes.

### Resource Domain Object

A `resource_domain` object expresses enforceable ceilings and reservations:

- CPU: share weight, hard ceiling, and reserved minimum for real-time and
  interactive classes.
- Memory: hard limit, soft limit that triggers reclaim, and a reservation that
  is protected from reclaim.
- I/O and network: bandwidth ceilings and priority classes, wired to the I/O
  queue and packet scheduling paths.
- Accelerator time: ceilings on GPU, NPU, DSP, and media engine queue occupancy.
- Object counts: maximum processes, threads, handles, channels, and mappings.
- Wakeups and background execution: rate ceilings for power management.
- Observability: log and trace emission rate ceilings, enforced by
  drop-at-source with visible drop counters
  (`../observability/02-collection-persistence-and-telemetry.md`).

A resource domain is bound to a job. Limits compose down the job tree: a child
can only tighten, never exceed, an ancestor's ceiling.

### Enforcement Semantics

- Memory hard-limit breach triggers, in order, pressure notification, reclaim,
  and then policy-driven termination selecting killable members, consistent with
  the memory-pressure model in `kernel/02`.
- CPU, I/O, network, and accelerator ceilings are enforced by the respective
  schedulers as throttling, not termination.
- Object-count ceilings cause the offending create operation to fail with a
  resource error rather than degrading the whole system.
- Every enforcement action emits a structured event and is attributed to the
  job, process, and component.

This replaces the informal "resource groups" reference in
`virtualization/01-virtualization-and-isolation.md` with a concrete object that
the scheduler, memory manager, and I/O paths honor.

## Namespaces And Views

Containers and sandboxes restrict what a member can see and name. Namespaces are
per-job or per-process views, assembled by policy, never ambient:

- Filesystem view: the mount and path namespace assembled by the storage manager
  and VFS service.
- Service namespace: the set of capability names the namespace broker will
  resolve, per `kernel/04-synchronization-and-ipc-guarantees.md`.
- Network namespace: interfaces, routes, and firewall scope from the network
  manager.
- Identity mapping: user and tenant identity mapping for the group.
- Device view: the device classes and instances the group may open.

A namespace is a restriction of the creator's own view. A component cannot name
authority it was not granted, so namespaces reduce rather than confer authority.

## Storage Composition For Images

Container and system images need layered, verifiable storage. The storage stack
provides a composition model:

- Read-only verified base layers, backed by verified system images from
  `drivers/02-storage-networking-usb-pcie.md`.
- Optional overlay layers that redirect writes to a private writable layer.
- Per-layer identity, signature, and measurement recorded for attestation.

Image composition is a storage-service policy over standard file and memory
objects; it does not introduce private kernel hooks.

## Containers As Composition

A container is not a distinct kernel primitive. It is a composition of the
mechanisms above:

- A job for containment, bulk lifecycle, and policy.
- A resource domain for enforceable limits.
- Namespaces for filesystem, service, network, identity, and device views.
- Capability-filtered handles for authority.
- A composed, verified image for its root filesystem.

Application sandboxes use the same mechanisms with tighter defaults and a single
process, exactly as `virtualization/01` intends, but now backed by named
kernel objects rather than prose. Confidential VMs and paravirtual guests layer
the VM object model on top of the same job and resource-domain containment.

## Observability

Containment and resource control emit structured events:

- Job creation, nesting depth, member exit, and kill cascades.
- Limit configuration and every throttle, reclaim, and termination action with
  attribution.
- Namespace assembly and the authority each view was derived from.
- Image layer identity and verification results.

These events feed the accounting, health, and audit facilities so that resource
enforcement is inspectable per component, application, user, container, and VM.
