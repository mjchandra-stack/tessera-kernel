<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Capability Revocation

## Purpose

`../security/01-security-model.md` promises that capabilities are revocable
and that revoking a capability revokes every capability derived from it. For
broker-mediated objects that is a service-level behavior, but for directly
held kernel objects it requires kernel bookkeeping — and naive per-duplication
derivation tracking (a capability derivation tree touched on every duplicate,
as in seL4's CDT) puts allocation and bookkeeping on one of the hottest paths
in the system. This document defines the mechanism that delivers the promised
semantics with O(1) hot paths: revocation scopes.

## Design Overview

The insight is that transitive revocation is only meaningful at trust
boundaries. Duplications inside one component share fate with the component
anyway — killing the process or job reclaims them. So the kernel does not
track intra-component duplication at all; it tracks delegation.

- Handles are unscoped by default. Duplicate and transfer of an unscoped
  handle create no derivation record and stay O(1) with no allocation.
- When a grantor delegates across a trust boundary, it derives the handle
  into a revocation scope. Every handle later duplicated or transferred from
  a scoped handle inherits the scope automatically. A scope can be narrowed
  (derive a child scope) but never shed.
- Revoking a scope invalidates every handle in it, transitively through child
  scopes, system-wide.

## The Revocation Scope Object

`revocation_scope` is a kernel object.

- Rights: `derive` (create scoped handles and child scopes), `revoke`,
  `admin`. These are registered in the Rights Catalog in
  `../security/01-security-model.md`.
- Scopes form a tree. A child scope created from a parent is revoked when the
  parent is revoked.
- Scope state is a liveness flag plus bookkeeping lists: child scopes,
  memory mappings established through scoped handles, and waiters blocked on
  scoped handles.

## Operational Semantics

On use of a scoped handle, the kernel performs a liveness check: one
dereference and one flag load, budgeted at ≤ 20 ns
(`../architecture/03-performance-budgets.md` B15). Handles do not chain to
ancestor scopes at use time; revocation cascades eagerly at revoke time so the
per-use check is O(1) regardless of delegation depth.

`revoke(scope)` performs, before returning:

1. Marks the scope and, cascading eagerly, all descendant scopes dead.
2. Unmaps every memory mapping established through handles in the revoked
   scopes, completing TLB shootdown, so subsequent access faults rather than
   reading stale data — the behavior `../security/01-security-model.md`
   requires for mapped objects.
3. Wakes every waiter blocked on a scoped handle with a distinct
   revocation error; in-flight channel operations complete or cancel with the
   same error.
4. Emits an audit event with the recorded reason, per
   `../security/01-security-model.md` "Audit And Forensics".

After return, no operation through any handle in the revoked scopes can
succeed. Dead handle-table entries are reaped lazily on next use or close;
the scope object itself is freed when its references drop.

## Cost Model

| Operation                          | Cost                                        |
| ---------------------------------- | ------------------------------------------- |
| Duplicate/transfer unscoped handle | O(1), no allocation                         |
| Derive handle into scope           | O(1) plus one reference                     |
| Create child scope                 | O(1) allocation                             |
| Per-operation liveness check       | O(1), ≤ 20 ns (B15)                         |
| Revoke                             | O(descendant scopes + mappings + waiters)   |

Revocation cost scales with what was delegated and mapped, never with the
total number of handles in the system.

## Relationship To Brokers And Jobs

- Broker-mediated capabilities (device access, namespace entries, data-class
  access) are still revoked at the broker, per
  `../security/01-security-model.md`. Brokers use revocation scopes
  internally when they hand out direct kernel objects — for example a shared
  memory ring granted alongside a brokered device — so revoking at the broker
  also kills the fast-path handles it granted, closing the gap between
  policy-level and kernel-level revocation.
- The namespace broker (`04-synchronization-and-ipc-guarantees.md`) derives
  granted channels into a per-grant scope, making every resolution
  individually revocable.
- Agent delegation chains in `../future/02-ai-runtime-security.md` map
  directly onto child scopes: a sub-agent's scope is a child of its parent's,
  so revoking the task revokes the whole chain mid-flight.
- Jobs remain the containment primitive for killing a principal outright;
  scopes exist to withdraw specific authority without killing anyone.

## Syscall Surface

Listed under "Handles And Capabilities" in
`../api/01-system-call-interface.md`: create revocation scope, create child
scope, duplicate or transfer a handle into a scope, and revoke.

## Observability

Scope creation, derivation counts, revocations, cascade sizes, mappings
unmapped, and waiters cancelled are emitted as structured events, so audits
can answer both "what could this component reach" and "what was withdrawn,
when, and why".
