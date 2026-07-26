<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Verified Programs

## Purpose

`01-kernel-model.md` permits constrained kernel extension through "verified
packet filters", "verified tracing probes", and "verified storage or security
hooks", and lists requirements — static verification, resource limits,
explicit attach points, audit logs, ABI versioning, kill switch — without a
design. Since these programs run inside kernel privilege, they are squarely
in the trusted computing base and deserve the same rigor as the syscall ABI.
This document defines the framework: one program model shared by every
attach-point class, so networking, tracing, and storage hooks do not grow
three divergent verifiers.

## Program Model

- A verified program is delivered as bytecode for a restricted register
  machine. Source language is unconstrained — the toolchain (a Rust subset
  first) compiles to the bytecode; the kernel trusts only the verifier,
  never the compiler.
- Programs are components: signed, manifest-carrying, versioned, and subject
  to the same supply-chain rules as drivers
  (`../lifecycle/01-development-maintenance-update-model.md`).
- Program state lives in typed map objects — kernel objects with handles and
  rights like everything else. A program can touch only the maps whose
  handles were attached with it; there is no ambient state.

## Verifier Guarantees

The verifier statically proves, before load, that a program:

- Terminates: loops are bounded; the per-invocation instruction budget is a
  verified property, not a runtime hope.
- Is memory-safe: access is limited to the attach point's typed context, the
  program's stack frame, and granted maps — all bounds-checked at
  verification time. There are no raw pointers in the model.
- Calls only the helper functions its attach-point class declares, with
  statically checked argument types.
- Stays within stack and map-size limits declared at load.

Programs that cannot be proven safe are rejected; there is no "trusted
program" bypass. Execution is interpreter-first; an in-kernel ahead-of-time
translator is permitted per architecture under the fast-path gate in
`../01-design-principles.md`, with translated code measured like any other
kernel text.

## Attach Points

Attach points are explicit, versioned kernel interfaces — the extension
analog of the syscall ABI, evolving under the same monotonic rules
(`../api/02-abi-versioning-and-compatibility.md`):

- Each attach-point class declares its context type (defined in ISL so trace
  decoding and fuzzing come for free), its helper set, and its write powers.
- Packet filters (`../network/01-network-stack.md`): read packet data and
  metadata, return a verdict (pass, drop, redirect queue, mark); they cannot
  modify payload or originate packets.
- Tracing probes (`../observability/01-debugging-monitoring-tracing-logging.md`):
  read-only over their context, emit structured events into per-CPU buffers;
  data-classification redaction applies to what they may capture.
- Storage and security hooks: verdict-only, per their subsystem contracts.

## Authority And Limits

- Loading a program requires a capability for its attach-point class;
  sandbox profiles grant none by default. Every load, attach, detach, and
  rejection is an audit event naming the program identity and authority.
- Map memory is charged to the loader's resource domain
  (`05-jobs-containment-and-resource-control.md`); per-invocation
  instruction budgets bound hot-path cost, and a program's aggregate CPU
  time is accounted and visible.
- Execution takes no locks and allocates nothing: programs run on per-CPU
  scratch state, consistent with `08-multicore-scalability.md`.

## Lifecycle And Kill Switch

- Detach is immediate and always available to the attaching authority and
  to platform policy — the kill switch of `01-kernel-model.md` is just
  revocation, and revocation scopes (`06-capability-revocation.md`) apply to
  program and map handles like any other.
- Programs are versioned artifacts; a revoked program version cannot be
  reattached, following the same revoke-and-replace pattern as compilers,
  models, and keys.
- Attach-point ABI changes follow deprecation policy; a program built for a
  removed attach-point version fails to load with a versioned error, never
  silently misbehaves.

## Observability

Per-program run counts, per-invocation time histograms, verdict statistics,
budget exhaustions, and verifier rejections (with reasons) are structured
events, so a misbehaving or expensive program is identified from the trace,
not from a bisect.
