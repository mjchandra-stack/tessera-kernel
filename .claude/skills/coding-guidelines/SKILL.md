---
name: coding-guidelines
description: Apply Tessera's coding guidelines when writing, editing, or reviewing any implementation code (Rust, asm, C) in this repository. Use before generating code and as the checklist when reviewing diffs.
---

# Tessera Coding Guidelines

Condensed from `docs/lifecycle/04-coding-guidelines.md` (normative — read it
for rationale; design docs win over both). Enforce these on every diff:

## Hard rules

- **Languages**: Rust for kernel/drivers/services; asm only in arch ports;
  C only for ISL-generated ABI headers. New C/C++ in privileged paths is a
  tracked memory-safety exception, never a convenience.
- **Unsafe**: services are `#![deny(unsafe_code)]`. Kernel/driver `unsafe`
  blocks need a `// SAFETY:` comment stating the *invariant* (not the
  operation) and an unsafe-inventory entry. `unsafe impl Send/Sync` counts.
- **Failure**: panics are bugs — no `unwrap()`/`expect()` outside tests
  unless provably infallible with a comment. Kernel allocation is fallible
  everywhere. Errors are stable-domain values, never parsed strings.
- **No silent fallback**: if code degrades (drops, truncates, falls back),
  it emits the structured event saying so.
- **Concurrency**: per-CPU by default; no lock on a budgeted path whose
  contention grows with cores; use the epoch-reclamation facility (no ad
  hoc lock-free); pad shared hot structs; document lock ordering per
  module; per-CPU sharded counters, never shared atomics on hot paths.
- **Boundaries**: every cross-component interface is an ISL protocol — no
  hand-rolled serialization. Never edit or check in generated code. Never
  renumber/reuse ordinals, fields, or rights. Caller identity comes from
  kernel-attested peer credentials, never payload fields.
- **Time/secrets**: time via the time page or clock syscalls (raw cycle
  counters are harness-only); randomness via the kernel CSPRNG only;
  secrets in secure pools, zeroized on drop, never formatted into logs.
- **Dependencies**: hash-pinned and vendored; permissive licenses only
  (Apache-2.0/MIT/BSD); TCB dependencies come from the curated allowlist.

## Every change ships with

- Its documented **observability events** (ISL-declared; no `println!`
  debugging; classified fields annotated for redaction).
- **Tests** at the lowest reproducing tier; regression test per bug fix;
  fuzz target for any parser of external input.
- **Perf results** attached if it touches a budgeted path; budgets change
  like ABI, never quietly.

## Conventions

- Module header names its governing spec: `Normative: docs/kernel/06-...`.
  Code diverging from the spec means the spec changes first.
- Budgeted modules declare it: `Budget: B3, B19`.
- SPDX header (`Apache-2.0`, project copyright) on every file; DCO
  sign-off on every commit; one concern per commit; flag ABI, budget,
  rights-catalog, and schema changes explicitly in the message.
