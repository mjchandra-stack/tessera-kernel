<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Interface Schema Language

## Purpose

Every stable interface in this system — service protocols, driver class
contracts, and the structured arguments of the syscall ABI — is "defined in
schemas" that generate bindings, validators, fuzzers, trace decoders, mocks,
and conformance tests. Until now the schema language itself was undefined,
despite being the most-referenced artifact in the design. This document
defines it: the Interface Schema Language (ISL).

ISL is closest in spirit to Fuchsia's FIDL, with three deliberate additions:
rights-typed handles, a canonical encoding suitable for signing, and a frozen
struct subset usable directly as syscall ABI.

## Requirements

- Deterministic memory layout; decode validates in place without allocation.
- Handle-aware: handles are typed and rights-constrained in the schema, and
  travel in a kernel-visible side table, never inside payload bytes.
- Evolvable under the monotonic extension rules of
  `02-abi-versioning-and-compatibility.md`.
- Canonical: exactly one valid encoding per value, so encoded artifacts can be
  hashed, signed, and deduplicated (`../security/02-cryptography-and-key-management.md`
  requires self-describing signed objects; ISL provides the encoding beneath
  them).
- Fuzzable and traceable by construction: the schema carries enough structure
  to generate structure-aware fuzzers and trace decoders mechanically.

## Type System

Primitives: `bool`, `int8`–`int64`, `uint8`–`uint64`, `float32`, `float64`.

Composites:

- `enum` — typed, explicit values, declared `strict` (unknown values are a
  validation error) or `flexible` (unknown values are preserved and passed
  through).
- `bits` — named flag sets over an unsigned base type.
- `struct` — frozen layout. Fields cannot be added, removed, or reordered
  after the struct is stable. Structs are the hot-path and syscall type.
- `table` — extensible record. Fields are named by ordinal; ordinals are
  add-only and never reused. Tables are the default for service protocols.
- `union` — tagged choice, `strict` or `flexible` like enums.
- `array<T, N>` — fixed length, inline.
- `vector<T>:N` — bounded length, out of line. Unbounded vectors are not
  expressible; every vector declares a maximum.
- `string:N` — bounded, validated UTF-8.
- `handle<type, rights>` — a handle whose object type and minimum rights mask
  are part of the type. The receiver-side binding rejects a message whose
  handle carries fewer rights than declared; rights beyond the declaration are
  reduced at transfer per the rights-reduction rule in
  `../kernel/01-kernel-model.md`.
- Out-of-line memory fields declare an ownership mode — `transfer`, `share`,
  or `snapshot` (the default) — with the semantics defined in
  `../kernel/04-synchronization-and-ipc-guarantees.md` "Out-Of-Line Memory
  Semantics". The schema compiler warns when a `share`-mode field is used in
  a validate-then-use position.
- Any field may be declared optional; optionality is explicit, never implied.

## Protocols

A `protocol` declares methods on a channel:

- Each protocol has a 64-bit interface ID derived from its fully qualified
  name and major version; it appears in the message header defined in
  `../kernel/02-scheduling-memory-ipc.md`.
- Methods carry explicit ordinals. Ordinals are never reused, including after
  removal.
- Method kinds: call (request and response, paired by transaction ID per
  `../kernel/04-synchronization-and-ipc-guarantees.md`), one-way request, and
  event (server-initiated one-way).
- Requests and responses are each a single struct or table.
- Methods may declare a deadline slot, filling the optional deadline metadata
  in the channel message header.

## Wire Format

- Little-endian, 8-byte alignment.
- A message is a primary object followed by out-of-line objects in
  depth-first declaration order.
- Table fields are envelopes: ordinal, size, and presence; absent fields cost
  nothing on the wire.
- Handles are indexed references into the message's handle vector, which the
  kernel validates and translates at transfer. Payload bytes never contain
  handle values.
- Canonical form: padding must be zero, envelopes must be minimal, vector and
  string lengths must match content. Decoders reject non-canonical input;
  there is no "lenient mode".

## Evolution Rules

Applying `02-abi-versioning-and-compatibility.md` mechanically:

- Structs are frozen; evolution happens by adding methods or migrating a
  parameter to a table in a new method.
- Tables and flexible enums/unions evolve by adding ordinals or members.
- Nothing is ever renumbered or reused; removed ordinals are reserved
  permanently in the schema file.
- Declarations carry `@available(added, deprecated, removed)` annotations tied
  to interface versions, which drive binding generation per ABI profile.
- Schema changes are reviewed as ABI changes, with the ABI diff tool operating
  on compiled schema IR, not source text, so formatting changes cannot mask
  semantic ones.

## Generated Artifacts

From one schema the toolchain generates, per design principle three:

- Bindings: Rust first-class; C for the ABI/FFI boundary; C++, Swift, and
  Kotlin for application frameworks.
- Validators: the same validation code for the runtime, the fuzzer, and the
  conformance suite, so they cannot drift apart.
- Structure-aware fuzz harnesses seeded from schema shape and bounds.
- Trace decoders keyed by interface ID and ordinal, correlated by the tracing
  correlation ID.
- Mock servers and clients for tests.
- Conformance goldens: encode/decode vectors checked across versions and
  across language bindings.
- Reference documentation.

## Kernel ABI Subset

Syscall structured arguments (`01-system-call-interface.md` "Structured
Arguments") are ISL structs restricted to: primitives, enums, bits, arrays,
handles, and nested structs — no tables, unions, vectors, or strings. Every
such struct begins with the mandatory `size`, `version`, and `flags` fields.
The kernel's validation code for these structs is generated from the same
schemas, so the syscall boundary and the service boundary share one
definition of validity.

## Limits And Security

- Default bounds, tightenable per channel per the message bounds in
  `../kernel/04-synchronization-and-ipc-guarantees.md`: 64 KiB inline
  payload, 64 handles, out-of-line nesting depth 32.
- All bounds are enforced before any payload interpretation.
- Schemas mark fields with data classifications from
  `../security/01-security-model.md` "Data Classification"; trace decoders and
  log renderers redact classified fields by default, which is how the
  redaction promises in `../observability/01-debugging-monitoring-tracing-logging.md`
  are kept mechanical rather than manual.
