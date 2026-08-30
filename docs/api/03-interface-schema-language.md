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

ISL is closest in spirit to Fuchsia's FIDL, with four deliberate additions:
rights-typed handles, a canonical encoding suitable for signing, a frozen
struct subset usable directly as syscall ABI, and the syscall surface itself —
a `syscall` declaration, because a trap is not a message and spelling one as
the other would put a response payload where there is a result word.

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

## System Calls

A `syscall` declares one entry into the kernel: a number, the register frame it
reads, and the single value a success hands back.

- The number is the value in the trap's number register, and it is unique
  across the library. Unlike a protocol ordinal this is not a versioning
  question — two calls behind one number is an unresolvable dispatch, not a
  compatibility mistake — so the compiler rejects it outright.
- The body lists register slots in order, `arg0` upwards with no gaps. A slot
  whose type is a primitive, `bits`, `enum`, or `handle` carries the value; a
  slot naming a struct carries a **user pointer** to one, which is what the
  eighteen calls taking scalars in registers and the thirty-two taking an
  argument struct differ in.
- `returns:` names what a success carries; a call that omits it succeeds only
  with zero. Failure needs no declaration: it is one negative word for every
  call (`01-system-call-interface.md`, "The Result Word"). A call may not
  return a struct — the kernel has nowhere to write one the caller did not
  name.
- Required rights ride on the handle types rather than being declared beside
  the call, because that is where they are enforced: a slot declared
  `handle<Object, {MAP}>` needs `MAP` on the capability in that register, and a
  handle arriving inside an argument struct states its requirement on that
  struct's field.

A `syscall` generates no wire codec — there is nothing to encode — but it is
the subject of the generated reference, and `//tools/checks:surface_test` holds it
against the kernel's own call-number enumeration in both directions.

## Declarations From Another Library

`extern struct Name from dotted.library;` names a type this schema points at
and another one defines.

ISL has no imports, deliberately. The call surface has to point at the argument
structs, and each of those belongs beside the subsystem it describes rather
than beside the trap numbers; a register slot needs the struct's *name* and
never its layout, because the register holds a pointer. So the dependency is
declared rather than resolved, and checked across the schema set by
`//tools/checks:surface_test` — which fails if the named library declares no `@abi`
struct by that name. An external name may be pointed at by a register slot and
nothing else: it carries no layout here, so a struct in this schema cannot
contain one.

## Documentation

The comment block directly above a declaration, member, or field is its
documentation, and it reaches the compiled IR. A blank line ends the block, so
a remark floating between two declarations documents neither. `///` is accepted
as the same thing as `//`. A file's leading block, less its SPDX and copyright
lines, documents the library.

This is not a comment convention: the reference documentation is generated from
the schema, so prose that the compiler discards is prose the reference cannot
carry. The generated Rust bindings carry it too, as doc comments.

## Status

`@status(implemented | designed | deferred)` says whether the thing declared
exists in this tree today. It is optional everywhere except on a `syscall`,
where it is required — a reader of the reference cannot discover a call's
status from anywhere else.

Reasoning belongs elsewhere. *Why* something is deferred is an argument, and
arguments live in the deviation ledger (`build/README.md`); the generated page
links there rather than copying it. `@available(added=N)` already carries when
a declaration arrived and is used unchanged for the call surface — a second
annotation meaning the same thing is the drift this vocabulary exists to
prevent.

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
- A syscall number is never reused, including after removal, on the same terms
  as an ordinal — with the difference that it is enforced within one schema
  rather than across versions, because the number is the trap's own argument.
- Schema changes are reviewed as ABI changes, with the ABI diff tool operating
  on compiled schema IR, not source text, so formatting changes cannot mask
  semantic ones. The diff is `api/abi/surface.lock` — SHA-256 over each
  schema's `islc emit-ir` output, and one digest over the set — recomputed by
  `//tools/checks:abi_test` on every run. The lock is checked in rather than
  generated: a build that emitted both the artifact and the record certifying
  it would certify whatever it happened to produce, so changing the ABI is an
  edit to a reviewed file. Whether a change is breaking, and therefore what it
  does to the version, stays a judgement made under
  `02-abi-versioning-and-compatibility.md`; the gate holds only that the
  published surface and the schemas agree.

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
- Reference documentation: one Markdown page per schema, from
  `islc emit-docs`, built by `tools/ci/docs.sh`. It describes only what the
  schema declares, which is what separates it from the design documents in
  `docs/api` — those are free to describe what does not exist, and say so.
- The release artifact: `//api/abi:abi_bundle`, one tar carrying the schemas,
  their compiled IR, the reference pages, the generated bindings with a build
  file declaring them, the wire runtime, `userspace/uabi`, a version and a
  manifest. It is what a party without this tree targets the system with, and
  the test of that is that the user-space tree builds against it — an artifact
  a program must be edited to consume is not the interface the program was
  written against.

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
