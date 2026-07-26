<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Coding Guidelines

## Purpose And Authority

These guidelines translate the design's normative gates into rules a
reviewer can apply to a diff. They are not style preferences: nearly every
rule below cites the design document that mandates it, and where a guideline
and a design document disagree, the design document wins and the guideline
gets fixed. Mechanical enforcement lives in tier 0 of
`02-build-and-test-infrastructure.md`; anything here that *can* be a lint or
a build gate *must* become one rather than remaining reviewer vigilance.

## Languages By Layer

Per the language table in `../../OVERVIEW.txt`:

- Rust for the kernel, driver components, and system services — the pinned
  toolchain of `02-build-and-test-infrastructure.md`, no exceptions per
  developer machine.
- Assembly only inside architecture ports, behind the porting layer of
  `../hardware/01-platform-and-cpu-support.md`.
- C only for the generated ABI boundary (ISL-emitted headers) and
  sanctioned legacy code under the sandboxing rules of
  `../security/01-security-model.md` "Memory Safety". New C or C++ in
  privileged paths is a memory-safety exception requiring an owner, a
  bounded scope, and a tracked entry — not a convenience.
- Kernel code may use unstable Rust features only from the enumerated,
  reviewed list in `02-build-and-test-infrastructure.md`, each with a
  migration plan. The list shrinks.

## Unsafe Code

`../security/01-security-model.md` makes memory safety a gate; this is the
gate at code granularity:

- Services and applications: `#![deny(unsafe_code)]`. An unsafe block in a
  service is a design event, not a code review nit.
- Kernel and drivers: every `unsafe` block carries a `// SAFETY:` comment
  stating the invariant that makes it sound and where that invariant is
  enforced. A SAFETY comment that restates the operation instead of the
  invariant fails review.
- Every module containing unsafe code is an entry in the unsafe inventory
  (tier 0 gate): owner, scope, and the reason no safe expression exists.
  New unprovenanced unsafe fails the build, per
  `02-build-and-test-infrastructure.md`.
- `unsafe impl Send`/`Sync` are inventory entries like any other unsafe —
  they are concurrency claims the compiler cannot check.

## Failure Discipline

- Panics are bugs. Kernel panic semantics are abort
  (`../kernel/03-paging-faults-and-exceptions.md` "Kernel-Internal
  Exceptions"); service panics are crashes handled by the failure model.
  Code must not use panic as control flow: no `unwrap()`/`expect()` outside
  tests except where infallibility is provable, stated in an adjacent
  comment, and preferably encoded in the type instead.
- Kernel allocation is fallible everywhere: allocation failure returns a
  resource error; there is no infallible-alloc path in kernel code. Reclaim
  and write-back paths draw only from their declared reservations
  (`../kernel/03` "Write-Back Under Memory Pressure").
- Errors use the stable numeric domains of
  `../api/01-system-call-interface.md`; errors are values, machine-readable
  and trace-decodable, never strings parsed by callers.
- No silent fallback, ever: the design's recurring pattern — linear-layout
  fallback is traced, expired messages are counted, drops are attributed —
  is a code rule. If code degrades, it emits the event that says so.

## Concurrency

`../kernel/08-multicore-scalability.md` is normative; in code terms:

- Kernel state is per-CPU by default. A new shared mutable structure
  justifies itself in review the way unsafe does, and a lock on a budgeted
  path whose contention grows with core count is a rejected diff.
- Read-mostly data uses the epoch-reclamation facility. Ad hoc lock-free
  structures are not accepted where it suffices — one memory-reclamation
  scheme, audited once.
- Frequently-written shared structures are cache-line padded; logically
  independent fields never share a line on hot paths.
- Every module with more than one lock documents its lock ordering at the
  module header. Blocking calls in interrupt or non-preemptible context are
  forbidden and linted where possible.
- Counters on hot paths are per-CPU sharded with lazy aggregation
  (`../observability/02-collection-persistence-and-telemetry.md`); a shared
  atomic counter on a budgeted path is the accounting anti-pattern named in
  kernel/08.

## Interfaces And ABI

- Everything that crosses a component boundary is an ISL protocol
  (`../api/03-interface-schema-language.md`). Hand-rolled serialization,
  ad hoc byte formats, and "just this once" JSON between components are
  rejected — bindings, validators, fuzzers, and trace decoders exist only
  for schemas.
- Generated code is never edited and never checked in
  (`02-build-and-test-infrastructure.md`).
- Stable ordinals, fields, and rights are never renumbered or reused;
  schema changes are reviewed as ABI changes with the diff tool's output
  attached (`../api/02-abi-versioning-and-compatibility.md`).
- Handles are requested with minimum rights; a component holding rights it
  does not use is a finding. New rights go through the Rights Catalog
  before use (`../security/01-security-model.md`).
- Caller identity comes from kernel-attested peer credentials
  (`../kernel/04-synchronization-and-ipc-guarantees.md`), never from
  payload fields.

## Time, Randomness, And Secrets

- Time comes from the time page or clock syscalls
  (`../api/01-system-call-interface.md` "Time"); raw cycle counters are
  benchmark-harness territory, not application logic — and are restricted
  as a side-channel primitive besides (`../security/01-security-model.md`).
- All randomness in privileged code comes from the kernel CSPRNG
  (`../kernel/03` "Kernel Randomness"). No ad hoc PRNGs, no seeding from
  time.
- Secrets live in secure memory pools, are never formatted into logs or
  traces (the Credentials class rules are absolute), and are zeroized on
  drop. Cryptographic code is constant-time per the microarchitectural
  rules; algorithm choices go through the crypto provider, never inlined
  (`../security/02-cryptography-and-key-management.md`).

## Observability Is Part Of The Change

- A subsystem's documented observability contract is implemented with the
  subsystem, not after it. A PR adding a mechanism without its structured
  events is incomplete, per the future-proofing checklist in
  `01-development-maintenance-update-model.md`.
- Events and tracepoints are ISL-declared; `println!`-style debugging does
  not land. Data classification annotations on event fields are mandatory
  where the payload could carry classified data — redaction is codegen,
  not diligence (`../api/03-interface-schema-language.md`).
- Errors returned to callers and events emitted for operators carry the
  correlation ID discipline of
  `../observability/02-collection-persistence-and-telemetry.md`.

## Performance Discipline

- Know your budget: code on a budgeted path names it — the convention is a
  module-header note (`Budget: B3, B19`) — and changes to such code attach
  perf-rig results to the PR. The 5 % regression gate
  (`../architecture/03-performance-budgets.md`) is mechanical, but the
  author runs the suite before CI does.
- No allocation, no locks, no shared-cache-line writes on budgeted paths;
  see Concurrency above.
- A change that cannot meet its budget triggers the fast-path petition
  process, not a quiet budget edit — budgets change like ABI.

## Testing

Per the tiers of `02-build-and-test-infrastructure.md`:

- Unit tests live beside the code; kernel subsystems are written
  host-testable against the mocked architecture layer unless physically
  impossible, in which case they carry kernel-test-image coverage.
- Every bug fix lands with a regression test at the lowest tier that
  reproduces it. No exceptions — this is how the tier system accretes
  value.
- Every parser of external input has a fuzz target before it merges
  (`../security/01-security-model.md`); storage-format code adds
  crash-consistency cut points to the harness.
- Tests are sandboxed components with manifest-declared capabilities; a
  test that needs ambient authority is testing the wrong thing.

## Comments And Documentation

- Comments state invariants and constraints the code cannot express —
  SAFETY invariants, lock ordering, units, why a bound is what it is.
  Comments that narrate the code or justify the diff to a reviewer are
  removed.
- Every module header names its governing design document
  (`Normative: docs/kernel/06-capability-revocation.md`), so the spec and
  the implementation stay findable from each other. If the code needs to
  diverge from the document, the document changes first.
- Public interfaces carry doc comments; reference documentation is
  generated, versioned with the interfaces it describes
  (`01-development-maintenance-update-model.md`).

## Dependencies

Per the supply-chain rules in `01-development-maintenance-update-model.md`:

- All dependencies are pinned by content hash and vendored; nothing is
  fetched at build time.
- License allowlist for in-tree and vendored code: Apache-2.0, MIT,
  BSD-2/3-Clause, and compatible permissive licenses. Copyleft
  dependencies do not enter the tree.
- The kernel and other TCB components use a curated dependency allowlist —
  each entry reviewed like a contribution, because it is one. Every
  dependency appears in the SBOM.

## Commits And Review

- Apache-2.0 with DCO sign-off per `../../CONTRIBUTING.md`; SPDX headers
  on every file.
- One concern per commit; commit messages state what changed and why, and
  flag ABI, budget, rights-catalog, and schema changes explicitly so they
  get the review those categories require.
- CI is the same hermetic execution as local presubmit
  (`02-build-and-test-infrastructure.md`); "worked locally" is an
  infrastructure bug report, not an excuse.
