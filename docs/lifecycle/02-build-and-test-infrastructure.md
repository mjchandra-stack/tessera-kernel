<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Build And Test Infrastructure

## Purpose

`01-development-maintenance-update-model.md` states the testing strategy, CI
coverage, and supply-chain requirements; `../architecture/03-performance-budgets.md`
adds normative budgets and prototype harnesses. This document defines the
infrastructure that makes those enforceable: which compilers are used and how
they are pinned, what the build system must guarantee, and how testing is
tiered from unit tests to hardware-in-the-loop. Like everything else here,
the infrastructure is designed for decades: toolchains are versioned inputs,
not ambient state on a build machine.

## Toolchain And Compiler Selection

Per the language-by-layer table in `../../OVERVIEW.txt` (Rust for kernel,
driver hosts, and services; assembly for architecture ports; C for the ABI
boundary only):

- Rust: one pinned toolchain version per release train, upgraded on a
  scheduled cadence with a soak period on the nightly channel builds before
  promotion. Kernel and early-boot code may use unstable features only from
  an enumerated, reviewed list, each entry carrying a migration plan to
  stable; the list must shrink, mirroring the unsafe-code inventory rule in
  `../security/01-security-model.md`.
- Code generation: LLVM via rustc. Cross-compilation to every supported
  architecture from every supported host is mandatory; there are no
  target-only build machines.
- Kernel targets are custom target specifications per architecture with
  reviewed codegen flags: no red zone, kernel code model, no hardware
  floating point in kernel context, and the hardening features the security
  model requires where the architecture provides them (CFI, shadow stacks,
  pointer authentication, memory tagging).
- C: a single C compiler policy — Clang, same LLVM version as rustc — used
  for ABI boundary verification and sanctioned legacy code only. ABI headers
  are generated from ISL schemas (`../api/03-interface-schema-language.md`)
  and compile warning-clean under strict flags; a build step diffs the C and
  Rust views of every ABI struct layout so the two can never drift.
- Assembly: LLVM integrated assembler for architecture ports; no standalone
  assembler dialects.
- Toolchain provenance: compilers, linkers, and standard libraries are
  content-hash-pinned inputs under the dependency rules of
  `01-development-maintenance-update-model.md` "Supply Chain Security".
  Toolchain updates are reviewed changes with their own SBOM entries, and
  release toolchains are rebuilt and hash-verified from upstream sources
  rather than trusted as opaque binaries.

## Build System

Requirements, in order of importance: hermetic, reproducible, one graph for
everything, remote-cacheable, and honest about what it rebuilt.

- A single graph build system orchestrates the whole tree: kernel, services,
  drivers, ISL code generation, images, SDK, and documentation. Cargo remains
  the developer inner loop for pure-Rust crates, but release artifacts are
  produced only by the graph build with vendored, pinned dependencies — the
  inner loop is a convenience, never the source of truth.
- The ISL compiler is a build rule: schemas are sources; bindings,
  validators, fuzz harnesses, trace decoders, and conformance goldens are
  generated targets. Nothing generated is checked in.
- Image assembly is a build target: verified base images, platform support
  packages, and update payloads are ordinary outputs of the graph. Signing is
  not: release signing happens in the separate signing service defined by the
  supply-chain rules, and CI workers never hold signing keys.
- Determinism: builds run with no network access, fixed timestamps, and
  stable input ordering. An independent rebuild reproducing the release
  bit-for-bit is a release-blocking CI job, which makes the reproducibility
  promise in `01-development-maintenance-update-model.md` a tested property
  rather than a stated one.

## Test Tiers

### Tier 0 — Static

Formatting and lint pinned to the toolchain version, license and SBOM
verification, ISL schema lint, ABI diff against the last release
(`../api/02-abi-versioning-and-compatibility.md`), and the unsafe-code
inventory gate: new `unsafe` in privileged code fails the build unless it
carries a registered exception per `../security/01-security-model.md`
"Memory Safety".

### Tier 1 — Unit

- Services and libraries: host-target Rust tests; fast, no emulation.
- Kernel code is structured so architecture-independent subsystems build for
  the host with a mocked architecture layer and are unit-tested there;
  unsafe-heavy crates additionally run under interpreter-based UB checking.
- Code that cannot be host-tested (trap paths, page-table plumbing, context
  switch) is covered by a kernel test image: a build variant that boots under
  QEMU and runs an in-kernel test harness, reporting over the early console.

### Tier 2 — Component And Conformance

- ISL conformance goldens checked across every generated language binding.
- Driver class conformance run against the simulated devices from the driver
  SDK (`../drivers/01-driver-framework.md` "Developer Experience"), so a
  class contract is testable before any hardware exists.
- Service protocol tests against generated mocks.
- Fuzzing: structure-aware fuzz targets generated from ISL run continuously
  with persistent corpora; parsers and binary interfaces (per the security
  model) have mandatory fuzz targets that fail CI if absent.

### Tier 3 — System Integration

QEMU/KVM matrix across x86-64, AArch64, and RISC-V booting full system
images, running scenario suites: boot, A/B update and rollback, driver-host
crash and device rebind, the pager-under-pressure harness, namespace and
policy audit verification, and suspend/resume in the virtual platform
profile. Fault injection is first-class here: killed driver hosts, injected
DMA faults, dropped IPC peers, and clock steps are scripted scenarios, not
manual experiments.

### Tier 4 — Performance

The budget rig from `../architecture/03-performance-budgets.md`: dedicated
bare-metal runners, R1-class per merge and R2/R3-class per release
candidate, fixed statistical methodology (defined run counts, warm-up,
percentile reporting), with results published per release. A regression
beyond the 5 % gate blocks the train.

### Tier 5 — Hardware-In-The-Loop

The board farm covers the first-party hardware allowlist from
`../roadmap/01-sequencing-and-mvp.md`: controllable power and USB switching
for hotplug and surprise-removal tests, watchdog-backed recovery, power-loss
during update, and thermal soak. Vendor certification
(`../drivers/01-driver-framework.md` "Certification") runs the same suites on
vendor hardware.

## CI Topology

- Pre-merge: tiers 0–2 plus a one-architecture tier 3 smoke boot, within a
  30-minute budget. Anything slower moves post-merge rather than being
  skipped.
- Post-merge continuous: full tier 3 matrix, tier 4 on R1, and the fuzzing
  fleet.
- Release candidate: everything, including tier 5, the reproducible-rebuild
  check, the ABI diff review artifact, and the published budget report.
- All workers are hermetic and network-isolated during builds; artifacts are
  content-addressed and carry provenance per
  `01-development-maintenance-update-model.md`.

## Test Authoring Rules

- No interface stabilizes without conformance tests — restating interface
  governance as a build-enforced gate, not a review checklist item.
- Every bug fix lands with a regression test at the lowest tier that can
  reproduce the bug.
- Flaky tests are quarantined with a named owner and a deadline, and the
  quarantine list is public inside the project; a tier's flake rate is itself
  a tracked health metric.
- System tests are components: they run sandboxed with manifest-declared
  capabilities, so the test infrastructure dogfoods the security model
  instead of bypassing it.

## Developer Experience

- One command bootstraps a workstation: fetch pinned toolchains, build, boot
  the result under QEMU.
- The local presubmit is the same hermetic execution as CI pre-merge, so
  "passed locally, failed in CI" is an infrastructure bug by definition.
- Trace viewer and crash symbolization work against local builds using the
  same build IDs and symbol packages as production
  (`../observability/01-debugging-monitoring-tracing-logging.md`).

## Sequencing

Stage 0 of `../roadmap/01-sequencing-and-mvp.md` requires: the graph build
with pinned toolchains, ISL build rules, tiers 0–2, the tier 3 smoke boot,
and the tier 4 rig for budgets B1–B11. The board farm and tier 5 arrive with
stages 1–2, gated by the first hardware allowlist. Building this
infrastructure is therefore the first engineering work of Stage 0, alongside
the kernel itself — not a follow-up to it.
