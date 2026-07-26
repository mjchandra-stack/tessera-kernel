<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Development, Maintenance, And Update Model

## Goals

The OS must be maintainable for decades across many products and hardware
generations. Maintenance is an architecture concern, not just a release process.

## Source Organization

Source is organized by stable ownership boundaries:

- Kernel core.
- Architecture ports.
- Platform support packages.
- Driver framework.
- Driver classes.
- System services.
- Application frameworks.
- Compatibility layers.
- Tools and SDKs.
- Tests and certification suites.

Internal APIs can evolve, but public contracts are versioned and tested.

## Interface Governance

Stable interfaces require:

- Owner.
- Schema.
- Documentation.
- Tests.
- Fuzzing strategy.
- Trace event definitions.
- Compatibility statement.
- Deprecation policy.
- Security review.

No stable interface is accepted without a compatibility test.

Interfaces that introduce a new device class or AI capability must additionally
satisfy the future-proofing checklist in
`../future/01-ai-and-wearable-era.md` "Future-Proofing Rules" — resource-graph or
schema description, driver or service interface, data classifications, permission
and policy rules, observability events, conformance tests, power and thermal
accounting, and update and rollback support. This checklist is a conformance gate
in the testing strategy below, not merely guidance; a capability that skips
capabilities, policy, or observability is not accepted.

## Release Channels

Release channels:

- Main development.
- Nightly.
- Preview.
- Stable.
- Long-term support.
- Security hotfix.
- Vendor certification.

Product profiles choose supported channels. Critical security fixes can bypass
normal feature trains while preserving rollback safety.

## Update Model

System updates are:

- Signed.
- Atomic.
- Rollback-capable.
- Measured.
- Staged.
- Health-checked.
- Compatible with platform support package constraints.

Supported mechanisms:

- A/B system images.
- Snapshot updates.
- Component updates.
- Firmware updates.
- Driver package updates.
- Bootloader updates.
- Recovery image updates.
- Model updates.
- Delta delivery against a known base, verified against the signed image
  root before activation.

The slot state machine, boot-success and commit criteria, the
backward-compatible-until-commit rule for shared user data, early-boot
bring-up, bootloader self-update, and the recovery environment are defined
in `03-boot-sequence-and-update-mechanics.md`.

## Model Updates

AI models are updatable components, and their update and rollback are owned here
rather than left to the model registry. The registry in
`../future/01-ai-and-wearable-era.md` describes what a model is; this section
governs how it changes.

- Models use A/B swap so a new version can be validated before it replaces the
  active one, and reverted without downtime.
- Models are signed and provenance-checked before activation, per
  `../security/02-cryptography-and-key-management.md` and "Supply Chain Security".
- Model rollback triggers extend the general rollback list below with
  model-specific ones: quality regression, safety-evaluation failure, and failed
  post-activation health checks.
- A revoked model version (compromised or unsafe) is disabled through revocation
  and cannot be reactivated.

## Rollback

Rollback is triggered by:

- Boot failure.
- Repeated service crash.
- Driver crash loop.
- Failed health check.
- User or admin request.
- Security policy decision.

Rollback records include logs, traces, crash dumps, and update metadata.

Package revocation is the application-level analog of key, model, and
compiler revocation: a package version revoked as hostile or critically
vulnerable is disabled through the same revocation-list distribution and
cannot be reinstalled. Fleet-wide remote disable of an installed app is a
profile policy decision with explicit consent and legal constraints — it is
audited, reversible, and visible to the user; silent removal is not a
supported operation.

## Vendor Support

Vendors provide:

- Platform support package.
- Drivers.
- Firmware.
- Calibration data.
- Update metadata.
- Hardware lifecycle declarations.
- Security bulletin hooks.

Certification requires support windows and compatibility test results.

## Testing Strategy

Test layers:

- Unit tests.
- Kernel tests.
- ABI tests.
- Interface schema tests.
- Driver class tests.
- Hardware-in-the-loop tests.
- Fault injection.
- Fuzzing.
- Suspend/resume tests.
- Hotplug tests.
- Power and thermal tests.
- Update and rollback tests.
- Security policy tests.
- Performance regression tests.
- Cross-profile tests.
- Future-proofing conformance for new device classes and AI capabilities
  (`../future/01-ai-and-wearable-era.md` "Future-Proofing Rules").

## Continuous Integration

CI must cover:

- Multiple CPU architectures.
- Emulated platforms.
- Physical device labs.
- Virtualization profiles.
- Compatibility layers.
- Static analysis.
- Memory safety tools.
- ABI diffing.
- Documentation generation.
- Reproducible builds.

## Supply Chain Security

The security model in `../security/01-security-model.md` treats supply-chain
attack as an assumed adversary. This is where those controls are implemented, so
that the threat named there has concrete mitigations here.

- Software bill of materials: every artifact (image, component, driver, firmware,
  model package) ships with an SBOM enumerating its inputs and versions.
- Build provenance: builds emit signed provenance attesting to the source
  revision, build environment, and toolchain, so an artifact can be traced to the
  exact inputs that produced it.
- Reproducible and hermetic builds: builds run from pinned, verified inputs with
  no network access, so an independent rebuild reproduces the signed artifact
  bit-for-bit.
- Dependency pinning: all dependencies are pinned by content hash and verified;
  unpinned or unverified inputs fail the build rather than being fetched.
- Signing infrastructure: signing keys live in hardware, every signing operation
  is logged and attributable, and release signing requires more than one
  operator. Key lifecycle follows
  `../security/02-cryptography-and-key-management.md`.
- Verification at install and update: SBOM and provenance are checked when an
  artifact is installed or updated, feeding the attestation and device-posture
  evaluations in `../security/01-security-model.md`, not only at build time.

## Documentation

Documentation is part of the release:

- Architecture docs.
- Interface references.
- Driver authoring guides.
- Security model.
- Porting guides.
- Debugging guides.
- Compatibility notes.
- Migration guides.

Docs are versioned with the interfaces they describe.

## Maintenance Lessons Applied

From Linux and other systems, this model avoids:

- Unbounded internal API exposure.
- Unreviewed ABI expansion.
- Out-of-tree driver dependence.
- Distribution-specific debugging gaps.
- Hardware quirks hidden in unrelated code.
- Optional observability.
- Updates that cannot recover automatically.

## Support Lifecycle

Each product profile declares:

- OS support duration.
- Security update duration.
- Driver update duration.
- Firmware update duration.
- Compatibility profile.
- End-of-life policy.

The package manager and update service expose support status to users and
administrators.

