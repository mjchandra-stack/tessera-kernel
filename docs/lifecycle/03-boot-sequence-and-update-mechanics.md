<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Boot Sequence And Update Mechanics

## Purpose

The trust half of boot and update is complete — verification, measurement,
and anti-rollback in `../security/01-security-model.md` and
`../security/02-cryptography-and-key-management.md`. This document supplies
the mechanics half: the A/B slot state machine, the update verifier's
actual job, how early boot gets from initrd to the real system, bootloader
self-update, the recovery environment, and delta delivery.

## Boot-Control Block And Slot State Machine

Slot state lives in a boot-control block: a dedicated, bootloader-readable
region, integrity-protected (signed or device-key-MACed) and covered by a
monotonic version so forging or replaying it — which would *be* the
downgrade attack — is rejected like any other rollback.

Each slot is in one state:

- `empty` — no valid image.
- `pending` — newly written, not yet booted; carries a tries-remaining
  counter (default 3).
- `active` — currently booted.
- `successful` — committed; eligible for selection indefinitely.
- `unbootable` — tries exhausted or explicitly invalidated.

The bootloader's algorithm is deliberately dumb, because it must work when
nothing else does: select the `pending` slot if one has tries remaining,
decrementing the counter *before* handoff; otherwise select `successful`;
otherwise enter recovery. A new image that never reaches userspace burns
its tries and the device falls back with no OS cooperation required.

## Boot Success And Commit

The update verifier — started by the root task in the
`../architecture/01-system-architecture.md` boot flow, and until now only a
name — owns the transition out of `pending`:

- Boot success is defined, not vibed: the critical service set (component,
  device, storage, security policy, log services) reaches ready, the first
  health-service pass succeeds, and the system survives a
  profile-configured soak (minutes, not seconds, so crash loops that take
  a moment to develop still count as failures).
- On success the verifier commits: marks the slot `successful`, advances
  the minimum-SVN counters per `../security/02` "Anti-Rollback", releases
  the post-commit migrations below, and records the update outcome.
- On failure (rollback triggers from `01-development-maintenance-update-model.md`
  before commit) it marks the slot `unbootable` and reboots into the old
  slot, attaching the flight-recorder tail and crash dumps to the rollback
  record.

## User Data Across The Commit Boundary

A/B makes the system atomic; user data is shared by both slots, so the rule
is **backward compatible until commit**: between first boot on a new slot
and commit, the system must not write user data in formats the previous
slot cannot read — no filesystem feature-flag advancement
(`../storage/01-native-cow-filesystem.md` gates feature enablement on
commit), no destructive schema migrations, and application data migrations
(`../api/02-abi-versioning-and-compatibility.md`) are similarly deferred or
reversible. Format migrations run only after commit, when rollback is no
longer an automatic path. Rolling back never hands the old system data it
cannot read, by rule rather than by luck.

## Early Boot: From Initrd To System

The verified initrd is the bootstrap set, closing the
services-need-binaries-before-filesystems-exist gap:

1. The kernel starts the root task from the initrd.
2. The root task starts the bootstrap components from initrd memory: the
   component manager, the security policy seed, the log service, the
   update verifier, and a minimal storage bring-up — block driver host,
   volume manager, and filesystem service sufficient to mount the system
   volume.
3. Storage bring-up honors the bootloader's slot choice, passed as
   verified boot parameters, and mounts the selected verified system
   subvolume; sealed-subvolume verification makes the mount
   integrity-checked on the paging path from the first page.
4. The component manager re-roots namespaces onto the system image;
   subsequent services start from the verified system volume, and initrd
   memory is reclaimed. The initrd and system image ship from the same
   build, so there is no version skew between bootstrap and system.

## Bootloader Self-Update

The bootloader is the one component whose failed update bricks the device:

- Where the flash layout allows, the bootloader is itself A/B with the
  same tries/fallback discipline, applied by the firmware boot stage.
- Where it cannot be, updates use a two-phase, power-loss-ordered protocol:
  write and verify the new image in a staging region, then switch with the
  platform's smallest atomic operation; the power-loss test matrix in
  `02-build-and-test-infrastructure.md` covers every cut point.
- Bootloader images carry their own SVNs; a committed bootloader update
  advances the minimum like any security-critical firmware.

## Recovery Environment

Recovery is a real, minimal, verified system — not a mode:

- Entry: both slots `unbootable`, watchdog escalation exhaustion
  (`../drivers/04-embedded-buses-power-and-timekeeping.md`), an explicit
  user chord, or administrative policy.
- Capabilities: reflash from signed images, factory reset by key
  destruction (crypto-erase, per the storage model), export of diagnostic
  bundles under the same consent rules as normal operation, and sideload
  only under debug-unlock policy — which is measured and visible to
  attestation, so a device that has been in permissive recovery says so.
- Recovery is itself signed, measured, SVN-protected, and updated as an
  artifact class in `01-development-maintenance-update-model.md`; its
  attack surface is minimal by construction (no network stack beyond what
  reflashing requires, no application runtime).

## Delta And Streaming Delivery

The CoW storage design makes deltas nearly free, so they are claimed:

- Updates ship as extent deltas against a named base subvolume generation;
  the device assembles the target subvolume and verifies it against the
  signed Merkle root before the slot ever becomes `pending`. The transport
  therefore needs no trust of its own — a corrupted or malicious delta
  produces a verification failure, not a bootable image.
- Assembly streams to the inactive slot while the system runs; the
  foreground cost is bounded I/O in the background class.
- Full-image delivery remains for recovery and first provisioning.

## First Boot And Provisioning

The trust root's birthday is a sequence, not an assumption: on first boot,
device keys are generated inside the hardware root of trust, the key
hierarchy of `../security/02` is initialized, attestation identity is
enrolled, factory calibration and provisioning data from the platform
manifest are consumed and sealed, and the first user principal is created
through the standard flow in
`../security/03-authentication-and-user-model.md`. Update gating on battery
state (do not begin apply below a threshold; never interrupt commit) is
profile policy, stated so it is a decision.

## Observability

Slot state transitions with tries counts, boot-success evaluations with the
failing criterion named, commits and SVN advancements, rollbacks with their
trigger and attached evidence, bootloader update phases, recovery entries
with cause, and first-boot provisioning steps are structured events —
`boot failure` diagnosis starts from data, per
`../observability/01-debugging-monitoring-tracing-logging.md`.
