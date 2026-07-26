<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Cryptography And Key Management

## Purpose

The security model in `01-security-model.md` relies on signing, verified boot,
hardware-backed key storage, attestation, and encrypted storage and transport.
Those guarantees are only as durable as the cryptography beneath them. Because
this OS is designed to be maintained for decades, no algorithm can be assumed
permanent. This document defines how algorithms are named, negotiated, rotated,
and retired, how keys and trust anchors live and die, and how the system migrates
to post-quantum cryptography without a rewrite.

## Crypto Agility

No cryptographic algorithm is hard-coded into a wire format, an on-disk format, a
signature, or an interface. Every cryptographic artifact is self-describing.

- Algorithms are referenced by versioned algorithm identifiers, never implied by
  position or field length.
- Every signed or encrypted object carries the algorithm identifier, key
  identifier, and format version in its header.
- A single cryptographic provider service owns algorithm selection, so policy can
  enable, deprecate, or forbid an algorithm centrally without recompiling
  dependents.
- Verifiers accept a set of currently valid algorithms and reject deprecated or
  forbidden ones by policy, not by code change.
- New algorithms are added the same way any typed interface evolves, following
  the monotonic extension rules in `../api/02-abi-versioning-and-compatibility.md`.

## Post-Quantum Readiness

The design assumes a cryptographically relevant quantum computer may appear
within the supported lifetime of deployed devices, and that "harvest now, decrypt
later" attacks against long-lived data are already a present concern.

- Signature and key-establishment surfaces support hybrid schemes that combine a
  classical algorithm with a post-quantum algorithm, so a break in either leaves
  the artifact protected.
- The signed boot chain, package signing, driver signing, and model signing all
  support hybrid signatures. Verifiers accept classical-only, hybrid, or
  post-quantum-only signatures according to policy for a given generation of
  hardware.
- Long-lived data-at-rest keys and key-transport paths prioritize post-quantum
  key establishment first, because their exposure window is longest.
- Migration is staged: introduce post-quantum verification support, then dual-sign
  and dual-encrypt during a transition window, then deprecate classical-only
  artifacts, then forbid them. Each stage is a policy decision, not a release
  break.

## Key Hierarchy And Storage

Keys are organized as a hierarchy rooted in hardware where the platform provides
it, consistent with the hardware-backed key storage principle in
`01-security-model.md`.

- A hardware root of trust (TPM, secure element, or platform TEE) anchors the
  hierarchy and never exposes root private material to software.
- Derived and wrapped keys are bound to device identity, boot measurements, or
  data classification, so keys are only usable in an attested, policy-approved
  state.
- Data-class keys follow the taxonomy in `01-security-model.md` "Data
  Classification": more sensitive classes require stronger binding, shorter
  lifetimes, and eviction on lock or suspend.
- Key material lives in secure memory pools (`../kernel/02-scheduling-memory-ipc.md`
  "Secure Memory") and is never traced, dumped, or swapped in the clear.
- Access to keys is capability-gated and produces `Key access` audit events
  (`01-security-model.md` "Audit And Forensics").

## Key Lifecycle

Every key has a defined lifecycle rather than an indefinite existence.

- Generation: keys are generated from the kernel CSPRNG
  (`../kernel/03-paging-faults-and-exceptions.md` "Kernel Randomness") or a
  hardware generator, with entropy health verified before first use.
- Rotation: keys have scheduled rotation intervals and support forced rotation on
  policy events. Rotation is transparent to callers because artifacts name the key
  identifier that produced them.
- Revocation: compromised keys are revoked and their identifiers distributed
  through revocation lists that verifiers consult before trusting an artifact.
- Retirement: retired keys can still verify historical artifacts within a policy
  window but cannot produce new ones.

## Trust Anchors And Signing Infrastructure

Trust anchors are the public keys and measurements that verifiers treat as
authoritative. They are themselves managed, not baked in forever.

- Trust anchors are versioned and can be added or removed through signed,
  measured updates delivered by the update model in
  `../lifecycle/01-development-maintenance-update-model.md`.
- A compromised signing key is handled by revoking its trust anchor, distributing
  the revocation, and re-signing affected artifacts under a replacement anchor.
- The system TLS trust store is managed the same way: public CA roots are a
  versioned, signed, monotonically-versioned anchor set updated through the
  update model. Applications may pin more strictly, never more loosely.
  Enterprise CA injection is scoped to enterprise profiles or per-app VPN
  contexts, is visible to the user as an explicit "traffic may be inspected"
  state, and is audited — a silently trusted interception root is not a
  supported configuration.
- Signing infrastructure (the systems that hold private signing keys for the OS,
  drivers, packages, and models) is part of the supply-chain trust model in
  `../lifecycle/01-development-maintenance-update-model.md` "Supply Chain
  Security": signing keys live in hardware, signing operations are logged and
  attributable, and no single operator can silently sign a release.

## Anti-Rollback

Rollback protection prevents an attacker from downgrading to an older, signed but
vulnerable artifact. Signature validity alone is not sufficient.

- Boot images and firmware carry monotonically increasing security version
  numbers. The platform stores the minimum acceptable version in monotonic
  counters or fuses where hardware provides them; images below that version are
  rejected even if correctly signed.
- Data-at-rest keys are bound to the security version so that rolling back the
  system does not re-expose data that a newer policy protected.
- Trust-anchor and revocation-list versions are also monotonic, so an attacker
  cannot replay an older anchor set to reintroduce a revoked key.
- Rollback protection interacts with the recovery and update flow in
  `../lifecycle/01-development-maintenance-update-model.md`: legitimate downgrades
  require an explicit, policy-authorized, and audited path.

## Randomness

All cryptographic operations draw from the kernel CSPRNG described in
`../kernel/03-paging-faults-and-exceptions.md` "Kernel Randomness".

- Randomness is available early in boot and never returns low-entropy output after
  the initial seed is established.
- Virtual machines receive freshly seeded entropy on creation, resume, and
  snapshot restore, so cloned or restored guests never reuse randomness. Guest
  entropy trust follows `../virtualization/01-virtualization-and-isolation.md`.
- Reseeding occurs on process and VM fork boundaries to prevent duplicate-stream
  hazards.

## Time Dependency

Certificate expiry, revocation freshness, and attestation nonces depend on
trusted time. The cryptographic provider treats time as a security input:

- It uses the secure time service (`../kernel/01-kernel-model.md` "Time") and
  degrades safely, rather than silently, when trusted time is unavailable.
- Audit records that establish artifact validity include the time source and its
  trust level.
