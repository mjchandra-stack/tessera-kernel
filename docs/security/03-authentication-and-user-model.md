<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Authentication, Users, And Recovery

## Purpose

`01-security-model.md` uses lock state as a posture input and evicts keys on
lock, but never designs how the device locks and unlocks, who the user is,
how consent prompts are protected from spoofing, or how encrypted data
survives device loss. Those are the human boundary of the security model,
and they are decided here.

## Authentication Architecture

- Credential verification runs in secure hardware, not in the OS:
  PIN/password verification and biometric matching execute in the TEE,
  secure element, or biometric coprocessor
  (`../hardware/03-component-interaction-model.md` "Secure Components").
  The OS transports blinded credentials and receives verdicts plus key
  material; it never holds the reference template or the raw secret.
- Anti-hammering is hardware-backed: retry counters and lockout schedules
  live in the secure element's monotonic state, so throttling survives OS
  compromise and disk manipulation. Lockout escalation is policy; the floor
  (counters the OS cannot reset) is not.
- Unlock is tiered, and tiers release different authority: a successful
  verification yields an unlock token for a declared tier — biometric
  unlock releases fewer key classes than credential unlock (per the
  key-binding strengths in `02-cryptography-and-key-management.md`), and
  the most sensitive classes may require credential-plus-biometric or
  recent-credential freshness. Data classification names each class's
  required tier.
- Unlock state propagates as capabilities, not as a flag: the identity
  service presents the unlock token to the key service, which releases
  unwrapping for the tier's key domains; lock revokes those grants through
  standard revocation (`../kernel/06-capability-revocation.md`) and evicts
  per `01-security-model.md` "Physical Access Protection". "Locked" is
  therefore enforced by absent keys, not by services agreeing to behave.

## User Model

- A user is a principal: per-user key domains root the user's data
  encryption, and every process carries its user in its security context
  (`../kernel/05-jobs-containment-and-resource-control.md`), so per-user
  policy, accounting, and audit attribution are structural.
- User switching quiesces the outgoing session (jobs suspended, its key
  domains locked per its lock policy) and starts or resumes the incoming
  session; desktop profiles may keep multiple sessions resident, mobile
  profiles typically lock the inactive one fully. One user's session never
  holds another's unwrapped keys.
- Work and enterprise profiles are a scoped second principal owned by the
  same human: a separate key domain, namespace views, and app set under
  enterprise policy, with cross-profile data flow governed by data
  classification and consent — the same machinery as everything else, so a
  work profile is composition, not a new subsystem. Enterprise wipe removes
  the profile's key domain and leaves the personal principal untouched.
- Guest and kiosk sessions are ephemeral principals whose key domains are
  destroyed at session end — deletion by key destruction, per the storage
  model.

## Trusted Consent Path

Capability grants flow from user consent, so consent rendering and input
must be trustworthy:

- Permission prompts and security surfaces (credential entry, consent
  dialogs, the device-class indicators) are rendered by a trusted system
  component onto secure surfaces through the compositor's secure
  presentation path (`../drivers/03-graphics-display-media-sensors-ai.md`):
  un-occludable, excluded from capture, and visually bound to a
  system-reserved indicator region no application surface can draw.
- While a consent surface is active, the input broker
  (`../platforms/01-mobile-desktop-wearable-experience.md`) grants it
  exclusive focus and rejects synthetic input injection toward it;
  hardware-attested input paths are used where the platform provides them.
- Prompts identify the requesting component from its kernel-attested
  identity (`../kernel/04-synchronization-and-ipc-guarantees.md` "Peer
  Credentials"), never from self-declared names alone, and a prompt's
  decision is bound to the exact request that raised it — a stale or
  replayed approval grants nothing.
- Credential entry surfaces additionally suppress screen capture, remote
  display, and accessibility injection except through audited, explicitly
  enrolled assistive services.

## Backup And Recovery

Hardware-bound keys without a recovery design mean device loss is data
loss; the design chooses recoverability per class, explicitly:

- Backups are end-to-end encrypted: backup payloads are encrypted under
  keys derived from user secrets (and optionally a recovery key), wrapped
  so that the backup transport and storage provider can never decrypt.
  Backup infrastructure is honest-but-curious in the threat model, like
  the network.
- Restore is attestation-gated: a new device proves its posture through
  the "Attestation" flow before escrowed material is re-wrapped to its
  hardware root; downgrade to an unattested or lower-posture device is a
  policy decision, not a default.
- Recovery keys: a user-held recovery key (printable, or escrowed with a
  user-chosen guardian scheme) can recover the backup hierarchy after
  credential loss; secure-element-backed escrow with anti-hammering
  applies where profiles support it.
- Recoverability is a per-class property declared in the data
  classification: most user data is backup-eligible; classes may be
  device-bound by policy (hardware-attested credentials, some biometric
  templates) and are then explicitly unrecoverable — stated to the user,
  not discovered at restore time. Enterprise classes follow enterprise
  escrow policy.
- Every backup, restore, and recovery-key use is an audit event; restore
  onto a new device is visible in the account's device list.

## Observability

Authentication attempts and lockouts (without credential content), unlock
tier transitions, key-domain lock and release events, user and profile
switches, consent-surface presentations with the attested requester
identity, injection rejections, and backup/restore/recovery operations are
structured events under the strictest redaction classes, consistent with
`../observability/01-debugging-monitoring-tracing-logging.md`.
