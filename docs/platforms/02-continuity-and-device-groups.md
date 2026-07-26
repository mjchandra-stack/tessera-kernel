<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Continuity And Device Groups

## Purpose

`01-mobile-desktop-wearable-experience.md` lists continuity features and the
requirements they must satisfy — consent, device identity, encrypted
transport, classification, revocation, auditability — without the
architecture. This document supplies it: how devices become trusted peers,
what authority can and cannot cross between them, and how each continuity
feature composes from mechanisms the design already has.

## The Capability Boundary

The most important rule first, stated so no one builds around it:
**capabilities do not cross devices.** Handles are per-kernel. Continuity is
protocol-level re-authorization — a request arrives at the peer, and the
peer's own brokers grant or deny under the peer's own policy, exactly as if
a local component had asked. There is no remote handle, no capability
serialization, and no authority that arrives by transport rather than by
grant. A device group changes *who may ask*, never *what asking yields*.

## Device Groups

A device group is a user's circle of trusted devices — the "device identity"
requirement made concrete:

- Each device holds a hardware-rooted device key
  (`../security/02-cryptography-and-key-management.md`); pairing binds
  devices to the group through the user's account identity with an
  in-person confirmation ceremony (numeric comparison or equivalent) so
  transport-level attackers cannot join silently.
- Membership is mutual-attestation-gated: joining and each session
  establishment exchange posture evidence through the
  `../security/01-security-model.md` "Attestation" flow. Policy consumes
  peer posture per data class — an unlocked phone does not hand health data
  to a debug-unlocked tablet, because the class's egress rule sees the
  peer's posture, not just its membership.
- Membership is managed and visible: the user sees the group on every
  member; removal (or remote wipe of a lost device) revokes the removed
  device's group credentials, and every member drops its sessions with the
  removed peer immediately — revocation lists distribute through the same
  machinery as everything else.
- Work profiles participate as their own principal: an enterprise profile's
  continuity peers are governed by enterprise policy, disjoint from the
  personal group unless policy says otherwise.

## Continuity Service And Transport

- Each device runs a continuity service — the single component holding the
  device-group keys and the peer sessions, and the egress choke point for
  cross-device data the way the diagnostics service is for telemetry.
- Discovery uses the existing nearby/local-network permissions and radio
  policy; transport is encrypted and mutually authenticated with
  device-group credentials over whatever link is available (Wi-Fi, BT, UWB
  — link choice is radio policy, trust comes from the group keys, never
  the link).
- Every cross-device operation is audited with the peer identity, the data
  classes involved, and the consent under which it moved.

## Feature Composition

- Clipboard: cross-device paste is a classified egress — the clipboard
  entry's class is checked against the peer's posture before transfer;
  credential and protected-media classes never cross; paste on the peer is
  a fresh grant by the peer's clipboard policy.
- Notifications: routing is class-gated per peer posture and rendered under
  the peer's lock-screen redaction rules
  (`01-mobile-desktop-wearable-experience.md` "Notifications").
- Handoff: platform-mediated, not per-app improvisation. Apps declare
  continuation points in their manifests; handoff transfers the app's
  classified state blob — the same format as the lifecycle
  save/restore contract in `01` "App Lifecycle" — to the peer, where the
  peer's package manager launches (or the user is offered) the app, which
  restores from the blob. The blob's classification gates whether it may
  move to that peer at all.
- Remote display: composes with the protection and privacy metadata already
  carried by every display path
  (`../drivers/03-graphics-display-media-sensors-ai.md`); protected
  surfaces are excluded from remote paths unless the peer's path attests
  equivalent protection.
- Remote input: this is exactly the injection the input broker polices —
  remote input arrives as a consent-scoped injection session with a
  visible, persistent indicator on the controlled device, never injects
  into trusted consent or credential surfaces
  (`../security/03-authentication-and-user-model.md`), and is revocable
  instantly from the controlled device.
- Companion wearable sync (`../future/01-ai-and-wearable-era.md`) and
  personal-context continuity ride the same service, with context transfer
  additionally governed by the context store's scoped-view and provenance
  rules.

Shared app sessions (real-time collaborative state) are explicitly deferred:
the trust and transport substrate here is their prerequisite, but the
feature is not designed in v1 — recorded as a decision per the roadmap's
scope discipline.

## Failure And Absence

Continuity degrades to absence, never to weaker security: an unreachable or
attestation-failing peer simply isn't offered; queued handoffs expire rather
than falling back to unencrypted or unattested paths; and a device removed
from the group mid-session loses in-flight transfers with a distinct error.

## Observability

Group membership changes, pairing ceremonies, session establishment with
posture summaries, per-feature transfers with classes and consent, remote
input session lifecycles, and every denial with its reason are structured
events under the strictest redaction classes, consistent with
`../observability/01-debugging-monitoring-tracing-logging.md`.
