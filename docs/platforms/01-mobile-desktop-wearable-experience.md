<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Mobile, Desktop, And Wearable Experience

## Goal

The OS should expose a coherent platform across device categories without
forcing every product to share the same shell, interaction model, or power
policy.

The platform has one core architecture and multiple product profiles.

## Product Profiles

### Mobile

Mobile profile priorities:

- Touch-first interaction.
- Strict background limits.
- Strong app sandboxing.
- Battery-first scheduling.
- Cellular, Wi-Fi, Bluetooth, UWB, NFC, and GNSS integration.
- Camera, microphone, sensor, and location privacy.
- Seamless update and rollback.
- App store and sideload policy defined by product or region.

### Desktop

Desktop profile priorities:

- Multi-window shell.
- Keyboard, mouse, pen, touch, and accessibility input.
- Broad peripheral support.
- Developer tools.
- Terminal and scripting.
- Professional graphics and audio workflows.
- Local virtualization.
- Flexible file access with visible user consent.
- Enterprise management.

### Wearable

Wearable profile priorities:

- Always-on low-power operation.
- Glanceable UI.
- Health and biometric sensor privacy.
- Companion-device continuity.
- Offline local inference for immediate context.
- Minimal network and background cost.
- Fast suspend and resume.
- Strong data minimization.

### Embedded And Appliance

Embedded profile priorities:

- Fixed-purpose shells.
- Long support windows.
- Remote diagnostics.
- Atomic updates.
- Real-time or deadline workloads where required.
- Restricted app model.
- Hardware watchdog integration.

### Workstation

Workstation profile priorities:

- High CPU, GPU, memory, and storage throughput.
- Professional driver support.
- Multiple displays.
- Local and remote development.
- Advanced tracing and profiling.
- Virtualization and containers.
- Fine-grained user control.

## Common Platform Services

All profiles share:

- Component model.
- Package model.
- Permission model.
- Capability model.
- System call ABI.
- Driver framework.
- Update model.
- Logging and tracing.
- Security policy engine.
- Hardware resource graph.

Profiles differ in default policies and available framework APIs.

## UI And Session Architecture

The session manager owns the binding between a user principal and a running
session: it starts and supervises the shell, drives lock-state transitions
with the identity and key services
(`../security/03-authentication-and-user-model.md`), and quiesces sessions
on user switch. The shell owns look and interaction; the session manager
owns existence and lock state.

The session manager starts the profile-specific shell:

- Mobile shell.
- Desktop shell.
- Wearable shell.
- Kiosk shell.
- Headless service shell.

Shells use common services:

- Window and surface manager.
- Input service.
- Accessibility service.
- Notification service.
- Identity service.
- Permission broker.
- Display compositor.

## Input Model

Input devices include:

- Touch.
- Mouse.
- Keyboard.
- Pen.
- Game controller.
- Voice.
- Gesture.
- Eye tracking.
- Wearable crown or button.
- Spatial controller.
- Assistive devices.

Input is routed through a broker that enforces focus, privacy, accessibility,
and injection policy.

## Text Input And Input Methods

An input method sees every keystroke, which makes it one of the most
privileged components on a device; it is designed accordingly:

- IMEs are sandboxed components brokered by the input service, with no
  network access by default — a keyboard that wants sync or cloud
  suggestions requests it as a visible, per-IME permission, so the
  keylogger-by-design failure mode is a user-facing choice, not a default.
- Input fields carry an input classification: credential and password
  fields bypass third-party IMEs entirely and route to the trusted input
  surface of `../security/03-authentication-and-user-model.md`; sensitive
  classes may restrict IME learning and suggestion persistence.
- The active IME is user-selected, visibly indicated, and switchable only
  through the input service — an app cannot substitute the IME its users
  type into.

## Notifications

Notifications carry private content onto lock screens and across devices,
so they compose with classification rather than bypassing it:

- Notification content carries a data classification; lock-screen rendering
  redacts by class and by the current unlock tier
  (`../security/03-authentication-and-user-model.md`), so a locked device
  shows the existence of a message without its health-classified body.
- Cross-device routing is class-gated against the peer's posture per
  `02-continuity-and-device-groups.md`.
- Posting is a per-app permission with rate and priority policy — the
  notification channel is not an unthrottled attention channel, and
  interruption budgets are profile policy like every other budget.

## Cross-Device Continuity

Continuity features include:

- Shared clipboard.
- Nearby device handoff.
- Cross-device notifications.
- Companion wearable data.
- Remote display.
- Remote input.
- Shared app sessions.
- Local network device discovery.

Continuity requires:

- User consent.
- Device identity.
- Encrypted transport.
- Data classification.
- Revocation.
- Auditability.

The architecture satisfying these — device groups, the rule that
capabilities never cross devices, the continuity service, and per-feature
composition — is defined in `02-continuity-and-device-groups.md`.

## App Lifecycle

Application states:

- Not running.
- Launching.
- Foreground.
- Visible background.
- Suspended.
- Background task.
- Terminating.
- Crashed.

Policies differ by profile. Mobile and wearable profiles are stricter about
background execution. Desktop profiles allow more persistent processes but still
account for resources.

State preservation is a contract, not a convention: before eviction becomes
termination, the platform delivers a save-state callback with a deadline;
the app persists a classified state blob, and restoration on next launch
receives it. Apps that miss the deadline are terminated anyway — the
contract bounds the platform's patience, not the app's. The same blob format
is the handoff payload in `02-continuity-and-device-groups.md`, so surviving
memory pressure and moving to another device are one discipline.

## Permissions

Permissions are expressed as meaningful capabilities:

- Files selected by user.
- Camera.
- Microphone.
- Screen capture.
- Location.
- Health data.
- Contacts.
- Calendar.
- Photos.
- Local network.
- Nearby devices.
- Notifications.
- AI personal context.
- Background execution.

Permissions can be one-time, session-scoped, time-limited, or persistent.

## Accessibility

Accessibility is a platform service, not an app convention.

Supported areas:

- Screen readers.
- Magnification.
- Switch control.
- Voice control.
- Captions.
- Haptics.
- High contrast.
- Reduced motion.
- Alternative input routing.
- Assistive AI with explicit data policy.

Accessibility services hold read-screen and inject-input authority — the
most powerful grants in the permission model — so enrollment is explicit,
per-service, audited, and visibly indicated while active; credential and
consent surfaces admit only enrolled assistive services per
`../security/03-authentication-and-user-model.md`.

## Enterprise And Managed Devices

Enterprise profile capabilities:

- Device enrollment.
- Policy management.
- Certificate management.
- Remote wipe.
- Managed app distribution.
- Per-app VPN.
- Data loss prevention.
- Audit export.
- Update rings.
- Debug restriction.

Enterprise policy composes with user privacy and regional legal requirements.

