<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Separation Of Concerns

## Responsibility Boundaries

The architecture is built around explicit ownership boundaries. A subsystem owns
the smallest set of responsibilities needed to provide its contract.

## Kernel Boundary

The kernel owns:

- CPU execution contexts.
- Virtual memory and page tables.
- Physical memory accounting.
- Scheduling and preemption.
- Interrupt routing.
- Kernel object handles and rights checks.
- IPC primitives.
- Timekeeping primitives.
- IOMMU and DMA isolation coordination.
- Low-level power state transitions needed for correctness.

The kernel does not own:

- Filesystem policy.
- Network protocol policy above minimal packet delivery.
- Display policy.
- User identity policy.
- Package policy.
- AI model policy.
- Desktop or mobile session policy.

## Device Manager Boundary

The device manager owns the normalized hardware resource graph and driver
binding decisions.

It receives facts from:

- Firmware tables.
- ACPI.
- Device Tree.
- PCIe enumeration.
- USB descriptors.
- Platform support packages.
- Runtime discovery.
- Secure monitor interfaces.

It emits:

- Device objects.
- Driver binding requests.
- Resource leases.
- Power dependency graphs.
- Security domain assignments.
- Hotplug events.

## Driver Boundary

Drivers own hardware-specific control and data-path translation. They do not own
global policy.

A storage controller driver should expose queues and media capabilities. It
should not decide the user's backup policy.

A camera driver should expose sensor modes and buffers. It should not decide
which app may use the camera.

An AI accelerator driver should expose supported tensor formats, memory
requirements, and execution queues. It should not decide whether a model may
process private microphone data.

## Service Boundary

Services own policy and high-level abstractions:

- Storage manager owns volume policy, encryption policy, quota policy, snapshot
  policy, and mount namespace assembly.
- Network manager owns network selection, firewall policy, DNS policy, VPN
  policy, and per-app network rules.
- Display service owns composition, window surfaces, protected content routing,
  color management, and display leasing.
- AI runtime owns model selection, accelerator placement, model cache policy,
  and sensitive data routing.

## Application Boundary

Applications receive:

- A sandbox.
- A data container.
- Handles to approved capabilities.
- Framework APIs.
- User-mediated permissions.

Applications do not receive:

- Raw device access by default.
- Global filesystem access by default.
- Unrestricted background execution by default.
- Unrestricted sensor streams by default.
- Unrestricted model or accelerator access by default.

## User Boundary

The user controls consent and high-level policy, but the system must not force
the user to understand low-level device details. Consent surfaces are expressed
as meaningful data and device classes:

- Location.
- Camera.
- Microphone.
- Local network.
- Health sensors.
- Nearby devices.
- Contacts.
- Screen capture.
- Files and folders.
- AI memory and personal context.

## Vendor Boundary

Hardware vendors provide platform support packages, firmware, and drivers.
Vendor code runs with least privilege and must pass compatibility tests.

Vendor boundaries:

- Firmware is measured and versioned.
- Platform manifests are signed.
- Driver capabilities are explicit.
- Device quirks are declared in data, not scattered through unrelated code.
- Update support windows are declared for certified devices.

## AI Boundary

AI components are split into:

- Model binaries and weights.
- Runtime engines.
- Accelerator drivers.
- Personal context stores.
- Policy brokers.
- Application agents.

No single AI component automatically receives all sensor streams, user data, or
device access. The permission model treats inference as data processing, not as
an authority bypass.

## Cross-Cutting Services

Some concerns cross subsystem boundaries:

- Logging.
- Tracing.
- Security policy.
- Power management.
- Update management.
- Accessibility.
- Internationalization.
- Privacy controls.

These are exposed as platform services with explicit APIs, not as hidden global
state.

