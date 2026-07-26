<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Platform And CPU Support

## Goals

The OS supports multiple CPU families and platform types without letting
hardware-specific code leak throughout the system.

Supported platform categories:

- Phones and tablets.
- Laptops and desktops.
- Workstations.
- Wearables.
- Embedded systems.
- Edge servers.
- Virtual machines.
- Development boards.

Supported CPU architecture families should include, where practical:

- x86-64.
- AArch64.
- RISC-V 64.
- Future capability or memory-safe architectures.

## Architecture Porting Layer

Each CPU family implements an architecture porting layer. The layer exposes a
small set of primitives to the kernel core:

- CPU discovery.
- Boot CPU and secondary CPU startup.
- Trap entry and return.
- Syscall entry and return.
- Context switch.
- Page table creation and update.
- TLB shootdown.
- Atomic operations.
- Cache maintenance.
- Interrupt controller interface.
- Timer interface.
- CPU idle states.
- Memory ordering primitives.
- User-kernel copy helpers.
- Architecture security controls.

The kernel core never directly reaches into architecture-specific registers
outside this layer.

## Platform Support Package

A platform support package describes board or device-specific integration:

- Boot protocol.
- Firmware interfaces.
- Firmware power and sleep interfaces (PSCI, ACPI sleep states) consumed by
  `../power/01-power-management.md`.
- Memory map.
- Interrupt topology.
- Power domains.
- Clock and reset controllers.
- Security domains.
- Device tree or ACPI overrides.
- Firmware blobs and version constraints.
- Known hardware quirks.
- Recovery mode.
- Update constraints.

Platform support packages are signed, versioned, and tested against OS
compatibility suites.

## Heterogeneous Processors

Modern systems may contain:

- Performance CPU cores.
- Efficiency CPU cores.
- Low-power always-on cores.
- DSPs.
- NPUs.
- GPUs.
- ISPs.
- Video encode/decode engines.
- Secure enclaves.
- Sensor hubs.
- Radio processors.

The OS represents these as schedulable or service-managed compute resources.
They are not treated as invisible implementation details.

The resource graph records:

- Which memory regions each processor can access.
- Which interrupts each processor can raise.
- Which firmware owns each processor.
- Which security domain controls it.
- Which driver or runtime schedules it.
- Which power and thermal domains it belongs to.

## CPU Feature Model

CPU features are exposed through stable feature sets, not raw vendor-specific
flags. Raw details remain available for diagnostics.

Feature sets include:

- Virtualization.
- Memory tagging.
- Pointer authentication or control-flow integrity.
- Trusted execution.
- Vector extensions.
- Matrix extensions.
- Cryptographic acceleration.
- Fine-grained timers.
- Performance counters.
- Cache partitioning.
- Memory encryption.

Applications should target feature profiles. System services decide when to use
specific CPU capabilities.

## Endianness And Word Size

The primary ABI assumes 64-bit little-endian platforms. The internal design
should avoid needless assumptions, but supporting 32-bit or big-endian platforms
is a product decision rather than a core goal.

Compatibility layers can support legacy binaries where a product profile
requires it.

## Virtual Platform Support

The OS must boot well as a guest. The virtual platform profile includes:

- Paravirtual clock.
- Paravirtual interrupt controller where available.
- Virtio-style devices.
- Synthetic GPU and display.
- Balloon memory device.
- Shared clipboard and file exchange policy.
- VM attestation.
- Confidential VM support where hardware permits.

The guest profile should use the same driver framework as physical hardware.

## Porting Rules

To add a new CPU architecture or platform:

1. Implement the architecture porting layer.
2. Provide boot and firmware integration.
3. Provide a platform support package.
4. Produce a normalized hardware resource graph.
5. Pass kernel architecture tests.
6. Pass driver binding tests.
7. Pass security and boot measurement tests.
8. Pass suspend, resume, hotplug, and update tests for the target product
   profile.

No product-specific code should be accepted into core services unless it
represents a general platform capability.

