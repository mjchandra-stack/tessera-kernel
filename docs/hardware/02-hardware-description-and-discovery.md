<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Hardware Description And Discovery

## Problem

Hardware is discovered through many mechanisms:

- ACPI.
- Device Tree.
- PCIe enumeration.
- USB descriptors.
- Firmware tables.
- SMBIOS-like tables.
- Secure monitor calls.
- Platform manifests.
- Runtime bus discovery.
- Vendor-specific firmware protocols.

Using these sources directly throughout the OS creates fragile code and makes
quirks hard to manage.

## Normalized Resource Graph

The device manager converts all discovery sources into one normalized resource
graph.

Graph nodes include:

- CPU.
- Memory region.
- Interrupt controller.
- Bus.
- Device.
- Function.
- Clock.
- Reset line.
- Power domain.
- Regulator.
- DMA aperture.
- IOMMU context.
- Firmware image.
- Secure element.
- Sensor.
- Display pipeline.
- Accelerator.
- Thermal zone.

Graph edges include:

- Parent bus.
- Interrupt route.
- DMA route.
- Power dependency.
- Clock dependency.
- Reset dependency.
- Security domain membership.
- Firmware dependency.
- Memory access permission.
- Physical topology.
- Logical grouping.

## Hardware Description Schemas

The OS defines schemas for normalized hardware descriptions. Schemas provide:

- Required fields.
- Optional fields.
- Versioning.
- Units.
- Enumerations.
- Validation rules.
- Security-sensitive properties.
- Driver binding metadata.

Schemas are used to generate validators, documentation, diagnostics, and test
fixtures.

## Accepted Inputs

### ACPI

ACPI is accepted for PC-class and server-class systems. The OS consumes ACPI
tables through a parser that validates and normalizes device, interrupt, power,
thermal, and firmware data.

### Device Tree

Device Tree is accepted for embedded, Arm, RISC-V, and development-board
platforms. Bindings must be schema-validated before driver binding. The OS
maintains its own schema mappings for the upstream DT bindings it accepts —
a reviewed, versioned vocabulary rather than ad hoc parsing — so upstream
binding churn lands as schema review, not as scattered driver patches.

### PCIe

PCIe devices are enumerated at runtime. The OS records:

- Bus, device, function.
- Vendor and device ID.
- Class code.
- BARs.
- MSI/MSI-X capability.
- ATS, PRI, PASID, and SR-IOV capabilities where available.
- IOMMU grouping.
- Hotplug state.
- Firmware and option ROM policy.

### USB

USB devices are enumerated by descriptors. Class drivers bind through standard
class, subclass, protocol, and vendor-specific descriptors.

### Platform Manifest

A platform manifest fills gaps that firmware tables do not represent well:

- Board revision.
- Known errata.
- Secure world services.
- Firmware compatibility.
- Sensor calibration.
- Factory provisioning.
- Update restrictions.
- Product policy defaults.

## Quirk Management

Quirks must be:

- Data-driven where possible.
- Scoped to specific hardware revisions.
- Signed with the platform support package.
- Tested by compatibility suites.
- Expirable when hardware or firmware is fixed.
- Visible to diagnostics.

Quirks should not silently alter unrelated subsystem behavior.

## Binding Process

Driver binding follows this flow:

1. Discover hardware facts from firmware and buses.
2. Normalize facts into the resource graph.
3. Validate graph nodes against schemas.
4. Resolve power, clock, reset, interrupt, DMA, and security dependencies.
5. Match driver candidates by class, vendor, version, and policy.
6. Start driver host with least required capabilities.
7. Hand driver a device capability and resource leases.
8. Record binding decision in diagnostics.

## Dynamic Reconfiguration

The graph can change at runtime:

- USB hotplug.
- Thunderbolt or USB4 hotplug.
- PCIe hotplug.
- Docking stations.
- External GPUs.
- Display attach and detach.
- Sensor modules.
- Virtual devices.
- VM device assignment.

Graph changes produce versioned events. Drivers and services must tolerate
removal, reset, suspend, and rebinding.

## Security

Hardware discovery is not inherently trusted. The OS defends against:

- Malicious USB devices.
- Compromised firmware tables.
- DMA attacks.
- Thunderbolt and PCIe attacks.
- Counterfeit devices.
- Rogue sensors.
- Hostile virtual devices.

Security controls include IOMMU isolation, signed platform manifests, restricted
firmware loading, hotplug policy, user consent for sensitive classes, and
attestation where available.

