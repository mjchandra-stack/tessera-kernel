<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Hardware Component Interaction Model

## Purpose

Hardware components interact through buses, memory, interrupts, clocks, resets,
power rails, firmware, and security domains. The OS needs a common model so
drivers can coordinate without hard-coded board knowledge.

## Resource Leasing

Drivers do not own raw hardware globally. They receive leases for specific
resources:

- MMIO ranges.
- I/O port ranges where applicable.
- Interrupts.
- DMA windows.
- Power votes.
- Clock rates.
- Reset controls.
- Firmware mailboxes.
- Secure monitor endpoints.
- Device memory heaps.

Leases are revocable during device removal, suspend, reset, or policy change.

## Power Domains

Power is represented as dependency graph:

- System power states.
- Package power states.
- Device power states.
- Display power states.
- Sensor always-on states.
- Accelerator power islands.
- Radio power states.

Drivers express requirements as votes:

- Off.
- Retention.
- Low power active.
- Full active.
- Performance boost.

The power manager arbitrates votes with user intent, battery state, thermal
state, policy, and real-time deadlines. The power manager's boundary with the
kernel, system sleep states, suspend sequencing, wakeup sources, and CPU
power governing are defined in `../power/01-power-management.md`.

## Clock And Reset Domains

Clock and reset resources are explicit. Drivers request clock rates through
bounded APIs rather than poking controller registers directly unless they are
the clock controller driver.

Reset sequencing is owned by the device manager and relevant bus or controller
drivers. Reset plans are recorded for diagnostics.

## Interrupts

Interrupts are mapped to interrupt objects. Driver hosts can wait on interrupt
objects but cannot arbitrarily reprogram interrupt routing unless granted the
appropriate controller capability.

Interrupt handling supports:

- Mask and unmask.
- Acknowledge.
- Threaded interrupt handling.
- MSI/MSI-X.
- Wake-capable interrupts.
- Virtual interrupt injection for guests.
- Shared lines: each claimant of a shared level-triggered line holds its own
  interrupt object; the kernel masks the line on assertion, signals every
  claimant, and unmasks only when all have acknowledged — one slow claimant
  is visible in its acknowledgment latency, never a mystery storm.

## DMA And IOMMU

All DMA-capable devices belong to an IOMMU protection domain where hardware
permits. The kernel brokers DMA buffers:

- Driver requests a DMA mapping.
- Kernel validates ownership, rights, size, alignment, and device domain.
- IOMMU mapping is established.
- Mapping is tied to a lease and lifetime.
- Mapping is revoked on device reset or driver crash.

Devices without IOMMU protection are placed into restricted trust classes.
Product profiles may reject them or require user consent.

Device memory heaps, contiguity and carveouts, coherency ownership for
non-coherent engines, shared virtual addressing, and I/O page faults build on
this brokering model and are defined in
`04-device-memory-and-unified-memory.md`.

## Firmware Interaction

Firmware is treated as executable code with security implications.

Firmware policy includes:

- Signed firmware images.
- Version constraints.
- Rollback prevention for security-critical firmware.
- Measured firmware loading.
- Runtime firmware health reporting.
- Crash dump capture where supported.
- Separation between vendor firmware update and OS update policy.

## Secure Components

Secure components include:

- TPM.
- TEE.
- Secure enclave.
- Secure element.
- Biometric coprocessor.
- Display content protection path.
- Key storage engine.

Access is mediated through security services. Drivers expose device operations,
but policy services decide which components may use sensitive functions.

## Data Flow Examples

### Camera

1. Camera driver binds to sensor and ISP nodes.
2. Power manager enables required rails and clocks.
3. Camera service requests user consent and opens the device.
4. Driver allocates protected frame buffers where needed.
5. ISP and sensor streams are synchronized.
6. Frames are delivered to the camera service through shared memory rings.
7. Protected or private frames are marked with data classification labels.

### AI Accelerator

1. Accelerator driver exposes queues, memory requirements, and supported
   operations.
2. AI runtime selects model placement based on policy and hardware state.
3. Tensor buffers are allocated through a memory service.
4. Kernel maps buffers into the accelerator DMA domain.
5. Completion events are delivered through I/O queues.
6. Power and thermal contributions are accounted to the requesting component.

### External GPU

1. PCIe or USB4 hotplug updates the resource graph.
2. Security policy validates the device and IOMMU isolation.
3. GPU driver host binds and initializes the device.
4. Display service may lease scanout or rendering capability.
5. Removal triggers fence cancellation, surface migration, and driver teardown.

