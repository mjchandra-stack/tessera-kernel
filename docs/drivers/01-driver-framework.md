<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Driver Framework

## Goals

The driver framework must support broad hardware coverage without making the
kernel fragile. It must provide:

- Safe driver isolation.
- Strong performance paths.
- Clear class contracts.
- Vendor extensibility.
- Hotplug and suspend/resume support.
- Crash recovery.
- DMA safety.
- Power and thermal coordination.
- Traceability.
- Certification.

## Driver Placement

### User-Space Drivers By Default

Most drivers run in driver hosts, which are isolated processes with:

- Device capabilities.
- Resource leases.
- Restricted address spaces.
- Dedicated I/O queues.
- DMA mapping rights only for assigned devices.
- Structured logging and tracing.
- Restart policy.

Driver host crash should not crash the kernel.

### Driver Unit And Hosting Model

What a driver *is*, stated so the ecosystem is built on a decision rather
than an inference:

- A driver is a component — a sandboxed process speaking its class contract
  over channels and I/O queues. The "driver host" is that process plus the
  framework harness it starts from; vendor code never links into
  system-provided binaries.
- There is no stable in-process driver ABI, and none is promised: the
  stable surface is the ISL class protocol
  (`../api/03-interface-schema-language.md`). This is deliberate — Rust has
  no stable binary ABI, and freezing an FFI module boundary would be
  exactly the internal-API freeze this design rejects. Drivers are
  distributed as source or verified intermediate code and built through the
  local compilation service with binding records
  (`../security/01-security-model.md` "Locally Generated Executable Code"),
  or prebuilt by the vendor against a specific release and rebuilt per
  release train.
- Colocation is a policy decision with a default: one driver component per
  host process. The device manager may colocate multiple driver instances
  in one host only when they share a security domain and a vendor package
  and policy permits — the canonical case being the HID functions of one
  hub. Colocated drivers are one failure unit: the crash-recovery ladder
  treats the host, not the instance, as the blast radius, which is why
  colocation across vendor or security-domain boundaries is never
  permitted.
- Interrupt-wait threads in a host serving admitted reserved pipelines run
  under the host's server reservation
  (`../kernel/07-scheduler-admission-control.md`), and the interrupt wake
  path carries that urgency — the interrupt-to-handler budget (B32) is
  measured under exactly this configuration.

### Bus Topology And Data Paths

Bus controllers are drivers whose children are drivers; the framework
defines the binding tree, and this defines what the data path may cost:

- Where the controller hardware provides per-child queue separation
  (multi-queue NVMe namespaces, USB streams, SR-IOV functions), child
  queues are mapped directly to the child driver or consumer — the
  controller host stays on the control path only, and a transfer crosses
  no extra process.
- Where hardware lacks separation, transfers relay through the bus host;
  a relaying class contract declares its added latency and throughput
  cost, and end-to-end admission (`../kernel/07-scheduler-admission-control.md`)
  consumes the declaration — a deep tree of relaying hubs is a declared
  cost, not a surprise.
- Relay hops count against the device class's budgets: a class cannot meet
  its budget on direct-attach and silently miss it behind two hubs without
  the declaration making that arithmetic visible at binding time.

### In-Kernel Fast Paths

In-kernel code is allowed for:

- Interrupt routing glue.
- Minimal bus enumeration where needed for boot.
- IOMMU setup.
- Early console and boot storage.
- Extremely latency-sensitive queue submission.
- Verified packet or storage filters.

Fast paths must be small, reviewed, fuzzed, traced, and replaceable where
possible.

## Driver Lifecycle

Driver lifecycle states:

- Discovered.
- Matched.
- Starting.
- Probing.
- Active.
- Suspending.
- Suspended.
- Resuming.
- Resetting.
- Degraded.
- Stopping.
- Removed.
- Failed.

Transitions are observable through structured events.

## Driver Binding

Binding inputs:

- Device class.
- Vendor and product ID.
- Hardware revision.
- Firmware version.
- Bus type.
- Security domain.
- Power domain.
- Driver signature.
- Driver class contract version.
- Product policy.

Binding outputs:

- Driver host identity.
- Granted capabilities.
- Resource leases.
- Required services.
- Trace identity.
- Update channel.

## Driver Class Contracts

A driver class contract defines:

- Required methods.
- Optional methods.
- Event types.
- Buffer ownership rules.
- DMA rules.
- Power states.
- Error codes.
- Reset behavior.
- Trace events.
- Conformance tests.

Class contracts are stable public interfaces. Vendor-private methods are allowed
only through explicitly versioned extension namespaces.

## DMA Safety

Driver DMA must use kernel-mediated mappings:

- Buffers are created by trusted allocators.
- Device access rights are explicit.
- IOMMU mappings are scoped to a device and lease.
- Protected memory cannot be mapped unless policy permits it.
- Mappings are revoked on driver crash, device removal, or lease expiration.
- DMA faults are logged and can trigger driver isolation.

## Firmware Loading

Firmware loading is mediated by the driver framework:

- Firmware is signed.
- Firmware version constraints are checked.
- Security-critical rollback is blocked.
- Firmware provenance is logged.
- Firmware crash telemetry is captured where possible.
- Firmware update compatibility is checked before OS update commit.

## Power Management

Drivers expose:

- Supported power states.
- Wake capabilities.
- Resume latency.
- Performance states.
- Dependencies.
- Runtime idle behavior.

Drivers vote for power states. The power manager arbitrates across users,
services, thermal state, and platform policy.

## Hotplug

Hotplug must be reliable for:

- USB.
- PCIe.
- Thunderbolt and USB4.
- Docking stations.
- External displays.
- External GPUs.
- Removable storage.
- Virtual devices.
- Wearable companion devices.

Drivers must tolerate surprise removal. The framework provides cancellation,
timeout, reset, and teardown hooks.

## Crash Recovery

On driver crash:

1. Kernel revokes mappings and interrupts.
2. Device manager marks the device degraded.
3. Crash dump and trace tail are captured.
4. Dependent services are notified.
5. Device reset is attempted if policy allows.
6. Driver host is restarted.
7. Binding is restored or disabled based on failure policy.

Repeated crashes can trigger rollback, fallback drivers, or device quarantine.

## Driver Languages

Preferred implementation languages:

- Rust for new drivers where the ecosystem supports it.
- Memory-safe subsets or checked wrappers for C and C++ where necessary.
- C for narrow hardware-adjacent code that cannot practically use Rust yet.

Language choice does not weaken sandboxing or DMA rules.

## Certification

Driver certification includes:

- ABI conformance.
- Fuzzing.
- Suspend/resume.
- Hotplug.
- DMA fault handling.
- Power management.
- Crash recovery.
- Security policy compliance.
- Performance regression tests.
- Trace event schema validation.

Certified drivers can be distributed through signed update channels.

## Developer Experience

The driver SDK provides:

- Interface schema compiler.
- Driver host template.
- Hardware simulator hooks.
- Trace viewer integration.
- Fault injection.
- DMA test harness.
- Power state emulator.
- Firmware package tooling.
- Certification test runner.

