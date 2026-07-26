<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Detailed Design Index

This directory contains the detailed architecture for a modern operating system
intended to span mobile, desktop, wearable, embedded, workstation, and
virtualized environments.

Forty-eight design documents, grouped by area. The numbering is a reading
order: each area assumes the ones above it. Areas also carry their own
sub-index where the split needs explaining (see [Drivers](drivers/README.md)).

## Reading Order

### Foundations

1. [Design Principles](01-design-principles.md) — the non-negotiable
   principles and the tradeoffs they cost.

### Architecture

Overall system model, component boundaries, and the budgets every subsystem is
held to.

2. [System Architecture](architecture/01-system-architecture.md)
3. [Separation Of Concerns](architecture/02-separation-of-concerns.md)
4. [Performance Budgets](architecture/03-performance-budgets.md)

### Kernel

What the enforcing kernel is responsible for: scheduling, memory, IPC,
containment, and the guarantees each one makes.

5. [Kernel Model](kernel/01-kernel-model.md)
6. [Scheduling, Memory, And IPC](kernel/02-scheduling-memory-ipc.md)
7. [Paging, Faults, And Exceptions](kernel/03-paging-faults-and-exceptions.md)
8. [Synchronization And IPC Guarantees](kernel/04-synchronization-and-ipc-guarantees.md)
9. [Jobs, Containment, And Resource Control](kernel/05-jobs-containment-and-resource-control.md)
10. [Capability Revocation](kernel/06-capability-revocation.md)
11. [Scheduler Admission Control And Deadline Composition](kernel/07-scheduler-admission-control.md)
12. [Multicore Scalability](kernel/08-multicore-scalability.md)
13. [Verified Programs](kernel/09-verified-programs.md)

### Hardware

CPU and platform support, hardware description as a schema-governed contract,
and the device memory model.

14. [Platform And CPU Support](hardware/01-platform-and-cpu-support.md)
15. [Hardware Description And Discovery](hardware/02-hardware-description-and-discovery.md)
16. [Hardware Component Interaction Model](hardware/03-component-interaction-model.md)
17. [Device Memory, Contiguity, And Unified Memory](hardware/04-device-memory-and-unified-memory.md)

### Drivers

Driver hosting and the class-specific designs. See
[drivers/README.md](drivers/README.md) for how the four documents divide the
space.

18. [Driver Framework](drivers/01-driver-framework.md)
19. [Storage, Networking, USB, And PCIe Drivers](drivers/02-storage-networking-usb-pcie.md)
20. [Graphics, Display, Media, Sensors, And AI Drivers](drivers/03-graphics-display-media-sensors-ai.md)
21. [Embedded Buses, Power, And Timekeeping Drivers](drivers/04-embedded-buses-power-and-timekeeping.md)

### Power

Power manager boundary, system sleep, wakeup sources, CPU power governing, and
energy attribution.

22. [Power Management And System Sleep](power/01-power-management.md)

### Storage

Native copy-on-write filesystem, file I/O, caching, direct I/O, and swap.

23. [Native Copy-On-Write Filesystem](storage/01-native-cow-filesystem.md)
24. [File I/O, Caching, And Swap](storage/02-file-io-and-caching.md)

### Network

Stack instancing, data path, flow API, firewall, VPN, and DNS.

25. [Network Stack](network/01-network-stack.md)

### Graphics

Surface and presentation protocol, buffer negotiation, and the compositor
restart contract.

26. [Surface And Presentation Protocol](graphics/01-surface-and-presentation.md)

### API

The system call ABI and everything that keeps it stable across releases.

27. [System Call Interface](api/01-system-call-interface.md)
28. [ABI Versioning And Compatibility](api/02-abi-versioning-and-compatibility.md)
29. [Interface Schema Language](api/03-interface-schema-language.md)
30. [Linux And POSIX Compatibility](api/04-linux-and-posix-compatibility.md)

### Security

Trust boundaries, key management, and the user-facing authentication model.

31. [Security Model](security/01-security-model.md)
32. [Cryptography And Key Management](security/02-cryptography-and-key-management.md)
33. [Authentication, Users, And Recovery](security/03-authentication-and-user-model.md)

### Virtualization

Hypervisor, VM, container, and device virtualization model.

34. [Virtualization And Isolation](virtualization/01-virtualization-and-isolation.md)
35. [VMM Architecture And Exit Model](virtualization/02-vmm-and-exit-model.md)

### Observability

Debugging, monitoring, tracing, logging, and troubleshooting facilities.

36. [Debugging, Monitoring, Tracing, And Logging](observability/01-debugging-monitoring-tracing-logging.md)
37. [Collection, Persistence, And Telemetry](observability/02-collection-persistence-and-telemetry.md)

### Platforms

Per-form-factor experience architecture and cross-device continuity.

38. [Mobile, Desktop, And Wearable Experience](platforms/01-mobile-desktop-wearable-experience.md)
39. [Continuity And Device Groups](platforms/02-continuity-and-device-groups.md)

### Lifecycle

Development, build, release, update, and maintenance model.

40. [Development, Maintenance, And Update Model](lifecycle/01-development-maintenance-update-model.md)
41. [Build And Test Infrastructure](lifecycle/02-build-and-test-infrastructure.md)
42. [Boot Sequence And Update Mechanics](lifecycle/03-boot-sequence-and-update-mechanics.md)
43. [Coding Guidelines](lifecycle/04-coding-guidelines.md)

### Future

AI-native and wearable-era architecture.

44. [AI And Wearable Era](future/01-ai-and-wearable-era.md)
45. [AI Runtime Security](future/02-ai-runtime-security.md)

### Roadmap And Prototypes

Build sequencing, MVP scope, stage exit gates, and the harnesses that prove the
Stage 0 budgets.

46. [Sequencing And MVP](roadmap/01-sequencing-and-mvp.md)
47. [IPC Benchmark Harness](prototypes/01-ipc-benchmark-harness.md)
48. [Pager-Under-Pressure Harness](prototypes/02-pager-pressure-harness.md)

## Hierarchy

```text
docs/
  README.md
  01-design-principles.md
  architecture/
    01-system-architecture.md
    02-separation-of-concerns.md
    03-performance-budgets.md
  kernel/
    01-kernel-model.md
    02-scheduling-memory-ipc.md
    03-paging-faults-and-exceptions.md
    04-synchronization-and-ipc-guarantees.md
    05-jobs-containment-and-resource-control.md
    06-capability-revocation.md
    07-scheduler-admission-control.md
    08-multicore-scalability.md
    09-verified-programs.md
  hardware/
    01-platform-and-cpu-support.md
    02-hardware-description-and-discovery.md
    03-component-interaction-model.md
    04-device-memory-and-unified-memory.md
  drivers/
    README.md
    01-driver-framework.md
    02-storage-networking-usb-pcie.md
    03-graphics-display-media-sensors-ai.md
    04-embedded-buses-power-and-timekeeping.md
  power/
    01-power-management.md
  storage/
    01-native-cow-filesystem.md
    02-file-io-and-caching.md
  network/
    01-network-stack.md
  graphics/
    01-surface-and-presentation.md
  api/
    01-system-call-interface.md
    02-abi-versioning-and-compatibility.md
    03-interface-schema-language.md
    04-linux-and-posix-compatibility.md
  security/
    01-security-model.md
    02-cryptography-and-key-management.md
    03-authentication-and-user-model.md
  virtualization/
    01-virtualization-and-isolation.md
    02-vmm-and-exit-model.md
  observability/
    01-debugging-monitoring-tracing-logging.md
    02-collection-persistence-and-telemetry.md
  platforms/
    01-mobile-desktop-wearable-experience.md
    02-continuity-and-device-groups.md
  lifecycle/
    01-development-maintenance-update-model.md
    02-build-and-test-infrastructure.md
    03-boot-sequence-and-update-mechanics.md
    04-coding-guidelines.md
  future/
    01-ai-and-wearable-era.md
    02-ai-runtime-security.md
  roadmap/
    01-sequencing-and-mvp.md
  prototypes/
    01-ipc-benchmark-harness.md
    02-pager-pressure-harness.md
```

## Architectural Position

The design is intentionally not a clone of Linux, Windows, Android, iOS, Fuchsia,
or a traditional microkernel. It adopts the strongest lessons from each style:

- Linux-style hardware reach and pragmatic performance.
- Microkernel-style fault isolation and restartable services.
- Mobile-style sandboxing, permission prompts, energy accounting, and seamless
  updates.
- Desktop-style open extensibility, professional tooling, windowing,
  virtualization, and broad peripheral support.
- Cloud-style observability, rollout safety, and policy-driven fleet
  management.

The result is a hybrid OS centered on a small enforcing kernel, typed system
interfaces, isolated services, isolated drivers, capability security, and
portable hardware abstraction.
