<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# System Architecture

## Architectural Style

The OS is a hybrid architecture with a small enforcing kernel and a rich set of
isolated system services. It avoids two extremes:

- A fully monolithic system where most drivers and policies share kernel
  privilege.
- A purist microkernel where every operation crosses several protection
  boundaries even when hardware performance goals make that impractical.

The kernel is responsible for mechanisms. Services are responsible for policy.
Fast paths are explicitly designed, measured, and reviewed.

## Layered View

```text
Applications and agents
  Desktop apps, mobile apps, wearable apps, CLI tools, web runtimes,
  AI assistants, background jobs, enterprise agents.

Application frameworks
  UI toolkit, media framework, storage APIs, networking APIs, identity APIs,
  AI APIs, sensor APIs, notification APIs, accessibility APIs.

User-space system services
  App lifecycle, package manager, permission manager, compositor, storage
  manager, network manager, audio service, camera service, sensor service,
  model runtime, diagnostics service, update service.

Driver hosts
  Isolated processes that run class drivers and vendor drivers with bounded
  privileges, DMA capabilities, and restart policy.

Kernel
  Scheduling, memory, IPC, handles, timers, interrupts, traps, capability
  checks, IOMMU coordination, minimal architecture and platform support.

Firmware and hardware
  Boot firmware, secure monitor, TPM/TEE/secure enclave, CPUs, memory,
  buses, storage, networking, GPUs, NPUs, displays, sensors, radios.
```

## Core Object Model

The kernel exposes objects through handles. Handles carry rights and refer to
kernel-managed or service-backed objects.

Primary object classes:

- `process`: an execution container with address spaces and handles.
- `thread`: a schedulable execution context.
- `job`: a tree grouping of processes and child jobs for policy and lifecycle.
- `address_space`: a virtual memory map.
- `memory_object`: anonymous, file-backed, device-backed, or shared memory.
- `pager`: user-space backing-store provider for a memory object.
- `channel`: bidirectional structured IPC.
- `stream`: ordered byte transport with backpressure.
- `port`: event delivery endpoint.
- `event`: signalable synchronization primitive.
- `lock`: owner-aware lock supporting priority inheritance.
- `sync`: timeline synchronization object ordering device and cross-process
  completion.
- `exception_channel`: destination for synchronous fault reports.
- `timer`: deadline or interval signal source.
- `interrupt`: restricted object delivered to authorized driver hosts.
- `device`: typed device endpoint owned by the device manager.
- `io_queue`: asynchronous I/O submission and completion queue.
- `resource_domain`: enforceable resource limits and reservations for a job.
- `revocation_scope`: transitive revocation anchor for handles delegated
  across trust boundaries.
- `vm`: virtual machine object with guest memory and vCPU state.
- `security_context`: process identity, sandbox, and policy state.

The same rights model applies to objects regardless of whether the object is
implemented directly by the kernel or represented by a service.

## Boot Flow

1. Firmware verifies and loads the first-stage bootloader.
2. The bootloader verifies the kernel, boot policy, platform support package,
   initial ramdisk, and system image metadata.
3. Firmware and bootloader measurements are extended into hardware-backed
   measurement storage where available.
4. The kernel initializes CPU-local state, memory management, interrupt
   controllers, timers, early console, and a minimal root task.
5. The root task starts the component manager, device manager, security policy
   service, logging service, and update verifier.
6. The device manager normalizes hardware discovery into the system resource
   graph and starts driver hosts.
7. The session manager starts mobile, desktop, server, embedded, or wearable
   product profiles.

Slot selection, the initrd-to-system transition, boot-success and update
commit are defined in
`../lifecycle/03-boot-sequence-and-update-mechanics.md`.

## Component Model

Every long-running service, driver, and application is a component with a
manifest. The manifest declares:

- Binary identity and signature requirements.
- Required capabilities.
- Offered capabilities.
- Data storage classes.
- Network access classes.
- Device access classes.
- Logging and tracing permissions.
- Restart policy.
- Resource budgets.
- Update channel.
- Compatibility profile.

Components do not discover authority by scanning global paths. They receive
capabilities from parents, policy services, or brokered user consent.

## System Services

System services are replaceable within compatibility limits. Important services
include:

- Component manager.
- Device manager.
- Driver supervisor.
- Storage manager.
- Filesystem service.
- Network manager.
- Network stack service.
- Display compositor.
- Audio graph service.
- Camera and sensor broker.
- Package and update manager.
- Identity and account service.
- Permission broker.
- Secrets and key service.
- Power and thermal manager.
- AI runtime and model broker.
- Log service.
- Diagnostics and telemetry service.

## Data Planes And Control Planes

The architecture separates control messages from high-throughput data paths.

Control plane:

- Typed IPC over channels.
- Capability transfer.
- Policy decisions.
- Configuration.
- Lifecycle events.

Data plane:

- Shared memory rings.
- I/O queues.
- Mapped command buffers.
- DMA buffers mediated by the kernel and IOMMU.
- Zero-copy packet buffers where security policy allows.

This avoids excessive IPC overhead while keeping authority explicit.

## Failure Model

The system assumes components will fail. Kernel mechanisms support:

- Driver host restart after crash.
- Device reset and rebind.
- Service dependency restart.
- Crash dump capture.
- Watchdog escalation.
- Automatic rollback after update failure.
- Degraded operation when optional services are unavailable.

Critical services are supervised. Restart policy is part of each component
manifest.

## Product Profiles

The same architecture supports multiple product profiles:

- Phone and tablet.
- Laptop and desktop.
- Workstation.
- Wearable.
- TV and appliance.
- Automotive or industrial profile.
- Server and edge node.
- Hypervisor host.

Profiles select default services, UI shell, security policy, power policy,
available APIs, and update cadence. The kernel and stable ABI remain shared.

