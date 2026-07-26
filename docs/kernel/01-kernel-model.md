<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Kernel Model

## Kernel Mission

The kernel is an enforcement engine. It provides the minimal set of mechanisms
needed to isolate components, schedule work, manage memory, route events, and
mediate access to hardware.

It should remain small enough that:

- Code review is tractable.
- Security boundaries are clear.
- Formal verification can be applied to selected critical pieces.
- Fuzzing coverage is practical.
- Driver and policy bugs usually remain outside kernel privilege.

Small does not mean serial: the kernel's internal concurrency and
scalability requirements are defined in `08-multicore-scalability.md`.

## Kernel Subsystems

### Architecture Layer

Per-CPU-family code implements:

- Boot entry.
- Trap and syscall entry.
- Context switching.
- Page table operations.
- TLB maintenance.
- Atomic primitives.
- Cache maintenance.
- Timer access.
- Interrupt controller integration.
- CPU feature detection.
- CPU idle and low-level power transitions.
- Architecture security features.

### Scheduler

The scheduler supports:

- Preemptive multitasking.
- Real-time classes for audio, input, radio, and industrial workloads.
- Interactive classes for UI responsiveness.
- Throughput classes for compute.
- Background and maintenance classes.
- Deadline scheduling for media and sensor pipelines.
- Heterogeneous CPU placement.
- Thermal and energy-aware scheduling.
- VM-aware scheduling.
- Per-tenant and per-application accounting.

### Memory Manager

The memory manager supports:

- Per-process virtual address spaces.
- Copy-on-write memory.
- Anonymous memory.
- File-backed memory.
- Shared memory objects.
- Guard pages.
- Huge pages where useful.
- Memory compression where product profiles enable it.
- NUMA and disaggregated memory awareness.
- Memory pressure notifications.
- Secure and protected memory pools.
- DMA memory registration through explicit kernel mediation.

### IPC

IPC primitives include:

- Channels for typed request/response.
- Ports for event fan-in.
- Shared memory for high-throughput data transfer.
- I/O queues for asynchronous submission and completion.
- Capability transfer between authorized components.

The kernel does not parse high-level service protocols unless the protocol is a
kernel ABI. User-space services own their own schemas.

### Handle And Rights System

Each process has a handle table. A handle references an object plus a rights
mask.

Example rights:

- `read`
- `write`
- `execute`
- `map`
- `signal`
- `wait`
- `duplicate`
- `transfer`
- `configure`
- `bind`
- `admin`

Rights can be reduced when handles are duplicated or transferred. Rights cannot
be expanded without a broker that already has the required authority.

### Interrupts And Exceptions

The kernel handles:

- CPU exceptions.
- Page faults.
- Syscalls.
- Timer interrupts.
- Inter-processor interrupts.
- Device interrupts.

Device interrupts can be represented as restricted interrupt objects delivered
to driver hosts. Driver hosts acknowledge or mask interrupts through a kernel
mediated interface.

### Time

The kernel exposes:

- Monotonic time.
- Boot time.
- Real-time clock time through a time service.
- High-resolution timers.
- Deadline timers.
- Timer slack for power-aware batching.

Wall-clock policy, time zones, NTP, secure time, and user-visible time settings
belong to services.

## Kernel Extensibility

Kernel extensions are discouraged as a general extension mechanism. When needed,
the system supports constrained extension models:

- Verified packet filters.
- Verified tracing probes.
- Verified storage or security hooks.
- Architecture-specific platform modules signed as part of platform support.

The verified-program framework — bytecode, verifier guarantees, attach
points, authority, and lifecycle — is defined in
`09-verified-programs.md`.

Any extension mechanism must include:

- Static verification.
- Resource limits.
- Explicit attach points.
- Audit logs.
- ABI versioning.
- Kill switch and rollback.

## In-Kernel Fast Paths

Fast paths are permitted when moving work out of the kernel would break a
measurable requirement.

Candidate areas:

- Futex-style waits.
- Event notification.
- Packet steering.
- GPU scheduling assist.
- Block I/O queue submission.
- Real-time audio wakeups.
- VM exits and interrupt injection.

Fast paths must preserve the same authority model as the higher-level service
path.

## Kernel Non-Goals

The kernel should not become:

- A generic plugin host.
- A place for vendor policy.
- A user interface policy engine.
- A filesystem feature laboratory.
- A dumping ground for compatibility hacks.
- An AI model runtime.

Compatibility and feature evolution belong in versioned services whenever
possible.

