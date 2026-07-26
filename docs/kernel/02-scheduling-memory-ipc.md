<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Scheduling, Memory, And IPC

## Scheduling Goals

The scheduler must handle workloads that look very different:

- Mobile foreground interaction.
- Desktop multitasking.
- Wearable always-on sensing.
- Real-time audio and input.
- Background synchronization.
- Local AI inference.
- VM hosting.
- Build workloads and workstation compute.
- Server-style network services.

The scheduler is therefore policy-extensible but mechanism-stable.

## Scheduling Classes

### Critical Real-Time

For bounded-latency tasks such as audio callbacks, industrial control loops, and
radio deadlines. Admission is controlled by policy. Tasks must declare budgets
and deadlines. The reservation model, schedulability tests, and enforcement
semantics are defined normatively in `07-scheduler-admission-control.md`.

### Interactive

For UI, input, window management, shell operations, and active user workflows.
This class is latency-sensitive and power-aware.

### Media Deadline

For camera, video, audio graph, display composition, and sensor fusion pipelines.
It uses deadline hints and pipeline metadata. Pipeline descriptors and
end-to-end deadline composition are defined in
`07-scheduler-admission-control.md`.

### Compute

For builds, data processing, rendering, local inference, indexing, and batch
work.

### Background

For sync, backup, maintenance, prefetch, indexing, and speculative AI tasks.
This class is aggressively power and thermal constrained.

### Guest

For virtual CPUs and VM support threads. The scheduler understands vCPU
relationships, halt states, virtual interrupts, and host overcommit policy.

## Heterogeneous CPU Scheduling

The scheduler models:

- Performance cores.
- Efficiency cores.
- Real-time islands.
- Always-on microcontrollers.
- SMT sibling relationships.
- NUMA domains.
- Cache topology.
- Memory bandwidth.
- Thermal zones.

Tasks carry hints:

- Latency sensitivity.
- Throughput preference.
- Energy preference.
- Affinity constraints.
- Security constraints.
- Accelerator dependencies.

Hints are advisory unless policy marks them mandatory.

The "Security constraints" hint carries the task's security domain, defined
normatively in `../security/01-security-model.md` "Security Domains". The
scheduler uses it to enforce microarchitectural isolation — for example refusing
to co-tenant SMT siblings across mutually distrusting domains — as described in
`../security/01-security-model.md` "Microarchitectural Isolation". For these
domains the constraint is mandatory, not advisory.

## Accelerator-Aware Scheduling

AI, graphics, media, and sensor workloads often span CPU, GPU, NPU, DSP, ISP,
and memory engines. The scheduler coordinates with accelerator services to
avoid:

- CPU threads waiting on oversubscribed accelerators.
- Thermal overload from simultaneous CPU and NPU boost.
- Background inference harming foreground UI.
- Priority inversion across shared command queues.

Command queues are isolated between security domains so that submissions from one
domain cannot observe or delay another through shared accelerator state, per
`../security/01-security-model.md` "Microarchitectural Isolation".

## Memory Model

### Address Spaces

Each process has one or more address spaces. Multiple address spaces allow:

- Sandboxed plugin compartments.
- JIT separation.
- Protected media paths.
- VM monitor isolation.
- Language runtime isolation.

### Memory Objects

Memory objects represent:

- Anonymous memory.
- File-backed memory.
- Shared memory.
- Device memory.
- Secure memory.
- Guest memory.
- Copy-on-write snapshots.

Mapping rights are separate from object ownership rights.

Device memory heaps, physical-contiguity constraints, reclaimable carveouts,
cross-device coherency ownership, shared virtual addressing, and I/O page
faults are defined in `../hardware/04-device-memory-and-unified-memory.md`.

### Memory Pressure

Memory pressure is reported through structured events:

- Per-process soft warnings.
- Per-cgroup or per-component pressure.
- System-wide pressure.
- Foreground protection hints.
- Killable and reclaimable classifications.

The memory manager supports compression, reclaim, pageout, process suspension,
and policy-driven termination depending on product profile. The compression
tier, the swap pager, and swap encryption are defined in
`../storage/02-file-io-and-caching.md` "Swap And Memory Compression".

### Memory Placement And Affinity

The scheduler models NUMA domains, cache topology, and heterogeneous memory, but
that awareness is useless without a way for callers to express placement intent.
The memory manager exposes a placement API that names memory tiers as first-class
resources rather than raw physical addresses.

Memory tiers are discovered from the resource graph and exposed as stable
identifiers:

- Local NUMA node memory.
- Remote NUMA node memory.
- High-bandwidth or on-package memory.
- Capacity or far memory in disaggregated systems.
- Accelerator-attached or coherent device memory.

Placement is expressed as advisory hints or, where policy permits, binding
constraints on a memory object or a mapped range:

- Preferred tier or preferred node with fallback order.
- Strict binding that fails allocation rather than spilling to another tier.
- Interleave across a set of nodes for bandwidth-bound workloads.
- Co-location with a thread, a job, or an accelerator DMA domain.
- Migration policy: pin, allow migration, or request migration to a tier.

The memory manager may migrate pages between tiers under pressure or on explicit
request, honoring strict bindings and secure-memory restrictions. Placement
decisions and migrations are accounted per component and emitted as structured
events so bandwidth and latency regressions are diagnosable. Guests receive
virtualized tier identifiers so the same API works inside VMs.

### Secure Memory

Secure memory types include:

- Non-swappable memory.
- Hardware-encrypted memory.
- Protected video path memory.
- Key material memory.
- Confidential VM memory.
- AI sensitive-context buffers.

Access requires specific capabilities and may restrict tracing, dumping, and
sharing.

## IPC Model

### Channels

Channels are bidirectional message endpoints. Messages contain:

- Header with interface ID, method ID, flags, and transaction ID.
- Inline data.
- Out-of-line memory references (ownership modes per
  `04-synchronization-and-ipc-guarantees.md`).
- Transferable handles.
- Optional deadline metadata.
- Optional data-classification label.
- Optional tracing correlation ID.

### Ports

Ports provide event fan-in for:

- Timers.
- Object state changes.
- I/O completions.
- Interrupt notifications.
- Child process exits.
- Driver hotplug.

### Shared Memory Rings

High-throughput subsystems use shared memory rings for:

- Network packets.
- Audio buffers.
- Video frames.
- AI tensor buffers.
- Storage I/O descriptors.
- Graphics command buffers.

Shared rings have kernel-mediated ownership transitions and traceable sequence
numbers.

### I/O Queues

I/O queues provide asynchronous operations with:

- Submission queues.
- Completion queues.
- Cancellation.
- Deadlines.
- Priorities.
- Batch submission.
- Event integration.

I/O queues are the preferred model for storage, networking, and high-throughput
device classes.

## Priority Inversion Control

The system supports:

- Priority inheritance for locks and IPC calls where applicable.
- Deadline inheritance for media pipelines.
- Bounded service call chains.
- Scheduler-visible dependency tracking.
- Diagnostic events for blocked high-priority tasks.

## Accounting

Resource accounting is done per:

- Process.
- Component.
- Application.
- User.
- Container.
- VM.
- Driver.
- Device.
- Data class.

Accounting covers CPU time, memory, I/O, network, accelerator time, wakeups,
power estimates, thermal contribution, and background execution.

