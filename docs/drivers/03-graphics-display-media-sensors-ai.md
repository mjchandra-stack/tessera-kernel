<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Graphics, Display, Media, Sensors, And AI Drivers

## Graphics

### Stack

```text
Applications and UI frameworks
  Windows, surfaces, games, compute APIs.

Compositor
  Window composition, display routing, protected surfaces, color management.

Graphics runtime
  API translation, shader compilation, memory management policy.

GPU driver host
  Command submission, queues, memory binding, fences, firmware interaction.

Kernel fast path
  Scheduler assist, memory mapping, fence signaling, reset coordination.
```

### GPU Driver Contract

GPU drivers expose:

- Queue families.
- Command buffer formats.
- Memory heaps.
- Synchronization primitives.
- Fence model, built on timeline sync objects
  (`../kernel/04-synchronization-and-ipc-guarantees.md`).
- Preemption granularity as a declared capability: mid-draw, draw boundary,
  or command-buffer boundary.
- Display scanout support where integrated.
- Reset behavior.
- Protected content support.
- Telemetry and fault reporting.
- Virtualization support.

### GPU Security

GPU drivers must account for:

- Cross-process memory isolation.
- Shader compiler attack surface.
- Command buffer validation.
- Side-channel risk from shared accelerators.
- Protected media surfaces.
- VM guest access.

Shader and pipeline caches are locally generated code and follow
`../security/01-security-model.md` "Locally Generated Executable Code".

### GPU Scheduling And Preemption

The driver host owns queue arbitration within kernel-enforced constraints;
the kernel scheduler assist enforces the constraints, not the policy:

- The compositor and display service hold a preempting high-priority queue
  capability — background compute cannot starve composition, by
  construction rather than by tuning.
- Kernel-side priority and deadline inheritance map into GPU queue priority
  bands, so a reserved media pipeline's GPU stage runs at the pipeline's
  urgency (`../kernel/07-scheduler-admission-control.md` admits GPU stages
  against queue budgets using the declared preemption granularity).
- Queue occupancy ceilings from resource domains and security-domain queue
  isolation apply per `../kernel/05-jobs-containment-and-resource-control.md`
  and `../kernel/02-scheduling-memory-ipc.md`.
- Device-local memory oversubscription uses the migration and pressure
  machinery of `../hardware/04-device-memory-and-unified-memory.md`; the
  driver host owns eviction policy, and residency loss is observable to
  clients through object-state signals, never silent stalls.

### Reset And Robustness

- Reset escalates: hung context first (only the offending client's context
  dies), then engine, then whole-GPU reset, then quarantine per
  `01-driver-framework.md`. Each step is an attributed event.
- Context loss is a defined client contract: affected clients receive an
  object-state signal and poisoned sync points
  (`../kernel/04-synchronization-and-ipc-guarantees.md` "Timeline Sync
  Objects"), and recreate resources — the device-lost model, not a crash.
- The compositor survives full GPU reset: client buffers in system memory
  are unaffected, device-local surface contents are lost and their clients
  told to redraw, and the session recomposes per
  `../graphics/01-surface-and-presentation.md` without terminating
  applications.

## Display

### Display Service

The display service owns:

- Physical displays.
- Virtual displays.
- Display leasing.
- Surface composition.
- Color management.
- HDR policy.
- Variable refresh rate.
- Touch-to-display association.
- Secure presentation.
- Screen capture policy.

Display drivers expose display pipelines, modes, connectors, planes, scaling,
color capabilities, and hotplug events.

### Multi-Device Display

The architecture supports:

- External monitors.
- Wireless display.
- AR glasses.
- Wearable companion displays.
- Remote desktop surfaces.
- VM displays.

Every display path carries protection and privacy metadata.

## Multimedia

### Audio

The audio system includes:

- Audio graph service.
- Low-latency audio path.
- Audio device drivers.
- Bluetooth audio integration.
- Spatial audio support.
- Voice isolation and enhancement.
- Policy for microphone privacy.

Audio drivers expose:

- Stream formats.
- Buffer sizes.
- Latency ranges.
- Clock domains.
- Jack and route state.
- DSP offload capabilities.
- Wake-word hardware support where present.

### Camera And Video

Camera and video pipelines include:

- Sensor drivers.
- ISP drivers.
- Video codec drivers.
- Camera service.
- Privacy indicator enforcement.
- Protected buffer support.
- Per-frame metadata.
- Multi-camera synchronization.

Camera access is brokered by policy. Raw sensor access requires special
capabilities.

### Codecs

Codec drivers and services support:

- Hardware encode.
- Hardware decode.
- Protected content.
- Format negotiation.
- Quality and latency controls.
- Power-aware placement.
- Sandboxed software fallback.

Codec parsing of untrusted media should occur in sandboxed processes.

## Sensors

### Sensor Classes

Supported sensor classes include:

- Accelerometer.
- Gyroscope.
- Magnetometer.
- Barometer.
- Ambient light.
- Proximity.
- GPS and GNSS.
- Camera-derived sensors.
- Microphone-derived sensors.
- Health and biometric sensors.
- Environmental sensors.
- Wearable contact sensors.

### Sensor Broker

The sensor broker owns:

- Permission checks.
- Sampling policy.
- Batching policy.
- Sensor fusion.
- Privacy-preserving degradation.
- Background limits.
- Cross-device sensor continuity.

Drivers expose calibrated sensor streams and hardware capabilities. They do not
decide application-level access.

### Always-On Sensing

Always-on sensing requires special handling:

- Low-power sensor hub support.
- On-device filtering.
- Wake event policy.
- Data minimization.
- Clear audit trails.
- User-visible privacy controls.

## AI Accelerators

### AI Accelerator Driver Contract

AI accelerator drivers expose:

- Supported operations.
- Tensor formats.
- Quantization formats.
- Memory alignment requirements.
- Shared virtual addressing and I/O page fault support where hardware
  provides it (`../hardware/04-device-memory-and-unified-memory.md`).
- Queue model.
- Preemption granularity as a declared capability: per-operation, kernel
  boundary, queue drain, or none.
- Firmware scheduling declaration: where a firmware scheduler owns the
  queues, the contract declares what the host can preempt, reorder, and
  observe — admission and QoS promises are bounded by the declaration.
- Compilation cache requirements.
- Model partitioning support.
- Secure execution support.
- Telemetry counters.
- Fault reporting.

### AI Runtime Boundary

The AI runtime, not the driver, owns:

- Model selection.
- Graph compilation policy.
- Accelerator placement.
- Data classification checks.
- Model cache policy.
- User consent for personal context.
- Fallback to CPU, GPU, NPU, or cloud.

### Accelerator Preemption, Reset, And Robustness

The AI accelerator classes carry the same execution contracts as the GPU:

- "Foreground inference preempts background" is enforceable only against
  the declared preemption granularity; the scheduler and admission control
  (`../kernel/07-scheduler-admission-control.md`) consume the declaration,
  and an engine declaring `none` cannot back latency promises — the
  contract is never more honest than the hardware.
- Reset escalates: hung job, then engine, then device, then quarantine per
  `01-driver-framework.md`, each step attributed. In-flight jobs on a reset
  path complete their timeline sync points with poisoned status
  (`../kernel/04-synchronization-and-ipc-guarantees.md`), so the runtime
  and its clients observe device-lost semantics and recreate state rather
  than hang.
- The AI runtime survives accelerator reset: weights re-page from sealed
  images, sessions re-establish, and clients receive a distinct
  inference-reset error, mirroring the compositor's GPU-reset survival.

### Sensitive Inference

The system treats inference over private data as a sensitive operation. The
policy engine can require:

- Local-only execution.
- Protected memory.
- No logging of raw inputs.
- No model cache persistence.
- User consent.
- Enterprise policy approval.
- Attestation of model and runtime.

### Multi-Accelerator Scheduling

AI workloads may span CPU, GPU, NPU, DSP, and memory engines. The runtime
coordinates with the scheduler and power manager to avoid foreground impact and
thermal overload.

