<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Design Principles

## 1. Enforcement In The Kernel, Policy In Services

The kernel should enforce isolation, scheduling, memory protection, IPC rights,
and object lifetimes. Policy should live in replaceable, restartable services
where it can evolve without expanding the trusted computing base.

Kernel responsibilities:

- Threads, address spaces, scheduling, timers, and waits.
- Virtual memory and physical memory accounting.
- Interrupt routing and low-level exception handling.
- IPC primitives and shared memory.
- Capability handle tables and rights checks.
- IOMMU and DMA isolation coordination.
- Minimal boot, CPU, and platform abstraction.

Service responsibilities:

- Filesystems and storage policy.
- Network stack policy and high-level protocols.
- Graphics composition and display policy.
- Package management and updates.
- User identity, authentication, and authorization policy.
- App lifecycle, permissions, and session management.
- AI runtime policy, model placement, and privacy controls.

## 2. Capabilities Instead Of Ambient Authority

Every process receives explicit handles to objects it can use. A handle carries
rights such as read, write, map, signal, duplicate, transfer, configure, bind, or
administer. Global namespaces are views assembled by policy services, not
authority by themselves.

This reduces accidental privilege and makes sandboxing inspectable.

## 3. Typed Interfaces Over Escape Hatches

Subsystems expose typed object methods described by schemas. Schema definitions
generate:

- C, Rust, Swift, Kotlin, and C++ bindings.
- Validation code.
- Trace decoders.
- Fuzzing harnesses.
- Documentation.
- Compatibility tests.

Opaque escape hatches exist for development, but they are not stable public ABI
unless promoted through review and conformance testing.

## 4. Isolation By Default, Shared Fast Paths By Exception

Drivers, filesystems, codecs, AI model runtimes, network services, and device
managers run outside the kernel by default. Shared memory rings, batched IPC,
kernel-mediated event queues, and mapped command buffers provide performance.

In-kernel fast paths require:

- A documented latency or throughput requirement.
- A bounded interface.
- Memory-safety strategy or verifier coverage.
- Fuzz tests.
- Tracepoints.
- Rollback plan.

## 5. Hardware Is A Resource Graph

Hardware is represented as a typed graph of devices, buses, memory ranges,
interrupts, clocks, resets, power rails, firmware dependencies, security
domains, DMA windows, and topology relationships.

The graph is derived from ACPI, Device Tree, PCIe, USB, firmware tables,
platform manifests, and runtime discovery. The normalized graph is what drivers
bind to.

## 6. Stable Public ABI, Flexible Internal APIs

Public interfaces must be stable and versioned. Internal kernel and service APIs
can evolve aggressively as long as public ABI profiles and conformance tests
continue to pass.

Compatibility is a product feature, not a side effect.

## 7. Observability Is A System Contract

Every subsystem emits structured events, counters, logs, and crash records with
stable schemas. Debugging should work across:

- Kernel and user space.
- Drivers and services.
- Virtual machines and containers.
- Mobile and desktop sessions.
- Local and remote devices.
- Production and development builds.

## 8. Power, Thermal, And Privacy Are Scheduling Inputs

Modern platforms are constrained by battery, thermal envelopes, privacy
expectations, and accelerator availability. Scheduling decisions must consider:

- CPU topology.
- GPU, NPU, DSP, and media accelerator load.
- Memory bandwidth.
- Thermal headroom.
- Battery state.
- Foreground or background status.
- Data sensitivity.
- User intent.

## 9. Updates Must Be Atomic And Recoverable

The system supports A/B or snapshot-based updates, signed boot chains, rollback,
driver and firmware compatibility checks, staged rollout, and crash-based
automatic remediation. The cryptography behind signing and rollback is
algorithm-agile and post-quantum-ready so it can evolve across the system's
multi-decade lifetime without a rewrite (see
`security/02-cryptography-and-key-management.md`).

## 10. Future Hardware Should Not Require Architectural Rewrite

The design assumes new device classes will appear: neural sensors, always-on AI
coprocessors, spatial displays, medical sensors, secure personal data vaults,
ambient microphones, multi-device compute fabrics, and new memory hierarchies.

The OS must absorb these through typed hardware descriptions, extensible driver
classes, stable capabilities, and policy-managed services.

