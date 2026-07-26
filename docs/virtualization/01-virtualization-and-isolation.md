<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Virtualization And Isolation

## Goals

Virtualization is a first-class operating system feature. The OS supports:

- Running as a host.
- Running as a guest.
- Containers.
- Application sandboxes.
- Confidential VMs where hardware supports them.
- Device assignment.
- Virtual devices.
- Development and test environments.
- Enterprise isolation.

## Hypervisor Architecture

The hypervisor can operate in two deployment modes:

- Type-1 profile: hypervisor layer owns hardware and runs the OS as a privileged
  management partition.
- Type-2 profile: OS kernel hosts VMs using hardware virtualization extensions.

Both profiles share VM object abstractions where possible. The VMM
architecture, the kernel/user exit-handling split, and what the type-1
profile concretely is are defined in `02-vmm-and-exit-model.md`.

## VM Object Model

VMs are kernel objects with handles and rights.

Objects include:

- VM.
- vCPU.
- Guest memory object.
- Virtual interrupt controller.
- Virtual timer.
- Virtual device queue.
- VM event port.
- Device assignment lease.

VM management requires explicit capabilities.

## Guest Memory

Guest memory supports:

- Anonymous memory.
- File-backed disk images.
- Shared memory with host services.
- Ballooning.
- Huge pages.
- NUMA placement.
- Confidential memory where hardware supports it.

Confidential memory has stricter tracing, dumping, and host access controls.

Reclaim of guest memory under host pressure is ordered and policy-bound:
balloon requests first (cooperative), free-page reporting where the guest
supports it, host swap of guest memory through the swap pager
(`../storage/02-file-io-and-caching.md`) only where per-VM policy permits —
and never for confidential memory, pinned ranges, or VMs holding reserved
vCPUs (`../kernel/07-scheduler-admission-control.md`) — and finally
policy-driven termination under the same pressure model as everything else.
Every step is attributed to the VM's resource domain.

## Virtual Devices

Virtual device models include:

- Paravirtual block.
- Paravirtual network.
- Paravirtual GPU.
- Input.
- Clipboard.
- Audio.
- Filesystem sharing.
- Entropy.
- Time.
- Serial and console.
- Sensor virtualization for test profiles.

Virtual devices are services, not arbitrary kernel plugins, unless a fast path
is justified.

Guest-to-host communication rides paravirtual device queues, not native
channels: kernel channels do not cross the VM boundary. Host-side management
of a VM uses the VM object's event port and handles like any other kernel
object.

## Device Assignment

Direct device assignment requires:

- IOMMU isolation.
- Interrupt remapping.
- Reset capability.
- Ownership transfer from host to guest.
- Security policy approval.
- Recovery path after guest crash.
- Compatibility with suspend and resume.

Mediated devices support sharing GPUs, NPUs, NICs, and storage controllers where
hardware and drivers permit it.

## Containers

Containers are built from native isolation mechanisms:

- Namespaces for filesystem and service views.
- Capability-filtered handles.
- Resource groups.
- Network namespaces.
- User identity mapping.
- Policy-controlled device access.
- Image verification.

Containers do not bypass the core capability model.

Container images use the native verified layer format
(`../kernel/05-jobs-containment-and-resource-control.md` "Storage
Composition For Images"); OCI images are supported by import — layers
converted to verified subvolumes — rather than natively, so verification is
preserved. Unconverted OCI workloads are a tier 3 Linux VM concern per
`../api/04-linux-and-posix-compatibility.md`.

## Application Sandboxes

Application sandboxes are lighter than containers but use the same principles:

- Explicit capabilities.
- Private storage.
- Brokered file access.
- Brokered device access.
- Network policy.
- Background execution policy.
- Debug policy.

## Isolation Tier Selection

The mechanisms form a ladder — sandbox, container, VM, confidential VM —
and tier selection is policy, not developer whim:

- The sandbox is the default for every component; containers add namespace
  and image isolation for composed or multi-process workloads.
- A VM is required by policy where the threat is the kernel attack surface
  itself: hostile-content processing beyond what codec and parser
  sandboxing covers, tier 3 compatibility workloads, and the Linux driver
  containment bridge.
- A confidential VM is required where the host is outside the trust
  boundary: enterprise workloads on shared infrastructure and the
  highest-sensitivity inference per `../future/02-ai-runtime-security.md` —
  the existing exemplar of tier selection by data class.
- The policy engine selects the minimum tier from data classification and
  threat posture; profiles declare defaults, and a component may request a
  stronger tier but never a weaker one than policy demands.

## Attestation

Confidential VMs and managed guests need verifiable evidence of what they are
running. Attestation is a defined flow, not an afterthought.

- Each VM has an attestation record derived from measured boot: firmware,
  bootloader, kernel, platform support package, and initial image measurements
  as produced by `security/01-security-model.md`.
- For confidential VMs, the hardware root of trust signs a quote over guest
  launch measurements and a guest-supplied nonce. The host cannot forge or alter
  the quote; it only transports it.
- A relying party (enterprise policy, a remote service, or the model permission
  broker) verifies the quote against expected measurements before releasing
  secrets or sensitive data classes to the guest.
- Attestation results are capability-gated: passing attestation yields handles to
  sealed keys or data-class access, rather than ambient trust.
- Attestation events are recorded in per-VM audit logs.

## Snapshot, Checkpoint, And Live Migration

Snapshots, checkpoints, and migration share one mechanism so state capture is
consistent and policy-aware.

### State Capture

A VM checkpoint captures a consistent point-in-time image:

- vCPU register state from all vCPUs after a coordinated pause.
- Guest memory, using dirty tracking to iterate on a running guest.
- Virtual device model state, quiesced through each device's save contract.
- Assigned-device state where the device supports save and restore; guests with
  non-migratable assigned devices are marked migration-ineligible.

### Live Migration

1. Pre-copy: guest memory is copied while the guest runs, using dirty-page
   tracking to re-send pages modified during transfer.
2. Convergence: when the remaining dirty set is small enough to meet the
   downtime target, the guest is briefly paused.
3. Stop-and-copy: final dirty pages, vCPU state, and device model state are
   transferred.
4. Resume: the destination validates compatibility and resumes the guest; the
   source releases resources only after the destination acknowledges.

### Confidential And Assigned-Device Constraints

- Confidential VM memory is opaque to the host, so migration uses hardware
  migration agents where available; the source and destination roots of trust
  perform a mutual attestation handshake and the guest is re-attested at the
  destination. Without hardware migration support, confidential VMs are
  snapshot-only or non-migratable per policy.
- Migration transport is encrypted and integrity-protected. Migration is a
  capability-gated, audited operation, and data-classification policy can forbid
  migrating guests that hold restricted data classes to non-attested hosts.
- Snapshots inherit the guest's data classification; snapshot storage,
  tracing, and dumping follow the confidential-memory rules above.

## VM-Aware Scheduling

The scheduler understands:

- vCPU threads.
- Halt states.
- Overcommit.
- Real-time guest constraints.
- Host foreground priority.
- VM memory pressure.
- Accelerator assignment.
- Thermal policy.

VMs are accounted to users, applications, or enterprise tenants.

## Security

Virtualization security includes:

- Hypervisor attack surface minimization.
- Device emulation sandboxing.
- VM escape mitigation.
- Guest-host clipboard and file sharing policy.
- Confidential VM support.
- Attestation.
- Per-VM audit logs.
- Restricted debug access.

## Developer Workflows

The platform supports:

- Local disposable VMs.
- Reproducible build VMs.
- Driver development VMs.
- OS compatibility VMs.
- Mobile and wearable emulators.
- Snapshot and rollback.
- Deterministic trace capture.

