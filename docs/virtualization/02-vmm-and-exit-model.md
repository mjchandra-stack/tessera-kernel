<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# VMM Architecture And Exit Model

## Purpose

`01-virtualization-and-isolation.md` defines VM objects and their guarantees
but not the component that runs a VM, the split of VM-exit handling between
kernel and user space, or what the type-1 profile concretely is. Those are
the decisions that determine hypervisor attack surface and virtualization
performance, so they are made here.

## The Virtual Machine Monitor

Each VM is run by its own VMM: a sandboxed, per-VM component holding that
VM's object handles and nothing else.

- One VMM per VM is the blast-radius rule: a compromised or crashed VMM
  takes down exactly one guest. The VMM, its vCPU threads, and its device
  backends live in one job, so containment, resource limits, and teardown
  are the standard mechanisms of
  `../kernel/05-jobs-containment-and-resource-control.md`.
- The VMM's sandbox is minimal: VM object handles, the guest memory
  objects, channels to its device backends, and whatever the manifest
  grants. It has no filesystem view and no network authority of its own —
  guest I/O reaches the world only through backends.
- Device backends are separable: simple devices (serial, entropy, balloon)
  run in the VMM process; data-plane devices (virtio-blk, virtio-net,
  virtio-gpu) may run as separate backend components bridging a virtual
  device queue to the corresponding host service — the block service, a
  network stack instance (`../network/01-network-stack.md`), the
  compositor. A backend crash resets its device, not the VM.
- The VMM registers as the VM's fault handler per
  `../kernel/03-paging-faults-and-exceptions.md`: guest faults are VM
  events, and unresolvable ones terminate or reset the guest per the VMM's
  policy, never the host.

## Exit Routing

VM exits split into two classes, and the split is the type-2 hypervisor's
core performance decision:

- Kernel-handled exits (the fast path from `../kernel/01-kernel-model.md`,
  budgeted as B27): virtual interrupt injection and acknowledgment, halt
  and idle transitions, virtual timer programming, inter-vCPU IPIs, an
  explicit allowlist of system-register and MSR accesses, and second-stage
  page faults resolvable against the guest's memory objects (including the
  pager path). These never leave the kernel; the vCPU re-enters directly.
- VMM-handled exits (budgeted as B28): MMIO to emulated devices,
  configuration-space access, unhandled system registers, and anything not
  on the allowlist. The run-vCPU call returns to the VMM with a typed exit
  structure (defined in ISL, so exits are traced and fuzzed like every
  interface), the VMM emulates, and re-enters.

The allowlist is part of the ABI and versioned; nothing is silently added
to kernel handling, because every kernel-handled exit is TCB growth and
must pass the fast-path gate in `../01-design-principles.md`.

Assigned-device interrupts bypass both paths where hardware permits: posted
interrupts (or direct virtual interrupt injection) deliver to a running
vCPU without an exit, falling back to kernel injection otherwise. This
capability is recorded in the resource graph and considered during
assignment.

## The Type-1 Profile, Concretely

The type-1 profile is the same kernel, not a second hypervisor codebase:

- In the type-1 deployment the kernel boots as the hypervisor and every
  workload — including the management OS — runs as a guest partition. The
  management partition is a privileged guest holding VM-management
  capabilities for its sibling partitions, exactly as any process holds VM
  handles in the type-2 profile; the VM object ABI is identical in both.
- Physical devices are partitioned by assignment: each partition receives
  its devices through the standard assignment machinery, and the management
  partition hosts driver VMs or backend services for shared devices.
- The difference between the profiles is configuration and what runs in
  root mode, not the object model — which is what "share VM object
  abstractions where possible" concretely means.
- The full partitioning profile (automotive, industrial consolidation) is
  deferred to its own stage gate per `../roadmap/01-sequencing-and-mvp.md`;
  the commitment made now is that it is a configuration of this kernel,
  not a new one.

## Nested Virtualization

Not supported in v1, stated as a posture rather than an omission: guests do
not see virtualization extensions. The exit model reserves space for it —
nested exits multiplex through the same typed exit structures — and it is
revisited when a target profile demands it (cloud development guests being
the expected driver). Nested *translation* for guest SVA
(`../hardware/04-device-memory-and-unified-memory.md`) is unrelated and
already supported.

## Guest Time

- Guests receive a paravirtual clock and per-vCPU steal-time reporting, so
  guest schedulers can account for host overcommit instead of misreading
  stolen time as their own load.
- The time-page ABI (`../api/01-system-call-interface.md` "Time") is
  per-kernel: a guest kernel maintains its own time page for its userspace
  from the paravirtual clock; the host's page is never mapped into guests.

## Observability

Exit counts and latency histograms per exit class and reason, allowlist
hits, VMM emulation latency, posted-interrupt delivery rates, steal time
per vCPU, and backend resets are structured events, tagged per VM and
tenant, consistent with
`../observability/01-debugging-monitoring-tracing-logging.md`.
