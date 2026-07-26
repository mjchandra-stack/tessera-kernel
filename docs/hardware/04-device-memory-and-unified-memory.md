<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Device Memory, Contiguity, And Unified Memory

## Purpose

The multimedia, graphics, DSP, and AI device classes in
`../drivers/03-graphics-display-media-sensors-ai.md` need more than the DMA
brokering in `03-component-interaction-model.md`: display scanout, ISP and
codec pipelines, DSP shared regions, and simpler NPUs require large
physically contiguous buffers; modern GPUs and NPUs increasingly share the
CPU's virtual address space and fault pages on demand; and non-coherent
engines need an explicit answer to who owns a buffer's cache state. None of
this was specified. This document defines device memory heaps, the
contiguity contract and reclaimable carveouts, the coherency ownership
protocol, shared virtual addressing, and I/O page faults — completing the
memory model in `../kernel/02-scheduling-memory-ipc.md` for device-visible
memory.

## Device Memory Heaps

A heap is a named allocation domain from which memory objects can be
created. Heaps are discovered from the resource graph and platform manifest
(`02-hardware-description-and-discovery.md`), not invented by drivers.

Heap kinds include:

- System heap: ordinary pageable memory.
- Contiguous carveout heaps: physically contiguous regions declared by the
  platform support package.
- Device-local heaps: memory attached to a device (GPU VRAM, NPU SRAM),
  exposed with explicit properties rather than pretended to be system RAM.
- Protected heaps: secure memory pools per `../kernel/02` "Secure Memory" —
  protected media, confidential, and AI sensitive-context buffers.

Every heap declares: physical properties (contiguity guarantee, minimum and
maximum allocation, alignment, addressing constraints such as a 32-bit DMA
limit), coherency class per attachable device, security domain, protected
status, and reclaim policy. Allocation from a heap is capability-gated; the
device manager grants heap capabilities to driver hosts and services at
binding time, so which components can consume scarce carveout or protected
memory is explicit and auditable.

## Contiguity Contract

A memory object may be created with placement constraints: a named heap,
physical contiguity, minimum alignment, and an addressing limit. Constraints
follow the strict-binding semantics of the placement API in `../kernel/02`:
they are satisfied at allocation or the create fails with a resource error —
never silently weakened.

IOMMU-first rule: physical contiguity is a last resort, not a convenience.
When the consuming device sits behind an IOMMU, the broker satisfies a
"contiguous" requirement by presenting an IOVA-contiguous mapping over
scattered physical pages, and the request must declare device-visible
contiguity rather than physical contiguity. Physical contiguity is honored
only for devices that genuinely require it — no scatter-gather capability
and no IOMMU on their path — which the resource graph records. This keeps
carveout pressure proportional to hardware that actually needs it.

## Reclaimable Carveouts

Carveouts make contiguity obtainable after boot without wasting the memory
when idle — the role CMA plays on Linux.

- The platform support package declares each carveout: base, size,
  alignment, which heaps it backs, and its security domain.
- While unclaimed, carveout pages are lent to the general allocator for
  movable allocations only: page cache and migratable anonymous memory.
  Pinned pages, kernel allocations, and DMA-mapped pages never land in a
  carveout, so reclaim is always possible.
- A contiguous allocation migrates lent pages out, then allocates. Migration
  failure fails the allocation with a resource error and a diagnostic
  naming what could not move; it never blocks indefinitely. Allocation
  latency is budgeted (B18 in `../architecture/03-performance-budgets.md`).
- Lending, migration latency, and per-component carveout consumption are
  emitted as structured events and accounted per
  `../kernel/05-jobs-containment-and-resource-control.md`.

## Cross-Device Sharing And Coherency Ownership

Memory objects are already the cross-process sharing primitive; they are
also the cross-device one (the role of dma-buf): one object may be mapped
into CPU address spaces and attached to multiple device DMA domains through
the brokered mapping flow in `03-component-interaction-model.md`.

Each attachment has a coherency class from the heap and device properties:

- Coherent: no software cache maintenance; ownership transfer is ordering
  only (fences, ring sequence numbers).
- Non-coherent: explicit ownership required.

For non-coherent attachments, access is bracketed by an ownership protocol:
begin-access and end-access operations declaring the accessor (CPU or a
named device attachment) and direction (read, write, or both). The kernel
performs the required cache maintenance through the architecture port at
each transition. GPU fences (`../drivers/03`) and the kernel-mediated ring
ownership transitions (`../kernel/02`) compose with this: a fence or ring
handoff may carry the ownership transition so streaming pipelines pay no
extra syscall. Access outside a held ownership span is a contract violation;
debug builds detect it by protection games and it is a certification test
for the affected driver classes.

## Shared Virtual Addressing

Where the device and IOMMU support PASID and ATS
(`02-hardware-description-and-discovery.md` records these), a process
address space may be bound to a device:

- Binding is brokered by the device manager, requires an explicit
  capability, and is permitted only when the device's security domain is
  compatible with the process's (`../security/01-security-model.md`
  "Security Domains"). Every bind and unbind is audited.
- A bind names which address space, honoring the multiple-address-spaces
  model in `../kernel/02` — a process can expose a JIT or ML compartment to
  an accelerator without exposing its whole address space.
- After binding, the device translates through the same page tables via its
  PASID. The kernel extends TLB shootdown to the IOMMU: page table changes
  invalidate device translations before completing, so a device can never
  use a stale mapping.
- Unbind or process exit quiesces the PASID, drains device faults, and
  invalidates translations before page tables are torn down.
- Protected heaps and lock-evicted key-domain memory are never SVA-visible
  to devices in lower security domains; classification rules govern, as
  everywhere.
- Guests receive SVA through nested translation where hardware supports it,
  composing with the virtualization model rather than bypassing it.

## I/O Page Faults

Without fault capability, device-mapped memory is pinned for the life of the
DMA lease — the existing rule, unchanged. With PRI-class fault support,
SVA-bound memory stays pageable:

- A device page request arrives from the IOMMU and is resolved like a CPU
  fault: resolvable faults route to the backing object's pager under the
  external pager contract in
  `../kernel/03-paging-faults-and-exceptions.md`, served at the bound
  process's effective priority.
- A pager deadline miss or unresolvable fault completes the page request
  with a failure response to the device and raises a device fault event to
  the driver host — the device receives an error it must handle; the IOMMU
  and the paging path are never wedged waiting on it.
- Fault-capable paths declare their fault-service requirements at admission
  when they participate in reserved pipelines
  (`../kernel/07-scheduler-admission-control.md`), since a device fault
  storm is a schedulability input like any other.
- IOPF rates and service latency are structured events; the pager-pressure
  harness (`../prototypes/02-pager-pressure-harness.md`) gains an IOPF
  scenario when the first fault-capable target (virtio-iommu emulation
  first) lands, and IOPF page-in joins the budget suite at that point.

## Observability

Heap utilization and per-component consumption, carveout lending and
migration latency, contiguous allocation failures with the blocking page
named, coherency ownership transitions and violations, SVA binds and
unbinds, and IOPF rates and latencies are all structured events, consistent
with `../observability/01-debugging-monitoring-tracing-logging.md`.
