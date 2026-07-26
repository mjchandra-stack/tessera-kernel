<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Sequencing And MVP

## Purpose

The design documents describe an end state that spans phones, desktops,
wearables, servers, and hypervisor hosts. No project survives by building an
end state. This document defines the build order, the first product, the exit
gate for each stage, and what is explicitly out of scope for v1. It exists
because the largest risk to this architecture is not a wrong mechanism; it is
running out of credibility before an ecosystem exists.

## Sequencing Principles

1. Validate the riskiest architectural bets first, with the smallest possible
   hardware surface. The riskiest bets are IPC performance with scheduling
   handoff, the external pager under memory pressure, and driver-host I/O
   overhead — all now bound by `../architecture/03-performance-budgets.md`.
2. Prefer virtual hardware until the core bets are proven. Board bring-up is
   expensive and proves nothing about the architecture.
3. Ship a real product early, in a niche where the design's differentiators
   (atomic updates, isolation, observability, long support) matter and the
   required driver surface is small.
4. Ecosystem before breadth. Every stage must leave developers and vendors
   with something usable, or the next stage has no participants.

## Stage 0 — Core Bet Validation (Virtual Platform Only)

Targets: QEMU/KVM guest on x86-64 and AArch64 using the virtual platform
profile from `../hardware/01-platform-and-cpu-support.md`.

Scope:

- Kernel: boot, threads, address spaces, handles and rights, channels with
  synchronous handoff (`../kernel/04-synchronization-and-ipc-guarantees.md`
  "Synchronous Call Scheduling"), ports, wait-on-address, timers, jobs.
- Interface schema language toolchain
  (`../api/03-interface-schema-language.md`): compiler, Rust bindings,
  validators, conformance goldens. The IDL is built before the services that
  need it, not after.
- Component manager, device manager with a minimal resource graph, one driver
  host running virtio-blk and virtio-net class drivers.
- External pager with a RAM-backed filesystem service, including the
  write-back-under-pressure rules in
  `../kernel/03-paging-faults-and-exceptions.md`.
- The two mandated prototype harnesses from
  `../architecture/03-performance-budgets.md`: the IPC microbenchmark suite
  (`../prototypes/01-ipc-benchmark-harness.md`) and the pager-under-pressure
  harness (`../prototypes/02-pager-pressure-harness.md`).

Exit gate: budgets B1–B11 met on reference class R1; pager pressure and
self-paging tests pass; kill-a-driver-host-under-load recovers per the failure
model. If the IPC or pager budgets cannot be met, the architecture is revised
here, before any board support or product work begins.

Gate status (see `../../build/README.md`, D56). The pager-pressure / self-paging
clause and the kill-a-driver-host clause are **met** (D55/M22 and D51/M21). The
budget clause is evaluated in two tiers: the in-repo rig runs B1–B11 under QEMU as
a **regression** gate (budgets tracked continuously, no regressions — met), while
**bare-metal R1 compliance** for B1–B11 is a distinct **hardware-CI** gate that
requires reference hardware absent from the development environment (per
prototypes/01, "QEMU/KVM runs validate harness correctness only"). R1 compliance
is therefore the one remaining Stage-0 exit criterion, formally scoped to a
dedicated hardware-bring-up milestone rather than blocking in-repo progress; the
rest of Stage 0 proceeds QEMU-certified.

Two facts sharpen what that hardware milestone must carry. B5 (cross-core notify)
and B24 (cross-core call) are cross-core measurements, and the kernel is
**single-core** by D8 — so R1 compliance is gated on multicore support, not on
procurement alone. And the reference class R1 itself ("out-of-order core at
≥ 3 GHz", `../architecture/03-performance-budgets.md`) is what a candidate board
must satisfy; a board can serve as a Stage-1 *reference board* for driver and
platform work without qualifying as an R1 *measurement rig*. The two roles are
separate and should be sourced separately.

Scope status. Every Stage-0 scope bullet above is **built**: the kernel
primitives (through jobs and the ELF loader), the ISL toolchain, the component
manager and device manager, the external pager with its RAM-backed filesystem,
both mandated prototype harnesses, and — closing the last of them — one driver
host running virtio-blk and virtio-net class drivers. Tracked leftovers are the
ISL codegen gaps in D10 (nested table/union fields, non-Rust bindings, fuzzers,
ABI-diff). Stage 0 is therefore complete in-repo, with bare-metal R1 (above) the
sole outstanding exit criterion.

Architecture coverage (M27 onward, `../../build/README.md` D61–D65, D70–D85).
Stage 0's "QEMU/KVM guest on x86-64 **and AArch64**" target is met on both, and
now well past the kernel level. The AArch64 port boots under
`qemu-system-aarch64 -M virt` and runs the same architecture-conformance battery
(D63) x86-64 does, closing D5's "no in-kernel test harness" and satisfying
Porting Rule 5. It has since gained **ring-3 parity**: EL0 user mode with
per-process TTBR0 address spaces and ASIDs, ELF-loaded `no_std` Rust user
programs, channel IPC between EL0 processes, and capability-gated `map_device` /
`dma_alloc` — all routed through the shared frame-neutral syscall dispatcher both
ports call (D79). On that substrate runs the **ring-3 device host**: one resident
EL0 process driving both virtio-blk and virtio-net through the unchanged
architecture-neutral virtio core, serving clients over a user↔user ISL protocol
the kernel transports opaquely, with reads driven by real device interrupts
delivered to ring 3. What remains is a demo-placement split rather than a
mechanism gap: the device host is AArch64-only while the component-manager,
pager, and ports demos are x86-64-only, though both ports share one `kcore` and
one dispatcher. The budget clause above stays x86-64-measured; AArch64 B7 is
tracked under QEMU (D65).

## Stage 1 — Self-Hosting Developer System

Targets: headless server/workstation profile on generic x86-64 and one
well-documented AArch64 reference board.

Scope:

- Storage: NVMe driver, block service, volume manager, and a ported
  memory-safe filesystem implementation as v0. The native copy-on-write
  filesystem is developed in parallel and is not on the critical path.
- Network: user-space stack v0 (IPv4/IPv6, TCP, UDP), one wired NIC driver.
- POSIX source-compatibility tier (`../api/04-linux-and-posix-compatibility.md`
  tier 1) sufficient to build and run the toolchain, shell, and core
  utilities.
- Logging, tracing, and crash dumps usable end to end.
- A/B system update with rollback on the reference board.

Exit gate: the OS builds itself on itself; B12–B14 met; update and rollback
pass the lifecycle tests.

## Stage 2 — First Product: Embedded And Appliance

The first shippable product uses the embedded/appliance profile from
`../platforms/01-mobile-desktop-wearable-experience.md`. Rationale: the
differentiators (atomic updates, watchdog-backed recovery, driver isolation,
long support windows, fleet observability) are exactly what that market buys,
and the driver surface per device is small enough to supply first-party.

Scope: embedded bus and platform driver classes from
`../drivers/04-embedded-buses-power-and-timekeeping.md`, hardware watchdog
escalation, remote diagnostics, signed platform support packages for the
supported boards, declared support windows.

Exit gate: a device in the field survives a hostile update/rollback/power-loss
test matrix and is diagnosable remotely without physical access.

## Stage 3 — Desktop Developer Preview

Scope: compositor and input stack, virtio-gpu first and one real GPU target
second, audio graph service, tier 2 Linux binary compatibility for developer
tools, and the Linux system VM (tier 3) for container workloads.

Exit gate: a developer can use the system as a daily driver for building the
OS itself; input-to-photon and audio budgets met.

## Stage 4 — Mobile And Wearable, With Partners

Mobile and wearable profiles require vendor platform support packages, radio
stacks, and certification infrastructure. They are deliberately last: they
need the ecosystem tooling proven in stages 0–3, and they are partnerships,
not solo engineering. The AI platform services in
`../future/01-ai-and-wearable-era.md` land here as ordinary components; the
earlier stages only guarantee the substrate (security domains, data classes,
accelerator driver contracts) that makes them possible.

## MVP Definition

In scope for v1 (through stage 2):

- Kernel with all objects in `../architecture/01-system-architecture.md`
  except `vm` (virtualization ships in stage 3).
- ISL toolchain and generated artifacts.
- Component, device, driver-host, storage, network, update, logging, and
  diagnostics services.
- Virtio, NVMe, one NIC, and the embedded driver classes.
- POSIX source tier; capability security model complete.

Explicitly out of scope for v1:

- Confidential VMs, live migration, device assignment.
- AI runtime, model registry, personal context store (design reserved, not
  built).
- Wearable, mobile, automotive profiles; spatial and ambient computing.
- Enterprise fleet management; accessibility beyond core hooks.
- Wi-Fi, cellular, Bluetooth, and other radio stacks.
- The native copy-on-write filesystem as default (ships when it beats the
  ported v0 in test, not by a date).

Cutting these from v1 changes no kernel interface: each lands as services and
driver classes on the same substrate, which is the point of the architecture.

## Ecosystem Bootstrapping

Three deliberate prongs, replacing hope with a plan:

1. Virtio-first drivers. Every class contract gets a virtio implementation
   before a hardware one. Anything that works in a VM works in every cloud and
   every developer machine on day one.
2. Linux driver containment as a bridge. Unsupported hardware can be driven by
   a Linux instance in a dedicated driver VM exporting the device over a
   native class contract (network, block, USB first). This is explicitly a
   bridge: it buys hardware reach while first-party and vendor drivers are
   written, and its use is measured so the bridge shrinks instead of
   ossifying.
3. First-party allowlist. A small, published list of reference hardware gets
   first-party, certified drivers. Breadth comes from vendors only after the
   SDK, certification suite, and update channels have been proven on that
   allowlist.

## Risks Accepted

- Stage 0 may prove a budget unreachable; that is the cheapest possible place
  to learn it, and the design treats it as revision input, not failure.
- The embedded-first product order delays consumer visibility; it is chosen
  because consumer profiles without an ecosystem fail publicly.
- The Linux driver VM bridge risks becoming permanent; the mitigation is
  measurement and the explicit allowlist commitment above.
