<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Tessera

A capability-based operating system designed for the next several decades of
personal computing — phones, desktops, wearables, embedded devices, servers,
and AI-native hardware — built on a small enforcing kernel, isolated
restartable services, and interfaces that are typed, versioned, and budgeted
from day one.

A *tessera* is a single tile in a mosaic: small, sharply bounded, and
meaningful only in composition. That is the architecture — every driver,
service, and application is an isolated component holding exactly the
capabilities it was granted, composing into a whole no single tile can
compromise.

**Status: design specification complete; Stage 0 implementation under
way.** The repository contains the full architecture — 50 documents — plus
the first twenty-four implementation milestones of
[Stage 0](docs/roadmap/01-sequencing-and-mvp.md). The kernel boots under
QEMU on x86-64 through a hermetic Bazel build graph with tier-0/1/3 gates,
brings up its own GDT/IDT, per-CPU state, frame allocator, and fallible
heap, then installs **its own page tables** (write-XOR-execute kernel
image, guard-paged stacks, a KASLR-randomized direct map), an
**address-space object** with map/unmap/protect, **kernel threads** on
guarded stacks, and a **per-CPU preemptive round-robin scheduler** driven
by the timer tick. On top of that sits the **capability core**: typed,
refcounted kernel objects reached through a per-process **handle table**,
each handle carrying a **rights mask that only ever narrows** — duplicate,
close, query, and replace-rights, with object lifetime driven by reference
count. Riding on the scheduler and capability core is **synchronous IPC**:
paired **channel** endpoints with bounded FIFO message queues, and a
request/response **call** that hands control *directly* from caller to
callee and back — a round trip in **exactly two context switches**, with
handles transferred atomically across the message and the reference
conserved in flight (the load-bearing bet behind the 2 µs IPC budget).
Riding on all of that is **user mode**: a **process** — its own address
space (sharing the kernel's higher half), a per-process handle table, and a
ring-3 thread — reaching the kernel only through a **SYSCALL/SYSRET**
boundary that validates every structured argument before interpreting it, and
whose **faults are contained** (the process is terminated, the kernel lives).
A boot demo runs a program in ring 3 that syscalls and then deliberately
faults, proving the isolation bet on real hardware. Memory is then served
**on demand**: anonymous user mappings are lazily zero-filled on first touch
and **copy-on-write** snapshots share pages read-only until written — a page
fault the kernel **resolves and resumes** rather than kills (the substrate the
external pager will build on), demonstrated by a ring-3 program that faults
across a lazy region and a COW page and runs to a clean exit. That substrate
then carries the **external pager**: a fault on **service-backed memory** is
forwarded over an IPC channel to a pager, which **supplies** the page (an
ownership transfer, at the faulting thread's inherited priority), and the read
resumes transparently — the pager relationship invisible to the consumer, so an
in-kernel pager swaps for a user-space service later; a boot demo has a ring-3
program read pager-backed pages a pager kernel thread serves over IPC. Two more
primitives complete the synchronization surface: **wait-on-address**, the
futex-style compare-and-block/wake keyed by an address with no kernel-visible
owner — a ring-3 thread blocks *inside* its syscall and a kernel thread wakes it
across the ring boundary — and **ports**, async event delivery that *cannot lose
an event or overflow*: one preallocated slot per bound (source, signal) pair,
edges coalescing into a single event carrying a pending count, and a drain that
reads current state (a consumer proves the coalescing while a producer signals
and wakes it). Processes are then contained by **jobs** — a tree in which every
process belongs to exactly one job: killing a job tears down its whole subtree
**innermost-first**, an object-count limit **tightens-only** down the tree (an
over-cap create fails with a resource error, never a silent drop), and a job's
**state port** signals member-exit and emptiness so a supervisor reclaims
deterministically; a boot demo builds a tree, watches the limit and the `KILL`
right reject, kills the subtree, and drains the state port. The first **real
user-space program** then arrives as an **ELF**: a freestanding ring-3 binary,
built as its own artifact and embedded in the image, is **parsed and loaded** by
the kernel — each `PT_LOAD` segment mapped at its own W^X rights (`rx` text,
never writable-and-executable), the file bytes copied and bss zeroed — then
started at its `e_entry` through the **three-phase create → populate → start**
path; a boot demo loads it, and it runs in ring 3, prints through the debug
syscall, and exits clean. That root task then becomes a **user-space loader**:
from ring 3 it calls the process-lifecycle syscalls — `ProcessCreate` →
`AddressSpaceMap` → `ProcessStart` — to create a **child process**, map and
populate its code into a fresh address space (copied from the parent's buffer
through the kernel's direct map, W^X applied), and start it; the child runs in
ring 3 and exits, and the parent resumes — the docs' "kernel maps, user-space
loads" model, with processes made handle-addressable and the syscall ABI a typed
schema. Those two processes then **talk over a channel**: a ring-3 **client**
issues a `ChannelCall` to a ring-3 **server** — inline bytes plus a **transferred
capability handle** — and the server `ChannelReply`s, all over the kernel's
synchronous call/reply handoff (exactly two switches), across the privilege
boundary and two address spaces; the transferred capability's reference is
conserved as it moves client→message→server. This is the first ring-3↔ring-3
RPC and the substrate every later user-space service sits on, with handles made
channel-addressable through an endpoint-object bridge. A ring-3 **driver host**
then owns a **real device**: a client asks it to service an I/O over a channel,
and the driver drives a 16550 UART (COM2) — poking a register through a
**capability-gated `DeviceIo` syscall**, taking the device's **hardware
interrupt in ring 3** (delivered as a port event through a new interrupt→port
bridge), reading the result, and replying to the client. This is the first
in-ring-3 device driver and the driver-host I/O bet, with the
submission→driver-visible latency measured (B11); the interrupt reaches ring 3
safely because every kernel path already runs interrupts-masked, so the
driver's thread is the only interruptible context. A ring-3 **device manager**
then closes the loop on how a driver *gets* its device: it owns a minimal
**resource graph** (a device node = an I/O port range + interrupt line), and when
a driver host asks for its device over a channel, the manager **grants a device
capability** — transferred in the channel reply. The driver installs the received
capability and drives the device through it, and the kernel now reads and
**enforces the device's `(base, len)` range from the capability's own payload**
rather than a compiled-in constant — closing the long-standing gap where a kernel
object could only be a typed refcount with no authority-scoping data. A
**microbenchmark harness**
then measures those mechanisms —
null syscall, handle op, IPC round trip (proven to be exactly two switches),
context switch, contended wait/wake, and demand-fill/COW faults — with
serialized invariant-TSC timing and exact percentiles, reporting a table at boot
(QEMU numbers validate the rig and catch regressions; the R1 budget gate is
bare-metal). A second, **pager-under-pressure** harness then proves the
write-back side of the external pager: pages are supplied read-only so the first
write **faults them dirty** (software dirty tracking), clean pages are **evicted**
under a resident cap and paged back in, a writer that dirties faster than
write-back is **throttled at the write fault**, a page is marked clean **only
after the pager acknowledges** its write-back, and killing a pager that holds
dirty pages **faults its object and reports exactly the lost ranges** — boot
scenarios cover each, and **B10 (page-in) is measured under pressure** at
50/90/99 % utilization, holding without a cliff. The three failure scenarios round
it out: a **write-back reservation** keeps reclaim progressing at hard memory
pressure (and fails cleanly, faulting the range, past the reservation), the kernel
**detects self-paging cycles** (pager A↔B, and the degenerate self-pager) and
faults the request instead of hanging, and a pager that **misses its page-in
deadline** hands the faulter a bounded error and escalates repeated misses to
supervised restart — the forbidden outcome in every case being a hang. The pager
itself then moves out
of the kernel: a ring-3 **RAM-backed filesystem service** holds a "file" in its
own memory, and when a client maps that object and faults, the page-in request
is handed to the service, which **supplies the page from its own buffer** — the
kernel copies the bytes through its direct map and installs the frame, so the
privileged page install stays in the kernel while the *backing store lives in a
user-space service*, exactly the external-pager split the design mandates (an
out-of-range supply is refused, and the page's ownership reference is conserved
across the transfer). Services are then made **supervisable**: a ring-3
**component manager** launches a service, watches it exit, and **restarts it per
a restart policy** — it retries a crashing service until it comes up clean, and a
**restart budget** hard-caps the retries so a service that keeps crashing is given
up on rather than restarted forever — the design's "service dependency restart"
made real on the process-lifecycle syscalls. That restart is then made
**unbounded** by **reclaim-on-exit**: when a supervised child exits, the kernel
returns *all* of its resources to their pools — its process-table and scheduler
slots, its kernel stack, its address space (leaf frames *and* the page-table
frames it uniquely owns), and the parent's handle to it — so a service can be
restarted hundreds of times without leaking, the deterministic reclaim the job
model mandates; a boot check restarts a service 41 times past the old leak bound
and comes up clean, drawing a bounded, launch-count-independent number of frames.
That supervision is then aimed at a **driver host**: a ring-3 driver that owns a
real device **crashes via a genuine CPU fault** (a null-dereference #PF, not a
simulated exit), the kernel **contains** it, and a supervisor **reclaims** the
crashed host, **revokes and rebinds** its device capability (its reference
conserved across every restart), and **restarts** it until it comes up clean and
services a client — the failure model's "driver host restart after crash" and
"device reset and rebind" made real, closing the Stage-0 exit gate that a
killed-under-load driver host recovers; a boot check crashes the host twice, each
time reclaimed and rebound, then watches it restart and drive the device.
Alongside the kernel, the
**[Interface Schema
Language](docs/api/03-interface-schema-language.md) toolchain** (v0)
compiles `.isl` schemas — parse, type-check under the ABI rules, a stable
compiled IR, and Rust bindings with a canonical wire codec verified by
conformance goldens (including the handle and syscall-argument ABIs and the
channel message header). Stage 0 validates the riskiest architectural bets on
virtual hardware before any board support or product work.

## Building And Booting

Prerequisites: [Bazelisk](https://github.com/bazelbuild/bazelisk) on PATH
as `bazel`, rustup (the pinned toolchain in `rust-toolchain.toml` installs
on first use), `qemu-system-x86` and `xorriso` from your distribution.

```bash
bazel test //...                        # gates + unit tests + QEMU smoke boot
bazel build //... --config=lint         # rustfmt + clippy over the whole graph
bazel build //kernel/image:tessera_iso  # bootable BIOS ISO
qemu-system-x86_64 -M q35 -m 512M -cdrom bazel-bin/kernel/image/tessera.iso \
  -serial stdio -display none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

Cargo (`cargo test`, `cargo kbuild`) is the developer inner loop; release
artifacts come only from the Bazel graph
([build/README.md](build/README.md), including the deviation ledger).

## What Makes It Different

- **Enforcement in the kernel, policy in services.** The kernel owns
  scheduling, memory, IPC, and capability enforcement. Filesystems, network
  stacks, drivers, and every policy decision live in sandboxed, restartable
  user-space components. A driver crash is a device reset, not a kernel
  panic; a compositor crash is a flicker, not a lost session.
- **Capabilities instead of ambient authority.** A process can touch only
  what it holds explicit handles to, rights only narrow, revocation is
  transitive and mechanical, and services authenticate callers through
  kernel-attested credentials — never payload claims.
- **The performance bet is falsifiable.** Isolation architectures
  historically die on performance folklore. Tessera instead carries
  [32 numbered budgets](docs/architecture/03-performance-budgets.md) —
  2 µs IPC round trips, 15 µs page-in through a user-space pager, parallel
  scaling floors — enforced as release gates, with
  [prototype harnesses](docs/prototypes/01-ipc-benchmark-harness.md) that
  gate Stage 0 and run today as a continuous regression tier under QEMU
  (bare-metal compliance on reference hardware is a separate, tracked
  gate). If a budget can't be met, the architecture gets revised, not the
  marketing.
- **One schema language for every boundary.** Syscalls, driver contracts,
  and service protocols are defined in a typed
  [interface schema language](docs/api/03-interface-schema-language.md)
  that generates bindings, validators, fuzzers, and trace decoders — so
  ABI stability, fuzzing coverage, and privacy redaction are properties of
  codegen, not discipline.
- **Data classification carried with the data.** Health, biometric,
  credential, and AI-context data classes drive encryption, key binding,
  logging redaction, telemetry egress, and inference placement uniformly —
  including an honest local-only boundary that binds telemetry too.
- **Designed for the AI and wearable era.** Model runtimes are isolated and
  attested, weights are untrusted data, agent authority flows through the
  same capability model as everything else, and prompt injection is
  answered at the authority layer — a persuasive prompt cannot grant what
  the agent does not hold.
- **Observability as a system contract.** Every subsystem specifies its
  structured events; logs survive kernel panics; every budget is measured
  from the events the system itself emits.

## Reading Guide

| If you want… | Start here |
| --- | --- |
| The five-minute overview | [OVERVIEW.txt](OVERVIEW.txt) |
| The full spec, in order | [docs/README.md](docs/README.md) — 48-document reading order |
| The non-negotiables | [Design Principles](docs/01-design-principles.md) |
| What gets built first, and what v1 explicitly is not | [Sequencing And MVP](docs/roadmap/01-sequencing-and-mvp.md) |
| The numbers the architecture must hit | [Performance Budgets](docs/architecture/03-performance-budgets.md) |
| The security model end to end | [Security Model](docs/security/01-security-model.md) |

## Repository Layout

```text
api/
  isl/             ISL compiler: parser, type checker, IR, Rust codegen
  isl-runtime/     no_std canonical wire codec for generated bindings
kernel/
  karch/           Architecture porting layer: traits + plain types
  karch-mock/      Mock architecture layer for host unit tests
  karch-x86_64/    x86-64 port: UART, GDT/IDT, traps, PIC/PIT, per-CPU,
                   page tables, context switch
  karch-arm-common/ Platform devices both Arm ports drive: GICv2, PL011 UART
                   (a device is shared, a system register is not)
  karch-aarch64/   AArch64 port: EL1 traps + EL0 entry, generic timer,
                   TTBR0/TTBR1 page tables, context switch
  karch-arm32/     ARM 32-bit port: LPAE page tables (40-bit physical behind
                   32-bit virtual), banked-mode vector table, CP15 timer
  karch-riscv-common/ Platform devices both RISC-V ports drive: PLIC,
                   NS16550A UART, test finisher (a device is shared, a CSR is not)
  karch-riscv64/   RISC-V 64 port (RVA23): S-mode trap vector, Sstc timer,
                   Sv39 page tables, context switch
  karch-riscv32/   RISC-V 32 port: the first 32-bit word size — Sv32 page
                   tables (physical addresses wider than pointers), scause
                   bit 31, a two-CSR timer compare, context switch
  arch-conformance/ One battery every port runs, so "implements the porting
                    layer" is a result rather than a claim
  kcore/           Arch-independent core: console, frame alloc (+ reclaim),
                   heap, panic, address spaces (demand paging, copy-on-write,
                   external-pager page-in, write-back/eviction/dirty-tracking),
                   threads, scheduler, objects/handles/rights, channels +
                   synchronous-handoff IPC (executive), wait-on-address, ports,
                   jobs (containment tree), ELF64 loader, processes + the
                   shared frame-neutral syscall dispatcher both ports call
                   (ring-3 channel IPC, ports, capability device I/O, DMA),
                   structured events, benchmark stats
  devicetree/      Flattened Device Tree reader: the discovery front end for
                   platforms that describe themselves with DT rather than ACPI
  virtio/          Architecture-neutral, unsafe-free virtio core: the modern
                   (v2) virtio-mmio handshake, split virtqueues, blk/net codecs
  width-conformance/ Build-only gate: the architecture-independent crates
                   compiled at a 32-bit word size, so the core cannot acquire
                   a 64-bit assumption before the 32-bit ports land
  kernel/          x86-64 boot glue (Limine), linker script, composition root
  kernel-aarch64/  AArch64 boot glue (flat Image + DTB), linker script
  kernel-riscv64/  RISC-V 64 boot glue (SBI handoff + DTB), linker script
  kernel-riscv32/  RISC-V 32 boot glue (SBI handoff + DTB), linker script
  kernel-arm32/    ARM 32-bit boot glue (raw image + DTB in r2), linker script
  image/           Bootable ISO assembly
userspace/
  roottask/        First ring-3 program: a real ELF, embedded and loaded;
                   the M14 user-space loader — creates/populates/starts a child
  device-manager/  The ring-3 device manager: holds a capability to every
                   device, enumerates them by probing, and grants each driver
                   the one it binds to by class
  device-host/     The ring-3 driver host: one resident EL0 process that binds
                   its devices from the manager at runtime, drives both
                   virtio-blk and virtio-net through the unchanged virtio
                   core, and serves clients over channel IPC
  blk-client/      A ring-3 block-service client holding only a channel
                   endpoint — no device or DMA capability at all
build/             Bazel platforms, kernel + user rules, deviation ledger
tools/
  checks/          Tier-0 gates: SPDX, license pins, unsafe inventory
  lint/            rustfmt/clippy gate targets
  qemu/            Tier-3 smoke boot
third_party/       Vendored dependencies (hash-pinned, permissive licenses)
docs/
  architecture/    System model, separation of concerns, performance budgets
  kernel/          Kernel model, scheduling, memory, IPC, admission control,
                   revocation, multicore scalability, verified programs
  hardware/        CPU/platform support, resource graph, device memory
  drivers/         Driver framework and class contracts
  storage/         Native CoW filesystem, file I/O, caching, swap
  network/         Network stack, flow API, firewall, VPN
  graphics/        Surface and presentation protocol
  power/           Power management and system sleep
  api/             Syscall interface, ABI versioning, schema language,
                   Linux/POSIX compatibility
  security/        Security model, cryptography, authentication and users
  virtualization/  VMs, containers, VMM and exit model
  observability/   Tracing, logging, telemetry, crash persistence
  platforms/       Product profiles, continuity and device groups
  lifecycle/       Update model, build/test infrastructure, boot mechanics,
                   coding guidelines
  future/          AI runtime and wearable-era architecture
  roadmap/         Build sequencing and MVP scope
  prototypes/      Stage 0 benchmark and pressure-harness specifications
```

## Contributing

Contributions to the design are as welcome as future code. See
[CONTRIBUTING.md](CONTRIBUTING.md) — Apache-2.0 inbound=outbound with DCO
sign-off (`git commit -s`) — and the
[Coding Guidelines](docs/lifecycle/04-coding-guidelines.md) that will govern
implementation. The project's one standing rule: no component stays named
but undesigned, no hot path ships unbudgeted, and no degradation is silent.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 Jagadeesh Chandra Muddana.
