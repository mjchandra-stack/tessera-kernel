<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Composition And Self-Hosting

## Purpose

`01-sequencing-and-mvp.md` sets Stage 1's exit gate as "the OS builds itself on
itself". Every other Stage-1 item — storage, network, POSIX, update — is
downstream of that sentence, and none of them is the reason it is out of reach.
This document says what is, and in what order to remove it.

It exists because the tree has run out of the kind of work it is good at.
Two hundred and forty-seven ledger rows have each added a mechanism and a check
that the mechanism works, and the mechanisms are done: five ports, SMP through
its verification phase, ring-3 drivers, channel IPC, an external pager, a
verified store, a filesystem over a real block device. What has never been done
once is **run them at the same time, in one system, without the kernel
arranging it.**

The second subject here is the interface surface, and it is in this document
rather than its own because it is not a separate project. A toolchain that
targets this system needs the system call surface written down; a second
repository cannot be split off across an ABI that only exists as Rust doc
comments. Documentation is Phase 0 of self-hosting, not an errand beside it.

## The Rules

Two sentences decide every phase below.

1. **The kernel's job ends at starting one process.** Which services exist,
   in what order, holding which capabilities, is a decision user space makes,
   and the kernel should have no opinion it is able to express.
   `kernel/boot-checks/src/lib.rs` already states the port half of this rule —
   "A port's `main.rs` is its composition root: it knows a boot protocol, a trap
   frame and an exit mechanism, and nothing else should." What follows is the
   same sentence about the system rather than about the port.

2. **Nothing the system runs comes out of the kernel's own image.** A program
   the linker placed in `.rodata` is a program the kernel cannot tell from
   itself, which is precisely the sentence D146 wrote when it built the verified
   store. The store exists; what it verifies is four synthetic blobs.

A third rule earns its keep for the interface surface specifically: **an
interface not generated from one definition is a description of the past.** The
tree already believes this about wire layouts and has the gates to prove it. It
does not yet believe it about the call surface, and the drift is measurable
below.

## Where The Tree Stands

**Sound.**

- **ISL owns the argument layouts.** 140 `@abi` structs across 27 schemas, and
  all 29 `decode_*_args` functions in `kernel/kcore/src/syscall.rs` decode
  through generated `WireDecode` bindings (D24, closed by D54). No phase below
  needs to relitigate the wire format.
- **The store verifies before it reads** (D146): a measurement, an anchor that
  is kernel source rather than build output — because a build that emitted both
  the container and the anchor would authorize whatever it happened to produce —
  and anti-rollback refusal, with two images that exist to be refused for
  different reasons.
- **The filesystem is real.** `api/ext2` is checked against images `mke2fs`
  produced, and `userspace/fs-service` reads them over the block service.
  `claim fs.read` is not a mock of a filesystem; it is a filesystem.
- **`kernel/boot-checks` exists, and for the right reason** — two ports each
  carrying a copy of one check is two things that can drift into disagreeing
  about what passed.

**Decayed.**

- **`syscall_abi.isl` declares 6 calls of 50.** Its header says the bindings are
  "ready to wire when user-mode ABI stabilizes" — true when six was the whole
  set, and false for the forty-four that arrived since. The real reference for
  the call surface is 209 lines of doc comment on `SyscallNumber`: argument
  registers, return values, the required right for nineteen of them, and the
  ledger row explaining each gap. It is good documentation, and it is readable
  only from inside the kernel by someone who already has the source.
- **`docs/api/01` is a design document being read as a reference.** It describes
  about twenty syscall families, several of which — virtualization, I/O queues,
  verified programs — nothing implements, and it marks none of them. A reader
  cannot tell which of the twenty exist.
- **The doc backend was specified and never written.** `docs/api/03` lists
  reference documentation among the artifacts the toolchain generates from one
  schema. `api/isl/src/` contains `codegen_rust.rs` and `codegen_fuzz.rs`.
- **`userspace/roottask` did not become what its header says it is.** It calls
  itself "the seed the component manager grows from". It is 167 lines and its
  body is `global_asm!`. The component manager grew somewhere else — inside
  `kernel/kernel/src/main.rs`.

**Absent.**

- Any program image that is not linked into a kernel. Every ring-3 ELF reaches
  the machine through `tessera_embedded_elf`, and so does the verified store
  itself, as the symbol `SYSTEM_STORE`.
- A user-space process that starts another user-space process outside a demo.
- TCP and UDP — no occurrence of either in any `.rs` file in the tree. The one
  place a protocol above the link layer is parsed at all is
  `kernel/virtio/src/arp.rs`, which exists to prove a NIC round trip.
- A libc, a shell, and a compiler that runs on the machine.

**And the measurement that makes the shape plain.** The five kernel *binary*
crates are 43,366 lines against 24,798 for all 32 user-space components. Two
thirds of everything written to demonstrate a userland lives in the kernel.
`kernel/kernel/src/main.rs` is 11,515 lines and 24 `_demo` functions;
`kernel-aarch64` is 22,532 lines across 33 demo modules. Each demo builds a
world, runs one exchange, prints a claim, and tears the world down — 141 markers
in 40 groups, run by 27 boot checks. Every one of them passes. **No two of them
have ever been true at the same instant.**

That is not an accident and it was not wrong. Proving one mechanism at a time
against a check that fails without it is why the ledger has 247 real entries
instead of twelve aspirational ones. It has simply reached the end of what it
can prove: composition is the property that no single-mechanism check can see.

## Phase 0 — One Interface Surface

No composition work. The goal is that the system call surface can be handed to
somebody who does not have the kernel source, and that it cannot silently stop
being true — the same trade Phase 0 of the SMP plan made, where the harness came
before the mechanism.

- **Extend `syscall_abi.isl` to all 50 calls**, carrying what the Rust doc
  comments carry: the ordinal, the argument struct where there is one, the
  registers where there is not, the return value, and the required right. This
  is the rest of D24 — the layouts moved in D54 and the call surface did not.
- **Annotate status in the schema.** `@status(implemented | designed |
  deferred)` and `@since`, so a generated page can say what exists. Prose
  reasoning stays in the ledger and the page links to it rather than copying it;
  a schema is a poor place for an argument.
- **Write `codegen_docs.rs`.** One backend beside `codegen_rust.rs`, and it
  covers the other 31 schemas for free — every user↔user protocol
  (`block_driver`, `fs_service`, `power_manager`, `usb_host`, and the rest)
  gets a reference page from a definition that is already conformance-gated.
  That is the argument for doing this in ISL rather than by hand: it is not
  fifty syscalls of work, it is the whole interface surface.
- **Gate the three against each other**, in `tools/checks`, in the shape of
  `ledger.rs` and `inventory.rs`: every `SyscallNumber` variant has an ISL entry
  at the same ordinal with a non-empty doc, and every family in `docs/api/01`
  carries an explicit status. This is the item that matters. Ungated, the
  surface will drift back within three milestones, which is exactly what it did
  between D54 and here.
- **Separate design from reference, out loud.** `docs/api/01` stays normative
  and stays free to describe what does not exist — that is its job. The
  generated reference describes only what does. Today they are one document,
  which is why it can be trusted as neither.
- **Publish rustdoc.** `cargo doc` appears in no script in `tools/ci/`. The
  `karch` traits and the `kcore` modules are documented to a standard most
  kernels never reach, and none of it is readable without the tree.

**Done when** a syscall cannot be added without an ISL entry and a doc, the
reference is generated rather than written, and every family in `docs/api/01`
says whether it is real.

## Phase 1 — The System Starts Itself

Architecture-neutral, and the load-bearing phase. Nothing here is a new
mechanism; every syscall it needs has existed since D42.

- **`roottask` becomes a compiled Rust program** rather than a hand-written
  assembly blob — the same step `blk-driver` took in D80 and for the same
  reason: an assembly demo cannot grow, and this one has to.
- **It starts the device manager, which binds drivers, which serve their
  classes.** The sequence exists today, as `device_manager_demo`,
  `driver_host_demo`, and `component_manager_demo`, written three times in
  kernel code. Phase 1 writes it once in user code.
- **Capabilities are handed down, not seeded.** Each service receives exactly
  the handles its parent chose to give it. The kernel seeds the root task and
  nothing else, which is the first time the capability model will have been
  load-bearing rather than demonstrated.
- **A demo dies for every step that lands.** This is the phase's real
  discipline. Keeping `fs_service_demo` alive after the filesystem is reachable
  through the composed path means maintaining two systems and gating the wrong
  one.

**Done when** a boot check asserts against a system the kernel did not
assemble — and its inversion is available for free, because a check that still
passes with the root task removed is measuring the demos it was supposed to
replace.

## Phase 2 — A Program Comes From Storage

The rule-2 phase, and the one whose mechanism is already built.

- **Program images move into the verified store.** The store measures, refuses
  a rolled-back version, and checks against an anchor in kernel source. It is
  applied today to four blobs that `mkstore synth --seed` generated. Applying it
  to the artifacts that actually run is not new code; it is the store finally
  carrying its subject.
- **Then the store itself stops being a linked symbol.** `SYSTEM_STORE` is
  embedded by `tessera_embedded_elf` like everything else. Once the block path
  is composed, the container is read from the device it was always meant to
  come from.
- **`exec` from the filesystem.** The ELF loader takes bytes from `fs-service`
  instead of from `.rodata`. This is the single capability the rest of Stage 1
  is blocked on: no self-hosting without running a program that was written to
  disk by the program before it.

**Done when** the kernel image contains no program it did not itself execute,
and a binary placed on the ext2 image by the build runs without being linked to
anything.

## Phase 3 — The Network Is A Service

- IPv4 and IPv6, UDP, then TCP, in user space, over the existing NIC driver.
  `userspace/net-driver` moves packets today and `net-client` proves an ARP
  round trip; everything above the link layer is unwritten.
- The socket surface is an ISL protocol like every other service boundary, and
  gets its reference page from Phase 0 at no cost.
- **The budget question is asked here, not after.** `docs/architecture/03`
  binds the IPC path; a stack that crosses a channel per packet needs its number
  measured while it is still cheap to change the shape.

**Done when** the machine completes a TCP connection to the host and the
per-packet cost is on the record.

## Phase 4 — POSIX, And The Second Repository

The POSIX tier is where the split belongs, and this phase states the condition
rather than a date.

**The tier.** `docs/api/04` tier 1 — source compatibility sufficient to build
the toolchain, the shell, and core utilities. A libc over the native syscalls,
not an emulation layer.

**The split rule.** A repository boundary is affordable exactly when the
interface across it is frozen, generated, and gated. Phase 0 is that condition,
which is why it is Phase 0. Splitting before it means every ABI change becomes a
two-repository dance during the period when the ABI changes weekly.

**What splits, and what does not.**

- **Splits: the POSIX layer, the libc, and the ported toolchain.** Not for
  repository hygiene — because it is a different discipline on a different
  cadence, and mixing "port other people's C until autoconf stops complaining"
  into a tree whose culture is "every claim ships with an inversion that fails"
  will either corrupt the culture or crush the port.
- **Stays: drivers and services.** They are kernel-adjacent, they change with
  the kernel, and the ability to change both sides in one commit is worth more
  than the tidiness of separating them.

**The intermediate step, and it is available now.** `userspace/uabi` is 275
lines and is already the only thing a user program is supposed to know about the
kernel. Make that enforceable — a gate in `tools/checks`, in the shape of the
package gate that already walks `//:all_srcs` — and prove it by building all 32
user-space components with the kernel tree absent. That is most of the value of
a split, at none of the cost, and it is the honest test of whether the boundary
is real.

**Done when** the user-space tree builds against a published ABI artifact with
no path into `kernel/`.

## Phase 5 — Self-Hosting

The Stage 1 exit gate, and by this point a consequence rather than a project:
the compiler runs on the machine, reads sources from the filesystem, writes
objects back to it, and produces a kernel image the machine can boot.

**Done when** an image built by the system boots the system.

## What This Plan Is Likely To Get Wrong

Stated in advance, because the SMP plan's most useful section was the one
admitting which of its predictions were wrong.

- **Phase 1 is estimated as composition and will turn out to be capability
  plumbing.** Every demo today gets its handles by being kernel code. The first
  service that has to receive one it was not seeded with is where the model gets
  tested, and the tree has never once passed a capability down two levels.
- **Deleting the demos will be resisted, and should not be.** Each is a passing
  check and the temptation is to keep both. Two systems means the composed one
  is the untested one, which is the failure this plan exists to prevent.
- **"The kernel binary shrinks" is a prediction, not a plan.** D231 tried a
  restructuring of this kind and it cost 12 KiB *less* rather than 428 KiB more,
  in the opposite direction from the estimate. Measure the image at each phase
  and record the number rather than the intention.
- **Phase 0 may find that ISL cannot express the call surface** — a syscall
  taking scalars in registers is not a struct, and eighteen of the fifty do
  that, `MapDevice` and `PortBind` among them.
  If the schema has to grow a construct for it, that is a language change with
  the evolution rules of `docs/api/03` attached, and it is better found in
  Phase 0 than in Phase 4 when a toolchain depends on the output.
- **The network stack is the item most likely to be underestimated by a
  multiple.** It is listed as one phase because it is one dependency, not
  because it is one milestone's work.

## Out Of Scope

- The compositor, the audio graph, and anything with a display. Stage 3.
- The native copy-on-write filesystem. It ships when it beats ext2 in test,
  and Phase 2 needs a filesystem rather than the final one.
- Bare-metal R1 measurement. Still the one outstanding Stage-0 exit criterion
  (D56), still gated on hardware rather than on anything here.
- Reducing the port count. Five architectures is what makes a composition bug
  distinguishable from an architecture bug, and Phase 1 will need that.

## Ledger

Each phase lands with its own rows, and Phase 1 and Phase 2 each retire rows
rather than adding them. D42 already records the whole of Phase 2 as a
deviation — "the root-task ELF is still a Bazel-built artifact **embedded via a
generated byte array** (v0's 'initrd')... and **no signature/measurement** in
the load path" — alongside the initial-handle-set and startup-message wire
format that Phase 1 is the exit for; D45's boot-installed bootstrap channel is
the same gap seen from the IPC side.

Phase 0's gate is the exception and adds rather than retires: a surface that
cannot drift is a new claim about the tree, and it needs a row of its own
saying what it now enforces.
