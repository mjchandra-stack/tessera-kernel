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
Two hundred and seventy ledger rows have each added a mechanism and a check
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
tree already believed this about wire layouts and had the gates to prove it. It
did not believe it about the call surface, and the drift was measurable — six
calls declared of the fifty that had arrived. Phase 0 closed that, and the rule
is left standing here because it is what ordered the phases, not because the
gap is still open.

## Where The Tree Stands

*Measured at D270. Phases 0 and 1 have both landed since this section was first
written, and it is re-measured here rather than left standing: a state section
two phases out of date is the same defect this document exists to name.*

**Sound.**

- **ISL owns the argument layouts.** 152 `@abi` structs across 27 schemas, and
  all 31 `decode_*_args` functions in `kernel/kcore/src/syscall.rs` decode
  through generated `WireDecode` bindings (D24, closed by D54). No phase below
  needs to relitigate the wire format.
- **ISL owns the call surface too, and a gate holds it there** (D248, Phase 0).
  `api/isl/examples/syscall_abi.isl` declares all 53 calls the kernel answers —
  the register frame, the rights each demands, the result word, and a status
  apiece — and `//tools/checks:surface_test` fails when a `SyscallNumber`
  variant, its schema entry, or a `docs/api/01` family's status stops agreeing
  with the others.
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
- **The root task composes the system on all five machines** (D249-D264,
  Phase 1). `userspace/roottask` is 1,299 lines of compiled Rust: it creates its
  own channels, walks a real ELF, grants capabilities its children hold, and
  supervises a service to a clean start.

**Still decayed.**

Every bullet this heading carried was closed by the two phases below — the
schema, the family statuses, the doc backend, and the root task — which is an
argument for the ordering rather than a reason to drop the heading. What is
left is what D248 left, and that row named both:

- **The reference is generated, gated, and published nowhere.**
  `tools/ci/docs.sh` builds the ISL reference — 7,210 lines across 32 pages, of
  which the syscall surface is 1,085 — and `cargo doc` beside it on every run,
  and drops both. Phase 0's stated purpose was that the surface can be handed
  to somebody who does not have the kernel source. It can be generated for
  them; it cannot yet be fetched by them.
- **The gate checks a call's name and number, not its argument shapes.**
  Writing the surface down found `HandleDuplicate` and `PageSupply` read as
  registers by the shared dispatcher (`kcore::dispatch`, D79) and as `@abi`
  argument structs by the x86-64 handler that predates it. D248 recorded the
  divergence rather than resolving it, because resolving it is a change to a
  boot check.

**Absent.**

- Any program image that is not linked into a kernel. Every ring-3 ELF reaches
  the machine through `tessera_embedded_elf`, and so does the verified store
  itself, as the symbol `SYSTEM_STORE`. Phase 2 is the whole of this bullet.
- TCP and UDP — no occurrence of either in any `.rs` file in the tree. The one
  place a protocol above the link layer is parsed at all is
  `kernel/virtio/src/arp.rs`, which exists to prove a NIC round trip.
- A libc, a shell, and a compiler that runs on the machine.

**And the measurement that makes the shape plain.** The five kernel *binary*
crates are 46,721 lines against 26,424 for all 34 user-space components. Two
thirds of everything written to demonstrate a userland still lives in the
kernel. The demos that are the bulk of it have moved without going: D196 and
D265-D267 split every composition root into modules, so
`kernel/kernel/src/main.rs` is 1,691 lines rather than the 11,515 this section
first recorded, and `kernel-aarch64`'s 23,446 lines are spread across 37
modules beside its own `main.rs`. Each still builds a world, runs one exchange,
prints a claim, and tears the world down — 147 markers in 40 groups, run by 27
boot checks. Every one of them passes. **Phase 1 was the first time any two of
them were true at the same instant**, and it converted five demos into a
composed path that makes the same claims. The other forty-odd groups still
stand alone.

That is not an accident and it was not wrong. Proving one mechanism at a time
against a check that fails without it is why the ledger has 270 real entries
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

**Done** (`build/README.md`, D248). All six bullets landed. `syscall_abi.isl`
declared 6 calls of the 50 that had arrived and now declares all of them, each
with a register frame, a result word and a `@status` — and it carries **53**
today rather than fifty, because Phase 1 added `PortCreate`, `PortBind` and
`DeviceIrqBind` and the gate would not let them in without an entry apiece.
That is the phase working: the number in the bullet above went out of date the
way it is supposed to, by the schema moving with the kernel instead of behind
it. `codegen_docs.rs` is the third backend beside `codegen_rust.rs` and
`codegen_fuzz.rs`, and it did cover the other 31 schemas for free — 7,210 lines
across 32 pages, of which the syscall surface is 1,085, and **not one of the
other schemas was edited to gain a doc**, because a `//` block above a
declaration was already how every one of them was written. `docs/api/01` opens
each of its 19 families with a status: 2 implemented, 7 partial, 10 designed.

**The gate is the item that mattered, and it needed a word the schema does
not.** `//tools/checks:surface_test` holds four agreements, of which the first —
every `SyscallNumber` variant is a `syscall` at the same number with a
description, **and the reverse** — is what makes adding a call without
documenting it impossible rather than discouraged. The family vocabulary needed
a fourth word, `partial`: "Memory" lists twenty operations of which thirteen
exist, and a family forced to choose between implemented and designed would
have to lie either way.

**The last section's prediction came true, and was cheap where it was
predicted to be.** ISL could not express the call surface as it stood. A syscall
is a trap number, a register frame and one result word, and spelling that as a
`protocol` method would put a response payload where there is a result word and
a channel where there is a trap — so the language grew a `syscall` declaration,
which `docs/api/03` now specifies first. That is the language change the
prediction named, arriving in Phase 0 rather than in Phase 4 with a toolchain
already depending on the output, which is the whole reason this phase is
numbered zero.

**Two things the phase did not do**, both standing on D248's own exit criterion
and both restated under "Still decayed" above: the generated reference and
`cargo doc` are built in the continuous gate and published nowhere, and the gate
checks a call's name and number but not its argument shapes — which is why
`HandleDuplicate` and `PageSupply` are recorded as having two argument forms in
one tree rather than reduced to one.

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

**Done** (`build/README.md`, D264). All five machines run one root task from one
source, on one `kcore::loader`: it creates its own channels, walks a real ELF,
grants capabilities its children hold, supervises a service to a clean start and
gives up on one that never comes up. The kernel seeds a job, and on the machines
that have them a bus and a device, and nothing else.

The inversion was **run, not assumed**. Removing the root task from all five
images fails all five boots — four on the missing `roottask.channel-created`
claim and x86-64 on the verdict itself.

**The preamble above is wrong, and it is the larger of two corrections.**
"Nothing here is a new mechanism; every syscall it needs has existed since D42"
was the estimate. The phase built `ProcessGrant` (D249), an asynchronous
`ProcessStart` with `ProcessWait` (D250), `ChannelCreate`, `PortCreate` and
`PortBind` reachable from ring 3 (D253, D254), `DeviceIrqBind` (D255), and a
32-bit ELF class and syscall ABI width (D258, D259, D260) — six calls and two
ABI extensions, against a preamble that promised none. **The last section
predicted exactly this**: *"Phase 1 is estimated as composition and will turn
out to be capability plumbing."* D249 is `ProcessGrant`, and it is the phase's
first landing. The estimate was wrong in the direction the plan said it would
be wrong, which is the most a plan gets to be right about.

**What the phase retired**, which is the fourth bullet's discipline actually
running: `component_manager_demo`, `cm_budget_selftest` and `cm_reclaim_stress`
(D250), `driver_bind_check` (D256), and `compiled_program_check` (D262) — five,
each replaced by a composed path making the same claim, none kept alongside its
replacement.

**The second bullet was mis-scoped, and this is the other correction.** It
names `device_manager_demo`, `driver_host_demo` and `component_manager_demo` as
"the sequence, written three times in kernel code". That is true of the third,
which is gone (D250), and of the composition half of the first. It is not true
of the rest: the two survivors on x86-64 are the port's **only** ring-3 device
I/O and ring-3 interrupt delivery — a capability-gated port-I/O path with its
refusal, a real IRQ delivered to a ring-3 driver, and a client whose
`ChannelCall` that driver serves by driving hardware. AArch64's
`bring_up_device_host` and `relay_pair` are not demos at all but spawn helpers,
shared by checks that claim a resident driver host over real virtio, a
filesystem, a data-path budget and firmware loading.

None of those claims is reachable through the composed path yet, so retiring
them would delete coverage rather than stop maintaining two systems — which is
the opposite of what the fourth bullet asks. They go when the composed path
reaches what they assert, and Phase 3's driver work is where that happens.

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

**Started** (`build/README.md`, D271-D272). `//api/net` is the first thing here
that speaks a protocol above the link because something needs it carried:
Ethernet, IPv4, UDP, and enough DHCP to ask for a lease, host-tested against
RFC 1071's worked example rather than against itself, and on the fuzz gate's
hand-written-parser list because a frame is the one input nobody in this
machine wrote. The machine now sends a 290-byte datagram and QEMU's own DHCP
server answers it with a lease.

**The first bullet cost more than one milestone, and the plan said it would.**
"IPv4 and IPv6, UDP, then TCP, in user space, over the existing NIC driver"
reads as one step and the first half of it took two, because *"over the existing
NIC driver"* turned out not to be possible: the network class could transmit 64
bytes inline, `MAX_INLINE_BYTES` caps a whole message at 256 to hold budget B3,
and 42 bytes of headers leave 22 bytes of payload. The receive direction had
carried frames out of line since D131 and the transmit direction never had,
because ARP fit. D272 added `TransmitBuffer` for it. **The last section's
estimate was right about which item would be underestimated and wrong about
where the cost sat** — not in the protocol code, which is the part that looked
hard, but in the contract underneath it.

**The budget question is now askable, which is the third bullet's whole
point.** `TRANSFERRED` is forced rather than chosen: `SHARED_FOR_CALL` is what
a transmit wants and `TransferMode::SHARE` is still refused (D131), so a caller
creates, transfers and loses a memory object per frame. That is the per-packet
cost to measure before the shape sets.

**The second bullet is done, and it cost what the bullet said it would**
(D273). `flow_service.isl` is the socket surface — `Bind`, `SendTo`,
`RecvFrom`, `Close` — and it did get its reference page from Phase 0 at no
cost: 34 pages from 33 schemas, one `islc emit-docs` run, no work. Its fuzz
target is generated because it declares `@abi`, and its conformance test pins
the ordinals TCP is holding as well as the four in use. Nothing implements it
yet, which is where `network_driver.isl` sat between being written and D150.

**What writing it down settled.** Three places this tree cannot yet do what
`docs/network/01` describes are now schema comments rather than things a reader
would find out by implementing: there is no data ring, because a ring is a
shared buffer and `SHARE` is refused; there is no port authority, because there
is no namespace broker; and a receive hands back a different object than it was
given, because a service cannot write into a buffer it holds `READ` on. The
first of those is the per-packet cost the third bullet asks about, and it now
has a contract to be measured against.

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

**The intermediate step, and it is available now.** `userspace/uabi` is 550
lines — it doubled across Phase 1, which is what a boundary carrying real
traffic does — and is already the only thing a user program is supposed to know
about the kernel. Make that enforceable — a gate in `tools/checks`, in the shape
of the package gate that already walks `//:all_srcs` — and prove it by building
all 34 user-space components with the kernel tree absent. That is most of the
value of a split, at none of the cost, and it is the honest test of whether the
boundary is real.

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
  **Right (D249).** The phase's first landing is `ProcessGrant`, a syscall the
  phase's own preamble said it would not need, and five more followed it.
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
  **Right, and it cost what the placement was meant to make it cost (D248).**
  ISL grew a `syscall` declaration — `argN: T` carries a value and
  `argN: SomeArgs` carries a user pointer, which is the whole difference — and
  `docs/api/03` specifies it first. Sixteen of the fifty-three read scalars out
  of registers today.
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

Each phase lands with its own rows, and Phase 1 and Phase 2 were expected to
retire rows rather than add them.

**Phase 1 did the opposite, and this is the third thing it got wrong.** Sixteen
new rows, D249 through D264, and what it retired was five demos rather than a
ledger entry. Both rows it was named as the exit for are now amended rather
than closed, because reading them item by item found each to be a list and not
a single gap. **D42**: the ring-3 ELF parser (D249/D251, widened to ELF32 by
D258) and the initial-handle-set / startup-message / bootstrap-channel wire
format (D249, D261, D253) are struck; shared memory objects and cross-process
map are one gap under two names and still open, `TransferMode::SHARE` being
decoded and then refused. **D45**: four of five v0 deviations are struck —
ring-3 `ChannelCreate` (D253), ring-3 `ChannelSend` (D150),
reply-into-user-buffer (D79) and the single round trip (D82). What is left is
channel teardown from ring 3, and it is left because looking closed and being
closed came apart: `HandleClose` has branches for memory objects and devices
and none for endpoints, so it never reaches `close_endpoint` and never wakes a
blocked peer. That still waits for the holder to exit.

**What is still D42, and is the whole of Phase 2:** "the root-task ELF is still
a Bazel-built artifact **embedded via a generated byte array** (v0's
'initrd')... and **no signature/measurement** in the load path". That sentence
has been the accurate description of the load path since M14 and still is.

Phase 0's gate was the exception and added rather than retired, as expected: a
surface that cannot drift is a new claim about the tree, and D248 is the row
that says what it now enforces.
