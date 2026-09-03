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

*Measured at D300. Phases 0, 1, 2, 3 and 4 have all landed since this section
was first written, and it is re-measured here rather than left standing: a
state section out of date by a phase is the same defect this document exists
to name.*

*It was left standing once, and the correction is worth keeping. The note here
said the section had been re-measured at D270 "rather than left standing", and
then three more phases landed under it without it being touched — so a reader
at D300 was told TCP appeared in no `.rs` file in the tree, by a paragraph
whose own rule said that could not happen. **A re-measurement is not a
promise that the next one will happen**, and this note is not one either —
what would be is a gate, and there is none for a prose paragraph. What follows
is what the tree measured at D300, by counting the tree rather than by reading
the phases below.*

**Sound.**

- **ISL owns the argument layouts.** 164 `@abi` structs across 28 of the 33
  schemas, and all 32 `decode_*_args` functions in `kernel/kcore/src/syscall.rs`
  decode through generated `WireDecode` bindings (D24, closed by D54). No phase
  below needs to relitigate the wire format.
- **ISL owns the call surface too, and a gate holds it there** (D248, Phase 0).
  `api/isl/examples/syscall_abi.isl` declares all **55** calls the kernel
  answers — the register frame, the rights each demands, the result word, and a
  status apiece — and `//tools/checks:surface_test` fails when a
  `SyscallNumber` variant, its schema entry, its argument frame, its port's
  handler, or a `docs/api/01` family's status stops agreeing with the others.
  **53 in Phase 0's close, 55 now**: `ClockRead` (D281) and
  `SystemStoreInstall` (D291) each arrived with a schema entry because the gate
  admits no other kind of arrival. That is the number going out of date the way
  the phase intended, and it is the one number in this section a reader does not
  have to trust — the gate fails if it is wrong.
- **The store verifies before it reads** (D146): a measurement, an anchor that
  is kernel source rather than build output — because a build that emitted both
  the container and the anchor would authorize whatever it happened to produce —
  and anti-rollback refusal, with two images that exist to be refused for
  different reasons. Phase 2 gave an anchor a second form (D289): the firmware
  container keeps its pinned digest, and the program container is signed,
  because its contents are whatever the build just compiled. **The signing key
  is a development key in the tree** — `PROGRAM_STORE_KEY` in
  `build/rules/components.bzl`, its public half in `kernel/kcore/src/store.rs`
  — so what a program image is vouched for by today is the build that made it,
  not a party outside it. Both files say so; this section says it too, because
  "signed" is a word a reader completes on their own.
- **The filesystem is real.** `api/ext2` is checked against images `mke2fs`
  produced, and `userspace/fs-service` reads them over the block service.
  `claim fs.read` is not a mock of a filesystem; it is a filesystem.
- **`kernel/boot-checks` exists, and for the right reason** — two ports each
  carrying a copy of one check is two things that can drift into disagreeing
  about what passed.
- **The root task composes the system on all five machines** (D249-D264,
  Phase 1). `userspace/roottask` is 1,104 lines of compiled Rust: it creates its
  own channels, walks a real ELF, grants capabilities its children hold, and
  supervises a service to a clean start. It was 1,299 when this section first
  recorded it and is smaller now without doing less — D294 moved the ELF parse
  out to `//userspace/elfload`, where `fs-client` shares it and the malformed
  images it refuses are host tests rather than a hundred lines of header
  arithmetic no test could reach.
- **A program runs that no kernel image carries** (D289-D294, Phase 2).
  `userspace/disk-program` is on the ext2 volume and in no image; `fs-client`
  reads `/program.elf` back through the composed filesystem path, creates a
  process, maps its segments and starts it.
- **The network is a service** (D271-D288, Phase 3). `api/net` speaks IPv4,
  IPv6, UDP and TCP against RFC worked examples in 54 host tests, and
  `userspace/net-stack` serves `flow_service.isl` to a client holding one
  channel endpoint and nothing else. The per-datagram cost is gated, not
  merely recorded: `FLOW_DATAGRAM_PATH_CEILING` is 115 and may only fall.
- **A user program's only path to the kernel is the ABI, and a gate holds it
  there** (D295-D296, Phase 4). `//api/abi:abi_bundle` is the published
  artifact, and `//userspace/...` builds to completion with `kernel/` deleted
  and `api/isl` reduced to the artifact.

**Still decayed.**

Every bullet this heading has ever carried is struck, which is an argument for
the ordering rather than a reason to drop the heading. **What is decayed now is
not a mechanism — it is an item of this plan's own discipline that no phase
owns.** It is stated here rather than in a phase because that is precisely its
problem:

- **The demo-retirement discipline has no owner.** Phase 1's fourth bullet is
  the plan's stated discipline, and Phase 1 ran it: five demos retired, none
  kept beside its replacement. What it could not retire it deferred — *"They go
  when the composed path reaches what they assert, and Phase 3's driver work is
  where that happens."* Phase 3 closed saying it had not happened, and deferred
  it again: *"that is Phase 2's work and the block class's, not this one's."*
  Phase 2 closed without doing it. **Both handoffs were correct** — a check is
  retired when the composed path claims what it claims, and no path built since
  has reached the block class, firmware loading or ring-3 port I/O — and two
  correct handoffs into a phase that then closed leaves an item nobody holds.
  The measurement below is what that costs. **Whoever opens the next phase
  inherits this bullet**, and what it needs is a composed path over the block
  class: the shape Phase 3 built for the network class and did not build twice.

And the two D248 left, both closed:

- ~~**The reference is generated, gated, and published nowhere.**~~ Closed by
  D296. `//api/abi:abi_bundle` is the artifact: the schemas, their compiled IR,
  the reference pages, the generated bindings *and a build file declaring
  them*, the wire runtime, `uabi`, a version and a manifest. What made it
  publishing rather than packaging is that the user-space tree builds against
  it with `api/isl` reduced to the artifact and `kernel/` deleted.
- ~~**The gate checks a call's name and number, not its argument shapes.**~~
  Closed by D298. `surface_test` holds a **frame agreement**: every handler
  reads exactly the registers `syscall_abi.isl` declares. `HandleDuplicate` and
  `PageSupply` are converged onto the schema, and the gate found five more of
  the same class on the way — including a `PortWait` that ignored the register
  a `PortEventRecord` goes in, reached by a blob that still had `PortBind`'s
  source id in it.

**Absent.**

Two of the three bullets this heading carried are struck, and both by Phase 2
and Phase 3 rather than by being reworded:

- ~~Any program image that is not linked into a kernel.~~ Closed by D294. What
  is left is narrower and is a size decision rather than a capability gap: the
  **program store** is still a linked symbol, `PROGRAM_STORE`, on all five
  ports. The **system store** is off a medium on **aarch64 only** — the other
  four still reference `system_store_image::SYSTEM_STORE` from their `main.rs`.
  Phase 2's second bullet is met on the port D292 names and on no other, which
  its close records in a parenthetical ("this port's list") that is easy to read
  past.
- ~~TCP and UDP — no occurrence of either in any `.rs` file in the tree.~~
  Closed by D271-D285. `api/net` is the transport and `userspace/net-stack`
  serves it. **TCP is IPv4 only**, and nothing here accepts a connection it did
  not open.
- A libc, a shell, and a compiler that runs on the machine. `grep -li
  'libc\|posix'` across `userspace/` and `api/` matches nothing. **This bullet
  is the whole of what remains**, and Phase 4 closed with its "Done when" met
  and its named subject — `docs/api/04` tier 1, a libc over the native syscalls
  — unstarted, because the criterion was written against the intermediate step
  that phase also describes. Phase 5 is downstream of every word of it.

**And the measurement that makes the shape plain.** The five kernel *binary*
crates are **47,441** lines against **31,286** for all **38** user-space
components. Three fifths of everything written to demonstrate a userland still
lives in the kernel. The demos that are the bulk of it have moved without
going: D196 and D265-D267 split every composition root into modules, so
`kernel/kernel-x86_64/src/main.rs` is 1,700 lines rather than the 11,515 this section
first recorded, and `kernel-aarch64`'s 24,347 lines are spread across 38
modules beside its own `main.rs`. Each still builds a world, runs one exchange,
prints a claim, and tears the world down — **155 markers in 42 groups**, run by
27 boot checks. Every one of them passes: `bazel test //... --config=ci` is 150
of 150 at D300.

**The direction of that number is the finding.** At D270 it was 46,721 against
26,424 in 34 components, and the three phases that have landed since moved it
from two thirds to three fifths — by adding 4,862 lines of user space, while
the kernel binaries **grew by 720**. Phase 1 was the first time any two of
these claims were true at the same instant, and it converted five demos into a
composed path; Phases 2, 3 and 4 added composed paths beside the standing ones
and retired nothing. The forty-odd groups that stood alone still stand alone.
**The plan's own prediction — "two systems means the composed one is the
untested one" — is the sentence this measurement is now about**, and the
bullet under "Still decayed" is who is supposed to act on it.

That is not an accident and it was not wrong. Proving one mechanism at a time
against a check that fails without it is why the ledger has 300 real entries
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
one tree rather than reduced to one. *Both were closed in Phase 4 — the
reference is published by D296, the argument shapes gated by D298 — which is
what the phase ordering was for: a surface with a gate behind it is what made
publishing it worth doing.*

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

*Phase 3 closed without this happening — see its Done block. The composed path
it built claims the network class and nothing else, so the survivors are still
there and still earning their place.*

*And D299 makes the distinction the fourth bullet was really about. What cost
something to maintain was never the demos: it was that each had installed a
**syscall handler** of its own — sixteen registrations over eight functions,
where AArch64 has one — so this port had sixteen partial answers to a surface
that may have one. That is where every divergence D298 found had lived. The
handlers went; the demos stayed, because their claims are still the only ones
this port makes about ring-3 device I/O and interrupt delivery. **Two systems
was the defect, not two demos.***

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

**Started** (`build/README.md`, D289–D291), and the first bullet had a fork in
it the bullet does not name. The store's integrity was a digest checked into
kernel source, which works because its blobs are generated from fixed seeds and
never change; program images change on every userspace edit, so that constant
would be stale on every build. An anchor is now either a measurement or a
**key** (D289) — the format's `anchor_id` was documented as a key identifier
from the start — and the two are used where each still holds: the firmware
container keeps its pinned digest, and the program container is signed.

**The programs moved** (D290). One signed container per machine holds every
ring-3 program that machine starts, and the generated accessors read from it by
name. The bytes are still in the image, so this is not the second bullet; what
changed is that a program the kernel starts is now one something vouched for.

**And the second bullet is half met** (D291). `SystemStoreInstall` lets a
component offer the kernel a container it read from a medium; the kernel
measures it against anchors in its own source, copies it before measuring, and
installs it once. The ring3-host boot proves the whole chain — the container is
on the disk, `blk-client` reads it through the composed block path, and the
firmware check later in the same boot uses that store rather than the image's.

**And the second bullet is met** (D292). The image carries no container: the
dependency is off this port's list, the accessor is gone, and every store this
kernel sees came off a medium. The claims moved with it — `store.ok`,
`store.refused` and the firmware policy claims are made in the boot that has a
device, against the container a component read from it, which is something they
could not say while the kernel carried their subject. A boot with no medium
reports that it has no store and skips.

**What is left of Phase 2 is the third bullet alone.** The *program* store is
still linked into the image; `exec` from the filesystem is what removes it, and
it is the capability the sequencing document says the rest of Stage 1 waits on.

**And it has started** (D293). `userspace/disk-program` is on the ext2 volume
and in no image, and `fs-client` reads it back through the composed filesystem
path and establishes that what came off is a loadable image for this machine.

**And it is done** (D294). The composition it needed was exactly the one named:
the filesystem check seeds its client a job, publishes the same loader seam the
root-task check publishes, and `fs-client` reads `/program.elf`, creates a
process, maps its segments and starts it. Nothing new was invented — the seam
was never the root task's, only its use of it was.

Two things the composition taught, both general. **A paged file has to be
touched before the kernel is asked to read it**: a loader hands the kernel
addresses in its own space, the kernel copies at EL1, and a missing page there
is a kernel abort rather than a request to a pager. And **the ELF parse became
testable by moving**, not by being wrapped in a test — a `no_main` ring-3 binary
has no host test target, so a hundred lines of header arithmetic had never been
shown a malformed image; `//userspace/elfload` is shared with the root task and
carries the refusals as tests.

**Phase 2 is closed.** The program store is still linked into the image, which
is now a size decision rather than a capability gap: this kernel has run a
program it was not carrying, read off a volume through a filesystem it does not
implement, and the boot check confirms that program's marker is in the ext2
image and absent from the kernel's.

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

**And something serves it** (D275). `userspace/net-stack` is a stack instance:
it speaks the network class to the driver and the flow contract to its client,
and it is the only program in the chain that knows what an IPv4 header looks
like. Four processes, each knowing strictly less than the one below it. The
client holds **one channel endpoint** — no device, no DMA, no port, no Ethernet
constant — and completes a DHCP exchange through it. The phase's title stops
being a heading at this point: the network is a service, and a program reaches
it by asking.

**Two SDK gaps, both found by needing them rather than by review.** There was
no `close`, so a service could not give up a transferred object — the leak D272
had just been bitten by, with no way to avoid it. And `memory_map` asks for
`READ | WRITE`, which is refused for every buffer granted `{READ, MAP}`, so a
receiver of a grant could not map it at all. Both now exist, and the simulator
counts closes so a leak fails a test rather than an unrelated allocation four
calls later.

**The third bullet is answered** (D276). The number is
`obj=5 map=7 close=4 call=8 send=1 recv=18 irq=1 wait=4 all=63` for one
datagram each way plus the four processes' startup, counted at the one place
every EL0 syscall passes through rather than reasoned about from the code.

**It is deliberately not B25.** That budget is a packet rate on R1 hardware,
which nothing under QEMU/TCG can measure (D34/D56), and this exchange waits on
a DHCP server outside the machine besides. What the bullet actually asked for
was the number *"while it is still cheap to change the shape"*, and kernel
round trips per datagram are exact, machine-independent, and a property of the
shape rather than of the silicon.

**Which half is stable was itself a finding.** Across six runs the total moved
— 63 five times, 65 once — and every data-path count was identical. The
variance is the driver's interrupt pump answering the host. So the ratchet is
`obj + map + close + call = 24`, may only fall, and the total is reported
rather than gated.

**And the shape's real cost is now a number rather than an argument:** four
objects, seven mappings, four closes and three channel calls per round trip —
18 data-path syscalls and 32 in all — measured by running the same code at one,
two and three datagrams and differencing, which came out exactly linear
(D277). That is what `TransferMode::SHARE` being refused (D131) costs a data
path. The shared buffer that would take four objects to one is
`SHARED_FOR_CALL`, blocked on the object table D131 named.

**The receive queue is in** (D277), and it was free: at one datagram the new
shape costs the same 18 data-path syscalls as the blocking one it replaced.
`net-stack` waits on its client and its driver at once rather than on whichever
it happens to want, so a datagram arriving while nobody is asking is held
instead of sitting in a kernel channel until that fills and the driver drops
it. Bounded at four, oldest evicted, and the eviction count is asserted zero
rather than assumed — a stack that drops is allowed to, and one that drops
quietly is not.

**IPv6 is written and not yet run** (D278). `api/net` speaks it — the header,
the RFC 8200 pseudo-header, EUI-64, the multicast MAC mapping, and stateless
DHCPv6 — with 33 host tests and a checksum checked against a separate
implementation, which is what caught a multicast constant written a group
early. `FlowAddress` is sixteen bytes wide, because D273's claim that `family`
and `version` would let v6 *"append rather than renumber"* was wrong: reserving
a discriminant without reserving the space reserves nothing.

**And the round trip completes** (D279): a DHCPv6 Information-Request goes out
over IPv6 and a Reply comes back naming `fec0::3`, through the same contract
and the same stack instance as the v4 exchange.

**The blocker D278 described did not exist.** That row reasoned from a symptom
and concluded that unsolicited Router Advertisements deadlocked the older
`net-class` check. The real cause was `ipv6=on` alone making QEMU disable
*IPv4*, so the guest's ARP went out and nothing answered — invisible in the
serial log and obvious in a packet capture, which is what should have been
reached for first. Reasoning from a symptom named a bug that was not there and
cost a row saying so.

**What the specification actually required, and this tree did not do.**
Neighbour Discovery is not optional: IPv6 has no ARP, so a peer that wants to
unicast a reply first asks who holds the address, and a host that never answers
is a host nothing can reply to. The advertisement then has to carry hop limit
255, because 64 is silently discarded. And a reply correlates on its
transaction id rather than its source port — this peer answers from an
ephemeral one and sends no `SERVERID`, both contrary to RFC 8415.

**And the machine completes a TCP connection** (D280), which is half of this
phase's stated exit. A ring-3 client opens a stream to an echo server the
emulated network runs, sends bytes, reads them back, and closes — over the same
contract that carried the datagrams, because after `Connect` the same `SendTo`
and `RecvFrom` carry stream bytes. The state machine lives in `api/net` and a
whole connection is driven on the host, so its corners are reachable without a
machine.

**What it is not is worth stating plainly.** There is no retransmission timer,
no congestion control, no reassembly, and no window that moves. The first is
not deferred by preference: a ring-3 program here has no clock, so the stack
cannot know an acknowledgement is late. Over a lossless link it moves bytes
correctly; over one that loses a segment it stalls, silently. That is a
connection, not a transport to build a service on, and the distance between
them is a syscall that does not exist yet.

**Done when**, revisited: the connection is made and the per-packet cost is on
the record, so this phase's exit criterion is met as written. The sentence it
was written to mean — a network a service could rely on — is not, and the
honest next step is the clock rather than more protocol.

**The clock now exists** (D281). `ClockRead` returns monotonic nanoseconds on
all five ports, and `net-stack` uses it: a deferred request that waits past its
deadline is answered rather than left hanging, which is the first time anything
here could tell that time had passed. `docs/api/01`'s Time family moves from
*designed* to *partial* — the time page it describes as the fast path is still
unwritten.

**And a receive can now be woken by it** (D282). `ChannelRecvAny` takes a
deadline; the executive carries the port's clock, a parked thread carries the
deadline of the wait it is in, and `run` expires them beside the page-in expiry
that has always been there. A flow bound to a port nothing sends to now gets
`WOULD_BLOCK` instead of silence.

**The first version of that shipped invisible, and the inversions are what
caught it.** Both passed — removing the expiry pass, and discarding the
deadline register outright — because in a healthy run nothing ever times out.
A mechanism no check can fail on is not finished, whatever the suite says.

**And a client can now survive a service that stops** (D283). `ChannelCall`
takes a deadline too, so the bound belongs to whoever is waiting rather than to
whoever they are waiting on — which is the difference that matters, because a
service that has stopped cannot be relied on to be well-behaved about anything,
including its own timeouts. The call is *abandoned* rather than cancelled: the
request was delivered and may still be acted on, so the reply it is owed is
discarded when it comes instead of being handed to the next caller. The leg
that proves it needs nothing broken — the client holds both ends of a channel
and calls on one, which is what a wedged service looks like from the outside.

**And the connection is a transport now** (D284). The retransmission timer is
RFC 6298: the segment is held until it is acknowledged, the round trip is
measured and the timeout derived from it, each miss doubles the next, and a
peer that never answers is given up on in eight seconds rather than waited on
forever. Three departures from the RFCs are made deliberately and stated where
they are made — a 200 ms floor, an eight-second give-up, and the give-up
expressed as a time rather than a count.

**The check needed a black hole, and that was the work.** QEMU's user-mode
network terminates TCP on the host and answers everything it is sent, so a
segment cannot be lost on that wire — `restrict=on` gives silence and kills the
DHCPv6 leg, and an unassigned address's silence depends on the host's routing
table. What works is the guest's own address, which slirp forwards nowhere.
That leg is what made the timer visible: without it, a serve loop that ignored
the connection's deadline passed every check.

**And the send buffer landed** (D285). The connection holds four segments
oldest-first instead of one, an acknowledgement releases the prefix it covers,
a timeout retransmits the front and nothing else, and the peer's advertised
window is read and honoured rather than assumed to be large. What it buys is
the round trip: with one held segment a connection moved one segment per RTT
however fast the link was.

**What it did not buy is the frame.** A segment is still a memory object
created, mapped, handed to the driver and closed — whether it is new, a
retransmission, or a bare acknowledgement. That is the single largest cost in
this path and the only one whose fix is a kernel change rather than a network
one: the shared buffer, still blocked on the object table D131 named.

**And the kernel half of that shared buffer is in** (D286). `SHARE` was the
one mode the ABI defined and the kernel refused; a memory object now records
the set of processes holding it and frees its frames when the last lets go.
The reason D131 deferred it — three ports with no object table — turned out to
be the wrong table: what a shared object needs counted is which processes hold
it, which is known where the object already lives.

**And a frame stops being an object** (D287). The stack shares one region with
the driver at startup; every frame after it is a message naming an offset. The
per-packet number the phase asked for by name falls for the first time since it
was measured — 193 to 133, which is fifteen frames at four syscalls each — and
the sentence the ceiling had made twice is no longer true of the transmit
direction.

The bound is where the interest is. An offset and a length from a client are
exactly how a client names memory outside what it lent, and nothing in ordinary
operation sends a bad one — so the class-conformance probe does, and a driver
without the check reads past its mapping and dies.

**And the receive direction follows** (D288), with the ownership the other way
round: frames arrive by DMA, so the region has to be memory the device can
reach, and the driver creates it and lends the stack a read-only view. Zero-copy
stays zero-copy — the NIC writes into the region and the stack reads the same
bytes. 133 to 115, less than transmit saved because a lent slot has to be given
back, and that `ReleaseFrame` is the price of doing flow control by message
rather than by indices in shared memory.

**Done** (`build/README.md`, D271–D288). All three bullets landed, and the
exit criterion has been met since D280 — the machine completes a TCP connection
to the host, and the per-packet cost is not merely on the record but gated.

**The first bullet, with one limit worth naming.** IPv4, IPv6, UDP and TCP are
in user space over the existing NIC driver: `api/net` is 54 host tests against
RFC worked examples rather than against itself, and `userspace/net-stack` is a
service that speaks all of it. **TCP is IPv4 only.** A v6 stream needs a
neighbour resolved for its unicast destination and this stack resolves none —
`build_udp6_frame` refuses a unicast address for exactly that reason. That is a
gap in the transport, not in the layering, and it is the same gap `Listen` and
`Accept` sit behind at their reserved ordinals: nothing here accepts a
connection it did not open.

**The second bullet cost nothing, which was the prediction.** `flow_service.isl`
is a protocol like every other service boundary and got its reference page from
Phase 0's `codegen_docs.rs` without being edited for it.

**The third bullet is the one that paid.** The number was measured while the
shape was still cheap to change, and then the shape changed twice. Within a
fixed exchange the transmit direction fell four syscalls per frame (D287) and
the receive direction two (D288) — 193 to 133 to 115 — and both were possible
only because the kernel gained `SHARE` (D286), which D131 had deferred on a
reason that turned out to name the wrong table. **A ceiling that had only ever
risen is a ceiling nobody had tested falling.**

**What the number does not mean.** The ceiling ran 42 → 70 → 112 → 115 → 118 →
141 → 193 before it fell, and almost none of that was a datagram getting dearer:
each rise was a leg added — a second datagram, IPv6, TCP, a deadline, a
retransmission, a send buffer — so the totals are not comparable across the
whole history. Only the last two steps compare like with like, because the
exchange did not move under them.

**Two things are true at once about the exit criterion.** As written, it is met.
The sentence it was written to mean — *a network a service could rely on* — is
closer than it was and is not the same claim: there is no congestion control, no
reassembly of out-of-order segments, no receive window that moves, one flow and
one client at a time, and the per-packet **rate** B25 asks for is unmeasurable
here and needs the R1 hardware D56 has been waiting for since Stage 0. Those are
a transport project and a hardware dependency respectively. Neither is this
phase, and **Phase 4 waits on none of them**.

**What is left in the per-packet path is deliberate.** The client's own payload
object per datagram is the flow contract's `transfer handle` — ownership moves,
so the receiver validates memory the sender cannot rewrite. That is the property
the contract is for, not an overhead to remove.

**Two things this phase was expected to do and did not.**

Phase 1's close said the surviving in-kernel demos *"go when the composed path
reaches what they assert, and Phase 3's driver work is where that happens"*.
It did not happen. `bring_up_device_host` and `relay_pair` on AArch64, and the
two x86-64 survivors, are all still there — the flow check composes four ring-3
processes over the network class and asserts nothing about the block device,
firmware loading, or ring-3 port I/O, which is what those checks are for.
Retiring them still means building the composed path that claims what they
claim, and that is Phase 2's work and the block class's, not this one's.

And **the phases were not done in order**: Phase 2 was open when this closed.
A program still came out of `.rodata` rather than off the ext2 image, which is
the capability the rest of Stage 1 is blocked on. Nothing in Phase 3 needed it,
which is why the order held — but the sequencing document's claim is about
Phase 2, and closing this one did not move it.

*Phase 2 closed at D294, six rows after this paragraph was written, and the
paragraph stood in the present tense for those six rows saying a program still
comes out of `.rodata` — two sections of one file disagreeing about one fact.
It is in the past tense now. **A phase's close is a statement about the tree at
that moment**, and the tense is what says so.*

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

**And the intermediate step has landed** (`build/README.md`, D295), with the
finding that a prediction list should have carried: **the boundary was not
almost real, and what breached it was not user-space code reaching for kernel
mechanism.** Nine user-space packages reached into `kernel/`, and every crate
they reached was device logic — a virtio transport, NVMe, xHCI, SDHCI, PL061,
PCIe enumeration, a Device Tree reader. Six of them had no dependencies at all.
They were under `kernel/` because the kernel needed them first, and the layered
view in `docs/architecture/01` had said for as long as it existed that driver
hosts sit *above* the kernel. So the fix was a rename, not a redesign: they are
`drivers/` now, and the one genuine coupling — the Device Tree reader reporting
the kernel's own `MemoryRegion` — became the ports' conversion, which is what
the x86-64 glue already did for Limine's map.

**The gate is a reachability question**, because the edge that actually existed
was two hops long and a `deps`-at-a-time reading would have passed it. And the
proof the paragraph above asked for was run rather than argued: `//userspace/...`
builds to completion in a tree with `kernel/` deleted, and the same command
against the tree one commit earlier fails in analysis.

**Done when** the user-space tree builds against a published ABI artifact with
no path into `kernel/`.

**Done** (`build/README.md`, D295-D296). Both halves, and the second one is
also the half of D248 that had been standing since Phase 0.

**The artifact is 148 files, and the load-bearing one is a `BUILD.bazel`.**
Everything else — 33 schemas, their compiled IR, 8,251 lines of reference,
15,933 lines of generated bindings, the wire runtime, `uabi`, a version, a
manifest — is content somebody could have tarred up at any point in the last
year. What makes it *published* is that `//api/isl:process_abi_bindings`, the
label a program already writes, resolves against the release: `//userspace/...`
builds to completion with `kernel/` deleted and `api/isl` reduced to the
artifact, no schemas and no compiler present. **If a program had to be edited
to build against the published ABI, the published ABI would not be the thing
the program was written against.**

**And the gate is the ABI diff this tree specified and never built.**
`docs/api/03` has said since it was written that schema changes are reviewed as
ABI changes *"with the ABI diff tool operating on compiled schema IR, not
source text, so formatting changes cannot mask semantic ones"*. It exists now,
and it was worth stating that way round: swapping two fields of
`ProcessCreateArgs` moves an offset and fails the gate; rewording the comment
above them changes nothing. A digest over source text gets both wrong.

**And the one thing that was left is closed** (D298). `HandleDuplicate` and
`PageSupply` read what the schema declares, on every port, and a gate holds
every handler to the frame this file writes down. The published surface states
one truth per number.

**What resolving it found is the part worth keeping.** The divergence was not
two argument shapes but two *calls* sharing number 22 — different arguments,
different meanings, and a return value the schema declares none of. And the
gate that closed it immediately found five more, all in the same x86-64 demo
glue, one of them a latent bug: a `PortWait` whose ignored register held a
leftover value a kernel honouring its own ABI would have written a record to.
**A surface nothing checks does not drift in one place at a time.**

## Phase 5 — Self-Hosting

The Stage 1 exit gate: the compiler runs on the machine, reads sources from the
filesystem, writes objects back to it, and produces a kernel image the machine
can boot.

**Done when** an image built by the system boots the system.

**"And by this point a consequence rather than a project" is struck**, and it
is the largest thing this document got wrong. That clause assumed a POSIX tier
would be underneath this phase by the time it was reached, because Phase 4 is
where the tier was scheduled — and Phase 4 closed on its "Done when", which was
written against the intermediate step, with `docs/api/04` tier 1 unstarted.
Measured at D300: `grep -li 'libc\|posix'` across `userspace/` and `api/`
matches nothing, and neither does `global_allocator` anywhere in the tree.
**A phase whose premise is another phase's unfinished subject is a project.**

It is sequenced in `04-self-hosting.md`, which is a separate document for the
reason `02-smp-bring-up-plan.md` is one. What that plan found on measuring:
four of the five things the sentence above names — reading a source off the
volume, writing bytes back durably, loading and running a program off it, and a
published ABI to target — already exist and are gated. The fifth is that no
program on this machine has ever produced a program, and underneath it is that
there is no heap in ring 3 at all.

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
map were one gap under two names and open at Phase 1's close, with
`TransferMode::SHARE` decoded and then refused. *That is struck too, by D286:
a memory object records the set of processes holding it and frees its frames
when the last lets go. The reason D131 deferred it — three ports with no object
table — named the wrong table, and Phase 3 is what made it worth finding out.*
**D45**: four of five v0 deviations are struck —
ring-3 `ChannelCreate` (D253), ring-3 `ChannelSend` (D150),
reply-into-user-buffer (D79) and the single round trip (D82). What is left is
channel teardown from ring 3, and it is left because looking closed and being
closed came apart: `HandleClose` has branches for memory objects and devices
and none for endpoints, so it never reaches `close_endpoint` and never wakes a
blocked peer. That still waits for the holder to exit.

**What was still D42, and was the whole of Phase 2:** "the root-task ELF is
still a Bazel-built artifact **embedded via a generated byte array** (v0's
'initrd')... and **no signature/measurement** in the load path". That sentence
was the accurate description of the load path from M14 to D289, which is the
longest any sentence in this ledger has been true. **Its second half is struck**
(D289/D290): the load path measures, against an anchor that is kernel source.
Its first half is struck for the program that came off the volume (D293/D294)
and stands for the rest, which reach the machine out of `PROGRAM_STORE` — a
signed byte array rather than an unsigned one, and still a byte array.

Phase 0's gate was the exception and added rather than retired, as expected: a
surface that cannot drift is a new claim about the tree, and D248 is the row
that says what it now enforces.
