<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Self-Hosting

## Purpose

`03-composition-and-self-hosting.md` closes with four lines about Phase 5:
the compiler runs on the machine, reads sources from the filesystem, writes
objects back to it, and produces a kernel image the machine can boot — "by
this point a consequence rather than a project".

**It is not a consequence, and this document exists because the sentence that
said it would be rested on a premise that did not land.** Phase 4 closed on its
"Done when" — the user-space tree builds against a published ABI artifact with
no path into `kernel/` — while its named subject, `docs/api/04` tier 1 and a
libc over the native syscalls, was never started. Phase 5 was written assuming
a POSIX tier would be underneath it. There is none.

So this is the plan the stub was standing in for. It is a separate document
for the reason `02-smp-bring-up-plan.md` is one: a stage's exit gate that takes
more than a phase is sequenced where it can be sequenced properly, and the
parent document keeps the sentence and points here.

## The Rules

Three, and they decide the ordering below.

1. **The gate is an image, not a demonstration.** "An image built by the system
   boots the system" is one claim and it is falsifiable. Everything below is
   ordered by what that claim needs, not by what is interesting to build.

2. **Every step runs on the machine or it has not happened.** A cross-compiled
   artifact that a host toolchain produced is what this tree already does on
   every commit. The subject here is the *other* direction, and the only
   evidence that counts is a boot check on one of the five machines.

3. **The tier is discovered by needing it, not by specifying it.** `docs/api/04`
   lists a POSIX surface; the useful subset is whichever calls the toolchain
   actually traps on. Phase 3 of the composition plan learned this the cheap
   way — "two SDK gaps, both found by needing them rather than by review" — and
   a libc written to a specification before anything on this machine has asked
   for a byte of it would be the same defect as a reference nobody generated.

## Where The Tree Stands

*Measured at D300, by counting the tree.*

**Four of the five things Phase 5's sentence names already exist, and are
gated.** This is the finding that shapes the plan, and it is the opposite of
what the stub's placement implies:

- **Reading a source from the filesystem.** `userspace/fs-client` opens and
  reads a path off the ext2 volume through the composed filesystem path;
  `claim fs.read` is a boot check on a real volume `mke2fs` produced.
- **Writing bytes back to it, durably.** `fs-service` implements all seven
  `fs_service.isl` methods — `Open`, `Read`, `Close`, `Write`, `Sync`,
  `Create`, `Unlink` — and `api/ext2` has `write_at`, `truncate`, `create`,
  `unlink` and `flush_inode` behind a `BlockIo` that refuses writes by default
  rather than dropping them. `tools/qemu/fs_crash_aarch64.sh` kills the machine
  with `SIGKILL` the instant the bytes appear in the image and requires them to
  already be on the medium. **An acknowledged write survives the machine dying**
  is a claim this tree can already make.
- **Loading and running a program off the volume.** D294: `fs-client` reads
  `/program.elf`, creates a process, maps its segments and starts it.
  `claim fs.exec`.
- **A published interface a toolchain could target.** D296: the ABI is an
  artifact — schemas, IR, reference, bindings, wire runtime, `uabi`, a version
  and a manifest — and `//userspace/...` builds against it with `kernel/`
  deleted.

**The fifth is absent, and so is the thing underneath it.**

- **No program on this machine has ever produced a program.** Every artifact
  that has ever run here was cross-compiled by the host toolchain. The loop
  Phase 5 is about — source in, program out, run what came out — has never
  closed at any scale.
- **There is no heap.** `grep -rn 'global_allocator\|impl GlobalAlloc'` over
  the tree matches **nothing**; `extern crate alloc` matches one file, and it
  is `kernel/karch-mock`, a host test double. All 38 user-space source files
  are `#![no_std]` and fixed-buffer: a program picks a virtual address out of
  `userspace/uabi`'s per-architecture layout, calls `memory_create` and
  `memory_map`, and lives inside what it asked for. **This is the blocker.** A
  compiler is a program whose working-set size is a property of its input, and
  nothing above a demo can be written without one.
- **There is no libc and no POSIX anything.** `grep -li 'libc\|posix'` across
  `userspace/` and `api/` matches nothing.
- **The machine is not a target.** `rust-toolchain.toml` names
  `aarch64-unknown-none-softfloat` and `x86_64-unknown-none`. Programs here are
  built freestanding, for no operating system. There is no target
  specification that says "this system", so there is nothing for a toolchain to
  emit *for* even once a toolchain exists.

**And one mechanism is already general enough and should be noticed.**
`ProcessStartArgs` carries a startup message that is "bytes the kernel does not
interpret", copied into a page in the child at an address the parent chooses.
Argument vectors and environments are an ISL schema riding on that, not a
kernel change — the same way `StartupHandles` already rides on it.

## Phase 0 — A Program Can Allocate

The blocker, and nothing below it can start.

- **A `GlobalAlloc` for ring 3**, backed by the memory objects a program
  already creates and maps. `Platform::memory_create` and
  `Platform::memory_map` are the whole of what it needs from the kernel; what
  does not exist is anything that calls them for a `Vec`.
- **A heap region in `userspace/uabi`'s layout**, per architecture, beside
  `PROBE_WINDOW_BASE` and the rest — because that file is the one place a
  program is allowed to know an address, and a heap that picked its own would
  be a second layout.
- **Growth is a syscall and a failure is a value.** The heap grows by creating
  and mapping another object. When it cannot, it says so through the event
  facility rather than returning null into a `handle_alloc_error` that prints
  nothing: `docs/lifecycle/04` forbids silent degradation and an allocator is
  the easiest place in a system to violate it.
- **`unsafe` where it is unavoidable and nowhere else.** `impl GlobalAlloc` is
  unsafe by signature; it needs an unsafe-inventory entry and a `// SAFETY:`
  stating the invariant. Every program above it stays `#![deny(unsafe_code)]`.

**Done when** a ring-3 program uses `alloc::vec::Vec` on a real machine and a
boot check fails with the allocator removed.

**Done** (`build/README.md`, D301). All four bullets, on AArch64.
`//userspace/ualloc` holds the free list with its metadata out of line, so the
algorithm is arithmetic that 20 host tests reach without any memory to run
against; `userspace/heap-probe` is given no handles at all, because the
authority to ask for memory is one a process has by being a process.

**The third bullet cost more than it reads, and the reason is a kernel bound.**
`MAX_OBJECT_PAGES` is 16, so no memory object may exceed 64 KiB — set against
the harder bound that an object too large to reclaim is a limit that cannot be
honoured on the way out. **A heap here is therefore many objects and not one**,
and a request larger than 64 KiB is served only because consecutive objects are
mapped adjacently and the free list coalesces them. That was found by booting,
not by reading: the first run failed with the grow code for a refused
`MemoryCreate`.

*The prediction below — that this phase is an allocator and the memory model
is the real cost — is untested and still stands. Nothing here asks the pager or
the reclaim path what a program may have; `HEAP_MAX_BYTES` is a ceiling that
stops a runaway walking into an address it was never given, which is a much
smaller claim than a policy.*

## Phase 1 — A Program Has Arguments And Output

A compiler takes a filename and says what went wrong. Neither is expressible.

- **An argument vector as an ISL schema** on the startup message, beside
  `StartupHandles`. No kernel change: the mechanism is D261's and this is a
  second payload for it.
- **Output as a service, not as the kernel's debug console.** `DebugWrite` is a
  kernel call for a kernel's benefit. A program that emits diagnostics is
  speaking to something above it, and the thing above it is a contract.
- **An exit status a parent reads.** `ProcessWait` returns one; what is missing
  is the convention that says which numbers mean what, which is a schema.

**Done when** a program is started with a path it did not have compiled into
it, reads that path, and reports failure in a way its parent can act on.

**Started** (`build/README.md`, D302). The first and third bullets landed
together, because neither is provable alone: an argument that arrives and is
acted on needs a way to say what acting on it produced, and a status vocabulary
with one program to exercise it proves only that a number can be returned.
`StartupArgs` composes `StartupHandles` rather than extending it, `ExitStatus`
takes `sysexits.h`'s values where it has one, and the root task runs one
program three ways on all five machines — a path it echoes back intact, no
arguments at all, and a path it will not resolve.

**The first bullet said "no kernel change", and that held** — the mechanism is
D261's and this is a second payload for it. What it cost instead was a
*compiler* change: `array<Struct, N>` was expressible in ISL and had never been
used, so the arm that generates its decode had never been compiled, and the
first schema to need one failed in rustc rather than in `islc`.

**Done** (`build/README.md`, D302-D303). `diagnostic.isl` is the contract and
`userspace/log-service` is what a program's output is addressed to: the root
task composes three processes over two channels, the probes report, the
collector forwards whole records, and the composer matches the exact bytes —
including a path it chose itself, coming back through a process that is neither
the sender nor itself.

**The second bullet found the thing this phase was really about.**
`syscall_abi.isl` declares `DebugWrite` as a buffer and a length, and **every
port implements the length-zero case alone**, recording the argument register as
a value. So no ring-3 program in this tree can emit a byte of text by any means,
and "move output off the kernel's debug console" turned out to be moving it off
something that was never a text path. The collector forwards rather than renders
for that reason. What the contract buys is that the text now has an addressee:
when a console arrives, the one program that changes is the service, not every
program that reports.

*And the exit criterion is met in the weaker of its two readings.* The child
reads the **argument**; it does not open the file the argument names, because
this leg runs under the root task and the root task has no filesystem. Opening
a file a parent named is the first thing Phase 2 does.

## Phase 2 — A Program Produces A Program

The loop, at the smallest scale where it is real, and the phase this plan
exists to make reachable.

- **A code generator that runs in ring 3** and emits a loadable ELF for the
  machine it is running on. Not a Rust compiler — the smallest input language
  that makes the output non-trivial, on the argument the composition plan made
  about `mkstore synth --seed`: a store that verifies four synthetic blobs has
  not carried its subject, and a generator that emits a fixed byte array has
  not either.
- **It reads its source off the volume and writes its output back**, through
  the paths Phase 0 of the composition plan and D294 already gated.
- **The system then runs what it wrote**, and the check asserts a marker only
  the *generated* program can print.

**Done when** a boot check asserts output from a program that was not on the
volume when the machine started and was not in any image — and its inversion is
free, because a check that still passes with the generator removed is asserting
something the build put there.

*This is the whole of Phase 5's sentence at a scale that needs no libc, and it
is where the gate stops being a plan. Everything after it is size.*

**Done** (`build/README.md`, D304). `/source.tsm` is six lines of text on the
ext2 volume; `//userspace/tsm` compiles it to AArch64; `fs-client` reads the
source through the filesystem, writes the image back to the same volume, reads
it back and runs what came off. The machine reports `0xc0debeef` — arithmetic
the source describes, in no build artifact anywhere.

**The prediction held.** This plan warned the phase "will be attempted with too
large an input language", and the language is an accumulator with five
operations. What made it a compiler rather than a template is that nothing is
folded and the check changes the source: one hex digit moves the reported value
by exactly `0x10`.

**And the cost was not in the compiler.** Three bugs, all in the composition
around it — a whole-machine object budget of 8 that the filesystem path spends
in three places at once, a service that kept a closed file's object, and a
client that left two files open. The compiler itself worked the first time it
ran, which is what a host-testable code generator with an interpreter beside it
buys.

*The second inversion is the one worth keeping.* Executing the compiled image
straight from memory rather than writing it leaves the in-machine claim
**passing** — the value is still right — and is caught only from outside the
machine, by the artifact not being on the volume. A check that asked only what
the machine said would have missed it.

## Phase 3 — The Machine Is A Target

- **A target specification for this system**, so a toolchain emits programs for
  it rather than freestanding ones. The ABI artifact D296 publishes is what
  that target links against, which is why it was worth publishing before this.
- **The C ABI question gets answered here**, because a target that a ported
  toolchain can use is one that agrees with the toolchain about how arguments
  are passed — and `docs/api/03` already says ISL-generated C headers are the
  only C this tree admits.

**Done when** a program built for the machine's own target, by a host
toolchain, runs on the machine unmodified.

**The second bullet is done** (`build/README.md`, D305). `codegen_c.rs` is the
fourth ISL backend and covered every schema at once — 34 headers, 176 structs,
no schema edited to gain one — and they are published in
`//api/abi:abi_bundle` beside the IR and the reference. **The header proves
itself**: 1,382 `_Static_assert`s for sizes and field offsets, checked by a C
compiler on the target it compiles for, so "the C and Rust declarations
describe the same bytes" is a claim the compiler makes rather than a test.
Nothing is packed, because a packed struct would force the agreement instead of
demonstrating it.

**The first bullet is blocked on a decision rather than on work, and the
decision is not this plan's to make.** A custom rustc target triple needs a
target JSON, which needs `core` built for it, which needs `-Z build-std` —
**nightly**. `rust-toolchain.toml` and `MODULE.bazel` both pin stable 1.97.0,
and MODULE.bazel says why in as many words: *"Every bare-metal triple ships
prebuilt core/alloc, so kernel targets need no build-std (deviation D1:
built-in target specs)"*. So `target_os = "tessera"` costs the whole tree its
stable pin.

**And D1 already tracks it**, with an exit criterion about the CFI and
shadow-stack hardening flags the security model wants — not about self-hosting.
That is the better place for it: the target spec lands when *two* reasons ask
for it, and one of them is already written down.

*What Phase 4 can do without it.* A libc is C, and C is what this milestone
made the ABI speak. A ported toolchain still needs a triple before it can emit
for this machine — so the triple is Phase 5's dependency rather than Phase 4's,
which is the ordering the second bullet quietly assumed all along.

## Phase 4 — The POSIX Tier

Phase 4 of the composition plan, entered from the bottom rather than the top:
this is its named subject, and `malloc` — not `printf` — is where a libc
starts, which is why it is here and not first.

- **`docs/api/04` tier 1, driven by what the toolchain traps on.** Rule 3: the
  subset is discovered by running something and seeing what it asks for.
- **The split becomes affordable here**, on the composition plan's own rule —
  the interface is frozen, generated and gated, so the POSIX layer and the
  ported toolchain go to the second repository and the drivers and services
  stay.

**Done when** the shell and core utilities run on the machine.

**Started** (`build/README.md`, D306). A program that is not written in Rust
runs here: `userspace/libc` is the floor — `tessera/syscall.h`, the C
counterpart of `userspace/uabi`, and a `crt0` whose `_start` calls `main` and
exits with what it returned — and `c-probe` is a C program that reports
arithmetic it performed, with syscall numbers taken from D305's generated
headers rather than from constants of its own.

**Rule 3 held, and cheaply.** `userspace/libc` is not `docs/api/04` tier 1 nor
a subset chosen in advance: it is what the first C program actually needed,
which was two functions. No `argc`, no environment, no `atexit`, no static
constructors — each is a line in `crt0.c` when something traps on it.

**What is left is most of it.** There is no `malloc`, which this plan says is
where a libc starts: the heap D301 built is Rust, so a C one either binds to it
across the ABI or is written again. No `argc`/`argv`, because `StartupArgs`
(D302) is decoded by the wire codec and that is Rust too. No string or memory
functions, which is the first thing any real C program traps on.

*And the split has not been made.* The second bullet's condition is met — the
interface is frozen, generated and gated — so it is affordable. There is
nothing yet on the far side of it worth moving, which is a better reason to
wait than the condition not holding.

## Phase 5 — The Toolchain Runs On The Machine

- The compiler reads sources from the filesystem and writes objects back to it.

**Done when** a program compiled on the machine runs on the machine.

**That criterion was already met by Phase 2, and it should not have been.**
D304 compiled a source off the volume and ran the program it produced — which
is this sentence, word for word, three rows before this phase was started. A
criterion the previous phase satisfies is not a criterion, and it is the same
defect `03`'s Phase 4 had: **narrower than its own subject**, which is *the
toolchain*. Written down here rather than quietly re-scoped, because a plan
that lets this happen twice will let it happen again.

**Started** (`build/README.md`, D307), on the half of the subject that is
reachable. `userspace/tsmc` is the compiler as a program you run: what to
compile arrives in its arguments (D302), the input and output are files it
opens through the filesystem itself (D294), and what went wrong is a sentence
naming a line over `diagnostic.isl` (D303) — `tsmc: /bad.tsm:3: unknown
operation`. Every one of those mechanisms existed and none had been composed.

**The rest of the subject is out of reach here, and this plan said so first.**
Its own prediction — *"'the compiler' is doing a lot of work in one noun"* —
holds: rustc and LLVM on the machine needs a target triple (D1's, and blocked
on the toolchain-channel decision), a POSIX tier (D306 built its floor), and a
heap far larger than this kernel's object budget can serve. That is the port of
somebody else's very large program the composition plan wanted in a second
repository, and it is not this row.

*And the nearest wall is not the compiler.* The composition sits close enough
to `MAX_MEMORY_OBJECTS` that dropping one leg is what made it fit, and the
failure mode is `Open` answering `NoBuffer` on a file with nothing wrong with
it, several steps from whatever exhausted the table.

## Phase 6 — The Gate

**Done when** an image built by the system boots the system.

## What This Plan Is Likely To Get Wrong

Stated in advance, because the two plans before this one found their most
useful section to be the one admitting which predictions failed.

- **Phase 0 is estimated as an allocator and will turn out to be a memory
  model.** The moment a program can allocate, "how much may it have" is a
  question the system has never been asked, and this tree has a pager, a
  reclaim path and a budget culture that all have opinions. The allocator is a
  week; the policy is not.
- **Phase 2 will be attempted with too large an input language.** The
  temptation is to make the generator impressive. The claim is the *loop*, and
  the loop is provable with an input language nobody would call a language.
- **The heap will make the fixed-buffer discipline look obsolete, and it is
  not.** Every driver and service in this tree is fixed-buffer because a
  data-path allocation is a budget violation and a latency spike. Phase 0 is
  for programs, and a driver that grows a heap after this lands is a regression
  the ratchets should catch and probably will not.
- **Rule 2 will be the expensive one.** Every phase here has a host-side
  version that is easy and does not count. The pressure to accept one will be
  strongest in Phase 5, where the on-machine version is slowest to run and the
  cross-compiled artifact is byte-identical.
- **"The compiler" is doing a lot of work in one noun.** Self-hosting a tree
  written in Rust means rustc and LLVM on the machine. Nothing in Phases 0–3
  is sized for that, and the honest reading of Phase 5 is that it is a port of
  somebody else's very large program — which is exactly why the composition
  plan wanted it in a second repository on a different cadence.

## Out Of Scope

- A native compiler written here. The gate says an image built by the system
  boots the system; it does not say by a compiler this tree wrote.
- The native copy-on-write filesystem. ext2 carries this, as it carried
  Phase 2 of the composition plan.
- Bare-metal R1 measurement (D56), still the outstanding Stage-0 criterion and
  still gated on hardware.

## Ledger

Rows land per phase. Phase 0 is expected to add one row and no deviations: the
mechanisms it needs — `MemoryCreate`, `MemoryMap`, the event facility — all
exist and are gated, and if that estimate is wrong it will be wrong in the
direction the composition plan's Phase 1 was wrong, which is capability
plumbing.
