// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The three-phase process-lifecycle syscall ABI, defined in ISL
// (docs/api/01-system-call-interface.md, "Process And Thread"): create an
// empty, not-yet-started process under a parent job's create-process authority;
// map memory objects into it (the loader operation); then start it. The @abi
// structs are the structured arguments; their wire bindings are generated and
// conformance-checked. The in-kernel ELF loader exercises the same
// create/populate/start path today; the ring-3 caller + the process
// object/handle bridge are deferred (build/README.md, D42).

library tessera.kernel.process;

// The rights the process-lifecycle operations require, matching the kernel
// Rights Catalog bit positions (kernel/kcore/src/rights.rs), by convention
// (deviation D16).
// **The whole catalog, not the subset these calls happen to use.**
//
// `ProcessGrant` hands on *any* capability, so its `rights` field has to be
// able to name any right — and this is a `bits` type, whose generated decoder
// rejects a value carrying a bit the schema does not declare. A partial
// catalog therefore does not merely omit documentation: it makes a capability
// unpassable. The first one to hit it was `DERIVE`, on a root task handing a
// bus to a device manager, and the refusal arrived as `Protocol` from the
// decoder rather than as anything about authority (build/README.md, D253).
//
// Matches `kernel/kcore/src/rights.rs` and `handle_abi.isl` bit for bit, by
// convention until the ABI-diff path enforces it (deviation D16).
bits Rights : uint64 {
    READ = 0x1;
    WRITE = 0x2;
    MAP = 0x4;
    EXECUTE = 0x8;
    SIGNAL = 0x10;
    WAIT = 0x20;
    DUPLICATE = 0x40;
    // The authority to hand a capability to somebody else, which a grant into
    // a child needs for the same reason a channel transfer does.
    TRANSFER = 0x80;
    CONFIGURE = 0x100;
    BIND = 0x200;
    ADMIN = 0x400;
    CREATE_PROCESS = 0x10000;
    SUPPLY = 0x1000000;
    // The authority to produce a capability *from* this one — held by a bus
    // controller over the devices behind it. What a root task hands a device
    // manager, and the bit whose absence here made that impossible.
    DERIVE = 0x100000000;
    WAKE = 0x1000000000;
    SLEEP = 0x2000000000;
    FIRMWARE = 0x4000000000;
    PROTECTED_DMA = 0x8000000000;
};

// Phase 1 — create an empty, not-yet-started process under `job`.
@abi
struct ProcessCreateArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    job: handle<Object, {}>;
    reserved: uint32;
};

// Phase 2 — map `length` bytes into a created process's address space at
// `vaddr` with `rights` (the loader placing a segment), populating them from
// the caller's buffer at `src` (the map+copy v0 loader mechanism, D44). W^X is
// enforced by the kernel; `src == 0` maps zero-filled anonymous memory.
@abi
struct AddressSpaceMapArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    process: handle<Object, {}>;
    reserved: uint32;
    vaddr: uint64;
    length: uint64;
    rights: Rights;
    src: uint64;
};

// Between phases 2 and 3 — hand the created process a capability the caller
// holds.
//
// **What a child starts with is its parent's decision, and this is where the
// parent makes it.** `docs/api/01` has listed "install the initial handle set
// into a created process before start" since it was written, and nothing
// implemented it: every service in this tree got its handles from kernel boot
// glue reaching into its table, which is the kernel deciding what user space
// may reach (`build/README.md`, D42, D249). A process that receives its
// authority from its parent is what makes the capability model load-bearing
// rather than demonstrated.
//
// **One capability per call, deliberately.** A vector would install a set
// atomically, and this ABI has been bitten by hand-decoded vectors before
// (`build/README.md`, D101): the count is the only guard against a misparse,
// and here the cost of one is a child holding authority nobody named. A loop
// costs a syscall per handle at startup and makes each grant separately
// refusable and separately auditable.
//
// **The kernel narrows and never expands**, as `HandleDuplicate` does: a
// request for a right `source` does not carry is refused rather than trimmed.
// A parent that believed it granted more than it held would find out when the
// child was refused something, somewhere else, later.
//
// Only a process in the created state may be granted to. Once it is running,
// what it holds is its own business and a parent reaching in would be an
// ambient authority over a process it no longer composes.
@abi
struct ProcessGrantArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The created, not-yet-started process to grant to. `MAP` is the same
    // authority `AddressSpaceMapArgs` requires: composing a child's handle
    // table and composing its address space are one authority, held by
    // whoever is building it.
    process: handle<Object, {MAP}>;
    // The capability to hand over. `TRANSFER` is the authority to give a
    // capability to somebody else — the same right a channel transfer needs,
    // required here for the same reason.
    source: handle<Object, {TRANSFER}>;
    // What the child's handle carries. Must be a subset of `source`'s rights.
    rights: Rights;
    reserved: uint32;
};

// Phase 3 — start a created + populated process's initial thread at `entry`
// with stack pointer `stack` and initial argument `arg`.
//
// **It returns as soon as the child is runnable, and that is what makes a
// system possible.** It used to hand the CPU to the child and come back with
// the child's exit code, which is a spawn-and-wait — so a parent could only
// ever have one child running, and a root task could not start a server and
// then start something to talk to it. `docs/api/01` has always listed "start
// process" and "wait for process or thread termination" as two operations;
// this is the first of them (`build/README.md`, D250).
//
// A parent that wants the exit code asks for it with `ProcessWaitArgs`. A
// parent that does not need one is not made to wait for it.
//
// **v2 adds the startup message**, which `docs/api/01` has listed beside the
// initial handle set since it was written and nothing implemented. Until now a
// child learned where its capabilities landed through `arg` alone — one word —
// so a parent with two things to say packed them into its halves. That is a
// convention rather than a mechanism, and it is a **64-bit** one: on a 32-bit
// machine the argument register is 32 bits and the second handle has nowhere
// to go (build/README.md, D261).
//
// The message is **bytes the kernel does not interpret**. What is in it is an
// agreement between a parent and the child it started, which is exactly the
// kind of thing this tree writes in ISL and exactly the kind of thing the
// kernel has no business reading. It is copied out of the parent's memory into
// a page mapped in the child at `message_va`, and the child is told where by
// the parent putting that address in `arg` — so a program wanting a plain
// scalar passes `message_len = 0` and nothing changes for it.
//
// One page, and refused rather than truncated past it: a child that received
// part of its startup message would be a child that read a handle number out
// of whatever followed the cut.
@abi
struct ProcessStartArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    process: handle<Object, {}>;
    reserved: uint32;
    entry: uint64;
    stack: uint64;
    arg: uint64;
    // The startup message, in the **parent's** memory. Zero length means none,
    // and then the two fields below are ignored.
    message_ptr: uint64;
    message_len: uint64;
    // Where the child finds it. Page-aligned, in the child's user half, and
    // the parent's choice — a program chooses its own layout.
    message_va: uint64;
};

// The first startup-message payload in this tree: where a parent's grants
// landed in the child's handle table.
//
// **The kernel never reads this.** `ProcessStartArgs`'s message is bytes, and
// which schema a given message carries is an agreement between a parent and the
// child it started — the same kind of agreement any two components make about a
// protocol, and written the same way rather than hand-packed. It lives beside
// the process ABI because that is where the bootstrap is, not because the
// kernel has an opinion about it.
//
// **Named slots rather than a vector.** A count and an array would be a
// hand-decoded vector, and this ABI has been bitten by one before
// (build/README.md, D101): the count is the only guard against a misparse, and
// the cost of getting it wrong here is a child holding a capability under a
// name nobody chose. Two named fields cannot be miscounted.
@abi
struct StartupHandles {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The channel endpoint the parent granted, and the port it may raise an
    // edge on. Talking to somebody and waking them are different authorities,
    // which is why they are two capabilities and two fields.
    endpoint: handle<Object, {}>;
    port: handle<Object, {}>;
};

// Wait for a process to terminate, and learn how.
//
// **The other half of a start that does not block.** A supervisor is a loop
// over launch, wait, decide — and until `ProcessStart` stopped waiting there
// was no wait to write, because the start was one. Splitting them is what lets
// a parent hold several children at once and still be told about each.
//
// The caller blocks until the named process has exited. A process that has
// *already* exited returns immediately: a wait that missed the exit and parked
// for ever would make every supervisor a race against its own child.
//
// The exit code comes back in the result word as a `uint32` bit pattern,
// zero-extended — a code is an `int32` and the result word spells failure with
// its sign, so a negative code returned directly would be read as a kernel
// error (`docs/api/01`, "The Result Word"). The caller casts it back.
@abi
struct ProcessWaitArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The process to wait for. `READ` rather than `MAP`: learning that a child
    // died is not composing it, and a process handed a watch over something it
    // may not modify is a reasonable thing to hold.
    process: handle<Object, {READ}>;
    reserved: uint32;
};

// One argument a parent hands its child.
//
// **Bytes and a length, not a string.** A path is not required to be UTF-8 —
// the same reason `FsOpenRequest.path` is bytes — and a fixed array with an
// explicit length is a shape whose decode the generator writes rather than the
// program.
struct StartupArg {
    len: uint32;
    reserved: uint32;
    // **160 rather than the 128 this started at** (D319). Long enough for any
    // path this system has, and chosen against the *count* below rather than on
    // its own: the two together decide the message's size, and the message has
    // to fit places neither of them can see.
    bytes: array<uint8, 160>;
};

// The startup message for a child that takes **arguments** as well as
// capabilities (`docs/roadmap/04`, Phase 1).
//
// **It composes `StartupHandles` rather than extending it**, which is the whole
// design decision here. Appending argument fields to that struct would put five
// hundred bytes of path in front of every child that only ever wanted to know
// where its endpoint landed, and would be an ABI break for programs that take
// no arguments at all. Placing a second struct at a remembered offset in the
// same page would be worse: "a layout both sides remember" is exactly what
// D261 replaced when it made the startup message a schema. Nesting is neither —
// one struct, one decode, and a child that takes arguments says so by the type
// it decodes.
//
// **A count and an array, where `StartupHandles` deliberately used named
// slots.** That struct's reasoning was that a miscounted vector hands a child a
// capability under a name nobody chose; the cost here is a wrong path, and an
// argument vector has no honest fixed-slot spelling — `argc` is a number the
// caller varies by definition. What makes it safe is that nothing decodes it by
// hand: the bindings are generated, and `count` is checked against the array's
// bound by the consumer before any element is read.
@abi
struct StartupArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // Where the child's capabilities landed. The same struct a child that takes
    // no arguments receives on its own.
    handles: StartupHandles;
    // Where this program's diagnostics go: an endpoint speaking
    // `diagnostic.isl`, or zero for a program whose parent is collecting
    // nothing.
    //
    // **The third thing a program is handed at startup**, after its
    // capabilities and its arguments, and the one that took longest to notice
    // was missing. A program that could only report through `DebugWrite` was
    // talking to the kernel about something the kernel has no stake in — see
    // `diagnostic.isl` for what that costs (D303).
    //
    // Zero rather than absent, because a handle field has no empty spelling and
    // a program with nowhere to report is a real case: the check that runs it
    // may not care, and it must not fail for that.
    output: handle<Object, {}>;
    // How many of `args` carry a value. Greater than the array's bound is a
    // malformed message and is refused, not clamped: a child that clamped would
    // act on a prefix of what its parent meant.
    count: uint32;
    reserved: uint32;
    // **Twelve rather than the four this started at, and the number is a
    // measurement of two ceilings rather than a preference** (D319). Four could
    // not hold a compiler invocation — `cc -c -I dir -o out.o in.c` is seven
    // words before any real flags — which is the thing `docs/roadmap/04`
    // Phase 4 exists to run, so the bound had to move and moving it is the
    // first non-additive change to this surface.
    //
    // What decided *twelve* is the child's stack, not the page — and the number
    // is measured rather than modelled. The message is written into one page
    // and both launchers map exactly one, which would allow sixteen by 240;
    // but every consumer materialises the wire buffer *and* the decoded value,
    // and a child is given four pages, 16 KiB, on every port. `arg-probe`'s
    // entry frame goes from 1944 bytes to **6360** across this change, which is
    // 39% of that stack spent before its `main` does anything. Sixteen by 240
    // very nearly doubles the message again and would have taken most of what
    // is left, so the vector would have had to arrive with a stack change on
    // five ports — a wider blast radius than the vector itself. The narrower
    // ceiling is the one that binds, and it binds well before the page does.
    args: array<StartupArg, 12>;
};

// What a program's exit status means, as a closed set.
//
// **`ProcessWait` has returned an exit code since D250 and nothing said what a
// code meant.** A parent could tell zero from non-zero and no more, so every
// program in this tree spells its failures in numbers of its own — which is a
// convention per program rather than a contract, and a supervisor cannot act on
// it. `docs/roadmap/04` Phase 1 asks for the schema, because a compiler that
// cannot say *why* it failed is one a build system cannot use.
//
// The values are `sysexits.h`'s where it has one, deliberately: a POSIX tier is
// Phase 4 of that plan, and a status this tree invented would have to be
// translated at exactly the boundary the tier exists to remove.
strict enum ExitStatus : int32 {
    // The program did what it was asked.
    OK = 0;
    // The arguments were wrong: too few, too many, or one this program does
    // not understand. Distinct from `NOT_FOUND` because a caller retries one
    // and not the other.
    USAGE = 64;
    // What the arguments named is not there.
    NOT_FOUND = 66;
    // The program could not reach something it needed — a service that did not
    // answer, a capability it was not granted.
    UNAVAILABLE = 69;
    // The program failed in a way it does not have a word for. A status of
    // last resort, and one a parent should log rather than interpret.
    SOFTWARE = 70;
};
