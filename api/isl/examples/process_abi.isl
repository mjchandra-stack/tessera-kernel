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
