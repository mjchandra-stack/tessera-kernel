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
bits Rights : uint64 {
    READ = 0x1;
    WRITE = 0x2;
    EXECUTE = 0x8;
    MAP = 0x4;
    CREATE_PROCESS = 0x10000;
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

// Phase 3 — start a created + populated process's initial thread at `entry`
// with stack pointer `stack` and initial argument `arg`.
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
