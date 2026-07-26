// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The system-call structured-argument ABI, defined in ISL. `Syscall` is the
// call-number enum; the `@abi` structs are the structured arguments for the
// operations that take one (docs/api/01 "Structured Arguments": leading
// size/version/flags, kernel-validated before interpretation). The kernel
// (kernel/kcore/src/syscall.rs) shares these layouts by a hand-written decoder
// by convention until the ABI-diff path enforces agreement (build/README.md,
// D24) — the handle-duplicate argument is `DuplicateArgs` in `handle_abi.isl`,
// already conformance-gated. The bindings here are generated and
// conformance-checked, demonstrating the syscall boundary is ISL-expressible
// and ready to wire when user-mode ABI stabilizes.

library tessera.kernel.syscall;

// The minimal syscall set this milestone implements.
strict enum Syscall : uint64 {
    NULL = 0;
    DEBUG_WRITE = 1;
    HANDLE_DUPLICATE = 2;
    HANDLE_QUERY_RIGHTS = 3;
    HANDLE_CLOSE = 4;
    PROCESS_EXIT = 5;
};

// Arguments for `debug_write`: a user buffer to copy to the debug console. The
// kernel validates `[buffer, buffer + length)` against the caller's mappings
// before the copy (docs/security/01, "Strict user-kernel copy validation").
@abi
struct DebugWriteArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    buffer: uint64;
    length: uint64;
};

// Arguments for `process_exit`: the calling process's exit code.
@abi
struct ProcessExitArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    code: int32;
    reserved: array<uint8, 4>;
};
