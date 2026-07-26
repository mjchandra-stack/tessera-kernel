// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The handle syscall ABI, defined in ISL. `bits Rights` mirrors the kernel's
// Rights Catalog (kernel/kcore/src/rights.rs) — the two share these bit values
// by convention until the ABI-diff path enforces it (deviation D16). The @abi
// structs are the structured arguments for the handle operations; their wire
// bindings are generated and conformance-checked, demonstrating the syscall
// boundary is ISL-expressible and ready to wire when user-mode entry lands.

library tessera.kernel.handle;

// Core rights bits, matching the kernel Rights Catalog bit positions.
bits Rights : uint64 {
    READ = 0x1;
    WRITE = 0x2;
    MAP = 0x4;
    EXECUTE = 0x8;
    SIGNAL = 0x10;
    WAIT = 0x20;
    DUPLICATE = 0x40;
    TRANSFER = 0x80;
    CONFIGURE = 0x100;
    BIND = 0x200;
    ADMIN = 0x400;
};

// Duplicate a handle with a reduced rights mask.
@abi
struct DuplicateArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    source: handle<Object, {DUPLICATE}>;
    new_rights: Rights;
};

// Query the rights a handle carries.
@abi
struct QueryRightsArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    target: handle<Object, {}>;
    observed: Rights;
};

// Replace a handle's rights in place with a reduced set.
@abi
struct ReplaceRightsArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    target: handle<Object, {}>;
    new_rights: Rights;
};
