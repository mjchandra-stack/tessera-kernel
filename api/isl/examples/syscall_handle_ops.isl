// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// Example kernel-ABI schema: handle operations as syscall structured
// arguments. Each @abi struct is a frozen, fixed-layout record leading with
// the mandatory size/version/flags header (docs/api/01, "Structured
// Arguments").

library tessera.kernel.handleops;

// Rights mask carried by a handle (a subset of the Rights Catalog).
bits Rights : uint64 {
    READ = 0x1;
    WRITE = 0x2;
    DUPLICATE = 0x4;
    TRANSFER = 0x8;
    WAIT = 0x10;
    SIGNAL = 0x20;
};

strict enum ObjectType : uint32 {
    NONE = 0;
    CHANNEL = 1;
    MEMORY = 2;
    THREAD = 3;
};

// Duplicate a handle with a reduced rights mask.
@abi
struct DuplicateArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    source: handle<Object, {DUPLICATE}>;
    new_rights: Rights;
    reserved: array<uint8, 4>;
};

// Query a handle's type and rights.
@abi
struct QueryArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    target: handle<Object, {READ}>;
    observed_type: ObjectType;
    observed_rights: Rights;
};
