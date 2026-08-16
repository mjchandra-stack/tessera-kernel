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
    // Object-graph rights, which start at bit 32 in the catalog. DERIVE is the
    // authority to produce a capability *from* this one — held by a bus
    // controller over the devices behind it, and deliberately not implied by
    // holding the bus.
    DERIVE = 0x100000000;
    // Power rights, at bit 36 in the catalog. WAKE is the authority to let a
    // device's interrupt wake the machine, and to hold a wake hold that vetoes
    // a suspend. Deliberately not implied by holding the device: otherwise the
    // set of things able to wake this machine would be the driver table, which
    // nobody chose and nobody can audit.
    WAKE = 0x1000000000;
    // SLEEP is the authority to commit the system to sleep. Separate from WAKE
    // because they are opposite authorities over the same machine: one says
    // what may interrupt a sleeping system, the other stops it running at all.
    SLEEP = 0x2000000000;
    // Firmware rights, at bit 38 in the catalog. FIRMWARE is the authority to
    // load a firmware image into a device. Not implied by holding the device:
    // firmware is code that runs on hardware outside the CPU's protection, so
    // the set of components able to put it there is an explicit set rather than
    // the driver table. Held by whatever mediates loading and narrowed away
    // when the device is handed to a driver — which is what makes "the
    // framework chooses the image" a rule the kernel enforces rather than a
    // convention drivers observe.
    FIRMWARE = 0x4000000000;
    // Protected memory, at bit 39 in the catalog. PROTECTED_DMA is the
    // authority to expose memory on the protected handling path to a device.
    // A right of the device rather than of the memory's holder: which hardware
    // may be trusted with protected content is a platform fact, and asking
    // each buffer's owner would be asking whoever knows least.
    PROTECTED_DMA = 0x8000000000;
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
