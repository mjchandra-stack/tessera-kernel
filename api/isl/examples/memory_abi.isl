// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The memory-object syscall ABI: how a process creates a range of pages it can
// hand to somebody else, and how a process that has been handed one maps it.
//
// `docs/kernel/02` ("Memory Objects") makes these the system's sharing
// primitive; `docs/kernel/04` ("Out-Of-Line Memory Semantics") says an
// out-of-line message payload *is* one of these, referenced by handle. That is
// why there is no "send a big buffer" syscall here and never will be: the
// buffer is an object, the object is a capability, and capabilities already
// travel over channels. What was missing was the object.
//
// **Mapping rights are separate from object rights** (`docs/kernel/02`,
// "Memory Objects"). A holder may map read-only something it holds writable —
// which is how a driver hands a client a buffer it must not scribble on — so
// `MemoryMap` takes the rights the *mapping* is to have, capped by what the
// capability carries. A request for more than the handle holds is refused
// rather than quietly reduced: a caller that asked for write and got read
// would discover it by faulting somewhere unrelated.

library tessera.kernel.memory;

// The rights a mapping may be given. A subset of the Rights catalog
// (`handle_abi.isl`), named here as its own set because only these three mean
// anything to a page table.
bits MapRights : uint32 {
    READ = 0x1;
    WRITE = 0x2;
    EXECUTE = 0x4;
};

// MemoryCreate — allocate `bytes` of zeroed anonymous memory as a new object,
// and install a handle to it in the caller's table.
//
// The pages are **zeroed**, and that is a security property rather than
// hygiene: an object exists to be handed to somebody else, and a page arriving
// with whatever its last owner left would make every grant a disclosure.
//
// `bytes` is rounded up to a whole number of pages and refused above the
// per-object ceiling (`kcore::memory::MAX_OBJECT_PAGES`). The ceiling is a
// refusal rather than a clamp, because a caller handed a smaller object than
// it asked for would overrun it and find out by faulting.
@abi
struct MemoryCreateArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    bytes: uint64;
};

// MemoryMap — map the object named by `memory` into the caller's own address
// space at page-aligned `vaddr`, with `rights`.
//
// Requires `Rights::MAP` on the handle, the same authority `MapDevice`
// requires and for the same reason: naming a capability is not the same as
// being entitled to put it in your address space.
//
// The whole object is mapped. Partial mappings need an offset and a length,
// which need the range bookkeeping a partial *unmap* would also need — and a
// range that can be unmapped piecewise is a range whose revocation is no
// longer all-or-nothing (`docs/kernel/06`). Deferred deliberately, not
// forgotten.
@abi
struct MemoryMapArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    memory: handle<Object, {}>;
    rights: MapRights;
    vaddr: uint64;
};

// DmaAttach — make the object named by `memory` reachable by the device named
// by `device`, and return the address the device uses to reach it.
//
// **The point of the whole out-of-line path.** Without this a driver handed a
// client's buffer can only copy through a page of its own that `DmaAlloc`
// already made device-visible, which means the CPU touches every byte of every
// transfer — and a class contract whose reason for existing is moving bytes no
// CPU touches (network frames, framebuffers, sound rings) cannot be honoured.
//
// Requires `MAP` on **both** handles. On the device, the authority `MapDevice`
// and `DmaAlloc` require. On the memory, because a device's aperture is an
// address space and `MAP` is what says a capability may be placed in one — so
// a client can hand out a buffer that may be read and written but **not**
// exposed to a device, by narrowing `MAP` away before it transfers it.
//
// The whole object is attached, at one address. Behind an IOMMU that is a
// contiguous run of device addresses covering every page. With no IOMMU it is
// the physical address of the object's single page, and an object of more than
// one page is refused rather than partly attached — physical frames are not
// contiguous, so there is no single address to return and returning the first
// would name a device address that walks into somebody else's page.
//
// An object already attached is `ALREADY_MAPPED`, never a silent
// re-attachment: replacing the record would leave the first translation
// installed with nothing able to name it.
@abi
struct DmaAttachArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {MAP}>;
    memory: handle<Object, {MAP}>;
};

// DmaDetach — stop the device reaching the object named by `memory`.
//
// After this the device's next transaction to the address `DmaAttach` returned
// **faults**. That is the property the whole mechanism rests on, and it is why
// the address is not reissued afterwards: a device may hold it in a descriptor
// ring the kernel cannot see, and only the end of a lease is a point at which
// the device is known to have forgotten.
//
// A driver need not call this before handing the buffer back — transferring
// the capability away detaches it, and a driver that cannot forget is better
// than one that must remember. It exists for a driver that wants a buffer back
// in CPU-land while continuing to hold it.
@abi
struct DmaDetachArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    memory: handle<Object, {MAP}>;
    reserved: uint32;
};

// DmaRenew — say that a DMA lease is still wanted, and until when.
//
// **A lease expires because its holder stopped saying it wanted one**, which
// is the one way a lease can end that nothing else expresses: no capability
// moved, no device misbehaved, no holder died. Nothing happened, and that is
// the fact being reported.
//
// `ticks` is a deadline on the kernel's scheduler tick counter — the only
// monotonic source it has. That makes this a **liveness bound rather than a
// clock**: it answers "is the holder still there and still asking", not "how
// long has it been". A deadline in the wall-clock sense needs the time page.
//
// Zero means no deadline, which is what every lease has until its holder asks
// for one. A driver that predates expiry keeps a lease that never ends of its
// own accord, because giving every existing driver a lifetime it never agreed
// to would be the mechanism breaking its own users on the way in.
//
// Only the holder may renew. A renewal by anyone else would keep alive a lease
// its owner had stopped wanting, which is exactly what expiry exists to catch.
@abi
struct DmaRenewArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {MAP}>;
    reserved: uint32;
    ticks: uint64;
};
