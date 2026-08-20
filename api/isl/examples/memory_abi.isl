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
// Placement constraints a memory object may be created with
// (`docs/hardware/04`, "Contiguity Contract").
//
// **Strict-binding**: a constraint is satisfied at allocation or the create
// fails with a resource error. Never silently weakened — a caller handed
// scattered pages after asking for contiguous ones finds out when a device
// reads the wrong memory, which is the worst possible place to learn it.
bits MemoryConstraint : uint32 {
    // The object must appear contiguous **to the device**. Behind an IOMMU
    // this costs nothing but the mapping: the broker lays scattered physical
    // pages out at consecutive device addresses.
    DEVICE_CONTIGUOUS = 0x1;
    // The object must be contiguous in **physical memory**.
    //
    // A last resort and not a convenience. It is honoured only for hardware
    // that genuinely requires it — no scatter-gather capability and no IOMMU
    // on its path, which the resource graph records — because every such
    // object spends a run of physical memory that nothing can defragment. A
    // device behind an IOMMU asking for this is refused and told to ask for
    // `DEVICE_CONTIGUOUS`, which keeps carveout pressure proportional to the
    // hardware that actually needs it.
    PHYSICALLY_CONTIGUOUS = 0x2;
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
//
// **Version 2 carries placement constraints.** Before it there was nothing for
// a request to say about where memory had to be, which made the contiguity
// contract unstatable: a driver needing a run of physical pages had no way to
// ask, and a broker had nothing to refuse.
@abi
struct MemoryCreateArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    bytes: uint64;
    constraints: MemoryConstraint;
    // The lowest address boundary the object must start on, in bytes. Zero is
    // no requirement; anything else must be a power of two and at least a
    // page. A request the allocator cannot place is **refused**, never rounded
    // down to what it could manage.
    alignment: uint64;
    // The highest device address the object may occupy, for hardware whose
    // addressing is narrower than the machine's — a 32-bit controller behind a
    // 64-bit bus. Zero is no limit.
    address_limit: uint64;
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

// The handling path a region of memory is on
// (`docs/security/01-security-model.md`, "Memory Classification").
//
// **Not the data class.** Several of the nine data classes select the same
// treatment of memory — protected media and credentials both require that no
// device reach the bytes without explicit authority — and the memory manager
// needs to know the treatment, not which of nine reasons produced it. Mirroring
// the taxonomy here would declare eight paths the kernel does nothing about.
//
// Two, and further ones arrive when they have handling rules.
strict enum MemoryClass : uint32 {
    UNCLASSIFIED = 0;
    PROTECTED = 1;
};

// MemoryClassify — put the object named by `memory` on a handling path.
//
// **Classification only rises.** A request that would lower it is refused, which
// is `docs/security/01`'s "the strongest applicable class governs" applied to
// memory: without that rule anything holding a protected buffer could
// declassify it and hand it to a device, and protection would be advisory.
// Declassification is a policy act with its own authority and audit, and this
// is not it.
//
// Requires `WRITE` on the memory. Raising a class restricts what may be done
// with the object, so it is a modification of the object rather than an opinion
// about it — and a holder with a read-only view has no business changing what
// everyone else may do.
//
// Re-classifying to the class an object already has succeeds and changes
// nothing: an idempotent request is not an error, and a caller that had to
// remember whether it had already asked would be keeping state the kernel
// already has.
@abi
struct MemoryClassifyArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    memory: handle<Object, {WRITE}>;
    class: MemoryClass;
};

// MemoryCreatePaged — create a **service-backed** object: `bytes` rounded up to
// whole pages, none of which exist yet, supplied on demand by the endpoint
// named by `pager`.
//
// **Not `MemoryCreate` with a flag.** `MemoryCreate`'s contract is that it
// returns fully-backed memory or fails, and half of that sentence is false
// here: this draws no frames at all, so an object of a hundred pages costs
// nothing until somebody reads one. That is the whole reason a page cache can
// be larger than the memory a process is entitled to, and folding the two verbs
// together would leave callers unable to say which contract they are asking
// for.
//
// There are no placement constraints, deliberately. A placement constraint is a
// promise about physical addresses and there are no physical addresses yet, so
// the honest place to refuse a paged object a device cannot reach is the attach
// that asks for it — not a constraint recorded at create time that nothing can
// check.
//
// `pager` requires `SUPPLY`: the authority to answer for this object's
// contents. The creator keeps it, and what it hands to a consumer is a
// *different* handle to the object itself, narrowed to what a consumer needs.
@abi
struct MemoryCreatePagedArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    bytes: uint64;
    pager: handle<Object, {SUPPLY}>;
    // Padding to a 8-byte boundary, so the wire size is a whole number of
    // words on every port. Reserved rather than named: a field invented to
    // fill a hole is one nobody can remove later.
    reserved: uint32;
};

// PageSupply — put the contents of the caller's page at `source` into `memory`
// at `offset`, which must be page-aligned and inside the object.
//
// The kernel copies; it does not take the caller's page. Ownership transfer is
// what `docs/kernel/03` describes and what this will become, but a copy is what
// can be *checked* today: the source stays the pager's, mapped and readable, so
// there is no window where a page belongs to neither side and no way for a
// pager to lose memory by answering a request. The cost is one page copy per
// page-in, and it is stated in the deviation ledger rather than hidden here.
//
// Requires `SUPPLY` on the memory handle. That is the authority to decide what
// a *reader somewhere else* will see, which is why it is its own right and not
// `WRITE`: a process that may write an object it has mapped is not thereby
// entitled to answer for pages it has never seen.
//
// Supplying a page that is already resident is refused rather than replacing
// it. The old frame's only reference would go on the floor while the mapping
// went on using it, so a pager that answered the same request twice would leak
// a page per duplicate.
@abi
struct PageSupplyArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    memory: handle<Object, {SUPPLY}>;
    reserved: uint32;
    // The byte offset within the object, page-aligned.
    offset: uint64;
    // The page-aligned address, in the caller's own space, whose contents
    // become the object's page. Readable by the caller, and read once.
    source: uint64;
};

// --- The pager protocol: what the kernel asks a service for ---

// PageIn — the kernel is holding a thread that faulted on a page of `object`
// that nobody has supplied, and is asking the service that owns the object's
// contents to put it there.
//
// **The request travels the same way any other message does.** It arrives on
// the endpoint the object was bound to at creation, so a pager is an ordinary
// server: it receives, supplies, and replies. Nothing about the shape of this
// is special to the kernel being the caller — which is what keeps a pager
// testable without one.
//
// The faulting thread is blocked from the moment this is sent until the reply
// comes back. A pager that takes a page-in request and never answers holds a
// thread for ever; the deadline that would break that is not built yet, and the
// deviation ledger says so rather than this comment implying otherwise.
@abi
struct PageInRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The object whose page is missing. A pager serving more than one object
    // needs it, and one serving a single object can check it.
    object: uint64;
    // The byte offset of the missing page within the object, page-aligned.
    offset: uint64;
    // The handle **in the receiving service's own table** that names the
    // object and carries `SUPPLY`.
    //
    // The kernel resolves it, because it is the only thing the receiver can
    // act on: `PageSupply` takes a handle, and a service told only the object
    // id would have to keep a table mapping numbers it has no way to learn.
    // Zero means the kernel found no such handle, and a service that is asked
    // to fill in a page it holds no authority over should refuse.
    handle: uint32;
    // Padding to a whole number of words, reserved rather than named.
    reserved: uint32;
};

// The pager's answer. `supplied` false means the page could not be provided —
// the kernel faults the access rather than resuming a thread whose page is
// still absent, and a caller that resumed on a false answer would re-fault at
// the same address for ever.
@abi
struct PageInReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    supplied: bool;
};

protocol Pager {
    // Required. Supply the named page, then reply. The service is expected to
    // have called `PageSupply` on the object before it answers; the kernel
    // checks that the page is there rather than trusting the reply, so a reply
    // of `true` with nothing supplied fails the access instead of resuming into
    // an absent page.
    1: PageIn(PageInRequest) -> (PageInReply);
};
