// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **block device class contract**.
//
// `docs/drivers/01-driver-framework.md` ("Driver Class Contracts") lists ten
// things a class contract defines, and this file is all ten:
//
//   1. Required methods      — `protocol BlockDevice`, ordinals 1..=5.
//   2. Optional methods      — the same protocol, gated by `BlockFeature`.
//   3. Event types           — server-initiated methods, ordinals 20..=21.
//   4. Buffer ownership      — `BufferOwnership`, declared per method.
//   5. DMA rules             — `BlockDmaRules`, reported by `Describe`.
//   6. Power states          — `BlockPowerState` and `SetPower`.
//   7. Error codes           — `BlockError`.
//   8. Reset behaviour       — `Reset`, and what it is defined to leave.
//   9. Trace events          — `BlockTracePoint`.
//  10. Conformance tests     — `//api/class-conformance`, which reads a
//                              driver's transcript against the rules here.
//
// Before this it was two structs — a read request and its reply — which is a
// *message pair*, not a contract. The difference is what a second
// implementation can be held to: two structs say what the bytes look like, and
// a contract says which methods must exist, what may be absent and how a
// driver says so, who owns a buffer while a call is in flight, what a reset
// leaves behind, and which errors a client is allowed to see.
//
// **What is deliberately not here.** No MMIO base, no interrupt number, no
// queue geometry. Those live inside the device capability and the driver's own
// transport; a class contract that named them would be a description of one
// implementation rather than of a class.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it. Only the two EL0 programs hold these bindings.

library tessera.driver.block;

// --- 7. Error codes ---------------------------------------------------------

// What a block driver is allowed to fail with.
//
// A **closed set**, and that is the point: a client can enumerate the ways a
// call can go wrong and handle each, which it cannot do against an open
// integer. A driver returning something outside this set is not returning an
// unusual error, it is failing to conform — and the conformance suite says so.
//
// Values are ABI: append only, never renumbered or reused.
strict enum BlockError : uint32 {
    // The call succeeded. Present as a value rather than as "the absence of an
    // error", so a status field has a meaning at every value it can hold.
    OK = 0;
    // The sector is outside the medium.
    OUT_OF_RANGE = 1;
    // The medium is present but the transfer did not complete: a device error,
    // a timeout, a retry budget spent.
    IO_ERROR = 2;
    // The device is there and the medium is not — an empty removable bay.
    NO_MEDIUM = 3;
    // The medium is present and cannot be written to.
    READ_ONLY = 4;
    // The method exists in this contract and this driver does not implement
    // it. **The only correct answer for an unimplemented optional method**:
    // silence, or a generic failure, would leave a client unable to tell a
    // driver that cannot flush from one whose flush failed.
    NOT_SUPPORTED = 5;
    // The request was malformed, or arrived in a state that does not admit it
    // — a read while suspended, a vendor method with no namespace negotiated.
    PROTOCOL = 6;
    // The device is not in a state where it can serve this. A driver that has
    // marked itself degraded answers with this rather than attempting the
    // transfer and reporting an I/O error, because the two say different
    // things about whether a retry is worth anything.
    DEGRADED = 7;
    // The device is no longer in the machine. A request in flight when it was
    // pulled is completed with this rather than left to time out.
    //
    // **Not `DEGRADED`, and the difference is what a client does next.**
    // Degraded invites a retry — the device is unwell and may recover. Removed
    // forbids one: there is nothing to retry against, and a client that kept
    // trying would be waiting for hardware that has left the building.
    REMOVED = 8;
};

// --- 2. Optional methods ----------------------------------------------------

// What a particular block driver can do beyond the required set.
//
// **Optionality is a reported fact, not an inference.** A client that
// discovered a driver's capabilities by calling a method and seeing what
// happened would be probing, and probing has side effects — a discard is not a
// question. `Describe` reports these bits up front, and a method whose bit is
// clear is defined to answer `NOT_SUPPORTED`, so the two ways of finding out
// agree.
bits BlockFeature : uint64 {
    // The driver implements `Write`.
    WRITE = 0x1;
    // The driver implements `Flush`, and a completed flush means the data is
    // durable.
    FLUSH = 0x2;
    // The driver implements `Discard`.
    DISCARD = 0x4;
    // The medium can be removed while the driver is bound, so `OnMediaChanged`
    // can fire and `NO_MEDIUM` is a reachable error.
    REMOVABLE = 0x8;
    // The driver implements `ReadInto` and `WriteFrom`, which move a whole
    // sector through a memory object instead of the message's inline payload.
    //
    // One bit for the pair rather than two, because a driver that can be
    // handed a buffer to fill can be handed one to drain: the capability is
    // the ability to accept an out-of-line grant at all, and splitting it
    // would let a driver advertise a half of the mechanism that does not
    // exist. `WRITE` still gates the writing direction — a read-only medium
    // advertises `OUT_OF_LINE` without `WRITE` and answers `WriteFrom` with
    // `READ_ONLY`.
    OUT_OF_LINE = 0x10;
};

// --- 6. Power states --------------------------------------------------------

// The power states a block device class defines.
//
// Four rather than two: the interesting distinction is between a device that
// has stopped serving but is instantly available (`IDLE`) and one whose
// medium has spun down or whose link is off (`STANDBY`), because they differ
// by orders of magnitude in resume latency and the power manager arbitrates on
// exactly that. `Describe` reports which of these a driver actually
// implements, and the resume latency of each.
strict enum BlockPowerState : uint32 {
    // Serving requests.
    ACTIVE = 1;
    // Not serving, immediately available. No medium state has been given up.
    IDLE = 2;
    // Not serving, and the medium or link has been powered down. Resuming
    // costs the latency `Describe` reports.
    STANDBY = 3;
    // Off. Everything that was not flushed is gone, which is why a driver
    // moving here without a preceding `Flush` is a conformance failure for a
    // device that claims `FLUSH`.
    OFF = 4;
};

// --- 4. Buffer ownership ----------------------------------------------------

// Who owns the memory a request names, and for how long.
//
// The rule a class contract has to state and a message definition cannot: the
// same bytes on the wire mean different things depending on whether the driver
// may keep them, and getting it wrong is a use-after-free across a process
// boundary that no type system on either side can catch.
//
// The block contract's rule, stated once here rather than per method:
// **every request's payload is `CALLER_RETAINS`**. The caller owns its buffer
// throughout, the driver may read it only until it replies, and a driver that
// holds a reference past the reply — to complete a transfer asynchronously, say
// — is not conformant. Asynchronous completion belongs to the queue interface
// (deferred), where the ownership mode is `SHARED_FOR_CALL` and the lifetime is
// explicit.
strict enum BufferOwnership : uint32 {
    // The caller owns the buffer and the driver may touch it only for the
    // duration of the call.
    CALLER_RETAINS = 1;
    // Ownership moves to the driver, which is responsible for releasing it.
    TRANSFERRED = 2;
    // Both may access it until the driver signals completion. Requires an
    // explicit completion signal, which is why the synchronous contract below
    // does not use it.
    SHARED_FOR_CALL = 3;
};

// --- 5. DMA rules -----------------------------------------------------------

// The constraints a driver's DMA imposes on the buffers a client gives it.
//
// Reported rather than assumed, because they are properties of a device and
// not of a class: a client that hardcoded 512-byte alignment would work until
// it met a device that needed 4096, and the failure would be a transfer that
// silently moved the wrong bytes.
@abi
struct BlockDmaRules {
    size: uint32;
    version: uint32;
    flags: uint64;
    // Every buffer address the driver is given must be a multiple of this.
    alignment: uint32;
    // The largest single transfer, in sectors. Zero means the driver imposes
    // no limit of its own beyond the medium's size.
    max_transfer_sectors: uint32;
    // Whether the driver's device translates through an IOMMU. **Reported so
    // that it can be false**: a client handing buffers to an unscoped device
    // is handing it the machine, and `docs/drivers/01` requires that be a
    // visible property rather than a silent one (see `DEVICE_DMA_UNSCOPED`).
    scoped: bool;
    reserved: array<uint8, 7>;
};

// --- 9. Trace events --------------------------------------------------------

// The trace points a conformant block driver emits.
//
// Naming them in the contract is what makes a driver's tracing *checkable*:
// `docs/drivers/01` requires "trace event schema validation" as part of
// certification, and a schema nobody wrote down cannot be validated. A driver
// that emits points outside this set is not wrong, but a driver that omits one
// of these cannot be traced by tooling that expects the class.
strict enum BlockTracePoint : uint32 {
    // A request was accepted from a client, before any device work.
    REQUEST_ACCEPTED = 1;
    // The request was published to the device.
    REQUEST_SUBMITTED = 2;
    // The device reported completion.
    REQUEST_COMPLETED = 3;
    // A reply was sent. Separate from COMPLETED because the gap between them
    // is the driver's own overhead, which is the number a latency budget is
    // about.
    REPLY_SENT = 4;
    // The driver reset its device.
    DEVICE_RESET = 5;
    // A power-state transition was applied.
    POWER_CHANGED = 6;
};

// --- 15. Versioned vendor extension namespaces ------------------------------

// A vendor's private extension to this class, as the driver declares it.
//
// `docs/drivers/01`: *"Class contracts are stable public interfaces.
// Vendor-private methods are allowed only through explicitly versioned
// extension namespaces."* Three fields, and each closes a different way a
// private method becomes a de facto public one:
//
// - `vendor` and `namespace` mean two vendors cannot collide on an ordinal, so
//   nobody's extension quietly becomes another's.
// - `version` means an extension can change without a client that knows the
//   old one silently getting the new behaviour. An extension without a version
//   is a stable interface pretending not to be.
//
// A driver reports this in `Describe`. Ordinals at or above
// `VENDOR_ORDINAL_BASE` belong to the declared namespace and to nothing else,
// and a driver **must** answer `PROTOCOL` to one when no namespace has been
// negotiated — the check that stops a vendor method from being reachable by
// accident.
@abi
struct VendorNamespace {
    size: uint32;
    version: uint32;
    flags: uint64;
    // Zero means this driver declares no extensions, which is the honest
    // answer and not the same as declaring vendor 0.
    vendor: uint32;
    namespace: uint32;
    // The extension's own version, independent of the class contract's.
    extension_version: uint32;
    reserved: uint32;
};

// --- 1. Required methods, and what `Describe` answers ------------------------

// The reply to `Describe`: everything a client needs to know before it sends a
// request it might not be allowed to send.
//
// **This is the method that makes the other nine elements usable.** Optional
// methods, DMA rules, power states and the vendor namespace are all facts about
// a particular driver, and a client with no way to ask them would have to
// assume — which is the same as the contract not specifying them.
@abi
struct BlockDescribeReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    // Which version of *this contract* the driver implements. A client that
    // sees a major it does not know must not proceed: the ordinals may mean
    // different things.
    contract_version: uint32;
    status: BlockError;
    // 2. Which optional methods exist.
    features: uint64;
    // The medium.
    sector_size: uint32;
    reserved: uint32;
    sector_count: uint64;
    // 5. What the driver's DMA requires of the caller.
    dma_alignment: uint32;
    dma_max_transfer_sectors: uint32;
    dma_scoped: uint32;
    // 6. Which power states this driver implements, as a bitmask of
    // `1 << BlockPowerState`, and the worst-case resume latency in
    // microseconds from the deepest one it supports.
    power_states: uint32;
    resume_latency_us: uint64;
    // 15. The vendor extension namespace this driver offers, or zeroes.
    vendor: uint32;
    vendor_namespace: uint32;
    vendor_extension_version: uint32;
    reserved2: uint32;
};

// A read of one sector, sent by the client with ChannelCall. The reply
// arrives in the same call buffer (the symmetric call-buffer convention:
// ChannelMsgArgs' inline descriptor is the request source and the reply
// destination, so the buffer must hold the larger of the two structs).
//
// Unchanged from the two-struct version this file used to be: it is the wire
// two programs already speak, and a class contract that broke it to look tidier
// would be changing an ABI for no reason.
@abi
struct BlockReadRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    sector: uint64;
};

// The driver's reply: the outcome and the sector's first 64 bytes — enough
// for the proof (the test disk's magic lives at byte 0) while fitting the
// channel's inline payload. Full-sector transfer needs a shared-memory grant,
// deferred with the rest of the service surface.
//
// `status` is a `BlockError` value. It is typed `uint32` rather than the enum
// so the existing wire layout is untouched and an out-of-contract value can be
// *observed* — a strict enum would refuse to decode it, and the conformance
// suite's job is to report a driver returning one, not to be unable to see it.
@abi
struct BlockReadReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    reserved: uint32;
    data: array<uint8, 64>;
};

// A write of one sector's leading bytes. The counterpart of `BlockReadRequest`,
// and the reason this contract is no longer read-only.
//
// Buffer ownership: `CALLER_RETAINS`. The driver may read `data` until it
// replies and not afterwards.
@abi
struct BlockWriteRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    sector: uint64;
    data: array<uint8, 64>;
};

// The outcome of a write, and how much of it landed.
//
// `written` is not redundant with `status`: a short write is a real outcome —
// the medium filled, the transfer was truncated at a boundary — and a contract
// with only a status would force a driver to report it as either success (a
// lie) or an I/O error (a different lie).
@abi
struct BlockWriteReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    written: uint32;
};

// The argument to every method that carries no payload of its own — `Describe`,
// `Flush`, `Reset` — and to `SetPower`, which carries only a state.
//
// One struct rather than four empty ones: the envelope is what the kernel and
// the decoder need, and four distinguishable-only-by-name empty structs would
// be four ways to get the same thing wrong.
@abi
struct BlockControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // Meaningful only for `SetPower`; `ACTIVE` otherwise.
    state: BlockPowerState;
    reserved: uint32;
};

// The outcome of a control method.
@abi
struct BlockControlReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    // The state the device is in after the call. For `Reset` this is the
    // state a reset is *defined* to leave — see the protocol below.
    state: BlockPowerState;
};

// 3. An event the driver raises without being asked.
@abi
struct BlockEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The trace point or error this event reports.
    status: uint32;
    sector: uint32;
};

// --- Out-of-line transfer ---------------------------------------------------

// A transfer whose payload is a **memory object**, not inline bytes
// (`docs/kernel/04`, "Out-Of-Line Memory Semantics").
//
// **`buffer` names which transferred capability is the buffer — by index, not
// by number.** `docs/api/03`: *"Handles are indexed references into the
// message's handle vector … Payload bytes never contain handle values."* The
// sender writes 0 for "the first handle I attached"; the receiver resolves
// that against the kernel's installed-handle report, which is the only thing
// that knows the number the capability landed on. A handle *number* in these
// bytes would be meaningless — the sender does not choose it, and the
// receiver's own generation counter guarantees it differs from any number
// either side remembered.
//
// One handle today, so the index is always 0 — and the field is still not
// redundant: it is what lets a later request attach a completion endpoint
// beside the buffer without either side having to agree, out of band, about
// which of the two came first.
//
// Buffer ownership: **`transfer`**, declared on the field rather than stated in
// this comment, which is the difference between a rule and a note. The client's
// handle and its mappings are gone by the time the driver sees the message, so
// the driver is reading or writing memory nobody else can touch — the property
// that makes a full-sector transfer checkable rather than a race. The driver
// transfers the object back with its reply.
@abi
struct BlockBufferRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    sector: uint64;
    // Bytes to move, starting at the object's first byte. Above the object's
    // length, or not a whole number of sectors, is `PROTOCOL` — a driver that
    // quietly moved fewer bytes would leave the client believing a sector it
    // never read.
    length: uint64;
    // Which of this message's transferred handles is the buffer. The declared
    // rights are what the driver needs to do the job in both directions: read
    // it to write a sector, write it to fill one, map it at all, and transfer
    // it back.
    buffer: transfer handle<Object, {READ, WRITE, MAP, TRANSFER}>;
};

// The outcome of an out-of-line transfer. Carries no data: the data is in the
// object, which comes back attached to this reply.
//
// `status` is a `BlockError` value, typed `uint32` for the same reason
// `BlockReadReply.status` is — an out-of-contract value must be observable
// rather than undecodable.
@abi
struct BlockBufferReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    reserved: uint32;
    // Bytes actually moved. Equal to the request's `length` on success, and
    // reported rather than assumed so a partial transfer is a fact the client
    // can act on instead of a silence it has to infer.
    transferred: uint64;
};

// --- The protocol -----------------------------------------------------------

// The block device class.
//
// **Reset behaviour (element 8), stated where the method is.** `Reset` is
// defined to leave the device: in `ACTIVE` power state; with no request
// outstanding — every in-flight call is completed with `IO_ERROR` before the
// reset returns, never left to time out; with the medium's contents unchanged;
// and with every negotiated feature re-negotiated, so `Describe` after a reset
// may legitimately report fewer features than before. A driver whose reset
// leaves an outstanding request is the one that matters: the client is holding
// a buffer it believes the driver may still be reading.
protocol BlockDevice {
    // Required. What this driver is and what it can do. A client calls this
    // first; everything else in the contract is conditional on the answer.
    1: Describe(BlockControlRequest) -> (BlockDescribeReply);
    // Required. Read one sector.
    2: Read(BlockReadRequest) -> (BlockReadReply);
    // Optional, gated by `BlockFeature.WRITE`. Write one sector.
    3: Write(BlockWriteRequest) -> (BlockWriteReply);
    // Optional, gated by `BlockFeature.FLUSH`. Make prior writes durable.
    4: Flush(BlockControlRequest) -> (BlockControlReply);
    // Required. See the reset behaviour above.
    5: Reset(BlockControlRequest) -> (BlockControlReply);
    // Required. Move to a power state the driver reported in `Describe`; a
    // state it did not report is `NOT_SUPPORTED`, not a best effort.
    6: SetPower(BlockControlRequest) -> (BlockControlReply);
    // Optional, gated by `BlockFeature.DISCARD`.
    7: Discard(BlockWriteRequest) -> (BlockControlReply);

    // Optional, gated by `BlockFeature.OUT_OF_LINE`. Read `length` bytes from
    // `sector` into the transferred buffer, and transfer the buffer back.
    10: ReadInto(BlockBufferRequest) -> (BlockBufferReply);
    // Optional, gated by `BlockFeature.OUT_OF_LINE` *and* `BlockFeature.WRITE`.
    // Write the transferred buffer's `length` bytes to `sector`, and transfer
    // the buffer back.
    11: WriteFrom(BlockBufferRequest) -> (BlockBufferReply);

    // Ordinals 12..=19 remain reserved for methods this class has not needed
    // yet. Reserving a *range* rather than allocating on demand is what keeps
    // the event and vendor ranges below at fixed, memorable boundaries.
    //
    // 8 and 9 are retired, not available: they were reserved before the
    // out-of-line pair existed and stay reserved now that it does. An ordinal
    // that has ever been published as unusable cannot become usable later
    // without a peer somewhere reading a new method as the old refusal.
    8: reserved;
    9: reserved;

    // 3. Events. The driver raises these; no client asked.
    20: -> OnError(BlockEvent);
    21: -> OnMediaChanged(BlockEvent);
    // The device is gone. An **event**, not a reply, because nobody asked —
    // and because it is addressed to everyone holding this contract rather
    // than to whoever happened to have a call outstanding.
    //
    // Distinct from `OnMediaChanged`, which is the *medium* leaving a device
    // that is still there: a client can wait for a new disc, and cannot wait
    // for a new controller. And distinct from `OnError`, which describes a
    // request that failed against a device still able to fail.
    22: -> OnDeviceGone(BlockEvent);
};
