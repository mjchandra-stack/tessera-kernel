// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **network device class contract** — the second class, and the reason it
// exists is to find out whether the first one's shape was a shape or a
// coincidence.
//
// Written against the same ten elements as `block_driver.isl`, in the same
// order, so the two can be read side by side. What is worth noticing is where
// they differ, because those are the places the block contract was describing
// block devices rather than devices:
//
// - **Events matter here.** A block driver raises events for exceptions — an
//   error, a medium change. A network driver's *normal operation* is
//   event-driven: a frame arrives without anyone having asked, and the class
//   is unusable without a way to say so. `OnFrameReceived` is not the analogue
//   of `OnError`; it is the analogue of a completed read.
// - **Buffer ownership genuinely varies.** A block write is
//   `CALLER_RETAINS` — the driver reads the sector and replies. A received
//   frame is `TRANSFERRED`: the driver has a buffer it does not want back, and
//   holding one per client until each replies is how a receive path stalls.
//   The block contract could state one rule for the whole class; this one
//   cannot, which is why the rule is per method rather than per contract.
// - **Power states are the same four and mean different things.** `STANDBY` on
//   a disk is a spun-down platter; here it is a link that has been brought
//   down, and coming back costs an autonegotiation rather than a spin-up. The
//   *states* generalised; their latencies did not, which is why `Describe`
//   reports the latency rather than the contract naming it.
// - **The error set is not the block set with words changed.** `NO_MEDIUM`
//   becomes `LINK_DOWN`, and that is a real difference: a disk with no medium
//   cannot serve anything, and a link that is down still accepts
//   configuration.
//
// The seven elements that did generalise unchanged — required and optional
// methods, DMA rules, reset behaviour, trace events, the vendor namespace, and
// the shape of `Describe` — are the evidence that the block contract was a
// class contract rather than one device's interface written out.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it.

library tessera.driver.network;

// --- 7. Error codes ---------------------------------------------------------

// A closed set, as in the block class, and deliberately not the same set.
strict enum NetError : uint32 {
    OK = 0;
    // The frame is longer than the interface's MTU, or shorter than a frame
    // can be.
    BAD_LENGTH = 1;
    // The transfer did not complete: a device error, a spent retry budget.
    IO_ERROR = 2;
    // The link is down. The device is present and configurable — which is why
    // this is not the block class's `NO_MEDIUM`, where nothing can be done at
    // all.
    LINK_DOWN = 3;
    // No buffer was available to receive into. A real and recoverable outcome
    // on this class and meaningless on the block one: a client that has not
    // posted receive buffers is not broken, it is behind.
    NO_BUFFER = 4;
    // The method exists in this contract and this driver does not implement
    // it.
    NOT_SUPPORTED = 5;
    // Malformed, or not admissible in the current state.
    PROTOCOL = 6;
    // The driver has marked itself degraded and will not attempt the transfer.
    DEGRADED = 7;
    // The device is no longer in the machine. The same distinction the block
    // contract draws: degraded invites a retry, removed forbids one.
    REMOVED = 8;
};

// --- 2. Optional methods ----------------------------------------------------

bits NetFeature : uint64 {
    // The driver implements `Transmit`.
    TRANSMIT = 0x1;
    // The driver implements `SetPromiscuous`.
    PROMISCUOUS = 0x2;
    // The device computes checksums on the driver's behalf.
    CHECKSUM_OFFLOAD = 0x4;
    // The device reports link state changes, so `OnLinkChanged` can fire.
    LINK_EVENTS = 0x8;
};

// --- 6. Power states --------------------------------------------------------

// The same four names as the block class, which is the point: a power manager
// arbitrates across every device on the machine and cannot do that against a
// per-class vocabulary. What differs is what they cost, and that is reported
// rather than named.
strict enum NetPowerState : uint32 {
    ACTIVE = 1;
    // Link up, not serving.
    IDLE = 2;
    // Link down. Coming back costs an autonegotiation.
    STANDBY = 3;
    OFF = 4;
};

// --- 4. Buffer ownership ----------------------------------------------------

// Per method here, unlike the block class, and that difference is the finding.
//
// - `Transmit` is `CALLER_RETAINS`: the driver copies or DMAs out of the
//   caller's frame and replies.
// - `OnFrameReceived` is `TRANSFERRED`: the driver hands the frame over and
//   keeps nothing. A receive path that waited for each client to give a buffer
//   back would stall on the slowest one, which is the whole reason this class
//   needs an ownership mode the block class never used.
strict enum NetBufferOwnership : uint32 {
    CALLER_RETAINS = 1;
    TRANSFERRED = 2;
    SHARED_FOR_CALL = 3;
};

// --- 9. Trace events --------------------------------------------------------

strict enum NetTracePoint : uint32 {
    FRAME_QUEUED = 1;
    FRAME_TRANSMITTED = 2;
    FRAME_RECEIVED = 3;
    FRAME_DROPPED = 4;
    LINK_UP = 5;
    LINK_DOWN = 6;
    DEVICE_RESET = 7;
    POWER_CHANGED = 8;
};

// --- 15. Versioned vendor extension namespaces ------------------------------

// The same three fields as the block class, and the same rule: ordinals at or
// above the vendor base belong to the declared namespace, and a driver answers
// `PROTOCOL` to one when nothing has been negotiated.
//
// That this is identical across two classes is the argument for it being a
// *framework* rule rather than a per-class one — and the reason the conformance
// suite checks it the same way for both.
@abi
struct NetVendorNamespace {
    size: uint32;
    version: uint32;
    flags: uint64;
    vendor: uint32;
    namespace: uint32;
    extension_version: uint32;
    reserved: uint32;
};

// --- 1. Required methods, and what `Describe` answers ------------------------

@abi
struct NetDescribeReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    contract_version: uint32;
    status: NetError;
    features: uint64;
    // The interface.
    mtu: uint32;
    link_up: uint32;
    // The MAC address, low six bytes.
    mac_low: uint32;
    mac_high: uint32;
    // 5. DMA rules, reported for the same reason the block class reports
    // them: a client that assumed would meet a device that disagreed.
    dma_alignment: uint32;
    dma_max_frame: uint32;
    dma_scoped: uint32;
    // 6. Supported power states as a bitmask of `1 << NetPowerState`, and the
    // worst-case resume latency from the deepest.
    power_states: uint32;
    resume_latency_us: uint64;
    // 15.
    vendor: uint32;
    vendor_namespace: uint32;
    vendor_extension_version: uint32;
    reserved: uint32;
};

// A frame handed to the driver to send. Ownership: `CALLER_RETAINS`.
//
// 64 bytes, matching the block class's payload for the same reason: it is what
// fits the channel's inline payload, and a full-MTU frame needs a shared-memory
// grant that is deferred with the rest of the queue interface. An ARP request
// is 42 bytes, so the frames this class is proven with are whole ones rather
// than truncations.
@abi
struct NetTransmitRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    length: uint32;
    reserved: uint32;
    frame: array<uint8, 64>;
};

@abi
struct NetTransmitReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    // Bytes accepted. Not redundant with `status` for the same reason
    // `BlockWriteReply.written` is not: a truncated send is an outcome, and a
    // contract with only a status forces it to be reported as a lie.
    sent: uint32;
};

@abi
struct NetControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    state: NetPowerState;
    // Meaningful only for `SetPromiscuous`.
    enable: uint32;
};

@abi
struct NetControlReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    state: NetPowerState;
};

// A frame the device received, handed to whoever registered for them.
// Ownership: `TRANSFERRED` — the driver keeps nothing and expects nothing back.
//
// **What `TRANSFERRED` costs the driver, stated as a field.** The buffer
// travels with the event: the driver relinquishes it and replenishes its own
// receive pool, so a client that is slow to consume frames spends the client's
// memory rather than stalling the driver's. Ownership is per method on this
// class precisely because `Transmit` cannot work this way and a receive path
// cannot work any other.
//
// A driver with nothing to grant — one that copies out of a ring it must keep
// — sends no buffer, and then `frame` carries the bytes. Both are conformant
// and they are distinguishable: `buffer` is absent in the second, which is a
// fact about the message rather than a flag anyone has to set honestly.
@abi
struct NetFrameEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    length: uint32;
    reserved: uint32;
    frame: array<uint8, 64>;
    // The rights are what a *receiver* of a frame needs and no more: read it
    // and map it. Deliberately no `WRITE` — the client is being given data,
    // not a scratch buffer — and no `TRANSFER`, so a frame cannot be passed on
    // a second time by a client that was only ever meant to read it.
    buffer: transfer handle<Object, {READ, MAP}>;
};

// A link-state change.
@abi
struct NetLinkEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    link_up: uint32;
    reserved: uint32;
};

// --- The protocol -----------------------------------------------------------

// The network device class.
//
// **Reset behaviour (element 8).** `Reset` is defined to leave the device: in
// `ACTIVE` power state; with every queued transmit completed with `IO_ERROR`
// rather than left outstanding; with every posted receive buffer returned to
// its owner, which the block class has no equivalent of and is exactly the
// asymmetry `TRANSFERRED` ownership creates; with the MAC address unchanged;
// with promiscuous mode off; and with features re-negotiated, so `Describe`
// after a reset may report fewer.
protocol NetworkDevice {
    // Required.
    1: Describe(NetControlRequest) -> (NetDescribeReply);
    // Optional, gated by `NetFeature.TRANSMIT`.
    2: Transmit(NetTransmitRequest) -> (NetTransmitReply);
    // Required. See the reset behaviour above.
    3: Reset(NetControlRequest) -> (NetControlReply);
    // Required. A state the driver did not report is `NOT_SUPPORTED`.
    4: SetPower(NetControlRequest) -> (NetControlReply);
    // Optional, gated by `NetFeature.PROMISCUOUS`.
    5: SetPromiscuous(NetControlRequest) -> (NetControlReply);

    6: reserved;
    7: reserved;

    // 3. Events — and on this class they are the data path, not the exception
    // path. A frame arriving is the normal case.
    20: -> OnFrameReceived(NetFrameEvent);
    21: -> OnLinkChanged(NetLinkEvent);
    22: -> OnError(NetLinkEvent);
    // The device is gone. Distinct from `OnLinkChanged`, which is the *link*
    // going down on a NIC that is still there — a client can wait for a cable
    // to be plugged back in, and cannot wait for a new NIC.
    23: -> OnDeviceGone(NetLinkEvent);
};
