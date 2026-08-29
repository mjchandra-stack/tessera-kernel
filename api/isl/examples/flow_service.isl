// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// **The flow API**: what a program asks a network stack instance for, and how
// a datagram gets in and out without the program holding a NIC.
//
// `docs/network/01-network-stack.md` ("Flow API And Port Authority") is
// normative and names this surface: *"Flow lifecycle (bind, listen, connect,
// accept, options) is a typed ISL protocol on that channel"*. This is that
// protocol. `docs/roadmap/03` Phase 3 asks for it in the same breath as the
// stack itself, because a socket surface that is not generated from one
// definition is a description of the past.
//
// --- What this covers, and what it deliberately does not -------------------
//
// **Datagram flows only.** `Bind`, `SendTo`, `RecvFrom`, `Close`. There is no
// `Listen`, no `Accept` and no `Connect` here, and their ordinals are reserved
// rather than invented: those three are the stream vocabulary, and a stream is
// a retransmission timer, a window and a reassembly queue that nothing in this
// tree has yet. Writing their signatures now would be guessing at the shape of
// code nobody has written — the mistake `docs/api/01` records having made with
// twenty syscall families.
//
// **No data ring, and that is the deviation to read first.** The normative
// design says an accepted flow arrives as *"a transferred handle carrying a
// data ring ... plus a signal set that binds to ports for readiness"*. What is
// here instead is a memory object per datagram, transferred in and transferred
// back, which is the same mechanism the block and filesystem contracts use and
// the only one this kernel has: `TransferMode::SHARE` is decoded and refused
// until every port carries an object table to refcount against (D131). A ring
// is a shared buffer by definition. So the shape below costs an object per
// datagram, which is a number `docs/architecture/03` wants measured while it
// is still cheap to change, and not a claim that this is the final shape.
//
// **No port authority.** The normative design is emphatic that *"listening is
// not ambient authority"* and that a listen port needs a port-range capability
// from the namespace broker. There is no namespace broker in this tree, so
// `Bind` here takes a port and the service decides. That is a real gap and it
// is named rather than papered over: the field the capability will occupy is
// reserved below, so adding it does not renumber anything.
//
// **One flow per client, and the reply says so.** A table of flows needs an
// eviction story the moment it can fill, and a client that can open two has
// not been shown to need to.

library flow_service;

// --- 1. Errors --------------------------------------------------------------

// Closed and stable, and deliberately the same shape as the other service
// contracts here: one word, six meanings, no strings.
strict enum FlowError : uint32 {
    OK = 0;
    // The port is in use, or outside what this client may bind.
    PORT_UNAVAILABLE = 1;
    // No flow with that id, or not this client's.
    NO_SUCH_FLOW = 2;
    // The datagram is larger than the flow's transport allows, or a length
    // field disagrees with the object it describes.
    BAD_LENGTH = 3;
    // Nothing had arrived. **Not an error in the ordinary sense** — a
    // receiver that has caught up is the normal state of a healthy flow, and
    // a contract that made it one would force every caller to special-case
    // its own success.
    WOULD_BLOCK = 4;
    // The interface underneath has no link, or the stack cannot reach it.
    UNREACHABLE = 5;
    // Malformed, or not admissible in the current state.
    PROTOCOL = 6;
    // The flow table is full.
    EXHAUSTED = 7;
};

// --- 2. Addresses -----------------------------------------------------------

// An IPv4 endpoint: four bytes and a port.
//
// **Four bytes rather than sixteen, and a version field to grow.** IPv6 is
// `docs/roadmap/03` Phase 3's other half and is not written here, because an
// address union nothing produces is a union nobody has checked. `version` is
// what a v6 address will arrive under, and `family` is what a decoder will
// switch on — declared now so that adding v6 appends rather than renumbers.
@abi
struct FlowAddress {
    size: uint32;
    version: uint32;
    flags: uint64;
    // 4 for IPv4. No other value is defined yet, and a decoder must refuse one
    // it does not know rather than read the bytes as v4.
    family: uint32;
    port: uint32;
    addr: array<uint8, 4>;
    reserved: uint32;
};

// --- 3. Requests and replies ------------------------------------------------

// Ask for a local port to receive on.
@abi
struct FlowBindRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The local address and port. A port of zero asks the service to choose,
    // which is the ephemeral case; an address of 0.0.0.0 is any interface.
    local: FlowAddress;
    // **Where the port-range capability will go** when there is a namespace
    // broker to resolve one (`docs/network/01`, "Port Authority"). Zero today
    // and refused as non-zero, so that a client compiled against a later
    // schema cannot appear to have authority this service never checked.
    port_authority: uint32;
    reserved: uint32;
};

@abi
struct FlowBindReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    // The flow this client now holds. Opaque, and only meaningful to the
    // service that issued it.
    flow: uint32;
    // The address actually bound, which is how a caller that asked for an
    // ephemeral port learns which one it got.
    local: FlowAddress;
};

// Send one datagram.
//
// **The payload is a transferred object, not an inline array**, for the reason
// D271 measured on the network class: the channel's whole inline payload is
// 256 bytes, and 42 bytes of Ethernet, IPv4 and UDP headers leave 22. A
// contract built around a message size is a contract that cannot carry a
// datagram.
@abi
struct FlowSendRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    flow: uint32;
    // How much of the object is payload.
    length: uint32;
    // Where it goes.
    remote: FlowAddress;
    // The payload. `TRANSFERRED` rather than lent, because a lent buffer needs
    // a share mode this kernel refuses (D131) — so the caller gives the
    // datagram away and the service frees it, and post-send mutation is
    // impossible by construction rather than by convention.
    payload: transfer handle<Object, {READ, MAP}>;
};

@abi
struct FlowSendReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    // Bytes accepted. Separate from `status` for the reason
    // `NetTransmitReply.sent` is: a short send is an outcome, and a contract
    // with only a status forces it to be reported as a lie.
    sent: uint32;
};

// Take the next datagram waiting on a flow.
//
// **The caller supplies the buffer**, transferred in and not returned: the
// service fills it, keeps it, and hands back a *different* object with the
// datagram in it. Two objects rather than one because the service cannot write
// into a buffer it was given `READ` on, and granting `WRITE` to a service so
// it can fill a caller's page is the shape that makes a caller's memory
// writable by whoever it last spoke to.
@abi
struct FlowRecvRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    flow: uint32;
    // The largest datagram the caller will accept. A datagram longer than this
    // is `BAD_LENGTH` and stays queued, rather than being truncated into
    // something that looks like a short read.
    max_length: uint32;
};

@abi
struct FlowRecvReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    // How much of the returned object is the datagram.
    length: uint32;
    // Who sent it.
    remote: FlowAddress;
    // The datagram, in an object the service made and gives away. Read-only:
    // the caller is being given data, and no `TRANSFER`, so a datagram cannot
    // be passed on by a client that was only meant to read it — the same
    // rights `NetFrameEvent.buffer` grants for the same reason.
    payload: transfer handle<Object, {READ, MAP}>;
};

@abi
struct FlowCloseRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    flow: uint32;
    reserved: uint32;
};

@abi
struct FlowCloseReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    reserved: uint32;
};

// --- 4. The protocol --------------------------------------------------------

protocol Flow {
    // Take a local port. Required.
    1: Bind(FlowBindRequest) -> (FlowBindReply);
    // Send one datagram to `remote`. Required.
    2: SendTo(FlowSendRequest) -> (FlowSendReply);
    // Take the next datagram, or `WOULD_BLOCK`. Required.
    3: RecvFrom(FlowRecvRequest) -> (FlowRecvReply);
    // Give up a flow. Required — a service whose clients leaked flows would
    // refuse the client that opened the most rather than the one that leaked.
    4: Close(FlowCloseRequest) -> (FlowCloseReply);

    // The stream vocabulary, reserved rather than guessed. `Listen`, `Accept`
    // and `Connect` arrive with TCP and not before: their replies have to say
    // what a half-open connection is, and nothing here has one yet.
    5: reserved;
    6: reserved;
    7: reserved;
};
