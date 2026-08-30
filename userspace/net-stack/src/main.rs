// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **A network stack instance**: the thing between a program that wants to
//! send a datagram and the driver that owns the NIC.
//!
//! `docs/network/01-network-stack.md` calls this a stack instance and says a
//! component reaches one over a control channel; `docs/roadmap/03` Phase 3
//! calls the phase "The Network Is A Service" and this is the service. It
//! serves `flow_service.isl` (D273) to its client and speaks
//! `network_driver.isl` to the driver, and it is the only program in the chain
//! that knows what an IPv4 header looks like.
//!
//! **What the split buys, stated as who knows what.** The client knows DHCP
//! and not Ethernet; this program knows Ethernet, IPv4 and UDP and not what
//! they carry; the driver knows virtio and not what a datagram is. Before
//! this, one program knew all three because it had to — `net-client` built its
//! own frames because there was nothing to ask.
//!
//! **The client holds no device capability and no NIC.** It holds one endpoint
//! to this program. That is the claim this service exists to make: a program
//! reaches the network by asking, and what it can reach is what its stack
//! instance will do for it, which is where a firewall and a port authority
//! will eventually live (`docs/network/01`, "Firewall Enforcement").
//!
//! **Two channels, one loop, and a bounded queue** (D277). This program is a
//! server with two inputs — its client asks on one, the driver pushes frames
//! on the other — so it waits on both at once with `ChannelRecvAny` and never
//! blocks on one while the other has something to say. Before this it blocked
//! on whichever it was interested in: while waiting for a client request it
//! could not hear the driver, and a frame arriving then sat in the kernel
//! channel until that filled and the *driver* dropped it, reporting nothing
//! this program could see.
//!
//! **The queue is the only path a datagram takes**, not a fallback for when
//! nobody is waiting. A frame is parsed and enqueued as it arrives; a
//! `RecvFrom` is answered out of the queue, or deferred and answered when the
//! queue next has something. One path rather than two is what stops the
//! deferred case from being the untested one.
//!
//! **Bounded, and an overflow is counted rather than silent.** The queue holds
//! [`QUEUE_DEPTH`] datagrams; a further one evicts the oldest, closes its
//! object, and increments a counter this program reports — `docs/lifecycle/04`
//! is explicit that code which drops has to say so. The oldest goes because a
//! datagram that has waited longest is the most likely to be irrelevant
//! already.
//!
//! **Still one flow and one client.** A flow table needs an eviction story of
//! its own, and nothing has needed a second flow yet.
//!
//! Normative: docs/network/01-network-stack.md ("Flow API And Port Authority"),
//! docs/drivers/02-storage-networking-usb-pcie.md

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use flow_service::{
    Flow, FlowAddress, FlowBindReply, FlowBindRequest, FlowCloseReply, FlowCloseRequest,
    FlowConnectReply, FlowConnectRequest, FlowError, FlowRecvReply, FlowRecvRequest, FlowSendReply,
    FlowSendRequest,
};
use network_driver::{
    NetAttachRegionReply, NetAttachRegionRequest, NetDescribeReply, NetError, NetFrameEvent,
    NetPowerState, NetTransmitAtRequest, NetTransmitBufferRequest, NetTransmitReply, NetworkDevice,
};
use tessera_isl_runtime::{HandleRef, Ownership, decode, encode};
use tessera_sdk::{Endpoint, Error as SdkError, Handle, Platform as _, Transfer, machine::Machine};
use tessera_uabi::fail;

/// This program's whole authority, in the order boot installs it.
///
/// Three endpoints and nothing else: no device, no DMA, no memory it did not
/// make. A stack instance is not privileged — it is a component that happens
/// to be between two others.
const FLOW_SERVER_HANDLE: u64 = 0;
const DRIVER_REQUEST_HANDLE: u64 = 1;
const DRIVER_EVENT_HANDLE: u64 = 2;

/// The symmetric message buffer. The largest struct in either direction is a
/// `NetFrameEvent` at 96 bytes.
const MSG_BUF_LEN: usize = 256;

/// Where a client's outgoing payload is mapped while its frame is built.
const CLIENT_PAYLOAD_VA: u64 = 0x0000_1000_00a0_0000;
/// Where the frame handed to the driver is built.
const TX_FRAME_VA: u64 = 0x0000_1000_00b0_0000;
/// Where a frame arriving from the driver is read.
const RX_FRAME_VA: u64 = 0x0000_1000_00c0_0000;
/// Where a datagram handed back to the client is written.
const RX_PAYLOAD_VA: u64 = 0x0000_1000_00d0_0000;

/// One page holds any frame this class carries: the MTU is 1500.
const OBJECT_BYTES: u64 = 4096;

/// How long a deferred request waits before this service answers it anyway.
///
/// **The first thing in this tree that can time out.** Before `ClockRead`
/// (D281) a stack had no way to know that an answer was late: a `RecvFrom`
/// with nothing to answer waited for a frame that might never come, and a
/// `Connect` whose SYN was lost waited for ever. Neither failed — they
/// stopped, which is the failure mode hardest to tell from slowness.
///
/// A tenth of a second, measured against what this link actually takes: the
/// whole flow exchange runs in tens of milliseconds of guest time, so this is
/// comfortably longer than any legitimate wait and short enough that a check
/// can afford to sit through one.
const DEADLINE_NANOS: u64 = 100_000_000;

/// How many datagrams this service will hold for a client that has not asked
/// for them yet.
///
/// Small on purpose. A deep queue turns a slow client into memory pressure
/// somewhere else, and every entry is an object this program owns until the
/// client takes it or the queue evicts it.
const QUEUE_DEPTH: usize = 4;

/// The address this stack answers to over IPv4.
///
/// **Static, and the same one the v4 exchange above leases.** A stack that had
/// to complete DHCP before it could open a stream would be testing two things
/// at once; this is the address the emulated network hands out anyway.
const OUR_IP: [u8; 4] = [10, 0, 2, 15];

/// The initial sequence number this stack opens a connection with.
///
/// Fixed, for the reason every other constant in this check is: the kernel
/// CSPRNG is the only randomness a program here may use, and a boot check's
/// value is that it repeats itself. A predictable ISN lets an off-path
/// attacker inject into a stream, which is a real cost and stated rather than
/// hidden (`tcp::Connection::connect`).
const TCP_ISN: u32 = 0x1000_0000;

/// The only flow id this service hands out. One flow per client, so the id is
/// a constant rather than a table — and non-zero, so a client that never bound
/// cannot pass a zeroed struct and be believed.
const THE_FLOW: u32 = 1;

/// Report bits, read by the boot check.
///
/// **Byte 1, because the client reports in byte 0.** The kernel's sink
/// composes reporters by XOR, which is the right shape for several programs
/// each saying something different and the wrong one for two programs setting
/// the same bit — those cancel and read as neither having run. Disjoint ranges
/// make the composition an OR in practice, and leave each side's half legible
/// in the final word.
/// Where this program's claims start in the shared report word.
///
/// **This service owns bits 8 to 23, and the client owns 0 to 7 and 24 up.**
/// The sink XORs every reporter's word together, so two programs that pick the
/// same bit cancel each other and the run reports neither — which has now
/// happened twice (D282, and again while D284 was being written, when a fourth
/// bit here reached bit 20 and met the client's). Written down as a range
/// rather than left to be rediscovered by whoever adds the next one.
const REPORT_SHIFT: u32 = 8;
const REPORT_BOUND: u64 = 1 << REPORT_SHIFT;
const REPORT_SENT: u64 = 1 << (REPORT_SHIFT + 1);
const REPORT_RECEIVED: u64 = 1 << (REPORT_SHIFT + 2);
const REPORT_CLOSED: u64 = 1 << (REPORT_SHIFT + 3);
/// A `RecvFrom` was answered out of the queue rather than deferred — which is
/// to say a datagram was being held while the client was not asking.
const REPORT_SERVED_FROM_QUEUE: u64 = 1 << (REPORT_SHIFT + 4);
/// This station answered a Neighbour Solicitation, which is what lets a peer
/// send it a unicast IPv6 datagram at all.
const REPORT_ANSWERED_NEIGHBOUR: u64 = 1 << (REPORT_SHIFT + 5);
/// A TCP connection reached `Established` — the three-way handshake completed
/// against a peer outside this machine.
const REPORT_CONNECTED: u64 = 1 << (REPORT_SHIFT + 7);
/// A deferred request was answered by its deadline rather than by an arrival.
///
/// **Set in a passing run, and it was not always.** This began as a bit the
/// check required *clear* — a run that timed out was a run whose other claims
/// were about a network that was not answering. D282 then added a leg that
/// asks for a datagram on a port nothing sends to, precisely so that giving up
/// is exercised, and from then on a healthy run reaches this. The claim it
/// carries now is that the deadline worked, not that nothing needed one.
const REPORT_TIMED_OUT: u64 = 1 << (REPORT_SHIFT + 8);

/// A segment went out with its retransmission timer armed (D284).
const REPORT_RTO_ARMED: u64 = 1 << (REPORT_SHIFT + 9);
/// ...and an acknowledgement released it on a connection that had **never**
/// retransmitted.
///
/// **The "never" is what makes this a claim rather than a note.** A timer that
/// fired on a link losing nothing would still eventually see its segment
/// acknowledged, so a bare "it was disarmed" is set either way. This one says
/// the echo connection completed with the timer armed the whole time and never
/// firing — which is the property a badly tuned timeout breaks first, and it
/// stays a true statement about that connection even though the black-hole
/// connection later in the same run retransmits deliberately.
const REPORT_RTO_DISARMED: u64 = 1 << (REPORT_SHIFT + 10);
/// The timeout was recomputed from a measured round trip, so it follows the
/// link rather than the one-second guess RFC 6298 starts at.
const REPORT_RTT_MEASURED: u64 = 1 << (REPORT_SHIFT + 11);
/// The driver took a shared transmit region, so a frame is one message rather
/// than an object created, mapped, transferred and freed (D287).
const REPORT_REGION_ATTACHED: u64 = 1 << (REPORT_SHIFT + 14);
/// A segment was sent again because it went unacknowledged.
const REPORT_RETRANSMITTED: u64 = 1 << (REPORT_SHIFT + 12);
/// A connection was **given up on** after every retransmission went
/// unanswered, and its client was told so.
///
/// The end of the road this timer exists to build: a peer that says nothing
/// produces a connection that fails, in bounded time, with the client still
/// running.
const REPORT_GAVE_UP: u64 = 1 << (REPORT_SHIFT + 13);

/// This service evicted a datagram because its queue was full. **A check
/// requires this clear**: a run that lost data is a run whose other claims are
/// about a path that quietly dropped some.
const REPORT_DROPPED: u64 = 1 << (REPORT_SHIFT + 6);

/// Announces a claim the first time it is reached.
///
/// **A resident service cannot report at exit, because it does not exit.**
/// The driver and the device manager in this check do not either; only the
/// client does. `DebugWrite` XOR-accumulates into the one sink, so a claim
/// written once composes with every other reporter's — which is what lets this
/// program say what it did without inventing a shutdown it has no reason to
/// perform (D279). Written once: XOR means a bit sent twice cancels.
fn claim(stack: &mut Stack, bit: u64) {
    if stack.report & bit == 0 {
        stack.report |= bit;
        let _ = tessera_uabi::syscall2(SYS_DEBUG_WRITE, bit, 0);
    }
}

/// `DebugWrite`, whose `x0` the boot check XOR-accumulates.
const SYS_DEBUG_WRITE: u64 = 1;

/// `ClockRead`, and the monotonic clock's id (D281).
const SYS_CLOCK_READ: u64 = 53;
const CLOCK_MONOTONIC: u64 = 1;

/// Monotonic nanoseconds, or `None` on a machine that could not tell.
///
/// **A stack that cannot read a clock must not pretend to have one.** Every
/// caller here treats `None` as "no deadline can be enforced" rather than as
/// zero, because a deadline computed from a clock that is always zero expires
/// immediately and would turn a working exchange into a spurious failure.
fn now_nanos() -> Option<u64> {
    let v = tessera_uabi::syscall1(SYS_CLOCK_READ, CLOCK_MONOTONIC);
    match v {
        n if n > 0 => Some(n as u64),
        _ => None,
    }
}

/// What a client is waiting for, when it is waiting.
#[derive(Clone, Copy)]
enum Pending {
    /// A `RecvFrom`, and the largest datagram it will accept.
    Recv(u32),
    /// A `Connect`, which cannot be answered until the handshake finishes —
    /// the whole reason this is an enum rather than one option.
    Connect,
}

/// One datagram held for a client that has not asked for it yet.
struct Queued {
    /// The object holding just the datagram. This program owns it until the
    /// client takes it or the queue evicts it.
    payload: Handle,
    length: u32,
    remote: FlowAddress,
}

/// What this service knows about its client's flow.
struct Stack {
    /// The MAC the driver reported, which every frame this program builds
    /// needs as its source.
    mac: [u8; 6],
    /// Whether a flow is open: which family, and on which local port.
    ///
    /// **The family is part of the binding**, so a datagram of the other one
    /// arriving on the same port is not this flow's. A stack that matched on
    /// the port alone would hand a v6 datagram to a v4 flow the moment both
    /// families used a well-known port with the same number.
    bound: Option<(u32, u16)>,
    /// Which claims this run has reached, reported once at exit.
    report: u64,
    /// Datagrams received and not yet handed to the client, oldest first.
    queue: [Option<Queued>; QUEUE_DEPTH],
    /// What the client is blocked in, if anything.
    pending: Option<Pending>,
    /// The stream, when this flow carries one.
    ///
    /// **A connection is a property of the flow, not a second kind of flow.**
    /// After `Connect` the same `SendTo` and `RecvFrom` carry stream bytes,
    /// which is what a socket does and what keeps this from growing a parallel
    /// set of methods (D280).
    stream: Option<tessera_net::tcp::Connection>,
    /// Where the stream's peer is, needed for every segment's pseudo-header.
    peer: Option<([u8; 4], u16)>,
    /// Datagrams evicted because the queue was full. **Reported, never
    /// silent**: a stack that drops is allowed to, and a stack that drops
    /// quietly is a stack whose client cannot tell a lost datagram from one
    /// that was never sent.
    dropped: u32,
    /// The shared transmit region, when the driver took one (D287).
    ///
    /// **Held for as long as this service runs**, because holding it is what
    /// keeps the driver's mapping of it alive: the object's frames go when the
    /// last holder lets go, and the driver is the other one. `Some` also means
    /// [`TX_FRAME_VA`] is permanently mapped, so a frame is built there
    /// without a create and a map first — which is the entire saving.
    tx_region: Option<Handle>,
    /// The deepest the queue ever got, which is the only honest way to say
    /// whether [`QUEUE_DEPTH`] is the right size.
    high_water: u32,
    /// When the pending request stops being worth waiting for, in monotonic
    /// nanoseconds — `None` when nothing is pending or the machine has no
    /// clock to set one against.
    deadline: Option<u64>,
}

impl Stack {
    /// Puts a datagram at the back, evicting the oldest if there is no room.
    fn enqueue(&mut self, entry: Queued) {
        if self.queue[QUEUE_DEPTH - 1].is_some() {
            // Full: the oldest goes, and its object with it — an evicted entry
            // whose handle stayed open would leak the memory *and* keep this
            // program's mapping window occupied.
            if let Some(evicted) = self.queue[0].take() {
                let _ = Machine.close(evicted.payload);
                self.dropped = self.dropped.saturating_add(1);
                // Announced immediately, for the reason `claim` gives: a
                // service that drops has to say so, and this one has no exit
                // at which to say it later.
                if self.report & REPORT_DROPPED == 0 {
                    self.report |= REPORT_DROPPED;
                    let _ = tessera_uabi::syscall2(SYS_DEBUG_WRITE, REPORT_DROPPED, 0);
                }
            }
            self.queue.rotate_left(1);
        }
        for slot in self.queue.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                break;
            }
        }
        let depth = self.queue.iter().filter(|s| s.is_some()).count() as u32;
        self.high_water = self.high_water.max(depth);
    }

    /// Takes the oldest datagram the client will accept.
    ///
    /// A datagram longer than `max_length` is **left where it is** rather than
    /// truncated or discarded: a short read a caller cannot distinguish from a
    /// whole one is the failure `max_length` exists to prevent, and dropping it
    /// would make the caller's own bound the reason its data vanished.
    fn dequeue(&mut self, max_length: u32) -> Option<Queued> {
        let at = self
            .queue
            .iter()
            .position(|s| s.as_ref().is_some_and(|q| q.length <= max_length))?;
        let taken = self.queue[at].take();
        self.queue[at..].rotate_left(1);
        taken
    }

    /// Gives up everything still held. Called when the flow closes, because an
    /// object nobody will ever ask for is a leak with a longer fuse.
    fn drain(&mut self) {
        for slot in self.queue.iter_mut() {
            if let Some(entry) = slot.take() {
                let _ = Machine.close(entry.payload);
            }
        }
    }
}

/// Asks the driver what it is, which is where the MAC comes from.
fn describe() -> Result<[u8; 6], u64> {
    let mut request = [0u8; MSG_BUF_LEN];
    let control = network_driver::NetControlRequest {
        size: network_driver::NetControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: NetPowerState::Active,
        enable: 0,
    };
    if encode(
        &control,
        &mut request[..network_driver::NetControlRequest::WIRE_SIZE],
    )
    .is_err()
    {
        return Err(fail(0x90, 0xe));
    }
    let mut reply = [0u8; MSG_BUF_LEN];
    let n = Machine
        .call(
            Endpoint(Handle(DRIVER_REQUEST_HANDLE)),
            NetworkDevice::DESCRIBE,
            &request[..network_driver::NetControlRequest::WIRE_SIZE],
            &mut reply,
        )
        .map_err(|_| fail(0x90, 1))?;
    if n < NetDescribeReply::WIRE_SIZE {
        return Err(fail(0x90, 2));
    }
    let described = decode::<NetDescribeReply>(&reply[..NetDescribeReply::WIRE_SIZE])
        .map_err(|_| fail(0x90, 3))?;
    let low = described.mac_low.to_le_bytes();
    let high = described.mac_high.to_le_bytes();
    Ok([low[0], low[1], low[2], low[3], high[0], high[1]])
}

/// An IPv4 endpoint, in the wide address field.
fn address(addr: [u8; 4], port: u16) -> FlowAddress {
    let mut wide = [0u8; 16];
    wide[..4].copy_from_slice(&addr);
    FlowAddress {
        size: FlowAddress::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        family: 4,
        port: u32::from(port),
        addr: wide,
        reserved: 0,
    }
}

/// An IPv6 endpoint.
fn address6(addr: [u8; 16], port: u16) -> FlowAddress {
    FlowAddress {
        size: FlowAddress::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        family: 6,
        port: u32::from(port),
        addr,
        reserved: 0,
    }
}

/// The local endpoint a bind reply reports: the unspecified address of the
/// bound family, and the port actually taken.
fn local_address(family: u32, port: u16) -> FlowAddress {
    if family == 6 {
        address6(tessera_net::ipv6::UNSPECIFIED, port)
    } else {
        address([0, 0, 0, 0], port)
    }
}

/// `Bind`: take a local port.
fn serve_bind(stack: &mut Stack, bytes: &[u8], out: &mut [u8]) -> Result<usize, u64> {
    // **Exactly the struct's own bytes.** A decoder handed the slack after a
    // smaller message has trailing bytes to account for and refuses; the
    // receive buffer is sized for the largest request on this contract, so
    // every smaller one arrives with slack behind it.
    let request = decode::<FlowBindRequest>(
        bytes
            .get(..FlowBindRequest::WIRE_SIZE)
            .ok_or(fail(0x91, 1))?,
    )
    .map_err(|_| fail(0x91, 0xd))?;
    // **The reserved capability field must be zero.** There is no namespace
    // broker to resolve a port-range capability against, so a non-zero value is
    // a client claiming authority nothing checked — refused rather than
    // ignored, which is what keeps the field usable when a broker exists.
    let status = if request.port_authority != 0 {
        FlowError::Protocol
    } else if request.local.family != 4 && request.local.family != 6 {
        FlowError::Protocol
    } else if stack.bound.is_some() {
        // One flow per client. `EXHAUSTED` rather than `PORT_UNAVAILABLE`:
        // the port is not the thing in the way.
        FlowError::Exhausted
    } else {
        let port = request.local.port as u16;
        stack.bound = Some((request.local.family, port));
        claim(stack, REPORT_BOUND);
        FlowError::Ok
    };
    let reply = FlowBindReply {
        size: FlowBindReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        flow: if status == FlowError::Ok { THE_FLOW } else { 0 },
        local: match stack.bound {
            Some((family, port)) => local_address(family, port),
            None => local_address(4, 0),
        },
    };
    encode(&reply, &mut out[..FlowBindReply::WIRE_SIZE]).map_err(|_| fail(0x91, 0xe))?;
    Ok(FlowBindReply::WIRE_SIZE)
}

/// `SendTo`: wrap the client's payload in three headers and hand it to the
/// driver.
fn serve_send(
    stack: &mut Stack,
    bytes: &[u8],
    payload_handle: Option<Handle>,
    out: &mut [u8],
) -> Result<usize, u64> {
    let request = decode::<FlowSendRequest>(
        bytes
            .get(..FlowSendRequest::WIRE_SIZE)
            .ok_or(fail(0x92, 1))?,
    )
    .map_err(|_| fail(0x92, 0xd))?;
    let (status, sent) = match send(stack, &request, payload_handle) {
        Ok(sent) => {
            claim(stack, REPORT_SENT);
            (FlowError::Ok, sent)
        }
        Err(status) => (status, 0),
    };
    let reply = FlowSendReply {
        size: FlowSendReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        sent,
    };
    encode(&reply, &mut out[..FlowSendReply::WIRE_SIZE]).map_err(|_| fail(0x92, 0xe))?;
    Ok(FlowSendReply::WIRE_SIZE)
}

/// The send path proper, so the reply above has one thing to report.
fn send(
    stack: &mut Stack,
    request: &FlowSendRequest,
    payload_handle: Option<Handle>,
) -> Result<u32, FlowError> {
    let Some((family, local_port)) = stack.bound else {
        return Err(FlowError::NoSuchFlow);
    };
    // A flow bound to one family does not send in the other. The two use
    // different headers and different pseudo-headers, and a caller that mixed
    // them would be asking for a datagram nothing on the link would answer.
    if request.remote.family != family {
        return Err(FlowError::Protocol);
    }
    // **A connected flow sends a segment, not a datagram.** The contract says
    // `SendTo` carries stream bytes once `Connect` has run, so the transport
    // is a property of the flow rather than of the method — which is what
    // stops this growing a second `Send` that differs only in that (D280).
    if stack.stream.is_some() {
        return send_stream_bytes(stack, request, payload_handle);
    }
    if request.flow != THE_FLOW {
        return Err(FlowError::NoSuchFlow);
    }
    // The ordinal says a payload was transferred; without one there is nothing
    // to send, and a zero-length datagram is not what was asked for.
    let Some(handle) = payload_handle else {
        return Err(FlowError::Protocol);
    };
    let length = request.length as usize;
    if length == 0 || length > tessera_net::MAX_FRAME_LEN - tessera_net::HEADERS_LEN {
        // The handle is dropped below on every path, including this one.
        let _ = Machine.close(handle);
        return Err(FlowError::BadLength);
    }

    let mut frame_len = 0usize;
    let result = (|| -> Result<(), FlowError> {
        Machine
            .memory_map_readable(handle, CLIENT_PAYLOAD_VA)
            .map_err(|_| FlowError::Protocol)?;
        // SAFETY: the kernel just mapped this object read-only at
        // `CLIENT_PAYLOAD_VA`; `length` is bounded above by the largest
        // payload this crate builds, so it lies inside the object's first
        // page, and this is the only reference formed to the range.
        let payload =
            unsafe { core::slice::from_raw_parts(CLIENT_PAYLOAD_VA as *const u8, length) };

        let (out, held) = begin_frame(stack)?;
        // **Built first, then judged, so the window is given back either way.**
        // The `?` this used to end each arm with returned before the transmit
        // object was closed, which leaked a page for every frame that failed to
        // build — invisible while nothing failed, and a fallback path is
        // exactly where something eventually does.
        let built = if family == 6 {
            // **The source is the link-local this station formed from its own
            // MAC.** A v6 host has one before it has anything else, which is
            // what makes a stateless exchange possible with nothing
            // configured. The destination must be multicast, because resolving
            // a unicast one needs Neighbour Discovery nothing here implements
            // — `build_udp6_frame` refuses rather than guessing a MAC.
            tessera_net::build_udp6_frame(
                out,
                stack.mac,
                tessera_net::ipv6::link_local_from_mac(stack.mac),
                request.remote.addr,
                local_port,
                request.remote.port as u16,
                payload,
            )
            .ok_or(FlowError::Unreachable)
        } else {
            let mut v4 = [0u8; 4];
            v4.copy_from_slice(&request.remote.addr[..4]);
            tessera_net::build_udp_frame(
                out,
                stack.mac,
                tessera_net::eth::BROADCAST,
                tessera_net::ipv4::UNSPECIFIED,
                v4,
                local_port,
                request.remote.port as u16,
                0,
                payload,
            )
            .ok_or(FlowError::BadLength)
        };
        frame_len = match built {
            Ok(len) => len,
            Err(status) => {
                abort_frame(held);
                return Err(status);
            }
        };
        finish_frame(held, frame_len)
    })();
    // The client's payload is given away either way: it was transferred, so it
    // is this program's to free, and holding it would also leave
    // `CLIENT_PAYLOAD_VA` occupied for the next call.
    let _ = Machine.close(handle);
    result?;
    Ok(frame_len as u32)
}

/// Sends `payload` on the flow's stream.
///
/// Split from the datagram path rather than branching inside it: the two share
/// only the buffer handling, and a single function that switched transport
/// halfway would be two functions with one name.
fn send_stream_bytes(
    stack: &mut Stack,
    request: &FlowSendRequest,
    payload_handle: Option<Handle>,
) -> Result<u32, FlowError> {
    let Some(handle) = payload_handle else {
        return Err(FlowError::Protocol);
    };
    let length = request.length as usize;
    let outcome = (|| -> Result<u32, FlowError> {
        let (peer_addr, _) = stack.peer.ok_or(FlowError::NoSuchFlow)?;
        if stack.stream.is_none() {
            return Err(FlowError::NoSuchFlow);
        }
        if length == 0 || length > MAX_STREAM_SEND {
            return Err(FlowError::BadLength);
        }
        Machine
            .memory_map_readable(handle, CLIENT_PAYLOAD_VA)
            .map_err(|_| FlowError::Protocol)?;
        // SAFETY: the kernel just mapped this object read-only at
        // `CLIENT_PAYLOAD_VA`; `length` is bounded above, so it lies inside
        // the object's first page, and this is the only reference to it.
        let payload =
            unsafe { core::slice::from_raw_parts(CLIENT_PAYLOAD_VA as *const u8, length) };
        let peers = tessera_net::udp::Peers::V4 {
            src: OUR_IP,
            dst: peer_addr,
        };
        let mut segment = [0u8; MAX_STREAM_SEND + tessera_net::tcp::HEADER_LEN];
        // **Borrowed, not copied out and put back.** The connection carries a
        // send buffer now, which is about a kilobyte; copying it twice per
        // segment on the path a packet takes was affordable when it held one
        // and is not now. The borrow ends with this statement, which is what
        // lets `transmit_ipv4` take the stack mutably below.
        let conn = stack.stream.as_mut().ok_or(FlowError::NoSuchFlow)?;
        let len = conn
            .send(&mut segment, peers, payload, now_nanos().unwrap_or(0))
            // **Refused, not sent.** A payload past what the connection can
            // hold, or a second write while the first is unacknowledged: both
            // are segments this end could not send again (D284).
            .ok_or(FlowError::BadLength)?;
        transmit_ipv4(
            stack,
            peer_addr,
            tessera_net::tcp::PROTOCOL,
            &segment[..len],
        )?;
        Ok(length as u32)
    })();
    // The client's payload was transferred; this program frees it either way,
    // which also frees the mapping window for the next call.
    let _ = Machine.close(handle);
    outcome
}

/// The largest stream write this stack will take in one call.
///
/// **One segment's worth**, because there is no send buffer to split a larger
/// write across. It is now exactly what the connection can hold for
/// retransmission (`tcp::MAX_SEGMENT_PAYLOAD`): a write this stack accepted
/// and could not send again would be one the timer cannot protect, which is
/// the stall D284 removed reappearing in the one place nobody would look for
/// it. It was 512 while nothing could retransmit anything.
const MAX_STREAM_SEND: usize = tessera_net::tcp::MAX_SEGMENT_PAYLOAD;

/// Hands the built frame to the driver over `TransmitBuffer` (D272).
/// Creates the shared transmit region and offers it to the driver.
///
/// **One object, shared once, and every frame after it is one message.** A
/// frame handed over as its own object costs an object created, mapped,
/// transferred and freed — four kernel round trips, and the same four whether
/// the frame is a 290-byte DHCP DISCOVER or a bare acknowledgement. This pays
/// those four at startup instead (D287).
///
/// Silent on refusal, because a refusal is a conformant driver saying it does
/// not implement an optional method, and the caller's answer to that is to
/// carry on with the per-frame path.
fn attach_transmit_region(stack: &mut Stack) {
    let Ok(region) = Machine.memory_create(OBJECT_BYTES) else {
        return;
    };
    if Machine.memory_map(region, TX_FRAME_VA).is_err() {
        let _ = Machine.close(region);
        return;
    }
    let request = NetAttachRegionRequest {
        size: NetAttachRegionRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        length: OBJECT_BYTES,
        region: HandleRef::new(0),
    };
    let mut bytes = [0u8; NetAttachRegionRequest::WIRE_SIZE];
    if encode(&request, &mut bytes).is_err() {
        let _ = Machine.close(region);
        return;
    }
    let give = [Transfer {
        handle: region,
        // Read off the contract rather than typed to match it — and here that
        // check is load-bearing rather than decorative: a schema saying
        // `transfer` and a sender saying `share` would hand the object away
        // and leave this service building frames into memory it no longer owns.
        rights: match NetAttachRegionRequest::REGION_OWNERSHIP {
            Ownership::Share => NetAttachRegionRequest::REGION_RIGHTS,
            _ => {
                let _ = Machine.close(region);
                return;
            }
        },
        shared: true,
    }];
    let mut reply = [0u8; MSG_BUF_LEN];
    let taken = Machine.call_with(
        Endpoint(Handle(DRIVER_REQUEST_HANDLE)),
        NetworkDevice::ATTACH_TRANSMIT_REGION,
        &bytes,
        &mut reply,
        &give,
        &mut [],
    );
    let accepted = matches!(taken, Ok((n, _)) if n >= NetAttachRegionReply::WIRE_SIZE)
        && decode::<NetAttachRegionReply>(&reply[..NetAttachRegionReply::WIRE_SIZE])
            .is_ok_and(|answered| answered.status == NetError::Ok as u32);
    if accepted {
        stack.tx_region = Some(region);
        claim(stack, REPORT_REGION_ATTACHED);
    } else {
        // **Unmapped as well as closed.** The window has to be free again for
        // the per-frame path, which maps each frame's object at the same
        // address — and a mapping left behind would refuse every one of them.
        let _ = Machine.unmap(TX_FRAME_VA, OBJECT_BYTES);
        let _ = Machine.close(region);
    }
}

/// Sends `frame_len` bytes already built at [`TX_FRAME_VA`] in the shared
/// region.
fn transmit_at(frame_len: usize) -> Result<(), FlowError> {
    let request = NetTransmitAtRequest {
        size: NetTransmitAtRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        // Offset zero, because this service builds one frame at a time and
        // waits for the reply before touching the region again. A second
        // offset would need a ring's producer and consumer indices, which is
        // the contract's own note on why it does not have one.
        offset: 0,
        length: frame_len as u32,
    };
    let mut bytes = [0u8; NetTransmitAtRequest::WIRE_SIZE];
    encode(&request, &mut bytes).map_err(|_| FlowError::Protocol)?;
    let mut reply = [0u8; MSG_BUF_LEN];
    let n = Machine
        .call(
            Endpoint(Handle(DRIVER_REQUEST_HANDLE)),
            NetworkDevice::TRANSMIT_AT,
            &bytes,
            &mut reply,
        )
        .map_err(|_| FlowError::Unreachable)?;
    if n < NetTransmitReply::WIRE_SIZE {
        return Err(FlowError::Unreachable);
    }
    let answered = decode::<NetTransmitReply>(&reply[..NetTransmitReply::WIRE_SIZE])
        .map_err(|_| FlowError::Protocol)?;
    match answered.status {
        s if s == NetError::Ok as u32 => Ok(()),
        s if s == NetError::LinkDown as u32 => Err(FlowError::Unreachable),
        s if s == NetError::BadLength as u32 => Err(FlowError::BadLength),
        _ => Err(FlowError::Protocol),
    }
}

/// Opens the transmit window and returns a writable slice into it.
///
/// `Some(handle)` back means the per-frame path: the object is this call's to
/// hand over, or to close if the frame cannot be built. `None` means the
/// shared region, which is mapped for the life of the service and belongs to
/// nobody in particular.
fn begin_frame(stack: &Stack) -> Result<(&'static mut [u8], Option<Handle>), FlowError> {
    let held = if stack.tx_region.is_some() {
        None
    } else {
        let object = Machine
            .memory_create(OBJECT_BYTES)
            .map_err(|_| FlowError::Exhausted)?;
        if Machine.memory_map(object, TX_FRAME_VA).is_err() {
            let _ = Machine.close(object);
            return Err(FlowError::Protocol);
        }
        Some(object)
    };
    // SAFETY: `TX_FRAME_VA` is mapped read-write for `OBJECT_BYTES` — by the
    // region attach for the life of this service, or by the map just above —
    // and this service builds one frame at a time, so no other reference to
    // the range is live.
    let out =
        unsafe { core::slice::from_raw_parts_mut(TX_FRAME_VA as *mut u8, OBJECT_BYTES as usize) };
    Ok((out, held))
}

/// Sends what [`begin_frame`] opened, by whichever route it opened.
fn finish_frame(held: Option<Handle>, frame_len: usize) -> Result<(), FlowError> {
    match held {
        Some(object) => transmit(object, frame_len),
        None => transmit_at(frame_len),
    }
}

/// Gives up a frame that could not be built.
fn abort_frame(held: Option<Handle>) {
    if let Some(object) = held {
        let _ = Machine.close(object);
    }
}

fn transmit(frame: Handle, frame_len: usize) -> Result<(), FlowError> {
    let request = NetTransmitBufferRequest {
        size: NetTransmitBufferRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        length: frame_len as u32,
        reserved: 0,
        buffer: HandleRef::new(0),
    };
    let mut bytes = [0u8; NetTransmitBufferRequest::WIRE_SIZE];
    encode(&request, &mut bytes).map_err(|_| FlowError::Protocol)?;
    let give = [Transfer {
        handle: frame,
        // Read off the contract rather than typed to match it.
        rights: match NetTransmitBufferRequest::BUFFER_OWNERSHIP {
            Ownership::Transfer => NetTransmitBufferRequest::BUFFER_RIGHTS,
            _ => return Err(FlowError::Protocol),
        },
        shared: false,
    }];
    let mut reply = [0u8; MSG_BUF_LEN];
    let (n, _) = Machine
        .call_with(
            Endpoint(Handle(DRIVER_REQUEST_HANDLE)),
            NetworkDevice::TRANSMIT_BUFFER,
            &bytes,
            &mut reply,
            &give,
            &mut [],
        )
        .map_err(|_| FlowError::Unreachable)?;
    if n < NetTransmitReply::WIRE_SIZE {
        return Err(FlowError::Unreachable);
    }
    let answered = decode::<NetTransmitReply>(&reply[..NetTransmitReply::WIRE_SIZE])
        .map_err(|_| FlowError::Protocol)?;
    match answered.status {
        s if s == NetError::Ok as u32 => Ok(()),
        s if s == NetError::LinkDown as u32 => Err(FlowError::Unreachable),
        s if s == NetError::BadLength as u32 => Err(FlowError::BadLength),
        _ => Err(FlowError::Protocol),
    }
}

/// `RecvFrom`: answer out of the queue, or defer until something arrives.
///
/// Returns `None` when the request is deferred — the client stays blocked in
/// its call and is answered later, from [`answer_pending`], which is the whole
/// reason this program waits on both channels at once.
fn serve_recv(
    stack: &mut Stack,
    bytes: &[u8],
) -> Result<Option<(usize, [u8; MSG_BUF_LEN], Option<Handle>)>, u64> {
    let request = decode::<FlowRecvRequest>(
        bytes
            .get(..FlowRecvRequest::WIRE_SIZE)
            .ok_or(fail(0x93, 1))?,
    )
    .map_err(|_| fail(0x93, 0xd))?;
    let bad = if stack.bound.is_none() || request.flow != THE_FLOW {
        Some(FlowError::NoSuchFlow)
    } else {
        None
    };
    if let Some(status) = bad {
        return Ok(Some((
            refusal(status, &mut [0u8; MSG_BUF_LEN])?,
            [0u8; MSG_BUF_LEN],
            None,
        )));
    }
    match stack.dequeue(request.max_length) {
        Some(entry) => {
            claim(stack, REPORT_RECEIVED);
            claim(stack, REPORT_SERVED_FROM_QUEUE);
            let (len, buf) = recv_reply(FlowError::Ok, entry.length, entry.remote)?;
            Ok(Some((len, buf, Some(entry.payload))))
        }
        None => {
            // Nothing to answer with. Remember what was asked and keep serving
            // both channels; the frame that arrives next is what answers it —
            // or the deadline does, if none ever comes.
            stack.pending = Some(Pending::Recv(request.max_length));
            stack.deadline = now_nanos().map(|t| t + DEADLINE_NANOS);
            Ok(None)
        }
    }
}

/// Encodes a receive reply. Separate because both the immediate and the
/// deferred path build the same message, and two copies of it would be two
/// places for the status and the length to disagree.
fn recv_reply(
    status: FlowError,
    length: u32,
    remote: FlowAddress,
) -> Result<(usize, [u8; MSG_BUF_LEN]), u64> {
    let reply = FlowRecvReply {
        size: FlowRecvReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        length,
        remote,
        payload: HandleRef::new(0),
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    encode(&reply, &mut buf[..FlowRecvReply::WIRE_SIZE]).map_err(|_| fail(0x93, 0xe))?;
    Ok((FlowRecvReply::WIRE_SIZE, buf))
}

/// A bare status, for the arms whose only answer is a refusal.
fn refusal(status: FlowError, out: &mut [u8; MSG_BUF_LEN]) -> Result<usize, u64> {
    let reply = FlowCloseReply {
        size: FlowCloseReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        reserved: 0,
    };
    encode(&reply, &mut out[..FlowCloseReply::WIRE_SIZE]).map_err(|_| fail(0x95, 0xe))?;
    Ok(FlowCloseReply::WIRE_SIZE)
}

/// `Connect`: open a stream, and answer when the handshake finishes.
///
/// Returns `Some(len)` when the request is refused outright and `None` when a
/// SYN went out and the client stays blocked — the same deferral `RecvFrom`
/// uses, for the same reason: a connect that returned before the connection
/// existed would make every caller invent its own way to wait.
fn serve_connect(stack: &mut Stack, bytes: &[u8], out: &mut [u8]) -> Result<Option<usize>, u64> {
    let request = decode::<FlowConnectRequest>(
        bytes
            .get(..FlowConnectRequest::WIRE_SIZE)
            .ok_or(fail(0x96, 1))?,
    )
    .map_err(|_| fail(0x96, 0xd))?;
    let refuse = |status: FlowError, out: &mut [u8]| -> Result<Option<usize>, u64> {
        let reply = FlowConnectReply {
            size: FlowConnectReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status: status as u32,
            reserved: 0,
            local: local_address(4, 0),
        };
        encode(&reply, &mut out[..FlowConnectReply::WIRE_SIZE]).map_err(|_| fail(0x96, 0xe))?;
        Ok(Some(FlowConnectReply::WIRE_SIZE))
    };
    let Some((family, local_port)) = stack.bound else {
        return refuse(FlowError::NoSuchFlow, out);
    };
    if request.flow != THE_FLOW || stack.stream.is_some() {
        return refuse(FlowError::NoSuchFlow, out);
    }
    // **IPv4 only.** A v6 stream needs a neighbour for its unicast
    // destination, and this stack resolves none — `build_udp6_frame` refuses a
    // unicast address for exactly that reason, and a stream would need one.
    if family != 4 || request.remote.family != 4 {
        return refuse(FlowError::Protocol, out);
    }
    let mut remote = [0u8; 4];
    remote.copy_from_slice(&request.remote.addr[..4]);
    let remote_port = request.remote.port as u16;

    // The initial sequence number. Fixed, for the reason every other constant
    // in this check is: the kernel CSPRNG is the only randomness a program
    // here may use, and this is a boot check whose value is repeating itself.
    let mut conn = tessera_net::tcp::Connection::connect(local_port, remote_port, TCP_ISN);
    let mut segment = [0u8; 64];
    let peers = tessera_net::udp::Peers::V4 {
        src: OUR_IP,
        dst: remote,
    };
    // **The clock the retransmission timer runs on** (D284). A machine that
    // cannot read one gets a connection with no timer rather than one with a
    // broken timer: the loop below never asks an unarmed connection what time
    // it is, so the moment recorded here is read by nobody.
    let now = now_nanos().unwrap_or(0);
    let Some(len) = conn.syn(&mut segment, peers, now) else {
        return refuse(FlowError::Protocol, out);
    };
    if transmit_ipv4(stack, remote, tessera_net::tcp::PROTOCOL, &segment[..len]).is_err() {
        return refuse(FlowError::Unreachable, out);
    }
    stack.stream = Some(conn);
    claim(stack, REPORT_RTO_ARMED);
    stack.peer = Some((remote, remote_port));
    stack.pending = Some(Pending::Connect);
    // **No deadline of its own, and that is the point** (D284). A connect is
    // answered when the handshake completes or when the transport gives up
    // retransmitting the SYN — the transport's timer is the right bound and
    // knows the difference between slow and never. The fixed 100 ms this used
    // to set was a second, worse answer to the same question: it reported
    // `UNREACHABLE` while the SYN was still in flight and left the connection
    // retransmitting behind the client's back.
    stack.deadline = None;
    Ok(None)
}

/// Answers a deferred `Connect` once the handshake has completed.
fn answer_connect(stack: &mut Stack) -> Result<(), u64> {
    let Some(Pending::Connect) = stack.pending else {
        return Ok(());
    };
    let (status, local_port) = {
        let Some(conn) = stack.stream.as_ref() else {
            return Ok(());
        };
        let status = match conn.state {
            tessera_net::tcp::State::Established => FlowError::Ok,
            tessera_net::tcp::State::Reset => FlowError::Unreachable,
            // Still handshaking: keep waiting.
            _ => return Ok(()),
        };
        (status, conn.local_port)
    };
    stack.pending = None;
    stack.deadline = None;
    if status == FlowError::Ok {
        claim(stack, REPORT_CONNECTED);
    }
    let reply = FlowConnectReply {
        size: FlowConnectReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        reserved: 0,
        local: local_address(4, local_port),
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    encode(&reply, &mut buf[..FlowConnectReply::WIRE_SIZE]).map_err(|_| fail(0x96, 0xe))?;
    Machine
        .respond(
            Endpoint(Handle(FLOW_SERVER_HANDLE)),
            &buf[..FlowConnectReply::WIRE_SIZE],
        )
        .map_err(|_| fail(0x96, 2))?;
    Ok(())
}

/// Wraps `payload` in an IPv4 header of `protocol` and hands the frame to the
/// driver.
///
/// **The gateway's MAC is not resolved.** Every frame this stack sends goes to
/// the broadcast address, which the emulated network answers as readily as a
/// unicast — a real link needs ARP, and that is the v4 counterpart of the
/// neighbour discovery D279 added for v6. Named rather than hidden.
fn transmit_ipv4(
    stack: &mut Stack,
    dst: [u8; 4],
    protocol: u8,
    payload: &[u8],
) -> Result<(), FlowError> {
    let (out, held) = begin_frame(stack)?;
    let Some(len) = tessera_net::build_ipv4_frame(
        out,
        stack.mac,
        tessera_net::eth::BROADCAST,
        OUR_IP,
        dst,
        protocol,
        0,
        payload,
    ) else {
        abort_frame(held);
        return Err(FlowError::BadLength);
    };
    finish_frame(held, len)
}

/// Takes a frame the driver pushed and puts whatever is ours into the queue.
///
/// **Every frame ends here and every frame is released here.** The driver gave
/// it away, so this program owns it: one that is not ours, or does not parse,
/// is closed rather than kept, and the datagram inside one that is ours is
/// copied into an object of this program's own before the frame goes.
fn absorb_frame(stack: &mut Stack, frame_handle: Handle, frame_len: usize) {
    // **Neighbour Discovery first, and it is not optional** (D279). IPv6 has
    // no ARP: a peer that wants to send this host a unicast datagram asks who
    // holds the address and waits for an answer. A stack that never answers is
    // one nothing can reply to — the DHCPv6 request went out, the server
    // solicited, and the Reply was never sent because there was nowhere to
    // send it. This is the stack's own business and the client never sees it.
    //
    // **The frame is mapped exactly once**, and both readers work off that one
    // slice. Mapping it twice is not idempotent — the second call is refused
    // because the window is occupied — so a neighbour check that mapped on its
    // own left every datagram behind it unreadable. That was a real regression
    // and it presented as no traffic at all rather than as a mapping error.
    if frame_len == 0 || frame_len > OBJECT_BYTES as usize {
        let _ = Machine.close(frame_handle);
        return;
    }
    if Machine
        .memory_map_readable(frame_handle, RX_FRAME_VA)
        .is_err()
    {
        let _ = Machine.close(frame_handle);
        return;
    }
    // SAFETY: the kernel just mapped this object read-only at `RX_FRAME_VA`;
    // `frame_len` is bounded by the object's size above, and this is the only
    // reference formed to the range.
    let frame = unsafe { core::slice::from_raw_parts(RX_FRAME_VA as *const u8, frame_len) };
    let answered = answer_solicitation(stack, frame);
    // A stream's segments go to the connection rather than the queue: they are
    // not datagrams, and what a client receives from a stream is bytes in
    // order rather than whatever arrived.
    let consumed = !answered && absorb_segment(stack, frame);
    let taken = if answered || consumed {
        None
    } else {
        take_datagram(frame, stack.mac, stack.bound)
    };
    // The driver gave the frame away; this program frees it either way, which
    // also frees `RX_FRAME_VA` for the next one.
    let _ = Machine.close(frame_handle);
    if let Some(entry) = taken {
        stack.enqueue(entry);
    }
}

/// Answers a Neighbour Solicitation for this station, returning whether the
/// frame was one.
fn answer_solicitation(stack: &mut Stack, frame: &[u8]) -> bool {
    let mut reply = [0u8; 128];
    let Some(len) = tessera_net::answer_neighbour_solicitation(frame, &mut reply, stack.mac) else {
        return false;
    };
    // Built into this program's own buffer first, because the frame it answers
    // is still mapped: the transmit object is a separate one, and the caller
    // closes the incoming frame either way.
    let Ok((out, held)) = begin_frame(stack) else {
        return true;
    };
    if len > out.len() {
        abort_frame(held);
        return true;
    }
    out[..len].copy_from_slice(&reply[..len]);
    let _ = finish_frame(held, len);
    claim(stack, REPORT_ANSWERED_NEIGHBOUR);
    true
}

/// Feeds a TCP segment to the connection, returning whether the frame was one.
///
/// Data the connection accepts is queued as though it were a datagram, so a
/// client's `RecvFrom` reaches it through the one path everything else uses.
fn absorb_segment(stack: &mut Stack, frame: &[u8]) -> bool {
    let Some((peer_addr, _)) = stack.peer else {
        return false;
    };
    if stack.stream.is_none() {
        return false;
    }
    let Some((src, dst, protocol, payload)) = tessera_net::parse_ipv4_frame(frame, stack.mac)
    else {
        return false;
    };
    if protocol != tessera_net::tcp::PROTOCOL || src != peer_addr || dst != OUR_IP {
        return false;
    }
    let peers = tessera_net::udp::Peers::V4 { src, dst };
    let Some(segment) = tessera_net::tcp::parse(payload, peers) else {
        return false;
    };
    let mut reply = [0u8; 64];
    let ours = tessera_net::udp::Peers::V4 { src: dst, dst: src };
    // **The borrow covers the advance and nothing else.** Everything below
    // needs `stack` mutably — the transmit, the queue, the claims — so what
    // they need from the connection is read out here, while it is borrowed,
    // rather than by holding the borrow across them. The connection used to be
    // copied out and put back for this; it carries a send buffer now, and a
    // kilobyte copied twice per frame is not a per-packet path.
    let (data, ack, outstanding, retransmitted, measured, measured_before, in_flight) = {
        let conn = match stack.stream.as_mut() {
            Some(conn) => conn,
            None => return false,
        };
        let measured_before = conn.srtt.is_some();
        let (data, ack) = conn.on_segment(&segment, &mut reply, ours, now_nanos().unwrap_or(0));
        (
            data,
            ack,
            conn.awaiting_ack(),
            conn.retransmissions,
            conn.srtt.is_some(),
            measured_before,
            conn.segments_in_flight(),
        )
    };
    // **Not reported, and the reason is worth stating.** How many segments
    // are outstanding at once here depends on whether the peer's
    // acknowledgement beats the client's next request, and on this link it
    // usually does — so a claim about it would be a claim that fails on a fast
    // network. The send buffer's behaviour is asserted in `api/net`, where the
    // peer is written by the test and the question has an answer (D285).
    let _ = in_flight;
    // **Disarmed by an acknowledgement rather than by firing**, which is the
    // half of the claim a healthy link can show: the timer was armed when the
    // segment went out and is not armed now, and nothing was sent twice.
    if !outstanding && retransmitted == 0 {
        claim(stack, REPORT_RTO_DISARMED);
    }
    if measured && !measured_before {
        claim(stack, REPORT_RTT_MEASURED);
    }
    if data > 0 {
        // Stream bytes reach the client through the same queue a datagram
        // does. `remote` is the connected peer, which is what a caller
        // receiving on a connected flow expects to be told.
        let start = segment.payload.len() - data;
        if let Some(entry) = hold_bytes(&segment.payload[start..], address(src, segment.src_port)) {
            stack.enqueue(entry);
        }
    }
    if let Some(len) = ack {
        let _ = transmit_ipv4(stack, peer_addr, tessera_net::tcp::PROTOCOL, &reply[..len]);
    }
    let _ = answer_connect(stack);
    true
}

/// Copies bytes into an object of this program's own, ready to hand up.
fn hold_bytes(bytes: &[u8], remote: FlowAddress) -> Option<Queued> {
    if bytes.is_empty() || bytes.len() > OBJECT_BYTES as usize {
        return None;
    }
    let object = Machine.memory_create(OBJECT_BYTES).ok()?;
    if Machine.memory_map(object, RX_PAYLOAD_VA).is_err() {
        let _ = Machine.close(object);
        return None;
    }
    // SAFETY: just created and mapped read-write at `RX_PAYLOAD_VA`; the copy
    // is bounded by the object's size, and nothing else references the range.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), RX_PAYLOAD_VA as *mut u8, bytes.len());
    }
    let entry = Queued {
        payload: object,
        length: bytes.len() as u32,
        remote,
    };
    let _ = Machine.unmap(RX_PAYLOAD_VA, OBJECT_BYTES);
    Some(entry)
}

/// Sends again whatever the stream has outstanding past its timeout, and gives
/// the connection up when it has run out of attempts.
///
/// **Called on every pass of the serve loop, not only on a timeout** (D284).
/// The loop wakes for whatever comes first — a client request, a frame, its
/// own deadline — and a retransmission that is due is due regardless of which
/// of those woke it. Asking here rather than only in the timeout arm is what
/// keeps a busy link from postponing a retransmission indefinitely.
fn expire_retransmission(stack: &mut Stack) -> Result<(), u64> {
    let Some(conn) = stack.stream.as_ref() else {
        return Ok(());
    };
    // **The question that costs nothing is asked first.** Whether anything is
    // outstanding is a field; what time it is, is a syscall — and this runs on
    // every pass of the serve loop, so reading the clock before checking
    // whether there is a timer to compare it against would put a trap on the
    // per-packet path to answer a question that is usually "nothing".
    let Some(deadline) = conn.retransmit_at() else {
        return Ok(());
    };
    let (Some(now), Some((peer_addr, _))) = (now_nanos(), stack.peer) else {
        return Ok(());
    };
    if now < deadline {
        return Ok(());
    }
    let peers = tessera_net::udp::Peers::V4 {
        src: OUR_IP,
        dst: peer_addr,
    };
    let mut segment = [0u8; MAX_STREAM_SEND + tessera_net::tcp::HEADER_LEN];
    let (again, state) = {
        let Some(conn) = stack.stream.as_mut() else {
            return Ok(());
        };
        let again = conn.on_timeout(&mut segment, peers, now);
        (again, conn.state)
    };
    match again {
        Some(len) => {
            claim(stack, REPORT_RETRANSMITTED);
            let _ = transmit_ipv4(
                stack,
                peer_addr,
                tessera_net::tcp::PROTOCOL,
                &segment[..len],
            );
        }
        // **Given up on, and the client is told rather than left waiting.**
        // A connection that ran out of attempts is the case this whole
        // mechanism exists for: without it the client sits in its `Connect`
        // until its own deadline and learns "not yet" instead of "not ever".
        None if state == tessera_net::tcp::State::Aborted => {
            claim(stack, REPORT_GAVE_UP);
            answer_aborted(stack)?;
        }
        None => {}
    }
    Ok(())
}

/// Tells a client whose stream was given up on.
fn answer_aborted(stack: &mut Stack) -> Result<(), u64> {
    let Some(pending) = stack.pending else {
        return Ok(());
    };
    stack.pending = None;
    stack.deadline = None;
    let mut reply = [0u8; MSG_BUF_LEN];
    let len = match pending {
        Pending::Connect => {
            let answer = FlowConnectReply {
                size: FlowConnectReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status: FlowError::Unreachable as u32,
                reserved: 0,
                local: local_address(4, 0),
            };
            encode(&answer, &mut reply[..FlowConnectReply::WIRE_SIZE])
                .map_err(|_| fail(0x9e, 0xe))?;
            FlowConnectReply::WIRE_SIZE
        }
        // A read on a stream whose peer stopped answering: the contract's
        // `UNREACHABLE`, for the same reason.
        Pending::Recv(_) => {
            let answer = FlowRecvReply {
                size: FlowRecvReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status: FlowError::Unreachable as u32,
                length: 0,
                remote: local_address(4, 0),
                payload: HandleRef::new(0),
            };
            encode(&answer, &mut reply[..FlowRecvReply::WIRE_SIZE]).map_err(|_| fail(0x9e, 0xe))?;
            FlowRecvReply::WIRE_SIZE
        }
    };
    Machine
        .respond(Endpoint(Handle(FLOW_SERVER_HANDLE)), &reply[..len])
        .map_err(|_| fail(0x9e, 1))?;
    Ok(())
}

/// Answers a deferred request that has waited past its deadline.
///
/// **What a clock buys, stated as behaviour.** Without one this service could
/// only wait; a request whose answer was never coming stopped the client for
/// the rest of the boot, and nothing distinguished that from a slow network.
/// With one it answers `WOULD_BLOCK` — which the contract already defines and
/// already says is not an error in the ordinary sense — and stays serving.
fn expire_pending(stack: &mut Stack) -> Result<(), u64> {
    let (Some(pending), Some(deadline)) = (stack.pending, stack.deadline) else {
        return Ok(());
    };
    // **A `Connect` has no deadline of its own** (D284), so it never arrives
    // here: it is answered by the handshake, or by the transport giving up on
    // the SYN in [`expire_retransmission`]. Named rather than swept into a
    // wildcard, because the alternative reading — that a connect *should* be
    // answered here — is the one this comment exists to refuse.
    let Pending::Recv(_) = pending else {
        return Ok(());
    };
    let Some(now) = now_nanos() else {
        return Ok(());
    };
    if now < deadline {
        return Ok(());
    }
    stack.pending = None;
    stack.deadline = None;
    claim(stack, REPORT_TIMED_OUT);
    let (len, buf) = recv_reply(FlowError::WouldBlock, 0, address([0, 0, 0, 0], 0))?;
    Machine
        .respond(Endpoint(Handle(FLOW_SERVER_HANDLE)), &buf[..len])
        .map_err(|_| fail(0x97, 1))?;
    Ok(())
}

/// Answers a deferred `RecvFrom` if the queue can now satisfy it.
fn answer_pending(stack: &mut Stack) -> Result<(), u64> {
    let Some(Pending::Recv(max_length)) = stack.pending else {
        return Ok(());
    };
    let Some(entry) = stack.dequeue(max_length) else {
        return Ok(());
    };
    stack.pending = None;
    stack.deadline = None;
    claim(stack, REPORT_RECEIVED);
    let (len, buf) = recv_reply(FlowError::Ok, entry.length, entry.remote)?;
    Machine
        .respond_with(
            Endpoint(Handle(FLOW_SERVER_HANDLE)),
            &buf[..len],
            &[Transfer {
                handle: entry.payload,
                rights: FlowRecvReply::PAYLOAD_RIGHTS,
                shared: false,
            }],
        )
        .map_err(|_| fail(0x93, 2))?;
    Ok(())
}

/// Maps a received frame, checks it is this flow's, and copies the datagram
/// into a fresh object.
///
/// **A copy, and a second object, and both are forced.** The frame belongs to
/// this program now, but the *client* must not be handed it: the frame holds
/// somebody else's headers, and the contract says a caller receives a
/// datagram. Handing back a page whose first 42 bytes are link and network
/// state would make every client parse them.
///
/// **No `max_length` here**, unlike before. A datagram is admitted to the
/// queue on its own merits and a caller's bound is applied when it is taken
/// out — otherwise one client's small buffer would decide what the stack was
/// allowed to have received.
fn take_datagram(frame: &[u8], mac: [u8; 6], bound: Option<(u32, u16)>) -> Option<Queued> {
    let (family, local_port) = bound?;
    // **Parsed as the bound family and not the other**, so a frame is admitted
    // by the flow it belongs to rather than by whichever parser accepts it
    // first.
    let (remote, payload) = if family == 6 {
        let got =
            tessera_net::parse_udp6_frame(frame, mac, tessera_net::ipv6::link_local_from_mac(mac))?;
        if got.dst_port != local_port {
            return None;
        }
        (address6(got.src_addr, got.src_port), got.payload)
    } else {
        let got = tessera_net::parse_udp_frame(frame, mac)?;
        if got.dst_port != local_port {
            return None;
        }
        (address(got.src_addr, got.src_port), got.payload)
    };
    let datagram = payload;
    let object = Machine.memory_create(OBJECT_BYTES).ok()?;
    if Machine.memory_map(object, RX_PAYLOAD_VA).is_err() {
        let _ = Machine.close(object);
        return None;
    }
    // SAFETY: just created and mapped read-write at `RX_PAYLOAD_VA`; the copy
    // is bounded by the frame's length, itself bounded by the object's size,
    // and nothing else references the range.
    unsafe {
        core::ptr::copy_nonoverlapping(datagram.as_ptr(), RX_PAYLOAD_VA as *mut u8, datagram.len());
    }
    let entry = Queued {
        payload: object,
        length: datagram.len() as u32,
        remote,
    };
    // The mapping goes now, not when the object is handed over: the next frame
    // needs this window, and an object mapped here cannot also be mapped by
    // whoever receives it.
    let _ = Machine.unmap(RX_PAYLOAD_VA, OBJECT_BYTES);
    Some(entry)
}

/// `Close`: give up the flow.
fn serve_close(stack: &mut Stack, bytes: &[u8], out: &mut [u8]) -> Result<usize, u64> {
    let request = decode::<FlowCloseRequest>(
        bytes
            .get(..FlowCloseRequest::WIRE_SIZE)
            .ok_or(fail(0x94, 1))?,
    )
    .map_err(|_| fail(0x94, 0xd))?;
    stack.deadline = None;
    let status = if request.flow == THE_FLOW && stack.bound.take().is_some() {
        // **The connection goes with the flow.** A stream is a property of the
        // flow (D280), so closing the flow ends it — and leaving it behind
        // meant the next `Connect` was refused for the rest of the run,
        // because this service holds one stream at a time and the old one was
        // still there.
        stack.stream = None;
        stack.peer = None;
        claim(stack, REPORT_CLOSED);
        FlowError::Ok
    } else {
        FlowError::NoSuchFlow
    };
    let reply = FlowCloseReply {
        size: FlowCloseReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        reserved: 0,
    };
    encode(&reply, &mut out[..FlowCloseReply::WIRE_SIZE]).map_err(|_| fail(0x94, 0xe))?;
    Ok(FlowCloseReply::WIRE_SIZE)
}

/// The serve loop: **both channels at once**.
///
/// Hand-written rather than `sdk::serve_many`, because that helper answers
/// every request it dispatches and this one sometimes does not: a `RecvFrom`
/// with nothing to answer is deferred, and the reply goes out later from
/// [`answer_pending`] when a frame arrives. That deferral is the whole point —
/// a server that replied to everything immediately would have to block on the
/// driver inside the handler, which is what it used to do and what left the
/// other channel unheard.
fn run() -> u64 {
    let mac = match describe() {
        Ok(mac) => mac,
        Err(code) => return code,
    };
    let mut stack = Stack {
        mac,
        bound: None,
        report: 0,
        queue: [const { None }; QUEUE_DEPTH],
        pending: None,
        deadline: None,
        stream: None,
        peer: None,
        dropped: 0,
        high_water: 0,
        tx_region: None,
    };
    // **Asked for once, and a refusal is not a failure.** `AttachTransmitRegion`
    // is optional on this class, so a driver that answers `NOT_SUPPORTED` is
    // conformant and this service falls back to handing over an object per
    // frame — which is what it did before D287 and what the contract still
    // defines.
    attach_transmit_region(&mut stack);
    let endpoints = [
        Endpoint(Handle(FLOW_SERVER_HANDLE)),
        Endpoint(Handle(DRIVER_EVENT_HANDLE)),
    ];
    let mut buf = [0u8; MSG_BUF_LEN];
    // **Asked once, because the answer cannot change.** A machine either has a
    // counter this kernel could calibrate or it does not (D281), and a timer
    // is either real or absent for the life of the run — reading it per pass
    // would be a syscall on the loop's hot path to learn something settled at
    // boot.
    let has_clock = now_nanos().is_some();
    loop {
        // **What this waits on depends on whether a flow is open**, and that is
        // what lets the service finish. `ChannelRecvAny` returns only when one
        // of its endpoints has a message or *all* their peers have gone — so a
        // stack that always waited on both kept waiting after its client
        // exited, because the driver was still there. A stack with no flow
        // open has no reason to listen to the wire: waiting on the client
        // alone means the client going away ends the loop, which is the one
        // thing that should (D279).
        let waiting = if stack.bound.is_some() {
            &endpoints[..]
        } else {
            &endpoints[..1]
        };
        // **A deadline only means something while a request is waiting on it.**
        // One left behind by a served request expires the *next* wait
        // immediately, and every wait after it — a spin that serves nobody and
        // looks like a hang. Derived from `pending` rather than stored beside
        // it, so the two cannot disagree.
        let client_deadline = stack.pending.is_some().then_some(stack.deadline).flatten();
        // **And the retransmission timer is a deadline this loop must not
        // sleep past** (D284). It belongs to the connection rather than to any
        // client request — a segment stays unacknowledged whether or not
        // anybody is currently asking for anything — so a loop that waited on
        // the client's deadline alone would sleep through every loss, which is
        // exactly the stall the timer was written to end.
        //
        // The earlier of the two, because waking early costs one pass round
        // this loop and waking late costs whichever deadline was missed.
        let retransmit = stack
            .stream
            .as_ref()
            .and_then(|conn| conn.retransmit_at())
            .filter(|_| has_clock);
        let until = match (client_deadline, retransmit) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let mut handles = [Handle(0); 1];
        // **The wait itself carries the deadline now** (D282). Before this the
        // service could measure that time had passed but only when something
        // else woke it, so total silence on the link still stopped it; the
        // receive is woken by the deadline itself.
        let (which, request) =
            match Machine.receive_any_until(waiting, &mut buf, &mut handles, until) {
                Ok(pair) => pair,
                // A deadline that expired is not the peer leaving: send again
                // whatever went unacknowledged, answer the request that was
                // waiting if its own deadline is what passed, and keep
                // serving.
                Err(SdkError::TimedOut) => {
                    if let Err(code) = expire_retransmission(&mut stack) {
                        return code;
                    }
                    if let Err(code) = expire_pending(&mut stack) {
                        return code;
                    }
                    continue;
                }
                // **The peer going away is the only thing that ends this loop.**
                // `Close` used to, which is wrong the moment a client opens a
                // second flow: it closed the first and found the service gone, and
                // the failure looked like a client that hung rather than a server
                // that left (D279). A flow's lifetime is not the connection's.
                Err(_) => break,
            };
        let arrived = (request.handles > 0).then_some(handles[0]);
        let taken = buf;

        // **Checked whenever this loop wakes, which is as often as it can be.**
        // `ChannelRecvAny` has no deadline argument — `docs/api/01`'s
        // cancellation-and-timeouts surface is still designed — so nothing
        // wakes this service to notice that time passed. What a clock buys
        // here is that a request whose answer is never coming is answered the
        // next time *anything* arrives, instead of stopping the client for the
        // rest of the boot. Total silence on the link still stops it, and that
        // needs a deadline on the receive rather than a clock (D281).
        if let Err(code) = expire_retransmission(&mut stack) {
            return code;
        }
        if let Err(code) = expire_pending(&mut stack) {
            return code;
        }

        // The driver's channel: a frame, and nobody asked for it.
        if which == 1 {
            if request.method == NetworkDevice::ON_FRAME_RECEIVED
                && let Some(frame_handle) = arrived
                && let Ok(event) = decode::<NetFrameEvent>(&taken[..NetFrameEvent::WIRE_SIZE])
            {
                absorb_frame(&mut stack, frame_handle, event.length as usize);
            } else if let Some(handle) = arrived {
                // An event this program does not act on still carried a
                // capability, and it is this program's now.
                let _ = Machine.close(handle);
            }
            if let Err(code) = answer_pending(&mut stack) {
                return code;
            }
            continue;
        }

        // The client's channel.
        let mut reply = [0u8; MSG_BUF_LEN];
        let answer = match request.method {
            Flow::BIND => match serve_bind(&mut stack, &taken, &mut reply) {
                Ok(len) => Some((len, None)),
                Err(code) => return code,
            },
            Flow::SEND_TO => match serve_send(&mut stack, &taken, arrived, &mut reply) {
                Ok(len) => Some((len, None)),
                Err(code) => return code,
            },
            Flow::RECV_FROM => match serve_recv(&mut stack, &taken) {
                Ok(Some((len, bytes, give))) => {
                    reply = bytes;
                    Some((len, give))
                }
                // Deferred: the client stays in its call.
                Ok(None) => None,
                Err(code) => return code,
            },
            Flow::CLOSE => match serve_close(&mut stack, &taken, &mut reply) {
                Ok(len) => Some((len, None)),
                Err(code) => return code,
            },
            Flow::CONNECT => match serve_connect(&mut stack, &taken, &mut reply) {
                // Answered now, because it was refused now.
                Ok(Some(len)) => Some((len, None)),
                // The SYN is out; the reply waits for the handshake.
                Ok(None) => None,
                Err(code) => return code,
            },
            // An ordinal this contract does not define. A refusal the client
            // should hear rather than a reason to die holding its request.
            _ => match refusal(FlowError::Protocol, &mut reply) {
                Ok(len) => Some((len, None)),
                Err(code) => return code,
            },
        };

        if let Some((len, give)) = answer {
            let outcome = match give {
                Some(handle) => Machine.respond_with(
                    endpoints[0],
                    &reply[..len],
                    &[Transfer {
                        handle,
                        rights: FlowRecvReply::PAYLOAD_RIGHTS,
                        shared: false,
                    }],
                ),
                None => Machine.respond(endpoints[0], &reply[..len]),
            };
            if outcome.is_err() {
                break;
            }
        }
    }
    stack.drain();
    // **Nothing is reported here**, because every claim was announced when it
    // was reached. This program is resident: reaching this line means its
    // client went away, which is not itself a claim about anything.
    0
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in this
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    Machine.finish(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    Machine.finish(fail(0x9f, 0))
}
