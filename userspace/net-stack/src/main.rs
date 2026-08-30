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
    Flow, FlowAddress, FlowBindReply, FlowBindRequest, FlowCloseReply, FlowCloseRequest, FlowError,
    FlowRecvReply, FlowRecvRequest, FlowSendReply, FlowSendRequest,
};
use network_driver::{
    NetDescribeReply, NetError, NetFrameEvent, NetPowerState, NetTransmitBufferRequest,
    NetTransmitReply, NetworkDevice,
};
use tessera_isl_runtime::{HandleRef, Ownership, decode, encode};
use tessera_sdk::{Endpoint, Handle, Platform as _, Transfer, machine::Machine};
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

/// How many datagrams this service will hold for a client that has not asked
/// for them yet.
///
/// Small on purpose. A deep queue turns a slow client into memory pressure
/// somewhere else, and every entry is an object this program owns until the
/// client takes it or the queue evicts it.
const QUEUE_DEPTH: usize = 4;

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
    /// A `RecvFrom` the client is blocked in that had nothing to answer with,
    /// and the largest datagram it will accept.
    pending: Option<u32>,
    /// Datagrams evicted because the queue was full. **Reported, never
    /// silent**: a stack that drops is allowed to, and a stack that drops
    /// quietly is a stack whose client cannot tell a lost datagram from one
    /// that was never sent.
    dropped: u32,
    /// The deepest the queue ever got, which is the only honest way to say
    /// whether [`QUEUE_DEPTH`] is the right size.
    high_water: u32,
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

        let frame = Machine
            .memory_create(OBJECT_BYTES)
            .map_err(|_| FlowError::Exhausted)?;
        Machine
            .memory_map(frame, TX_FRAME_VA)
            .map_err(|_| FlowError::Protocol)?;
        // SAFETY: the object was just created and mapped read-write at
        // `TX_FRAME_VA`; `OBJECT_BYTES` is its whole size and nothing else
        // references it.
        let out = unsafe {
            core::slice::from_raw_parts_mut(TX_FRAME_VA as *mut u8, OBJECT_BYTES as usize)
        };
        frame_len = if family == 6 {
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
            .ok_or(FlowError::Unreachable)?
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
            .ok_or(FlowError::BadLength)?
        };
        transmit(frame, frame_len)
    })();
    // The client's payload is given away either way: it was transferred, so it
    // is this program's to free, and holding it would also leave
    // `CLIENT_PAYLOAD_VA` occupied for the next call.
    let _ = Machine.close(handle);
    result?;
    Ok(frame_len as u32)
}

/// Hands the built frame to the driver over `TransmitBuffer` (D272).
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
            // both channels; the frame that arrives next is what answers it.
            stack.pending = Some(request.max_length);
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
    let taken = if answered {
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
    let Ok(object) = Machine.memory_create(OBJECT_BYTES) else {
        return true;
    };
    if Machine.memory_map(object, TX_FRAME_VA).is_err() {
        let _ = Machine.close(object);
        return true;
    }
    // SAFETY: just created and mapped read-write at `TX_FRAME_VA`; `len` is
    // bounded by `reply`'s size, and nothing else references the range.
    unsafe {
        core::ptr::copy_nonoverlapping(reply.as_ptr(), TX_FRAME_VA as *mut u8, len);
    }
    let _ = transmit(object, len);
    claim(stack, REPORT_ANSWERED_NEIGHBOUR);
    true
}

/// Answers a deferred `RecvFrom` if the queue can now satisfy it.
fn answer_pending(stack: &mut Stack) -> Result<(), u64> {
    let Some(max_length) = stack.pending else {
        return Ok(());
    };
    let Some(entry) = stack.dequeue(max_length) else {
        return Ok(());
    };
    stack.pending = None;
    claim(stack, REPORT_RECEIVED);
    let (len, buf) = recv_reply(FlowError::Ok, entry.length, entry.remote)?;
    Machine
        .respond_with(
            Endpoint(Handle(FLOW_SERVER_HANDLE)),
            &buf[..len],
            &[Transfer {
                handle: entry.payload,
                rights: FlowRecvReply::PAYLOAD_RIGHTS,
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
    let status = if request.flow == THE_FLOW && stack.bound.take().is_some() {
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
        dropped: 0,
        high_water: 0,
    };
    let endpoints = [
        Endpoint(Handle(FLOW_SERVER_HANDLE)),
        Endpoint(Handle(DRIVER_EVENT_HANDLE)),
    ];
    let mut buf = [0u8; MSG_BUF_LEN];
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
        let mut handles = [Handle(0); 1];
        let (which, request) = match Machine.receive_any(waiting, &mut buf, &mut handles) {
            Ok(pair) => pair,
            // **The peer going away is the only thing that ends this loop.**
            // `Close` used to, which is wrong the moment a client opens a
            // second flow: it closed the first and found the service gone, and
            // the failure looked like a client that hung rather than a server
            // that left (D279). A flow's lifetime is not the connection's.
            Err(_) => break,
        };
        let arrived = (request.handles > 0).then_some(handles[0]);
        let taken = buf;

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
