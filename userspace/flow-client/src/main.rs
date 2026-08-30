// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **A program that reaches the network by asking.**
//!
//! What it holds is one endpoint to a stack instance. No device capability, no
//! DMA, no NIC, and no knowledge of Ethernet — this program cannot name a MAC
//! address and does not contain the constant. It binds a port, sends a DHCP
//! DISCOVER as a *payload*, and reads the OFFER out of what comes back.
//!
//! **The layering is the claim.** `net-client` builds its own Ethernet, IPv4
//! and UDP headers because until D273 there was nothing to ask; this program
//! speaks `flow_service.isl` and DHCP and nothing in between. Everything below
//! UDP is the stack instance's business, which is what `docs/network/01` means
//! by a flow API and what `docs/roadmap/03` Phase 3 means by the network being
//! a service.
//!
//! Reporting: one bit per claim, or a `0xdead_...` failure code.
//!
//! Normative: docs/network/01-network-stack.md ("Flow API And Port Authority")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use flow_service::{
    Flow, FlowAddress, FlowBindReply, FlowBindRequest, FlowCloseReply, FlowCloseRequest,
    FlowConnectReply, FlowConnectRequest, FlowError, FlowRecvReply, FlowRecvRequest, FlowSendReply,
    FlowSendRequest,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_net::{dhcp, dhcpv6, ipv6};
use tessera_sdk::{Endpoint, Error as SdkError, Handle, Platform as _, Transfer, machine::Machine};
use tessera_uabi::fail;

/// The one endpoint this program holds.
const STACK_HANDLE: u64 = 0;

const MSG_BUF_LEN: usize = 256;

/// Where the outgoing DHCP payload is built, and where a received one is read.
const TX_PAYLOAD_VA: u64 = 0x0000_1000_00e0_0000;
const RX_PAYLOAD_VA: u64 = 0x0000_1000_00f0_0000;
const OBJECT_BYTES: u64 = 4096;

/// The MAC this client puts in its DHCP message.
///
/// **A DHCP client names its own hardware address, and that is a fact about
/// DHCP rather than a capability.** The `chaddr` field is what the server keys
/// its lease on; it is inside the payload, so it is this program's to fill in.
/// Nothing here can send a frame with it — the stack instance supplies the
/// Ethernet source, and this constant reaching it changes nothing about what
/// this program may do.
const CLIENT_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// The transaction the offer must echo. Fixed for the reason `net-client`
/// gives: this is a boot check whose value is doing the same thing every run,
/// and the kernel CSPRNG is the only randomness a program may use.
const DHCP_XID: u32 = 0x5445_5354;

/// What SLIRP always offers first, and the server it offers from.
const EXPECTED_OFFER: [u8; 4] = [10, 0, 2, 15];
const EXPECTED_SERVER: [u8; 4] = [10, 0, 2, 2];

/// The recursive name server the emulated network always names over IPv6:
/// the third address of its prefix, exactly as 10.0.2.3 is over IPv4.
const SLIRP_V6_DNS: [u8; 16] = [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03];

/// The v6 transaction, which is 24 bits rather than 32.
const DHCPV6_XID: u32 = 0x00ab_cdef;

/// The TCP peer: an echo server the emulated network runs for this check, and
/// the port it listens on.
///
/// **A host command behind a guest address**, which is the only deterministic
/// TCP peer this backend offers — it forwards nothing outward here, and a
/// service that depended on the host's network would be a check that depended
/// on the machine it ran on. The same trade `api/ext2` makes by having
/// `mke2fs` lay out its image.
const ECHO_ADDR: [u8; 4] = [10, 0, 2, 100];
const ECHO_PORT: u16 = 9;
/// The ephemeral port this client connects from.
const ECHO_LOCAL_PORT: u16 = 40000;
/// What goes out, and must come back byte for byte.
const ECHO_BYTES: &[u8] = b"tessera";

/// A port the emulated network never sends to, for the leg that proves a
/// receive can give up.
const QUIET_PORT: u16 = 40001;

/// **A TCP peer that says nothing at all**, for the leg that proves a
/// connection can give up.
///
/// This station's own address, and the choice is the whole of why the leg is
/// deterministic. QEMU's user-mode network terminates TCP on the host side and
/// answers everything it is asked — a closed port with a reset, an outside
/// address by opening a host socket whose failure depends on the host's
/// routing table. Neither is silence. A segment addressed to the guest itself
/// is not something slirp forwards anywhere, so it is dropped and nothing
/// comes back, on any host, with no `restrict=on` and no filter (D284).
///
/// Measured, not reasoned: the wire was captured for this address and for an
/// unassigned one, and only this one was silent.
const BLACKHOLE_ADDR: [u8; 4] = [10, 0, 2, 15];
/// The ephemeral port that connection goes out from.
const BLACKHOLE_LOCAL_PORT: u16 = 40002;

/// How many datagrams this exchange puts in flight before reading any answer.
///
/// **Two, and the second one is the test.** One proves only the deferred path,
/// where the client asks before anything has arrived. The queue's other half —
/// holding a datagram that arrived while nobody was asking — needs a moment
/// when nobody is asking, and with one datagram in flight there is never one.
const DATAGRAMS: usize = 2;

const REPORT_BOUND: u64 = 1 << 0;
const REPORT_SENT: u64 = 1 << 1;
const REPORT_OFFER: u64 = 1 << 2;
const REPORT_CLOSED: u64 = 1 << 3;
/// A refusal this client asked for and got: binding with a port capability
/// nobody can resolve is rejected rather than ignored.
const REPORT_AUTHORITY_REFUSED: u64 = 1 << 4;
/// The same exchange over IPv6: a stateless DHCPv6 Information-Request out and
/// a Reply back, through the same contract and the same stack instance.
const REPORT_V6_REPLY: u64 = 1 << 5;
/// A TCP connection opened to a peer outside this machine.
const REPORT_CONNECTED: u64 = 1 << 6;
/// And carried bytes: what went out came back.
const REPORT_ECHOED: u64 = 1 << 7;
/// A receive on a flow nobody is sending to came back `WOULD_BLOCK` instead of
/// never coming back. **The only claim in this check that is about time**: it
/// is false on a kernel where the deadline is recorded and not acted on, which
/// nothing else here would notice (D282).
///
/// **Bit 24, and the number is the whole lesson.** This program's own bits are
/// byte 0 and the stack instance's are 8 to 23; a ninth bit here first landed
/// on the stack's first, and the sink XORs — so the two claims cancelled and
/// the run reported neither (D282). It moved to bit 20, which the stack then
/// grew into while D284 was being written, so the regions are now stated in
/// `net-stack`'s `REPORT_SHIFT` and this program's overflow starts at 24. The
/// report is a shared address space, and running off the end of one program's
/// byte is running into another's.
const REPORT_TIMED_OUT: u64 = 1 << 24;
/// A **call** that gave up: a request into a channel with an open peer that
/// nobody is serving came back `TimedOut` instead of never coming back.
///
/// The other half of the same claim. `REPORT_TIMED_OUT` is a receive the
/// service bounded on this client's behalf, which works only for as long as
/// the service is there to do it; this one is the client bounding its own wait
/// and is the only thing that survives a service that stops (D283).
const REPORT_CALL_TIMED_OUT: u64 = 1 << 25;
/// A connection to a peer that never answered was **given up on** rather than
/// waited on forever: the retransmission timer sent the SYN again, backed off,
/// ran out of attempts, and the service answered `UNREACHABLE` (D284).
const REPORT_GAVE_UP: u64 = 1 << 26;
const REPORT_TAG: u64 = 0x5e << 56;

/// How long this client waits for an answer that is never coming, in
/// nanoseconds.
///
/// **Long enough to be a deadline and not a race.** Everything else in this
/// run is faster than this by orders of magnitude, so a leg that expires
/// cannot be a leg that was merely slow; and it is short enough that a kernel
/// which never expires it hangs the check rather than delaying it, which is
/// the failure worth having.
const SILENCE_BUDGET_NS: u64 = 20_000_000;

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

/// Calls the stack and returns the reply bytes.
fn call(method: u32, request: &[u8], reply: &mut [u8]) -> Result<usize, u64> {
    Machine
        .call(Endpoint(Handle(STACK_HANDLE)), method, request, reply)
        .map_err(|_| fail(0xa0, u64::from(method)))
}

/// `Bind`, with the port capability field set to `authority`.
fn bind(family: u32, port: u16, authority: u32) -> Result<FlowBindReply, u64> {
    let local = if family == 6 {
        address6(ipv6::UNSPECIFIED, port)
    } else {
        address([0, 0, 0, 0], port)
    };
    let request = FlowBindRequest {
        size: FlowBindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        local,
        port_authority: authority,
        reserved: 0,
    };
    let mut bytes = [0u8; FlowBindRequest::WIRE_SIZE];
    encode(&request, &mut bytes).map_err(|_| fail(0xa1, 0xe))?;
    let mut reply = [0u8; MSG_BUF_LEN];
    let n = call(Flow::BIND, &bytes, &mut reply)?;
    if n < FlowBindReply::WIRE_SIZE {
        return Err(fail(0xa1, 1));
    }
    decode::<FlowBindReply>(&reply[..FlowBindReply::WIRE_SIZE]).map_err(|_| fail(0xa1, 0xd))
}

/// Builds the DHCP DISCOVER into a fresh object and hands it to the stack.
fn send_discover(flow: u32) -> Result<u32, u64> {
    let handle = Machine
        .memory_create(OBJECT_BYTES)
        .map_err(|_| fail(0xa2, 1))?;
    Machine
        .memory_map(handle, TX_PAYLOAD_VA)
        .map_err(|_| fail(0xa2, 2))?;
    // SAFETY: just created and mapped read-write at `TX_PAYLOAD_VA`;
    // `OBJECT_BYTES` is the object's whole size and nothing else references it.
    let out =
        unsafe { core::slice::from_raw_parts_mut(TX_PAYLOAD_VA as *mut u8, OBJECT_BYTES as usize) };
    let Some(len) = dhcp::build_discover(out, CLIENT_MAC, DHCP_XID) else {
        return Err(fail(0xa2, 3));
    };

    let request = FlowSendRequest {
        size: FlowSendRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow,
        length: len as u32,
        // Broadcast: a client with no address cannot be answered by unicast,
        // because the sender would have to ARP for an address nobody has yet.
        remote: address([255, 255, 255, 255], dhcp::SERVER_PORT),
        payload: HandleRef::new(0),
    };
    let mut bytes = [0u8; FlowSendRequest::WIRE_SIZE];
    encode(&request, &mut bytes).map_err(|_| fail(0xa2, 0xe))?;
    let mut reply = [0u8; MSG_BUF_LEN];
    let (n, _) = Machine
        .call_with(
            Endpoint(Handle(STACK_HANDLE)),
            Flow::SEND_TO,
            &bytes,
            &mut reply,
            &[Transfer {
                handle,
                rights: FlowSendRequest::PAYLOAD_RIGHTS,
            }],
            &mut [],
        )
        .map_err(|_| fail(0xa2, 4))?;
    if n < FlowSendReply::WIRE_SIZE {
        return Err(fail(0xa2, 5));
    }
    let answered =
        decode::<FlowSendReply>(&reply[..FlowSendReply::WIRE_SIZE]).map_err(|_| fail(0xa2, 0xd))?;
    if answered.status != FlowError::Ok as u32 {
        return Err(fail(0xa2, u64::from(answered.status)));
    }
    Ok(answered.sent)
}

/// `RecvFrom`, and reads the offer out of the datagram that comes back.
/// Opens a stream to the echo server.
/// Asks for a connection and returns the status the service answered with.
///
/// The status is returned rather than judged, because two legs want opposite
/// answers from it: the echo leg needs `OK`, and the leg that connects to a
/// peer which says nothing needs `UNREACHABLE`.
fn connect_to(flow: u32, remote: [u8; 4], port: u16) -> Result<u32, u64> {
    let request = FlowConnectRequest {
        size: FlowConnectRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow,
        reserved: 0,
        remote: address(remote, port),
    };
    let mut bytes = [0u8; FlowConnectRequest::WIRE_SIZE];
    encode(&request, &mut bytes).map_err(|_| fail(0xac, 0xe))?;
    let mut reply = [0u8; MSG_BUF_LEN];
    let n = call(Flow::CONNECT, &bytes, &mut reply)?;
    if n < FlowConnectReply::WIRE_SIZE {
        return Err(fail(0xac, 1));
    }
    let answered = decode::<FlowConnectReply>(&reply[..FlowConnectReply::WIRE_SIZE])
        .map_err(|_| fail(0xac, 0xd))?;
    Ok(answered.status)
}

fn connect(flow: u32) -> Result<(), u64> {
    match connect_to(flow, ECHO_ADDR, ECHO_PORT)? {
        status if status == FlowError::Ok as u32 => Ok(()),
        status => Err(fail(0xac, u64::from(status))),
    }
}

/// Sends bytes on a connected flow. The remote is the connected peer, which
/// the contract says the flow already knows.
fn send_stream(flow: u32, bytes: &[u8]) -> Result<(), u64> {
    let handle = Machine
        .memory_create(OBJECT_BYTES)
        .map_err(|_| fail(0xad, 1))?;
    Machine
        .memory_map(handle, TX_PAYLOAD_VA)
        .map_err(|_| fail(0xad, 2))?;
    // SAFETY: just created and mapped read-write at `TX_PAYLOAD_VA`;
    // `bytes.len()` is far inside the object and nothing else references it.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), TX_PAYLOAD_VA as *mut u8, bytes.len());
    }
    let request = FlowSendRequest {
        size: FlowSendRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow,
        length: bytes.len() as u32,
        remote: address(ECHO_ADDR, ECHO_PORT),
        payload: HandleRef::new(0),
    };
    let mut buf = [0u8; FlowSendRequest::WIRE_SIZE];
    encode(&request, &mut buf).map_err(|_| fail(0xad, 0xe))?;
    let mut reply = [0u8; MSG_BUF_LEN];
    let (n, _) = Machine
        .call_with(
            Endpoint(Handle(STACK_HANDLE)),
            Flow::SEND_TO,
            &buf,
            &mut reply,
            &[Transfer {
                handle,
                rights: FlowSendRequest::PAYLOAD_RIGHTS,
            }],
            &mut [],
        )
        .map_err(|_| fail(0xad, 3))?;
    if n < FlowSendReply::WIRE_SIZE {
        return Err(fail(0xad, 4));
    }
    let answered =
        decode::<FlowSendReply>(&reply[..FlowSendReply::WIRE_SIZE]).map_err(|_| fail(0xad, 0xd))?;
    if answered.status != FlowError::Ok as u32 {
        return Err(fail(0xad, u64::from(answered.status)));
    }
    Ok(())
}

/// Reads what the echo server sent back and checks it byte for byte.
fn receive_echo(flow: u32) -> Result<(), u64> {
    let (length, handle, _) = receive_datagram(flow, 0xae)?;
    Machine
        .memory_map_readable(handle, RX_PAYLOAD_VA)
        .map_err(|_| fail(0xae, 5))?;
    // SAFETY: the kernel just mapped this object read-only at `RX_PAYLOAD_VA`;
    // `length` is bounded by the object's size, and this is the only reference
    // formed to the range.
    let got = unsafe { core::slice::from_raw_parts(RX_PAYLOAD_VA as *const u8, length) };
    let same = got == ECHO_BYTES;
    let _ = Machine.close(handle);
    if !same {
        return Err(fail(0xae, 8));
    }
    Ok(())
}

/// Builds a stateless DHCPv6 Information-Request and hands it to the stack.
///
/// The client builds the DHCPv6 message; the stack builds the Ethernet, IPv6
/// and UDP headers around it. That split is the same one the v4 leg uses, and
/// it is the reason this program needs no IPv6 constant beyond the address it
/// is asking about.
fn send_information_request(flow: u32) -> Result<(), u64> {
    let handle = Machine
        .memory_create(OBJECT_BYTES)
        .map_err(|_| fail(0xaa, 1))?;
    Machine
        .memory_map(handle, TX_PAYLOAD_VA)
        .map_err(|_| fail(0xaa, 2))?;
    // SAFETY: just created and mapped read-write at `TX_PAYLOAD_VA`;
    // `OBJECT_BYTES` is the object's whole size and nothing else references it.
    let out =
        unsafe { core::slice::from_raw_parts_mut(TX_PAYLOAD_VA as *mut u8, OBJECT_BYTES as usize) };
    let Some(len) = dhcpv6::build_information_request(out, CLIENT_MAC, DHCPV6_XID) else {
        return Err(fail(0xaa, 3));
    };
    let request = FlowSendRequest {
        size: FlowSendRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow,
        length: len as u32,
        remote: address6(ipv6::ALL_DHCP_SERVERS, dhcpv6::SERVER_PORT),
        payload: HandleRef::new(0),
    };
    let mut bytes = [0u8; FlowSendRequest::WIRE_SIZE];
    encode(&request, &mut bytes).map_err(|_| fail(0xaa, 0xe))?;
    let mut reply = [0u8; MSG_BUF_LEN];
    let (n, _) = Machine
        .call_with(
            Endpoint(Handle(STACK_HANDLE)),
            Flow::SEND_TO,
            &bytes,
            &mut reply,
            &[Transfer {
                handle,
                rights: FlowSendRequest::PAYLOAD_RIGHTS,
            }],
            &mut [],
        )
        .map_err(|_| fail(0xaa, 4))?;
    if n < FlowSendReply::WIRE_SIZE {
        return Err(fail(0xaa, 5));
    }
    let answered =
        decode::<FlowSendReply>(&reply[..FlowSendReply::WIRE_SIZE]).map_err(|_| fail(0xaa, 0xd))?;
    if answered.status != FlowError::Ok as u32 {
        return Err(fail(0xaa, u64::from(answered.status)));
    }
    Ok(())
}

/// Reads the DHCPv6 Reply out of the datagram the stack hands back.
fn receive_v6_reply(flow: u32) -> Result<dhcpv6::Reply, u64> {
    let (length, handle, remote) = receive_datagram(flow, 0xab)?;
    // **The family is checked and the source port is not.** RFC 8415 says a
    // server answers from port 547; the emulated network answers from an
    // ephemeral one, so requiring 547 discarded a reply that was otherwise
    // perfect (D279). The transaction id is what ties a reply to its request,
    // and `dhcpv6::parse_reply` below is what checks it.
    if remote.family != 6 {
        return Err(fail(0xab, 4));
    }
    Machine
        .memory_map_readable(handle, RX_PAYLOAD_VA)
        .map_err(|_| fail(0xab, 5))?;
    // SAFETY: the kernel just mapped this object read-only at `RX_PAYLOAD_VA`;
    // `length` is bounded by the object's size, and this is the only reference
    // formed to the range.
    let payload = unsafe { core::slice::from_raw_parts(RX_PAYLOAD_VA as *const u8, length) };
    let parsed = dhcpv6::parse_reply(payload, DHCPV6_XID);
    let _ = Machine.close(handle);
    parsed.ok_or(fail(0xab, 7))
}

/// One `RecvFrom`, returning the datagram's length, its object, and who sent
/// it.
///
/// Shared by both legs, because the flow contract does not change with the
/// address family — which is the point of having written it as a contract.
/// `stage` is the caller's failure code, so a fault still says which exchange
/// was in progress.
fn receive_datagram(flow: u32, stage: u64) -> Result<(usize, Handle, FlowAddress), u64> {
    let request = FlowRecvRequest {
        size: FlowRecvRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow,
        max_length: OBJECT_BYTES as u32,
    };
    let mut bytes = [0u8; FlowRecvRequest::WIRE_SIZE];
    encode(&request, &mut bytes).map_err(|_| fail(stage, 0xe))?;
    let mut reply = [0u8; MSG_BUF_LEN];
    let mut taken = [Handle(0); 1];
    let (n, handles) = Machine
        .call_with(
            Endpoint(Handle(STACK_HANDLE)),
            Flow::RECV_FROM,
            &bytes,
            &mut reply,
            &[],
            &mut taken,
        )
        .map_err(|_| fail(stage, 1))?;
    if n < FlowRecvReply::WIRE_SIZE {
        return Err(fail(stage, 2));
    }
    let answered = decode::<FlowRecvReply>(&reply[..FlowRecvReply::WIRE_SIZE])
        .map_err(|_| fail(stage, 0xd))?;
    if answered.status != FlowError::Ok as u32 {
        return Err(fail(stage, u64::from(answered.status)));
    }
    if handles == 0 {
        return Err(fail(stage, 3));
    }
    let length = answered.length as usize;
    if length == 0 || length > OBJECT_BYTES as usize {
        return Err(fail(stage, 6));
    }
    Ok((length, taken[0], answered.remote))
}

fn receive_offer(flow: u32) -> Result<dhcp::Offer, u64> {
    let (length, handle, remote) = receive_datagram(flow, 0xa3)?;
    // The datagram came from the DHCP server's port, which the stack reports
    // rather than this program inferring it from the payload.
    if remote.port as u16 != dhcp::SERVER_PORT || remote.family != 4 {
        return Err(fail(0xa3, 4));
    }
    Machine
        .memory_map_readable(handle, RX_PAYLOAD_VA)
        .map_err(|_| fail(0xa3, 5))?;
    // SAFETY: the kernel just mapped this object read-only at `RX_PAYLOAD_VA`;
    // `length` is bounded by the object's size, and this is the only reference
    // formed to the range.
    let payload = unsafe { core::slice::from_raw_parts(RX_PAYLOAD_VA as *const u8, length) };
    let parsed = dhcp::parse_offer(payload, DHCP_XID);
    // Copied out before the object is given up: `Offer` holds addresses by
    // value, and the slice stops being mapped on the next line.
    let _ = Machine.close(handle);
    parsed.ok_or(fail(0xa3, 7))
}

fn close(flow: u32) -> Result<(), u64> {
    let request = FlowCloseRequest {
        size: FlowCloseRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        flow,
        reserved: 0,
    };
    let mut bytes = [0u8; FlowCloseRequest::WIRE_SIZE];
    encode(&request, &mut bytes).map_err(|_| fail(0xa4, 0xe))?;
    let mut reply = [0u8; MSG_BUF_LEN];
    let n = call(Flow::CLOSE, &bytes, &mut reply)?;
    if n < FlowCloseReply::WIRE_SIZE {
        return Err(fail(0xa4, 1));
    }
    let answered = decode::<FlowCloseReply>(&reply[..FlowCloseReply::WIRE_SIZE])
        .map_err(|_| fail(0xa4, 0xd))?;
    if answered.status != FlowError::Ok as u32 {
        return Err(fail(0xa4, u64::from(answered.status)));
    }
    Ok(())
}

fn run() -> u64 {
    let mut report = 0u64;

    // 1. **The refusal first**, because a contract's reserved field is only
    //    reserved if something enforces it. Binding with a port capability
    //    nobody can resolve must be refused rather than ignored, or a client
    //    compiled against a later schema would appear to hold authority this
    //    service never checked.
    match bind(4, dhcp::CLIENT_PORT, 1) {
        Ok(reply) if reply.status == FlowError::Protocol as u32 => {
            report |= REPORT_AUTHORITY_REFUSED;
        }
        Ok(reply) => return fail(0xa5, u64::from(reply.status)),
        Err(code) => return code,
    }

    // 2. Bind for real.
    let flow = match bind(4, dhcp::CLIENT_PORT, 0) {
        Ok(reply) if reply.status == FlowError::Ok as u32 => {
            report |= REPORT_BOUND;
            reply.flow
        }
        Ok(reply) => return fail(0xa6, u64::from(reply.status)),
        Err(code) => return code,
    };

    // 3. **Two DISCOVERs before either answer is read**, and the second one is
    //    what tests the queue. One datagram proves the deferred path: the
    //    client asks before anything has arrived and the stack answers when it
    //    does. It cannot prove the other half — a datagram arriving while
    //    nobody is asking — because there is never a moment when nobody is.
    //    With two in flight, the second offer arrives while the stack is
    //    answering the first, so it has to be *held*, and the second
    //    `RecvFrom` is served out of the queue rather than deferred.
    //
    //    This program never names a MAC as a frame's source, never names an
    //    ethertype, and never computes a checksum — the stack does all three.
    for _ in 0..DATAGRAMS {
        match send_discover(flow) {
            Ok(_) => report |= REPORT_SENT,
            Err(code) => return code,
        }
    }

    // 4. Read both offers. The same lease answers both, because the server is
    //    answering the same client asking twice.
    for _ in 0..DATAGRAMS {
        let offer = match receive_offer(flow) {
            Ok(offer) => offer,
            Err(code) => return code,
        };
        if offer.offered != EXPECTED_OFFER || offer.server != EXPECTED_SERVER {
            return fail(0xa7, 0);
        }
        report |= REPORT_OFFER;
    }

    // 5. Give the flow up, so the service does not have to infer it from the
    //    client exiting.
    match close(flow) {
        Ok(()) => report |= REPORT_CLOSED,
        Err(code) => return code,
    }

    // 6. **The same exchange over IPv6**, through the same contract and the
    //    same stack instance. A second flow, because this one binds a
    //    different family on a different port and the service holds one at a
    //    time; the v4 flow is closed above.
    //
    //    Stateless DHCPv6 rather than an address lease: an IPv6 host gets its
    //    address from Router Advertisement and asks DHCPv6 for the rest, and
    //    the stateless exchange is the one a host can complete with the
    //    link-local address it formed itself. It is also the only UDP service
    //    the emulated network answers over IPv6, which makes it the v6
    //    counterpart of the DHCP round trip above.
    let flow6 = match bind(6, dhcpv6::CLIENT_PORT, 0) {
        Ok(reply) if reply.status == FlowError::Ok as u32 => reply.flow,
        Ok(reply) => return fail(0xa8, u64::from(reply.status)),
        Err(code) => return code,
    };
    if let Err(code) = send_information_request(flow6) {
        return code;
    }
    match receive_v6_reply(flow6) {
        Ok(reply) => {
            // **The answer is what is asserted, not the envelope.** The reply
            // names the resolver the emulated network always names, which is
            // the thing that was asked for and could only come from a server
            // that read the request. Its `SERVERID` is *not* required here:
            // RFC 8415 says a Reply carries one and this peer sends none, the
            // third place it departs from the specification in this exchange
            // (D279) — after answering from an ephemeral port instead of 547,
            // and after `ipv6=on` alone turning IPv4 off. `has_server_id` is
            // still parsed and reported, because a fact worth knowing is worth
            // carrying even when nothing gates on it.
            if reply.dns != Some(SLIRP_V6_DNS) {
                return fail(0xa9, 0);
            }
            report |= REPORT_V6_REPLY;
        }
        Err(code) => return code,
    }
    if let Err(code) = close(flow6) {
        return code;
    }

    // 7. **A stream.** Bind an ephemeral port, open a connection to the echo
    //    server the emulated network runs, send bytes and read them back, then
    //    close. The same `SendTo` and `RecvFrom` carry the stream that carried
    //    the datagrams — which is the contract's claim that a connection is a
    //    property of a flow rather than a second kind of thing (D280).
    let stream = match bind(4, ECHO_LOCAL_PORT, 0) {
        Ok(reply) if reply.status == FlowError::Ok as u32 => reply.flow,
        Ok(reply) => return fail(0xaf, u64::from(reply.status)),
        Err(code) => return code,
    };
    match connect(stream) {
        Ok(()) => report |= REPORT_CONNECTED,
        Err(code) => return code,
    }
    if let Err(code) = send_stream(stream, ECHO_BYTES) {
        return code;
    }
    match receive_echo(stream) {
        Ok(()) => report |= REPORT_ECHOED,
        Err(code) => return code,
    }
    if let Err(code) = close(stream) {
        return code;
    }

    // 8. **A receive that nobody will answer.** Bind a port the emulated
    //    network never sends to, ask for a datagram, and require the service
    //    to say `WOULD_BLOCK` rather than to stop. Before deadlines reached
    //    the receive itself this hung for the rest of the boot, which is the
    //    failure mode hardest to tell from slowness — and the reason this leg
    //    exists is that no other claim here fails when the deadline stops
    //    working.
    let quiet = match bind(4, QUIET_PORT, 0) {
        Ok(reply) if reply.status == FlowError::Ok as u32 => reply.flow,
        Ok(reply) => return fail(0xb0, u64::from(reply.status)),
        Err(code) => return code,
    };
    match receive_datagram(quiet, 0xb1) {
        // A datagram on a port nothing sends to means the check is not testing
        // what it thinks it is.
        Ok(_) => return fail(0xb1, 9),
        Err(code) if code == fail(0xb1, u64::from(FlowError::WouldBlock as u32)) => {
            report |= REPORT_TIMED_OUT;
        }
        Err(code) => return code,
    }
    if let Err(code) = close(quiet) {
        return code;
    }

    // 9. **A connection to a peer that says nothing.** The one leg here that
    //    needs the transport to recover rather than merely to be wired: the
    //    SYN goes into a black hole, the stack sends it again at one second
    //    and again at two and again at four, runs out of attempts, and answers
    //    `UNREACHABLE` — seven seconds in, with this client still running.
    //
    //    Without the retransmission timer this leg does not fail, it hangs:
    //    the connect is deferred, nothing ever arrives to answer it, and the
    //    service has nothing that would wake it (D284).
    let dead = match bind(4, BLACKHOLE_LOCAL_PORT, 0) {
        Ok(reply) if reply.status == FlowError::Ok as u32 => reply.flow,
        Ok(reply) => return fail(0xb3, u64::from(reply.status)),
        Err(code) => return code,
    };
    match connect_to(dead, BLACKHOLE_ADDR, ECHO_PORT) {
        Ok(status) if status == FlowError::Unreachable as u32 => report |= REPORT_GAVE_UP,
        // A connection that opened means the peer answered, which means this
        // leg is not testing what it thinks it is.
        Ok(status) if status == FlowError::Ok as u32 => return fail(0xb3, 9),
        Ok(status) => return fail(0xb3, u64::from(status)),
        Err(code) => return code,
    }
    if let Err(code) = close(dead) {
        return code;
    }

    // 10. **A call nobody will answer**, which is what a service that stops
    //    looks like from here. The channel is this program's own: it holds
    //    both ends, receives on neither, and calls on one — so the peer is
    //    open (this is not `PeerGone`) and no thread anywhere will ever reply.
    //    Nothing needs to be broken to arrange it, which is the point; a
    //    wedged service is indistinguishable from this from the caller's side.
    //
    //    Without a deadline on the call this leg does not fail, it *hangs*,
    //    and the client never reaches its report.
    let (unserved, calling) = match Machine.channel_create() {
        Ok(pair) => pair,
        Err(_) => return fail(0xb2, 1),
    };
    let Some(now) = Machine.now_nanos() else {
        return fail(0xb2, 2);
    };
    let mut ignored = [0u8; MSG_BUF_LEN];
    match Machine.call_until(
        calling,
        Flow::BIND,
        &[],
        &mut ignored,
        Some(now + SILENCE_BUDGET_NS),
    ) {
        // An answer from a channel with no server means this leg is not
        // testing what it thinks it is.
        Ok(_) => return fail(0xb2, 9),
        Err(SdkError::TimedOut) => report |= REPORT_CALL_TIMED_OUT,
        Err(_) => return fail(0xb2, 3),
    }
    for end in [unserved, calling] {
        if Machine.close(end.0).is_err() {
            return fail(0xb2, 4);
        }
    }

    REPORT_TAG | report
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
    Machine.finish(fail(0xae, 0))
}
