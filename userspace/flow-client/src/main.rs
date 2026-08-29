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
    Flow, FlowAddress, FlowBindReply, FlowBindRequest, FlowCloseReply, FlowCloseRequest, FlowError,
    FlowRecvReply, FlowRecvRequest, FlowSendReply, FlowSendRequest,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_net::{dhcp, dhcpv6, ipv6};
use tessera_sdk::{Endpoint, Handle, Platform as _, Transfer, machine::Machine};
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
const REPORT_TAG: u64 = 0x5e << 56;

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
    if remote.port as u16 != dhcpv6::SERVER_PORT || remote.family != 6 {
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

    // 6. **The IPv6 leg is written and not run**, and the reason is a property
    //    of the link rather than of this program (D278). Completing a stateless
    //    DHCPv6 exchange needs `ipv6=on` on the emulated network, and enabling
    //    it puts unsolicited Router Advertisements on the segment — which
    //    deadlocks the older `net-class` check sharing this NIC, whose driver
    //    and client were built for a link that carries only what they asked
    //    for. Running this leg would mean either that check failing or its
    //    claims being weakened to accommodate traffic they should tolerate.
    //
    //    [`send_information_request`] and [`receive_v6_reply`] are the leg;
    //    `api/net` is host-tested against an independently computed v6
    //    checksum, and the flow contract carries a v6 address. What is missing
    //    is a link this can be run on.
    let _ = (
        send_information_request,
        receive_v6_reply,
        SLIRP_V6_DNS,
        REPORT_V6_REPLY,
    );

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
