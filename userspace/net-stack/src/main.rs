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
//! **One flow, one client, and no receive queue.** A datagram that arrives
//! when nobody is in `RecvFrom` is dropped, because the alternative is a queue
//! with an eviction policy and nothing has yet needed one. `RecvFrom` blocks
//! on the driver's event channel, which makes the exchange synchronous: this
//! is a stack that can do a request-response protocol and not one that can
//! serve a listener. Both are named in the ledger rather than implied.
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

/// How many frames `RecvFrom` will look at before giving up.
///
/// The segment carries whatever else the emulated network is doing, and a
/// receive that accepted only the next frame would be reporting on arrival
/// order rather than on delivery.
const RECV_ATTEMPTS: usize = 6;

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

/// What this service knows about its client's flow.
struct Stack {
    /// The MAC the driver reported, which every frame this program builds
    /// needs as its source.
    mac: [u8; 6],
    /// Whether a flow is open, and on which local port.
    bound: Option<u16>,
    /// Which claims this run has reached, reported once at exit.
    report: u64,
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

/// An address struct, filled in.
fn address(addr: [u8; 4], port: u16) -> FlowAddress {
    FlowAddress {
        size: FlowAddress::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        family: 4,
        port: u32::from(port),
        addr,
        reserved: 0,
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
    } else if request.local.family != 4 {
        FlowError::Protocol
    } else if stack.bound.is_some() {
        // One flow per client. `EXHAUSTED` rather than `PORT_UNAVAILABLE`:
        // the port is not the thing in the way.
        FlowError::Exhausted
    } else {
        let port = request.local.port as u16;
        stack.bound = Some(port);
        stack.report |= REPORT_BOUND;
        FlowError::Ok
    };
    let reply = FlowBindReply {
        size: FlowBindReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        flow: if status == FlowError::Ok { THE_FLOW } else { 0 },
        local: address([0, 0, 0, 0], stack.bound.unwrap_or(0)),
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
            stack.report |= REPORT_SENT;
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
    let Some(local_port) = stack.bound else {
        return Err(FlowError::NoSuchFlow);
    };
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
        frame_len = tessera_net::build_udp_frame(
            out,
            stack.mac,
            tessera_net::eth::BROADCAST,
            tessera_net::ipv4::UNSPECIFIED,
            request.remote.addr,
            local_port,
            request.remote.port as u16,
            0,
            payload,
        )
        .ok_or(FlowError::BadLength)?;
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

/// `RecvFrom`: wait for a frame addressed to this flow and hand its payload up.
fn serve_recv(
    stack: &mut Stack,
    bytes: &[u8],
    out: &mut [u8],
) -> Result<(usize, Option<Handle>), u64> {
    let request = decode::<FlowRecvRequest>(
        bytes
            .get(..FlowRecvRequest::WIRE_SIZE)
            .ok_or(fail(0x93, 1))?,
    )
    .map_err(|_| fail(0x93, 0xd))?;
    let mut remote = address([0, 0, 0, 0], 0);
    let mut length = 0u32;
    let mut give = None;
    let status = match recv(stack, &request, &mut remote, &mut length) {
        Ok(handle) => {
            give = Some(handle);
            stack.report |= REPORT_RECEIVED;
            FlowError::Ok
        }
        Err(status) => status,
    };
    let reply = FlowRecvReply {
        size: FlowRecvReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        length,
        remote,
        payload: HandleRef::new(0),
    };
    encode(&reply, &mut out[..FlowRecvReply::WIRE_SIZE]).map_err(|_| fail(0x93, 0xe))?;
    Ok((FlowRecvReply::WIRE_SIZE, give))
}

/// The receive path proper. Returns an object holding just the datagram.
fn recv(
    stack: &mut Stack,
    request: &FlowRecvRequest,
    remote: &mut FlowAddress,
    length: &mut u32,
) -> Result<Handle, FlowError> {
    let Some(local_port) = stack.bound else {
        return Err(FlowError::NoSuchFlow);
    };
    if request.flow != THE_FLOW {
        return Err(FlowError::NoSuchFlow);
    }
    for _ in 0..RECV_ATTEMPTS {
        let mut buf = [0u8; MSG_BUF_LEN];
        let mut handles = [Handle(0); 1];
        let event = Machine
            .receive_with(
                Endpoint(Handle(DRIVER_EVENT_HANDLE)),
                &mut buf,
                &mut handles,
            )
            .map_err(|_| FlowError::Unreachable)?;
        if event.method != NetworkDevice::ON_FRAME_RECEIVED || event.handles == 0 {
            continue;
        }
        let frame_handle = handles[0];
        let Ok(frame_event) = decode::<NetFrameEvent>(&buf[..NetFrameEvent::WIRE_SIZE]) else {
            let _ = Machine.close(frame_handle);
            continue;
        };
        let taken = take_datagram(
            frame_handle,
            frame_event.length as usize,
            stack.mac,
            local_port,
            request.max_length,
            remote,
            length,
        );
        // The driver gave the frame away; this program frees it either way,
        // which also frees `RX_FRAME_VA` for the next attempt.
        let _ = Machine.close(frame_handle);
        match taken {
            Some(handle) => return Ok(handle),
            None => continue,
        }
    }
    Err(FlowError::WouldBlock)
}

/// Maps a received frame, checks it is this flow's, and copies the datagram
/// into a fresh object.
///
/// **A copy, and a second object, and both are forced.** The frame belongs to
/// this program now, but the *client* must not be handed it: the frame holds
/// somebody else's headers, and the contract says a caller receives a datagram.
/// Handing back a page whose first 42 bytes are link and network state would
/// make every client parse them.
#[allow(clippy::too_many_arguments)]
fn take_datagram(
    frame_handle: Handle,
    frame_len: usize,
    mac: [u8; 6],
    local_port: u16,
    max_length: u32,
    remote: &mut FlowAddress,
    length: &mut u32,
) -> Option<Handle> {
    if frame_len == 0 || frame_len > OBJECT_BYTES as usize {
        return None;
    }
    Machine
        .memory_map_readable(frame_handle, RX_FRAME_VA)
        .ok()?;
    // SAFETY: the kernel just mapped this object read-only at `RX_FRAME_VA`;
    // `frame_len` is bounded by the object's size above, and this is the only
    // reference formed to the range.
    let frame = unsafe { core::slice::from_raw_parts(RX_FRAME_VA as *const u8, frame_len) };
    let datagram = tessera_net::parse_udp_frame(frame, mac)?;
    if datagram.dst_port != local_port {
        return None;
    }
    // A datagram longer than the caller will take stays refused rather than
    // truncated: a short read a caller cannot distinguish from a whole one is
    // the failure the contract's `max_length` exists to prevent.
    if datagram.payload.len() > max_length as usize {
        return None;
    }
    let out_handle = Machine.memory_create(OBJECT_BYTES).ok()?;
    if Machine.memory_map(out_handle, RX_PAYLOAD_VA).is_err() {
        let _ = Machine.close(out_handle);
        return None;
    }
    // SAFETY: just created and mapped read-write at `RX_PAYLOAD_VA`; the copy
    // is bounded by `max_length`, itself bounded by the object's size, and
    // nothing else references the range.
    unsafe {
        core::ptr::copy_nonoverlapping(
            datagram.payload.as_ptr(),
            RX_PAYLOAD_VA as *mut u8,
            datagram.payload.len(),
        );
    }
    *remote = address(datagram.src_addr, datagram.src_port);
    *length = datagram.payload.len() as u32;
    Some(out_handle)
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
        stack.report |= REPORT_CLOSED;
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

/// The serve loop. Hand-written rather than `sdk::serve_transfers`, because a
/// reply here sometimes carries a capability *out* and that helper's contract
/// is about giving back what came in.
fn run() -> u64 {
    let mac = match describe() {
        Ok(mac) => mac,
        Err(code) => return code,
    };
    let mut stack = Stack {
        mac,
        bound: None,
        report: 0,
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    loop {
        let mut handles = [Handle(0); 1];
        let request = match Machine.receive_with(
            Endpoint(Handle(FLOW_SERVER_HANDLE)),
            &mut buf,
            &mut handles,
        ) {
            Ok(request) => request,
            // The client is gone, which is how a service finishes.
            Err(_) => break,
        };
        let arrived = (request.handles > 0).then_some(handles[0]);
        let mut reply = [0u8; MSG_BUF_LEN];
        let taken = buf;
        let (len, give) = match request.method {
            Flow::BIND => match serve_bind(&mut stack, &taken, &mut reply) {
                Ok(len) => (len, None),
                Err(code) => return code,
            },
            Flow::SEND_TO => match serve_send(&mut stack, &taken, arrived, &mut reply) {
                Ok(len) => (len, None),
                Err(code) => return code,
            },
            Flow::RECV_FROM => match serve_recv(&mut stack, &taken, &mut reply) {
                Ok(pair) => pair,
                Err(code) => return code,
            },
            Flow::CLOSE => match serve_close(&mut stack, &taken, &mut reply) {
                Ok(len) => (len, None),
                Err(code) => return code,
            },
            // An ordinal this contract does not define. A refusal the client
            // should hear rather than a reason to die holding its request.
            _ => {
                let refusal = FlowCloseReply {
                    size: FlowCloseReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    status: FlowError::Protocol as u32,
                    reserved: 0,
                };
                match encode(&refusal, &mut reply[..FlowCloseReply::WIRE_SIZE]) {
                    Ok(_) => (FlowCloseReply::WIRE_SIZE, None),
                    Err(_) => return fail(0x95, 0xe),
                }
            }
        };
        let outcome = match give {
            Some(handle) => Machine.respond_with(
                Endpoint(Handle(FLOW_SERVER_HANDLE)),
                &reply[..len],
                &[Transfer {
                    handle,
                    rights: FlowRecvReply::PAYLOAD_RIGHTS,
                }],
            ),
            None => Machine.respond(Endpoint(Handle(FLOW_SERVER_HANDLE)), &reply[..len]),
        };
        if outcome.is_err() {
            break;
        }
        if stack.report & REPORT_CLOSED != 0 {
            break;
        }
    }
    stack.report
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
