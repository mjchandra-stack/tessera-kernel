// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **network class client**: a `no_std` Rust user program that
//! exercises a live network driver through `tessera.driver.network` and judges
//! it against the class conformance suite.
//!
//! It holds no device, no DMA capability and no memory it did not make: two
//! channel endpoints, and that is all. One it calls on; on the other it
//! **receives things nobody replied to**, which is the half of this class that
//! the block class had no equivalent of.
//!
//! What it proves, in the order it does it:
//!
//! 1. `Describe`, then `Transmit` of a real ARP request for the gateway.
//! 2. It then blocks on its event endpoint **with no call outstanding**, and
//!    the reply frame arrives as `OnFrameReceived` — sent because the NIC
//!    interrupted the driver, not because this program asked. The frame is in a
//!    memory object the driver gave away and no longer holds; this client maps
//!    it read-only and parses the ARP out of its first byte.
//! 3. `SetPower(STANDBY)` takes the link down, `OnLinkChanged` says so, and a
//!    `Transmit` while it is down answers `LINK_DOWN` — the class's own
//!    distinction from a block device with no medium, which can do nothing at
//!    all. `ACTIVE` brings it back and says so again.
//! 4. The whole transcript goes through `//api/class-conformance` against the
//!    NETWORK spec — the same suite, the same seven rules, a different class.
//!
//! Reporting: one `DebugWrite` carrying the gateway MAC the ARP resolved, plus
//! a bit per claim above, or a `0xdead_...` failure code. Every wait is
//! bounded by the driver being alive, and the panic handler exits, so this
//! program cannot hang the boot on its own.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts"),
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use memory_abi::{MapRights, MemoryConstraint, MemoryCreateArgs, MemoryMapArgs};
use network_driver::{
    NetAttachRegionReply, NetAttachRegionRequest, NetControlReply, NetControlRequest,
    NetDescribeReply, NetError, NetFrameEvent, NetLinkEvent, NetPowerState, NetReceiveRegionReply,
    NetReleaseFrameRequest, NetTransmitAtRequest, NetTransmitBufferRequest, NetTransmitReply,
    NetTransmitRequest, NetworkDevice,
};
use tessera_class_conformance::{Described, Exchange, NETWORK, Report, check};
use tessera_isl_runtime::{HandleRef, Ownership, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall1, syscall2};
use tessera_virtio::arp;

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_HANDLE_CLOSE: u64 = 4;
const SYS_MEMORY_CREATE: u64 = 30;
const SYS_MEMORY_MAP: u64 = 31;

/// This client's whole authority: the channel it calls the driver on, and the
/// one its events arrive on. Two, because a pushed event and a reply sharing a
/// queue would let a call dequeue an event as its answer.
const REQUEST_ENDPOINT_HANDLE: u64 = 0;
const EVENT_ENDPOINT_HANDLE: u64 = 1;

/// The symmetric call buffer: the largest struct in either direction is a
/// `NetFrameEvent` at 96 bytes.
const MSG_BUF_LEN: usize = 128;

/// Where a granted frame is mapped. Read-only, because that is all the contract
/// grants — a received frame is data, not a scratch page.
const FRAME_VA: u64 = 0x0000_1000_0080_0000;

/// How many frames the ARP leg looks at before giving up on its answer.
///
/// The segment carries whatever else the network is doing — Router
/// Advertisements above all, once IPv6 is enabled on it — and a leg that
/// accepted only the next frame was reporting on arrival order rather than on
/// resolution.
const ARP_ATTEMPTS: usize = 8;

/// Where this program builds a frame too large to travel inside a message.
///
/// Read **and** write, unlike [`FRAME_VA`]: this is an object this program
/// made and is filling in, not one it was handed. It is given away as soon as
/// it is full, and the rights it arrives with at the driver are narrower than
/// the ones held here — `NetTransmitRequest::BUFFER_RIGHTS` is `READ | MAP`.
const TX_FRAME_VA: u64 = 0x0000_1000_0090_0000;

/// How large a transmit object this program asks for: one page, which holds
/// any frame the class will carry — the MTU is 1500.
const TX_OBJECT_BYTES: u64 = 4096;

/// Where the DHCP leg maps each frame it looks at, one at a time.
///
/// **One address, reused, because each frame is released before the next is
/// mapped.** A frame arrives as an object this program now owns, so closing the
/// handle revokes the mapping and frees the pages — which is not merely tidy:
/// a leg that kept every frame it inspected exhausted the machine's memory
/// objects, and the driver's *next* receive buffer was what failed to be
/// created (D272).
const DHCP_FRAME_VA: u64 = FRAME_VA + 0x1_0000;

/// How many frames the leg looks at before giving up on an offer. The offer is
/// normally the next one, but the segment carries whatever else the emulated
/// network is doing, and a leg that accepted only the next frame would be
/// reporting on arrival order.
const DHCP_ATTEMPTS: usize = 4;

/// The transaction id the offer must echo.
///
/// **Fixed, and this is the one place that is right.** A transaction id should
/// be unpredictable so an off-path attacker cannot forge an offer; the kernel
/// CSPRNG is the only randomness a program here may use (`docs/lifecycle/04`),
/// and this program is a boot check whose value is doing the same thing every
/// run. The stack service that replaces this leg gets a real one.
const DHCP_XID: u32 = 0x5445_5353;

/// The SLIRP addresses, the same convention every other net check on this
/// machine uses: our static guest IP and the gateway we ARP for.
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

/// An ordinal in the vendor range, which this driver declares no namespace for
/// and must therefore refuse. The only method number written out here; every
/// other one comes from `NetworkDevice::*`, which the contract generates.
const M_VENDOR: u32 = 0x8000_0000;

/// Exchanges the conformance transcript holds.
const MAX_EXCHANGES: usize = 8;

/// Report bits above the 48-bit gateway MAC, one per claim.
const REPORT_CONFORMANT: u64 = 1 << 48;
const REPORT_LINK_DOWN_REFUSED: u64 = 1 << 49;
const REPORT_LINK_EVENTS: u64 = 1 << 50;
const REPORT_FRAME_WAS_GRANTED: u64 = 1 << 51;
/// A DHCP server answered a datagram this program built out of three headers it
/// wrote itself, in a buffer it handed the driver — the first protocol above
/// the link in this tree, and the first frame too large to be a message.
const REPORT_DHCP_OFFER: u64 = 1 << 52;
/// The tag that makes this program's report distinguishable from every other
/// reporter folded into the same sink.
/// The driver refused a `TransmitAt` naming memory outside the region it was
/// lent (D287). The bounds check is the security-relevant half of the shared
/// region, and nothing in ordinary operation exercises it.
const REPORT_REGION_BOUNDED: u64 = 1 << 53;
/// The driver refused a `ReleaseFrame` naming an offset that is not a slot it
/// lent (D288). The receive side's counterpart of `REPORT_REGION_BOUNDED`.
const REPORT_RELEASE_BOUNDED: u64 = 1 << 54;
const REPORT_TAG: u64 = 0x4e << 56;

/// `kcore::dispatch::HANDLE_NOT_INSTALLED` — what the installed-handle report
/// holds at a position whose capability did not land.
const HANDLE_NOT_INSTALLED: u32 = u32::MAX;

/// Field offsets in an encoded `ChannelMsgArgs` (`channel_msg.isl`).
const ARGS_METHOD_ID: usize = 32;

/// Reads back a u32 the kernel wrote into one of this program's buffers.
///
/// Volatile because the compiler has no idea a syscall wrote here and would
/// otherwise reuse whatever this program last put there.
fn kernel_u32(bytes: &[u8], at: usize) -> u32 {
    let mut out = [0u8; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        if at + i >= bytes.len() {
            return 0;
        }
        // SAFETY: a bounds-checked byte of this program's own stack buffer.
        *slot = unsafe { core::ptr::read_volatile(&bytes[at + i]) };
    }
    u32::from_le_bytes(out)
}

/// Sends whatever is already encoded in `msg_buf` as method `method`, and
/// returns how many bytes came back.
fn call(msg_buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Result<usize, u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: msg_buf.as_ptr() as u64,
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut args_buf).is_err() {
        return Err(fail(0x70, 1));
    }
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args_buf.as_ptr() as u64,
        REQUEST_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0x71, (-n) as u64));
    }
    Ok(n as usize)
}

/// An empty control request, which three of the five methods take.
fn control_request(msg_buf: &mut [u8; MSG_BUF_LEN], state: NetPowerState) -> Result<(), u64> {
    let request = NetControlRequest {
        size: NetControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state,
        enable: 0,
    };
    match encode(&request, &mut msg_buf[..NetControlRequest::WIRE_SIZE]) {
        Ok(_) => Ok(()),
        Err(_) => Err(fail(0x70, 2)),
    }
}

/// Calls a control-shaped method and returns the exchange the conformance suite
/// will judge, with the returned power state as its detail.
fn control(msg_buf: &mut [u8; MSG_BUF_LEN], method: u32, state: NetPowerState) -> Exchange {
    let unanswered = Exchange {
        ordinal: method,
        status: 0,
        answered: false,
        detail: 0,
    };
    if control_request(msg_buf, state).is_err() || call(msg_buf, method).is_err() {
        return unanswered;
    }
    let bytes = read_kernel_filled::<{ NetControlReply::WIRE_SIZE }>(msg_buf);
    match decode::<NetControlReply>(&bytes) {
        Ok(reply) => Exchange {
            ordinal: method,
            status: reply.status,
            answered: true,
            detail: reply.state as u32,
        },
        Err(_) => unanswered,
    }
}

/// Transmits one frame and returns both the exchange and the status, because
/// the link legs care about the status and the suite cares about the exchange.
fn transmit(msg_buf: &mut [u8; MSG_BUF_LEN], frame: &[u8]) -> (Exchange, u32) {
    let unanswered = Exchange {
        ordinal: NetworkDevice::TRANSMIT,
        status: 0,
        answered: false,
        detail: 0,
    };
    let mut payload = [0u8; 64];
    if frame.len() > payload.len() {
        return (unanswered, u32::MAX);
    }
    payload[..frame.len()].copy_from_slice(frame);
    let request = NetTransmitRequest {
        size: NetTransmitRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        length: frame.len() as u32,
        reserved: 0,
        frame: payload,
    };
    if encode(&request, &mut msg_buf[..NetTransmitRequest::WIRE_SIZE]).is_err()
        || call(msg_buf, NetworkDevice::TRANSMIT).is_err()
    {
        return (unanswered, u32::MAX);
    }
    let bytes = read_kernel_filled::<{ NetTransmitReply::WIRE_SIZE }>(msg_buf);
    match decode::<NetTransmitReply>(&bytes) {
        Ok(reply) => (
            Exchange {
                ordinal: NetworkDevice::TRANSMIT,
                status: reply.status,
                answered: true,
                detail: reply.sent,
            },
            reply.status,
        ),
        Err(_) => (unanswered, u32::MAX),
    }
}

/// One event, as it arrived: which one, and the buffer that came with it.
struct Event {
    method: u32,
    frame: Option<NetFrameEvent>,
    link: Option<NetLinkEvent>,
    buffer: u32,
}

/// Blocks until the driver sends something.
///
/// **Nothing is outstanding when this is called.** That is the whole point: the
/// message that wakes this program is one the driver decided to send, and a
/// receive is the only way to hear it.
fn await_event(msg_buf: &mut [u8; MSG_BUF_LEN]) -> Result<Event, u64> {
    let mut installed = [0u8; 4];
    // Cleared first: a receive that installs nothing writes nothing here, and
    // the previous event's handle would otherwise look like this one's buffer.
    for byte in installed.iter_mut() {
        // SAFETY: a byte of this program's own stack buffer; volatile so the
        // store is not elided as dead before the kernel's write.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: msg_buf.as_ptr() as u64,
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: installed.as_mut_ptr() as u64,
        installed_cap: 1,
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut args_buf).is_err() {
        return Err(fail(0x72, 1));
    }
    let n = syscall2(
        SYS_CHANNEL_RECV,
        args_buf.as_ptr() as u64,
        EVENT_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0x72, (-n) as u64));
    }
    // The kernel writes the arrived message's ordinal into the descriptor. A
    // pushed message has no call to name it, so this is the only thing that
    // says which event it is.
    let method = kernel_u32(&args_buf, ARGS_METHOD_ID);
    let buffer = match u32::from_le_bytes(read_kernel_filled::<4>(&installed)) {
        HANDLE_NOT_INSTALLED | 0 => 0,
        handle => handle,
    };
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    let mut event = Event {
        method,
        frame: None,
        link: None,
        buffer,
    };
    // Decoded from exactly the struct's own bytes: the receive buffer is the
    // largest message this client can take, and a decoder handed the slack
    // after a smaller one has trailing bytes to account for.
    match method {
        NetworkDevice::ON_FRAME_RECEIVED => {
            match decode::<NetFrameEvent>(&bytes[..NetFrameEvent::WIRE_SIZE]) {
                Ok(frame) => event.frame = Some(frame),
                Err(_) => return Err(fail(0x73, 0)),
            }
        }
        NetworkDevice::ON_LINK_CHANGED
        | NetworkDevice::ON_DEVICE_GONE
        | NetworkDevice::ON_ERROR => {
            match decode::<NetLinkEvent>(&bytes[..NetLinkEvent::WIRE_SIZE]) {
                Ok(link) => event.link = Some(link),
                Err(_) => return Err(fail(0x73, 1)),
            }
        }
        // An ordinal this contract does not define arriving unsolicited is
        // worse than one arriving in a call: there is nobody to refuse it to.
        // Reported and fatal, rather than ignored.
        _ => return Err(fail(0x73, 2)),
    }
    Ok(event)
}

/// Maps a granted frame read-only and returns its bytes.
///
/// `READ` and nothing else, because `NetFrameEvent.buffer` grants `READ | MAP`
/// — this client is being given data, not a scratch page, and asking for write
/// here would be refused by the kernel rather than by politeness.
fn map_frame(handle: u32, length: u32, vaddr: u64) -> Result<&'static [u8], u64> {
    let args = MemoryMapArgs {
        size: MemoryMapArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        memory: HandleRef::new(handle),
        rights: MapRights(MapRights::READ.bits()),
        vaddr,
    };
    let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x74, 1));
    }
    let mapped = syscall2(SYS_MEMORY_MAP, buf.as_ptr() as u64, 0);
    if mapped < 0 {
        return Err(fail(0x74, (-mapped) as u64));
    }
    let length = length as usize;
    if length == 0 || length > 4096 {
        return Err(fail(0x74, 0x100));
    }
    // SAFETY: the kernel just mapped this object's first page read-only at
    // `vaddr` and the call succeeded; `length` is inside that page, and
    // nothing else in this program references the range.
    Ok(unsafe { core::slice::from_raw_parts(vaddr as *const u8, length) })
}

/// Gives up a frame this program was handed.
///
/// **Closing the last handle to an object this process owns revokes its
/// mappings and frees its pages**, so this is both the unmap and the free —
/// and ownership moved to this program when the driver transferred the frame,
/// which is what makes it the one able to do either.
fn release_frame(handle: u32) -> Result<(), u64> {
    let closed = syscall1(SYS_HANDLE_CLOSE, u64::from(handle));
    if closed < 0 {
        return Err(fail(0x7c, (-closed) as u64));
    }
    Ok(())
}

/// Creates a memory object, maps it writable, and copies `frame` into it.
///
/// Returns the handle, which the caller gives away. **Nothing here keeps a
/// reference to the mapping afterwards**: the object is about to belong to
/// somebody else, and a slice outliving the transfer would be a pointer into
/// memory this program no longer owns.
fn build_out_of_line_frame(frame: &[u8]) -> Result<u32, u64> {
    let create = MemoryCreateArgs {
        size: MemoryCreateArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        bytes: TX_OBJECT_BYTES,
        // **No constraint at all**, which is the difference from the driver's
        // receive buffer: no device ever reaches this object. The driver copies
        // out of it into a page the NIC can see, so asking for device-visible
        // contiguity would spend a property nothing here uses.
        constraints: MemoryConstraint(0),
        alignment: 0,
        address_limit: 0,
    };
    let mut buf = [0u8; MemoryCreateArgs::WIRE_SIZE];
    if encode(&create, &mut buf).is_err() {
        return Err(fail(0x7a, 0xe));
    }
    let handle = syscall2(SYS_MEMORY_CREATE, buf.as_ptr() as u64, 0);
    if handle < 0 {
        return Err(fail(0x7a, (-handle) as u64));
    }
    let handle = handle as u32;

    let map = MemoryMapArgs {
        size: MemoryMapArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        memory: HandleRef::new(handle),
        rights: MapRights(MapRights::READ.bits() | MapRights::WRITE.bits()),
        vaddr: TX_FRAME_VA,
    };
    let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
    if encode(&map, &mut buf).is_err() {
        return Err(fail(0x7a, 0xd));
    }
    let mapped = syscall2(SYS_MEMORY_MAP, buf.as_ptr() as u64, 0);
    if mapped < 0 {
        return Err(fail(0x7a, 0x100 | (-mapped) as u64));
    }
    if frame.len() > TX_OBJECT_BYTES as usize {
        return Err(fail(0x7a, 0x200));
    }
    // SAFETY: the kernel just mapped this object read-write at `TX_FRAME_VA`
    // and the call returned success; `frame.len()` is bounded by `PAGE` above,
    // and this is the only reference formed to the range — it ends with the
    // statement.
    unsafe {
        core::ptr::copy_nonoverlapping(frame.as_ptr(), TX_FRAME_VA as *mut u8, frame.len());
    }
    Ok(handle)
}

/// Transmits a frame that does not fit inside a message, by giving the driver
/// the object holding it.
///
/// **The mirror of what the driver does on receive**, and deliberately built
/// out of the same two declarations: the schema says how the buffer travels
/// and with which rights, and this reads both off the generated contract
/// rather than restating them.
fn transmit_out_of_line(msg_buf: &mut [u8; MSG_BUF_LEN], frame: &[u8]) -> Result<u32, u64> {
    let handle = build_out_of_line_frame(frame)?;
    let request = NetTransmitBufferRequest {
        size: NetTransmitBufferRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        length: frame.len() as u32,
        reserved: 0,
        // An index into this message's transfer vector, not a handle number:
        // the number the driver ends up holding is the kernel's to choose.
        buffer: HandleRef::new(0),
    };
    if encode(
        &request,
        &mut msg_buf[..NetTransmitBufferRequest::WIRE_SIZE],
    )
    .is_err()
    {
        return Err(fail(0x7b, 0xe));
    }
    let descriptor = HandleTransfer {
        // Both read off the contract rather than from constants typed to match
        // it, the same way the driver builds its receive-side descriptor.
        mode: match NetTransmitBufferRequest::BUFFER_OWNERSHIP {
            Ownership::Transfer => TransferMode::Transfer,
            _ => return Err(fail(0x7b, 4)),
        },
        rights: NetTransmitBufferRequest::BUFFER_RIGHTS,
        handle,
    };
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    if encode(&descriptor, &mut transfer).is_err() {
        return Err(fail(0x7b, 2));
    }
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: NetworkDevice::TRANSMIT_BUFFER,
        msg_flags: 0,
        inline_ptr: msg_buf.as_ptr() as u64,
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: transfer.as_ptr() as u64,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut args_buf).is_err() {
        return Err(fail(0x7b, 1));
    }
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args_buf.as_ptr() as u64,
        REQUEST_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0x7b, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ NetTransmitReply::WIRE_SIZE }>(msg_buf);
    match decode::<NetTransmitReply>(&bytes) {
        Ok(reply) => Ok(reply.status),
        Err(_) => Err(fail(0x7b, 3)),
    }
}

/// Shares a region with the driver and asks it to send a frame that is not
/// inside it.
///
/// **The probe's job, and nothing else's.** The driver bounds an offset and a
/// length from a client against the region it was lent (D287) — those two
/// numbers are exactly how a client reaches past what it lent, so the refusal
/// is the security-relevant half of the mechanism. Nothing in ordinary
/// operation exercises it: the stack instance sends offset zero with a frame
/// it just built, so a driver that dropped the check would serve every real
/// run correctly and read whatever followed its mapping on a malformed one.
///
/// **Out of the conformance transcript, like the DHCP exchange above.** The
/// suite judges a driver against the class contract; this asks one driver a
/// question about one optional method, and folding it in would change what
/// `net-class.conformance-complete` means in order to test something else.
///
/// Returns the status the driver answered the bad request with.
fn probe_region_bounds(msg_buf: &mut [u8; MSG_BUF_LEN]) -> Result<u32, u64> {
    // The region is this probe's own object, shared rather than handed over —
    // it is still holding it when the call returns, which is the whole
    // difference the mode makes.
    let handle = build_out_of_line_frame(&[0u8; 64])?;
    let request = NetAttachRegionRequest {
        size: NetAttachRegionRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        length: TX_OBJECT_BYTES,
        region: HandleRef::new(0),
    };
    if encode(&request, &mut msg_buf[..NetAttachRegionRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0x7c, 0xe));
    }
    let descriptor = HandleTransfer {
        // Read off the contract, like every other descriptor this probe
        // builds. A schema saying `share` and a probe saying `transfer` would
        // hand the region away and test nothing.
        mode: match NetAttachRegionRequest::REGION_OWNERSHIP {
            Ownership::Share => TransferMode::Share,
            _ => return Err(fail(0x7c, 4)),
        },
        rights: NetAttachRegionRequest::REGION_RIGHTS,
        handle,
    };
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    if encode(&descriptor, &mut transfer).is_err() {
        return Err(fail(0x7c, 2));
    }
    let status = call_with_region(
        msg_buf,
        NetworkDevice::ATTACH_TRANSMIT_REGION,
        &transfer,
        NetAttachRegionReply::WIRE_SIZE,
        None,
    )?;
    if status != NetError::Ok as u32 {
        return Err(fail(0x7c, u64::from(status)));
    }

    // **One byte past the end**, which is the interesting offset: a bound that
    // capped the length alone, or that added without checking for overflow,
    // lets this through.
    let bad = NetTransmitAtRequest {
        size: NetTransmitAtRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        offset: TX_OBJECT_BYTES as u32,
        length: 64,
    };
    if encode(&bad, &mut msg_buf[..NetTransmitAtRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0x7c, 0xe));
    }
    call_with_region(
        msg_buf,
        NetworkDevice::TRANSMIT_AT,
        &[],
        NetTransmitReply::WIRE_SIZE,
        None,
    )
}

/// Attaches the driver's receive region and asks it to take back a slot it
/// never lent.
///
/// **The other half of D288's bound, and the same argument as D287's.** A
/// client returning an arbitrary offset is how it frees a slot somebody else
/// is using, or the same slot twice — which would have the driver post two
/// buffers into one place. The stack instance only ever returns an offset the
/// driver just gave it, so nothing in ordinary operation asks this question.
///
/// Returns the status the bad release was answered with.
fn probe_release_bounds(msg_buf: &mut [u8; MSG_BUF_LEN]) -> Result<u32, u64> {
    let request = NetControlRequest {
        size: NetControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: NetPowerState::Active,
        enable: 0,
    };
    if encode(&request, &mut msg_buf[..NetControlRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0x7d, 0xe));
    }
    let mut installed = [0u8; 4];
    let status = call_with_region(
        msg_buf,
        NetworkDevice::ATTACH_RECEIVE_REGION,
        &[],
        NetReceiveRegionReply::WIRE_SIZE,
        Some(&mut installed),
    )?;
    if status != NetError::Ok as u32 {
        return Err(fail(0x7d, u64::from(status)));
    }
    // The lent view is this probe's now and it is not going to read it. Closed
    // rather than left held: the region's frames go when the last holder lets
    // go, and a probe that kept one would be a holder nobody could account for.
    let lent = u32::from_le_bytes(read_kernel_filled::<4>(&installed));
    if lent != 0 {
        let _ = syscall2(SYS_HANDLE_CLOSE, u64::from(lent), 0);
    }

    // Not on a slot boundary, which is the offset a driver dividing without
    // checking the remainder would accept.
    let bad = NetReleaseFrameRequest {
        size: NetReleaseFrameRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        offset: 1,
        reserved: 0,
    };
    if encode(&bad, &mut msg_buf[..NetReleaseFrameRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0x7d, 0xe));
    }
    call_with_region(
        msg_buf,
        NetworkDevice::RELEASE_FRAME,
        &[],
        NetControlReply::WIRE_SIZE,
        None,
    )
}

/// Sends one request on the driver's channel and returns the `status` word its
/// reply starts with — the shape every reply in this contract shares.
fn call_with_region(
    msg_buf: &mut [u8; MSG_BUF_LEN],
    method: u32,
    transfer: &[u8],
    reply_len: usize,
    installed: Option<&mut [u8; 4]>,
) -> Result<u32, u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: msg_buf.as_ptr() as u64,
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: if transfer.is_empty() {
            0
        } else {
            transfer.as_ptr() as u64
        },
        handle_count: if transfer.is_empty() { 0 } else { 1 },
        // Where the kernel writes the number a capability *arriving* with the
        // reply landed at, which is the receiving half and separate from the
        // outbound vector above.
        installed_ptr: match &installed {
            Some(slot) => slot.as_ptr() as u64,
            None => 0,
        },
        installed_cap: u64::from(installed.is_some()),
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut args_buf).is_err() {
        return Err(fail(0x7c, 1));
    }
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args_buf.as_ptr() as u64,
        REQUEST_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0x7c, (-n) as u64));
    }
    if (n as usize) < reply_len {
        return Err(fail(0x7c, 5));
    }
    // Every reply in this contract begins size, version, flags, status — so
    // the status is the word at offset 16 whichever reply this is.
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    let mut status = [0u8; 4];
    status.copy_from_slice(&bytes[16..20]);
    Ok(u32::from_le_bytes(status))
}

/// The whole exercise. Returns the report the boot check reads.
fn run() -> u64 {
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut transcript = [Exchange {
        ordinal: 0,
        status: 0,
        answered: false,
        detail: 0,
    }; MAX_EXCHANGES];
    let mut used = 0usize;
    let mut push = |exchange: Exchange, transcript: &mut [Exchange; MAX_EXCHANGES]| {
        if used < MAX_EXCHANGES {
            transcript[used] = exchange;
            used += 1;
        }
    };

    // 1. Describe. Everything else is conditional on this answer, so it is
    // first and the features it reports are what the suite judges against.
    if control_request(&mut msg_buf, NetPowerState::Active).is_err() {
        return fail(0x75, 1);
    }
    if call(&mut msg_buf, NetworkDevice::DESCRIBE).is_err() {
        return fail(0x75, 2);
    }
    let bytes = read_kernel_filled::<{ NetDescribeReply::WIRE_SIZE }>(&msg_buf);
    let described_reply = match decode::<NetDescribeReply>(&bytes) {
        Ok(reply) => reply,
        Err(_) => return fail(0x75, 3),
    };
    push(
        Exchange {
            ordinal: NetworkDevice::DESCRIBE,
            status: described_reply.status as u32,
            answered: true,
            detail: described_reply.mtu,
        },
        &mut transcript,
    );
    let described = Described {
        contract_version: described_reply.contract_version,
        features: described_reply.features,
        vendor: described_reply.vendor,
    };
    let our_mac = {
        let low = described_reply.mac_low.to_le_bytes();
        let high = described_reply.mac_high.to_le_bytes();
        [low[0], low[1], low[2], low[3], high[0], high[1]]
    };

    // 2. Transmit an ARP request, then wait for a frame nobody replied with.
    let request = arp::build_request(our_mac, OUR_IP, GATEWAY_IP);
    let (exchange, status) = transmit(&mut msg_buf, &request);
    push(exchange, &mut transcript);
    if status != NetError::Ok as u32 {
        return fail(0x76, u64::from(status));
    }
    // **The next frame is not necessarily the answer**, and assuming it was is
    // a bug this leg carried until the link had other traffic on it. A segment
    // with IPv6 enabled carries Router Advertisements nobody solicited, so a
    // client that took the first frame as its ARP reply failed against a
    // network that was behaving correctly. Skip what is not ours, bounded, and
    // release each one — a frame arrives as an object this program then owns.
    let mut report = 0u64;
    let mut resolved = None;
    for _ in 0..ARP_ATTEMPTS {
        let event = match await_event(&mut msg_buf) {
            Ok(event) => event,
            Err(code) => return code,
        };
        let Some(frame_event) = event.frame else {
            return fail(0x77, u64::from(event.method));
        };
        if event.buffer == 0 {
            // The driver copied the frame inline. Conformant, but not what
            // this check is about, and saying so beats reporting a pass.
            return fail(0x77, 0x100);
        }
        report |= REPORT_FRAME_WAS_GRANTED;
        let frame = match map_frame(event.buffer, frame_event.length, FRAME_VA) {
            Ok(frame) => frame,
            Err(code) => return code,
        };
        // The frame starts at the buffer's first byte — no transport header to
        // skip, which is the whole reason the driver split its receive chain.
        let parsed = arp::parse_reply(frame).filter(|r| r.sender_ip == GATEWAY_IP);
        // Copied out before the mapping goes: `Reply` holds its fields by
        // value, and closing the handle revokes the window this frame is in —
        // which is also what frees `FRAME_VA` for the next attempt.
        if let Err(code) = release_frame(event.buffer) {
            return code;
        }
        if let Some(reply) = parsed {
            resolved = Some(reply);
            break;
        }
    }
    let Some(reply) = resolved else {
        return fail(0x78, 0);
    };
    for (i, byte) in reply.sender_mac.iter().enumerate() {
        report |= (*byte as u64) << (8 * i);
    }

    // 2b. **A protocol above the link, in a frame too large to be a message.**
    //     Everything up to here has been one frame the link layer understands
    //     end to end; ARP is the link asking about itself, and at 42 bytes it
    //     fits inline. This leg builds an Ethernet frame carrying an IPv4
    //     datagram carrying a UDP datagram carrying a DHCP DISCOVER — 290
    //     bytes, larger than the channel's whole inline payload — hands it to
    //     the driver in a memory object, and reads the offer that comes back.
    //
    //     Two things outside this tree decide whether it worked: QEMU's DHCP
    //     server has to accept the datagram, which means the three checksums
    //     have to be right, and it has to answer with a lease. A frame this
    //     tree builds wrongly is one that is silently never answered.
    //
    //     The exchange deliberately does **not** go into the conformance
    //     transcript. The suite judges the driver against the class contract,
    //     and a second `Transmit` says nothing about the driver the first did
    //     not; adding it would change what `net-class.conformance-complete`
    //     means in order to test something else.
    let mut discover = [0u8; tessera_net::MAX_FRAME_LEN];
    let Some(discover_len) = tessera_net::build_dhcp_discover(&mut discover, our_mac, DHCP_XID)
    else {
        return fail(0x79, 0);
    };
    match transmit_out_of_line(&mut msg_buf, &discover[..discover_len]) {
        Ok(status) if status == NetError::Ok as u32 => {}
        Ok(status) => return fail(0x79, u64::from(status)),
        Err(code) => return code,
    }
    let mut offer = None;
    for _ in 0..DHCP_ATTEMPTS {
        let event = match await_event(&mut msg_buf) {
            Ok(event) => event,
            Err(code) => return code,
        };
        let (Some(frame_event), true) = (event.frame, event.buffer != 0) else {
            continue;
        };
        let frame = match map_frame(event.buffer, frame_event.length, DHCP_FRAME_VA) {
            Ok(frame) => frame,
            Err(code) => return code,
        };
        // Every layer is checked in one call, so this leg cannot accidentally
        // accept a datagram whose UDP checksum was never verified.
        //
        // The parse is copied out before the handle is closed: `Offer` holds
        // addresses by value, and the slice it came from stops being mapped on
        // the next line.
        let parsed = tessera_net::parse_dhcp_offer(frame, our_mac, DHCP_XID);
        if let Err(code) = release_frame(event.buffer) {
            return code;
        }
        if parsed.is_some() {
            offer = parsed;
            break;
        }
    }
    let Some(offer) = offer else {
        return fail(0x79, 2);
    };
    // Both the address and the server are asserted: an offer that parsed but
    // named something else would mean the option walk read the wrong bytes,
    // which a structural check alone would pass.
    if offer.offered != OUR_IP || offer.server != GATEWAY_IP {
        return fail(0x79, 3);
    }
    report |= REPORT_DHCP_OFFER;

    // 2c. **A frame that is not inside the region it was named in.** Out of
    //     the transcript, like the exchange above, and for the same reason.
    match probe_region_bounds(&mut msg_buf) {
        Ok(status) if status == NetError::BadLength as u32 => {
            report |= REPORT_REGION_BOUNDED
        }
        // A driver that *sent* something is one that read past what it was
        // lent, which is the failure this leg exists to catch rather than a
        // status to report.
        Ok(status) if status == NetError::Ok as u32 => return fail(0x7c, 9),
        Ok(status) => return fail(0x7c, u64::from(status)),
        Err(code) => return code,
    }

    // 2d. **And a slot returned that was never lent.**
    match probe_release_bounds(&mut msg_buf) {
        Ok(status) if status == NetError::BadLength as u32 => {
            report |= REPORT_RELEASE_BOUNDED
        }
        Ok(status) if status == NetError::Ok as u32 => return fail(0x7d, 9),
        Ok(status) => return fail(0x7d, u64::from(status)),
        Err(code) => return code,
    }

    // 3. The link legs. STANDBY on this class is the link going down, and the
    // driver says so without being asked.
    push(
        control(
            &mut msg_buf,
            NetworkDevice::SET_POWER,
            NetPowerState::Standby,
        ),
        &mut transcript,
    );
    let down = match await_event(&mut msg_buf) {
        Ok(event) => event,
        Err(code) => return code,
    };
    let link_went_down = down.method == NetworkDevice::ON_LINK_CHANGED
        && down.link.map(|link| link.link_up) == Some(0);

    // A transmit while the link is down is `LINK_DOWN`, not an I/O error: the
    // device is present and configurable, which is the distinction this class
    // draws and the block class's `NO_MEDIUM` does not.
    let (exchange, status) = transmit(&mut msg_buf, &request);
    push(exchange, &mut transcript);
    if status == NetError::LinkDown as u32 {
        report |= REPORT_LINK_DOWN_REFUSED;
    }

    push(
        control(
            &mut msg_buf,
            NetworkDevice::SET_POWER,
            NetPowerState::Active,
        ),
        &mut transcript,
    );
    let up = match await_event(&mut msg_buf) {
        Ok(event) => event,
        Err(code) => return code,
    };
    let link_came_back =
        up.method == NetworkDevice::ON_LINK_CHANGED && up.link.map(|link| link.link_up) == Some(1);
    if link_went_down && link_came_back {
        report |= REPORT_LINK_EVENTS;
    }

    // 4. The rest of the contract: an optional method this driver does not
    // advertise, a reset, and an ordinal nobody negotiated.
    push(
        control(
            &mut msg_buf,
            NetworkDevice::SET_PROMISCUOUS,
            NetPowerState::Active,
        ),
        &mut transcript,
    );
    push(
        control(&mut msg_buf, NetworkDevice::RESET, NetPowerState::Active),
        &mut transcript,
    );
    push(
        control(&mut msg_buf, M_VENDOR, NetPowerState::Active),
        &mut transcript,
    );

    let judged: Report = check(&NETWORK, &described, &transcript[..used]);
    // **Complete, not merely clean.** `is_clean` says nothing failed, which a
    // transcript that called one method would also satisfy; this says every
    // rule was reached as well.
    if judged.is_complete() {
        report |= REPORT_CONFORMANT;
    }
    report | REPORT_TAG
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, value, 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    exit_reporting(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
