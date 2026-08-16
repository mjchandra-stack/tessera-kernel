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

use channel_msg::ChannelMsgArgs;
use memory_abi::{MapRights, MemoryMapArgs};
use network_driver::{
    NetControlReply, NetControlRequest, NetDescribeReply, NetError, NetFrameEvent, NetLinkEvent,
    NetPowerState, NetTransmitReply, NetTransmitRequest, NetworkDevice,
};
use tessera_class_conformance::{Described, Exchange, NETWORK, Report, check};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};
use tessera_virtio::arp;

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
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
/// The tag that makes this program's report distinguishable from every other
/// reporter folded into the same sink.
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
fn map_frame(handle: u32, length: u32) -> Result<&'static [u8], u64> {
    let args = MemoryMapArgs {
        size: MemoryMapArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        memory: HandleRef::new(handle),
        rights: MapRights(MapRights::READ.bits()),
        vaddr: FRAME_VA,
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
    // FRAME_VA and the call succeeded; `length` is inside that page, and
    // nothing else in this program references the range.
    Ok(unsafe { core::slice::from_raw_parts(FRAME_VA as *const u8, length) })
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
    let event = match await_event(&mut msg_buf) {
        Ok(event) => event,
        Err(code) => return code,
    };
    let Some(frame_event) = event.frame else {
        return fail(0x77, u64::from(event.method));
    };
    let mut report = 0u64;
    if event.buffer != 0 {
        report |= REPORT_FRAME_WAS_GRANTED;
    } else {
        // The driver copied the frame inline. Conformant, but not what this
        // check is about, and saying so beats reporting a pass.
        return fail(0x77, 0x100);
    }
    let frame = match map_frame(event.buffer, frame_event.length) {
        Ok(frame) => frame,
        Err(code) => return code,
    };
    // The frame starts at the buffer's first byte — no transport header to
    // skip, which is the whole reason the driver split its receive chain.
    let Some(reply) = arp::parse_reply(frame) else {
        return fail(0x78, 0);
    };
    if reply.sender_ip != GATEWAY_IP {
        return fail(0x78, 1);
    }
    for (i, byte) in reply.sender_mac.iter().enumerate() {
        report |= (*byte as u64) << (8 * i);
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
