// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 block-service client (build/README.md, D81/D82): a `no_std`
//! Rust user program that requests TWO sector reads from the resident ring-3
//! blk driver over a channel and verifies the returned bytes (sector 0 =
//! `TESSERAV`, sector 1 = `TESSERA2` on the test disk). It holds no device
//! or DMA capability at all — only a channel endpoint. Two instances run
//! per boot, distinguished by the spawn argument (`_start`'s `id` in `x0`).
//! The request/reply payload is the `tessera.driver.block` ISL protocol,
//! which the kernel transports opaquely; the call buffer is symmetric
//! (request out, reply back in).
//!
//! Reporting: one `DebugWrite` with either the disk magic rotated by the
//! client id (`DISK_MAGIC.rotate_left(8 * id)` — the check XORs both
//! clients' reports, so each is load-bearing and distinct) or a
//! `0xdead_...` failure code, then `ProcessExit`.
//!
//! Normative: docs/api/01-system-call-interface.md,
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{
    BlockBufferReply, BlockBufferRequest, BlockControlReply, BlockControlRequest,
    BlockDescribeReply, BlockDevice, BlockError, BlockPowerState, BlockReadReply, BlockReadRequest,
    BlockWriteReply, BlockWriteRequest,
};
use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use memory_abi::{
    MapRights, MemoryClass, MemoryClassifyArgs, MemoryConstraint, MemoryCreateArgs, MemoryMapArgs,
};
use tessera_class_conformance::{BLOCK, Described, Exchange, Report, Rule, check};
use tessera_isl_runtime::{HandleRef, Ownership, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_MEMORY_CREATE: u64 = 30;
const SYS_MEMORY_MAP: u64 = 31;
const SYS_HANDLE_CLOSE: u64 = 4;
const SYS_MEMORY_CLASSIFY: u64 = 40;

/// The client's whole authority: its channel endpoint, at handle 0.
const ENDPOINT_HANDLE: u64 = 0;

/// The expected first 8 bytes of the two sectors this proof requests.
const DISK_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");
const SECTOR1_MAGIC: u64 = u64::from_le_bytes(*b"TESSERA2");

/// The symmetric call buffer: request source and reply destination, sized for
/// the largest struct in either direction — a `BlockWriteRequest` (88).
const MSG_BUF_LEN: usize = 128;

/// An ordinal in the vendor range, which this driver declares no namespace for
/// and must therefore refuse.
///
/// **The only method number written out in this program**, and deliberately:
/// every other one comes from `BlockDevice::*`, which the contract generates.
/// This one is not in the contract — that is the whole point of the check — so
/// there is nothing to generate it from.
const M_VENDOR: u32 = 0x8000_0000;

/// The sector this client writes to and reads back.
///
/// **Not sector 0 or 1.** Those carry the disk magic every other check on this
/// machine verifies, and a write path proven by destroying the evidence other
/// proofs depend on would be a poor trade. Sector 2 is zeroed padding on the
/// test disk, so a magic found there came from this client and nowhere else.
const WRITE_SECTOR: u64 = 2;

/// What this client writes, chosen to be recognisable in a sector that is
/// otherwise zero.
const WRITE_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAW");

/// Asks this program to **wait for the medium to go**, instead of reading
/// anything that must succeed.
///
/// The one leg of the block contract that no fixed device can exercise: a
/// driver bound to a disk that will still be there next time can answer
/// `NO_MEDIUM` only by lying. A removable card can be pulled, and this loops on
/// the same request that worked a moment ago until the answer changes.
const MEDIUM_GONE: u64 = 1 << 58;

/// What this program reports when it saw the medium go.
const MEDIUM_GONE_REPORT: u64 = 0x5344 << 48;

/// How many times the medium is asked about before giving up. Bounded, because
/// a card that never leaves is a test that failed rather than one that waits.
const MEDIUM_GONE_TRIES: u32 = 200_000;

/// Exchanges the conformance transcript holds.
const MAX_EXCHANGES: usize = 8;

/// The sector the out-of-line round trip uses, and what it writes there.
///
/// A **separate sector from the inline write path's**, because the two prove
/// different things and a shared sector would let either one's success cover
/// the other's failure. Sector 3 is zeroed padding on the test disk, so
/// anything found there afterwards came from this client.
const GRANT_SECTOR: u64 = 3;
const GRANT_MAGIC: [u8; 8] = *b"TESSERAG";

/// One sector — the whole point of the out-of-line path, since a channel
/// message's inline payload tops out at 256 bytes and this is 512.
const SECTOR: usize = 512;

/// Where this client maps a buffer it owns. Free again after every transfer,
/// because a transfer takes the sender's mappings with it.
const GRANT_VA: u64 = 0x0000_1000_0080_0000;

/// Sends whatever is already encoded in `msg_buf` as method `method`, and
/// returns how many bytes came back.
///
/// The descriptor's `method_id` is what makes a class contract usable: before
/// it, a driver could only serve one method because a request could only mean
/// one thing. `inline_len` covers the whole buffer, so the request goes out
/// padded and the largest reply fits coming back.
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
        // No capability is expected back, so no report is asked for.
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut args_buf).is_err() {
        return Err(fail(0x11, 1));
    }
    let n = syscall2(SYS_CHANNEL_CALL, args_buf.as_ptr() as u64, ENDPOINT_HANDLE);
    if n < 0 {
        return Err(fail(0x12, (-n) as u64));
    }
    Ok(n as usize)
}

/// Creates a memory object of `bytes` and returns its handle.
fn memory_create(bytes: u64) -> Result<u32, u64> {
    let args = MemoryCreateArgs {
        size: MemoryCreateArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        bytes,
        // No placement constraints: this buffer is read and written by the CPU
        // here and reached by the device through an attachment, so where its
        // pages sit is nobody's business. Asking for contiguity that nothing
        // needs is how carveout pressure grows.
        constraints: MemoryConstraint(0),
        alignment: 0,
        address_limit: 0,
    };
    let mut buf = [0u8; MemoryCreateArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x40, 1));
    }
    let handle = syscall2(SYS_MEMORY_CREATE, buf.as_ptr() as u64, 0);
    if handle < 0 {
        return Err(fail(0x40, (-handle) as u64));
    }
    Ok(handle as u32)
}

/// Maps `handle` read-write at [`GRANT_VA`] and returns the bytes as a slice.
///
/// Always the same address, and always available: the previous mapping went
/// away when the object was transferred to the driver. A second mapping at an
/// occupied address is refused, so this succeeding at all is the revocation
/// being observed rather than assumed.
fn map_grant(handle: u32, stage: u64) -> Result<&'static mut [u8], u64> {
    let args = MemoryMapArgs {
        size: MemoryMapArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        memory: HandleRef::new(handle),
        rights: MapRights(MapRights::READ.bits() | MapRights::WRITE.bits()),
        vaddr: GRANT_VA,
    };
    let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(stage, 1));
    }
    let mapped = syscall2(SYS_MEMORY_MAP, buf.as_ptr() as u64, 0);
    if mapped < 0 {
        return Err(fail(stage, (-mapped) as u64));
    }
    // SAFETY: the kernel just mapped this object's first page read-write at
    // GRANT_VA and the call succeeded; SECTOR is within the page, nothing else
    // in this program references the range, and it stays mapped until the next
    // transfer takes it away.
    Ok(unsafe { core::slice::from_raw_parts_mut(GRANT_VA as *mut u8, SECTOR) })
}

/// One out-of-line exchange: transfer `handle` to the driver with a
/// `BlockBufferRequest`, and get the object back as the handle the *kernel*
/// reports.
///
/// The handle number changes across the round trip, and it must: a handle is
/// an index and a generation, so the object coming home lands at the same
/// index with a different value. That is why `installed_ptr` exists — a client
/// that reused the number it sent would be naming a slot whose generation has
/// moved on.
fn buffer_call(
    msg_buf: &mut [u8; MSG_BUF_LEN],
    method: u32,
    handle: u32,
    sector: u64,
) -> Result<(u32, BlockBufferReply), u64> {
    let request = BlockBufferRequest {
        size: BlockBufferRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        sector,
        length: SECTOR as u64,
        // Index 0 — the first (and only) handle attached below. An *index*,
        // not the handle number: the number this client holds is not the
        // number the driver will hold, and neither side gets to choose it.
        buffer: HandleRef::new(0),
    };
    if encode(&request, &mut msg_buf[..BlockBufferRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0x41, 1));
    }
    let descriptor = HandleTransfer {
        // **Both of these come from the contract**, not from constants typed
        // here to match it. The schema declares
        // `buffer: transfer handle<Object, {READ, WRITE, MAP, TRANSFER}>`, and
        // that declaration is what the driver was written against — so a
        // client computing its own mask would be agreeing with the driver by
        // coincidence rather than by construction.
        mode: match BlockBufferRequest::BUFFER_OWNERSHIP {
            Ownership::Transfer => TransferMode::Transfer,
            // The kernel refuses share, so a contract that asked for it should
            // fail here — where the mismatch is legible — rather than at a
            // syscall returning NotSupported for reasons nothing explains.
            _ => return Err(fail(0x41, 4)),
        },
        rights: BlockBufferRequest::BUFFER_RIGHTS,
        handle,
    };
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    if encode(&descriptor, &mut transfer).is_err() {
        return Err(fail(0x41, 2));
    }
    let mut installed = [0u8; 4];
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
        handles_ptr: transfer.as_ptr() as u64,
        handle_count: 1,
        // The buffer comes back with the reply, at a handle only the kernel
        // knows.
        installed_ptr: installed.as_mut_ptr() as u64,
        installed_cap: 1,
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut args_buf).is_err() {
        return Err(fail(0x41, 3));
    }
    let n = syscall2(SYS_CHANNEL_CALL, args_buf.as_ptr() as u64, ENDPOINT_HANDLE);
    if n < 0 {
        return Err(fail(0x42, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BlockBufferReply::WIRE_SIZE }>(msg_buf);
    let reply = match decode::<BlockBufferReply>(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x43, 0)),
    };
    let returned = u32::from_le_bytes(read_kernel_filled::<4>(&installed));
    if returned == 0 {
        // The driver kept the buffer. Reported rather than worked around: the
        // client's memory is stranded in a process it cannot reach, and every
        // later request would be refused for want of a buffer anyway.
        return Err(fail(0x44, 0));
    }
    Ok((returned, reply))
}

/// The out-of-line round trip: write a full sector through a memory object,
/// read it back through the same mechanism, and check every byte.
///
/// **This is what the inline path cannot do.** A channel message carries at
/// most 256 bytes, so `Read`/`Write` above move a sector's first 64 and the
/// rest of it is a thing the two programs can only agree about in principle.
/// Here the whole 512 goes out, comes back off the medium, and is compared —
/// and the boot script then reads the same sector out of the disk image, which
/// is the only check a driver and a client agreeing with each other cannot
/// fake.
fn out_of_line_round_trip(msg_buf: &mut [u8; MSG_BUF_LEN]) -> u64 {
    let handle = match memory_create(4096) {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    let buffer = match map_grant(handle, 0x45) {
        Ok(buffer) => buffer,
        Err(code) => return code,
    };
    // A pattern with a recognisable head and a body that varies per byte, so
    // a driver that wrote the right first word and zeroes after it fails here
    // rather than passing.
    buffer[..8].copy_from_slice(&GRANT_MAGIC);
    for (i, byte) in buffer.iter_mut().enumerate().skip(8) {
        *byte = (i as u8) ^ 0x5a;
    }

    let (handle, reply) = match buffer_call(msg_buf, BlockDevice::WRITE_FROM, handle, GRANT_SECTOR)
    {
        Ok(answer) => answer,
        Err(code) => return code,
    };
    if reply.status != BlockError::Ok as u32 || reply.transferred != SECTOR as u64 {
        return fail(0x46, u64::from(reply.status) << 32 | reply.transferred);
    }

    // Zero the buffer before reading back, so a driver that returned the
    // buffer untouched cannot pass by leaving what this client wrote in it.
    let buffer = match map_grant(handle, 0x47) {
        Ok(buffer) => buffer,
        Err(code) => return code,
    };
    buffer.fill(0);

    let (handle, reply) = match buffer_call(msg_buf, BlockDevice::READ_INTO, handle, GRANT_SECTOR) {
        Ok(answer) => answer,
        Err(code) => return code,
    };
    if reply.status != BlockError::Ok as u32 || reply.transferred != SECTOR as u64 {
        return fail(0x48, u64::from(reply.status) << 32 | reply.transferred);
    }

    let buffer = match map_grant(handle, 0x49) {
        Ok(buffer) => buffer,
        Err(code) => return code,
    };
    if buffer[..8] != GRANT_MAGIC {
        return fail(
            0x4a,
            u64::from_le_bytes(match buffer[..8].try_into() {
                Ok(head) => head,
                Err(_) => return fail(0x4a, 0),
            }),
        );
    }
    for (i, byte) in buffer.iter().enumerate().skip(8) {
        if *byte != (i as u8) ^ 0x5a {
            // The offset of the first wrong byte, which says far more about
            // what went wrong than "mismatch" does.
            return fail(0x4b, i as u64);
        }
    }

    // **And now the same buffer, on the protected handling path.**
    //
    // Everything about the next request is identical to the one that just
    // worked — the same object, the same driver, the same device, the same
    // sector — except that this client has classified the memory. So a refusal
    // can only be the classification's doing, which is what makes this a
    // proof rather than an observation that something failed.
    //
    // The driver never maps this buffer; it attaches it to the block device and
    // puts the device address in a descriptor. That attach is what the kernel
    // refuses, because the driver's device capability carries no authority for
    // protected memory (`docs/security/01`, "Memory Classification").
    if let Err(code) = classify_protected(handle) {
        return code;
    }
    match buffer_call(msg_buf, BlockDevice::READ_INTO, handle, GRANT_SECTOR) {
        // The request came back refused, which is the whole point. The handle
        // came back with it, because a refused attach moves nothing.
        Ok((handle, reply)) if reply.status != BlockError::Ok as u32 => {
            if syscall2(SYS_HANDLE_CLOSE, u64::from(handle), 0) < 0 {
                return fail(0x4c, 0);
            }
            0
        }
        // **The failure this step exists to catch.** The driver moved a sector
        // into memory this client had marked protected, which means nothing
        // enforced the marking.
        Ok((_, reply)) => fail(0x4d, u64::from(reply.status) << 32 | reply.transferred),
        Err(code) => code,
    }
}

/// Puts this client's buffer on the protected handling path.
///
/// Requires `WRITE`, which this program holds on memory it created. Raising a
/// class restricts what may be done with the object from then on, so it is a
/// modification of the buffer rather than an opinion about it.
fn classify_protected(handle: u32) -> Result<(), u64> {
    let args = MemoryClassifyArgs {
        size: MemoryClassifyArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        memory: HandleRef::new(handle),
        class: MemoryClass::Protected,
    };
    let mut buf = [0u8; MemoryClassifyArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x4e, 1));
    }
    let result = syscall2(SYS_MEMORY_CLASSIFY, buf.as_ptr() as u64, 0);
    if result < 0 {
        return Err(fail(0x4e, (-result) as u64));
    }
    Ok(())
}

/// Calls a method whose request and reply are both the control structs, and
/// returns the exchange the conformance suite will judge.
///
/// A failed *transport* call is recorded as `answered: false` rather than as
/// an error status, and the two must not be conflated: a driver that returned
/// an error answered the question, and one that never replied did not.
fn discard(msg_buf: &mut [u8; MSG_BUF_LEN]) -> Exchange {
    let unanswered = Exchange {
        ordinal: BlockDevice::DISCARD,
        status: 0,
        answered: false,
        detail: 0,
    };
    let request = BlockWriteRequest {
        size: BlockWriteRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        sector: WRITE_SECTOR,
        data: [0; 64],
    };
    if encode(&request, &mut msg_buf[..BlockWriteRequest::WIRE_SIZE]).is_err() {
        return unanswered;
    }
    if call(msg_buf, BlockDevice::DISCARD).is_err() {
        return unanswered;
    }
    // The reply is a control reply — the contract pairs an asymmetric request
    // and response here, which is exactly the kind of thing a hand-written
    // dispatch gets to be sloppy about and a generated one does not.
    let bytes = read_kernel_filled::<{ BlockControlReply::WIRE_SIZE }>(msg_buf);
    match decode::<BlockControlReply>(&bytes) {
        Ok(reply) => Exchange {
            ordinal: BlockDevice::DISCARD,
            status: reply.status,
            answered: true,
            detail: reply.state as u32,
        },
        Err(_) => unanswered,
    }
}

fn control(msg_buf: &mut [u8; MSG_BUF_LEN], method: u32, state: BlockPowerState) -> Exchange {
    let request = BlockControlRequest {
        size: BlockControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state,
        reserved: 0,
    };
    let unanswered = Exchange {
        ordinal: method,
        status: 0,
        answered: false,
        detail: 0,
    };
    if encode(&request, &mut msg_buf[..BlockControlRequest::WIRE_SIZE]).is_err() {
        return unanswered;
    }
    if call(msg_buf, method).is_err() {
        return unanswered;
    }
    let bytes = read_kernel_filled::<{ BlockControlReply::WIRE_SIZE }>(msg_buf);
    match decode::<BlockControlReply>(&bytes) {
        Ok(reply) => Exchange {
            ordinal: method,
            status: reply.status,
            answered: true,
            // What the method left the device in — the observation the reset
            // rule is judged on.
            detail: reply.state as u32,
        },
        Err(_) => unanswered,
    }
}

/// One sector read over the channel: sends the request through the symmetric
/// call buffer, verifies the reply header/status, and checks the sector's
/// first 8 bytes against `expect`. Returns the failure report, or 0.
fn read_and_verify(msg_buf: &mut [u8; MSG_BUF_LEN], sector: u64, expect: u64) -> u64 {
    let request = BlockReadRequest {
        size: BlockReadRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        sector,
    };
    if encode(&request, &mut msg_buf[..BlockReadRequest::WIRE_SIZE]).is_err() {
        return fail(0x11, 0);
    }
    let n = match call(msg_buf, BlockDevice::READ) {
        Ok(n) => n,
        Err(code) => return code,
    };
    if n < BlockReadReply::WIRE_SIZE {
        return fail(0x13, n as u64);
    }

    let reply_bytes = read_kernel_filled::<{ BlockReadReply::WIRE_SIZE }>(msg_buf);
    let reply = match decode::<BlockReadReply>(&reply_bytes) {
        Ok(reply) => reply,
        Err(_) => return fail(0x14, 0),
    };
    if reply.size != BlockReadReply::WIRE_SIZE as u32 || reply.version != 1 || reply.flags != 0 {
        return fail(0x14, 1);
    }
    if reply.status != 0 {
        return fail(0x15, reply.status as u64);
    }

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&reply.data[..8]);
    if u64::from_le_bytes(magic) != expect {
        // The bytes that came back, not just which sector disagreed: a wrong
        // magic is a driver reading the wrong place, and *what* it read is what
        // says where.
        return fail(0x16, sector);
    }
    0
}

/// Writes `magic` to `sector` and reads it back — the proof the contract is no
/// longer read-only.
///
/// **Reading it back is the whole test.** A write that reported success and
/// changed nothing is exactly what a driver marking its data descriptor
/// device-writable produces, and the reply alone cannot tell that apart from a
/// write that worked.
fn write_and_read_back(msg_buf: &mut [u8; MSG_BUF_LEN], sector: u64, magic: u64) -> u64 {
    let mut data = [0u8; 64];
    data[..8].copy_from_slice(&magic.to_le_bytes());
    let request = BlockWriteRequest {
        size: BlockWriteRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        sector,
        data,
    };
    if encode(&request, &mut msg_buf[..BlockWriteRequest::WIRE_SIZE]).is_err() {
        return fail(0x21, 0);
    }
    let n = match call(msg_buf, BlockDevice::WRITE) {
        Ok(n) => n,
        Err(code) => return code,
    };
    if n < BlockWriteReply::WIRE_SIZE {
        return fail(0x22, n as u64);
    }
    let bytes = read_kernel_filled::<{ BlockWriteReply::WIRE_SIZE }>(msg_buf);
    let reply = match decode::<BlockWriteReply>(&bytes) {
        Ok(reply) => reply,
        Err(_) => return fail(0x23, 0),
    };
    if reply.status != 0 {
        return fail(0x24, reply.status as u64);
    }
    if reply.written == 0 {
        return fail(0x24, 0xff);
    }
    // And back off the medium.
    read_and_verify(msg_buf, sector, magic)
}

/// Runs the block class's conformance suite against the driver on the other
/// end of this channel, and returns the report.
///
/// **A transcript, not a set of assertions.** The rules live in
/// `tessera_class_conformance` and are host-tested there against transcripts no
/// real driver would produce on demand — an advertised method that refuses, a
/// vendor ordinal answered with nothing negotiated, a reset that comes back in
/// the wrong state. This client's job is to *reach* every rule, and the
/// suite's is to judge what it found. A client that judged for itself would be
/// a second implementation of the contract, and the two would drift.
fn conformance(msg_buf: &mut [u8; MSG_BUF_LEN]) -> Result<Report, u64> {
    // `Describe` first: every other rule is relative to what the driver says
    // about itself, and a client that assumed would not be testing the driver.
    //
    // It gets its own call rather than going through `control`, because it is
    // the one method whose reply is not a `BlockControlReply` — the reply that
    // carries everything the rest of the suite reads cannot itself be shaped
    // like the replies it describes.
    let request = BlockControlRequest {
        size: BlockControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: BlockPowerState::Active,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..BlockControlRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0x30, 0));
    }
    let n = match call(msg_buf, BlockDevice::DESCRIBE) {
        Ok(n) => n,
        Err(code) => return Err(code),
    };
    if n < BlockDescribeReply::WIRE_SIZE {
        return Err(fail(0x31, n as u64));
    }
    let bytes = read_kernel_filled::<{ BlockDescribeReply::WIRE_SIZE }>(msg_buf);
    let reply = match decode::<BlockDescribeReply>(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x32, 0)),
    };
    let describe_status = reply.status as u32;
    let described = Described {
        contract_version: reply.contract_version,
        features: reply.features,
        vendor: reply.vendor,
    };

    let mut transcript = [Exchange {
        ordinal: 0,
        status: 0,
        answered: false,
        detail: 0,
    }; MAX_EXCHANGES];
    // Describe itself is an exchange like any other: it is a required method,
    // and a suite that exempted the method it read its own inputs from would
    // have a hole exactly where a lying driver would put one.
    transcript[0] = Exchange {
        ordinal: BlockDevice::DESCRIBE,
        status: describe_status,
        answered: true,
        detail: 0,
    };
    // A read of a sector that exists. A read that did not return the bytes
    // the medium holds is a **driver failure**, not a conformance nuance —
    // reported here rather than folded into a transcript entry, because the
    // suite judges whether a driver obeyed its contract and this is a driver
    // that did not do its job.
    let read = read_and_verify(msg_buf, 0, DISK_MAGIC);
    if read != 0 {
        return Err(read);
    }
    transcript[1] = Exchange {
        ordinal: BlockDevice::READ,
        status: 0,
        answered: true,
        detail: 0,
    };
    // An advertised optional: WRITE, verified by reading it back off the
    // medium. A write that reported success and changed nothing is exactly
    // what a driver marking its data descriptor device-writable produces.
    let write = write_and_read_back(msg_buf, WRITE_SECTOR, WRITE_MAGIC);
    if write != 0 {
        return Err(write);
    }
    transcript[2] = Exchange {
        ordinal: BlockDevice::WRITE,
        status: 0,
        answered: true,
        detail: 0,
    };
    // An advertised optional with no payload: FLUSH.
    transcript[3] = control(msg_buf, BlockDevice::FLUSH, BlockPowerState::Active);
    // Required, and the one whose *outcome state* the contract defines.
    transcript[4] = control(msg_buf, BlockDevice::RESET, BlockPowerState::Active);
    // Required, with a state the driver reported it supports.
    transcript[5] = control(msg_buf, BlockDevice::SET_POWER, BlockPowerState::Idle);
    // An optional the driver did **not** advertise: it must answer
    // NOT_SUPPORTED, and neither succeed nor fail in some other way.
    //
    // Sent as a `BlockWriteRequest`, because that is what the contract pairs
    // with this ordinal. It used to go out as a control request and be decoded
    // as one — a pairing the schema does not define, which both programs got
    // wrong in the same way and so never noticed. The generated dispatch is
    // what made it visible.
    transcript[6] = discard(msg_buf);
    // A vendor-range ordinal with no namespace negotiated: it must be refused.
    transcript[7] = control(msg_buf, M_VENDOR, BlockPowerState::Active);

    // Put the device back in service. A conformance run that left the driver
    // suspended would break every check that follows it, and a suite with side
    // effects nobody undoes is one people stop running.
    let restored = control(msg_buf, BlockDevice::SET_POWER, BlockPowerState::Active);
    if !restored.answered || restored.status != 0 {
        return Err(fail(0x33, restored.status as u64));
    }

    Ok(check(&BLOCK, &described, &transcript))
}

/// Requests sectors 0 and 1 from the resident driver, verifies both, and — on
/// the first client only — runs the class conformance suite.
///
/// Only the first, because the suite writes to the medium and changes the
/// device's power state: running it twice concurrently would have two clients
/// disagreeing about a device neither of them owns, which is a test artefact
/// rather than a finding.
/// Reads sector 0 until the driver says the medium is gone.
///
/// **The same request that succeeded, and the only thing that changed is the
/// card.** A client and a driver agreeing that a card is present prove nothing;
/// one agreeing it is gone when it is gone is card detection with content.
fn wait_for_medium_gone(msg_buf: &mut [u8; MSG_BUF_LEN]) -> u64 {
    for _ in 0..MEDIUM_GONE_TRIES {
        let request = BlockReadRequest {
            size: BlockReadRequest::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            sector: 0,
        };
        if encode(&request, &mut msg_buf[..BlockReadRequest::WIRE_SIZE]).is_err() {
            return fail(0x36, 1);
        }
        if call(msg_buf, BlockDevice::READ).is_err() {
            return fail(0x36, 2);
        }
        let bytes = read_kernel_filled::<{ BlockReadReply::WIRE_SIZE }>(msg_buf);
        let reply: BlockReadReply = match decode(&bytes) {
            Ok(reply) => reply,
            Err(_) => return fail(0x36, 3),
        };
        if reply.status == BlockError::NoMedium as u32 {
            return MEDIUM_GONE_REPORT;
        }
        // Any other failure is a different fact: the medium is still there and
        // something else went wrong, which this leg must not report as a card
        // having left.
        if reply.status != BlockError::Ok as u32 {
            return fail(0x36, 0x100 | u64::from(reply.status));
        }
    }
    fail(0x36, 0x200)
}

fn run(id: u64) -> u64 {
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    if id & MEDIUM_GONE != 0 {
        return wait_for_medium_gone(&mut msg_buf);
    }
    let r = read_and_verify(&mut msg_buf, 0, DISK_MAGIC);
    if r != 0 {
        return r;
    }
    let r = read_and_verify(&mut msg_buf, 1, SECTOR1_MAGIC);
    if r != 0 {
        return r;
    }
    // One client runs the out-of-line round trip, so exactly one program
    // writes the sector the boot script later reads out of the disk image —
    // two would make the medium's contents a race rather than evidence. The
    // ids are 1 and 2 (the kernel's spawn arguments), and this is the one that
    // does *not* run the conformance suite below, so each client carries one
    // proof rather than one carrying both.
    if id == 2 {
        let r = out_of_line_round_trip(&mut msg_buf);
        if r != 0 {
            return r;
        }
    }
    if id == 1 {
        let report = match conformance(&mut msg_buf) {
            Ok(report) => report,
            Err(code) => return code,
        };
        // Every rule reached and none broken. `is_complete` rather than
        // `is_clean`: a transcript that skipped a rule reports nothing failed,
        // and treating that as a pass is the failure mode a conformance suite
        // exists to prevent rather than to have.
        if !report.is_complete() {
            return fail(
                0x34,
                u64::from(report.failed) << 32
                    | u64::from(report.unchecked) << 8
                    | u64::from(report.offending_ordinal & 0xff),
            );
        }
        // And the rule that would be easiest to leave unreached, named
        // explicitly so a future transcript that stops exercising it fails
        // here rather than quietly narrowing what "conformant" means.
        if !report.passed(Rule::VendorMethodsNeedANamespace) {
            return fail(0x35, 0);
        }
    }
    DISK_MAGIC.rotate_left(8 * id as u32)
}

/// Entry: the kernel's `spawn_user` set SP to the top of the mapped user
/// stack, so plain Rust runs from the first instruction.
// SAFETY: the unmangled `_start` symbol is the ELF entry the linker script
// names; nothing else in this single-binary program can collide with it.
#[unsafe(no_mangle)]
extern "C" fn _start(id: u64) -> ! {
    let report = run(id);
    let _ = syscall2(SYS_DEBUG_WRITE, report, 0);
    let expected = if id & MEDIUM_GONE != 0 {
        MEDIUM_GONE_REPORT
    } else {
        DISK_MAGIC.rotate_left(8 * id as u32)
    };
    let code = u64::from(report != expected);
    let _ = syscall2(SYS_PROCESS_EXIT, code, 0);
    // ProcessExit never returns; keep the type honest without UB.
    loop {
        core::hint::spin_loop();
    }
}

/// A panic must not hang the boot: report a distinct code and exit.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, fail(0xff, 0), 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 1, 0);
    loop {
        core::hint::spin_loop();
    }
}
