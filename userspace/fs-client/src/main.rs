// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Opens a file and reads it, through the filesystem service.
//!
//! The one program in the stack that asks the question the whole stack exists
//! to answer: **what is in `/hello.txt`?** Every layer below has been proved by
//! something else — the format by `//api/ext2`'s host tests, the transfer path
//! by `blk-client`, the block layer by the class-conformance battery — and
//! none of that establishes that the parts compose.
//!
//! What it checks is the bytes `mke2fs` put there, not a length or a status.
//! A service that answered `OK` with a zero-filled buffer would pass every
//! check that read only the reply.

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use fs_service::{
    FileSystem, FsCloseReply, FsCloseRequest, FsOpenReply, FsOpenRequest, FsReadReply,
    FsReadRequest,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_sdk::{Endpoint, Handle as SdkHandle, Platform as _, Transfer, machine::Machine};
use tessera_uabi::fail;

/// The service, at the one handle boot installs.
const SERVICE_ENDPOINT_HANDLE: u64 = 0;

/// Sized for the widest struct on the contract, which is the open request.
const MSG_BUF_LEN: usize = 192;

/// Where the read buffer is mapped. Always the same address: handing it to the
/// service revokes this program's mapping, so it is free again every time.
const BUFFER_VA: u64 = 0x0000_1000_0120_0000;
const BUFFER_LEN: usize = 512;

/// What `testdata/mkimage.sh` writes into `/hello.txt`.
const HELLO: &[u8] = b"hello from ext2\n";

/// The rights a buffer carries across the wire, from the contract rather than
/// typed here to match it.
fn buffer_rights() -> u64 {
    FsReadRequest::BUFFER_RIGHTS
}

fn open(path: &[u8], buf: &mut [u8; MSG_BUF_LEN]) -> Result<(u32, u64), u64> {
    if path.len() > 128 {
        return Err(fail(0xd1, 1));
    }
    let mut padded = [0u8; 128];
    padded[..path.len()].copy_from_slice(path);
    let request = FsOpenRequest {
        size: FsOpenRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        path: padded,
        path_len: path.len() as u32,
        reserved: 0,
    };
    let mut out = [0u8; MSG_BUF_LEN];
    encode(&request, &mut out[..FsOpenRequest::WIRE_SIZE]).map_err(|_| fail(0xd1, 2))?;
    Machine
        .call(
            Endpoint(SdkHandle(SERVICE_ENDPOINT_HANDLE)),
            FileSystem::OPEN,
            &out[..FsOpenRequest::WIRE_SIZE],
            buf,
        )
        .map_err(|_| fail(0xd1, 3))?;
    let reply: FsOpenReply = decode(&buf[..FsOpenReply::WIRE_SIZE]).map_err(|_| fail(0xd1, 4))?;
    if reply.status != 0 {
        return Err(fail(0xd1, 0x100 | u64::from(reply.status)));
    }
    Ok((reply.file, reply.length))
}

/// Reads `length` bytes at `offset` into a fresh mapping of `buffer`, and
/// hands back the handle the buffer returned at.
fn read(
    file: u32,
    offset: u64,
    length: u64,
    buffer: SdkHandle,
    buf: &mut [u8; MSG_BUF_LEN],
) -> Result<(SdkHandle, u64), u64> {
    let request = FsReadRequest {
        size: FsReadRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        file,
        reserved: 0,
        offset,
        length,
        // An index into this message's handle vector, not a handle number:
        // the number this program holds means nothing in the service's table.
        buffer: HandleRef::new(0),
    };
    let mut out = [0u8; MSG_BUF_LEN];
    encode(&request, &mut out[..FsReadRequest::WIRE_SIZE]).map_err(|_| fail(0xd2, 1))?;
    let give = [Transfer {
        handle: buffer,
        rights: buffer_rights(),
    }];
    let mut back = [SdkHandle(0); 1];
    let (_, returned) = Machine
        .call_with(
            Endpoint(SdkHandle(SERVICE_ENDPOINT_HANDLE)),
            FileSystem::READ,
            &out[..FsReadRequest::WIRE_SIZE],
            buf,
            &give,
            &mut back,
        )
        .map_err(|_| fail(0xd2, 2))?;
    if returned == 0 {
        // The service kept the buffer, which strands this program's memory
        // where it cannot ask for it again.
        return Err(fail(0xd2, 3));
    }
    let reply: FsReadReply = decode(&buf[..FsReadReply::WIRE_SIZE]).map_err(|_| fail(0xd2, 4))?;
    if reply.status != 0 {
        return Err(fail(0xd2, 0x100 | u64::from(reply.status)));
    }
    Ok((back[0], reply.read))
}

fn close(file: u32, buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    let request = FsCloseRequest {
        size: FsCloseRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        file,
        reserved: 0,
    };
    let mut out = [0u8; MSG_BUF_LEN];
    encode(&request, &mut out[..FsCloseRequest::WIRE_SIZE]).map_err(|_| fail(0xd3, 1))?;
    Machine
        .call(
            Endpoint(SdkHandle(SERVICE_ENDPOINT_HANDLE)),
            FileSystem::CLOSE,
            &out[..FsCloseRequest::WIRE_SIZE],
            buf,
        )
        .map_err(|_| fail(0xd3, 2))?;
    let reply: FsCloseReply = decode(&buf[..FsCloseReply::WIRE_SIZE]).map_err(|_| fail(0xd3, 3))?;
    if reply.status != 0 {
        return Err(fail(0xd3, 0x100 | u64::from(reply.status)));
    }
    Ok(())
}

fn run() -> u64 {
    let mut buf = [0u8; MSG_BUF_LEN];

    let (file, length) = match open(b"/hello.txt", &mut buf) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    // The length the service reported is the inode's, so a wrong one is a
    // wrong inode — caught here rather than after the bytes have been read.
    if length != HELLO.len() as u64 {
        return fail(0xd4, length);
    }

    let mut buffer = match Machine.memory_create(BUFFER_LEN as u64) {
        Ok(handle) => handle,
        Err(_) => return fail(0xd5, 1),
    };
    let (returned, read) = match read(file, 0, HELLO.len() as u64, buffer, &mut buf) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    buffer = returned;
    if read != HELLO.len() as u64 {
        return fail(0xd6, read);
    }

    if Machine.memory_map(buffer, BUFFER_VA).is_err() {
        return fail(0xd7, 1);
    }
    // SAFETY: the kernel just mapped this object's single page read-write at
    // `BUFFER_VA` for this process, and nothing else here references it.
    let bytes = unsafe { core::slice::from_raw_parts(BUFFER_VA as *const u8, BUFFER_LEN) };
    // Every byte, and the offset of the first wrong one if any. A service that
    // answered OK with a zero-filled buffer fails here and nowhere earlier.
    for (index, (got, want)) in bytes.iter().zip(HELLO).enumerate() {
        if got != want {
            return fail(0xd8, index as u64);
        }
    }

    // A second open of a path that is not there, to prove a refusal is a
    // refusal rather than the only answer this client can produce.
    match open(b"/nope.txt", &mut buf) {
        Err(code) if code == fail(0xd1, 0x100 | 1) => {}
        Err(other) => return fail(0xd9, other & 0xffff),
        Ok(_) => return fail(0xd9, 0),
    }

    if let Err(code) = close(file, &mut buf) {
        return code;
    }

    // The disk magic rotated like every other client's report, so the check's
    // sink is a value only this sequence produces.
    u64::from_le_bytes(*b"TESSERAF").rotate_left(8)
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
    Machine.finish(fail(0xff, 0))
}
