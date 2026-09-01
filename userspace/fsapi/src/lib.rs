// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Talking to the filesystem service, for whoever is going to.**
//!
//! The seven operations `fs_service.isl` declares, the transfer buffer they
//! carry bytes in, and the two addresses a client maps things at. No policy:
//! which files to open and what to do with them is the caller's, because that
//! is the part that differs between one client and the next.
//!
//! **It lived in `//userspace/fs-client`**, which was the only program that
//! spoke this contract, and it could not be shared from there: a `no_main`
//! ring-3 binary is not a library. A second client — the compiler that Phase 5
//! makes a program rather than a function call — is what makes extracting it
//! right rather than speculative, which is the rule `//userspace/elfload`
//! recorded when the same thing happened to the ELF parser (D294, D307).
//!
//! **The addresses stay constants; the endpoint could not.** Every client is
//! its own process with its own address space, so "the buffer maps here" is the
//! same fact for all of them. The *handle* is not: it is 0 only for a client
//! whose table the kernel's boot glue filled in, and a child that receives the
//! service by `ProcessGrant` gets whatever slot was free — 8, in the first one
//! that tried. That is what `StartupHandles.endpoint` exists to say, and this
//! crate has to be told rather than assume (D307).
//!
//! So [`set_service_endpoint`] exists and defaults to 0: a program started by
//! boot needs no call, and one started by a parent makes it before its first
//! operation.
//!
//! Normative: docs/storage/02-file-io-and-caching.md,
//! docs/roadmap/04-self-hosting.md ("Phase 5")

#![no_std]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use fs_service::{
    FileSystem, FsCloseReply, FsCloseRequest, FsOpenReply, FsOpenRequest, FsReadReply,
    FsReadRequest, FsSyncReply, FsSyncRequest, FsWriteReply, FsWriteRequest,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_sdk::{Endpoint, Handle as SdkHandle, Platform as _, Transfer, machine::Machine};
use tessera_uabi::fail;

/// The service, at the handle boot installs — the default, not a law.
pub const SERVICE_ENDPOINT_HANDLE: u64 = 0;

/// Where this program's filesystem service actually is.
///
/// A `u32` because a handle is one, and atomic because it is written once
/// before any operation and read by all of them; there is no lock in a program
/// with one thread and nothing here to order against.
static SERVICE_ENDPOINT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(SERVICE_ENDPOINT_HANDLE as u32);

/// Says where the service is, for a program that was told rather than born
/// knowing.
///
/// Called before the first operation. A program started by boot never needs it;
/// one started by a parent reads `StartupHandles.endpoint` and passes it here.
pub fn set_service_endpoint(handle: u32) {
    SERVICE_ENDPOINT.store(handle, core::sync::atomic::Ordering::Relaxed);
}

/// The endpoint every operation below sends on.
fn endpoint() -> u64 {
    u64::from(SERVICE_ENDPOINT.load(core::sync::atomic::Ordering::Relaxed))
}

/// Sized for the widest struct on the contract, which is the open request.
pub const MSG_BUF_LEN: usize = 192;

/// Where the read buffer is mapped. Always the same address: handing it to the
/// service revokes this program's mapping, so it is free again every time.
pub const BUFFER_VA: u64 = 0x0000_1000_0120_0000;
pub const BUFFER_LEN: usize = 512;

/// What `testdata/mkimage.sh` writes into `/hello.txt`.

/// The rights a buffer carries across the wire, from the contract rather than
/// typed here to match it.
pub fn buffer_rights() -> u64 {
    FsReadRequest::BUFFER_RIGHTS
}

/// The one page this client moves bytes through, and whether it is mapped.
///
/// The flag is the point. Handing the page to the service revokes this
/// program's mapping of it, and the kernel refuses a second mapping of an
/// address that already has one — so "is it mapped?" depends on what this
/// program did last, and answering it from the call order was wrong the first
/// time a write followed a read.
pub struct Buffer {
    handle: SdkHandle,
    mapped: bool,
}

impl Buffer {
    pub fn new() -> Result<Self, u64> {
        let handle = Machine
            .memory_create(BUFFER_LEN as u64)
            .map_err(|_| fail(0xd5, 1))?;
        Ok(Buffer {
            handle,
            mapped: false,
        })
    }

    /// Puts the page at `BUFFER_VA`, or leaves it where it already is.
    pub fn map(&mut self) -> Result<(), u64> {
        if self.mapped {
            return Ok(());
        }
        Machine
            .memory_map(self.handle, BUFFER_VA)
            .map_err(|_| fail(0xd7, 1))?;
        self.mapped = true;
        Ok(())
    }

    /// Records that the page went across the wire and came back at `handle`:
    /// a new number, and no mapping.
    pub fn returned(&mut self, handle: SdkHandle) {
        self.handle = handle;
        self.mapped = false;
    }
}

/// Where a file's own memory object is mapped. One address, reused: this

/// client reads one file by mapping at a time.
pub const FILE_VA: u64 = 0x0000_1000_0130_0000;
/// A page: what a mapping of a file shorter than one still occupies, and so
/// the length its unmap names.
pub const PAGE_LEN: u64 = 4096;
/// `MapRights::READ` — all a reader needs.
pub const MAP_READ: u32 = 0x1;
/// `MapRights::READ | WRITE`, for the file this client changes through memory.
pub const MAP_RW: u32 = 0x1 | 0x2;
/// Long enough to give the file a page to write into, and recognisable in the
/// volume if the mapped write below never lands on top of it.

/// Opens `path` and takes the file's memory object with the reply.
///
/// The object is the point: with it the bytes of the file are *loads*, and the
/// service is out of the loop until a page is missing. `Ok((file, length,
/// object))`, where the object is `None` for an empty file — there is nothing
/// to page.
pub fn open_mapped(
    path: &[u8],
    buf: &mut [u8; MSG_BUF_LEN],
) -> Result<(u32, u64, Option<SdkHandle>), u64> {
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
    let mut arrived = [SdkHandle(0); 1];
    let (_, taken) = Machine
        .call_with(
            Endpoint(SdkHandle(endpoint())),
            FileSystem::OPEN,
            &out[..FsOpenRequest::WIRE_SIZE],
            buf,
            &[],
            &mut arrived,
        )
        .map_err(|_| fail(0xd1, 5))?;
    let reply: FsOpenReply = decode(&buf[..FsOpenReply::WIRE_SIZE]).map_err(|_| fail(0xd1, 6))?;
    if reply.status != 0 {
        return Err(fail(0xd1, 0x100 | u64::from(reply.status)));
    }
    let object = if taken == 0 { None } else { Some(arrived[0]) };
    Ok((reply.file, reply.length, object))
}

pub fn open(path: &[u8], buf: &mut [u8; MSG_BUF_LEN]) -> Result<(u32, u64), u64> {
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
            Endpoint(SdkHandle(endpoint())),
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
pub fn read(
    file: u32,
    offset: u64,
    length: u64,
    buffer: &mut Buffer,
    buf: &mut [u8; MSG_BUF_LEN],
) -> Result<u64, u64> {
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
        handle: buffer.handle,
        rights: buffer_rights(),
        shared: false,
    }];
    let mut back = [SdkHandle(0); 1];
    let (_, returned) = Machine
        .call_with(
            Endpoint(SdkHandle(endpoint())),
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
    buffer.returned(back[0]);
    let reply: FsReadReply = decode(&buf[..FsReadReply::WIRE_SIZE]).map_err(|_| fail(0xd2, 4))?;
    if reply.status != 0 {
        return Err(fail(0xd2, 0x100 | u64::from(reply.status)));
    }
    Ok(reply.read)
}

/// The bytes this client writes and then insists are on the medium.
///
/// The boot script greps the disk image for them **after** the machine has
/// stopped, which is the whole durability claim reduced to something an
/// outside observer can check: an acknowledged write is on stable media, not
/// in somebody's cache.

/// Creates `name` and returns the file id it was opened at.
pub fn create(name: &[u8], buf: &mut [u8; MSG_BUF_LEN]) -> Result<u32, u64> {
    let mut padded = [0u8; 128];
    padded[..name.len()].copy_from_slice(name);
    let request = FsOpenRequest {
        size: FsOpenRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        path: padded,
        path_len: name.len() as u32,
        reserved: 0,
    };
    let mut out = [0u8; MSG_BUF_LEN];
    encode(&request, &mut out[..FsOpenRequest::WIRE_SIZE]).map_err(|_| fail(0xda, 1))?;
    Machine
        .call(
            Endpoint(SdkHandle(endpoint())),
            FileSystem::CREATE,
            &out[..FsOpenRequest::WIRE_SIZE],
            buf,
        )
        .map_err(|_| fail(0xda, 2))?;
    let reply: FsOpenReply = decode(&buf[..FsOpenReply::WIRE_SIZE]).map_err(|_| fail(0xda, 3))?;
    if reply.status != 0 {
        return Err(fail(0xda, 0x100 | u64::from(reply.status)));
    }
    Ok(reply.file)
}

/// Writes `bytes` at `offset` out of `buffer`, and hands back the handle the
/// buffer returned at.
pub fn write(
    file: u32,
    offset: u64,
    bytes: &[u8],
    buffer: &mut Buffer,
    buf: &mut [u8; MSG_BUF_LEN],
) -> Result<u64, u64> {
    // Fill the buffer before it goes: handing it over revokes this program's
    // mapping of it, so the bytes have to be in it first.
    buffer.map()?;
    // SAFETY: the kernel just mapped this object's single page read-write at
    // `BUFFER_VA` for this process, and nothing else here references it.
    let page = unsafe { core::slice::from_raw_parts_mut(BUFFER_VA as *mut u8, BUFFER_LEN) };
    page[..bytes.len()].copy_from_slice(bytes);

    let request = FsWriteRequest {
        size: FsWriteRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        file,
        reserved: 0,
        offset,
        length: bytes.len() as u64,
        buffer: HandleRef::new(0),
    };
    let mut out = [0u8; MSG_BUF_LEN];
    encode(&request, &mut out[..FsWriteRequest::WIRE_SIZE]).map_err(|_| fail(0xdb, 2))?;
    let give = [Transfer {
        handle: buffer.handle,
        rights: buffer_rights(),
        shared: false,
    }];
    let mut back = [SdkHandle(0); 1];
    let (_, returned) = Machine
        .call_with(
            Endpoint(SdkHandle(endpoint())),
            FileSystem::WRITE,
            &out[..FsWriteRequest::WIRE_SIZE],
            buf,
            &give,
            &mut back,
        )
        .map_err(|_| fail(0xdb, 3))?;
    if returned == 0 {
        return Err(fail(0xdb, 4));
    }
    buffer.returned(back[0]);
    let reply: FsWriteReply = decode(&buf[..FsWriteReply::WIRE_SIZE]).map_err(|_| fail(0xdb, 5))?;
    if reply.status != 0 {
        return Err(fail(0xdb, 0x100 | u64::from(reply.status)));
    }
    Ok(reply.written)
}

/// Asks for the write to be on stable media, and does not carry on until the
/// answer says it is.
pub fn sync(file: u32, buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    let request = FsSyncRequest {
        size: FsSyncRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        file,
        reserved: 0,
    };
    let mut out = [0u8; MSG_BUF_LEN];
    encode(&request, &mut out[..FsSyncRequest::WIRE_SIZE]).map_err(|_| fail(0xdc, 1))?;
    Machine
        .call(
            Endpoint(SdkHandle(endpoint())),
            FileSystem::SYNC,
            &out[..FsSyncRequest::WIRE_SIZE],
            buf,
        )
        .map_err(|_| fail(0xdc, 2))?;
    let reply: FsSyncReply = decode(&buf[..FsSyncReply::WIRE_SIZE]).map_err(|_| fail(0xdc, 3))?;
    if reply.status != 0 {
        return Err(fail(0xdc, 0x100 | u64::from(reply.status)));
    }
    Ok(())
}

/// Removes a name, and reports what the service said.
pub fn unlink(name: &[u8], buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    let mut padded = [0u8; 128];
    padded[..name.len()].copy_from_slice(name);
    let request = FsOpenRequest {
        size: FsOpenRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        path: padded,
        path_len: name.len() as u32,
        reserved: 0,
    };
    let mut out = [0u8; MSG_BUF_LEN];
    encode(&request, &mut out[..FsOpenRequest::WIRE_SIZE]).map_err(|_| fail(0xe0, 1))?;
    Machine
        .call(
            Endpoint(SdkHandle(endpoint())),
            FileSystem::UNLINK,
            &out[..FsOpenRequest::WIRE_SIZE],
            buf,
        )
        .map_err(|_| fail(0xe0, 2))?;
    let reply: FsCloseReply = decode(&buf[..FsCloseReply::WIRE_SIZE]).map_err(|_| fail(0xe0, 3))?;
    if reply.status != 0 {
        return Err(fail(0xe0, 0x100 | u64::from(reply.status)));
    }
    Ok(())
}

pub fn close(file: u32, buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
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
            Endpoint(SdkHandle(endpoint())),
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
