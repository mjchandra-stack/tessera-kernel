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
    FsReadRequest, FsSyncReply, FsSyncRequest, FsWriteReply, FsWriteRequest,
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

/// The one page this client moves bytes through, and whether it is mapped.
///
/// The flag is the point. Handing the page to the service revokes this
/// program's mapping of it, and the kernel refuses a second mapping of an
/// address that already has one — so "is it mapped?" depends on what this
/// program did last, and answering it from the call order was wrong the first
/// time a write followed a read.
struct Buffer {
    handle: SdkHandle,
    mapped: bool,
}

impl Buffer {
    fn new() -> Result<Self, u64> {
        let handle = Machine
            .memory_create(BUFFER_LEN as u64)
            .map_err(|_| fail(0xd5, 1))?;
        Ok(Buffer {
            handle,
            mapped: false,
        })
    }

    /// Puts the page at `BUFFER_VA`, or leaves it where it already is.
    fn map(&mut self) -> Result<(), u64> {
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
    fn returned(&mut self, handle: SdkHandle) {
        self.handle = handle;
        self.mapped = false;
    }
}

/// Where a file's own memory object is mapped. One address, reused: this
/// client reads one file by mapping at a time.
const FILE_VA: u64 = 0x0000_1000_0130_0000;
/// `MapRights::READ` — all a reader needs, and all `Open` hands out.
const MAP_READ: u32 = 0x1;

/// Opens `path` and takes the file's memory object with the reply.
///
/// The object is the point: with it the bytes of the file are *loads*, and the
/// service is out of the loop until a page is missing. `Ok((file, length,
/// object))`, where the object is `None` for an empty file — there is nothing
/// to page.
fn open_mapped(
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
            Endpoint(SdkHandle(SERVICE_ENDPOINT_HANDLE)),
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
const DURABLE: &[u8] = b"tessera durable write\n";

/// Creates `name` and returns the file id it was opened at.
fn create(name: &[u8], buf: &mut [u8; MSG_BUF_LEN]) -> Result<u32, u64> {
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
            Endpoint(SdkHandle(SERVICE_ENDPOINT_HANDLE)),
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
fn write(
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
    }];
    let mut back = [SdkHandle(0); 1];
    let (_, returned) = Machine
        .call_with(
            Endpoint(SdkHandle(SERVICE_ENDPOINT_HANDLE)),
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
fn sync(file: u32, buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
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
            Endpoint(SdkHandle(SERVICE_ENDPOINT_HANDLE)),
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
fn unlink(name: &[u8], buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
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
            Endpoint(SdkHandle(SERVICE_ENDPOINT_HANDLE)),
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

    let (file, length, object) = match open_mapped(b"/hello.txt", &mut buf) {
        Ok(triple) => triple,
        Err(code) => return code,
    };
    // The length the service reported is the inode's, so a wrong one is a
    // wrong inode — caught here rather than after the bytes have been read.
    if length != HELLO.len() as u64 {
        return fail(0xd4, length);
    }

    // **The file, read as memory.** `Open` handed back its object; mapping it
    // and loading from it is the whole read — no message, no copy, and the
    // service is not involved until a page is missing. The first load below is
    // exactly that: it faults, the kernel asks the service, and the load runs
    // again with the page there.
    let Some(object) = object else {
        return fail(0xe2, 0);
    };
    if Machine.map_object(object, FILE_VA, MAP_READ).is_err() {
        return fail(0xe2, 1);
    }
    // SAFETY: the kernel just mapped the file's object read-only at `FILE_VA`
    // for this process, and nothing else here forms a reference to that range.
    let mapped = unsafe { core::slice::from_raw_parts(FILE_VA as *const u8, HELLO.len()) };
    for (index, (got, want)) in mapped.iter().zip(HELLO).enumerate() {
        if got != want {
            return fail(0xe3, index as u64);
        }
    }

    let mut buffer = match Buffer::new() {
        Ok(buffer) => buffer,
        Err(code) => return code,
    };
    let got = match read(file, 0, HELLO.len() as u64, &mut buffer, &mut buf) {
        Ok(got) => got,
        Err(code) => return code,
    };
    if got != HELLO.len() as u64 {
        return fail(0xd6, got);
    }

    if let Err(code) = buffer.map() {
        return code;
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

    // --- the write path, and the durability chain ---

    let written = match create(b"durable.txt", &mut buf) {
        Ok(file) => file,
        Err(code) => return code,
    };
    let count = match write(written, 0, DURABLE, &mut buffer, &mut buf) {
        Ok(count) => count,
        Err(code) => return code,
    };
    if count != DURABLE.len() as u64 {
        return fail(0xdd, count);
    }
    // Only after this answers is the write allowed to be called durable, and
    // only then does the boot script's search of the disk image mean anything.
    if let Err(code) = sync(written, &mut buf) {
        return code;
    }

    // Read it back through the service, so the claim is not just that the
    // bytes are somewhere on the medium but that the file holds them.
    let read_back = match read(written, 0, DURABLE.len() as u64, &mut buffer, &mut buf) {
        Ok(read_back) => read_back,
        Err(code) => return code,
    };
    if read_back != DURABLE.len() as u64 {
        return fail(0xde, read_back);
    }
    if let Err(code) = buffer.map() {
        return code;
    }
    // SAFETY: as above — the kernel just mapped this object at `BUFFER_VA`.
    let bytes = unsafe { core::slice::from_raw_parts(BUFFER_VA as *const u8, BUFFER_LEN) };
    for (index, (got, want)) in bytes.iter().zip(DURABLE).enumerate() {
        if got != want {
            return fail(0xdf, index as u64);
        }
    }

    // A name removed is a name gone. Created and removed in one breath, so the
    // volume ends as it began — and then asked for again, because an unlink
    // that answered OK and left the entry would pass any check that read only
    // the reply.
    if let Err(code) = create(b"transient.txt", &mut buf) {
        return code;
    }
    if let Err(code) = unlink(b"transient.txt", &mut buf) {
        return code;
    }
    match open(b"/transient.txt", &mut buf) {
        Err(code) if code == fail(0xd1, 0x100 | 1) => {}
        Err(other) => return fail(0xe1, other & 0xffff),
        Ok(_) => return fail(0xe1, 0),
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
