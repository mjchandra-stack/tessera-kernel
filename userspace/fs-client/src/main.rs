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
//!
//! **And it is a loader**, because it is the one process holding both a
//! filesystem and a job. It reads `/program.elf` off the same volume — a
//! program in no store, no accessor and no kernel image — creates a process,
//! maps its segments and starts it. That composition is Phase 2's third bullet
//! and the reason this program is the one that got the job seed
//! (`build/README.md`, D294); the authority is one right over one job, not a
//! privilege, which is what makes "loader" a role rather than a place.
//!
//! Normative: docs/roadmap/03-composition-and-self-hosting.md ("Phase 2")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use fs_service::{
    FileSystem, FsCloseReply, FsCloseRequest, FsOpenReply, FsOpenRequest, FsReadReply,
    FsReadRequest, FsSyncReply, FsSyncRequest, FsWriteReply, FsWriteRequest,
};
use process_abi::{
    AddressSpaceMapArgs, ProcessCreateArgs, ProcessStartArgs, ProcessWaitArgs,
    Rights as ProcessRights,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_sdk::{Endpoint, Handle as SdkHandle, Platform as _, Transfer, machine::Machine};
use tessera_uabi::{fail, syscall2};

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
/// A page: what a mapping of a file shorter than one still occupies, and so
/// the length its unmap names.
const PAGE_LEN: u64 = 4096;
/// `MapRights::READ` — all a reader needs.
const MAP_READ: u32 = 0x1;
/// `MapRights::READ | WRITE`, for the file this client changes through memory.
const MAP_RW: u32 = 0x1 | 0x2;
/// Long enough to give the file a page to write into, and recognisable in the
/// volume if the mapped write below never lands on top of it.
const FILLER: &[u8] = b"................................................................";
/// What the client stores **through its mapping**, with no message to the
/// service at all. The boot script looks for exactly this in the volume after
/// the machine has stopped: finding it means a store into memory became a byte
/// on a disk.
const MAPPED: &[u8] = b"tessera mapped write ok\n";
/// Stored through the same mapping **after** the first sync cleaned the page.
///
/// This is the one that needs the page to have been re-protected: a page left
/// writable when it was marked clean takes this store with no fault, nothing
/// records it, and the second sync finds no work to do. The boot script looks
/// for both markers, so a lost second write fails on this one alone.
const MAPPED_AGAIN: &[u8] = b"tessera second mapped ok\n";
/// Where the second marker goes — past the first, so both survive and the
/// script can tell which one is missing.
const MAPPED_AGAIN_AT: usize = 32;

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
        shared: false,
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
        shared: false,
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

    // Given back before the next file needs the address. One window, reused:
    // a program that never unmaps holds every address it has ever used, and
    // the second `map_object` here fails on an address still occupied by the
    // first — which is how this was found.
    if Machine.unmap(FILE_VA, PAGE_LEN).is_err() {
        return fail(0xe6, 0);
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

    // --- a write that never becomes a message ---
    //
    // Everything above went through the service: `Write` carried a buffer, and
    // `Sync` flushed what the service had already put on the medium. This is
    // the other path — the client stores into its own mapping of the file, the
    // service is never told, and `Sync` has to find the change in the kernel's
    // dirty set or answer for a write it never saw.
    let mapped = match create(b"mapped.txt", &mut buf) {
        Ok(file) => file,
        Err(code) => return code,
    };
    // Give it a page to write into. A file of zero length has no object, and
    // there would be nothing to map.
    let count = match write(mapped, 0, FILLER, &mut buffer, &mut buf) {
        Ok(count) => count,
        Err(code) => return code,
    };
    if count != FILLER.len() as u64 {
        return fail(0xe4, count);
    }
    if let Err(code) = sync(mapped, &mut buf) {
        return code;
    }
    if let Err(code) = close(mapped, &mut buf) {
        return code;
    }

    // Re-opened, because an object comes with `Open` and this file had no size
    // when it was created.
    let (mapped, length, object) = match open_mapped(b"/mapped.txt", &mut buf) {
        Ok(triple) => triple,
        Err(code) => return code,
    };
    if length != FILLER.len() as u64 {
        return fail(0xe5, length);
    }
    let Some(object) = object else {
        return fail(0xe5, 1);
    };
    if Machine.map_object(object, FILE_VA, MAP_RW).is_err() {
        return fail(0xe5, 2);
    }
    // The store. It faults once — the page is supplied read-only so it does —
    // and the kernel records the page written.
    // SAFETY: the kernel just mapped the file's object read-write at `FILE_VA`
    // for this process, and nothing else here references that range.
    let page = unsafe { core::slice::from_raw_parts_mut(FILE_VA as *mut u8, MAPPED.len()) };
    page.copy_from_slice(MAPPED);

    // And the claim: after this answers, the bytes are on the medium. Nothing
    // told the service what changed — it has to ask the kernel.
    if let Err(code) = sync(mapped, &mut buf) {
        return code;
    }

    // **A second store, after the flush.** The page is clean again, and the
    // only thing that makes this store visible is the fault the kernel put
    // back when it cleaned it. Written past the first marker so both are in the
    // volume and the script can say which one went missing.
    // SAFETY: the object is still mapped read-write at `FILE_VA`, and this
    // range is inside the page mapped above.
    let again = unsafe {
        core::slice::from_raw_parts_mut(
            (FILE_VA + MAPPED_AGAIN_AT as u64) as *mut u8,
            MAPPED_AGAIN.len(),
        )
    };
    again.copy_from_slice(MAPPED_AGAIN);
    if let Err(code) = sync(mapped, &mut buf) {
        return code;
    }
    if Machine.unmap(FILE_VA, PAGE_LEN).is_err() {
        return fail(0xe6, 1);
    }
    if let Err(code) = close(mapped, &mut buf) {
        return code;
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

    // **And an executable, off the same filesystem — run.** Everything above
    // reads data; this reads a *program* — one that is in no store, no
    // accessor and no kernel image, placed on the volume by the build — and
    // then executes it. That is Phase 2's third bullet, and what it needs is
    // one process holding both a job and a filesystem: this one, which is why
    // boot seeds it [`JOB_HANDLE`] on top of the service endpoint it already
    // had. The child's report reaches the check's sink by itself; what this
    // program judges is that it exited, and cleanly.
    match with_the_program(b"/program.elf", &mut buf, execute) {
        Ok(0) => {}
        Ok(other) => return fail(0xe9, other as u32 as u64),
        Err(code) => return code,
    }
    // **And a file that is not a program is refused before anything is
    // created.** Without this the parse cannot fail: the only file it is ever
    // shown is a valid one, so removing it entirely would pass. `/hello.txt`
    // is the negative — a real file, with real bytes, that is not an image.
    match with_the_program(b"/hello.txt", &mut buf, execute) {
        Err(code) if code == fail(0xe5, 0) => {}
        Err(other) => return fail(0xe6, other & 0xffff),
        Ok(_) => return fail(0xe6, 0),
    }

    // The disk magic rotated like every other client's report, so the check's
    // sink is a value only this sequence produces.
    u64::from_le_bytes(*b"TESSERAF").rotate_left(8)
}

/// Where the program on the volume is mapped while it is read and loaded.
const PROGRAM_VA: u64 = 0x0000_1000_0140_0000;

/// The job boot seeds this process, and the whole of the authority that makes
/// it a loader: one right, `create-process`, over one job.
const JOB_HANDLE: u32 = 1;

/// Where a child's stack goes in *its* address space — this port's user half,
/// which is the child's to lay out and not this program's.
const CHILD_STACK_BASE: u64 = 0x0000_0f00_0000_0000;

const SYS_PROCESS_CREATE: u64 = 8;
const SYS_ADDRESS_SPACE_MAP: u64 = 9;
const SYS_PROCESS_START: u64 = 10;
const SYS_PROCESS_WAIT: u64 = 51;

/// Maps `path` through the service, hands its bytes to `with`, and releases the
/// window on **both** paths.
///
/// The bytes are *loads*, not a copy: the file's memory object comes back with
/// the open reply and is mapped here, so the segment sources a loader hands the
/// kernel are addresses in this program's own address space. A file too large
/// to be a program on this volume is refused before it is mapped.
///
/// **Released on both paths, because the window is used twice** — once for the
/// program and once for the file that is not one. Mapping is not idempotent, so
/// a window left behind by the first makes the second fail for a reason that
/// has nothing to do with what it was asked.
fn with_the_program<R>(
    path: &[u8],
    buf: &mut [u8; MSG_BUF_LEN],
    with: impl FnOnce(&[u8]) -> Result<R, u64>,
) -> Result<R, u64> {
    let (file, length, object) = open_mapped(path, buf)?;
    // Smaller than the volume; a length past that is a wrong inode rather than
    // a wrong program. **No lower bound**, deliberately: a short file is not a
    // program either, and the parse below is what should say so — a length
    // bound that rejected it first would be a second answer to the same
    // question, and the one that fired would be an accident of ordering.
    if length > 1 << 20 {
        return Err(fail(0xe4, length));
    }
    let Some(object) = object else {
        return Err(fail(0xe4, 1));
    };
    if Machine.map_object(object, PROGRAM_VA, MAP_READ).is_err() {
        return Err(fail(0xe4, 2));
    }
    // SAFETY: the kernel just mapped the file's object read-only at
    // `PROGRAM_VA` for this process, and a file object is a whole number of
    // pages — so a slice of the file's length is inside the mapping. Nothing
    // else here references the range, and it is unmapped below before the
    // window is used again.
    let image = unsafe { core::slice::from_raw_parts(PROGRAM_VA as *const u8, length as usize) };
    // **Touched from here before the kernel is asked to read it.**
    //
    // The object is paged: its pages arrive when a fault on them is served by
    // the service, and the path that serves one is the *user* fault path. A
    // loader hands the kernel addresses in this address space and the kernel
    // copies from them at EL1 — where a missing page is not a request to a
    // pager but a data abort in the kernel, which is what this cost the first
    // time it ran (`far` one page past the mapping, translation fault, no line
    // to blame). One read per page is the whole fix: the pages are resident
    // before anything but this program depends on them being.
    for page in (0..length).step_by(PAGE_LEN as usize) {
        // SAFETY: inside the mapping established above; volatile so the read is
        // performed rather than elided, which is the entire point of it.
        unsafe { core::ptr::read_volatile((PROGRAM_VA + page) as *const u8) };
    }
    let verdict = with(image);
    let pages = (length as usize).div_ceil(PAGE_LEN as usize) * PAGE_LEN as usize;
    if Machine.unmap(PROGRAM_VA, pages as u64).is_err() {
        return Err(fail(0xe4, 3));
    }
    close(file, buf)?;
    verdict
}

/// Creates a process from `image`, starts it, and waits for it to exit.
///
/// **The parse is `//userspace/elfload`'s**, shared with the root task rather
/// than written again here: a second copy of a hundred lines of header
/// arithmetic is a second place for it to be wrong, and this one would have had
/// no tests at all (`build/README.md`, D294). What is this program's is the
/// three syscalls the parse feeds — create, map, start — and the job it holds
/// the authority in.
fn execute(image: &[u8]) -> Result<i32, u64> {
    let parsed = tessera_elfload::parse(image).ok_or(fail(0xe5, 0))?;
    let create = ProcessCreateArgs {
        size: ProcessCreateArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        job: HandleRef::new(JOB_HANDLE),
        reserved: 0,
    };
    let mut args = [0u8; 256];
    encode(&create, &mut args[..ProcessCreateArgs::WIRE_SIZE]).map_err(|_| fail(0xea, 0))?;
    let child = syscall2(SYS_PROCESS_CREATE, args.as_ptr() as u64, 0);
    if child < 0 {
        return Err(fail(0xea, (-child) as u64 & 0xffff));
    }
    let child = child as u32;

    for segment in parsed.segments() {
        map_segment(child, image, *segment)?;
    }

    let start = ProcessStartArgs {
        size: ProcessStartArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        process: HandleRef::new(child),
        reserved: 0,
        entry: parsed.entry,
        stack: CHILD_STACK_BASE,
        arg: 0,
        // No startup message: what this child is for is where its bytes came
        // from, and a message would be one more thing a failure could be.
        message_ptr: 0,
        message_len: 0,
        message_va: 0,
    };
    encode(&start, &mut args[..ProcessStartArgs::WIRE_SIZE]).map_err(|_| fail(0xeb, 0))?;
    let started = syscall2(SYS_PROCESS_START, args.as_ptr() as u64, 0);
    if started < 0 {
        return Err(fail(0xeb, (-started) as u64 & 0xffff));
    }

    let wait = ProcessWaitArgs {
        size: ProcessWaitArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        process: HandleRef::new(child),
        reserved: 0,
    };
    encode(&wait, &mut args[..ProcessWaitArgs::WIRE_SIZE]).map_err(|_| fail(0xec, 0))?;
    let code = syscall2(SYS_PROCESS_WAIT, args.as_ptr() as u64, 0);
    if code < 0 {
        return Err(fail(0xec, (-code) as u64 & 0xffff));
    }
    Ok(code as u32 as i32)
}

/// Maps one segment into `child`: the file bytes, then the zero-filled tail.
///
/// The kernel maps anonymous zeroed pages and copies into them, so a `.bss` is
/// a map with no source rather than a copy of zeros.
fn map_segment(child: u32, image: &[u8], segment: tessera_elfload::Segment) -> Result<(), u64> {
    let mut rights = ProcessRights(0);
    if segment.flags & tessera_elfload::PF_R != 0 {
        rights = ProcessRights(rights.bits() | ProcessRights::READ.bits());
    }
    if segment.flags & tessera_elfload::PF_W != 0 {
        rights = ProcessRights(rights.bits() | ProcessRights::WRITE.bits());
    }
    if segment.flags & tessera_elfload::PF_X != 0 {
        rights = ProcessRights(rights.bits() | ProcessRights::EXECUTE.bits());
    }
    let mut args = [0u8; AddressSpaceMapArgs::WIRE_SIZE];
    let covered = tessera_elfload::page_up(segment.filesz);
    // `(source, at, length)` for the file bytes and for the tail, so the two
    // maps are one encode rather than two spellings of it.
    let legs = [
        (
            image
                .get(segment.offset as usize..(segment.offset + segment.filesz) as usize)
                .map_or(0, |src| src.as_ptr() as u64),
            segment.vaddr,
            segment.filesz,
        ),
        (0, segment.vaddr + covered, segment.memsz.saturating_sub(covered)),
    ];
    for (src, vaddr, length) in legs {
        if length == 0 {
            continue;
        }
        let map = AddressSpaceMapArgs {
            size: AddressSpaceMapArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            process: HandleRef::new(child),
            reserved: 0,
            vaddr,
            length,
            rights,
            src,
        };
        encode(&map, &mut args).map_err(|_| fail(0xed, 0))?;
        let mapped = syscall2(SYS_ADDRESS_SPACE_MAP, args.as_ptr() as u64, 0);
        if mapped < 0 {
            return Err(fail(0xed, (-mapped) as u64 & 0xffff));
        }
    }
    Ok(())
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
