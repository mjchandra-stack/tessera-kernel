// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The filesystem service: ext2 over the block service.
//!
//! `docs/drivers/02` puts filesystem services above the block service and
//! below a VFS; this is one of them, and the format is a ported one for the
//! reason `//api/ext2` gives — `mke2fs` decides what the bytes mean, so a
//! check can be wrong about this program and cannot be wrong about ext2.
//!
//! **What this program is, is very little.** The format lives in `api/ext2`,
//! `forbid(unsafe_code)` and host-tested against a real image; the transport
//! is the SDK. What is here is the join: a `BlockIo` that fetches a sector by
//! asking the block service for it, a small table of open files, and the
//! contract's three methods.
//!
//! **Reads copy, and that is a deviation with a name.**
//! `docs/storage/02-file-io-and-caching.md` says there is one cache — the
//! kernel-held pages of a pager-backed memory object — and that `open` hands
//! back a handle to it. No ring-3 program can be handed such an object today:
//! `map_object` has no syscall, and the port where memory objects work is not
//! the port where the pager demo runs. So a read here copies out of a
//! transferred buffer, and `mmap` coherence, readahead and the page cache are
//! deferred rather than approximated (build/README.md).
//!
//! Normative: docs/storage/02-file-io-and-caching.md,
//! docs/drivers/02-storage-networking-usb-pcie.md

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{
    BlockBufferReply, BlockBufferRequest, BlockControlReply, BlockControlRequest, BlockDevice,
    BlockPowerState,
};
use fs_service::{
    FileSystemIncoming, FsCloseReply, FsError, FsOpenReply, FsOpenRequest, FsReadReply,
    FsSyncReply, FsWriteReply,
};
use tessera_ext2::{BlockIo, Fs, Inode, Kind, SECTOR};
use tessera_isl_runtime::{HandleRef, Reader, WireError, decode, encode};
use tessera_sdk::{
    Endpoint, Error as SdkError, Handle as SdkHandle, Platform as _, Transfer, machine::Machine,
};
use tessera_uabi::fail;

/// The capabilities boot installs, in order: the block service below, and this
/// service's own clients above.
const BLOCK_ENDPOINT_HANDLE: u64 = 0;
const CLIENT_ENDPOINT_HANDLE: u64 = 1;

/// Sized for the largest struct in either direction. `FsOpenRequest` is 152
/// bytes, which is the widest thing on this contract.
const MSG_BUF_LEN: usize = 192;

/// Where a sector fetched from the block service is mapped, and where a
/// client's read buffer is mapped while it is being filled.
///
/// Two fixed addresses rather than an allocator: a transfer revokes the
/// previous mapping, so the same address is free every time — and a second map
/// at an occupied one is refused, which makes that revocation observed rather
/// than assumed.
const SECTOR_VA: u64 = 0x0000_1000_0100_0000;
const CLIENT_VA: u64 = 0x0000_1000_0110_0000;

/// How many files may be open at once.
///
/// Bounded like every pool in this tree (D15/D29). A caller that opens more
/// hears `TOO_MANY_OPEN` rather than being handed a slot somebody else holds.
const MAX_OPEN: usize = 4;

/// What this service stamps into a removed inode's `i_dtime`.
///
/// ext2 requires it non-zero, and this program has no clock — no capability it
/// holds reads one. A build-time constant is the honest stand-in: a wrong time
/// stated is better than a zero that makes `e2fsck` call the volume corrupt,
/// and better than a clock this program invented for itself.
const DELETION_TIME: u32 = 1_700_000_000;

/// A sector fetched by asking the block service for it.
///
/// **One round trip per sector, and the contract is why.** Every block driver
/// here reports `dma_max_transfer_sectors = 1`, and the inline read reply
/// carries 64 bytes where a sector is 512 — so a whole sector has to come
/// through the out-of-line path, one at a time. That is the cost of v0's
/// layering and the reason a page cache is the next thing this needs.
struct BlockService {
    /// The buffer sectors arrive in. Created once and handed down and back for
    /// every read: creating one per request would exhaust the eight memory
    /// objects a machine has after eight sectors.
    buffer: SdkHandle,
    /// Whether the buffer is mapped at `SECTOR_VA` right now.
    ///
    /// Tracked rather than inferred from the call order. Handing the buffer
    /// down revokes this program's mapping of it and a read remaps it, so
    /// "mapped" was true after any read and false at start-up — which made a
    /// write mapping an already-mapped page and failing, and made the answer
    /// depend on whether a read happened to come first.
    mapped: bool,
}

impl BlockService {
    fn new() -> Result<Self, u64> {
        let buffer = Machine
            .memory_create(SECTOR as u64)
            .map_err(|_| fail(0xc1, 1))?;
        Ok(BlockService {
            buffer,
            mapped: false,
        })
    }

    /// Puts the buffer at `SECTOR_VA` unless it is already there.
    fn map(&mut self) -> Result<(), tessera_ext2::Error> {
        if self.mapped {
            return Ok(());
        }
        Machine
            .memory_map(self.buffer, SECTOR_VA)
            .map_err(|_| tessera_ext2::Error::Io)?;
        self.mapped = true;
        Ok(())
    }
}

impl BlockIo for BlockService {
    fn read_sector(
        &mut self,
        lba: u64,
        into: &mut [u8; SECTOR],
    ) -> Result<(), tessera_ext2::Error> {
        let request = BlockBufferRequest {
            size: BlockBufferRequest::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            sector: lba,
            length: SECTOR as u64,
            buffer: HandleRef::new(0),
        };
        let mut buf = [0u8; MSG_BUF_LEN];
        encode(&request, &mut buf[..BlockBufferRequest::WIRE_SIZE])
            .map_err(|_| tessera_ext2::Error::Io)?;

        let give = [Transfer {
            handle: self.buffer,
            rights: BlockBufferRequest::BUFFER_RIGHTS,
        }];
        let mut back = [SdkHandle(0); 1];
        let mut reply_buf = [0u8; MSG_BUF_LEN];
        let (_, returned) = Machine
            .call_with(
                Endpoint(SdkHandle(BLOCK_ENDPOINT_HANDLE)),
                BlockDevice::READ_INTO,
                &buf[..BlockBufferRequest::WIRE_SIZE],
                &mut reply_buf,
                &give,
                &mut back,
            )
            .map_err(|_| tessera_ext2::Error::Io)?;
        if returned == 0 {
            // The service kept the buffer. Every later read would fail for
            // want of one, so this is fatal rather than retried.
            return Err(tessera_ext2::Error::Io);
        }
        self.buffer = back[0];
        self.mapped = false;

        let reply: BlockBufferReply = decode(&reply_buf[..BlockBufferReply::WIRE_SIZE])
            .map_err(|_| tessera_ext2::Error::Io)?;
        if reply.status != 0 || reply.transferred != SECTOR as u64 {
            return Err(tessera_ext2::Error::Io);
        }

        // The buffer came back at a new handle and with no mapping, so map it
        // to read what the device wrote.
        self.map()?;
        // SAFETY: the kernel just mapped this object's single page read-write
        // at `SECTOR_VA` for this process, and nothing else in this program
        // forms a reference to that page while this slice is alive.
        let mapped = unsafe { core::slice::from_raw_parts(SECTOR_VA as *const u8, SECTOR) };
        into.copy_from_slice(mapped);
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, from: &[u8; SECTOR]) -> Result<(), tessera_ext2::Error> {
        // Fill the buffer before it goes: handing it to the layer below
        // revokes this program's mapping of it.
        self.map()?;
        // SAFETY: the kernel just mapped this object's single page read-write
        // at `SECTOR_VA`, and nothing else here references that page.
        let page = unsafe { core::slice::from_raw_parts_mut(SECTOR_VA as *mut u8, SECTOR) };
        page.copy_from_slice(from);

        let request = BlockBufferRequest {
            size: BlockBufferRequest::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            sector: lba,
            length: SECTOR as u64,
            buffer: HandleRef::new(0),
        };
        let mut buf = [0u8; MSG_BUF_LEN];
        encode(&request, &mut buf[..BlockBufferRequest::WIRE_SIZE])
            .map_err(|_| tessera_ext2::Error::Io)?;
        let give = [Transfer {
            handle: self.buffer,
            rights: BlockBufferRequest::BUFFER_RIGHTS,
        }];
        let mut back = [SdkHandle(0); 1];
        let mut reply_buf = [0u8; MSG_BUF_LEN];
        let (_, returned) = Machine
            .call_with(
                Endpoint(SdkHandle(BLOCK_ENDPOINT_HANDLE)),
                BlockDevice::WRITE_FROM,
                &buf[..BlockBufferRequest::WIRE_SIZE],
                &mut reply_buf,
                &give,
                &mut back,
            )
            .map_err(|_| tessera_ext2::Error::Io)?;
        if returned == 0 {
            return Err(tessera_ext2::Error::Io);
        }
        self.buffer = back[0];
        self.mapped = false;
        let reply: BlockBufferReply = decode(&reply_buf[..BlockBufferReply::WIRE_SIZE])
            .map_err(|_| tessera_ext2::Error::Io)?;
        if reply.status != 0 || reply.transferred != SECTOR as u64 {
            return Err(tessera_ext2::Error::Io);
        }
        Ok(())
    }
}

/// One open file: what the client named it, and what it resolved to.
#[derive(Clone, Copy)]
struct Open {
    id: u32,
    inode: Inode,
}

/// Everything this service holds.
struct Service {
    fs: Fs<BlockService>,
    open: [Option<Open>; MAX_OPEN],
    next_id: u32,
}

impl Service {
    /// Replaces the table's copy of an open file after a write changed it.
    ///
    /// The table holds inodes by value, so a write that grew a file leaves the
    /// table describing the old end of it — and the next read against that
    /// copy stops short of what was just written.
    fn remember(&mut self, inode: &Inode) {
        for slot in self.open.iter_mut().flatten() {
            if slot.inode.number == inode.number {
                slot.inode = *inode;
            }
        }
    }

    fn find(&self, id: u32) -> Option<Inode> {
        self.open
            .iter()
            .flatten()
            .find(|entry| entry.id == id)
            .map(|entry| entry.inode)
    }
}

fn open_reply(status: FsError, file: u32, length: u64, out: &mut [u8]) -> Result<usize, u64> {
    let reply = FsOpenReply {
        size: FsOpenReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        file,
        length,
    };
    encode(&reply, &mut out[..FsOpenReply::WIRE_SIZE])
        .map(|_| FsOpenReply::WIRE_SIZE)
        .map_err(|_| fail(0xc2, 0xe))
}

fn read_reply(status: FsError, read: u64, out: &mut [u8]) -> Result<usize, u64> {
    let reply = FsReadReply {
        size: FsReadReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        reserved: 0,
        read,
    };
    encode(&reply, &mut out[..FsReadReply::WIRE_SIZE])
        .map(|_| FsReadReply::WIRE_SIZE)
        .map_err(|_| fail(0xc3, 0xe))
}

fn write_reply(status: FsError, written: u64, out: &mut [u8]) -> Result<usize, u64> {
    let reply = FsWriteReply {
        size: FsWriteReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        reserved: 0,
        written,
    };
    encode(&reply, &mut out[..FsWriteReply::WIRE_SIZE])
        .map(|_| FsWriteReply::WIRE_SIZE)
        .map_err(|_| fail(0xc7, 0xe))
}

fn sync_reply(status: FsError, out: &mut [u8]) -> Result<usize, u64> {
    let reply = FsSyncReply {
        size: FsSyncReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        reserved: 0,
    };
    encode(&reply, &mut out[..FsSyncReply::WIRE_SIZE])
        .map(|_| FsSyncReply::WIRE_SIZE)
        .map_err(|_| fail(0xc8, 0xe))
}

/// Asks the layer below to push everything to stable media, and reports what
/// **it** said.
///
/// The middle link of the durability chain (`docs/storage/02`). This service
/// holds no cache, so it has nothing of its own to push — but it must still
/// ask, because the block service and the device below may, and an
/// acknowledgment that skipped them would be this program's confidence
/// standing in for the medium's.
fn flush_below() -> FsError {
    let request = BlockControlRequest {
        size: BlockControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: BlockPowerState::Active,
        reserved: 0,
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    if encode(&request, &mut buf[..BlockControlRequest::WIRE_SIZE]).is_err() {
        return FsError::IoError;
    }
    let mut request_bytes = [0u8; MSG_BUF_LEN];
    request_bytes[..BlockControlRequest::WIRE_SIZE]
        .copy_from_slice(&buf[..BlockControlRequest::WIRE_SIZE]);
    if Machine
        .call(
            Endpoint(SdkHandle(BLOCK_ENDPOINT_HANDLE)),
            BlockDevice::FLUSH,
            &request_bytes[..BlockControlRequest::WIRE_SIZE],
            &mut buf,
        )
        .is_err()
    {
        return FsError::IoError;
    }
    match decode::<BlockControlReply>(&buf[..BlockControlReply::WIRE_SIZE]) {
        // The device's answer, forwarded. Never this program's.
        Ok(reply) if reply.status == 0 => FsError::Ok,
        _ => FsError::IoError,
    }
}

fn close_reply(status: FsError, out: &mut [u8]) -> Result<usize, u64> {
    let reply = FsCloseReply {
        size: FsCloseReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status: status as u32,
        reserved: 0,
    };
    encode(&reply, &mut out[..FsCloseReply::WIRE_SIZE])
        .map(|_| FsCloseReply::WIRE_SIZE)
        .map_err(|_| fail(0xc4, 0xe))
}

fn serve(
    service: &mut Service,
    request: Result<FileSystemIncoming, WireError>,
    out: &mut [u8],
    arrived: &[SdkHandle],
    give_back: &mut [Transfer],
) -> Result<(usize, usize), u64> {
    let Ok(request) = request else {
        return open_reply(FsError::Protocol, 0, 0, out).map(|len| (len, 0));
    };
    match request {
        FileSystemIncoming::Open(open) => {
            let len = open.path_len as usize;
            if open.size != FsOpenRequest::WIRE_SIZE as u32 || len > open.path.len() {
                return open_reply(FsError::Protocol, 0, 0, out).map(|len| (len, 0));
            }
            let inode = match service.fs.lookup(&open.path[..len]) {
                Ok(inode) => inode,
                Err(tessera_ext2::Error::NotFound) => {
                    return open_reply(FsError::NotFound, 0, 0, out).map(|len| (len, 0));
                }
                Err(tessera_ext2::Error::NotDirectory) => {
                    return open_reply(FsError::NotAFile, 0, 0, out).map(|len| (len, 0));
                }
                Err(tessera_ext2::Error::Io) => {
                    return open_reply(FsError::IoError, 0, 0, out).map(|len| (len, 0));
                }
                Err(_) => return open_reply(FsError::BadVolume, 0, 0, out).map(|len| (len, 0)),
            };
            // A directory is not a file to read, and saying so is better than
            // handing back an id whose every read returns its raw entries.
            if inode.kind != Kind::Regular {
                return open_reply(FsError::NotAFile, 0, 0, out).map(|len| (len, 0));
            }
            let Some(slot) = service.open.iter().position(Option::is_none) else {
                return open_reply(FsError::TooManyOpen, 0, 0, out).map(|len| (len, 0));
            };
            service.next_id += 1;
            let id = service.next_id;
            service.open[slot] = Some(Open { id, inode });
            open_reply(FsError::Ok, id, inode.size, out).map(|len| (len, 0))
        }
        FileSystemIncoming::Read(read) => {
            // Whatever happens, the client's buffer goes home.
            let Some(buffer) = arrived.first().copied() else {
                return read_reply(FsError::NoBuffer, 0, out).map(|len| (len, 0));
            };
            give_back[0] = Transfer {
                handle: buffer,
                rights: BlockBufferRequest::BUFFER_RIGHTS,
            };
            let Some(inode) = service.find(read.file) else {
                return read_reply(FsError::Protocol, 0, out).map(|len| (len, 1));
            };
            let want = usize::try_from(read.length.min(SECTOR as u64)).unwrap_or(0);
            let mut staging = [0u8; SECTOR];
            let got = match service
                .fs
                .read_at(&inode, read.offset, &mut staging[..want])
            {
                Ok(got) => got,
                Err(_) => return read_reply(FsError::IoError, 0, out).map(|len| (len, 1)),
            };
            if Machine.memory_map(buffer, CLIENT_VA).is_err() {
                return read_reply(FsError::NoBuffer, 0, out).map(|len| (len, 1));
            }
            // SAFETY: the kernel just mapped the client's object read-write at
            // `CLIENT_VA`; nothing else here references that page, and the
            // write stays inside the sector it is sized to.
            let target = unsafe { core::slice::from_raw_parts_mut(CLIENT_VA as *mut u8, SECTOR) };
            target[..got].copy_from_slice(&staging[..got]);
            read_reply(FsError::Ok, got as u64, out).map(|len| (len, 1))
        }
        FileSystemIncoming::Write(write) => {
            let Some(buffer) = arrived.first().copied() else {
                return write_reply(FsError::NoBuffer, 0, out).map(|len| (len, 0));
            };
            give_back[0] = Transfer {
                handle: buffer,
                rights: BlockBufferRequest::BUFFER_RIGHTS,
            };
            let Some(mut inode) = service.find(write.file) else {
                return write_reply(FsError::Protocol, 0, out).map(|len| (len, 1));
            };
            let want = usize::try_from(write.length.min(SECTOR as u64)).unwrap_or(0);
            if Machine.memory_map(buffer, CLIENT_VA).is_err() {
                return write_reply(FsError::NoBuffer, 0, out).map(|len| (len, 1));
            }
            // SAFETY: the kernel just mapped the client's object read-write at
            // `CLIENT_VA`; nothing else here references that page, and the
            // read stays inside the sector it is sized to.
            let source = unsafe { core::slice::from_raw_parts(CLIENT_VA as *const u8, SECTOR) };
            let mut staging = [0u8; SECTOR];
            staging[..want].copy_from_slice(&source[..want]);
            match service.fs.write_at(&mut inode, write.offset, &staging[..want]) {
                Ok(written) => {
                    // The table holds the inode, and its size just changed:
                    // a later read against the stale copy would stop at the
                    // old end of the file.
                    service.remember(&inode);
                    write_reply(FsError::Ok, written as u64, out).map(|len| (len, 1))
                }
                Err(tessera_ext2::Error::ReadOnly) => {
                    write_reply(FsError::IoError, 0, out).map(|len| (len, 1))
                }
                Err(_) => write_reply(FsError::IoError, 0, out).map(|len| (len, 1)),
            }
        }
        FileSystemIncoming::Sync(sync) => {
            if service.find(sync.file).is_none() {
                return sync_reply(FsError::Protocol, out).map(|len| (len, 0));
            }
            // The chain: this answers what the layer below answered, and the
            // layer below answers what the device did.
            sync_reply(flush_below(), out).map(|len| (len, 0))
        }
        FileSystemIncoming::Create(open) => {
            let len = open.path_len as usize;
            if open.size != FsOpenRequest::WIRE_SIZE as u32 || len > open.path.len() {
                return open_reply(FsError::Protocol, 0, 0, out).map(|len| (len, 0));
            }
            // Only in the root, and only a leaf: a path with a directory in it
            // needs the parent resolved, which is `Open`'s walk and not
            // something to do twice differently.
            let name = &open.path[..len];
            let name = name.strip_prefix(b"/").unwrap_or(name);
            if name.contains(&b'/') || name.is_empty() {
                return open_reply(FsError::Protocol, 0, 0, out).map(|len| (len, 0));
            }
            let mut root = match service.fs.root() {
                Ok(root) => root,
                Err(_) => return open_reply(FsError::BadVolume, 0, 0, out).map(|len| (len, 0)),
            };
            let inode = match service.fs.create(&mut root, name) {
                Ok(inode) => inode,
                Err(tessera_ext2::Error::Exists) => {
                    return open_reply(FsError::Exists, 0, 0, out).map(|len| (len, 0));
                }
                // Distinct rather than collapsed: "the volume is full", "the
                // volume is not one I understand" and "the medium refused" ask
                // different things of a caller, and folding them into one told
                // this service's own client nothing when create first failed.
                Err(tessera_ext2::Error::Full | tessera_ext2::Error::TooLarge) => {
                    return open_reply(FsError::Full, 0, 0, out).map(|len| (len, 0));
                }
                Err(tessera_ext2::Error::Corrupt) => {
                    return open_reply(FsError::BadVolume, 0, 0, out).map(|len| (len, 0));
                }
                Err(tessera_ext2::Error::NameTooLong | tessera_ext2::Error::NotDirectory) => {
                    return open_reply(FsError::Protocol, 0, 0, out).map(|len| (len, 0));
                }
                Err(_) => return open_reply(FsError::IoError, 0, 0, out).map(|len| (len, 0)),
            };
            let Some(slot) = service.open.iter().position(Option::is_none) else {
                return open_reply(FsError::TooManyOpen, 0, 0, out).map(|len| (len, 0));
            };
            service.next_id += 1;
            let id = service.next_id;
            service.open[slot] = Some(Open { id, inode });
            open_reply(FsError::Ok, id, 0, out).map(|len| (len, 0))
        }
        FileSystemIncoming::Unlink(open) => {
            let len = open.path_len as usize;
            let name = &open.path[..len.min(open.path.len())];
            let name = name.strip_prefix(b"/").unwrap_or(name);
            let mut root = match service.fs.root() {
                Ok(root) => root,
                Err(_) => return close_reply(FsError::BadVolume, out).map(|len| (len, 0)),
            };
            // No clock: this program has none to read, so the deletion time it
            // stamps is the build's and not the machine's. Recorded rather
            // than invented — ext2 requires the field to be non-zero, and a
            // wrong time is better stated than a zero that fails `e2fsck`.
            let status = match service.fs.unlink(&mut root, name, DELETION_TIME) {
                Ok(()) => FsError::Ok,
                Err(tessera_ext2::Error::NotFound) => FsError::NotFound,
                Err(tessera_ext2::Error::NotDirectory) => FsError::NotAFile,
                Err(_) => FsError::IoError,
            };
            close_reply(status, out).map(|len| (len, 0))
        }
        FileSystemIncoming::Close(close) => {
            let mut found = false;
            for slot in service.open.iter_mut() {
                if slot.is_some_and(|entry| entry.id == close.file) {
                    *slot = None;
                    found = true;
                }
            }
            let status = if found {
                FsError::Ok
            } else {
                FsError::Protocol
            };
            close_reply(status, out).map(|len| (len, 0))
        }
    }
}

fn run() -> u64 {
    let device = match BlockService::new() {
        Ok(device) => device,
        Err(code) => return code,
    };
    let fs = match Fs::mount(device) {
        Ok(fs) => fs,
        // A volume this service cannot read is reported, never guessed past.
        Err(_) => return fail(0xc5, 1),
    };
    let mut service = Service {
        fs,
        open: [None; MAX_OPEN],
        next_id: 0,
    };

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut failure = 0u64;
    let served = tessera_sdk::serve_transfers(
        &mut Machine,
        Endpoint(SdkHandle(CLIENT_ENDPOINT_HANDLE)),
        &mut msg_buf,
        |method, bytes, arrived, out, give_back| {
            let count = u32::try_from(arrived.len()).unwrap_or(0);
            let request = FileSystemIncoming::decode(method, &mut Reader::in_message(bytes, count));
            match serve(&mut service, request, out, arrived, give_back) {
                Ok(pair) => Ok(pair),
                Err(code) => {
                    failure = code;
                    Err(SdkError::NotBound)
                }
            }
        },
    );
    if failure != 0 {
        return failure;
    }
    match served {
        Ok(()) => fail(0xc6, 11),
        Err(_) => fail(0xc6, 1),
    }
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
