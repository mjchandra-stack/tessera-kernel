// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Asks the question the whole storage stack exists to answer: **what is in
//! `/hello.txt`?**
//!
//! Every layer below has been proved by something else — the format by
//! `//api/ext2`'s host tests against an image `mke2fs` built, the transfer path
//! and the class contract by `blk-client`'s conformance battery — and none of
//! that establishes that the parts compose. This holds one channel to a
//! filesystem service and nothing else: no device, no bus, no block contract,
//! and no idea how many layers are underneath.
//!
//! **What it checks is the bytes, not a length or a status.** A service that
//! answered `OK` with a zero-filled buffer would pass every check that read
//! only the reply, and a service that resolved the wrong inode would pass one
//! that read only the length.
//!
//! **And it asks for a path that is not there.** A filesystem that answered
//! every name would answer this one too, so the refusal is the half that says
//! the lookup is a lookup — and it must be `NOT_FOUND` rather than an I/O
//! error, because the two say different things about whether the volume is
//! readable.
//!
//! Why a separate program from `//userspace/fs-client`: that one is also a
//! loader and a compiler driver — it reads a program off the volume, starts it,
//! compiles a source and runs what it built. Those are the self-hosting
//! roadmap's, and a machine that has just grown a filesystem should be able to
//! say so without them.
//!
//! Normative: docs/storage/02-file-io-and-caching.md

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use tessera_fsapi::{
    BUFFER_VA, Buffer, FILE_VA, MAP_READ, MAP_RW, MSG_BUF_LEN, PAGE_LEN, close, create, open,
    open_mapped, read, sync, unlink, write,
};
use tessera_sdk::{Platform as _, machine::Machine};
use tessera_uabi::fail;

/// What `//tools/qemu`'s image builder writes into `/hello.txt`. Stated here
/// and there, because a single shared definition would make agreement
/// automatic rather than checked.
const HELLO: &[u8] = b"hello from ext2\n";

/// A path the volume does not carry.
const MISSING: &[u8] = b"/nothing-here.txt";

/// `FsError::NOT_FOUND`, which is the one answer a lookup of [`MISSING`] may
/// give. Named from the wire value rather than imported, because what this
/// program needs is the one status it acts on — and stating it here is what
/// makes the check a check: a program that read the service's own enum would
/// agree with it whatever it said.
const NOT_FOUND: u64 = 1;

/// What this program reports when every leg held.
///
/// Rotated like every other client's report in this tree, so the value is one
/// only this sequence produces rather than a constant that could have been
/// written down.
const REPORT: u64 = u64::from_le_bytes(*b"TESSERAF").rotate_left(8);

/// Written through the service, and not called durable until `Sync` has
/// answered. The boot script greps the disk image for it **after the machine
/// has stopped**, which is the durability claim reduced to something an
/// outside observer can check: an acknowledged write is on the medium, not in
/// somebody's cache.
const DURABLE: &[u8] = b"tessera durable write\n";

/// Long enough to give a file a page to write into. A file of zero length has
/// no object, and there would be nothing to map.
const FILLER: &[u8] = b"................................................................";

/// What this program stores **through its mapping** of a file, with no message
/// to the service at all. Finding it in the volume means a store into memory
/// became a byte on a disk, and the only record of it in between was the
/// kernel's dirty set.
const MAPPED: &[u8] = b"tessera mapped write ok\n";

/// Stored through the same mapping **after** the first sync cleaned the page.
///
/// This is the one that needs the page to have been re-protected. A page left
/// writable when it was marked clean takes this store with no fault, nothing
/// records it, and the second sync finds no work to do — so it is written past
/// the first marker and looked for separately, and a lost second write fails
/// on this alone.
const MAPPED_AGAIN: &[u8] = b"tessera second mapped ok\n";

/// Where the second marker goes: past the first, so both survive and the
/// script can say which one went missing.
const MAPPED_AGAIN_AT: usize = 32;

/// A file with more pages than the kernel's page cache can hold at once, and
/// a byte pattern that varies per byte: `//api/ext2`'s image builder writes
/// `(i * 7 + 3) % 256` at offset `i`, over seventy thousand bytes.
///
/// **Restated here rather than shared.** A reader that computed the expected
/// byte from the same expression the builder used would agree with it by
/// construction; this is the check's own arithmetic, and the builder's comment
/// says the same thing from the other side.
const BIG_PATH: &[u8] = b"/cache.bin";
const BIG_LEN: u64 = 49152;

/// Pages of it this program walks, and the stride between the bytes it checks.
///
/// **More than the cache holds and fewer than one object may carry**, which is
/// what makes this an eviction check rather than a reading one: the kernel's
/// ceiling is eight frames across every object and its cap is sixteen pages per
/// object, so a walk of twelve cannot be resident at once and some page it
/// already read must be dropped and fetched again.
const BIG_PAGES: u64 = BIG_LEN / PAGE_LEN;

/// Where the walk maps it — **its own window, not the one the write legs
/// use**. Reusing an address a later leg maps read-write means the second
/// mapping depends on the first having been taken down exactly, and a walk
/// that got that wrong would surface as a fault inside somebody else's store
/// rather than as its own failure.
const WALK_VA: u64 = FILE_VA + 0x0010_0000;

/// The names this program writes. Both are removed before they are made, for
/// the reason the other port's client learned: a volume this machine has
/// already used carries them, `Create` answers `Exists` rather than
/// truncating, and a leg would fail on state rather than on behaviour. A
/// missing file is not an error here — this is making the state right, not
/// asserting it.
const DURABLE_NAME: &[u8] = b"durable.txt";
const MAPPED_NAME: &[u8] = b"mapped.txt";
/// The same file as a path: `Create` takes a name in the root directory and
/// `Open` takes a path, and the two spellings are what that difference is.
const MAPPED_PATH: &[u8] = b"/mapped.txt";

fn run() -> u64 {
    let mut buf = [0u8; MSG_BUF_LEN];

    // **A name, resolved by somebody else.** This program never sees a block, a
    // sector or an inode; what it hands over is a path, and what it gets back
    // is a file id and the size the directory entry's inode says.
    // `open_mapped` rather than `open`, and the difference is a handle rather
    // than a mechanism: the service answers every non-empty file with its
    // contents as a memory object, and a caller that did not ask for it is
    // still given it — the capability is installed whether or not the message
    // named somewhere to report it. Taking it and closing it below is the
    // difference between a program that hands a capability back and one that
    // leaks one per file it opens. What this program reads is still the
    // message path; the object is what `fs-client` maps.
    let (file, length, object) = match open_mapped(b"/hello.txt", &mut buf) {
        Ok(triple) => triple,
        Err(code) => return code,
    };
    let Some(object) = object else {
        return fail(0xf0, 0);
    };
    // The length is the inode's, so a wrong one is a wrong inode — caught here
    // rather than after the bytes have been read, where it would look like a
    // short read instead.
    if length != HELLO.len() as u64 {
        return fail(0xf1, length);
    }

    // The buffer is this program's own memory object, handed to the service
    // for the length of the call and given back at a handle the service's
    // table did not choose. A transfer moves, so it is unmapped while it is
    // gone and remapped to read what came back.
    let mut buffer = match Buffer::new() {
        Ok(buffer) => buffer,
        Err(code) => return code,
    };
    let got = match read(file, 0, HELLO.len() as u64, &mut buffer, &mut buf) {
        Ok(got) => got,
        Err(code) => return code,
    };
    if got != HELLO.len() as u64 {
        return fail(0xf2, got);
    }
    if let Err(code) = buffer.map() {
        return code;
    }
    // SAFETY: the kernel just mapped this object's single page read-write at
    // `BUFFER_VA` for this process, and nothing else here references it.
    let bytes = unsafe { core::slice::from_raw_parts(BUFFER_VA as *const u8, HELLO.len()) };
    for (index, (got, want)) in bytes.iter().zip(HELLO).enumerate() {
        if got != want {
            // Which byte, not just that they differed: a wrong byte in the
            // middle is a torn transfer and a wrong first byte is a wrong
            // block, and the index is what says which.
            return fail(0xf3, index as u64);
        }
    }

    if Machine.close(object).is_err() {
        return fail(0xf6, 0);
    }
    if let Err(code) = close(file, &mut buf) {
        return code;
    }

    // And the half that says the lookup is a lookup.
    match open(MISSING, &mut buf) {
        // A file this volume does not carry was opened, which is worse than a
        // failure to open one it does.
        Ok((file, _)) => return fail(0xf4, u64::from(file)),
        Err(code) if code == fail(0xd1, 0x100 | NOT_FOUND) => {}
        // Refused, but for some other reason — an I/O error says the volume is
        // unreadable rather than that the name is absent, and a client that
        // treated them alike would retry the wrong one.
        Err(code) => return fail(0xf5, code & 0xffff),
    }

    // **And then the other direction.** Everything above reads, and a volume
    // this stack can only read is one nothing can be built on. The two legs
    // below are the two ways a byte gets onto the medium, and they are
    // different mechanisms rather than the same one twice.
    if let Err(code) = durable_write(&mut buffer, &mut buf) {
        return code;
    }
    if let Err(code) = mapped_write(&mut buffer, &mut buf) {
        return code;
    }

    // **And a file the cache cannot hold all of.** Twelve pages walked through
    // one mapping, each byte checked against the pattern the image builder
    // wrote: the cache's ceiling is eight frames, so pages this program has
    // already read are dropped behind it and fetched again, and a page that
    // came back wrong would be eviction dropping the wrong thing.
    if let Err(code) = walk_big(&mut buf) {
        return code;
    }
    REPORT
}

/// Walks a file with more pages than the page cache holds, checking every one.
///
/// **Two things are being checked and both are needed.** That the walk gets
/// through at all says the cache evicted rather than refused; that every byte
/// is the one the image builder wrote says eviction dropped the right page. A
/// kernel that evicted nothing satisfies the second, and one that handed back
/// somebody else's page satisfies the first.
fn walk_big(buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    let (file, length, object) = open_mapped(BIG_PATH, buf)?;
    if length != BIG_LEN {
        return Err(fail(0xfe, length));
    }
    let Some(object) = object else {
        return Err(fail(0xfe, 1));
    };
    if Machine.map_object(object, WALK_VA, MAP_READ).is_err() {
        return Err(fail(0xfe, 2));
    }
    // **Twice around, and the second pass is the claim.** One pass says every
    // page can be fetched; a cache that held all twelve would then answer the
    // second pass out of memory it already has. The ceiling is eight, so the
    // pages this program read first are gone by the time it comes back to
    // them, and the kernel's supply count is what says so.
    for page in 0..BIG_PAGES * 2 {
        let at = (page % BIG_PAGES) * PAGE_LEN;
        // SAFETY: the kernel mapped this object read-only at `WALK_VA` for
        // this process, and `at` is inside the length the service reported.
        let got = unsafe { core::ptr::read_volatile((WALK_VA + at) as *const u8) };
        let want = ((at * 7 + 3) % 256) as u8;
        if got != want {
            // Which page, not just that they differed: a wrong byte on the
            // first page is a wrong file and a wrong byte on the ninth is the
            // cache handing back somebody else's frame.
            return Err(fail(0xfd, page));
        }
    }
    if Machine.unmap(WALK_VA, PAGE_LEN * BIG_PAGES).is_err() {
        return Err(fail(0xfe, 3));
    }
    if Machine.close(object).is_err() {
        return Err(fail(0xfe, 4));
    }
    close(file, buf)
}

/// A write through the service, made durable before this program carries on.
///
/// The `Sync` is the load-bearing call: until it answers, the bytes are
/// somewhere between here and the platter and the boot script's search of the
/// image would be asking a question with no defined answer. After it, they are
/// on the medium — and the script looks there once the machine has stopped,
/// which is a claim the machine cannot make about itself.
fn durable_write(buffer: &mut Buffer, buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    // Removed before it is made, so a volume a previous boot wrote is one this
    // leg can still run against.
    let _ = unlink(DURABLE_NAME, buf);
    let file = create(DURABLE_NAME, buf)?;
    let count = write(file, 0, DURABLE, buffer, buf)?;
    if count != DURABLE.len() as u64 {
        return Err(fail(0xf7, count));
    }
    sync(file, buf)?;

    // Read back through the service, so what is established is not only that
    // the bytes are somewhere on the medium but that the *file* holds them: a
    // write that landed at the wrong block would satisfy the script's search
    // of the image and fail here.
    let read_back = read(file, 0, DURABLE.len() as u64, buffer, buf)?;
    if read_back != DURABLE.len() as u64 {
        return Err(fail(0xf8, read_back));
    }
    buffer.map()?;
    // SAFETY: the kernel just mapped this object's single page read-write at
    // `BUFFER_VA` for this process, and nothing else here references it.
    let bytes = unsafe { core::slice::from_raw_parts(BUFFER_VA as *const u8, DURABLE.len()) };
    for (index, (got, want)) in bytes.iter().zip(DURABLE).enumerate() {
        if got != want {
            return Err(fail(0xf9, index as u64));
        }
    }
    // **Closed, and a file left open is not free**: every `Open` and `Create`
    // makes the service a pager-backed memory object, and there are eight.
    close(file, buf)
}

/// A write that never becomes a message.
///
/// The leg above went through the service — `Write` carried a buffer and
/// `Sync` flushed what the service had already put on the medium. This is the
/// other path: the store lands in this program's own mapping of the file, the
/// service is never told, and `Sync` has to find the change in the kernel's
/// dirty set or answer for a write it never saw.
///
/// **And a second store after the flush**, which is a different mechanism
/// again: the page was clean, so the only thing that makes this one visible is
/// the fault the kernel put back when it cleaned it. A kernel that cleaned
/// without re-protecting loses this write and nothing else.
fn mapped_write(buffer: &mut Buffer, buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    let _ = unlink(MAPPED_NAME, buf);
    let file = create(MAPPED_NAME, buf)?;
    // Give it a page to write into: a file of zero length has no object, and
    // there would be nothing to map.
    let count = write(file, 0, FILLER, buffer, buf)?;
    if count != FILLER.len() as u64 {
        return Err(fail(0xfa, count));
    }
    sync(file, buf)?;
    close(file, buf)?;

    // Re-opened, because the object arrives with `Open` and this file had no
    // size when it was created.
    let (file, length, object) = open_mapped(MAPPED_PATH, buf)?;
    if length != FILLER.len() as u64 {
        return Err(fail(0xfb, length));
    }
    let Some(object) = object else {
        return Err(fail(0xfb, 1));
    };
    if Machine.map_object(object, FILE_VA, MAP_RW).is_err() {
        return Err(fail(0xfc, 0));
    }

    // The store. It faults once — the page is supplied read-only even though
    // the mapping grants write, which is not a mistake but the mechanism: that
    // fault is the kernel's only chance to notice.
    // SAFETY: the kernel just mapped the file's object read-write at `FILE_VA`
    // for this process, and nothing else here references that range.
    let page = unsafe { core::slice::from_raw_parts_mut(FILE_VA as *mut u8, MAPPED.len()) };
    page.copy_from_slice(MAPPED);
    sync(file, buf)?;

    // SAFETY: the object is still mapped read-write at `FILE_VA`, and this
    // range is inside the page mapped above.
    let again = unsafe {
        core::slice::from_raw_parts_mut(
            (FILE_VA + MAPPED_AGAIN_AT as u64) as *mut u8,
            MAPPED_AGAIN.len(),
        )
    };
    again.copy_from_slice(MAPPED_AGAIN);
    sync(file, buf)?;

    if Machine.unmap(FILE_VA, PAGE_LEN).is_err() {
        return Err(fail(0xfd, 0));
    }
    if Machine.close(object).is_err() {
        return Err(fail(0xfd, 1));
    }
    close(file, buf)
}

/// Entry point.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    Machine.finish(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    Machine.finish(fail(0xff, 0))
}
