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

use tessera_fsapi::{BUFFER_VA, Buffer, MSG_BUF_LEN, close, open, open_mapped, read};
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
        Ok((file, _)) => fail(0xf4, u64::from(file)),
        Err(code) if code == fail(0xd1, 0x100 | NOT_FOUND) => REPORT,
        // Refused, but for some other reason — an I/O error says the volume is
        // unreadable rather than that the name is absent, and a client that
        // treated them alike would retry the wrong one.
        Err(code) => fail(0xf5, code & 0xffff),
    }
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
