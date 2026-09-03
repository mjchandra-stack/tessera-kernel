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

use channel_msg::{
    ChannelCreateArgs, ChannelCreateRecord, ChannelMsgArgs, Rights as ChannelRights,
};
use diagnostic::DiagnosticRecord;
use process_abi::{
    AddressSpaceMapArgs, ProcessCreateArgs, ProcessStartArgs, ProcessWaitArgs,
    Rights as ProcessRights,
};
use process_abi::{ProcessGrantArgs, StartupArg, StartupArgs, StartupHandles};
use tessera_fsapi::{
    BUFFER_LEN, BUFFER_VA, Buffer, FILE_VA, MAP_READ, MAP_RW, MSG_BUF_LEN, PAGE_LEN, close, create,
    open, open_mapped, read, sync, unlink, write,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_sdk::{Platform as _, machine::Machine};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// What `testdata/mkimage.sh` writes into `/hello.txt`.
const HELLO: &[u8] = b"hello from ext2\n";

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

/// The boot script greps the disk image for them **after** the machine has
/// stopped, which is the whole durability claim reduced to something an
/// outside observer can check: an acknowledged write is on stable media, not
/// in somebody's cache.
const DURABLE: &[u8] = b"tessera durable write\n";

fn run() -> u64 {
    let mut buf = [0u8; MSG_BUF_LEN];

    // **And the compiler as a program, rather than as a function call**
    // (`docs/roadmap/04` Phase 5, D307). Everything above compiled inside this
    // program, on paths built into it. This starts `tsmc`, tells
    // it what to compile *in its arguments*, and reads what it has to say on a
    // channel — which is the difference between a machine that can compile and
    // a toolchain something can drive.
    if let Err(code) = drive_the_compiler(&mut buf) {
        return code;
    }

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

    // **Unlinked first, because this volume may be one this machine has used**
    // (`docs/roadmap/04` Phase 6, D310). Every leg here was written against a
    // pristine copy, and `Create` answers `Exists` rather than truncating — so
    // the first boot to run on a volume a previous boot wrote failed here, on
    // a file that had nothing to do with what it was testing. A missing file is
    // not an error: this is making the state right, not asserting it.
    let _ = unlink(b"durable.txt", &mut buf);
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
    // **Closed, and it was not** (D304). Every `Open` and `Create` makes the
    // service a pager-backed memory object, and `MAX_MEMORY_OBJECTS` is 8 —
    // so a file left open holds one of eight for the rest of the boot. This
    // program leaked two, which cost nothing until a later step needed the
    // ninth and got `NoBuffer` from an `Open` that had nothing wrong with it.
    if let Err(code) = close(written, &mut buf) {
        return code;
    }

    // --- a write that never becomes a message ---
    //
    // Everything above went through the service: `Write` carried a buffer, and
    // `Sync` flushed what the service had already put on the medium. This is
    // the other path — the client stores into its own mapping of the file, the
    // service is never told, and `Sync` has to find the change in the kernel's
    // dirty set or answer for a write it never saw.
    // Idempotent for the same reason as `durable.txt` above.
    let _ = unlink(b"mapped.txt", &mut buf);
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
    // Idempotent for the same reason as `durable.txt` above.
    let _ = unlink(b"transient.txt", &mut buf);
    let transient = match create(b"transient.txt", &mut buf) {
        Ok(file) => file,
        Err(code) => return code,
    };
    // Closed before it is unlinked, for the reason above: a file this program
    // is finished with must not go on holding one of the service's objects.
    if let Err(code) = close(transient, &mut buf) {
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

    // **And now the loop that Phase 2 exists for**: this program reads a
    // *source* off the volume, compiles it, writes the program it produced back
    // to the same volume, reads that back, and runs it (`docs/roadmap/04`,
    // D304).
    //
    // Every step of it was already gated separately — reading (D294), writing
    // durably (the crash check), and executing an image off the volume (D294).
    // What has never happened is that the image being executed was **made
    // here**. Nothing in the build knows the number the generated program
    // reports; it is arithmetic the source describes and the generated
    // instructions perform.
    if let Err(code) = compile_and_run(&mut buffer, &mut buf) {
        return code;
    }

    // **And the half of it that one boot cannot do** (`docs/roadmap/04` Phase
    // 6). Everything above is this machine building a program and this machine
    // running it, with nothing in between. Here the two are in different boots:
    // one compiles `/gate.tsm` into `/gate.elf` and stops, the next finds it
    // and runs it. Last, because on the boot that runs it this is one more
    // paged object and the ones above have been given back by now.
    let gate = match the_gate(&mut buf) {
        Ok(gate) => gate,
        Err(code) => return code,
    };
    // Reported separately from the value below, so that "which half happened"
    // and "did the client pass" stay two answers. A boot emits exactly one of
    // these and the check reads it out of the ordered reports by name.
    let _ = syscall2(
        SYS_DEBUG_WRITE,
        match gate {
            Gate::Staged => GATE_STAGED_REPORT,
            Gate::Ran => GATE_RAN_REPORT,
        },
        0,
    );

    // The disk magic rotated like every other client's report, so the check's
    // sink is a value only this sequence produces.
    u64::from_le_bytes(*b"TESSERAF").rotate_left(8)
}

/// The source this program compiles, and where it puts what it produced.
const SOURCE_PATH: &[u8] = b"/source.tsm";
const BUILT_PATH: &[u8] = b"/built.elf";
/// The same file, as `Create` and `Unlink` name it: those take a name in the
/// root directory where `Open` takes a path.
const BUILT_NAME: &[u8] = b"built.elf";

/// Reads a source off the volume, compiles it, writes the result back, reads
/// *that* back, and runs it.
///
/// **The image is read back rather than kept.** Compiling into a buffer and
/// executing the buffer would prove a code generator works; it would not prove
/// the program went to the volume and came off it, which is the half this phase
/// is about. So the bytes make the whole round trip, through `Sync`, and what
/// runs is what a fresh `Open` returned.
fn compile_and_run(buffer: &mut Buffer, buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    // **The source, through the plain read path rather than the mapped one.**
    // `with_the_program` maps a file by asking the service for a *paged* memory
    // object, which is right for an image about to be loaded and wrong for a
    // hundred bytes of text: this program already opens four files that way, and
    // a fifth is what exhausted the service's supply — an `Open` answering
    // `NoBuffer`, which is what a failed `memory_create_paged` looks like from
    // the client's side. A source small enough to fit the transfer buffer does
    // not need a paged object at all.
    let mut source = [0u8; BUFFER_LEN];
    let file = open(SOURCE_PATH, buf)?.0;
    let got = read(file, 0, source.len() as u64, buffer, buf)?;
    close(file, buf)?;
    if got == 0 || got as usize > source.len() {
        return Err(fail(0xf4, got));
    }
    buffer.map()?;
    // SAFETY: the kernel just mapped this object's single page read-write at
    // `BUFFER_VA` for this process, and nothing else here references it.
    let page = unsafe { core::slice::from_raw_parts(BUFFER_VA as *const u8, BUFFER_LEN) };
    source[..got as usize].copy_from_slice(&page[..got as usize]);
    let read = got as usize;

    let program = tessera_tsm::parse(&source[..read]).map_err(|e| {
        // The line is in the report, because a compiler that says only "no"
        // about a file it read is one nobody can fix a source with.
        fail(0xf0, (u64::from(e.line) << 8) | e.kind as u64)
    })?;
    let mut image = [0u8; tessera_tsm::MAX_IMAGE];
    let len = program
        .emit(&mut image)
        .map_err(|e| fail(0xf1, e.kind as u64))?;

    // A previous run's output is not this run's evidence. Unlinked first, and
    // a missing file is not an error — which is what lets this run on a volume
    // an earlier boot of this machine wrote (D310), not only on a fresh copy.
    let _ = unlink(BUILT_NAME, buf);
    let file = create(BUILT_NAME, buf)?;
    let count = write(file, 0, &image[..len], buffer, buf)?;
    if count != len as u64 {
        return Err(fail(0xf3, count));
    }
    sync(file, buf)?;
    close(file, buf)?;

    // Read back, and run what came off the volume rather than what was in
    // memory. The child reports the value the source describes; this program
    // judges only that it exited cleanly, exactly as it does for `/program.elf`.
    match with_the_program(BUILT_PATH, buf, execute) {
        Ok(0) => Ok(()),
        Ok(other) => Err(fail(0xf2, other as u32 as u64)),
        Err(code) => Err(code),
    }
}

/// What `tsmc` builds, and what this program then runs.
const TSMC_OUTPUT_NAME: &[u8] = b"tsmc-out.elf";
const TSMC_OUTPUT_PATH: &[u8] = b"/tsmc-out.elf";
/// A source with a mistake on line 3, for the leg that checks the compiler can
/// say *why*.
const BAD_SOURCE: &[u8] = b"/bad.tsm";

/// Runs the compiler twice: once on a source it accepts, once on one it does
/// not.
///
/// **The failing leg is the one that matters.** A compiler that only ever
/// succeeds proves it can compile; one that fails and says which line and what
/// about it is one a person can use — and until now the answer to "why did the
/// build fail" on this machine was a packed hexadecimal word.
fn drive_the_compiler(buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    let mut said = [0u8; DiagnosticRecord::WIRE_SIZE];

    // The good source. It exits `OK`, says nothing, and leaves a program
    // behind — which this program then runs, off the volume, exactly as it runs
    // the one the build put there.
    let (status, spoke) = run_compiler(SOURCE_PATH, TSMC_OUTPUT_NAME, &mut said, buf)?;
    if status != 0 {
        return Err(fail(0xfd, status as u32 as u64));
    }
    if spoke {
        // A compiler that succeeded and complained anyway is one whose
        // diagnostics nobody will read for long.
        return Err(fail(0xfd, 1));
    }
    match with_the_program(TSMC_OUTPUT_PATH, buf, execute) {
        Ok(0) => {}
        Ok(other) => return Err(fail(0xfd, other as u32 as u64)),
        Err(code) => return Err(code),
    }

    // The bad source. Non-zero, and a sentence naming the line.
    let (status, spoke) = run_compiler(BAD_SOURCE, b"never.elf", &mut said, buf)?;
    if status == 0 || !spoke {
        return Err(fail(0xfe, status as u32 as u64));
    }
    let record: DiagnosticRecord = decode(&said).map_err(|_| fail(0xfe, 1))?;
    let len = record.len as usize;
    if len == 0 || len > record.text.len() {
        return Err(fail(0xfe, 2));
    }
    let text = &record.text[..len];
    // `tsmc: /bad.tsm:3: unknown operation` — the shape every compiler has said
    // since `cc`, checked for the two fields a build system parses.
    // `tsmc: /bad.tsm:3: unknown operation` — the shape every compiler has said
    // since `cc`, checked for the two fields a build system parses and the one
    // a person reads. The line number is the point: a compiler that said only
    // "no" about a file it read is one nobody can fix a source with.
    if !contains(text, b"/bad.tsm") {
        return Err(fail(0xfe, 3));
    }
    if !contains(text, b":3:") {
        return Err(fail(0xfe, 4));
    }
    if !contains(text, b"unknown operation") {
        return Err(fail(0xfe, 5));
    }
    Ok(())
}

/// The source the gate compiles, and the program it becomes.
///
/// `gate.elf` is on no build artifact and in no kernel image, and unlike
/// `built.elf` it is **not unlinked first** — the whole point is that it
/// outlives the boot that made it.
const GATE_SOURCE: &[u8] = b"/gate.tsm";
const GATE_NAME: &[u8] = b"gate.elf";
const GATE_PATH: &[u8] = b"/gate.elf";

/// Which half of the gate this boot performed.
///
/// Not a choice this program makes: the volume decides, because whether the
/// program is there is the only thing that distinguishes the two boots. One
/// kernel image, one client, and the machine converges on its own output.
enum Gate {
    /// No program on the volume, so this boot compiled one and stopped.
    Staged,
    /// A program was there from an earlier boot, and this boot ran it.
    Ran,
}

/// What this program reports for each half, so the check can tell them apart.
///
/// **Two constants rather than one flag folded into the client's report.** The
/// sink composes by XOR and cannot be decomposed; the ordered reports can, and
/// keeping one value meaning one thing is what made the last failure in this
/// check readable (D309). One of these is in every boot's reports and never
/// both.
const GATE_STAGED_REPORT: u64 = 0x5e1f_ba5e_0000_0001;
const GATE_RAN_REPORT: u64 = 0x5e1f_ba5e_0000_0002;

/// **The gate** (`docs/roadmap/04` Phase 6).
///
/// Everything else this program does happens inside one boot: it compiles and
/// it runs what it compiled, and the machine that made the artifact is the
/// machine still holding it. That proves a code generator works and it does not
/// prove the output is a *program* — an artifact whose existence does not
/// depend on the process that wrote it still being alive.
///
/// So this leg spans two. A boot that finds no `/gate.elf` builds one **with
/// the compiler as a program** — `tsmc`, given the source and the output name
/// in its arguments, syncing before it exits — and then stops without running
/// it. The next boot of that same volume finds it and runs it. Nothing between
/// the two is the host's: no rebuild, no copy, no patch.
///
/// **Which half runs is not a switch.** There is no flag, no argument and no
/// second kernel; the volume alone decides, which is the only version of this
/// that a second boot could not fake.
fn the_gate(buf: &mut [u8; MSG_BUF_LEN]) -> Result<Gate, u64> {
    // Probed with a plain `Open` rather than by letting `with_the_program`
    // fail: that one asks the service for a *paged* object before it can find
    // out the file is missing, and paged objects are the scarcest thing in this
    // composition (D308, D309). A probe should not cost what the operation
    // costs.
    match open(GATE_PATH, buf) {
        Ok((file, _)) => {
            close(file, buf)?;
            // Read back off the volume and run, exactly as `/program.elf` is
            // run — the loader is told nothing about where this one came from,
            // which is what makes "an image built by the system" a claim about
            // the image rather than about a special path for it.
            match with_the_program(GATE_PATH, buf, execute) {
                Ok(0) => Ok(Gate::Ran),
                Ok(other) => Err(fail(0xc1, other as u32 as u64)),
                Err(code) => Err(code),
            }
        }
        // The service's own `NOT_FOUND`, and only that. Any other refusal is a
        // filesystem that is broken rather than a volume that is new, and a
        // boot that quietly compiled its way past one would stage a program on
        // a volume it could not read.
        Err(code) if code == fail(0xd1, 0x100 | 1) => {
            let mut said = [0u8; DiagnosticRecord::WIRE_SIZE];
            let (status, spoke) = run_compiler(GATE_SOURCE, GATE_NAME, &mut said, buf)?;
            if status != 0 {
                return Err(fail(0xc0, status as u32 as u64));
            }
            if spoke {
                return Err(fail(0xc0, 1));
            }
            // Deliberately not run here. A boot that both built and ran it
            // would pass this check on its own, and the next boot's success
            // would prove nothing that this one had not already shown.
            Ok(Gate::Staged)
        }
        Err(other) => Err(fail(0xc2, other & 0xffff)),
    }
}

/// Whether `needle` appears in `haystack`. No allocator, no `str`: these are
/// bytes off a wire and a path is not required to be UTF-8.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    (0..=haystack.len() - needle.len()).any(|at| &haystack[at..at + needle.len()] == needle)
}

/// The compiler this program runs. Linked here rather than read off the
/// volume — see `run_compiler` for why.
const TSMC_ELF: &[u8] = &tsmc_image::TSMC_ELF;

/// Where a child's startup message lands in *its* address space.
const CHILD_MESSAGE_VA: u64 = 0x0000_1000_0150_0000;

/// Runs `tsmc` over `source` into `output`, and returns its exit status and
/// whatever it said about the attempt.
///
/// **This is Phase 5's shape**: the compiler is a program, told what to compile
/// by its arguments, whose complaints come back as sentences rather than as a
/// number. Everything it needs was built by an earlier phase and had never been
/// composed — argv on the startup message (D302), `diagnostic.isl` (D303), and
/// a program loaded off the volume (D294).
fn run_compiler(
    source: &[u8],
    output: &[u8],
    said: &mut [u8; DiagnosticRecord::WIRE_SIZE],
    buf: &mut [u8; MSG_BUF_LEN],
) -> Result<(i32, bool), u64> {
    // A channel for what the compiler has to say. This program keeps the read
    // end and grants the write end, which is the same shape the root task uses
    // and the reason a diagnostic cannot be forged by anyone else.
    let record_buf = [0u8; ChannelCreateRecord::WIRE_SIZE];
    let create_args = ChannelCreateArgs {
        size: ChannelCreateArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        end0_rights: ChannelRights(ChannelRights::READ.bits() | ChannelRights::WRITE.bits()),
        end1_rights: ChannelRights(ChannelRights::WRITE.bits() | ChannelRights::TRANSFER.bits()),
        record_ptr: record_buf.as_ptr() as u64,
    };
    let mut args = [0u8; 256];
    encode(&create_args, &mut args[..ChannelCreateArgs::WIRE_SIZE]).map_err(|_| fail(0xf5, 0))?;
    if syscall2(SYS_CHANNEL_CREATE, args.as_ptr() as u64, 0) < 0 {
        return Err(fail(0xf5, 1));
    }
    let filled: [u8; ChannelCreateRecord::WIRE_SIZE] = read_kernel_filled(&record_buf);
    let record: ChannelCreateRecord = decode(&filled).map_err(|_| fail(0xf5, 2))?;
    let (mine, theirs) = (record.end0, record.end1);

    // **The compiler is carried, not read off the volume**, and the reason is a
    // limit rather than a preference: the filesystem hands a caller a file's
    // contents as a memory object, an object caps at `MAX_OBJECT_PAGES` — 64
    // KiB — and the compiler is 151 KB. Phase 5's bullet is that the *sources*
    // come off the filesystem and the objects go back to it, which is what
    // happens below; how the compiler itself arrives is the parent's business,
    // and every other program a parent starts here is carried the same way.
    let (child, entry) = (|image: &[u8]| {
        let parsed = tessera_elfload::parse(image).ok_or(fail(0xf6, 0))?;
        let create = ProcessCreateArgs {
            size: ProcessCreateArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            job: HandleRef::new(JOB_HANDLE),
            reserved: 0,
        };
        let mut args = [0u8; 256];
        encode(&create, &mut args[..ProcessCreateArgs::WIRE_SIZE]).map_err(|_| fail(0xf6, 1))?;
        let child = syscall2(SYS_PROCESS_CREATE, args.as_ptr() as u64, 0);
        if child < 0 {
            return Err(fail(0xf6, (-child) as u64 & 0xffff));
        }
        let child = child as u32;
        for segment in parsed.segments() {
            map_segment(child, image, *segment)?;
        }
        Ok((child, parsed.entry))
    })(TSMC_ELF)?;

    // The compiler needs two capabilities and gets exactly two: the filesystem
    // it reads and writes through, and the endpoint it complains on.
    let granted_fs = grant_to(child, tessera_fsapi::SERVICE_ENDPOINT_HANDLE as u32, 0xf7)?;
    let granted_out = grant_to(child, theirs, 0xf8)?;

    let mut argv = [StartupArg {
        len: 0,
        reserved: 0,
        bytes: [0u8; 160],
    }; 12];
    for (slot, value) in argv.iter_mut().zip([source, output]) {
        if value.len() > slot.bytes.len() {
            return Err(fail(0xf9, value.len() as u64));
        }
        slot.len = value.len() as u32;
        slot.bytes[..value.len()].copy_from_slice(value);
    }
    let startup = StartupArgs {
        size: StartupArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        handles: StartupHandles {
            size: StartupHandles::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            endpoint: HandleRef::new(granted_fs),
            port: HandleRef::new(0),
        },
        output: HandleRef::new(granted_out),
        count: 2,
        reserved: 0,
        args: argv,
    };
    let mut message = [0u8; StartupArgs::WIRE_SIZE];
    encode(&startup, &mut message).map_err(|_| fail(0xf9, 1))?;

    let start = ProcessStartArgs {
        size: ProcessStartArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        process: HandleRef::new(child),
        reserved: 0,
        entry,
        stack: CHILD_STACK_BASE,
        arg: CHILD_MESSAGE_VA,
        message_ptr: message.as_ptr() as u64,
        message_len: message.len() as u64,
        message_va: CHILD_MESSAGE_VA,
    };
    let mut args = [0u8; 256];
    encode(&start, &mut args[..ProcessStartArgs::WIRE_SIZE]).map_err(|_| fail(0xfa, 0))?;
    if syscall2(SYS_PROCESS_START, args.as_ptr() as u64, 0) < 0 {
        return Err(fail(0xfa, 1));
    }

    let wait = ProcessWaitArgs {
        size: ProcessWaitArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        process: HandleRef::new(child),
        reserved: 0,
    };
    encode(&wait, &mut args[..ProcessWaitArgs::WIRE_SIZE]).map_err(|_| fail(0xfb, 0))?;
    let code = syscall2(SYS_PROCESS_WAIT, args.as_ptr() as u64, 0);
    if code < 0 {
        return Err(fail(0xfb, 1));
    }

    // Non-blocking: the compiler has exited, so a diagnostic either is queued
    // or never will be.
    let recv = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 1,
        inline_ptr: said.as_mut_ptr() as u64,
        inline_len: said.len() as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut recv_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    encode(&recv, &mut recv_buf).map_err(|_| fail(0xfc, 0))?;
    let got = syscall2(SYS_CHANNEL_RECV, recv_buf.as_ptr() as u64, u64::from(mine));
    let spoke = got > 0;
    if spoke {
        *said = read_kernel_filled(said);
    }
    Ok((code as u32 as i32, spoke))
}

/// Copies one of this program's capabilities into `child`, narrowed to what a
/// child needs: send on a channel, or use the service endpoint.
fn grant_to(child: u32, source: u32, tag: u64) -> Result<u32, u64> {
    let args = ProcessGrantArgs {
        size: ProcessGrantArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        process: HandleRef::new(child),
        source: HandleRef::new(source),
        // **`WRITE` alone, because that is what a client needs and all this
        // program may pass on.** A grant may not widen: the requested rights
        // must be a subset of what the granter holds, and this program holds
        // the service endpoint as `WRITE | TRANSFER`. Asking for `READ` too —
        // which the first version did — is refused as `AccessDenied`, from a
        // capability the granter legitimately has. A synchronous call needs no
        // `READ`: boot installs this same endpoint with `WRITE` alone for every
        // other client.
        rights: ProcessRights(ProcessRights::WRITE.bits()),
        reserved: 0,
    };
    let mut buf = [0u8; ProcessGrantArgs::WIRE_SIZE];
    encode(&args, &mut buf).map_err(|_| fail(tag, 0))?;
    let handle = syscall2(SYS_PROCESS_GRANT, buf.as_ptr() as u64, 0);
    if handle < 0 {
        return Err(fail(tag, (-handle) as u64 & 0xffff));
    }
    Ok(handle as u32)
}

/// Where the program on the volume is mapped while it is read and loaded.
const PROGRAM_VA: u64 = 0x0000_1000_0140_0000;

/// The job boot seeds this process, and the whole of the authority that makes
/// it a loader: one right, `create-process`, over one job.
const JOB_HANDLE: u32 = 1;

/// Where a child's stack goes in *its* address space — this port's user half,
/// which is the child's to lay out and not this program's.
const CHILD_STACK_BASE: u64 = 0x0000_0f00_0000_0000;

const SYS_DEBUG_WRITE: u64 = 1;
const SYS_CHANNEL_CREATE: u64 = 11;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_PROCESS_GRANT: u64 = 50;
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
    // **And the object goes back too** (D309). Unmapping gives up the *window*;
    // the handle is what makes this program a holder, and an object lives while
    // any holder holds one (D286). Keeping it meant the service's `Close` never
    // destroyed the object, so its pager binding was never released either —
    // and `MAX_PAGERS` is 8, so the ninth file opened this way was refused for
    // ever, on a machine with everything else free.
    let _ = Machine.close(object);
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
        (
            0,
            segment.vaddr + covered,
            segment.memsz.saturating_sub(covered),
        ),
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
