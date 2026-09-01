// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The compiler, as a program you run.**
//!
//! D304 proved a program on this machine could produce a program: `fs-client`
//! read a source off the volume, compiled it, wrote the image back and ran what
//! came off. What it did *not* produce was a compiler — the compilation was a
//! function call inside a filesystem client, on paths compiled into it, whose
//! errors were a packed failure word. That is a machine that can compile, and
//! it is not a toolchain (`docs/roadmap/04`, Phase 5; `build/README.md`, D307).
//!
//! This is the same code generator behind an interface a build system could
//! use: **what to compile arrives as arguments**, the input and output are
//! files it opens for itself, and **what went wrong is a sentence naming a
//! line** rather than a number nobody can act on. Every one of those is a
//! mechanism an earlier phase built and nothing had yet composed — argv from
//! D302, `diagnostic.isl` from D303, the filesystem from D294.
//!
//! ```text
//! tsmc /source.tsm built.elf
//! ```
//!
//! **Two arguments and no flags.** A compiler with options is a compiler whose
//! options need a parser, and this one has nothing to choose: the language has
//! five operations and the back end has one target. When there is a second, the
//! argument that selects it is the first flag.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 5")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use diagnostic::{Diagnostic, DiagnosticRecord, Severity};
use process_abi::{ExitStatus, StartupArgs};
use tessera_fsapi::{
    BUFFER_LEN, BUFFER_VA, Buffer, MSG_BUF_LEN, close, create, open, read, sync, unlink, write,
};
use tessera_isl_runtime::{decode, encode};
use tessera_tsm::{ErrorKind, MAX_IMAGE};
use tessera_uabi::{read_kernel_filled, syscall2};

const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_SEND: u64 = 12;

/// The most source this compiler will read.
///
/// The transfer buffer's size, because a source is read through it in one go: a
/// file longer than this is refused rather than compiled in part, which is the
/// same choice `tsm` makes about an operation count.
const MAX_SOURCE: usize = BUFFER_LEN;

/// Sends one diagnostic, if this program was given anywhere to report.
///
/// One-way, as the contract is: a compiler that blocked on whoever was
/// collecting its errors would hang a build rather than fail it.
fn report(output: u64, severity: Severity, text: &[u8]) {
    if output == 0 {
        return;
    }
    let mut record = DiagnosticRecord {
        size: DiagnosticRecord::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        severity,
        len: 0,
        truncated: 0,
        reserved: 0,
        text: [0u8; 192],
    };
    let n = if text.len() > record.text.len() {
        record.truncated = 1;
        record.text.len()
    } else {
        text.len()
    };
    record.len = n as u32;
    record.text[..n].copy_from_slice(&text[..n]);

    let mut payload = [0u8; DiagnosticRecord::WIRE_SIZE];
    if encode(&record, &mut payload).is_err() {
        return;
    }
    let msg = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: Diagnostic::INTERFACE_ID,
        txn_id: 0,
        method_id: Diagnostic::REPORT,
        msg_flags: 0,
        inline_ptr: payload.as_ptr() as u64,
        inline_len: payload.len() as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&msg, &mut buf).is_err() {
        return;
    }
    let _ = syscall2(SYS_CHANNEL_SEND, buf.as_ptr() as u64, output);
}

/// Writes `value` as decimal into `out`, returning how many bytes it took.
///
/// **A compiler has to be able to say a number.** There is no formatter here —
/// `core::fmt` needs an allocator for anything interesting and this program has
/// none — so the one number a diagnostic carries is written by hand.
fn decimal(mut value: u32, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 10];
    let mut n = 0;
    while value > 0 {
        digits[n] = b'0' + (value % 10) as u8;
        value /= 10;
        n += 1;
    }
    for i in 0..n {
        out[i] = digits[n - 1 - i];
    }
    n
}

/// The sentence a compiler says when it cannot compile.
///
/// `tsmc: <path>:<line>: <what>` — the shape every compiler has said since
/// `cc`, and it is that shape because a build system parses the first two
/// fields and a person reads the third.
fn complain(output: u64, path: &[u8], line: u32, what: &[u8]) {
    let mut text = [0u8; 192];
    let mut at = 0usize;
    let mut push = |bytes: &[u8], at: &mut usize| {
        let room = text.len() - *at;
        let n = bytes.len().min(room);
        text[*at..*at + n].copy_from_slice(&bytes[..n]);
        *at += n;
    };
    push(b"tsmc: ", &mut at);
    push(path, &mut at);
    push(b":", &mut at);
    if line > 0 {
        let mut digits = [0u8; 10];
        let n = decimal(line, &mut digits);
        push(&digits[..n], &mut at);
        push(b": ", &mut at);
    } else {
        push(b" ", &mut at);
    }
    push(what, &mut at);
    report(output, Severity::Error, &text[..at]);
}

/// What a `tsm` error is called, in words rather than in a discriminant.
fn describe(kind: ErrorKind) -> &'static [u8] {
    match kind {
        ErrorKind::UnknownOp => b"unknown operation",
        ErrorKind::BadOperand => b"operand is not a number, or is too wide for its instruction",
        ErrorKind::WrongArity => b"wrong number of operands",
        ErrorKind::TooManyOps => b"too many operations",
        ErrorKind::NoEmit => b"no `emit`, so the program would report nothing",
        ErrorKind::TrailingOps => b"operations after `emit` would never run",
        ErrorKind::ImageTooLarge => b"the program is too large to emit",
    }
}

fn run(message_va: u64) -> ExitStatus {
    let bytes = read_kernel_filled::<{ StartupArgs::WIRE_SIZE }>(
        // SAFETY: `message_va` is the address the parent named in
        // `ProcessStartArgs::message_va`, and the kernel mapped a full page
        // there before this program's first instruction ran.
        unsafe { core::slice::from_raw_parts(message_va as *const u8, StartupArgs::WIRE_SIZE) },
    );
    let Ok(startup) = decode::<StartupArgs>(&bytes) else {
        return ExitStatus::Software;
    };
    if startup.size != StartupArgs::WIRE_SIZE as u32 || startup.version != 1 {
        return ExitStatus::Software;
    }
    let output = u64::from(startup.output.index());
    // **Where the filesystem is, said by the parent rather than assumed.** A
    // program boot starts finds its service at handle 0; one a parent granted
    // finds it wherever the grant landed, which is what this field is for.
    tessera_fsapi::set_service_endpoint(startup.handles.endpoint.index());

    // Two arguments: what to compile, and what to call the result. Checked
    // before either is used, and refused rather than defaulted — a compiler
    // that invented an output name would overwrite a file nobody named.
    if startup.count != 2 {
        complain(output, b"", 0, b"usage: tsmc <source> <output>");
        return ExitStatus::Usage;
    }
    let src_len = startup.args[0].len as usize;
    let out_len = startup.args[1].len as usize;
    if src_len == 0 || src_len > 128 || out_len == 0 || out_len > 128 {
        complain(output, b"", 0, b"usage: tsmc <source> <output>");
        return ExitStatus::Usage;
    }
    let source_path = &startup.args[0].bytes[..src_len];
    let output_name = &startup.args[1].bytes[..out_len];

    let mut buf = [0u8; MSG_BUF_LEN];
    let Ok(mut buffer) = Buffer::new() else {
        complain(output, source_path, 0, b"no transfer buffer");
        return ExitStatus::Unavailable;
    };

    // --- read the source ---
    let file = match open(source_path, &mut buf) {
        Ok((file, _)) => file,
        Err(code) => {
            // **The service's status, not just "no".** `open` packs the
            // contract's status into the low byte of its failure; a compiler
            // that dropped it would say "cannot open" for a file that is
            // missing, a service that is out of buffers, and one that has too
            // many files open — three different things to do about it.
            let mut what = [0u8; 32];
            let head = b"cannot open, status ";
            what[..head.len()].copy_from_slice(head);
            let n = decimal((code & 0xff) as u32, &mut what[head.len()..]);
            complain(output, source_path, 0, &what[..head.len() + n]);
            return ExitStatus::NotFound;
        }
    };
    let mut source = [0u8; MAX_SOURCE];
    let Ok(got) = read(file, 0, source.len() as u64, &mut buffer, &mut buf) else {
        complain(output, source_path, 0, b"cannot read");
        return ExitStatus::Unavailable;
    };
    let _ = close(file, &mut buf);
    if got == 0 || got as usize > source.len() {
        complain(
            output,
            source_path,
            0,
            b"empty, or longer than this compiler reads",
        );
        return ExitStatus::Software;
    }
    if buffer.map().is_err() {
        complain(output, source_path, 0, b"cannot map the transfer buffer");
        return ExitStatus::Unavailable;
    }
    // SAFETY: the kernel just mapped this object's single page read-write at
    // `BUFFER_VA` for this process, and nothing else here references it.
    let page = unsafe { core::slice::from_raw_parts(BUFFER_VA as *const u8, BUFFER_LEN) };
    let read_len = got as usize;
    source[..read_len].copy_from_slice(&page[..read_len]);

    // --- compile ---
    let program = match tessera_tsm::parse(&source[..read_len]) {
        Ok(program) => program,
        Err(e) => {
            complain(output, source_path, e.line, describe(e.kind));
            return ExitStatus::Software;
        }
    };
    let mut image = [0u8; MAX_IMAGE];
    let len = match program.emit(&mut image) {
        Ok(len) => len,
        Err(e) => {
            complain(output, source_path, e.line, describe(e.kind));
            return ExitStatus::Software;
        }
    };

    // --- write the object ---
    let _ = unlink(output_name, &mut buf);
    let Ok(out_file) = create(output_name, &mut buf) else {
        complain(output, output_name, 0, b"cannot create");
        return ExitStatus::Unavailable;
    };
    let Ok(count) = write(out_file, 0, &image[..len], &mut buffer, &mut buf) else {
        complain(output, output_name, 0, b"cannot write");
        return ExitStatus::Unavailable;
    };
    if count != len as u64 {
        complain(output, output_name, 0, b"short write");
        return ExitStatus::Unavailable;
    }
    // **Synced before this program says it succeeded.** A compiler that
    // returned zero with its output still in a cache would have a build system
    // run a link step against a file that is not there.
    if sync(out_file, &mut buf).is_err() {
        complain(output, output_name, 0, b"cannot sync");
        return ExitStatus::Unavailable;
    }
    let _ = close(out_file, &mut buf);

    ExitStatus::Ok
}

fn exit(status: ExitStatus) -> ! {
    syscall2(SYS_PROCESS_EXIT, status as i32 as u64, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// The ELF entry point. `arg` is the address of this program's startup message.
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in this
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: usize) -> ! {
    exit(run(arg as u64))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(ExitStatus::Software)
}
