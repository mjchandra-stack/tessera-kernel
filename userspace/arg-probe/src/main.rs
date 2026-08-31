// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **A program told what to work on, rather than compiled knowing it.**
//!
//! Every ring-3 program in this tree has its subject built in: `fs-client`
//! opens `/program.elf` because that path is a constant in its source, and a
//! second file would be a second program. A compiler cannot be written that
//! way — the file it compiles is the one thing about it that changes on every
//! run — which is why `docs/roadmap/04` makes an argument vector Phase 1 and
//! why nothing above it can be written first (`build/README.md`, D302).
//!
//! **What it proves, and why the proof is not its own word.** The path arrives
//! in `StartupArgs` on the startup message, and this program sends those exact
//! bytes back on the endpoint its parent granted it. A parent that gets its own
//! string back on a channel it created knows the argument arrived intact and
//! arrived *here*: neither half can be faked from the kernel side, which is the
//! same standard `grant-probe` is held to.
//!
//! **And it refuses in the vocabulary its parent reads.** `ExitStatus` is a
//! schema rather than a number this program invented, so a supervisor can tell
//! "you gave me no arguments" from "what you named is not there" from "I broke"
//! — and act differently on each. That distinction is the whole of Phase 1's
//! third bullet: `ProcessWait` has returned an exit code since D250 and nothing
//! said what one meant.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 1"),
//! docs/api/01-system-call-interface.md ("Process And Thread")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use process_abi::{ExitStatus, StartupArgs};
use tessera_isl_runtime::{decode, encode};
use tessera_uabi::{read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_SEND: u64 = 12;

/// The most arguments `StartupArgs` can carry, and the bound `count` is checked
/// against.
///
/// Named here rather than written as `4` at the use site: the array's length is
/// a fact about the schema, and a program that hard-coded a different number
/// would read past what its parent filled or ignore what it sent.
const MAX_ARGS: usize = 4;

/// The longest argument, from `StartupArg::bytes`.
const MAX_ARG_LEN: usize = 128;

fn run(message_va: u64) -> ExitStatus {
    // Read volatile because the compiler has no idea the kernel wrote this
    // page, and decoded through the generated binding rather than by hand, so
    // a message of the wrong size or version is refused instead of misread.
    let bytes = read_kernel_filled::<{ StartupArgs::WIRE_SIZE }>(
        // SAFETY: `message_va` is the address the parent named in
        // `ProcessStartArgs::message_va`, and the kernel mapped a full page
        // there before this program's first instruction ran. `StartupArgs` is
        // 592 bytes, well inside it.
        unsafe { core::slice::from_raw_parts(message_va as *const u8, StartupArgs::WIRE_SIZE) },
    );
    let Ok(args) = decode::<StartupArgs>(&bytes) else {
        return ExitStatus::Software;
    };
    if args.size != StartupArgs::WIRE_SIZE as u32 || args.version != 1 {
        return ExitStatus::Software;
    }

    // **`count` is checked against the array's bound before anything is read,
    // and refused rather than clamped.** A program that clamped would act on a
    // prefix of what its parent meant and report success for it — which is
    // worse than not running, because the parent would believe it.
    let count = args.count as usize;
    if count == 0 || count > MAX_ARGS {
        return ExitStatus::Usage;
    }
    let arg = &args.args[0];
    let len = arg.len as usize;
    if len == 0 || len > MAX_ARG_LEN {
        return ExitStatus::Usage;
    }
    let path = &arg.bytes[..len];

    // **A path this program will not act on**, which is what makes the failure
    // leg something the parent asked for rather than an accident. Absolute
    // paths only: a relative one has no meaning here, because nothing in this
    // system has a working directory yet.
    if path[0] != b'/' {
        return ExitStatus::NotFound;
    }

    // Send the exact bytes back, so the parent's evidence is its own string
    // rather than this program's claim about it.
    let msg = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: path.as_ptr() as u64,
        inline_len: path.len() as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&msg, &mut buf).is_err() {
        return ExitStatus::Software;
    }
    // The endpoint number is the parent's answer, carried in the same message
    // as the arguments — `StartupArgs` composes `StartupHandles` so a child
    // that takes arguments still learns where its capabilities landed.
    let endpoint = u64::from(args.handles.endpoint.index());
    let sent = syscall2(SYS_CHANNEL_SEND, buf.as_ptr() as u64, endpoint);
    if sent < 0 {
        // The endpoint was not there, or carried no `WRITE`. That is a
        // capability this program was supposed to be given and was not, which
        // is `UNAVAILABLE` and not `SOFTWARE`: nothing here is broken.
        return ExitStatus::Unavailable;
    }
    if sent as usize != path.len() {
        return ExitStatus::Software;
    }
    ExitStatus::Ok
}

fn exit(status: ExitStatus) -> ! {
    syscall2(SYS_PROCESS_EXIT, status as i32 as u64, 0);
    // The kernel does not return from an exit; spin rather than fall off the
    // end of the entry point if a future one ever did.
    loop {
        core::hint::spin_loop();
    }
}

/// The ELF entry point. `arg` is what the parent passed in
/// `ProcessStartArgs::arg`: the address of this program's startup message.
///
/// `usize` rather than `u64`, because the kernel hands this over in one
/// argument register and a `u64` parameter would be passed in a pair on a
/// 32-bit machine (D259).
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: usize) -> ! {
    exit(run(arg as u64))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(ExitStatus::Software)
}
