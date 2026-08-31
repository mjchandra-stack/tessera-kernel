// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The thing a program's output is addressed to.**
//!
//! Until now a ring-3 program that wanted to say something called `DebugWrite`,
//! which is the kernel's console — a facility that exists so a machine which
//! cannot yet run programs can say what happened. A program is past that point
//! by definition, and what it emits belongs to whoever is collecting its
//! output. This is that collector: it holds one endpoint speaking
//! `diagnostic.isl`, and every program the root task starts reports to it
//! instead of to the kernel (`build/README.md`, D303).
//!
//! **It forwards rather than renders, and the reason is a gap worth naming.**
//! `syscall_abi.isl` declares `DebugWrite` as a buffer and a length; every port
//! implements the length-zero case alone, recording the argument register as a
//! *value*. So there is no console in this system that a ring-3 program can put
//! a byte of text on — not this service, not anybody. What this program does is
//! give the text an addressee, and hand it to whoever composed the run.
//!
//! **When a console arrives, this is the one program that changes.** That is
//! the whole benefit of the contract: a hundred programs reporting through
//! `DebugWrite` would all have to be edited, and a hundred programs reporting
//! through `Diagnostic` do not have to be touched at all.
//!
//! **One-way in, one-way out, and no reply anywhere.** A service that replied
//! would have to loop back to its own receive, which is the shape that has bit
//! this tree twice (D85, D91) — and a reporter that waited for an
//! acknowledgement would turn a failed program into a hung one. Nothing here
//! calls `ChannelReply`, so neither trap is reachable.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 1")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use diagnostic::{Diagnostic, DiagnosticIncoming, DiagnosticRecord};
use process_abi::{ExitStatus, StartupArgs};
use tessera_isl_runtime::{decode, encode};
use tessera_uabi::{read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_SEND: u64 = 12;
const SYS_CHANNEL_RECV: u64 = 13;

/// The most records this service will handle before giving up.
///
/// **A bound rather than a loop, because a service with no bound is a machine
/// that never boots.** Nothing in this composition can make this service stop
/// except the `Close` its composer sends, and a peer that misbehaved — sending
/// for ever, or being replaced by something that does — would otherwise hang
/// the check rather than fail it. Reaching this bound is a failure and is
/// reported as one.
const MAX_RECORDS: u32 = 64;

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
    // What it serves, and where it hands on what it collected. A collector with
    // nowhere to forward to is not a failure of this program — but it is not
    // what this composition asked for, so it says so.
    let inbound = u64::from(startup.handles.endpoint.index());
    let outbound = u64::from(startup.output.index());
    if outbound == 0 {
        return ExitStatus::Unavailable;
    }

    let mut seen: u32 = 0;
    loop {
        if seen >= MAX_RECORDS {
            return ExitStatus::Software;
        }
        // The wire buffer. A record is the largest thing this contract carries,
        // so one buffer sized for it serves both methods — `Close` arrives as a
        // zero-length payload and decodes from an empty reader.
        let mut inbox = [0u8; DiagnosticRecord::WIRE_SIZE];
        let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
        let recv = ChannelMsgArgs {
            size: ChannelMsgArgs::WIRE_SIZE as u32,
            version: 4,
            flags: 0,
            interface_id: Diagnostic::INTERFACE_ID,
            txn_id: 0,
            method_id: 0,
            // Blocking: a collector with nothing to collect waits, which is
            // what makes it a service rather than a poll.
            msg_flags: 0,
            inline_ptr: inbox.as_mut_ptr() as u64,
            inline_len: inbox.len() as u64,
            handles_ptr: 0,
            handle_count: 0,
            installed_ptr: 0,
            installed_cap: 0,
        };
        if encode(&recv, &mut args_buf).is_err() {
            return ExitStatus::Software;
        }
        let received = syscall2(SYS_CHANNEL_RECV, args_buf.as_ptr() as u64, inbound);
        if received < 0 {
            // The peer is gone, or the endpoint was never writable. Either way
            // there is nothing left to collect and nothing this program can do
            // about it.
            return ExitStatus::Unavailable;
        }
        // The kernel wrote the payload; the compiler did not see it happen. The
        // method id comes back in the same args struct the call was made with.
        let filled: [u8; DiagnosticRecord::WIRE_SIZE] = read_kernel_filled(&inbox);
        let echoed: [u8; ChannelMsgArgs::WIRE_SIZE] = read_kernel_filled(&args_buf);
        let Ok(header) = decode::<ChannelMsgArgs>(&echoed) else {
            return ExitStatus::Software;
        };
        let n = received as usize;
        if n > filled.len() {
            return ExitStatus::Software;
        }
        let Ok(incoming) = DiagnosticIncoming::decode(
            header.method_id,
            &mut tessera_isl_runtime::Reader::new(&filled[..n]),
        ) else {
            // A method this service does not implement, or a malformed record.
            // Refused rather than skipped: a collector that quietly dropped what
            // it could not parse would lose exactly the diagnostics that matter.
            return ExitStatus::Software;
        };

        match incoming {
            DiagnosticIncoming::Close => return ExitStatus::Ok,
            DiagnosticIncoming::Report(record) => {
                if record.len as usize > record.text.len() {
                    return ExitStatus::Software;
                }
                seen += 1;
                // **Forwarded whole, not summarised.** Whoever composed the run
                // is going to check what a program said, and a digest would
                // prove only that something arrived. The record goes on
                // unchanged, which also means this service has no opinion about
                // the contents — it routes.
                let mut out = [0u8; DiagnosticRecord::WIRE_SIZE];
                if encode(&record, &mut out).is_err() {
                    return ExitStatus::Software;
                }
                let msg = ChannelMsgArgs {
                    size: ChannelMsgArgs::WIRE_SIZE as u32,
                    version: 4,
                    flags: 0,
                    interface_id: Diagnostic::INTERFACE_ID,
                    txn_id: 0,
                    method_id: Diagnostic::REPORT,
                    msg_flags: 0,
                    inline_ptr: out.as_ptr() as u64,
                    inline_len: out.len() as u64,
                    handles_ptr: 0,
                    handle_count: 0,
                    installed_ptr: 0,
                    installed_cap: 0,
                };
                let mut send_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
                if encode(&msg, &mut send_buf).is_err() {
                    return ExitStatus::Software;
                }
                if syscall2(SYS_CHANNEL_SEND, send_buf.as_ptr() as u64, outbound) < 0 {
                    return ExitStatus::Unavailable;
                }
            }
        }
    }
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
