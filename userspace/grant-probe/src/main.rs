// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **grant probe**: a `no_std` Rust program that starts holding nothing
//! the kernel gave it.
//!
//! Every other ring-3 program in this tree begins with a handle table the
//! kernel's boot glue filled in — a device at 1, an endpoint at 0, a port at 2
//! — which is the kernel deciding what user space may reach. This one is
//! started by `//userspace/roottask`, and the single capability it holds was
//! put there by that root task with `ProcessGrant`. It does not even assume
//! *where*: the handle number arrives as its startup argument, because a
//! parent that chooses what its child holds is the same parent that should say
//! where it landed.
//!
//! What it does is send one message on that endpoint and raise an edge on a
//! port, then exit. Both are proofs, and they are proofs because neither can be
//! faked from the kernel side: a message arriving on the parent's end of a
//! channel the *parent* created means this program held a writable capability
//! to the far end, and an event on a port the parent made and bound means it
//! held `SIGNAL` on that port. The only way it could have either is the grant.
//!
//! **Two handles arrive in one startup word**, low half then high half, because
//! `ProcessStart` carries one. A parent that hands its child several
//! capabilities has to say where each landed, and until there is a startup
//! *message* (`docs/api/01`, still designed) packing them is the honest
//! alternative to a convention the child would otherwise have to assume.
//!
//! The exit code carries which step failed, so a boot that gets a message but
//! a non-zero code says where it went wrong rather than only that it did.
//!
//! Normative: docs/api/01-system-call-interface.md ("Process And Thread"),
//! docs/kernel/01-kernel-model.md ("Capabilities")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use process_abi::StartupHandles;
use tessera_isl_runtime::{decode, encode};
use tessera_uabi::{read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_SEND: u64 = 12;
const SYS_PORT_SIGNAL: u64 = 44;

/// The bytes this program sends. Recognisable in a hex dump and distinct from
/// anything the kernel puts on a channel of its own accord, so a boot check
/// asserting on them is asserting on *this* program having run.
pub const GRANTED_MAGIC: [u8; 8] = *b"GRANTED!";

/// Exit codes. Zero is success; each other value names the step that failed,
/// so a boot that sees no message can still tell "never ran" from "could not
/// encode" from "the send was refused".
const EXIT_OK: i32 = 0;
const EXIT_ENCODE_FAILED: i32 = 71;
const EXIT_SEND_REFUSED: i32 = 72;
const EXIT_SHORT_SEND: i32 = 73;
const EXIT_SIGNAL_REFUSED: i32 = 74;
/// The startup message did not arrive, or did not decode. Its own code because
/// "the parent never delivered it" and "the send was refused" are different
/// failures and a reader needs to know which.
const EXIT_BAD_MESSAGE: i32 = 75;

/// The source this program raises on the port it was granted. Agreed with the
/// parent, which bound the port to it — a raise names a source the port is
/// already bound to, never an arbitrary one.
const SIGNAL_SOURCE: u64 = 0x5161;

fn run(message_va: u64) -> i32 {
    // **The startup message, where the parent said it would be.** This used to
    // be two handle numbers packed into the halves of one word — a convention,
    // and a 64-bit one: on a 32-bit machine the argument register is 32 bits
    // and the second handle had nowhere to go (build/README.md, D261).
    //
    // Read volatile because the compiler has no idea the kernel wrote this
    // page, and decoded through the generated binding rather than by hand, so
    // a message of the wrong size or version is refused instead of misread.
    let bytes = read_kernel_filled::<{ StartupHandles::WIRE_SIZE }>(
        // SAFETY: `message_va` is the address the parent named in
        // `ProcessStartArgs::message_va` and the kernel mapped a full page
        // there before this program's first instruction ran.
        unsafe { core::slice::from_raw_parts(message_va as *const u8, StartupHandles::WIRE_SIZE) },
    );
    let Ok(handles) = decode::<StartupHandles>(&bytes) else {
        return EXIT_BAD_MESSAGE;
    };
    if handles.size != StartupHandles::WIRE_SIZE as u32 || handles.version != 1 {
        return EXIT_BAD_MESSAGE;
    }
    let endpoint = u64::from(handles.endpoint.index());
    let port = u64::from(handles.port.index());
    let payload = GRANTED_MAGIC;
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: payload.as_ptr() as u64,
        inline_len: payload.len() as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut args_buf).is_err() {
        return EXIT_ENCODE_FAILED;
    }
    // The handle number is the parent's answer, not a convention this program
    // and the kernel agreed on out of band.
    let sent = syscall2(SYS_CHANNEL_SEND, args_buf.as_ptr() as u64, endpoint);
    if sent < 0 {
        return EXIT_SEND_REFUSED;
    }
    if sent as usize != payload.len() {
        return EXIT_SHORT_SEND;
    }
    // The port half. Raising an edge is authority — `Rights::SIGNAL` on a
    // capability, not a number anyone may pass — and this program holds it
    // only because its parent chose to give it.
    if syscall2(SYS_PORT_SIGNAL, port, SIGNAL_SOURCE) < 0 {
        return EXIT_SIGNAL_REFUSED;
    }
    EXIT_OK
}

fn exit(code: i32) -> ! {
    syscall2(SYS_PROCESS_EXIT, code as u64, 0);
    // The kernel does not return from an exit; spin rather than fall off the
    // end of the entry point if a future one ever did.
    loop {
        core::hint::spin_loop();
    }
}

/// The ELF entry point. `arg` is what the parent passed in
/// `ProcessStartArgs::arg`: the address of this program's **startup message**,
/// which says where each capability `ProcessGrant` installed landed.
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
    exit(EXIT_ENCODE_FAILED)
}
