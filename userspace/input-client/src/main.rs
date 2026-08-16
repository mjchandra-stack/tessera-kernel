// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **input client**: a `no_std` Rust program that reads a keyboard
//! it has never heard of and judges the driver serving it.
//!
//! It is `blk-client` for a different class, and deliberately so. The point is
//! not that a keyboard works — it is that the **same conformance suite**, with
//! nothing added to it, holds a fourth contract to the same seven rules. This
//! program calls every required method, one optional the driver advertises, one
//! it does not, a reset, and a vendor ordinal nobody negotiated; it builds a
//! transcript out of what came back and hands it to
//! `tessera_class_conformance`, which knows what an ordinal is and does not
//! know what a keyboard is.
//!
//! **The interesting answer is `NO_REPORT`.** Every other class this suite
//! judges fails when it has nothing to give. An idle keyboard is a working
//! keyboard, so a poll that comes back empty has to count as a pass — and the
//! rule that makes it one is "answered within the closed set", which was
//! written for disks and needed no change.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use input_device::{
    InputControlReply, InputControlRequest, InputDescribeReply, InputError, InputPowerState,
    InputReportReply, InputReportRequest,
};
use tessera_class_conformance::{Described, Exchange, INPUT, check};
use tessera_isl_runtime::{decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;

/// The one capability boot installs: the driver's service endpoint.
const DRIVER_ENDPOINT_HANDLE: u64 = 0;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// The contract's ordinals, as this client calls them.
const DESCRIBE: u32 = 1;
const POLL: u32 = 2;
const SET_REPORT: u32 = 3;
const GET_REPORT: u32 = 4;
const RESET: u32 = 5;
const SET_POWER: u32 = 6;

/// Ordinals at or above this belong to a vendor extension namespace. Nothing
/// negotiated one, so a driver must refuse.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// Exchanges the transcript holds: the six calls above, plus the vendor one.
const TRANSCRIPT_LEN: usize = 7;

/// What this program reports: a tag, and what it found.
///
/// The tag makes the value unmistakable in a boot log, and the two halves below
/// are what a checker outside this program can compare against something it
/// worked out independently.
const REPORT_TAG: u64 = 0x1d << 56;
/// Set when the conformance suite came back complete — every rule reached and
/// every rule held.
const REPORT_CONFORMANT: u64 = 1 << 32;
/// Set when a poll answered `NO_REPORT`: the value this class exists to have,
/// and the one no other contract here can produce.
const REPORT_IDLE_IS_FINE: u64 = 1 << 33;
/// Set when `GetReport` came back with the report the device is holding — a
/// control transfer that crossed two other processes to reach a device with no
/// registers.
const REPORT_READ_THROUGH_RELAY: u64 = 1 << 34;

/// Writes a `ChannelMsgArgs` naming a method.
fn channel_args(
    buf_ptr: u64,
    buf_len: u64,
    method: u32,
) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: buf_len,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0xf0, 0xe)),
    }
}

/// One call to the driver. The reply lands back in the same buffer.
fn call(buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Result<(), u64> {
    // The whole buffer, not the request's length: a call's `inline_len` says
    // how many bytes go out *and* how many of the reply come back, so sizing it
    // to the question clamps every answer to the size of the question.
    let args = channel_args(buf.as_ptr() as u64, MSG_BUF_LEN as u64, method)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        DRIVER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xf1, (-n) as u64));
    }
    Ok(())
}

/// A control request, which is what five of this contract's six methods take.
fn control_request(state: InputPowerState) -> InputControlRequest {
    InputControlRequest {
        size: InputControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state,
        reserved: 0,
    }
}

/// An exchange the driver did not answer at all.
///
/// **Recorded rather than skipped.** A method that produced no reply is a
/// different failure from one that replied badly, and a transcript that simply
/// omitted it would let the suite report every rule as passing.
fn unanswered(ordinal: u32) -> Exchange {
    Exchange {
        ordinal,
        status: 0,
        answered: false,
        detail: 0,
    }
}

/// Calls a method taking a control request and returns what came back.
fn control(msg_buf: &mut [u8; MSG_BUF_LEN], method: u32, state: InputPowerState) -> Exchange {
    let request = control_request(state);
    if encode(&request, &mut msg_buf[..InputControlRequest::WIRE_SIZE]).is_err() {
        return unanswered(method);
    }
    if call(msg_buf, method).is_err() {
        return unanswered(method);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<InputControlReply>(&bytes[..InputControlReply::WIRE_SIZE]) {
        Ok(reply) => Exchange {
            ordinal: method,
            status: reply.status as u32,
            answered: true,
            // The power state a reset left, which is the one thing the suite
            // checks beyond the status.
            detail: reply.state as u32,
        },
        Err(_) => unanswered(method),
    }
}

/// Calls a method taking a report request.
fn report_call(
    msg_buf: &mut [u8; MSG_BUF_LEN],
    method: u32,
) -> (Exchange, InputError, u32, [u8; 64]) {
    // **`Poll` takes a control request and the other two take a report.** They
    // all answer with a report, which is what makes the difference easy to miss
    // — and a client that sent the wrong one would have the driver reject a
    // method it implements perfectly well.
    let encoded = if method == POLL {
        encode(
            &control_request(InputPowerState::Active),
            &mut msg_buf[..InputControlRequest::WIRE_SIZE],
        )
        .is_ok()
    } else {
        let request = InputReportRequest {
            size: InputReportRequest::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            report_id: 0,
            length: 0,
            report: [0u8; 64],
        };
        encode(&request, &mut msg_buf[..InputReportRequest::WIRE_SIZE]).is_ok()
    };
    if !encoded {
        return (unanswered(method), InputError::Protocol, 0, [0u8; 64]);
    }
    if call(msg_buf, method).is_err() {
        return (unanswered(method), InputError::Protocol, 0, [0u8; 64]);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<InputReportReply>(&bytes[..InputReportReply::WIRE_SIZE]) {
        Ok(reply) => (
            Exchange {
                ordinal: method,
                status: reply.status as u32,
                answered: true,
                detail: reply.length,
            },
            reply.status,
            reply.length,
            reply.report,
        ),
        Err(_) => match decode::<InputControlReply>(&bytes[..InputControlReply::WIRE_SIZE]) {
            // `SetReport` answers with a control reply, which is the contract's
            // shape and not an error.
            Ok(reply) => (
                Exchange {
                    ordinal: method,
                    status: reply.status as u32,
                    answered: true,
                    detail: 0,
                },
                reply.status,
                0,
                [0u8; 64],
            ),
            Err(_) => (unanswered(method), InputError::Protocol, 0, [0u8; 64]),
        },
    }
}

/// The whole program.
fn run() -> u64 {
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut found = REPORT_TAG;

    // Describe first: every rule about optional methods is relative to what the
    // driver said about itself, so a suite run without it would be judging a
    // driver against an assumption.
    let request = control_request(InputPowerState::Active);
    if encode(&request, &mut msg_buf[..InputControlRequest::WIRE_SIZE]).is_err() {
        return fail(0xf2, 0);
    }
    if let Err(code) = call(&mut msg_buf, DESCRIBE) {
        return code;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
    let described: InputDescribeReply = match decode(&bytes[..InputDescribeReply::WIRE_SIZE]) {
        Ok(described) => described,
        Err(_) => return fail(0xf2, 1),
    };

    let mut transcript = [unanswered(0); TRANSCRIPT_LEN];
    transcript[0] = Exchange {
        ordinal: DESCRIBE,
        status: described.status as u32,
        answered: true,
        detail: 0,
    };

    // A poll. An idle keyboard answers `NO_REPORT`, and that is a pass.
    let (exchange, status, _, _) = report_call(&mut msg_buf, POLL);
    transcript[1] = exchange;
    if status == InputError::NoReport {
        found |= REPORT_IDLE_IS_FINE;
    }

    // `SetReport`, which this driver does not advertise — so the rule that says
    // an unadvertised method must answer `NOT_SUPPORTED` is reachable.
    let (exchange, _, _, _) = report_call(&mut msg_buf, SET_REPORT);
    transcript[2] = exchange;

    // `GetReport`, which it does advertise — so the converse rule is reachable
    // too, on the same transcript.
    let (exchange, status, length, _) = report_call(&mut msg_buf, GET_REPORT);
    transcript[3] = exchange;
    if status == InputError::Ok && length > 0 {
        found |= REPORT_READ_THROUGH_RELAY;
    }

    transcript[4] = control(&mut msg_buf, RESET, InputPowerState::Active);
    transcript[5] = control(&mut msg_buf, SET_POWER, InputPowerState::Idle);
    // A vendor ordinal with no namespace negotiated. It must be refused, and
    // refused with `PROTOCOL` rather than ignored.
    transcript[6] = control(&mut msg_buf, VENDOR_ORDINAL_BASE, InputPowerState::Active);

    let report = check(
        &INPUT,
        &Described {
            contract_version: described.contract_version,
            features: described.features,
            vendor: described.vendor_namespace,
        },
        &transcript,
    );
    if report.is_complete() {
        found |= REPORT_CONFORMANT;
    }
    // What was found, and nothing inferred: a checker outside this program
    // compares the bits against what it expects, so a client that quietly
    // reported success would be caught by the value rather than believed.
    found | u64::from(described.protocol)
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, value, 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    exit_reporting(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
