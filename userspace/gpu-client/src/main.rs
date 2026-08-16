// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **display client**: a `no_std` Rust program that draws a picture
//! chosen so that being wrong looks wrong.
//!
//! **The pattern is the point.** Every pixel is a function of where it is:
//! red rises with the column and green with the row, so a wrong stride, a
//! transposed pair of axes, a wrong origin and a wrong byte order each produce
//! a *different* wrong picture. A flat colour would come out identical under
//! all four.
//!
//! It also runs the class conformance suite over the driver, as `blk-client`,
//! `input-client` and `snd-client` do — the same seven rules, a seventh
//! contract.
//!
//! Normative: docs/drivers/03-graphics-display-media-sensors-ai.md
//! ("Display And Graphics")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use display_output::{
    DisplayBlitReply, DisplayBlitRequest, DisplayControlReply, DisplayControlRequest,
    DisplayDescribeReply, DisplayError, DisplayFillRequest, DisplayOutput, DisplayPowerState,
    DisplayRectRequest,
};
use tessera_class_conformance::{DISPLAY, Described, Exchange, check};
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

/// Pixels one `Blit` carries.
const BLIT_PIXELS: u32 = 16;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// Exchanges the conformance transcript holds.
const TRANSCRIPT_LEN: usize = 8;

/// What this program reports.
const REPORT_TAG: u64 = 0xd0 << 56;
/// The conformance suite came back complete.
const REPORT_CONFORMANT: u64 = 1 << 32;
/// The whole framebuffer was written and shown.
const REPORT_DREW: u64 = 1 << 33;
/// A blit past the edge was refused rather than clipped.
const REPORT_REFUSED: u64 = 1 << 34;

/// The colour of the pixel at `(x, y)`.
///
/// **Chosen so that being wrong looks wrong.** Red rises with the column and
/// green with the row, so each of the four ways a framebuffer is commonly
/// mis-addressed produces a different picture — and the boot check can name a
/// corner and say what should be there.
fn colour_at(x: u32, y: u32) -> u32 {
    0xff00_0000 | ((x * 4) << 16) | ((y * 4) << 8) | 0x40
}

/// Writes a `ChannelMsgArgs` naming a method.
fn channel_args(buf_ptr: u64, method: u32) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0xd0, 0xe)),
    }
}

/// One call to the driver. The reply lands back in the same buffer.
fn call(buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Result<(), u64> {
    let args = channel_args(buf.as_ptr() as u64, method)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        DRIVER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xd1, (-n) as u64));
    }
    Ok(())
}

/// An exchange the driver did not answer at all.
fn unanswered(ordinal: u32) -> Exchange {
    Exchange {
        ordinal,
        status: 0,
        answered: false,
        detail: 0,
    }
}

/// Calls a method taking a control request.
fn control(msg_buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Exchange {
    let request = DisplayControlRequest {
        size: DisplayControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: DisplayPowerState::Active,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..DisplayControlRequest::WIRE_SIZE]).is_err() {
        return unanswered(method);
    }
    if call(msg_buf, method).is_err() {
        return unanswered(method);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<DisplayControlReply>(&bytes[..DisplayControlReply::WIRE_SIZE]) {
        Ok(reply) => Exchange {
            ordinal: method,
            status: reply.status as u32,
            answered: true,
            detail: reply.state as u32,
        },
        Err(_) => unanswered(method),
    }
}

/// Writes one run of pixels.
fn blit(msg_buf: &mut [u8; MSG_BUF_LEN], x: u32, y: u32, count: u32) -> Option<DisplayBlitReply> {
    let mut pixels = [0u8; 64];
    for index in 0..count.min(BLIT_PIXELS) {
        let at = (index * 4) as usize;
        pixels[at..at + 4].copy_from_slice(&colour_at(x + index, y).to_le_bytes());
    }
    let request = DisplayBlitRequest {
        size: DisplayBlitRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        x,
        y,
        count,
        reserved: 0,
        pixels,
    };
    if encode(&request, &mut msg_buf[..DisplayBlitRequest::WIRE_SIZE]).is_err() {
        return None;
    }
    if call(msg_buf, DisplayOutput::BLIT).is_err() {
        return None;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    decode::<DisplayBlitReply>(&bytes[..DisplayBlitReply::WIRE_SIZE]).ok()
}

/// Asks for a rectangle to be shown.
fn flush(msg_buf: &mut [u8; MSG_BUF_LEN], width: u32, height: u32) -> Exchange {
    let request = DisplayRectRequest {
        size: DisplayRectRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        x: 0,
        y: 0,
        width,
        height,
    };
    if encode(&request, &mut msg_buf[..DisplayRectRequest::WIRE_SIZE]).is_err() {
        return unanswered(DisplayOutput::FLUSH);
    }
    if call(msg_buf, DisplayOutput::FLUSH).is_err() {
        return unanswered(DisplayOutput::FLUSH);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<DisplayControlReply>(&bytes[..DisplayControlReply::WIRE_SIZE]) {
        Ok(reply) => Exchange {
            ordinal: DisplayOutput::FLUSH,
            status: reply.status as u32,
            answered: true,
            detail: 0,
        },
        Err(_) => unanswered(DisplayOutput::FLUSH),
    }
}

/// The whole program.
fn run() -> u64 {
    let mut found = REPORT_TAG;
    let mut msg_buf = [0u8; MSG_BUF_LEN];

    // The mode there is, asked before anything is drawn.
    let request = DisplayControlRequest {
        size: DisplayControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: DisplayPowerState::Active,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..DisplayControlRequest::WIRE_SIZE]).is_err() {
        return fail(0xd2, 0);
    }
    if let Err(code) = call(&mut msg_buf, DisplayOutput::DESCRIBE) {
        return code;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
    let described: DisplayDescribeReply = match decode(&bytes[..DisplayDescribeReply::WIRE_SIZE]) {
        Ok(described) => described,
        Err(_) => return fail(0xd2, 1),
    };
    if described.status != DisplayError::Ok || described.width == 0 || described.height == 0 {
        return fail(0xd2, 2);
    }
    let mut transcript = [unanswered(0); TRANSCRIPT_LEN];
    transcript[0] = Exchange {
        ordinal: DisplayOutput::DESCRIBE,
        status: described.status as u32,
        answered: true,
        detail: 0,
    };

    // **Refused rather than clipped**, asked for before the picture that works.
    // A client whose run was quietly trimmed would see a picture it did not
    // compose and have nothing to check.
    let Some(refused) = blit(&mut msg_buf, described.width - 1, 0, BLIT_PIXELS) else {
        return fail(0xd3, 0);
    };
    if refused.status == DisplayError::OutOfBounds && refused.written == 0 {
        found |= REPORT_REFUSED;
    }
    let Some(refused) = blit(&mut msg_buf, 0, described.height, BLIT_PIXELS) else {
        return fail(0xd3, 1);
    };
    if refused.status != DisplayError::OutOfBounds {
        return fail(0xd3, 2);
    }

    // **The reset comes first**, because it clears the glass and shows the
    // clearing — done after the picture it would erase it, and the picture has
    // to survive until somebody outside looks at it.
    transcript[7] = control(&mut msg_buf, DisplayOutput::RESET);

    // Every pixel, a run at a time.
    let mut wrote = 0u32;
    for y in 0..described.height {
        let mut x = 0;
        while x < described.width {
            let count = BLIT_PIXELS.min(described.width - x);
            let Some(reply) = blit(&mut msg_buf, x, y, count) else {
                return fail(0xd4, 0);
            };
            if reply.status != DisplayError::Ok {
                return fail(0xd4, reply.status as u64);
            }
            // `written` is authoritative: a client that assumed the whole run
            // landed would draw the rest of its row one place to the left.
            x += reply.written;
            wrote += reply.written;
            if reply.written == 0 {
                return fail(0xd4, 1);
            }
        }
    }
    transcript[1] = Exchange {
        ordinal: DisplayOutput::BLIT,
        status: DisplayError::Ok as u32,
        answered: true,
        detail: 0,
    };

    // **And now the only call with an effect outside the machine.** Everything
    // above changed a framebuffer nobody can see.
    transcript[2] = flush(&mut msg_buf, described.width, described.height);
    if transcript[2].status == DisplayError::Ok as u32
        && wrote == described.width * described.height
    {
        found |= REPORT_DREW;
    }

    // The optional this driver has, the one it does not, a reset and a vendor
    // ordinal nobody negotiated.
    let fill = DisplayFillRequest {
        size: DisplayFillRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        x: 0,
        y: 0,
        width: 1,
        height: 1,
        colour: colour_at(0, 0),
        reserved: 0,
    };
    transcript[3] = if encode(&fill, &mut msg_buf[..DisplayFillRequest::WIRE_SIZE]).is_ok()
        && call(&mut msg_buf, DisplayOutput::FILL).is_ok()
    {
        let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
        match decode::<DisplayControlReply>(&bytes[..DisplayControlReply::WIRE_SIZE]) {
            Ok(reply) => Exchange {
                ordinal: DisplayOutput::FILL,
                status: reply.status as u32,
                answered: true,
                detail: 0,
            },
            Err(_) => unanswered(DisplayOutput::FILL),
        }
    } else {
        unanswered(DisplayOutput::FILL)
    };
    transcript[4] = control(&mut msg_buf, DisplayOutput::SET_CURSOR);
    transcript[5] = control(&mut msg_buf, DisplayOutput::SET_POWER);
    transcript[6] = control(&mut msg_buf, VENDOR_ORDINAL_BASE);
    // Nothing after the flush shows anything: `Fill` writes into the
    // framebuffer and does not put it on the glass, and the rest move no
    // pixels at all. What is on the screen is what was flushed.

    let report = check(
        &DISPLAY,
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
    found
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
