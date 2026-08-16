// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **GPIO client**: a `no_std` Rust program that asks for one line
//! and waits for it.
//!
//! It holds no device, maps nothing, and has no idea what a PL061 is. What it
//! has is a channel to a driver and, after `WatchLine`, **a capability to one
//! line's interrupt** — which it can wait on and cannot raise.
//!
//! Two of these run in the boot check, watching different lines, and only one
//! of them is meant to wake. The one that does not is the load-bearing half:
//! the driver reads a status register and decides whose edge it was, and a
//! driver that got that wrong — or a mechanism that broadcast instead of
//! granting — would wake both. A client cannot tell the difference from the
//! inside, which is exactly why the check watches from outside.
//!
//! Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
//! ("GPIO And Pin Control")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use gpio_controller::{
    GpioConfigRequest, GpioControlReply, GpioControlRequest, GpioController, GpioDescribeReply,
    GpioDirection, GpioError, GpioLineRequest, GpioPowerState, GpioTrigger,
};
use tessera_isl_runtime::{decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_PORT_WAIT: u64 = 18;

/// The one capability boot installs: the driver's service endpoint.
const DRIVER_ENDPOINT_HANDLE: u64 = 0;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// A port event record, and where the source sits in it: `size`, `version` and
/// `flags` come first, so the field that says *what fired* is sixteen bytes in.
const EVENT_RECORD_LEN: usize = 32;
const EVENT_SOURCE: usize = 16;

/// What this program reports: a tag, the line it was watching, and what it saw.
///
/// The line is in the value so the two clients' reports cannot be confused for
/// each other — which matters, because the whole point of the check is that one
/// of them speaks and the other does not.
const REPORT_TAG: u64 = 0x91 << 56;
/// The edge arrived, and the event named the line this client asked for.
const REPORT_WOKEN: u64 = 1 << 32;
/// The driver handed over an interrupt object at all.
const REPORT_GRANTED: u64 = 1 << 33;

/// Encodes a `ChannelMsgArgs` naming a method, with somewhere for the kernel to
/// report a handle it installed.
fn channel_args(
    buf_ptr: u64,
    method: u32,
    installed: u64,
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
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: installed,
        installed_cap: if installed == 0 { 0 } else { 1 },
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0xf0, 0xe)),
    }
}

/// One call to the driver. The reply lands back in the same buffer.
fn call(buf: &mut [u8; MSG_BUF_LEN], method: u32, installed: u64) -> Result<(), u64> {
    let args = channel_args(buf.as_ptr() as u64, method, installed)?;
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

/// Reads a status out of a control reply.
fn control_status(buf: &[u8; MSG_BUF_LEN]) -> Result<GpioError, u64> {
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(buf);
    match decode::<GpioControlReply>(&bytes[..GpioControlReply::WIRE_SIZE]) {
        Ok(reply) => Ok(reply.status),
        Err(_) => Err(fail(0xf2, 0)),
    }
}

/// Reads back a u32 the kernel wrote into one of this program's buffers.
fn kernel_u32(bytes: &[u8], at: usize) -> u32 {
    let mut out = [0u8; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        if at + i >= bytes.len() {
            return 0;
        }
        // SAFETY: a bounds-checked byte of this program's own stack buffer;
        // volatile because the kernel wrote it.
        *slot = unsafe { core::ptr::read_volatile(&bytes[at + i]) };
    }
    u32::from_le_bytes(out)
}

/// The whole program. `line` is the one this client is interested in.
fn run(line: u32) -> u64 {
    let mut found = REPORT_TAG | (u64::from(line) << 40);
    let mut msg_buf = [0u8; MSG_BUF_LEN];

    // Describe first: what a driver can do is its to say, and asking for an
    // interrupt from one that has none would be waiting for something nobody
    // promised.
    let request = GpioControlRequest {
        size: GpioControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: GpioPowerState::Active,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..GpioControlRequest::WIRE_SIZE]).is_err() {
        return fail(0xf3, 0);
    }
    if let Err(code) = call(&mut msg_buf, GpioController::DESCRIBE, 0) {
        return code;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
    let described: GpioDescribeReply = match decode(&bytes[..GpioDescribeReply::WIRE_SIZE]) {
        Ok(described) => described,
        Err(_) => return fail(0xf3, 1),
    };
    if described.status != GpioError::Ok || line >= described.line_count {
        return fail(0xf3, 2);
    }
    // INTERRUPTS, which is what makes the wait below meaningful.
    if described.features & 0x2 == 0 {
        return fail(0xf3, 3);
    }

    // Claim it as an input that interrupts on a rising edge.
    let configure = GpioConfigRequest {
        size: GpioConfigRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        line,
        direction: GpioDirection::Input,
        trigger: GpioTrigger::RisingEdge,
        reserved: 0,
    };
    if encode(&configure, &mut msg_buf[..GpioConfigRequest::WIRE_SIZE]).is_err() {
        return fail(0xf4, 0);
    }
    if let Err(code) = call(&mut msg_buf, GpioController::CONFIGURE_LINE, 0) {
        return code;
    }
    match control_status(&msg_buf) {
        Ok(GpioError::Ok) => {}
        Ok(status) => return fail(0xf4, status as u64),
        Err(code) => return code,
    }

    // Ask to watch it. The reply carries the line's interrupt object, and the
    // kernel reports where it installed it — the handle number cannot be known
    // any other way, because a transfer bumps the generation of the slot it
    // lands in.
    let watch = GpioLineRequest {
        size: GpioLineRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        line,
        reserved: 0,
    };
    if encode(&watch, &mut msg_buf[..GpioLineRequest::WIRE_SIZE]).is_err() {
        return fail(0xf5, 0);
    }
    let installed = [0u32; 1];
    if let Err(code) = call(
        &mut msg_buf,
        GpioController::WATCH_LINE,
        installed.as_ptr() as u64,
    ) {
        return code;
    }
    match control_status(&msg_buf) {
        Ok(GpioError::Ok) => {}
        Ok(status) => return fail(0xf5, status as u64),
        Err(code) => return code,
    }
    // SAFETY: the kernel wrote this slot while installing the transferred
    // capability during the call above; volatile only forbids the compiler from
    // assuming the zero it stored is still there.
    let port = unsafe { core::ptr::read_volatile(&installed[0]) };
    if port == 0 || port == u32::MAX {
        return fail(0xf5, 0x100);
    }
    found |= REPORT_GRANTED;

    // And wait. Nothing else in this program can wake it: it holds one port,
    // for one line, with the right to be woken and not to do the waking.
    let mut event = [0u8; EVENT_RECORD_LEN];
    let waited = syscall2(SYS_PORT_WAIT, u64::from(port), event.as_mut_ptr() as u64);
    if waited < 0 {
        return fail(0xf6, (-waited) as u64);
    }
    // The event says which source fired, and this client checks it: being woken
    // is not the same as being woken by the line it asked for, and a client
    // that reported the first would pass against a driver that woke everybody.
    if kernel_u32(&event, EVENT_SOURCE) == line {
        found |= REPORT_WOKEN;
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

/// Entry point; the startup argument is the line to watch.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    exit_reporting(run(arg as u32))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
