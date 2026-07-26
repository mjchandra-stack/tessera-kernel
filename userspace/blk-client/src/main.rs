// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 block-service client (build/README.md, D81/D82): a `no_std`
//! Rust user program that requests TWO sector reads from the resident ring-3
//! blk driver over a channel and verifies the returned bytes (sector 0 =
//! `TESSERAV`, sector 1 = `TESSERA2` on the test disk). It holds no device
//! or DMA capability at all — only a channel endpoint. Two instances run
//! per boot, distinguished by the spawn argument (`_start`'s `id` in `x0`).
//! The request/reply payload is the `tessera.driver.block` ISL protocol,
//! which the kernel transports opaquely; the call buffer is symmetric
//! (request out, reply back in).
//!
//! Reporting: one `DebugWrite` with either the disk magic rotated by the
//! client id (`DISK_MAGIC.rotate_left(8 * id)` — the check XORs both
//! clients' reports, so each is load-bearing and distinct) or a
//! `0xdead_...` failure code, then `ProcessExit`.
//!
//! Normative: docs/api/01-system-call-interface.md,
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{BlockReadReply, BlockReadRequest};
use channel_msg::ChannelMsgArgs;
use tessera_isl_runtime::{decode, encode};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;

/// The client's whole authority: its channel endpoint, at handle 0.
const ENDPOINT_HANDLE: u64 = 0;

/// The expected first 8 bytes of the two sectors this proof requests.
const DISK_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");
const SECTOR1_MAGIC: u64 = u64::from_le_bytes(*b"TESSERA2");

/// The symmetric call buffer: request source and reply destination, sized
/// for the larger of `BlockReadRequest` (24) and `BlockReadReply` (88).
const MSG_BUF_LEN: usize = 96;

/// A failure report: `0xdead << 48 | stage << 16 | cause`. Client stages sit
/// above the driver's: 0x11 request encode, 0x12 call error, 0x13 short
/// reply, 0x14 reply decode, 0x15 reply status, 0x16 magic mismatch, 0xff
/// panic.
const fn fail(stage: u64, cause: u64) -> u64 {
    0xdead_0000_0000_0000 | (stage << 16) | (cause & 0xffff)
}

/// One syscall: `x8` = number, `x0`/`x1` = args, result in `x0`.
fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    // SAFETY: the svc traps to the kernel dispatcher, which restores every
    // GPR except x0 (the trap frame is saved/restored whole); only x0 is
    // written back, declared via inout. No memory is touched by the
    // instruction itself.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inout("x0") arg0 => ret,
            in("x1") arg1,
            options(nostack),
        );
    }
    ret
}

/// Reads the first `N` bytes of a buffer the **kernel** filled during a
/// preceding syscall, via volatile loads — making the cross-boundary write
/// visible to the compiler regardless of its alias analysis of this
/// never-Rust-mutated local.
fn read_kernel_filled<const N: usize>(buf: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: `&buf[i]` is a bounds-checked, initialized byte; volatile
        // only forbids the compiler from assuming a cached value.
        unsafe { *slot = core::ptr::read_volatile(&buf[i]) };
    }
    out
}

/// One sector read over the channel: sends the request through the symmetric
/// call buffer, verifies the reply header/status, and checks the sector's
/// first 8 bytes against `expect`. Returns the failure report, or 0.
fn read_and_verify(msg_buf: &mut [u8; MSG_BUF_LEN], sector: u64, expect: u64) -> u64 {
    let request = BlockReadRequest {
        size: BlockReadRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        sector,
    };
    if encode(&request, &mut msg_buf[..BlockReadRequest::WIRE_SIZE]).is_err() {
        return fail(0x11, 0);
    }

    // The channel descriptor: inline_len covers the whole buffer, so the
    // request goes out padded and the 88-byte reply fits coming back.
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: msg_buf.as_ptr() as u64,
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: 0,
        handle_count: 0,
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut args_buf).is_err() {
        return fail(0x11, 1);
    }

    let n = syscall2(SYS_CHANNEL_CALL, args_buf.as_ptr() as u64, ENDPOINT_HANDLE);
    if n < 0 {
        return fail(0x12, (-n) as u64);
    }
    if (n as usize) < BlockReadReply::WIRE_SIZE {
        return fail(0x13, n as u64);
    }

    let reply_bytes = read_kernel_filled::<{ BlockReadReply::WIRE_SIZE }>(msg_buf);
    let reply = match decode::<BlockReadReply>(&reply_bytes) {
        Ok(reply) => reply,
        Err(_) => return fail(0x14, 0),
    };
    if reply.size != BlockReadReply::WIRE_SIZE as u32 || reply.version != 1 || reply.flags != 0 {
        return fail(0x14, 1);
    }
    if reply.status != 0 {
        return fail(0x15, reply.status as u64);
    }

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&reply.data[..8]);
    if u64::from_le_bytes(magic) != expect {
        return fail(0x16, sector);
    }
    0
}

/// Requests sectors 0 and 1 from the resident driver and verifies both.
/// Returns the report: the disk magic rotated by this client's id.
fn run(id: u64) -> u64 {
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let r = read_and_verify(&mut msg_buf, 0, DISK_MAGIC);
    if r != 0 {
        return r;
    }
    let r = read_and_verify(&mut msg_buf, 1, SECTOR1_MAGIC);
    if r != 0 {
        return r;
    }
    DISK_MAGIC.rotate_left(8 * id as u32)
}

/// Entry: the kernel's `spawn_user` set SP to the top of the mapped user
/// stack, so plain Rust runs from the first instruction.
// SAFETY: the unmangled `_start` symbol is the ELF entry the linker script
// names; nothing else in this single-binary program can collide with it.
#[unsafe(no_mangle)]
extern "C" fn _start(id: u64) -> ! {
    let report = run(id);
    let _ = syscall2(SYS_DEBUG_WRITE, report, 0);
    let code = u64::from(report != DISK_MAGIC.rotate_left(8 * id as u32));
    let _ = syscall2(SYS_PROCESS_EXIT, code, 0);
    // ProcessExit never returns; keep the type honest without UB.
    loop {
        core::hint::spin_loop();
    }
}

/// A panic must not hang the boot: report a distinct code and exit.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, fail(0xff, 0), 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 1, 0);
    loop {
        core::hint::spin_loop();
    }
}
