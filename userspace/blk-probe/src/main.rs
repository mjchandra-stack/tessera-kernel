// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A minimal block driver, existing to be killed and replaced.
//!
//! It does the smallest thing a driver of a class does: asks the device
//! manager for a `Block` device, maps the capability it is handed, reads the
//! transport's identifying register, and reports what it found. It runs
//! twice in one boot — once as the driver that dies, and once as the driver
//! that takes over — and the point of the second run is that it acquires the
//! *same physical device* through the same protocol, with nothing carried
//! over from the first.
//!
//! Why a separate program rather than the device host: the host is a resident
//! service with two devices, an interrupt port, a select loop and clients. A
//! restart proof wants the opposite — something that starts, takes a device,
//! and stops — so the thing under test is the handover and not the driver.
//!
//! Its startup argument is the incarnation number, which it folds into its
//! report so the two runs are distinguishable in the sink rather than being
//! two identical values that could equally be one value written twice.
//!
//! Normative: docs/hardware/03-component-interaction-model.md,
//! docs/kernel/05-jobs-containment-and-resource-control.md ("failure model")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use device_abi::MapDeviceArgs;
use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{HandleRef, decode, encode};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_MAP_DEVICE: u64 = 23;

/// The bind channel boot installs first, so it is always handle 0 — this
/// program's whole bootstrap contract.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;


/// Where the device's registers are mapped.
const MMIO_VA: u64 = 0x0000_1000_0090_0000;

const REG_MAGIC: usize = 0x000;
const VIRTIO_MAGIC: u32 = 0x7472_6976;

/// Failure codes reported through `DebugWrite` before exiting. Stages: 0x50
/// bind, 0x51 map, 0x52 magic mismatch, 0x53 args encode, 0xff panic.
const fn fail(stage: u64, cause: u64) -> u64 {
    0xdead_0000_0000_0000 | (stage << 16) | (cause & 0xffff)
}

/// One syscall: `x8` = number, `x0`/`x1` = args, result in `x0`.
fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    // SAFETY: the svc traps to the kernel dispatcher, which restores every GPR
    // except x0 (the trap frame is saved/restored whole); only x0 is written
    // back, declared via inout. No memory is touched by the instruction.
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

/// Reads bytes the **kernel** wrote into a buffer during a preceding syscall,
/// via volatile loads — making the cross-boundary write visible to the
/// compiler regardless of its alias analysis of this never-Rust-mutated local.
fn read_kernel_filled<const N: usize>(buf: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: `&buf[i]` is a bounds-checked, initialized byte; volatile
        // only forbids the compiler from assuming a cached value.
        unsafe { *slot = core::ptr::read_volatile(&buf[i]) };
    }
    out
}

/// Asks the manager for a block device, returning the handle the capability
/// was installed at.
///
/// The handle is **read back**, not assumed. A handle is an index and a
/// generation, and a device that has been through another process's table
/// comes back with a different value than it left with — so a driver that
/// hard-coded "my device is handle 1" would be right exactly once. The
/// transfer vector doubles as the kernel's report of what it installed.
fn bind() -> Result<u32, u64> {
    let mut message = [0u8; 32];
    let mut installed = [0u32; 1];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Block,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0x53, 0xe));
    }
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: message.as_ptr() as u64,
        inline_len: message.len() as u64,
        handles_ptr: 0,
        handle_count: 0,
        // Transfer nothing, but ask which handle the capability lands on —
        // the pair a call could not express before the descriptor grew.
        installed_ptr: installed.as_ptr() as u64,
        installed_cap: 1,
    };
    let mut abuf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut abuf).is_err() {
        return Err(fail(0x53, 0xe));
    }
    let n = syscall2(SYS_CHANNEL_CALL, abuf.as_ptr() as u64, MANAGER_ENDPOINT_HANDLE);
    if n < 0 {
        return Err(fail(0x50, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x50, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0x50, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Block {
        return Err(fail(0x50, 0x200));
    }
    // SAFETY: the kernel wrote this slot while installing the transferred
    // capability during the call above; volatile only forbids the compiler
    // from assuming the zero it stored is still there.
    Ok(unsafe { core::ptr::read_volatile(&installed[0]) })
}

/// Maps the bound device and returns its identifying register.
fn probe(device: u32) -> Result<u32, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        reserved: 0,
        vaddr: MMIO_VA,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x53, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x51, (-base) as u64));
    }
    // SAFETY: `base` is the register base MapDevice granted from the
    // capability the manager handed over; the magic is the first word of the
    // virtio-mmio header the capability covers.
    let magic = unsafe { ((base as usize + REG_MAGIC) as *const u32).read_volatile() };
    if magic != VIRTIO_MAGIC {
        return Err(fail(0x52, u64::from(magic & 0xffff)));
    }
    Ok(magic)
}

/// Entry. `incarnation` distinguishes the driver that dies from the one that
/// replaces it; it is folded into the report so the two runs cannot be
/// mistaken for one.
///
/// # Safety
///
/// The unmangled `_start` symbol is the ELF entry the linker script names and
/// the kernel loader jumps to, with the startup argument in `x0`.
#[unsafe(no_mangle)]
extern "C" fn _start(incarnation: u64) -> ! {
    let report = match bind().and_then(probe) {
        Ok(magic) => u64::from(magic).rotate_left((incarnation as u32 % 64) * 8),
        Err(code) => code,
    };
    syscall2(SYS_DEBUG_WRITE, report, 0);
    syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    syscall2(SYS_DEBUG_WRITE, fail(0xff, 0), 0);
    syscall2(SYS_PROCESS_EXIT, 1, 0);
    loop {
        core::hint::spin_loop();
    }
}
