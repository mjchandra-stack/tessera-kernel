// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 device manager: the piece that decides which driver gets which
//! device.
//!
//! # What this changes
//!
//! Before this program, a driver knew its device by a compiled-in handle
//! number — `BLK_DEVICE_HANDLE = 0` — that the boot glue happened to install
//! in that slot. That is not binding; it is a constant shared between two
//! files, and it fails the moment the machine has its devices in a different
//! order, or two of a kind, or one fewer than expected. The driver was not
//! bound to a device, it was bound to a *convention*.
//!
//! Now boot grants **this** program a capability to every device it
//! discovered and nothing else grants any driver anything. A driver names a
//! class over a channel and is handed a capability to some device of that
//! class — or told there is none. It never learns a device's address, its
//! interrupt, or its position in the machine, because it does not need to:
//! all three live inside the capability, and the kernel reads them from there
//! when the driver maps it.
//!
//! # Enumeration is why this is a program and not a table
//!
//! The manager classifies devices by **probing** them: every virtio-mmio
//! transport on this machine has the same device-tree `compatible` string,
//! and what kind of device it is lives in a register (`device_id` at offset
//! 8). So the manager maps each device it was granted, reads two registers,
//! and records what it found. There is no way to learn this without touching
//! the device, on this bus or on PCIe, which is why enumeration is a job for
//! something holding capabilities rather than a constant in a header.
//!
//! To classify a device the manager must map it, which would leave this
//! program more privileged than the design wants — it has mapped every
//! device's registers — except that the kernel takes the mapping back. A
//! capability transferred out of a handle table takes its register window
//! with it, so the probe mappings made here are gone the moment each device
//! is handed on. Nothing in this program does the revoking, and nothing in it
//! could decline to.
//!
//! # Exclusivity is not a flag
//!
//! Nothing here marks a device "bound". A handle transferred in a reply is
//! removed from this program's table by the kernel, so a device can be handed
//! out exactly once; a second request for the same class finds the next
//! unbound device or fails. The framework's one-driver-per-device rule is a
//! property of capability conservation, and this program could not violate it
//! if it tried.
//!
//! Normative: docs/hardware/03-component-interaction-model.md,
//! docs/api/01-system-call-interface.md,
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels")

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
const SYS_CHANNEL_RECV: u64 = 13;
/// **Continue**, not plain `ChannelReply`. `reply` hands off to the caller and
/// leaves the replier Blocked, which is correct only for a server whose next
/// wake is the next call on that same endpoint — because `call` wakes a peer
/// only if it registered itself with `receive`. A server that replies and then
/// loops back to `recv` is Blocked without being a registered receiver, so the
/// *second* request deadlocks: the caller finds no waiting receiver and blocks
/// too, and neither side ever runs again. `ChannelReplyContinue` enqueues the
/// reply, unblocks the caller, and leaves this program runnable to reach its
/// own `recv`.
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_MAP_DEVICE: u64 = 23;

/// The service endpoint boot installs first, so it is always handle 0. Device
/// capabilities follow at 1..=count, and the count arrives as this program's
/// startup argument — the whole of its bootstrap contract with boot.
const SERVICE_ENDPOINT_HANDLE: u64 = 0;
const FIRST_DEVICE_HANDLE: u32 = 1;

/// Most devices this manager will enumerate. The `virt` machine lays out 32
/// virtio-mmio transports; boot grants only the ones it found populated.
const MAX_DEVICES: usize = 8;

/// Where each device's registers are mapped while being probed. One window
/// per device so a later probe never has to tear down an earlier one.
const PROBE_VA_BASE: u64 = 0x0000_1000_0080_0000;
const PROBE_VA_STRIDE: u64 = 0x1_0000;

/// virtio-mmio register offsets and the values that identify a transport.
const REG_MAGIC: usize = 0x000;
const REG_DEVICE_ID: usize = 0x008;
const VIRTIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_ID_NET: u32 = 1;
const VIRTIO_ID_BLOCK: u32 = 2;

/// Failure codes this program reports through `DebugWrite` before exiting.
/// Stages: 0x01 probe map, 0x02 magic mismatch, 0x03 recv, 0x04 request
/// decode, 0x05 reply encode, 0x06 reply, 0x07 args encode, 0xff panic.
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

/// Reports `code` and ends this process. Never returns.
fn die(code: u64) -> ! {
    syscall2(SYS_DEBUG_WRITE, code, 0);
    syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Reads a device register the manager mapped for probing.
fn read_register(base: u64, offset: usize) -> u32 {
    // SAFETY: `base` is a register base MapDevice granted, and both offsets
    // used here are inside the virtio-mmio header the capability covers.
    unsafe { ((base as usize + offset) as *const u32).read_volatile() }
}

/// Maps the device named by `handle` so its identifying registers can be read.
fn map_device(handle: u32, vaddr: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x01, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x01, (-base) as u64));
    }
    Ok(base as u64)
}

/// A device this manager holds a capability to, and what probing said it is.
#[derive(Clone, Copy)]
struct Device {
    handle: u32,
    /// Where this device's registers are mapped while it is held. The window
    /// is revoked by the kernel when the capability is handed on, so a
    /// returned device is re-probed at the same address it used before.
    probe_va: u64,
    class: DeviceClass,
    /// Cleared once the capability has been transferred to a driver. Tracked
    /// only so the manager can skip it without asking the kernel; the kernel's
    /// `take` is what actually makes the transfer exclusive.
    held: bool,
}

/// Encodes a `ChannelMsgArgs` describing the message buffer, optionally
/// carrying one handle to transfer.
fn channel_args(
    buf_ptr: u64,
    buf_len: u64,
    handle_ptr: u64,
    handle_count: u64,
    installed_ptr: u64,
    installed_cap: u64,
) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: buf_len,
        handles_ptr: handle_ptr,
        handle_count,
        installed_ptr,
        installed_cap,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0x07, 0xe)),
    }
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

/// Probes every granted device and records what it is.
fn enumerate(count: usize) -> Result<[Option<Device>; MAX_DEVICES], u64> {
    let mut devices = [None; MAX_DEVICES];
    for (index, slot) in devices.iter_mut().enumerate().take(count) {
        let handle = FIRST_DEVICE_HANDLE + index as u32;
        let base = map_device(handle, PROBE_VA_BASE + index as u64 * PROBE_VA_STRIDE)?;

        // A transport that does not identify itself is not something to guess
        // about: report rather than record a class nobody verified.
        let magic = read_register(base, REG_MAGIC);
        if magic != VIRTIO_MAGIC {
            return Err(fail(0x02, u64::from(magic & 0xffff)));
        }

        let class = match read_register(base, REG_DEVICE_ID) {
            VIRTIO_ID_BLOCK => DeviceClass::Block,
            VIRTIO_ID_NET => DeviceClass::Network,
            // A device the manager cannot classify is still recorded — it is
            // real, it is held, and it is simply never matched. Dropping it
            // silently would make the inventory a lie.
            _ => DeviceClass::Unknown,
        };
        *slot = Some(Device {
            handle,
            probe_va: PROBE_VA_BASE + index as u64 * PROBE_VA_STRIDE,
            class,
            held: true,
        });
    }
    Ok(devices)
}

/// Serves bind requests until the process is reaped. Never returns normally.
fn serve(devices: &mut [Option<Device>; MAX_DEVICES]) -> ! {
    // One buffer serves as both the request destination and the reply source
    // — the symmetric call-buffer convention the block protocol uses.
    let mut message = [0u8; 32];
    // The handle to transfer lives in its own vector; handle values never
    // travel in the payload bytes (docs/api/03, "Wire Format").
    let mut transfer = [0u32; 1];

    loop {
        // The transfer vector doubles as an *output* buffer on a receive: if
        // this request carries a capability, the kernel writes back the handle
        // it installed. Without that the number could not be known — `take`
        // bumps the generation of the slot it vacates, so a device coming back
        // to this table arrives with a different handle value than it left
        // with, and any remembered number is stale by construction.
        transfer[0] = 0;
        let args = match channel_args(
            message.as_ptr() as u64,
            message.len() as u64,
            // Nothing is transferred *out* on a receive; the vector below is
            // where the kernel reports what came in.
            0,
            0,
            transfer.as_ptr() as u64,
            1,
        ) {
            Ok(args) => args,
            Err(code) => die(code),
        };
        let received = syscall2(
            SYS_CHANNEL_RECV,
            args.as_ptr() as u64,
            SERVICE_ENDPOINT_HANDLE,
        );
        if received < 0 {
            die(fail(0x03, (-received) as u64));
        }

        // SAFETY: the kernel wrote this slot while installing any transferred
        // capability during the recv above; volatile only forbids the compiler
        // from assuming the zero it stored is still there.
        let returned = unsafe { core::ptr::read_volatile(&transfer[0]) };

        // A return, rather than an acquisition. The capability is already in
        // this program's table — the kernel installed it out of the message's
        // handle vector before this code ran — so the work is to find *which*
        // record it belongs to and make it available again.
        //
        // Which handle it landed on is not reported anywhere, so it is
        // deduced: the kernel installs at the lowest free slot, and the slots
        // this program has freed are exactly the ones it gave away. The lowest
        // handle among the records currently not held is therefore where the
        // return arrived. That deduction is sound only because this program is
        // the sole owner of its own table, and it is the same handle-discovery
        // gap the framework already carries — a returned handle should name
        // itself rather than be inferred from an allocation policy.
        // A message that carried a capability *is* a return — the kernel
        // reports the handle it installed, and nothing else in this protocol
        // hands this program a device. That is a stronger discriminator than a
        // flag in the body: a body can be forged by any sender, an installed
        // capability cannot. It also lets the **kernel** return a dead
        // driver's devices without knowing this protocol at all, which is
        // exactly what makes reclaim-on-death possible.
        if returned != 0 {
            let reclaimed = devices
                .iter_mut()
                .flatten()
                .find(|device| !device.held);
            match reclaimed {
                Some(device) => {
                    device.handle = returned;
                    // Re-probe rather than trust the old classification: the
                    // window was revoked when the capability left, so this both
                    // re-establishes the mapping and re-verifies that what came
                    // back is the device that went out.
                    match map_device(device.handle, device.probe_va) {
                        Ok(base) if read_register(base, REG_MAGIC) == VIRTIO_MAGIC => {
                            device.held = true;
                        }
                        // Something came back that is not the device that left.
                        _ => die(fail(0x08, 0x1)),
                    }
                }
                // Nothing is outstanding, so nothing can be returned. Accepting
                // would grow the inventory past the machine.
                None => die(fail(0x08, 0x2)),
            }
            // A return is a notification, not a request: the supervisor that
            // sends it is reclaiming on behalf of a driver that is already
            // gone, and is not waiting on an answer. Replying would queue a
            // message on the endpoint that the next caller's `call` would
            // dequeue as *its* reply — so the honest thing is to say nothing
            // and let a bad return kill this program instead.
            continue;
        }

        let bytes = read_kernel_filled::<{ BindRequest::WIRE_SIZE }>(&message);
        let request: BindRequest = match decode(&bytes) {
            Ok(request) => request,
            Err(_) => die(fail(0x04, 0xd)),
        };

        // Match: the first held device of the requested class. `Unknown` is
        // never matched, so a driver cannot acquire a device by asking for the
        // class the manager uses to mean "I could not tell".
        let matched = if request.class == DeviceClass::Unknown {
            None
        } else {
            devices.iter_mut().flatten().find(|device| {
                device.held && device.class == request.class
            })
        };

        let (status, class, count) = match matched {
            Some(device) => {
                transfer[0] = device.handle;
                // The class reported is the one *probing* found, not the one
                // the request asked for. They agree by construction of the
                // match above — which is exactly why echoing the request would
                // make the driver's cross-check vacuous, and echoing the
                // device keeps it meaning something if the match ever changes.
                let bound = device.class;
                // Marked before the reply, because after it the handle is gone
                // from this program's table and the number would name nothing.
                device.held = false;
                (0u32, bound, 1u64)
            }
            None => (1u32, DeviceClass::Unknown, 0u64),
        };

        let reply = BindReply {
            size: BindReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status,
            class,
        };
        if encode(&reply, &mut message).is_err() {
            die(fail(0x05, 0xe));
        }

        let args = match channel_args(
            message.as_ptr() as u64,
            BindReply::WIRE_SIZE as u64,
            transfer.as_ptr() as u64,
            count,
            0,
            0,
        ) {
            Ok(args) => args,
            Err(code) => die(code),
        };
        let replied = syscall2(
            SYS_CHANNEL_REPLY_CONTINUE,
            args.as_ptr() as u64,
            SERVICE_ENDPOINT_HANDLE,
        );
        if replied < 0 {
            die(fail(0x06, (-replied) as u64));
        }
    }
}

/// Entry point. `count` is the number of device capabilities boot installed
/// at handles 1..=count — this program's entire bootstrap contract, and the
/// only thing it is told rather than discovers.
///
/// # Safety
///
/// The unmangled `_start` symbol is the ELF entry the linker script names and
/// the kernel loader jumps to, with the startup argument in `x0`.
#[unsafe(no_mangle)]
extern "C" fn _start(count: u64) -> ! {
    let count = (count as usize).min(MAX_DEVICES);
    match enumerate(count) {
        Ok(mut devices) => serve(&mut devices),
        Err(code) => die(code),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    die(fail(0xff, 0))
}
