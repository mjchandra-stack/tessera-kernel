// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The RISC-V 64 block driver: a real `no_std` Rust program that runs in ring
//! 3 and reads a disk.
//!
//! Everything the port built over the last five milestones exists so that this
//! program can be ordinary. It holds a capability to a device and a port, and
//! from those it maps registers, allocates memory the device can address,
//! submits a request, and sleeps until the device says it is done. It contains
//! no privileged instruction and no platform constant: the register window
//! comes from `MapDevice`, the DMA buffers' device-visible addresses come from
//! `DmaAlloc`, and the interrupt line is never named at all — the driver waits
//! on a port and the kernel decides what wakes it.
//!
//! The transport itself is not here either. The handshake ordering and the
//! split-virtqueue layout live in `tessera-virtio`, which is host-tested
//! against a mock device and is used **unchanged** — the same crate the
//! AArch64 driver uses, and the same one the in-kernel proof used before
//! either existed. What this file adds is the part that genuinely cannot be
//! shared: the syscalls, and volatile access to a window the kernel mapped.
//!
//! Normative: docs/hardware/03-component-interaction-model.md,
//! docs/hardware/04-device-memory-and-unified-memory.md

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use device_abi::{DmaAllocArgs, IrqCompleteArgs, MapDeviceArgs};
use port_event::PortEventRecord;
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_virtio::{BLK_HEADER_LEN, Blk, Layout, Mmio, blk_read_header};

/// Syscall numbers — kcore `SyscallNumber` ordinals, the stable ABI.
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_PORT_WAIT: u64 = 18;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DMA_ALLOC: u64 = 24;
const SYS_IRQ_COMPLETE: u64 = 26;

/// The two capabilities boot grants, in install order — this program's whole
/// bootstrap contract, and the only constants it may assume.
const DEVICE_HANDLE: u32 = 0;
const PORT_HANDLE: u64 = 1;

/// Where this program asks for things to land in its own address space. Its
/// choice, not the kernel's: what it cannot choose is the physical window
/// behind the first, which is what makes the capability worth holding.
const MMIO_VA: u64 = 0x2000_0000;
const QUEUE_VA: u64 = 0x2100_0000;
const HEADER_VA: u64 = 0x2200_0000;
const DATA_VA: u64 = 0x2300_0000;
const STATUS_VA: u64 = 0x2400_0000;

/// Descriptors in the virtqueue: more than the three a single request needs,
/// and a power of two within any plausible `QueueNumMax`.
const QUEUE_SIZE: u16 = 8;

/// Failure codes reported through `DebugWrite` before exiting, so a failure
/// says which stage failed rather than merely failing. Stages: 0x60 map,
/// 0x61 dma, 0x62 transport init, 0x63 submit, 0x64 wait, 0x65 completion,
/// 0x66 encode, 0xff panic.
const fn fail(stage: u64, cause: u64) -> u64 {
    0xdead_0000_0000_0000 | (stage << 16) | (cause & 0xffff)
}

/// One syscall: `a7` = number, `a0`/`a1` = arguments, result in `a0`.
fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    // SAFETY: `ecall` traps to the kernel dispatcher, which saves and restores
    // the whole trap frame and writes back only `a0` — declared here as
    // `inout`. The instruction itself touches no memory.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") number,
            inout("a0") arg0 => ret,
            in("a1") arg1,
            options(nostack),
        );
    }
    ret
}

fn syscall1(number: u64, arg0: u64) -> i64 {
    syscall2(number, arg0, 0)
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    syscall1(SYS_DEBUG_WRITE, value);
    syscall1(SYS_PROCESS_EXIT, 0);
    // The kernel does not return from ProcessExit; this is unreachable and
    // exists so the function's type is honest.
    loop {
        core::hint::spin_loop();
    }
}

/// Reads bytes the **kernel** wrote into a buffer during a preceding syscall,
/// through volatile loads — so the cross-boundary write is visible to the
/// compiler regardless of what its alias analysis concluded about a local this
/// program never wrote to itself.
fn read_kernel_filled<const N: usize>(buf: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: `&buf[i]` is a bounds-checked, initialised byte; volatile
        // only forbids the compiler assuming a cached value.
        unsafe { *slot = core::ptr::read_volatile(&buf[i]) };
    }
    out
}

/// The device's register block, at the address the kernel mapped it to.
struct DeviceRegisters {
    base: usize,
}

impl Mmio for DeviceRegisters {
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the window `MapDevice` installed in this address
        // space, and `offset` is a defined 4-byte-aligned register inside it.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }

    fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read`; this driver exclusively owns the transport, which
        // is a property of the capability being conserved rather than shared.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// Maps the device's registers and returns the base the kernel chose.
fn map_device() -> Result<usize, u64> {
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(DEVICE_HANDLE),
        reserved: 0,
        vaddr: MMIO_VA,
    };
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x66, 1));
    }
    let base = syscall1(SYS_MAP_DEVICE, buf.as_ptr() as u64);
    if base < 0 {
        return Err(fail(0x60, (-base) as u64));
    }
    Ok(base as usize)
}

/// Allocates one page the device can address, at `vaddr` in this program's
/// space, returning the physical address the device must be told.
///
/// The two names for one page is the whole point: this program writes through
/// `vaddr` and hands the device the return value, and nothing it could compute
/// would relate them.
fn dma_page(vaddr: u64) -> Result<u64, u64> {
    let mut buf = [0u8; DmaAllocArgs::WIRE_SIZE];
    let args = DmaAllocArgs {
        size: DmaAllocArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(DEVICE_HANDLE),
        reserved: 0,
        vaddr,
    };
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x66, 2));
    }
    let phys = syscall1(SYS_DMA_ALLOC, buf.as_ptr() as u64);
    if phys < 0 {
        return Err(fail(0x61, (-phys) as u64));
    }
    Ok(phys as u64)
}

/// Sleeps until the device interrupts, then acknowledges it and hands the
/// interrupt line back.
///
/// The driver never learns the line's number. It waits on a port the kernel
/// bound to the device, and `IrqComplete` is authorised by the *device*
/// capability — so the authority to re-arm an interrupt is the same authority
/// as to touch the device, and neither is a number this program could invent.
fn await_device(blk: &Blk<'_, DeviceRegisters>) -> Result<u64, u64> {
    let mut event = [0u8; PortEventRecord::WIRE_SIZE];
    let waited = syscall2(SYS_PORT_WAIT, PORT_HANDLE, event.as_mut_ptr() as u64);
    if waited < 0 {
        return Err(fail(0x64, (-waited) as u64));
    }
    let bytes = read_kernel_filled::<{ PortEventRecord::WIRE_SIZE }>(&event);
    let Ok(record) = decode::<PortEventRecord>(&bytes) else {
        return Err(fail(0x64, 0xd));
    };

    // Acknowledge the device before asking for its line back: the kernel
    // masked it on delivery, and a line re-armed while the device still
    // asserts it would interrupt again immediately and forever. The
    // acknowledgement is virtio's own protocol, so the transport core does it.
    blk.ack_interrupt();

    let mut buf = [0u8; IrqCompleteArgs::WIRE_SIZE];
    let args = IrqCompleteArgs {
        size: IrqCompleteArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(DEVICE_HANDLE),
        reserved: 0,
    };
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x66, 3));
    }
    let done = syscall1(SYS_IRQ_COMPLETE, buf.as_ptr() as u64);
    if done < 0 {
        return Err(fail(0x64, (-done) as u64));
    }
    Ok(record.source)
}

/// Reads sector 0 and returns its first eight bytes.
fn read_sector_zero() -> Result<u64, u64> {
    let registers = DeviceRegisters { base: map_device()? };

    // Four pages the device can address. The queue's three rings share one —
    // they fit for this size — and the request's header, data and status get
    // their own, because the device writes two of them and a driver that let
    // it write into the ring would be handing over its own bookkeeping.
    let queue_phys = dma_page(QUEUE_VA)?;
    let header_phys = dma_page(HEADER_VA)?;
    let data_phys = dma_page(DATA_VA)?;
    let status_phys = dma_page(STATUS_VA)?;

    let layout = Layout::for_size(QUEUE_SIZE);
    let blk = Blk::init(
        &registers,
        QUEUE_SIZE,
        queue_phys,
        queue_phys + layout.avail_offset as u64,
        queue_phys + layout.used_offset as u64,
    )
    .map_err(|error| fail(0x62, error as u64))?;

    // SAFETY: every address below is a page this program just had mapped
    // read-write into its own address space by `DmaAlloc`, and each slice
    // stays inside its page — the queue's three rings are disjoint spans of
    // one page, given by the layout the transport core computed.
    let (header, status, queue) = unsafe {
        (
            core::slice::from_raw_parts_mut(HEADER_VA as *mut u8, BLK_HEADER_LEN),
            &mut *(STATUS_VA as *mut u8),
            core::slice::from_raw_parts_mut(QUEUE_VA as *mut u8, layout.total),
        )
    };
    header.copy_from_slice(&blk_read_header(0));
    // A status byte the device must overwrite. Starting it at a value the
    // device never writes means "it succeeded" cannot be confused with
    // "nothing happened".
    *status = 0xff;

    let (desc, rest) = queue.split_at_mut(layout.avail_offset);
    let (avail, _) = rest.split_at_mut(layout.used_offset - layout.avail_offset);
    blk.write_read_request(desc, avail, header_phys, data_phys, status_phys, 0);

    // Publish every ring write before the doorbell: the device reads this
    // memory by physical address and has no idea what order this core retired
    // its stores in.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    blk.notify();

    // Sleep until the device says it is done. Nothing spins.
    await_device(&blk)?;

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: as above — the used ring is the tail of the queue page.
    let used = unsafe {
        core::slice::from_raw_parts(
            (QUEUE_VA + layout.used_offset as u64) as *const u8,
            layout.total - layout.used_offset,
        )
    };
    match blk.completion(used, 0) {
        Ok(Some((_head, _len))) => {}
        Ok(None) => return Err(fail(0x65, 1)),
        Err(error) => return Err(fail(0x65, 0x100 + error as u64)),
    }

    // SAFETY: the status byte is in a page this program owns and the device
    // has finished writing it, which is what the completion above means.
    let code = unsafe { core::ptr::read_volatile(STATUS_VA as *const u8) };
    if code != 0 {
        return Err(fail(0x65, 0x200 + u64::from(code)));
    }
    // SAFETY: as above, for the first eight bytes the device wrote into the
    // data page.
    let magic = unsafe { core::ptr::read_volatile(DATA_VA as *const u64) };
    Ok(magic)
}

/// Entry point. The kernel starts this thread here with the ELF's entry
/// address; there is no runtime beneath it.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: usize) -> ! {
    match read_sector_zero() {
        Ok(magic) => exit_reporting(magic),
        Err(code) => exit_reporting(code),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit_reporting(fail(0xff, 0))
}
