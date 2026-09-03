// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 block driver: a real `no_std` Rust program that runs in ring 3
//! and reads a disk.
//!
//! It holds a capability to a device and nothing else privileged, and from that
//! it maps registers, allocates memory the device can address, submits a
//! request and collects the answer. It contains no privileged instruction and
//! no platform constant: the register window comes from `MapDevice`, the DMA
//! buffers' device-visible addresses come from `DmaAlloc`, and the addresses it
//! asks for are `tessera_uabi::layout`'s — the one place a per-architecture
//! fact about a user address space is allowed to live.
//!
//! The transport is not here either. The handshake ordering and the
//! split-virtqueue layout live in `tessera-virtio`, which is host-tested
//! against a mock device and is used **unchanged** — the same crate the
//! AArch64 driver uses, and the same one the in-kernel proof used before either
//! existed.
//!
//! **Nor are the syscalls.** They go through `userspace/sdk`'s `Platform`, so
//! what is left in this file is virtio, address arithmetic, and volatile access
//! to windows the kernel mapped. Nothing below names a syscall number, an
//! argument struct or a `version` field.
//!
//! # Two machines, two transports, one program
//!
//! virtio has more than one transport and they do not differ in what the
//! bring-up *means*. On virtio-mmio the controls are 32-bit registers at fixed
//! offsets in one block, which is why a driver on such a machine needs no
//! discovery at all. On virtio-pci there is no such block: the controls live in
//! up to five structures found through the function's vendor capabilities, and
//! **configuration space is not per-device**, so no capability to it can be
//! handed to a driver. The kernel resolved them during enumeration and
//! `DeviceInfo` is how a holder asks for what it found; `layout_valid` is what
//! says whether it found anything, and it is the one branch in this program.
//!
//! **How a completion is collected follows from that and is not a second
//! choice.** A virtio-mmio device on the reference machine has a wire the
//! resource graph routes, so this driver parks on a port and the kernel decides
//! what wakes it. A PCI function does not: its interrupts are message-signalled
//! and arrive through a different door, which is why the bus driver that
//! declares one declares no interrupt line at all — so on that transport this
//! driver watches the used ring, bounded, exactly as every other ring-3
//! virtio-pci driver in this tree does. Delivering MSI-X to ring 3 is a
//! milestone of its own and this program will lose the loop when it lands.
//!
//! Normative: docs/hardware/03-component-interaction-model.md,
//! docs/hardware/04-device-memory-and-unified-memory.md

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use device_abi::DeviceInfoRecord;
use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{decode, encode};
use tessera_sdk::{Dma, Endpoint, Error, Handle, Platform, machine::Machine};
use tessera_uabi::{fail, layout};
use tessera_virtio::pci::{PciTransport, Regs};
use tessera_virtio::{BLK_HEADER_LEN, Blk, Layout, Mmio, Transport};

/// Bit 0 of the startup argument: **this driver was composed behind a device
/// manager**, so handle 0 is the manager's endpoint and the device arrives by
/// binding for a class rather than seeded.
///
/// A composition fact, which is what a startup argument is for — the same use
/// `blk-probe` and `device-manager` already make of theirs. With the bit clear
/// the device is at handle 0 and its interrupt port at handle 1, which is the
/// contract the RISC-V 64 machine seeds and has never needed a manager for.
const COMPOSED_WITH_MANAGER: u64 = 1;

/// The bootstrap contract, both shapes of it.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
/// Where a device seeded by boot arrives, with its interrupt port after it.
const SEEDED_DEVICE_HANDLE: u64 = 0;
const SEEDED_PORT_HANDLE: u64 = 1;
/// Where a bound device lands: one handle — the manager's endpoint — below it.
const BOUND_DEVICE_HANDLE: u64 = 1;

/// Descriptors in the virtqueue: more than the three a single request needs,
/// and a power of two within any plausible queue maximum.
const QUEUE_SIZE: u16 = 8;

/// One page, which is the unit `DmaAlloc` hands out.
const PAGE: u64 = 0x1000;

/// How long the poll for a completion runs before the device is called dead.
///
/// Bounded because a device that never answers is a device, not a hang: the
/// check that runs this has a boot to fail rather than a timeout to wait out.
const POLL_BOUND: u32 = 4_000_000;

/// The block class contract version this driver implements. Checked against
/// what the binding says it was bound as, because a mis-binding is exactly the
/// thing a class contract exists to make visible.
const BLOCK_CONTRACT_VERSION: u32 = 1;

/// The device's register block, at the address the kernel mapped it to.
///
/// The virtio-mmio shape: one block, every control a 32-bit register in it.
struct DeviceRegisters {
    base: usize,
}

impl Mmio for DeviceRegisters {
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the window the platform installed in this address
        // space, and `offset` is a defined 4-byte-aligned register inside it.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }

    fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read`; this driver exclusively owns the transport, which
        // is a property of the capability being conserved rather than shared.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// One virtio-pci configuration structure, at the offset into the granted
/// window that the device's own capabilities put it at.
///
/// **Access width is the field's, never the widest convenient one.** The common
/// configuration structure packs `device_status` (one byte at +0x14),
/// `config_generation` (+0x15) and `queue_select` (+0x16) into adjacent bytes,
/// so a 32-bit write to the first would rewrite the other two — and the second
/// of those decides which queue every following access means.
struct Window {
    base: usize,
}

impl Regs for Window {
    fn read8(&self, offset: usize) -> u8 {
        // SAFETY: `base` is inside the window `MapDevice` installed in this
        // address space, and every offset is a defined field of the structure
        // the device's own capabilities placed there.
        unsafe { ((self.base + offset) as *const u8).read_volatile() }
    }
    fn read16(&self, offset: usize) -> u16 {
        // SAFETY: as `read8`.
        unsafe { ((self.base + offset) as *const u16).read_volatile() }
    }
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: as `read8`.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }
    fn write8(&self, offset: usize, value: u8) {
        // SAFETY: as `read8`; this driver exclusively owns the device, which is
        // a property of the capability being conserved rather than shared.
        unsafe { ((self.base + offset) as *mut u8).write_volatile(value) }
    }
    fn write16(&self, offset: usize, value: u16) {
        // SAFETY: as `write8`.
        unsafe { ((self.base + offset) as *mut u16).write_volatile(value) }
    }
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as `write8`.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// Turns an SDK error into this program's report value.
///
/// The mapping exists because the reports are this driver's own vocabulary and
/// the errors are the platform's; what it no longer has to do is turn a
/// negative syscall return into either.
fn failed(stage: u64, error: Error) -> u64 {
    let cause = match error {
        Error::PeerGone => 1,
        Error::TooLarge => 2,
        Error::NotBound => 3,
        Error::Refused => 4,
        // A wait that reached its deadline. This driver sets none, so it is
        // here to keep the mapping total rather than because it can happen.
        Error::TimedOut => 5,
        Error::Kernel(code) => code as u64,
    };
    fail(stage, cause)
}

/// The four pages the device reads and writes.
///
/// The queue's three rings share one — they fit at this size — and the
/// request's header, data and status get their own, because the device writes
/// two of them and a driver that let it write into the ring would be handing
/// over its own bookkeeping.
///
/// **The two names for one page are the whole point**: this program writes
/// through `va` and hands the device `device_address`, and nothing it could
/// compute would relate them.
struct Buffers {
    queue: Dma,
    header: Dma,
    data: Dma,
    status: Dma,
}

impl Buffers {
    /// Asks the platform for four pages, at four addresses of this program's
    /// own choosing out of the region `tessera_uabi::layout` reserves.
    fn take<P: Platform>(platform: &mut P, device: Handle) -> Result<Buffers, u64> {
        let mut next = 0u64;
        let mut page = |platform: &mut P| -> Result<Dma, u64> {
            let va = layout::DEVICE_DMA_VA + next * PAGE;
            next += 1;
            platform
                .dma_alloc(device, va)
                .map_err(|error| failed(0x61, error))
        };
        Ok(Buffers {
            queue: page(platform)?,
            header: page(platform)?,
            data: page(platform)?,
            status: page(platform)?,
        })
    }
}

/// What one run of this driver found out, in the order a reader would ask.
struct Report {
    /// The function this driver ended up holding, as `DeviceInfo` names it:
    /// vendor and product in the low word pair, the bus/device/function that
    /// identifies it on the machine above them.
    identity: u64,
    /// The device's capacity in 512-byte sectors, read out of the
    /// device-specific configuration structure.
    capacity: u64,
    /// The first eight bytes of sector 0.
    magic: u64,
}

/// Sleeps until the device interrupts, then acknowledges it and hands the
/// interrupt line back.
///
/// The driver never learns the line's number. It waits on a port the kernel
/// bound to the device, and completing the interrupt is authorised by the
/// *device* capability — so the authority to re-arm an interrupt is the same
/// authority as to touch the device, and neither is a number this program
/// could invent.
fn await_device<P: Platform, T: Transport>(
    platform: &mut P,
    device: Handle,
    port: Handle,
    blk: &Blk<'_, T>,
) -> Result<(), u64> {
    platform
        .wait_for_interrupt(port)
        .map_err(|error| failed(0x64, error))?;

    // Acknowledge the device before asking for its line back: the kernel
    // masked it on delivery, and a line re-armed while the device still
    // asserts it would interrupt again immediately and forever. The
    // acknowledgement is virtio's own protocol, so the transport core does it.
    blk.ack_interrupt();

    platform
        .interrupt_complete(device)
        .map_err(|error| failed(0x66, error))?;
    Ok(())
}

/// Reads the used ring's published index out of the queue page.
fn used_index(queue_va: u64, at: usize) -> u16 {
    // SAFETY: the used ring is a span of a page this program had mapped
    // read-write by `DmaAlloc`, and `at` is inside it by construction of
    // `Layout`. Volatile because the device is the other writer.
    unsafe { ((queue_va as usize + at + 2) as *const u16).read_volatile() }
}

/// Brings the device up on `transport`, reads sector 0 and reports what it saw.
///
/// Generic over the transport because that is the only thing the two machines
/// disagree about: everything from here down — the ring layout, the descriptor
/// chain, the status byte — is the same work either way, which is what the
/// `Transport` seam exists to say.
fn drive<P: Platform, T: Transport>(
    platform: &mut P,
    transport: &T,
    device: Handle,
    port: Option<Handle>,
    buffers: &Buffers,
) -> Result<(u64, u64), u64> {
    let layout = Layout::for_size(QUEUE_SIZE);
    let blk = Blk::init(
        transport,
        QUEUE_SIZE,
        buffers.queue.device_address,
        buffers.queue.device_address + layout.avail_offset as u64,
        buffers.queue.device_address + layout.used_offset as u64,
    )
    .map_err(|error| fail(0x62, error as u64))?;

    // The size the medium actually is, asked of the device rather than
    // assumed: a driver that reported a constant would be reporting the disk
    // the check happened to attach, and a filesystem cannot tell a made-up
    // sector count from a real one.
    let capacity = blk.capacity();

    // SAFETY: every address below is a page this program just had mapped
    // read-write into its own address space by `DmaAlloc`, and each slice stays
    // inside its page — the queue's three rings are disjoint spans of one page,
    // given by the layout the transport core computed.
    let (header, status, queue) = unsafe {
        (
            core::slice::from_raw_parts_mut(buffers.header.va as *mut u8, BLK_HEADER_LEN),
            &mut *(buffers.status.va as *mut u8),
            core::slice::from_raw_parts_mut(buffers.queue.va as *mut u8, layout.total),
        )
    };
    header.copy_from_slice(&tessera_virtio::blk_read_header(0));
    // A status byte the device must overwrite. Starting it at a value the
    // device never writes means "it succeeded" cannot be confused with
    // "nothing happened".
    *status = 0xff;

    let (desc, rest) = queue.split_at_mut(layout.avail_offset);
    let (avail, _) = rest.split_at_mut(layout.used_offset - layout.avail_offset);
    blk.write_read_request(
        desc,
        avail,
        buffers.header.device_address,
        buffers.data.device_address,
        buffers.status.device_address,
        0,
    );

    // Publish every ring write before the doorbell: the device reads this
    // memory by physical address and has no idea what order this core retired
    // its stores in.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    blk.notify();

    match port {
        // A wire the graph routes: nothing spins.
        Some(port) => await_device(platform, device, port, &blk)?,
        // No wire to route. Bounded, so a silent device is an answer.
        None => {
            let mut spun = 0u32;
            while used_index(buffers.queue.va, layout.used_offset) == 0 {
                if spun == POLL_BOUND {
                    return Err(fail(0x65, 2));
                }
                spun += 1;
                core::hint::spin_loop();
            }
        }
    }

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: as above — the used ring is the tail of the queue page.
    let used = unsafe {
        core::slice::from_raw_parts(
            (buffers.queue.va + layout.used_offset as u64) as *const u8,
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
    let code = unsafe { core::ptr::read_volatile(buffers.status.va as *const u8) };
    if code != 0 {
        return Err(fail(0x65, 0x200 + u64::from(code)));
    }
    // SAFETY: as above, for the first eight bytes the device wrote into the
    // data page.
    let magic = unsafe { core::ptr::read_volatile(buffers.data.va as *const u64) };
    Ok((capacity, magic))
}

/// Asks the device manager for a block device.
///
/// The **outputs of the binding are checked rather than ignored**: a driver
/// told which class it was bound as and against which contract version, and
/// then not looking, would leave those decorative — and a manager that stopped
/// filling them in would break nothing until something needed them.
fn bind<P: Platform>(platform: &mut P) -> Result<(), u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Block,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0x67, 0xe));
    }
    let mut answer = [0u8; BindReply::WIRE_SIZE];
    tessera_sdk::bind(
        platform,
        Endpoint(Handle(MANAGER_ENDPOINT_HANDLE)),
        &message,
        &mut answer,
    )
    .map_err(|error| failed(0x67, error))?;
    let reply: BindReply = match decode(&answer) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x67, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0x67, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Block {
        return Err(fail(0x67, 0x200));
    }
    if reply.contract_version != BLOCK_CONTRACT_VERSION {
        return Err(fail(0x67, 0x300 | u64::from(reply.contract_version)));
    }
    Ok(())
}

/// The whole run: acquire a device, map it, work out which transport it speaks,
/// and read sector 0 through it.
fn read_sector_zero<P: Platform>(platform: &mut P, arg: u64) -> Result<Report, u64> {
    let bound = arg & COMPOSED_WITH_MANAGER != 0;
    if bound {
        bind(platform)?;
    }
    let device = Handle(if bound {
        BOUND_DEVICE_HANDLE
    } else {
        SEEDED_DEVICE_HANDLE
    });
    // A seeded device comes with its wire; a bound one does not, for the reason
    // the module header gives.
    let port = (!bound).then_some(Handle(SEEDED_PORT_HANDLE));

    let base = platform
        .map_device(device, layout::DEVICE_MMIO_VA)
        .map_err(|error| failed(0x60, error))?;

    let mut record = [0u8; DeviceInfoRecord::WIRE_SIZE];
    platform
        .device_info(device, &mut record)
        .map_err(|error| failed(0x63, error))?;
    let info: DeviceInfoRecord = match decode(&record) {
        Ok(info) => info,
        Err(_) => return Err(fail(0x63, 0xd)),
    };
    let identity = (u64::from(info.bdf) << 32)
        | (u64::from(info.vendor & 0xffff) << 16)
        | u64::from(info.device & 0xffff);

    let buffers = Buffers::take(platform, device)?;

    let (capacity, magic) = if info.layout_valid != 0 {
        // virtio-pci: the controls are where the function's own capabilities
        // said they were, and the kernel is the only thing that could read
        // that. What this program is told is offsets into the window it was
        // granted, never where any of it is in physical memory.
        let common = Window {
            base: (base + u64::from(info.common_offset)) as usize,
        };
        let notify = Window {
            base: (base + u64::from(info.notify_offset)) as usize,
        };
        let isr = Window {
            base: (base + u64::from(info.isr_offset)) as usize,
        };
        let device_cfg = Window {
            base: (base + u64::from(info.device_config_offset)) as usize,
        };
        // The virtio device type the function's PCI device id names. Read from
        // what the graph says this function is rather than assumed, so a
        // manager that bound this driver to a network card is refused by
        // `Blk::init`'s own probe rather than driven as a disk.
        let Some(device_type) = tessera_virtio::pci::device_type(info.device as u16) else {
            return Err(fail(0x68, u64::from(info.device & 0xffff)));
        };
        let transport = PciTransport::new(
            &common,
            &notify,
            info.notify_multiplier,
            Some(&isr),
            Some(&device_cfg),
            device_type,
        );
        drive(platform, &transport, device, port, &buffers)?
    } else {
        // virtio-mmio: one block, and the register offsets are the standard's.
        let registers = DeviceRegisters {
            base: base as usize,
        };
        drive(platform, &registers, device, port, &buffers)?
    };
    Ok(Report {
        identity,
        capacity,
        magic,
    })
}

/// Entry point. The kernel starts this thread here with the ELF's entry
/// address; there is no runtime beneath it.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    let mut platform = Machine;
    match read_sector_zero(&mut platform, arg) {
        // **Three reports where there is a manager, one where there is not**,
        // and the difference is what the composition asked to be shown. A
        // seeded driver was handed its device by the kernel and speaks a
        // transport with nothing to discover, so the only thing its run
        // establishes is the sector it read; a bound one also had to be given
        // the right function by a service, and had to find the device's own
        // configuration structure to know how large the medium is. Reported
        // separately so they fail apart: a driver that bound to the wrong
        // device and one that read the wrong bytes are different failures.
        Ok(report) => {
            if arg & COMPOSED_WITH_MANAGER != 0 {
                platform.report(report.identity);
                platform.report(report.capacity);
            }
            platform.finish(report.magic)
        }
        Err(code) => platform.finish(code),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    Machine.finish(fail(0xff, 0))
}
