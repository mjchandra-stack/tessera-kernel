// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **NVMe driver**: a `no_std` Rust program that brings an NVMe
//! controller up from ring 3 and serves `tessera.driver.block` over it.
//!
//! **The same contract the virtio driver serves.** That is the claim worth
//! making here: a class contract is a property of the *class*, not of the
//! transport underneath it, and the way to show it is to put a completely
//! different controller behind the same interface and let the same client and
//! the same conformance suite judge it. Nothing about `block_driver.isl`
//! changed to accommodate NVMe, and nothing in the client knows which one it is
//! talking to.
//!
//! **Two I/O queues, and each one's completions arrive on its own interrupt.**
//! A submission queue and its completion queue are created with a distinct
//! MSI-X vector, and boot routes each vector to its own port. So the driver
//! does not demultiplex: it submits on a queue and waits on *that queue's*
//! port, and being woken there is what tells it which queue finished. A shared
//! interrupt cannot do that — it says only that something completed, and the
//! driver has to read every ring to find out what.
//!
//! Reads go on queue 1 and writes on queue 2, so the class contract's own
//! traffic exercises both rather than a side test doing it once.
//!
//! The transport itself is not here. Controller bring-up, the command
//! encodings, the doorbell arithmetic and the completion ring's phase tag live
//! in `tessera-nvme`, which is host-tested against a mock controller and
//! forbids `unsafe`. What this file adds is the part that genuinely cannot be
//! shared: the syscalls, and volatile access to a window the kernel mapped.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage"),
//! docs/drivers/01-driver-framework.md ("Driver Class Contracts")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{
    BlockBufferReply, BlockBufferRequest, BlockControlReply, BlockDescribeReply, BlockDevice,
    BlockDeviceIncoming, BlockError, BlockPowerState, BlockReadReply, BlockWriteReply,
};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{Reader, WireError, decode, encode};
use tessera_nvme::{
    CNS_NAMESPACE, COMMAND_LEN, CompletionRing, Controller, QueuePair, Registers,
    write_create_completion_queue, write_create_submission_queue, write_identify, write_read,
    write_write,
};
use tessera_sdk::{
    Endpoint, Error as SdkError, Handle as SdkHandle, Platform as _, Transfer, machine::Machine,
};
use tessera_uabi::fail;

/// The capabilities boot installs, in order. The bind channel is the only
/// inbound authority at startup; the device arrives by asking for a class.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const CLIENT_ENDPOINT_HANDLE: u64 = 1;
/// **A port per I/O queue, and that is the milestone.** Each carries one MSI-X
/// vector's interrupts, so being woken on one of them says which queue
/// completed — without reading either ring.
const QUEUE1_PORT_HANDLE: u64 = 2;
const QUEUE2_PORT_HANDLE: u64 = 3;
/// Where the bound device capability lands: four handles are installed above
/// it, so the kernel puts the first transferred one here.
const DEVICE_HANDLE: u32 = 4;

/// Where this program asks for things in its own space. Its choice; what it
/// cannot choose is the physical window behind the first, which is what makes
/// the capability worth holding.
const MMIO_VA: u64 = 0x0000_1000_0040_0000;
/// **A page per ring, and the specification is why.** Every queue base a
/// controller is given must be page-aligned — the admin pair in `ASQ`/`ACQ`,
/// and each I/O ring in the `PRP1` of the command that creates it. Packing two
/// rings into one page is what a driver does on a transport where a ring is
/// just memory; here it makes the controller refuse to enable, and it says so
/// with a fatal status rather than with anything that names the reason.
const ADMIN_SQ_VA: u64 = 0x0000_1000_0050_0000;
const ADMIN_CQ_VA: u64 = 0x0000_1000_0051_0000;
const SQ1_VA: u64 = 0x0000_1000_0052_0000;
const CQ1_VA: u64 = 0x0000_1000_0053_0000;
const SQ2_VA: u64 = 0x0000_1000_0054_0000;
const CQ2_VA: u64 = 0x0000_1000_0055_0000;
const DATA_VA: u64 = 0x0000_1000_0056_0000;

/// Entries per ring. Eight admin commands is more than bring-up uses, and four
/// per I/O queue is more than one outstanding request needs — both leave the
/// tail clear of the head, which is how a ring says it is not empty.
const ADMIN_ENTRIES: u16 = 8;
const IO_ENTRIES: u16 = 4;

/// The queue ids and the MSI-X vectors they raise. The vector numbers are the
/// contract with boot, which programmed the controller's MSI-X table and routed
/// each vector to the port this program holds for it.
const QUEUE_READ: u16 = 1;
const QUEUE_WRITE: u16 = 2;

/// The namespace this driver serves. One, which is what the reference
/// controller presents; a driver of a controller with more would enumerate.
const NAMESPACE: u32 = 1;

/// The sector size this driver reports and works in.
const SECTOR: u64 = 512;

/// What `Describe` answers.
///
/// `WRITE` and `OUT_OF_LINE`. Deliberately not `FLUSH` or `DISCARD`: a driver
/// that advertised everything would make the conformance suite's
/// unimplemented-optional rule unreachable, and a class contract whose
/// optionality is never exercised is one nobody has checked. Two of the four
/// optionals implemented and two refused keeps both rules reachable.
const FEATURES: u64 = 0x1 | 0x10;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace. This
/// driver declares none, so every one of them is refused.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// The symmetric request/reply buffer: the largest struct in either direction
/// is a `BlockWriteRequest` or a `BlockDescribeReply`, both 88.
const MSG_BUF_LEN: usize = 128;

/// Publishes stores before a doorbell; `dsb ish` is unprivileged.
fn barrier() {
    // SAFETY: a data synchronization barrier has no operands and no side
    // effect beyond ordering.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
}

/// The controller's register window, at the address the kernel mapped it to.
struct UserRegisters {
    base: usize,
}

impl Registers for UserRegisters {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the window `MapDevice` installed in this address
        // space, and every offset the transport core uses is a defined
        // register or a doorbell inside it.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }

    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as `read32`; this driver exclusively owns the controller,
        // which is a property of the capability being conserved rather than
        // shared.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// Reads back a u32 the kernel wrote into one of this program's buffers.
///
/// Writes a u64 into an encoded descriptor between messages.
///
/// Acquires a device of `class` from the device manager. Which controller
/// answers to "Block" is the manager's finding; the class in the reply is
/// checked so a mis-bind is caught here rather than as a driver talking to the
/// wrong hardware.
fn bind() -> Result<u32, u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Block,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0x91, 0xe));
    }
    let mut answer = [0u8; BindReply::WIRE_SIZE];
    if tessera_sdk::bind(
        &mut Machine,
        Endpoint(SdkHandle(MANAGER_ENDPOINT_HANDLE)),
        &message,
        &mut answer,
    )
    .is_err()
    {
        return Err(fail(0x91, 1));
    }
    let reply: BindReply = match decode(&answer) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x91, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0x91, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Block {
        return Err(fail(0x91, 0x200));
    }
    Ok(DEVICE_HANDLE)
}

/// Maps the controller's registers at `vaddr`, returning the register base.
fn map_device(vaddr: u64) -> Result<u64, u64> {
    Machine
        .map_device(SdkHandle(u64::from(DEVICE_HANDLE)), vaddr)
        .map_err(|_| fail(0x92, 1))
}

/// Allocates one page the controller can address at `vaddr`, returning the
/// address the controller must be told.
///
/// The two names for one page is the whole point: this program writes commands
/// through `vaddr`, and the controller fetches them from the return value —
/// and nothing this program could compute would relate them.
fn dma_page(vaddr: u64) -> Result<u64, u64> {
    Machine
        .dma_alloc(SdkHandle(u64::from(DEVICE_HANDLE)), vaddr)
        .map(|dma| dma.device_address)
        .map_err(|_| fail(0x93, 1))
}

/// Re-arms the controller's interrupt line after a completion has been taken.
fn irq_complete() -> Result<(), u64> {
    Machine
        .interrupt_complete(SdkHandle(u64::from(DEVICE_HANDLE)))
        .map_err(|_| fail(0x94, 1))
}

/// One page this program shares with the controller.
///
/// **The one thing here the SDK does not mediate, and it is a limitation
/// rather than an oversight.** `Platform::with_dma` hands a driver a *scoped*
/// slice, which is what lets `tessera_sdk::dma` watch what a driver does with
/// a page. This controller's submission and completion rings are long-lived —
/// they are borrowed for the life of the driver and threaded through every
/// request — so a scoped view cannot express them, and the pointer is formed
/// here. The consequence is precise: nvme's DMA discipline is not watchable by
/// the harness the way `gpu`'s and `snd`'s are.
///
/// SAFETY (at every call): `DmaAlloc` mapped exactly one zero-filled page
/// read+write at `va` in this process's space, and every offset used stays
/// inside it.
fn page(va: u64) -> &'static mut [u8] {
    // SAFETY: as documented above; each of the three pages is turned into a
    // slice exactly once, in `run`, and threaded from there.
    unsafe { core::slice::from_raw_parts_mut(va as *mut u8, 4096) }
}

/// The two I/O queue pairs' rings, indexed by queue id.
///
/// Borrowed as one struct rather than six slices because they are one thing:
/// which ring a request touches is chosen by the queue it goes on, and passing
/// them separately would mean every caller re-deciding that.
struct IoRings<'m> {
    sq: [&'m mut [u8]; 3],
    cq: [&'m [u8]; 3],
}

/// Everything the serve loop carries between requests.
struct Driver {
    registers: UserRegisters,
    admin_sq_phys: u64,
    admin_cq_phys: u64,
    io_sq_phys: [u64; 3],
    io_cq_phys: [u64; 3],
    data_phys: u64,
    /// Where each ring's producer or consumer has reached. A submission tail
    /// and a completion reader per queue, because the two advance
    /// independently and a shared cursor would make a completion look consumed
    /// because a command had been sent.
    admin_tail: u16,
    admin_completions: CompletionRing,
    io_tails: [u16; 3],
    io_completions: [CompletionRing; 3],
    /// The next command identifier. Monotonic within a boot, so a completion
    /// naming a command this driver never sent is visible as such.
    next_cid: u16,
    power: BlockPowerState,
}

/// Runs one admin command to completion: publish it, ring the doorbell, and
/// poll the admin completion ring.
///
/// Polled rather than parked, and only here: the admin queue is used three
/// times at startup and never again, so an interrupt route for it would be a
/// mechanism nothing exercises. The I/O queues, which carry every request the
/// class contract makes, are the ones that park.
fn admin_command(
    driver: &mut Driver,
    admin_sq: &mut [u8],
    admin_cq: &[u8],
    command: &[u8; COMMAND_LEN],
) -> Result<(), u64> {
    let at = usize::from(driver.admin_tail) * COMMAND_LEN;
    admin_sq[at..at + COMMAND_LEN].copy_from_slice(command);
    driver.admin_tail = (driver.admin_tail + 1) % ADMIN_ENTRIES;
    barrier();
    let controller = Controller::attach(&driver.registers);
    controller.ring_submission(0, driver.admin_tail);

    for _ in 0..POLL_LIMIT {
        barrier();
        match driver.admin_completions.poll(admin_cq) {
            Ok(Some(completion)) => {
                controller.ring_completion(0, driver.admin_completions.head());
                if completion.is_success() {
                    return Ok(());
                }
                return Err(fail(0x95, u64::from(completion.status)));
            }
            Ok(None) => {}
            Err(e) => return Err(fail(0x95, 0x100 + e as u64)),
        }
    }
    Err(fail(0x95, 0x200))
}

/// Bound on an admin completion poll: no timer exists at ring 3, so the wait is
/// a bounded spin. Only the admin path spins; every I/O completion is woken by
/// its queue's own interrupt.
const POLL_LIMIT: u32 = 50_000_000;

/// Runs one I/O command on `queue` and **waits on that queue's port**.
///
/// Being woken is what says which queue completed. The driver never reads the
/// other queue's ring to find out, which is the difference a vector per queue
/// buys and what a shared interrupt cannot give.
fn io_command(
    driver: &mut Driver,
    io: &mut IoRings,
    queue: u16,
    command: &[u8; COMMAND_LEN],
) -> Result<(), u64> {
    let port = match queue {
        QUEUE_READ => QUEUE1_PORT_HANDLE,
        QUEUE_WRITE => QUEUE2_PORT_HANDLE,
        _ => return Err(fail(0x96, 0)),
    };
    let at = usize::from(driver.io_tails[usize::from(queue)]) * COMMAND_LEN;
    io.sq[usize::from(queue)][at..at + COMMAND_LEN].copy_from_slice(command);
    driver.io_tails[usize::from(queue)] = (driver.io_tails[usize::from(queue)] + 1) % IO_ENTRIES;
    barrier();
    let controller = Controller::attach(&driver.registers);
    controller.ring_submission(queue, driver.io_tails[usize::from(queue)]);

    if Machine.wait_for_interrupt(SdkHandle(port)).is_err() {
        return Err(fail(0x97, 1));
    }
    irq_complete()?;

    barrier();
    match driver.io_completions[usize::from(queue)].poll(io.cq[usize::from(queue)]) {
        Ok(Some(completion)) => {
            controller.ring_completion(queue, driver.io_completions[usize::from(queue)].head());
            // The completion says which submission queue it came from, and it
            // must be the one this request went out on. A controller that
            // answered on the wrong queue would be one whose per-queue
            // interrupts mean nothing.
            if completion.sqid != queue {
                return Err(fail(0x98, u64::from(completion.sqid)));
            }
            if completion.is_success() {
                Ok(())
            } else {
                Err(fail(0x98, 0x100 + u64::from(completion.status)))
            }
        }
        // Woken with nothing to take. Reported rather than retried: the port
        // was signalled by this queue's vector, so an empty ring means the
        // driver and the controller disagree about where completions go.
        Ok(None) => Err(fail(0x98, 0x200)),
        Err(e) => Err(fail(0x98, 0x300 + e as u64)),
    }
}

/// Reads one sector into the shared data page.
fn read_sector(driver: &mut Driver, io: &mut IoRings, sector: u64) -> Result<(), u64> {
    read_sector_into(driver, io, sector, driver.data_phys)
}

/// Reads one sector into `data` — an address the *device* uses, which is this
/// driver's own page for an inline request and a client's attached buffer for
/// an out-of-line one.
///
/// Parameterised rather than duplicated because the command is identical: what
/// differs between the two paths is whose memory the controller writes into,
/// and that is one field.
fn read_sector_into(
    driver: &mut Driver,
    io: &mut IoRings,
    sector: u64,
    data: u64,
) -> Result<(), u64> {
    let mut command = [0u8; COMMAND_LEN];
    let cid = driver.next_cid;
    driver.next_cid = driver.next_cid.wrapping_add(1);
    if write_read(&mut command, cid, NAMESPACE, data, sector, 1, SECTOR).is_err() {
        return Err(fail(0x99, 0));
    }
    io_command(driver, io, QUEUE_READ, &command)
}

/// Writes one sector out of the shared data page.
fn write_sector(driver: &mut Driver, io: &mut IoRings, sector: u64) -> Result<(), u64> {
    write_sector_from(driver, io, sector, driver.data_phys)
}

/// Writes one sector out of `data`, the device-visible address.
fn write_sector_from(
    driver: &mut Driver,
    io: &mut IoRings,
    sector: u64,
    data: u64,
) -> Result<(), u64> {
    let mut command = [0u8; COMMAND_LEN];
    let cid = driver.next_cid;
    driver.next_cid = driver.next_cid.wrapping_add(1);
    if write_write(&mut command, cid, NAMESPACE, data, sector, 1, SECTOR).is_err() {
        return Err(fail(0x9a, 0));
    }
    io_command(driver, io, QUEUE_WRITE, &command)
}

/// Brings the controller up and creates both I/O queue pairs.
fn bring_up(
    driver: &mut Driver,
    admin_sq: &mut [u8],
    admin_cq: &[u8],
    io: &mut IoRings,
) -> Result<(), u64> {
    let controller = match Controller::reset_and_enable(
        &driver.registers,
        QueuePair {
            submission: driver.admin_sq_phys,
            completion: driver.admin_cq_phys,
            entries: ADMIN_ENTRIES,
        },
    ) {
        Ok(controller) => controller,
        Err(e) => return Err(fail(0x9b, e as u64)),
    };
    if controller.check_queue_size(IO_ENTRIES).is_err() {
        return Err(fail(0x9b, 0x100));
    }
    driver.admin_tail = 0;
    driver.admin_completions = match CompletionRing::new(ADMIN_ENTRIES) {
        Ok(ring) => ring,
        Err(e) => return Err(fail(0x9b, 0x200 + e as u64)),
    };

    // Ask the namespace what it is before doing anything to it. The answer is
    // not used beyond confirming the controller answers admin commands at all,
    // which is what a bring-up needs to establish before it creates queues
    // against it.
    let mut command = [0u8; COMMAND_LEN];
    if write_identify(
        &mut command,
        driver.next_cid,
        driver.data_phys,
        CNS_NAMESPACE,
        NAMESPACE,
    )
    .is_err()
    {
        return Err(fail(0x9b, 0x300));
    }
    driver.next_cid = driver.next_cid.wrapping_add(1);
    admin_command(driver, admin_sq, admin_cq, &command)?;

    // **Completion queue before submission queue, and each with its own
    // vector.** The order is the specification's and it is not arbitrary: a
    // submission queue names the completion queue its answers go to, so the
    // one it names has to exist.
    for queue in [QUEUE_READ, QUEUE_WRITE] {
        if write_create_completion_queue(
            &mut command,
            driver.next_cid,
            driver.io_cq_phys[usize::from(queue)],
            queue,
            IO_ENTRIES,
            // The vector is the queue's own, which is the whole arrangement:
            // boot routed each to a separate port, so a completion here wakes
            // this driver somewhere that identifies the queue.
            queue,
        )
        .is_err()
        {
            return Err(fail(0x9b, 0x400));
        }
        driver.next_cid = driver.next_cid.wrapping_add(1);
        admin_command(driver, admin_sq, admin_cq, &command)?;

        if write_create_submission_queue(
            &mut command,
            driver.next_cid,
            driver.io_sq_phys[usize::from(queue)],
            queue,
            IO_ENTRIES,
            queue,
        )
        .is_err()
        {
            return Err(fail(0x9b, 0x500));
        }
        driver.next_cid = driver.next_cid.wrapping_add(1);
        admin_command(driver, admin_sq, admin_cq, &command)?;

        driver.io_tails[usize::from(queue)] = 0;
        driver.io_completions[usize::from(queue)] = match CompletionRing::new(IO_ENTRIES) {
            Ok(ring) => ring,
            Err(e) => return Err(fail(0x9b, 0x600 + e as u64)),
        };
    }
    Ok(())
}

/// Serves `ReadInto`/`WriteFrom`: the client's own buffer, filled by the
/// controller without this driver ever mapping it.
///
/// **A driver with no mapping of a buffer did not copy it.** The capability
/// arrives, is attached to this device to get an address the controller can
/// use, is named in the command, and goes back with the reply — which is also
/// what detaches it. At no point is it in this program's address space.
///
/// The buffer is given back on **every** path, including the refusals. A
/// driver that kept it on an error would strand a client's memory in a process
/// it cannot reach, and every later request would be refused for want of a
/// buffer anyway.
#[allow(clippy::too_many_arguments)]
fn out_of_line(
    driver: &mut Driver,
    io: &mut IoRings,
    request: &BlockBufferRequest,
    method: u32,
    msg_buf: &mut [u8],
    arrived: &[SdkHandle],
    give_back: &mut [Transfer],
) -> Result<(usize, usize), u64> {
    let answer = |status: BlockError, transferred: u64, buf: &mut [u8]| {
        let reply = BlockBufferReply {
            size: BlockBufferReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status: status as u32,
            reserved: 0,
            transferred,
        };
        match encode(&reply, &mut buf[..BlockBufferReply::WIRE_SIZE]) {
            Ok(_) => Ok(BlockBufferReply::WIRE_SIZE),
            Err(_) => Err(fail(0x9d, 0xe)),
        }
    };

    // No buffer arrived, so there is nothing to give back and nothing to fill.
    let Some(buffer) = arrived.first().copied() else {
        return answer(BlockError::Protocol, 0, msg_buf).map(|len| (len, 0));
    };
    // Whatever happens below, the capability goes home.
    give_back[0] = Transfer {
        handle: buffer,
        rights: BlockBufferRequest::BUFFER_RIGHTS,
        shared: false,
    };
    let mut finish = |status: BlockError, moved: u64, buf: &mut [u8]| {
        answer(status, moved, buf).map(|len| (len, 1))
    };

    if request.size != BlockBufferRequest::WIRE_SIZE as u32 || request.version != 1 {
        return finish(BlockError::Protocol, 0, msg_buf);
    }
    // One sector per call, refused rather than trimmed: a driver that served
    // half of what was asked and said so in a length nobody reads is how a
    // filesystem gets a torn block.
    if request.length == 0 || request.length != SECTOR as u64 {
        return finish(BlockError::Protocol, 0, msg_buf);
    }
    // No range check: this driver reports `sector_count = 0` from `Describe`,
    // because it never asked the controller. Refusing against a size nobody
    // established would refuse valid sectors, and pretending to check is worse
    // than saying there is no check — the identify that would establish it is
    // its own change.

    let address = match Machine.dma_attach(SdkHandle(u64::from(DEVICE_HANDLE)), buffer) {
        Ok(address) => address,
        // Nothing reached the device, so a retry cannot help: that is
        // `Protocol` and not `IoError`.
        Err(_) => return finish(BlockError::Protocol, 0, msg_buf),
    };

    let outcome = if method == BlockDevice::READ_INTO {
        read_sector_into(driver, io, request.sector, address)
    } else {
        write_sector_from(driver, io, request.sector, address)
    };

    // **No detach here, deliberately.** Handing the capability back is what
    // detaches it: `kcore::dispatch` does it on the departure path rather than
    // asking a driver to remember, "because a driver that cannot forget is
    // better than one that must remember". Calling it anyway cost a syscall
    // per request and added a failure mode — a detach error would have turned
    // a completed read into a reported I/O error. `Platform::dma_detach`
    // remains for its real use: a driver that wants a buffer back in CPU-land
    // while continuing to hold it.
    match outcome {
        Ok(()) => finish(BlockError::Ok, SECTOR as u64, msg_buf),
        Err(_) => finish(BlockError::IoError, 0, msg_buf),
    }
}

/// Answers one client request: the reply's length, and how many capabilities
/// go back with it.
///
/// The two out-of-line ordinals are taken here rather than in the match below
/// because they are the only ones that answer with a capability as well as
/// bytes, and folding them in would make every other arm carry a count it
/// never sets.
#[allow(clippy::too_many_arguments)]
fn serve(
    driver: &mut Driver,
    admin_sq: &mut [u8],
    admin_cq: &[u8],
    io: &mut IoRings,
    data: &mut [u8],
    method: u32,
    request: Result<BlockDeviceIncoming, WireError>,
    msg_buf: &mut [u8],
    arrived: &[SdkHandle],
    give_back: &mut [Transfer],
) -> Result<(usize, usize), u64> {
    if let Ok(BlockDeviceIncoming::ReadInto(buffer) | BlockDeviceIncoming::WriteFrom(buffer)) =
        &request
    {
        return out_of_line(driver, io, buffer, method, msg_buf, arrived, give_back);
    }
    serve_inline(
        driver, admin_sq, admin_cq, io, data, method, request, msg_buf,
    )
    .map(|len| (len, 0))
}

/// Answers a request whose payload rides inline. Returns the reply's length.
#[allow(clippy::too_many_arguments)]
fn serve_inline(
    driver: &mut Driver,
    admin_sq: &mut [u8],
    admin_cq: &[u8],
    io: &mut IoRings,
    data: &mut [u8],
    method: u32,
    request: Result<BlockDeviceIncoming, WireError>,
    msg_buf: &mut [u8],
) -> Result<usize, u64> {
    let control = |status: BlockError, state: BlockPowerState, buf: &mut [u8]| {
        let reply = BlockControlReply {
            size: BlockControlReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status: status as u32,
            state,
        };
        match encode(&reply, &mut buf[..BlockControlReply::WIRE_SIZE]) {
            Ok(_) => Ok(BlockControlReply::WIRE_SIZE),
            Err(_) => Err(fail(0x9c, 0xe)),
        }
    };

    // An ordinal in the vendor range with nothing negotiated, one the contract
    // does not define, or a payload naming a capability that did not arrive:
    // three refusals the client should hear rather than three ways for this
    // driver to die holding a request.
    if method >= VENDOR_ORDINAL_BASE {
        return control(BlockError::Protocol, driver.power, msg_buf);
    }
    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return control(BlockError::Protocol, driver.power, msg_buf);
        }
        // A defined ordinal whose bytes do not decode is a different fact and a
        // fatal one: the client and this driver disagree about a type they both
        // compile from the same schema.
        Err(_) => return Err(fail(0x9d, 0)),
    };

    match request {
        BlockDeviceIncoming::Describe(_) => {
            let reply = BlockDescribeReply {
                size: BlockDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                status: BlockError::Ok,
                features: FEATURES,
                sector_size: SECTOR as u32,
                reserved: 0,
                // What the namespace holds is not something this driver needs
                // for the requests it serves, and reporting a number it did not
                // read would be worse than reporting none.
                sector_count: 0,
                // One PRP entry covers a page, which is what bounds a transfer
                // here — reported rather than assumed, because a client that
                // guessed would meet a controller that disagreed.
                dma_alignment: 4096,
                dma_max_transfer_sectors: (4096 / SECTOR) as u32,
                dma_scoped: 0,
                power_states: (1 << BlockPowerState::Active as u32)
                    | (1 << BlockPowerState::Idle as u32),
                resume_latency_us: 100,
                vendor: 0,
                vendor_namespace: 0,
                vendor_extension_version: 0,
                reserved2: 0,
            };
            match encode(&reply, &mut msg_buf[..BlockDescribeReply::WIRE_SIZE]) {
                Ok(_) => Ok(BlockDescribeReply::WIRE_SIZE),
                Err(_) => Err(fail(0x9c, 0xe)),
            }
        }
        BlockDeviceIncoming::Read(request) => {
            let status = match read_sector(driver, io, request.sector) {
                Ok(()) => BlockError::Ok,
                // The controller declined or the queue answered wrongly. The
                // driver stays up: one failed request is not a dead device, and
                // a client told so can decide for itself.
                Err(_) => BlockError::IoError,
            };
            let mut payload = [0u8; 64];
            if status == BlockError::Ok {
                payload.copy_from_slice(&data[..64]);
            }
            let reply = BlockReadReply {
                size: BlockReadReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status: status as u32,
                reserved: 0,
                data: payload,
            };
            match encode(&reply, &mut msg_buf[..BlockReadReply::WIRE_SIZE]) {
                Ok(_) => Ok(BlockReadReply::WIRE_SIZE),
                Err(_) => Err(fail(0x9c, 0xe)),
            }
        }
        BlockDeviceIncoming::Write(request) => {
            // Read the sector first, change its first 64 bytes, and write it
            // back. The contract's inline payload is 64 bytes and a block is
            // 512, so writing without reading would zero the rest of a sector
            // the client never asked to touch.
            let mut status = match read_sector(driver, io, request.sector) {
                Ok(()) => BlockError::Ok,
                Err(_) => BlockError::IoError,
            };
            if status == BlockError::Ok {
                data[..64].copy_from_slice(&request.data);
                status = match write_sector(driver, io, request.sector) {
                    Ok(()) => BlockError::Ok,
                    Err(_) => BlockError::IoError,
                };
            }
            let reply = BlockWriteReply {
                size: BlockWriteReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status: status as u32,
                written: if status == BlockError::Ok { 64 } else { 0 },
            };
            match encode(&reply, &mut msg_buf[..BlockWriteReply::WIRE_SIZE]) {
                Ok(_) => Ok(BlockWriteReply::WIRE_SIZE),
                Err(_) => Err(fail(0x9c, 0xe)),
            }
        }
        BlockDeviceIncoming::Reset(_) => {
            // What the contract defines a reset to leave: the ACTIVE power
            // state, and a device that has forgotten nothing a client told it.
            // Here that is the whole controller through its enable handshake
            // again, which is what a reset of an NVMe controller is.
            bring_up(driver, admin_sq, admin_cq, io)?;
            driver.power = BlockPowerState::Active;
            control(BlockError::Ok, BlockPowerState::Active, msg_buf)
        }
        BlockDeviceIncoming::SetPower(request) => match request.state {
            BlockPowerState::Active | BlockPowerState::Idle => {
                driver.power = request.state;
                control(BlockError::Ok, request.state, msg_buf)
            }
            // A state this driver did not report is `NOT_SUPPORTED`, which is
            // what makes the `power_states` mask worth reading.
            _ => control(BlockError::NotSupported, driver.power, msg_buf),
        },
        // Every optional this driver does not advertise, answered the one way
        // the contract permits.
        BlockDeviceIncoming::Flush(_) | BlockDeviceIncoming::Discard(_) => {
            control(BlockError::NotSupported, driver.power, msg_buf)
        }
        // Reached only if the wrapper above did not take them, which it
        // always does; kept so the match stays exhaustive over the contract.
        BlockDeviceIncoming::ReadInto(_) | BlockDeviceIncoming::WriteFrom(_) => {
            control(BlockError::NotSupported, driver.power, msg_buf)
        }
    }
}

/// The whole program: bind, bring the controller up, and serve.
fn run() -> u64 {
    if let Err(code) = bind() {
        return code;
    }
    let base = match map_device(MMIO_VA) {
        Ok(base) => base,
        Err(code) => return code,
    };
    // One page per ring, in the order the constants name them.
    let mut phys = [0u64; 7];
    for (slot, va) in [
        ADMIN_SQ_VA,
        ADMIN_CQ_VA,
        SQ1_VA,
        CQ1_VA,
        SQ2_VA,
        CQ2_VA,
        DATA_VA,
    ]
    .into_iter()
    .enumerate()
    {
        phys[slot] = match dma_page(va) {
            Ok(address) => address,
            Err(code) => return code,
        };
    }
    let admin_sq = page(ADMIN_SQ_VA);
    let admin_cq = page(ADMIN_CQ_VA);
    let sq1 = page(SQ1_VA);
    let cq1 = page(CQ1_VA);
    let sq2 = page(SQ2_VA);
    let cq2 = page(CQ2_VA);
    let data = page(DATA_VA);
    // Index 0 is unused: queue ids start at one, and an unused slot costs a
    // pointer where a map from queue id to ring would cost a lookup on every
    // request.
    let unused_sq = page(DATA_VA);
    let unused_cq = page(DATA_VA);
    let mut io = IoRings {
        sq: [unused_sq, sq1, sq2],
        cq: [unused_cq, cq1, cq2],
    };

    let empty = match CompletionRing::new(1) {
        Ok(ring) => ring,
        Err(_) => return fail(0x9b, 0x700),
    };
    let mut driver = Driver {
        registers: UserRegisters {
            base: base as usize,
        },
        admin_sq_phys: phys[0],
        admin_cq_phys: phys[1],
        io_sq_phys: [0, phys[2], phys[4]],
        io_cq_phys: [0, phys[3], phys[5]],
        data_phys: phys[6],
        admin_tail: 0,
        admin_completions: empty,
        io_tails: [0; 3],
        io_completions: [empty; 3],
        next_cid: 1,
        power: BlockPowerState::Active,
    };
    if let Err(code) = bring_up(&mut driver, admin_sq, admin_cq, &mut io) {
        return code;
    }

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut failure = 0u64;
    // The receive and the reply-and-loop-back are the SDK's; what a block
    // request means is this driver's. `serve` replies with CONTINUE, never a
    // plain reply: a plain one hands off to the caller and blocks the replier,
    // which is right for a server woken by the next call on that endpoint and
    // fatal for one that also parks on its device's ports — nothing would ever
    // hand back.
    let served = tessera_sdk::serve_transfers(
        &mut Machine,
        Endpoint(SdkHandle(CLIENT_ENDPOINT_HANDLE)),
        &mut msg_buf,
        |method, bytes, arrived, out, give_back| {
            // The reader is told how many capabilities arrived, so a request
            // naming a handle index past them is `HandleIndexOutOfRange` here
            // rather than a number this driver goes on to use. Passing zero
            // makes every out-of-line request fail to decode.
            let count = u32::try_from(arrived.len()).unwrap_or(0);
            let request =
                BlockDeviceIncoming::decode(method, &mut Reader::in_message(bytes, count));
            match serve(
                &mut driver,
                admin_sq,
                admin_cq,
                &mut io,
                data,
                method,
                request,
                out,
                arrived,
                give_back,
            ) {
                Ok(pair) => Ok(pair),
                Err(code) => {
                    // A class failure is this driver's, not the platform's, so
                    // it is carried out rather than folded into an SDK error.
                    failure = code;
                    Err(SdkError::NotBound)
                }
            }
        },
    );
    if failure != 0 {
        return failure;
    }
    match served {
        Ok(()) => fail(0x9e, 11),
        Err(_) => fail(0x9e, 1),
    }
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    Machine.finish(value)
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
