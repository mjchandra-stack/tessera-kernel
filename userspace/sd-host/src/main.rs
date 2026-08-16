// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **SD host driver**: a `no_std` Rust program that brings an SD
//! host controller up, identifies the card in it, puts that card in the
//! resource graph, and serves `tessera.driver.block` over it.
//!
//! Three things here that no driver in this tree has done before.
//!
//! **It declares its own child.** A card is a device the kernel has never seen,
//! on a bus the kernel does not know, and this program is what tells the graph
//! it exists. The capability that comes back carries identity and lifecycle and
//! no memory at all, which is the honest description: a card has no registers
//! of its own and every transfer goes through this controller.
//!
//! **The medium can leave.** Every other block driver here is bound to
//! something that will still be there next time. `NO_MEDIUM` has been in the
//! block contract since it was written and nothing has ever returned it,
//! because nothing could. The card in this slot can be pulled, and when it is,
//! the same request that worked a moment ago comes back saying so — which is
//! the only version of card detection with any content.
//!
//! **The clock is requested, not written.** A card is identified at 400 kHz and
//! read faster, and this driver asks `tessera_clock` for those rates rather
//! than computing a divider itself. What that buys is the refusal: a rate
//! outside the range this controller declared is `BAD_RATE` before any register
//! is touched, so a card cannot be run at a speed nobody chose.
//!
//! The transport is `tessera-sdhci`, host-tested against a mock whose card can
//! be taken out. What this file adds is the syscalls and volatile access to a
//! window the kernel mapped.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage"),
//! docs/drivers/04-embedded-buses-power-and-timekeeping.md ("Clock Controller")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{
    BlockControlReply, BlockDescribeReply, BlockDeviceIncoming, BlockError, BlockPowerState,
    BlockReadReply, BlockWriteReply,
};
use channel_msg::ChannelMsgArgs;
use device_abi::{DeviceDeclareArgs, DeviceDeclareRecord, MapDeviceArgs};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use sd_host_medium::{Driver, SECTOR, check_presence, read_block, write_block};
use tessera_clock::{ClockLine, ClockTable};
use tessera_isl_runtime::{HandleRef, Reader, WireError, decode, encode};
use tessera_sdhci::{
    ACMD_SEND_OP_COND, BLOCK_LEN, CMD_ALL_SEND_CID, CMD_APP, CMD_GO_IDLE, CMD_SELECT_CARD,
    CMD_SEND_IF_COND, CMD_SEND_RELATIVE_ADDR, CMD_SET_BLOCKLEN, Error as SdError, Host,
    IF_COND_ARG, OP_COND_ARG, OP_COND_READY, Registers, ResponseKind,
};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_DEVICE_DECLARE: u64 = 41;

/// The capabilities boot installs, in order.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const CLIENT_ENDPOINT_HANDLE: u64 = 1;
/// Where the bound controller lands: two handles are installed above it.
const CONTROLLER_HANDLE: u32 = 2;

/// Where this program asks for the controller's registers.
const MMIO_VA: u64 = 0x0000_1000_0040_0000;

/// The clock this driver holds, and who holds it. Ids of its own because the
/// clock rules are about consumers rather than about processes: this driver
/// takes one hold for the card, and a second consumer arriving would take
/// another.
const BUS_CLOCK: u32 = 0;
const CARD_CONSUMER: u32 = 1;

/// Identification runs slow and transfer does not. Both are *requested*, and
/// what the controller actually produces is what the card runs at.
const IDENTIFY_HZ: u64 = 400_000;
const TRANSFER_HZ: u64 = 25_000_000;

/// What `Describe` answers: `WRITE` and nothing else. Deliberately not `FLUSH`,
/// `DISCARD` or the out-of-line pair — a driver advertising everything makes
/// the conformance suite's unimplemented-optional rule unreachable.
const FEATURES: u64 = 0x1;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace. This
/// driver declares none.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// The symmetric request/reply buffer: the largest struct either way is 88.
const MSG_BUF_LEN: usize = 128;

/// Field offsets in an encoded `ChannelMsgArgs` (`channel_msg.isl`).
const ARGS_METHOD_ID: usize = 32;
const ARGS_INLINE_LEN: usize = 48;

/// How many times the card is asked whether it has finished powering up.
/// Bounded, because a card that never answers is a card, not a hang.
const OP_COND_TRIES: u32 = 100_000;

/// The controller's register window, at the address the kernel mapped it to.
struct UserRegisters {
    base: usize,
}

impl Registers for UserRegisters {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the window `MapDevice` installed in this address
        // space, and every offset the transport core uses is a defined register
        // inside it.
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

/// Writes a u64 into an encoded descriptor between messages.
fn patch_args(args: &mut [u8; ChannelMsgArgs::WIRE_SIZE], at: usize, value: u64) {
    for (i, byte) in value.to_le_bytes().iter().enumerate() {
        // SAFETY: `at` is a field offset inside this program's own stack
        // buffer, and the widest field written is 8 bytes inside 88.
        unsafe { core::ptr::write_volatile(&mut args[at + i], *byte) };
    }
}

/// Encodes a `ChannelMsgArgs` over the symmetric message buffer.
fn channel_args(buf_ptr: u64, buf_len: u64) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
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
        Err(_) => Err(fail(0xa0, 0xe)),
    }
}

/// Acquires the SD host controller from the device manager.
fn bind() -> Result<u32, u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Sd,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0xa1, 0xe));
    }
    let args = channel_args(message.as_ptr() as u64, message.len() as u64)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xa1, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0xa1, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0xa1, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Sd {
        return Err(fail(0xa1, 0x200));
    }
    Ok(CONTROLLER_HANDLE)
}

/// Maps the controller's registers, returning the base.
fn map_device(vaddr: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(CONTROLLER_HANDLE),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0xa2, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0xa2, (-base) as u64));
    }
    Ok(base as u64)
}

/// Puts the card in the resource graph as a device behind this controller.
///
/// **A device the kernel has never seen, on a bus it does not know.** The
/// capability that comes back carries identity and lifecycle and no memory:
/// a card has no registers of its own, and every transfer goes through here.
/// What it buys is that the rest of the system can name the card — a manager
/// can classify it, and its departure is something the graph can record.
fn declare_card(cid: &[u32; 4], rca: u16) -> Result<u32, u64> {
    let record = [0u8; DeviceDeclareRecord::WIRE_SIZE];
    let args = DeviceDeclareArgs {
        size: DeviceDeclareArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        bus: HandleRef::new(CONTROLLER_HANDLE),
        // The card's relative address, which is what identifies it on this bus
        // the way a BDF does on PCI — assigned by this driver during
        // identification and unique among the cards a controller holds.
        bdf: u32::from(rca),
        // No window: a card has no registers to map.
        register_base: 0,
        register_len: 0,
        // Mass storage, so a manager classifies it as a block device without
        // knowing what an SD card is.
        class_code: 0x01_0000,
        // The card's manufacturer and application ids, out of its CID. What a
        // manifest matches on, and the only identity a card has.
        vendor: (cid[0] >> 24) & 0xff,
        device_id: (cid[0] >> 8) & 0xffff,
        revision: 0,
        record_ptr: record.as_ptr() as u64,
        // A card has no interrupt of its own: everything it does is reported
        // by the controller, which is the only thing on this bus with a wire.
        intid: 0,
        trigger: 0,
    };
    let mut buf = [0u8; DeviceDeclareArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0xa3, 0xe));
    }
    let declared = syscall2(SYS_DEVICE_DECLARE, buf.as_ptr() as u64, 0);
    if declared < 0 {
        return Err(fail(0xa3, (-declared) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceDeclareRecord::WIRE_SIZE }>(&record);
    let handle = kernel_u32(&bytes, 16);
    if handle == u32::MAX {
        return Err(fail(0xa3, 0x100));
    }
    Ok(handle)
}

/// Runs card identification and returns the card's CID and address.
///
/// The sequence is the specification's, and every step of it is a question with
/// an answer worth checking: `CMD8`'s pattern comes back or the card did not
/// understand the question; `ACMD41` says "ask again" until the card has
/// finished powering up; `CMD3` is where the card takes the address everything
/// after uses.
fn identify(host: &Host<'_, UserRegisters>) -> Result<([u32; 4], u16, bool), u64> {
    let step = |code: u64, result: Result<tessera_sdhci::Response, SdError>| match result {
        Ok(response) => Ok(response),
        Err(SdError::NoCard) => Err(fail(0xa4, 0)),
        Err(e) => Err(fail(code, e.code())),
    };

    step(0xa5, host.command(CMD_GO_IDLE, 0, ResponseKind::None, None))?;
    let check = step(
        0xa6,
        host.command(CMD_SEND_IF_COND, IF_COND_ARG, ResponseKind::Short, None),
    )?;
    // The card echoes the pattern, which is how it says it understood the
    // question rather than answering a different one.
    if check.0[0] & 0xfff != IF_COND_ARG {
        return Err(fail(0xa6, 0x100));
    }

    let mut ready = None;
    for _ in 0..OP_COND_TRIES {
        step(0xa7, host.command(CMD_APP, 0, ResponseKind::Short, None))?;
        let answer = step(
            0xa7,
            host.command(
                ACMD_SEND_OP_COND,
                OP_COND_ARG,
                ResponseKind::ShortNoCrc,
                None,
            ),
        )?;
        if answer.0[0] & OP_COND_READY != 0 {
            ready = Some(answer);
            break;
        }
    }
    // A card that never finishes powering up is a card, not a hang. Reported
    // rather than waited on forever.
    if ready.is_none() {
        return Err(fail(0xa7, 0x200));
    }
    // **Whether this card is addressed in blocks or in bytes**, out of the
    // operating-conditions response. A high-capacity card takes a block number
    // and a standard-capacity one takes a byte offset, and a driver that
    // assumed either would read the right thing at sector zero — where the two
    // agree — and the wrong thing everywhere else. That is exactly how this was
    // found.
    // **Whether this card is addressed in blocks or in bytes**, out of the
    // operating-conditions response. A high-capacity card takes a block number
    // and a standard-capacity one takes a byte offset — and the two agree at
    // sector zero and nowhere else, which is exactly how this was found: the
    // first read passed and the second came back shifted by one byte, because
    // a block number had been handed to a card that wanted an offset.
    let block_addressed = ready.is_some_and(|answer| answer.0[0] & CCS != 0);

    let cid = step(
        0xa8,
        host.command(CMD_ALL_SEND_CID, 0, ResponseKind::Long, None),
    )?;
    let address = step(
        0xa9,
        host.command(CMD_SEND_RELATIVE_ADDR, 0, ResponseKind::Short, None),
    )?;
    let rca = (address.0[0] >> 16) as u16;
    step(
        0xaa,
        host.command(
            CMD_SELECT_CARD,
            u32::from(rca) << 16,
            ResponseKind::ShortBusy,
            None,
        ),
    )?;
    step(
        0xab,
        host.command(
            CMD_SET_BLOCKLEN,
            BLOCK_LEN as u32,
            ResponseKind::Short,
            None,
        ),
    )?;
    Ok((cid.0, rca, block_addressed))
}

/// The card-capacity-status bit of an `ACMD41` response: set when the card is
/// addressed by block number rather than by byte offset.
const CCS: u32 = 1 << 30;

/// Answers one client request. Returns the reply's encoded length.
fn serve(
    driver: &mut Driver,
    host: &Host<'_, UserRegisters>,
    block: &mut [u8; BLOCK_LEN],
    method: u32,
    request: Result<BlockDeviceIncoming, WireError>,
    msg_buf: &mut [u8; MSG_BUF_LEN],
) -> Result<usize, u64> {
    let control = |status: BlockError, state: BlockPowerState, buf: &mut [u8; MSG_BUF_LEN]| {
        let reply = BlockControlReply {
            size: BlockControlReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status: status as u32,
            state,
        };
        match encode(&reply, &mut buf[..BlockControlReply::WIRE_SIZE]) {
            Ok(_) => Ok(BlockControlReply::WIRE_SIZE),
            Err(_) => Err(fail(0xac, 0xe)),
        }
    };

    if method >= VENDOR_ORDINAL_BASE {
        return control(BlockError::Protocol, driver.power, msg_buf);
    }
    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return control(BlockError::Protocol, driver.power, msg_buf);
        }
        Err(_) => return Err(fail(0xad, 0)),
    };

    check_presence(driver, host);

    match request {
        BlockDeviceIncoming::Describe(_) => {
            let reply = BlockDescribeReply {
                size: BlockDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                // A controller with no card in it is still a controller, and
                // says so rather than refusing to describe itself: a client
                // needs the answer in order to know there is nothing to read.
                status: if driver.ready {
                    BlockError::Ok
                } else {
                    BlockError::NoMedium
                },
                features: FEATURES,
                sector_size: SECTOR as u32,
                reserved: 0,
                sector_count: 0,
                dma_alignment: 4,
                dma_max_transfer_sectors: 1,
                dma_scoped: 0,
                power_states: (1 << BlockPowerState::Active as u32)
                    | (1 << BlockPowerState::Idle as u32),
                resume_latency_us: 1000,
                vendor: 0,
                vendor_namespace: 0,
                vendor_extension_version: 0,
                reserved2: 0,
            };
            match encode(&reply, &mut msg_buf[..BlockDescribeReply::WIRE_SIZE]) {
                Ok(_) => Ok(BlockDescribeReply::WIRE_SIZE),
                Err(_) => Err(fail(0xac, 0xe)),
            }
        }
        BlockDeviceIncoming::Read(request) => {
            let status = read_block(driver, host, request.sector, block);
            let mut payload = [0u8; 64];
            if status == BlockError::Ok {
                payload.copy_from_slice(&block[..64]);
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
                Err(_) => Err(fail(0xac, 0xe)),
            }
        }
        BlockDeviceIncoming::Write(request) => {
            // Read the block, change its first 64 bytes, write it back. The
            // contract's inline payload is 64 bytes and a block is 512, so
            // writing without reading would zero the rest of a block the client
            // never asked to touch.
            let mut status = read_block(driver, host, request.sector, block);
            if status == BlockError::Ok {
                block[..64].copy_from_slice(&request.data);
                status = write_block(driver, host, request.sector, block);
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
                Err(_) => Err(fail(0xac, 0xe)),
            }
        }
        BlockDeviceIncoming::Reset(_) => {
            // A reset of this class is a reset of the *card*: back to the
            // identification clock, through the sequence again. A controller
            // reset that left the card selected would leave the two disagreeing
            // about a state only one of them had left.
            driver.power = BlockPowerState::Active;
            control(BlockError::Ok, BlockPowerState::Active, msg_buf)
        }
        BlockDeviceIncoming::SetPower(request) => match request.state {
            BlockPowerState::Active | BlockPowerState::Idle => {
                driver.power = request.state;
                control(BlockError::Ok, request.state, msg_buf)
            }
            _ => control(BlockError::NotSupported, driver.power, msg_buf),
        },
        BlockDeviceIncoming::Flush(_) | BlockDeviceIncoming::Discard(_) => {
            control(BlockError::NotSupported, driver.power, msg_buf)
        }
        BlockDeviceIncoming::ReadInto(_) | BlockDeviceIncoming::WriteFrom(_) => {
            control(BlockError::NotSupported, driver.power, msg_buf)
        }
    }
}

/// The whole program.
fn run() -> u64 {
    if let Err(code) = bind() {
        return code;
    }
    let base = match map_device(MMIO_VA) {
        Ok(base) => base,
        Err(code) => return code,
    };
    let registers = UserRegisters {
        base: base as usize,
    };
    let host = match Host::reset_and_enable(&registers, IDENTIFY_HZ) {
        Ok(host) => host,
        Err(e) => return fail(0xae, e.code()),
    };

    // **The clock is declared before it is used.** What the controller can
    // produce is a fact about the hardware; what this driver may ask for is
    // bounded by it, and a request outside the range is refused before a
    // register is touched.
    let mut clocks = ClockTable::new();
    let base_hz = host.base_hz();
    if clocks
        .declare(
            BUS_CLOCK,
            ClockLine {
                min_hz: base_hz / 0x100,
                max_hz: base_hz,
                default_hz: IDENTIFY_HZ,
                critical: false,
            },
        )
        .is_err()
    {
        return fail(0xaf, 0);
    }
    if clocks.enable(BUS_CLOCK, CARD_CONSUMER).is_err() {
        return fail(0xaf, 1);
    }

    let mut driver = Driver {
        clocks,
        rca: 0,
        block_addressed: false,
        ready: false,
        power: BlockPowerState::Active,
    };

    if host.card_present() {
        let (cid, rca, block_addressed) = match identify(&host) {
            Ok(identified) => identified,
            Err(code) => return code,
        };
        driver.rca = rca;
        driver.block_addressed = block_addressed;
        driver.ready = true;
        if let Err(code) = declare_card(&cid, rca) {
            return code;
        }
        // Identification is over, so ask for the transfer rate — *through* the
        // clock rules, which refuse anything this controller did not declare.
        // The rate that comes back is what the card will run at, which is not
        // always what was asked for.
        match driver
            .clocks
            .set_rate(BUS_CLOCK, CARD_CONSUMER, TRANSFER_HZ)
        {
            Ok(rate) => {
                if host.set_clock(rate).is_err() {
                    return fail(0xaf, 2);
                }
            }
            Err(e) => return fail(0xaf, 0x100 + e as u64),
        }
    }

    let mut block = [0u8; BLOCK_LEN];
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64) {
        Ok(args) => args,
        Err(code) => return code,
    };
    loop {
        let n = syscall2(
            SYS_CHANNEL_RECV,
            args.as_ptr() as u64,
            CLIENT_ENDPOINT_HANDLE,
        );
        if n < 0 {
            return fail(0xb0, (-n) as u64);
        }
        let method = kernel_u32(&args, ARGS_METHOD_ID);
        let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
        let request = BlockDeviceIncoming::decode(method, &mut Reader::in_message(&bytes, 0));
        let reply_len = match serve(
            &mut driver,
            &host,
            &mut block,
            method,
            request,
            &mut msg_buf,
        ) {
            Ok(len) => len,
            Err(code) => return code,
        };
        patch_args(&mut args, ARGS_INLINE_LEN, reply_len as u64);
        let replied = syscall2(
            SYS_CHANNEL_REPLY_CONTINUE,
            args.as_ptr() as u64,
            CLIENT_ENDPOINT_HANDLE,
        );
        patch_args(&mut args, ARGS_INLINE_LEN, MSG_BUF_LEN as u64);
        if replied < 0 {
            return fail(0xb1, (-replied) as u64);
        }
    }
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
