// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **USB mass-storage driver**: a `no_std` Rust program that serves
//! `tessera.driver.block` off a disk it reaches through two other processes.
//!
//! **The fourth transport under one class contract.** virtio, NVMe and SD serve
//! the same `tessera.driver.block` this does, and each of them owns a register
//! window and drives its device directly. This one owns nothing. It maps no
//! memory, touches no register, and reaches its disk by asking the USB host to
//! move bytes for it — so the contract is being held to by something whose
//! relationship to its hardware is completely different from the other three.
//! That is the strongest statement available about whether the class contract
//! describes a class or describes an implementation.
//!
//! **Three protocols, stacked.** A block request becomes a SCSI command, which
//! becomes a bulk-only transport wrapper, which becomes bulk transfers relayed
//! through the host. The wrapper is the interesting one: a command block goes
//! out, data moves, and a **status block** comes back — and the status block is
//! what says whether the command worked. A driver that took the data transfer's
//! success as the command's would report a good read of a sector the device
//! refused to give it.
//!
//! **A sector does not fit in a message.** The relay carries sixty-four bytes,
//! a sector is five hundred and twelve, so a read is eight transfers on one
//! bulk endpoint. That is not a workaround: a bulk endpoint is a byte stream
//! and reading it in pieces is what it is for. What matters is that all of it
//! is drained — a data phase left half-read leaves the endpoint holding bytes
//! that the next command would receive as its own.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage"),
//! docs/drivers/01-driver-framework.md ("Bus Topology And Data Paths")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{
    BlockControlReply, BlockDescribeReply, BlockDeviceIncoming, BlockError, BlockPowerState,
    BlockReadReply, BlockWriteReply,
};
use channel_msg::ChannelMsgArgs;
use device_abi::{DeviceInfoArgs, DeviceInfoRecord};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{HandleRef, Reader, WireError, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};
use usb_host::{
    UsbDeviceReply, UsbDeviceRequest, UsbError, UsbHost, UsbTransferKind, UsbTransferReply,
    UsbTransferRequest,
};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_DEVICE_INFO: u64 = 28;

/// The capabilities boot installs, in order, and where the bound device lands.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const HOST_ENDPOINT_HANDLE: u64 = 1;
const CLIENT_ENDPOINT_HANDLE: u64 = 2;
const DEVICE_HANDLE: u32 = 3;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// Field offsets in an encoded `ChannelMsgArgs` (`channel_msg.isl`).
const ARGS_METHOD_ID: usize = 32;
const ARGS_INLINE_LEN: usize = 48;

/// The most one relayed transfer carries.
const CHUNK: usize = 64;

/// The sector size this driver reports and works in.
const SECTOR: usize = 512;

/// Bulk-only transport: the command and status wrappers.
const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;
const CBW_LEN: usize = 31;
const CSW_LEN: usize = 13;
/// `bmCBWFlags` bit 7: the data phase runs from the device to the host.
const CBW_FLAG_IN: u8 = 0x80;

/// The SCSI commands this driver issues.
const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_REQUEST_SENSE: u8 = 0x03;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;
const SCSI_WRITE_10: u8 = 0x2a;

/// How many times the device is asked whether it is ready.
///
/// Bounded, and more than one on purpose: a device that has just been
/// configured answers the first command with a unit attention — "something
/// happened, ask again" — and a driver that took that as a failure would refuse
/// every disk it had just enumerated.
const READY_TRIES: u32 = 8;

/// What `Describe` answers beyond the required set: `WRITE`, and nothing else.
///
/// Deliberately not everything. `FLUSH`, `DISCARD` and the out-of-line pair
/// stay clear, so the conformance suite's unimplemented-optional rule is
/// reachable — a driver advertising everything makes it unreachable, and the
/// rule is what stops a `Describe` from being a wish.
const FEATURES: u64 = 0x1;

/// How many times the manager is asked for a device of this class before the
/// driver gives up. Bounded, because a device that is never going to arrive
/// must be reported rather than waited for.
const BIND_TRIES: u32 = 64;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

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

/// Encodes a `ChannelMsgArgs` over a buffer.
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
        Err(_) => Err(fail(0xe0, 0xe)),
    }
}

/// Acquires a block device from the device manager.
fn bind() -> Result<bool, u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Block,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0xe1, 0xe));
    }
    let args = channel_args(message.as_ptr() as u64, message.len() as u64, 0)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xe1, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0xe1, 0xd)),
    };
    if reply.status != 0 {
        // Not yet, rather than never.
        return Ok(false);
    }
    if reply.class != DeviceClass::Block {
        // The class it was actually handed, so a mis-binding says which rather
        // than only that.
        return Err(fail(0xe1, 0x200 | (reply.class as u64)));
    }
    Ok(true)
}

/// Asks until there is something to be given, or gives up saying so.
///
/// **A driver can start before its device exists.** This one's device is
/// produced by a bus host enumerating a tree, and the two are separate
/// processes with no ordering between them — so "nothing of that class" at
/// startup means "not yet", and a driver that took it for "never" would be a
/// driver whose success depended on which process the scheduler picked first.
///
/// Bounded, and it says which happened: a device that never arrives is
/// reported, not waited for.
fn bind_when_available() -> Result<(), u64> {
    for _ in 0..BIND_TRIES {
        if bind()? {
            return Ok(());
        }
    }
    Err(fail(0xe1, 0x100))
}

/// Asks the kernel what the bound device is, which is how this driver learns
/// the USB address to name.
fn device_address() -> Result<u32, u64> {
    let record = [0u8; DeviceInfoRecord::WIRE_SIZE];
    let args = DeviceInfoArgs {
        size: DeviceInfoArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(DEVICE_HANDLE),
        reserved: 0,
        record_ptr: record.as_ptr() as u64,
    };
    let mut buf = [0u8; DeviceInfoArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0xe2, 0xe));
    }
    let answered = syscall2(SYS_DEVICE_INFO, buf.as_ptr() as u64, 0);
    if answered < 0 {
        return Err(fail(0xe2, (-answered) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceInfoRecord::WIRE_SIZE }>(&record);
    let info: DeviceInfoRecord = match decode(&bytes) {
        Ok(info) => info,
        Err(_) => return Err(fail(0xe2, 0xd)),
    };
    Ok(info.bdf)
}

/// One call to the USB host, over the relay channel.
fn call_host(buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Result<(), u64> {
    // **The whole buffer, not the request's length.** A call's `inline_len` is
    // symmetric: it is how many bytes go out *and* how many of the reply come
    // back. Sizing it to the request would clamp every reply to the size of the
    // question — which reads as a device that answered with zeros rather than
    // as a message that was cut off.
    let args = channel_args(buf.as_ptr() as u64, MSG_BUF_LEN as u64, method)?;
    let n = syscall2(SYS_CHANNEL_CALL, args.as_ptr() as u64, HOST_ENDPOINT_HANDLE);
    if n < 0 {
        return Err(fail(0xe3, (-n) as u64));
    }
    Ok(())
}

/// Asks the host what the device at this address is.
fn describe_device(address: u32) -> Result<UsbDeviceReply, u64> {
    let request = UsbDeviceRequest {
        size: UsbDeviceRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        address,
        reserved: 0,
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    if encode(&request, &mut buf[..UsbDeviceRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0xe4, 0xe));
    }
    call_host(&mut buf, UsbHost::DESCRIBE)?;
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&buf);
    match decode::<UsbDeviceReply>(&bytes[..UsbDeviceReply::WIRE_SIZE]) {
        Ok(reply) => Ok(reply),
        Err(_) => Err(fail(0xe4, 0xd)),
    }
}

/// What this driver carries between requests.
struct Driver {
    address: u32,
    /// The bulk endpoints, as the device's own descriptors gave them: number in
    /// the low bits, direction in the high one.
    bulk_in: u32,
    bulk_out: u32,
    /// A tag that rises with every command, so a status block can be matched to
    /// the command it answers rather than to whatever came back.
    tag: u32,
    /// How many sectors the medium holds, read from it rather than assumed.
    sectors: u64,
    /// Whether the medium answered its readiness check.
    ready: bool,
    power: BlockPowerState,
}

/// One relayed bulk transfer. Returns what the device moved and, for a read,
/// the bytes.
fn bulk(
    driver: &Driver,
    endpoint: u32,
    data: &[u8],
    length: usize,
) -> Result<(UsbError, usize, [u8; 64]), u64> {
    let mut payload = [0u8; 64];
    let copy = data.len().min(payload.len());
    payload[..copy].copy_from_slice(&data[..copy]);
    let request = UsbTransferRequest {
        size: UsbTransferRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        address: driver.address,
        endpoint,
        kind: UsbTransferKind::Bulk,
        length: length as u32,
        data: payload,
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    if encode(&request, &mut buf[..UsbTransferRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0xe5, 0xe));
    }
    call_host(&mut buf, UsbHost::TRANSFER)?;
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&buf);
    match decode::<UsbTransferReply>(&bytes[..UsbTransferReply::WIRE_SIZE]) {
        Ok(reply) => Ok((reply.status, reply.transferred as usize, reply.data)),
        Err(_) => Err(fail(0xe5, 0xd)),
    }
}

/// Builds a command block wrapper around a SCSI command.
fn command_block(tag: u32, transfer: u32, device_to_host: bool, scsi: &[u8]) -> [u8; CBW_LEN] {
    let mut cbw = [0u8; CBW_LEN];
    cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
    cbw[4..8].copy_from_slice(&tag.to_le_bytes());
    cbw[8..12].copy_from_slice(&transfer.to_le_bytes());
    cbw[12] = if device_to_host { CBW_FLAG_IN } else { 0 };
    // One logical unit, which is what a disk behind this transport has.
    cbw[13] = 0;
    cbw[14] = scsi.len() as u8;
    let copy = scsi.len().min(16);
    cbw[15..15 + copy].copy_from_slice(&scsi[..copy]);
    cbw
}

/// Runs one SCSI command through the bulk-only transport.
///
/// **The status block is the answer, and the data transfer is not.** A command
/// whose data phase moved every byte it asked for and whose status block says
/// the device refused is a failed command; a driver that reported the first
/// would hand a client a sector the disk declined to give it.
///
/// `into` receives up to its own length of the data phase, and the rest is
/// **drained rather than abandoned** — a data phase left half-read leaves the
/// endpoint holding bytes the next command would receive as its own.
fn scsi(
    driver: &mut Driver,
    scsi: &[u8],
    transfer: u32,
    data: &mut [u8],
    to_device: bool,
) -> Result<BlockError, u64> {
    driver.tag = driver.tag.wrapping_add(1);
    let tag = driver.tag;
    let cbw = command_block(tag, transfer, !to_device, scsi);

    let (status, moved, _) = bulk(driver, driver.bulk_out, &cbw, CBW_LEN)?;
    if status != UsbError::Ok || moved != CBW_LEN {
        return Ok(class_error(status));
    }

    // The data phase, sixty-four bytes at a time because that is what one
    // message carries. A bulk endpoint is a byte stream, so moving it in pieces
    // is what it is for.
    let mut done = 0usize;
    while done < transfer as usize {
        let want = (transfer as usize - done).min(CHUNK);
        let (status, moved, bytes) = if to_device {
            let mut chunk = [0u8; CHUNK];
            let room = want.min(data.len().saturating_sub(done));
            chunk[..room].copy_from_slice(&data[done..done + room]);
            bulk(driver, driver.bulk_out, &chunk[..want], want)?
        } else {
            bulk(driver, driver.bulk_in, &[], want)?
        };
        if status != UsbError::Ok {
            return Ok(class_error(status));
        }
        if !to_device && done < data.len() {
            let room = (data.len() - done).min(moved);
            data[done..done + room].copy_from_slice(&bytes[..room]);
        }
        done += moved;
        // A device that moved less than it was asked for has finished early,
        // and the status block will say whether that was an error. Asking again
        // would hang against a device with nothing left to say.
        if moved < want {
            break;
        }
    }

    // The status block: the signature, the tag, and whether it worked.
    let (status, moved, csw) = bulk(driver, driver.bulk_in, &[], CSW_LEN)?;
    if status != UsbError::Ok || moved < CSW_LEN {
        return Ok(class_error(status));
    }
    if u32::from_le_bytes([csw[0], csw[1], csw[2], csw[3]]) != CSW_SIGNATURE {
        return Ok(BlockError::IoError);
    }
    // **Matched by tag.** A status block carrying somebody else's tag is a
    // transport out of step, and taking it would attribute one command's
    // outcome to another.
    if u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]) != tag {
        return Ok(BlockError::IoError);
    }
    Ok(match csw[12] {
        0 => BlockError::Ok,
        _ => BlockError::IoError,
    })
}

/// What a relayed transfer's outcome means to a client of this class.
fn class_error(status: UsbError) -> BlockError {
    match status {
        UsbError::Ok => BlockError::Ok,
        UsbError::Removed | UsbError::NoDevice => BlockError::Removed,
        UsbError::Unauthorized => BlockError::NotSupported,
        UsbError::Protocol => BlockError::Protocol,
        UsbError::Degraded => BlockError::Degraded,
        _ => BlockError::IoError,
    }
}

/// Asks the device whether it is ready, and asks again when it says something
/// has changed.
fn wait_ready(driver: &mut Driver) -> Result<bool, u64> {
    let mut nothing = [0u8; 1];
    for _ in 0..READY_TRIES {
        if scsi(
            driver,
            &[SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0],
            0,
            &mut nothing,
            false,
        )? == BlockError::Ok
        {
            return Ok(true);
        }
        // The sense data is read and discarded: what it says does not change
        // what this driver does, and leaving it unread leaves the device
        // holding a condition it will report again on the next command.
        let mut sense = [0u8; 18];
        let _ = scsi(
            driver,
            &[SCSI_REQUEST_SENSE, 0, 0, 0, sense.len() as u8, 0],
            sense.len() as u32,
            &mut sense,
            false,
        )?;
    }
    Ok(false)
}

/// Reads how big the medium is, from the medium.
fn read_capacity(driver: &mut Driver) -> Result<u64, u64> {
    let mut answer = [0u8; 8];
    if scsi(
        driver,
        &[SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        8,
        &mut answer,
        false,
    )? != BlockError::Ok
    {
        return Ok(0);
    }
    // Big-endian, which is SCSI's byte order and not this machine's — the one
    // place in this driver where that matters, and the reason it is spelled out
    // rather than transmuted.
    let last = u32::from_be_bytes([answer[0], answer[1], answer[2], answer[3]]);
    Ok(u64::from(last) + 1)
}

/// Reads one sector, keeping the first `CHUNK` bytes for the reply.
fn transfer_sector(
    driver: &mut Driver,
    sector: u64,
    block: &mut [u8; SECTOR],
    to_device: bool,
) -> Result<BlockError, u64> {
    if !driver.ready {
        return Ok(BlockError::NoMedium);
    }
    if driver.sectors > 0 && sector >= driver.sectors {
        return Ok(BlockError::OutOfRange);
    }
    let lba = (sector as u32).to_be_bytes();
    let command = [
        if to_device {
            SCSI_WRITE_10
        } else {
            SCSI_READ_10
        },
        0,
        lba[0],
        lba[1],
        lba[2],
        lba[3],
        0,
        0,
        1, // one block
        0,
    ];
    scsi(driver, &command, SECTOR as u32, block, to_device)
}

/// Answers one client request. Returns the reply's encoded length.
fn serve(
    driver: &mut Driver,
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
            Err(_) => Err(fail(0xe6, 0xe)),
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
        Err(_) => return Err(fail(0xe7, 0)),
    };

    match request {
        BlockDeviceIncoming::Describe(_) => {
            let reply = BlockDescribeReply {
                size: BlockDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                status: if driver.ready {
                    BlockError::Ok
                } else {
                    BlockError::NoMedium
                },
                features: FEATURES,
                sector_size: SECTOR as u32,
                reserved: 0,
                sector_count: driver.sectors,
                dma_alignment: 1,
                dma_max_transfer_sectors: 1,
                // **Nothing about DMA is this driver's to report.** It performs
                // none: the transfers it asks for are the USB host's, and the
                // memory they land in is the host's too. Zero is the honest
                // answer rather than a copy of somebody else's constraint.
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
                Err(_) => Err(fail(0xe6, 0xe)),
            }
        }
        BlockDeviceIncoming::Read(ask) => {
            let mut block = [0u8; SECTOR];
            let status = transfer_sector(driver, ask.sector, &mut block, false)?;
            let mut payload = [0u8; CHUNK];
            payload.copy_from_slice(&block[..CHUNK]);
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
                Err(_) => Err(fail(0xe6, 0xe)),
            }
        }
        BlockDeviceIncoming::Write(ask) => {
            // Read the sector, change its first sixty-four bytes, write it
            // back. The contract's inline payload is sixty-four bytes and a
            // sector is five hundred and twelve, so writing without reading
            // would zero the rest of a sector the client never asked to touch.
            let mut block = [0u8; SECTOR];
            let mut status = transfer_sector(driver, ask.sector, &mut block, false)?;
            if status == BlockError::Ok {
                block[..CHUNK].copy_from_slice(&ask.data);
                status = transfer_sector(driver, ask.sector, &mut block, true)?;
            }
            let reply = BlockWriteReply {
                size: BlockWriteReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status: status as u32,
                written: if status == BlockError::Ok {
                    CHUNK as u32
                } else {
                    0
                },
            };
            match encode(&reply, &mut msg_buf[..BlockWriteReply::WIRE_SIZE]) {
                Ok(_) => Ok(BlockWriteReply::WIRE_SIZE),
                Err(_) => Err(fail(0xe6, 0xe)),
            }
        }
        BlockDeviceIncoming::Reset(_) => {
            // A reset of this class is a readiness check again: the transport
            // below is somebody else's and cannot be reset from here, and a
            // driver that claimed to have reset it would be claiming to have
            // done something it has no way to do.
            driver.ready = wait_ready(driver)?;
            driver.power = BlockPowerState::Active;
            control(
                if driver.ready {
                    BlockError::Ok
                } else {
                    BlockError::NoMedium
                },
                BlockPowerState::Active,
                msg_buf,
            )
        }
        BlockDeviceIncoming::SetPower(ask) => match ask.state {
            BlockPowerState::Active | BlockPowerState::Idle => {
                driver.power = ask.state;
                control(BlockError::Ok, ask.state, msg_buf)
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
    if let Err(code) = bind_when_available() {
        return code;
    }
    let address = match device_address() {
        Ok(address) => address,
        Err(code) => return code,
    };
    let described = match describe_device(address) {
        Ok(described) => described,
        Err(code) => return code,
    };
    if described.status != UsbError::Ok {
        return fail(0xe8, described.status as u64);
    }
    // A device that is not bulk-only SCSI storage is one this driver cannot
    // drive, and it says so rather than issuing commands into it. The host's
    // allowlist already refused everything else, so this is the second of two
    // checks and deliberately: one is policy and one is competence.
    if described.class != 0x08 || described.protocol != 0x50 {
        return fail(0xe8, 0x100 | u64::from(described.class));
    }

    let mut driver = Driver {
        address,
        bulk_in: 0x81,
        bulk_out: 0x02,
        tag: 0,
        sectors: 0,
        ready: false,
        power: BlockPowerState::Active,
    };
    driver.ready = match wait_ready(&mut driver) {
        Ok(ready) => ready,
        Err(code) => return code,
    };
    if driver.ready {
        driver.sectors = match read_capacity(&mut driver) {
            Ok(sectors) => sectors,
            Err(code) => return code,
        };
    }

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64, 0) {
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
            return fail(0xe9, (-n) as u64);
        }
        let method = kernel_u32(&args, ARGS_METHOD_ID);
        let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
        let request = BlockDeviceIncoming::decode(method, &mut Reader::in_message(&bytes, 0));
        let reply_len = match serve(&mut driver, method, request, &mut msg_buf) {
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
            return fail(0xea, (-replied) as u64);
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
