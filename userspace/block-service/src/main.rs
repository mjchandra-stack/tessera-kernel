// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The block service: one layer above the storage drivers, one below a
//! filesystem.
//!
//! `docs/drivers/02-storage-networking-usb-pcie.md` puts six layers between an
//! application and a device, and names this one's job — "block queues,
//! scheduling, caching, integrity, discard, flush". This is v0 of it, and what
//! it does is deliberately less than that list: it speaks the **same class
//! contract on both sides**, forwarding a client's requests to the driver that
//! holds the device.
//!
//! **The same contract up and down, rather than one of its own.** A block
//! service is a block device — that is what the layer means — so a filesystem
//! written against `block_driver.isl` cannot tell whether it is talking to
//! this or to a driver, and this is held to the same class-conformance battery
//! a driver is. Inventing a second protocol would have meant a second contract
//! to keep in step, and a consumer that had to know which layer it reached.
//!
//! **It holds no dirty state, and that is the design rather than an
//! omission.** `docs/storage/02-file-io-and-caching.md` says the block service
//! "holds no dirty state of its own that can be lost silently, which is what
//! makes its restart survivable". A cache here would be state a restart loses,
//! so v0 has none: every request goes to the device before it is answered.
//! Caching and reordering *between barriers* are allowed by that document and
//! are deferred to when there is something to schedule.
//!
//! **What `Flush` means here is the whole point of the layer.** The durability
//! chain says an acknowledgment may propagate up "only after the block service
//! has issued, and the device has acknowledged, the corresponding cache flush
//! or FUA write". So a `Flush` from a client is a `Flush` to the device, and
//! its status is the device's — never a success this program decided on.
//!
//! Normative: docs/storage/02-file-io-and-caching.md ("The Durability Chain"),
//! docs/drivers/02-storage-networking-usb-pcie.md

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{
    BlockBufferReply, BlockBufferRequest, BlockControlReply, BlockControlRequest,
    BlockDescribeReply, BlockDevice, BlockDeviceIncoming, BlockError, BlockPowerState,
    BlockReadReply, BlockReadRequest, BlockWriteReply, BlockWriteRequest,
};
use tessera_isl_runtime::{Reader, WireError, decode, encode};
use tessera_sdk::{
    Endpoint, Error as SdkError, Handle as SdkHandle, Platform as _, Transfer, machine::Machine,
};
use tessera_uabi::fail;

/// The capabilities boot installs, in order.
///
/// No manager endpoint and no device: this program drives no hardware, so it
/// binds nothing. What it holds is one channel to the driver below and one to
/// the client above — which is the whole of a middle layer's authority.
const DRIVER_ENDPOINT_HANDLE: u64 = 0;
const CLIENT_ENDPOINT_HANDLE: u64 = 1;

/// Sized for the largest struct in either direction, as every program on this
/// contract is: one buffer carries a request out and a reply back.
const MSG_BUF_LEN: usize = 128;

/// One call down to the driver, request in and reply out of `buf`.
///
/// The SDK's `call` uses one buffer for both directions, so `buf` must hold
/// the larger of the two — which is why every program on this contract sizes
/// it to the biggest struct in either direction rather than to the request.
fn down(method: u32, request_len: usize, buf: &mut [u8; MSG_BUF_LEN]) -> Result<(), u64> {
    let mut request = [0u8; MSG_BUF_LEN];
    request[..request_len].copy_from_slice(&buf[..request_len]);
    Machine
        .call(
            Endpoint(SdkHandle(DRIVER_ENDPOINT_HANDLE)),
            method,
            &request[..request_len],
            buf,
        )
        .map(|_| ())
        .map_err(|_| fail(0xb1, u64::from(method)))
}

/// Forwards a request that carries a capability, and brings the capability
/// back.
///
/// The service is a middleman for a *move*: the client's buffer arrives here,
/// goes down to the driver, comes back at a handle the driver's table chose,
/// and goes up at a handle the client's table chooses. Nothing may keep it —
/// a buffer stranded in this process is memory its owner cannot reach and
/// cannot ask for again.
fn down_with_buffer(
    method: u32,
    request_len: usize,
    buf: &mut [u8; MSG_BUF_LEN],
    buffer: SdkHandle,
) -> Result<SdkHandle, u64> {
    let mut request = [0u8; MSG_BUF_LEN];
    request[..request_len].copy_from_slice(&buf[..request_len]);
    let give = [Transfer {
        handle: buffer,
        rights: BlockBufferRequest::BUFFER_RIGHTS,
        shared: false,
    }];
    let mut back = [SdkHandle(0); 1];
    let (_, returned) = Machine
        .call_with(
            Endpoint(SdkHandle(DRIVER_ENDPOINT_HANDLE)),
            method,
            &request[..request_len],
            buf,
            &give,
            &mut back,
        )
        .map_err(|_| fail(0xb2, u64::from(method)))?;
    if returned == 0 {
        // The driver kept the buffer. Nothing this service can do returns it,
        // and reporting rather than inventing one is the only honest answer.
        return Err(fail(0xb3, u64::from(method)));
    }
    Ok(back[0])
}

/// What this service reports when asked to describe itself: the device's own
/// answer, forwarded.
///
/// Not a description of its own. A block service is a block device, and a
/// client that got this layer's opinion of the geometry rather than the
/// device's would be told about a disk nobody has.
fn describe(buf: &mut [u8; MSG_BUF_LEN]) -> Result<usize, u64> {
    let request = BlockControlRequest {
        size: BlockControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: BlockPowerState::Active,
        reserved: 0,
    };
    encode(&request, &mut buf[..BlockControlRequest::WIRE_SIZE]).map_err(|_| fail(0xb4, 0xe))?;
    down(BlockDevice::DESCRIBE, BlockControlRequest::WIRE_SIZE, buf)?;
    Ok(BlockDescribeReply::WIRE_SIZE)
}

/// Answers one client request by asking the driver the same thing.
#[allow(clippy::too_many_arguments)]
fn serve(
    method: u32,
    request: Result<BlockDeviceIncoming, WireError>,
    buf: &mut [u8; MSG_BUF_LEN],
    arrived: &[SdkHandle],
    give_back: &mut [Transfer],
) -> Result<(usize, usize), u64> {
    let protocol = |buf: &mut [u8; MSG_BUF_LEN]| {
        let reply = BlockControlReply {
            size: BlockControlReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status: BlockError::Protocol as u32,
            state: BlockPowerState::Active,
        };
        match encode(&reply, &mut buf[..BlockControlReply::WIRE_SIZE]) {
            Ok(_) => Ok((BlockControlReply::WIRE_SIZE, 0)),
            Err(_) => Err(fail(0xb5, 0xe)),
        }
    };

    let Ok(request) = request else {
        return protocol(buf);
    };

    match request {
        BlockDeviceIncoming::Describe(_) => describe(buf).map(|len| (len, 0)),
        BlockDeviceIncoming::Read(read) => {
            let out = BlockReadRequest {
                size: BlockReadRequest::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                sector: read.sector,
            };
            encode(&out, &mut buf[..BlockReadRequest::WIRE_SIZE]).map_err(|_| fail(0xb6, 0xe))?;
            down(BlockDevice::READ, BlockReadRequest::WIRE_SIZE, buf)?;
            Ok((BlockReadReply::WIRE_SIZE, 0))
        }
        BlockDeviceIncoming::Write(write) => {
            let out = BlockWriteRequest {
                size: BlockWriteRequest::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                sector: write.sector,
                data: write.data,
            };
            encode(&out, &mut buf[..BlockWriteRequest::WIRE_SIZE]).map_err(|_| fail(0xb7, 0xe))?;
            down(BlockDevice::WRITE, BlockWriteRequest::WIRE_SIZE, buf)?;
            Ok((BlockWriteReply::WIRE_SIZE, 0))
        }
        // **The durability chain, and the one thing this layer must not get
        // wrong.** A flush from a client is a flush to the device, and the
        // status a client sees is the device's. This service never decides a
        // flush succeeded — it holds nothing to flush, so a success of its own
        // would be a durability statement about nobody's data.
        BlockDeviceIncoming::Flush(_) | BlockDeviceIncoming::Reset(_) => {
            let out = BlockControlRequest {
                size: BlockControlRequest::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                state: BlockPowerState::Active,
                reserved: 0,
            };
            encode(&out, &mut buf[..BlockControlRequest::WIRE_SIZE])
                .map_err(|_| fail(0xb8, 0xe))?;
            down(method, BlockControlRequest::WIRE_SIZE, buf)?;
            Ok((BlockControlReply::WIRE_SIZE, 0))
        }
        BlockDeviceIncoming::SetPower(control) => {
            let out = BlockControlRequest {
                size: BlockControlRequest::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                state: control.state,
                reserved: 0,
            };
            encode(&out, &mut buf[..BlockControlRequest::WIRE_SIZE])
                .map_err(|_| fail(0xb9, 0xe))?;
            down(BlockDevice::SET_POWER, BlockControlRequest::WIRE_SIZE, buf)?;
            Ok((BlockControlReply::WIRE_SIZE, 0))
        }
        BlockDeviceIncoming::Discard(discard) => {
            let out = BlockWriteRequest {
                size: BlockWriteRequest::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                sector: discard.sector,
                data: discard.data,
            };
            encode(&out, &mut buf[..BlockWriteRequest::WIRE_SIZE]).map_err(|_| fail(0xba, 0xe))?;
            down(BlockDevice::DISCARD, BlockWriteRequest::WIRE_SIZE, buf)?;
            Ok((BlockControlReply::WIRE_SIZE, 0))
        }
        BlockDeviceIncoming::ReadInto(buffer) | BlockDeviceIncoming::WriteFrom(buffer) => {
            let Some(handle) = arrived.first().copied() else {
                let reply = BlockBufferReply {
                    size: BlockBufferReply::WIRE_SIZE as u32,
                    version: 1,
                    flags: 0,
                    status: BlockError::Protocol as u32,
                    reserved: 0,
                    transferred: 0,
                };
                encode(&reply, &mut buf[..BlockBufferReply::WIRE_SIZE])
                    .map_err(|_| fail(0xbb, 0xe))?;
                return Ok((BlockBufferReply::WIRE_SIZE, 0));
            };
            let out = BlockBufferRequest {
                size: BlockBufferRequest::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                sector: buffer.sector,
                length: buffer.length,
                // Index into *this* message's handle vector, which is where
                // the one being sent down will sit — not the number it arrived
                // at here.
                buffer: tessera_isl_runtime::HandleRef::new(0),
            };
            encode(&out, &mut buf[..BlockBufferRequest::WIRE_SIZE]).map_err(|_| fail(0xbc, 0xe))?;
            let returned = down_with_buffer(method, BlockBufferRequest::WIRE_SIZE, buf, handle)?;
            // Straight back up to the client, at whatever number its table
            // gives it.
            give_back[0] = Transfer {
                handle: returned,
                rights: BlockBufferRequest::BUFFER_RIGHTS,
                shared: false,
            };
            Ok((BlockBufferReply::WIRE_SIZE, 1))
        }
    }
}

fn run() -> u64 {
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut failure = 0u64;
    let served = tessera_sdk::serve_transfers(
        &mut Machine,
        Endpoint(SdkHandle(CLIENT_ENDPOINT_HANDLE)),
        &mut msg_buf,
        |_platform, method, bytes, arrived, out, give_back| {
            let count = u32::try_from(arrived.len()).unwrap_or(0);
            let request =
                BlockDeviceIncoming::decode(method, &mut Reader::in_message(bytes, count));
            let mut buf = [0u8; MSG_BUF_LEN];
            let copy = bytes.len().min(MSG_BUF_LEN);
            buf[..copy].copy_from_slice(&bytes[..copy]);
            match serve(method, request, &mut buf, arrived, give_back) {
                Ok((len, handles)) if len <= out.len() => {
                    out[..len].copy_from_slice(&buf[..len]);
                    Ok((len, handles))
                }
                Ok(_) => Err(SdkError::TooLarge),
                Err(code) => {
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
        Ok(()) => fail(0xbd, 11),
        Err(_) => fail(0xbd, 1),
    }
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in this
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    Machine.finish(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    Machine.finish(fail(0xff, 0))
}
