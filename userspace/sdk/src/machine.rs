// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The [`Platform`](super::Platform) a driver gets on a real machine: syscalls.
//!
//! **This is the file the rest of the SDK exists to make unnecessary to read.**
//! Everything a driver author would otherwise have had to know — the syscall
//! numbers, that arguments arrive as an encoded struct rather than in
//! registers, which `version` each of those structs is on, that a buffer the
//! kernel filled must be read with volatile loads because the compiler did not
//! see it written — is here, once, and nowhere else.
//!
//! It is deliberately thin. Every method does the same three things: encode the
//! argument struct, make the call, turn a negative return into a named
//! [`Error`](super::Error). There is no policy in it, because policy that lived
//! here would be policy a simulator could not reproduce, and a driver that
//! behaved differently on the two would make the simulator worthless.
//!
//! Normative: docs/api/01-system-call-interface.md, docs/drivers/01-driver
//! -framework.md ("Developer Experience")

use super::{Dma, Endpoint, Error, Handle, Platform, Request};
use channel_msg::ChannelMsgArgs;
use device_abi::{DeviceInfoArgs, DmaAllocArgs, IrqCompleteArgs, MapDeviceArgs};
use port_event::PortEventRecord;
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_uabi::{read_kernel_filled, refresh_kernel_filled as refresh, syscall1, syscall2};

/// Syscall numbers — kcore's `SyscallNumber` ordinals, which are the stable
/// ABI. A driver never sees these.
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_PORT_WAIT: u64 = 18;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DMA_ALLOC: u64 = 24;
const SYS_DEVICE_INFO: u64 = 28;
const SYS_IRQ_COMPLETE: u64 = 26;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;

/// Where a request's method ordinal sits in a received `ChannelMsgArgs`.
const ARGS_METHOD_ID: usize = 32;
const ARGS_INLINE_LEN: usize = 48;

/// The machine.
pub struct Machine;

/// Turns a syscall's negative return into something a driver author can read.
///
/// The mapping is small and deliberately lossy: a driver acts on `PeerGone`,
/// `Refused` and `TooLarge` differently and on nothing else differently, so
/// everything past those keeps its number rather than being given a name that
/// implies a distinction nobody uses.
fn error_of(code: i64) -> Error {
    match -code {
        // KError::PeerClosed and the reply-side equivalent.
        11 | 12 => Error::PeerGone,
        // KError::AccessDenied.
        8 => Error::Refused,
        // KError::Protocol — an oversize message is the case a driver meets.
        10 => Error::TooLarge,
        other => Error::Kernel(other),
    }
}

/// Builds the argument struct a channel operation takes.
///
/// Version 4, which is the number that has to be right and is exactly the kind
/// of thing a driver author should never have to know: a stale one is accepted
/// by the encoder and refused by the kernel, at run time, on a machine.
fn channel_args(
    buf_ptr: u64,
    len: u64,
    method: u32,
) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], Error> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: len,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(Error::TooLarge),
    }
}

fn read32(bytes: &[u8], at: usize) -> u32 {
    let mut four = [0u8; 4];
    if at + 4 <= bytes.len() {
        four.copy_from_slice(&bytes[at..at + 4]);
    }
    u32::from_le_bytes(four)
}

impl Platform for Machine {
    fn call(
        &mut self,
        endpoint: Endpoint,
        method: u32,
        request: &[u8],
        reply: &mut [u8],
    ) -> Result<usize, Error> {
        if request.len() > reply.len() {
            // One buffer carries the request out and the reply back, so the
            // caller's reply buffer has to be able to hold the request first.
            return Err(Error::TooLarge);
        }
        reply[..request.len()].copy_from_slice(request);
        let args = channel_args(reply.as_ptr() as u64, reply.len() as u64, method)?;
        let n = syscall2(SYS_CHANNEL_CALL, args.as_ptr() as u64, endpoint.0.0);
        if n < 0 {
            return Err(error_of(n));
        }
        refresh(reply);
        Ok(reply.len())
    }

    fn receive(&mut self, endpoint: Endpoint, into: &mut [u8]) -> Result<Request, Error> {
        let mut args = channel_args(into.as_ptr() as u64, into.len() as u64, 0)?;
        let n = syscall2(SYS_CHANNEL_RECV, args.as_ptr() as u64, endpoint.0.0);
        if n < 0 {
            return Err(error_of(n));
        }
        // The kernel wrote the method and the length back into the argument
        // struct; a plain read would see what this program stored there.
        let filled = read_kernel_filled::<{ ChannelMsgArgs::WIRE_SIZE }>(&args);
        args.copy_from_slice(&filled);
        let len = read32(&args, ARGS_INLINE_LEN) as usize;
        // The message itself, not just the descriptor describing it.
        let filled_to = len.min(into.len());
        refresh(&mut into[..filled_to]);
        Ok(Request {
            method: read32(&args, ARGS_METHOD_ID),
            len,
        })
    }

    fn respond(&mut self, endpoint: Endpoint, reply: &[u8]) -> Result<(), Error> {
        // **`ReplyContinue`, never `Reply`.** A resident server that replies and
        // loops back to its own receive blocks on its own client with the plain
        // form; that mistake has been made twice in this tree (build/README.md
        // D85, D91) and is the single strongest reason for the serve loop to
        // live in one place.
        let args = channel_args(reply.as_ptr() as u64, reply.len() as u64, 0)?;
        let n = syscall2(
            SYS_CHANNEL_REPLY_CONTINUE,
            args.as_ptr() as u64,
            endpoint.0.0,
        );
        if n < 0 {
            return Err(error_of(n));
        }
        Ok(())
    }

    fn map_device(&mut self, device: Handle, va: u64) -> Result<u64, Error> {
        let args = MapDeviceArgs {
            size: MapDeviceArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            device: HandleRef::new(device.0 as u32),
            reserved: 0,
            vaddr: va,
        };
        let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
        if encode(&args, &mut buf).is_err() {
            return Err(Error::TooLarge);
        }
        let n = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
        if n < 0 {
            return Err(error_of(n));
        }
        // **The kernel's answer, not the address that was asked for.** They
        // agree today, and a driver built on that agreement would break the
        // first time they did not — which is precisely the assumption a
        // platform layer exists to stop a driver from making.
        Ok(n as u64)
    }

    fn dma_alloc(&mut self, device: Handle, va: u64) -> Result<Dma, Error> {
        let args = DmaAllocArgs {
            size: DmaAllocArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            device: HandleRef::new(device.0 as u32),
            reserved: 0,
            vaddr: va,
        };
        let mut buf = [0u8; DmaAllocArgs::WIRE_SIZE];
        if encode(&args, &mut buf).is_err() {
            return Err(Error::TooLarge);
        }
        let n = syscall2(SYS_DMA_ALLOC, buf.as_ptr() as u64, 0);
        if n < 0 {
            return Err(error_of(n));
        }
        // The two addresses of one page, and they are not the same number.
        Ok(Dma {
            va,
            device_address: n as u64,
        })
    }

    fn with_dma<R>(&mut self, dma: &Dma, f: impl FnOnce(&mut [u8]) -> R) -> R {
        tessera_uabi::with_dma_page(dma.va, super::dma::PAGE, f)
    }

    fn device_info(&mut self, device: Handle, record: &mut [u8]) -> Result<(), Error> {
        let args = DeviceInfoArgs {
            size: DeviceInfoArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            device: HandleRef::new(device.0 as u32),
            reserved: 0,
            record_ptr: record.as_ptr() as u64,
        };
        let mut buf = [0u8; DeviceInfoArgs::WIRE_SIZE];
        if encode(&args, &mut buf).is_err() {
            return Err(Error::TooLarge);
        }
        let n = syscall2(SYS_DEVICE_INFO, buf.as_ptr() as u64, 0);
        if n < 0 {
            return Err(error_of(n));
        }
        refresh(record);
        Ok(())
    }

    fn wait_for_interrupt(&mut self, port: Handle) -> Result<u64, Error> {
        let mut event = [0u8; PortEventRecord::WIRE_SIZE];
        let n = syscall2(SYS_PORT_WAIT, port.0, event.as_mut_ptr() as u64);
        if n < 0 {
            return Err(error_of(n));
        }
        let bytes = read_kernel_filled::<{ PortEventRecord::WIRE_SIZE }>(&event);
        match decode::<PortEventRecord>(&bytes) {
            Ok(record) => Ok(record.source),
            Err(_) => Err(Error::Kernel(0)),
        }
    }

    fn interrupt_complete(&mut self, device: Handle) -> Result<(), Error> {
        let args = IrqCompleteArgs {
            size: IrqCompleteArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            device: HandleRef::new(device.0 as u32),
            reserved: 0,
        };
        let mut buf = [0u8; IrqCompleteArgs::WIRE_SIZE];
        if encode(&args, &mut buf).is_err() {
            return Err(Error::TooLarge);
        }
        let n = syscall1(SYS_IRQ_COMPLETE, buf.as_ptr() as u64);
        if n < 0 {
            return Err(error_of(n));
        }
        Ok(())
    }

    fn finish(&mut self, report: u64) -> ! {
        let _ = syscall2(SYS_DEBUG_WRITE, report, 0);
        let _ = syscall2(SYS_PROCESS_EXIT, 0, 0);
        loop {
            core::hint::spin_loop();
        }
    }
}
