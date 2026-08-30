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

use super::{Dma, Endpoint, Error, Handle, Platform, Request, Transfer};
use channel_msg::{
    ChannelCreateArgs, ChannelCreateRecord, ChannelMsgArgs, HandleTransfer,
    Rights as ChannelRights, TransferMode,
};
use device_abi::{DeviceInfoArgs, DmaAllocArgs, IrqCompleteArgs, MapDeviceArgs};
use memory_abi::{
    DmaAttachArgs, DmaDetachArgs, MapRights, MemoryConstraint, MemoryCreateArgs,
    MemoryCreatePagedArgs, MemoryDirtyPagesArgs, MemoryMapArgs, PageSupplyArgs,
    PageWrittenBackArgs,
};
use port_event::PortEventRecord;
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_uabi::{
    read_kernel_filled, refresh_kernel_filled as refresh, syscall1, syscall2, syscall3,
};

/// Syscall numbers — kcore's `SyscallNumber` ordinals, which are the stable
/// ABI. A driver never sees these.
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CREATE: u64 = 11;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_RECV_ANY: u64 = 43;
const SYS_CLOCK_READ: u64 = 53;
const CLOCK_MONOTONIC: u64 = 1;
const SYS_HANDLE_DUPLICATE: u64 = 2;
const SYS_MEMORY_CREATE_PAGED: u64 = 45;
const SYS_MAP_OBJECT: u64 = 46;
const SYS_PAGE_SUPPLY: u64 = 22;
const SYS_MEMORY_DIRTY_PAGES: u64 = 47;
const SYS_PAGE_WRITTEN_BACK: u64 = 48;
const SYS_HANDLE_CLOSE: u64 = 4;
const SYS_MEMORY_UNMAP: u64 = 49;
const SYS_PORT_WAIT: u64 = 18;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DMA_ALLOC: u64 = 24;
const SYS_DEVICE_INFO: u64 = 28;
const SYS_IRQ_COMPLETE: u64 = 26;
const SYS_MEMORY_CREATE: u64 = 30;
const SYS_MEMORY_MAP: u64 = 31;
const SYS_DMA_ATTACH: u64 = 32;
const SYS_DMA_DETACH: u64 = 33;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;

/// Where a request's method ordinal sits in a received `ChannelMsgArgs`.
const ARGS_METHOD_ID: usize = 32;
/// The kernel writes the answering endpoint's index here on a wait-on-many.
const ARGS_MSG_FLAGS: usize = 36;
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
    // **The word is `-((domain << 16) | code)`, and this used to compare the
    // whole of it against a bare code** — so with `ErrorDomain::Kernel = 1`,
    // `PeerClosed` arrives as 65548 and the `12` arm never matched. Every
    // named error here fell through to `Kernel`, which is why the callers that
    // act on `PeerGone` appeared to work: their catch-alls were doing it.
    // Found by adding `TimedOut` and watching a service break instead of time
    // out (build/README.md, D282).
    let word = -code;
    let domain = word >> 16;
    match (domain, word & 0xffff) {
        // KError::PeerClosed and the reply-side equivalent, in the kernel
        // domain.
        (1, 11) | (1, 12) => Error::PeerGone,
        // KError::AccessDenied, which is the security-policy domain.
        (2, 8) => Error::Refused,
        // KError::Protocol — an oversize message is the case a driver meets —
        // in the protocol domain.
        (4, 10) => Error::TooLarge,
        // KError::TimedOut.
        (1, 17) => Error::TimedOut,
        _ => Error::Kernel(word),
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
    carrying_args(buf_ptr, len, method, 0, 0, 0, 0)
}

/// The same descriptor, with a handle vector and a place for the kernel to
/// report where it installed what arrived.
#[allow(clippy::too_many_arguments)]
fn carrying_args(
    buf_ptr: u64,
    len: u64,
    method: u32,
    handles_ptr: u64,
    handle_count: u64,
    installed_ptr: u64,
    installed_cap: u64,
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
        handles_ptr,
        handle_count,
        installed_ptr,
        installed_cap,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(Error::TooLarge),
    }
}

/// Encodes `give` into `out`, returning the bytes used.
///
/// The mode comes from each descriptor now (D286). `Snapshot` is still not
/// offered: the kernel does not implement it, so a call that could ask for it
/// would be a call that fails at run time instead of not compiling.
fn encode_transfers(
    give: &[Transfer],
    out: &mut [u8; HandleTransfer::WIRE_SIZE * super::MAX_TRANSFER],
) -> Result<usize, Error> {
    if give.len() > super::MAX_TRANSFER {
        return Err(Error::TooLarge);
    }
    for (index, transfer) in give.iter().enumerate() {
        let descriptor = HandleTransfer {
            mode: if transfer.shared {
                TransferMode::Share
            } else {
                TransferMode::Transfer
            },
            rights: transfer.rights,
            handle: u32::try_from(transfer.handle.0).map_err(|_| Error::TooLarge)?,
        };
        let at = index * HandleTransfer::WIRE_SIZE;
        encode(&descriptor, &mut out[at..at + HandleTransfer::WIRE_SIZE])
            .map_err(|_| Error::TooLarge)?;
    }
    Ok(give.len() * HandleTransfer::WIRE_SIZE)
}

fn read32(bytes: &[u8], at: usize) -> u32 {
    let mut four = [0u8; 4];
    if at + 4 <= bytes.len() {
        four.copy_from_slice(&bytes[at..at + 4]);
    }
    u32::from_le_bytes(four)
}

impl Platform for Machine {
    fn call_until(
        &mut self,
        endpoint: Endpoint,
        method: u32,
        request: &[u8],
        reply: &mut [u8],
        deadline: Option<u64>,
    ) -> Result<usize, Error> {
        if request.len() > reply.len() {
            // One buffer carries the request out and the reply back, so the
            // caller's reply buffer has to be able to hold the request first.
            return Err(Error::TooLarge);
        }
        reply[..request.len()].copy_from_slice(request);
        let args = channel_args(reply.as_ptr() as u64, reply.len() as u64, method)?;
        // **Three arguments, and the third is passed even when there is no
        // deadline.** Zero is the ABI's "wait as long as it takes" (D283), and
        // a program that left the register alone would hand the kernel
        // whatever the compiler had put there — a stack address read as a
        // deadline in nanoseconds, which is either no bound at all or an
        // immediate expiry depending on the value. An argument register is
        // only unused until the day it is not.
        let n = syscall3(
            SYS_CHANNEL_CALL,
            args.as_ptr() as u64,
            endpoint.0.0,
            deadline.unwrap_or(0),
        );
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
            handles: 0,
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

    fn call_with(
        &mut self,
        endpoint: Endpoint,
        method: u32,
        request: &[u8],
        reply: &mut [u8],
        give: &[Transfer],
        take: &mut [Handle],
    ) -> Result<(usize, usize), Error> {
        if request.len() > reply.len() {
            return Err(Error::TooLarge);
        }
        reply[..request.len()].copy_from_slice(request);
        let mut vector = [0u8; HandleTransfer::WIRE_SIZE * super::MAX_TRANSFER];
        encode_transfers(give, &mut vector)?;
        if take.len() > super::MAX_TRANSFER {
            return Err(Error::TooLarge);
        }
        // The kernel reports each installed handle as a u32, positionally.
        let mut installed = [0u8; 4 * super::MAX_TRANSFER];
        let args = carrying_args(
            reply.as_ptr() as u64,
            reply.len() as u64,
            method,
            if give.is_empty() {
                0
            } else {
                vector.as_ptr() as u64
            },
            give.len() as u64,
            if take.is_empty() {
                0
            } else {
                installed.as_mut_ptr() as u64
            },
            take.len() as u64,
        )?;
        // Zero: this form waits as long as it takes, and says so rather than
        // leaving the deadline register to chance. See `call_until`.
        let n = syscall3(SYS_CHANNEL_CALL, args.as_ptr() as u64, endpoint.0.0, 0);
        if n < 0 {
            return Err(error_of(n));
        }
        refresh(reply);
        let filled = read_kernel_filled::<{ 4 * super::MAX_TRANSFER }>(&installed);
        let mut arrived = 0usize;
        for (index, slot) in take.iter_mut().enumerate() {
            let number = read32(&filled, index * 4);
            // A zero is the kernel saying it installed nothing there, which is
            // how a caller learns a buffer was kept rather than returned.
            if number == 0 {
                break;
            }
            *slot = Handle(u64::from(number));
            arrived += 1;
        }
        Ok((reply.len(), arrived))
    }

    fn now_nanos(&mut self) -> Option<u64> {
        match syscall1(SYS_CLOCK_READ, CLOCK_MONOTONIC) {
            n if n > 0 => Some(n as u64),
            _ => None,
        }
    }

    fn receive_any(
        &mut self,
        endpoints: &[Endpoint],
        into: &mut [u8],
        handles: &mut [Handle],
    ) -> Result<(usize, Request), Error> {
        self.receive_any_until(endpoints, into, handles, None)
    }

    fn receive_any_until(
        &mut self,
        endpoints: &[Endpoint],
        into: &mut [u8],
        handles: &mut [Handle],
        deadline: Option<u64>,
    ) -> Result<(usize, Request), Error> {
        if endpoints.is_empty() || endpoints.len() > super::MAX_TRANSFER {
            return Err(Error::TooLarge);
        }
        if handles.len() > super::MAX_TRANSFER {
            return Err(Error::TooLarge);
        }
        // **The handle vector says where to wait, not what to send.** Nothing
        // is transferred out on a receive, so the outbound vector is free, and
        // the kernel reads the endpoints to wait on from it. The installed
        // report below is the inbound direction and stays separate.
        let mut waiting = [0u32; super::MAX_TRANSFER];
        for (slot, endpoint) in waiting.iter_mut().zip(endpoints) {
            *slot = endpoint.0.0 as u32;
        }
        let mut installed = [0u8; 4 * super::MAX_TRANSFER];
        let mut args = carrying_args(
            into.as_ptr() as u64,
            into.len() as u64,
            0,
            waiting.as_ptr() as u64,
            endpoints.len() as u64,
            if handles.is_empty() {
                0
            } else {
                installed.as_mut_ptr() as u64
            },
            handles.len() as u64,
        )?;
        let n = syscall2(
            SYS_CHANNEL_RECV_ANY,
            args.as_ptr() as u64,
            deadline.unwrap_or(0),
        );
        if n < 0 {
            return Err(error_of(n));
        }
        let filled = read_kernel_filled::<{ ChannelMsgArgs::WIRE_SIZE }>(&args);
        args.copy_from_slice(&filled);
        let len = read32(&args, ARGS_INLINE_LEN) as usize;
        let filled_to = len.min(into.len());
        refresh(&mut into[..filled_to]);

        // Which endpoint answered, written back into `msg_flags`. Checked
        // against the vector this call sent rather than trusted: an index past
        // its end would have a server reply to an endpoint it never waited on.
        let index = read32(&args, ARGS_MSG_FLAGS) as usize;
        if index >= endpoints.len() {
            return Err(Error::Kernel(-1));
        }

        let reported = read_kernel_filled::<{ 4 * super::MAX_TRANSFER }>(&installed);
        let mut count = 0usize;
        for (slot_index, slot) in handles.iter_mut().enumerate() {
            let number = read32(&reported, slot_index * 4);
            if number == 0 {
                break;
            }
            *slot = Handle(u64::from(number));
            count += 1;
        }
        Ok((
            index,
            Request {
                method: read32(&args, ARGS_METHOD_ID),
                len,
                handles: count,
            },
        ))
    }

    fn receive_with(
        &mut self,
        endpoint: Endpoint,
        into: &mut [u8],
        handles: &mut [Handle],
    ) -> Result<Request, Error> {
        if handles.len() > super::MAX_TRANSFER {
            return Err(Error::TooLarge);
        }
        let mut installed = [0u8; 4 * super::MAX_TRANSFER];
        let mut args = carrying_args(
            into.as_ptr() as u64,
            into.len() as u64,
            0,
            0,
            0,
            if handles.is_empty() {
                0
            } else {
                installed.as_mut_ptr() as u64
            },
            handles.len() as u64,
        )?;
        let n = syscall2(SYS_CHANNEL_RECV, args.as_ptr() as u64, endpoint.0.0);
        if n < 0 {
            return Err(error_of(n));
        }
        let filled = read_kernel_filled::<{ ChannelMsgArgs::WIRE_SIZE }>(&args);
        args.copy_from_slice(&filled);
        let len = read32(&args, ARGS_INLINE_LEN) as usize;
        let filled_to = len.min(into.len());
        refresh(&mut into[..filled_to]);

        // **The count is inferred, not reported.** The kernel does not write
        // the arrived handle count back into the descriptor — `handle_count`
        // is the field a *sender* fills — so the number that arrived is the
        // number of non-zero entries in the installed report. Zero is
        // unambiguous there: handle 0 is a program's own bootstrap endpoint
        // and is never where an installed capability lands.
        let reported = read_kernel_filled::<{ 4 * super::MAX_TRANSFER }>(&installed);
        let mut count = 0usize;
        for (index, slot) in handles.iter_mut().enumerate() {
            let number = read32(&reported, index * 4);
            if number == 0 {
                break;
            }
            *slot = Handle(u64::from(number));
            count += 1;
        }
        Ok(Request {
            method: read32(&args, ARGS_METHOD_ID),
            len,
            handles: count,
        })
    }

    fn respond_with(
        &mut self,
        endpoint: Endpoint,
        reply: &[u8],
        give: &[Transfer],
    ) -> Result<(), Error> {
        let mut vector = [0u8; HandleTransfer::WIRE_SIZE * super::MAX_TRANSFER];
        encode_transfers(give, &mut vector)?;
        let args = carrying_args(
            reply.as_ptr() as u64,
            reply.len() as u64,
            0,
            if give.is_empty() {
                0
            } else {
                vector.as_ptr() as u64
            },
            give.len() as u64,
            0,
            0,
        )?;
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

    fn handle_duplicate(&mut self, handle: Handle, rights: u64) -> Result<Handle, Error> {
        let new = syscall2(SYS_HANDLE_DUPLICATE, handle.0, rights);
        if new < 0 {
            return Err(error_of(new));
        }
        Ok(Handle(new as u64))
    }

    fn memory_create_paged(&mut self, bytes: u64, pager: Handle) -> Result<Handle, Error> {
        let args = MemoryCreatePagedArgs {
            size: MemoryCreatePagedArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            bytes,
            pager: HandleRef::new(pager.0 as u32),
            reserved: 0,
        };
        let mut buf = [0u8; MemoryCreatePagedArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let handle = syscall2(SYS_MEMORY_CREATE_PAGED, buf.as_ptr() as u64, 0);
        if handle < 0 {
            return Err(error_of(handle));
        }
        Ok(Handle(handle as u64))
    }

    fn page_supply(&mut self, memory: Handle, offset: u64, source: u64) -> Result<(), Error> {
        let args = PageSupplyArgs {
            size: PageSupplyArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            memory: HandleRef::new(memory.0 as u32),
            reserved: 0,
            offset,
            source,
        };
        let mut buf = [0u8; PageSupplyArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let result = syscall2(SYS_PAGE_SUPPLY, buf.as_ptr() as u64, 0);
        if result < 0 {
            return Err(error_of(result));
        }
        Ok(())
    }

    fn map_object(&mut self, memory: Handle, va: u64, rights: u32) -> Result<(), Error> {
        let args = MemoryMapArgs {
            size: MemoryMapArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            memory: HandleRef::new(memory.0 as u32),
            rights: MapRights(rights),
            vaddr: va,
        };
        let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let result = syscall2(SYS_MAP_OBJECT, buf.as_ptr() as u64, 0);
        if result < 0 {
            return Err(error_of(result));
        }
        Ok(())
    }

    fn memory_dirty_pages(&mut self, memory: Handle, offsets: &mut [u64]) -> Result<usize, Error> {
        // **Bytes, not a `[u64]`.** The kernel writes this vector behind the
        // compiler's back, so it has to be read the way every other
        // kernel-filled buffer here is — through `uabi`, which owns that one
        // `unsafe` on everybody's behalf. Handing the kernel a `&mut [u64]` and
        // re-reading it volatile would have put the second copy of that unsafe
        // in this crate, which is `deny(unsafe_code)` for a reason.
        const MAX_OFFSETS: usize = 16;
        if offsets.len() > MAX_OFFSETS {
            return Err(Error::TooLarge);
        }
        let mut raw = [0u8; MAX_OFFSETS * 8];
        let args = MemoryDirtyPagesArgs {
            size: MemoryDirtyPagesArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            memory: HandleRef::new(memory.0 as u32),
            capacity: offsets.len() as u32,
            offsets: raw.as_mut_ptr() as u64,
        };
        let mut buf = [0u8; MemoryDirtyPagesArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let n = syscall2(SYS_MEMORY_DIRTY_PAGES, buf.as_ptr() as u64, 0);
        if n < 0 {
            return Err(error_of(n));
        }
        let n = (n as usize).min(offsets.len());
        refresh(&mut raw[..n * 8]);
        for (slot, chunk) in offsets.iter_mut().zip(raw[..n * 8].chunks_exact(8)) {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            *slot = u64::from_le_bytes(word);
        }
        Ok(n)
    }

    fn page_written_back(&mut self, memory: Handle, offset: u64) -> Result<(), Error> {
        let args = PageWrittenBackArgs {
            size: PageWrittenBackArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            memory: HandleRef::new(memory.0 as u32),
            reserved: 0,
            offset,
        };
        let mut buf = [0u8; PageWrittenBackArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let result = syscall2(SYS_PAGE_WRITTEN_BACK, buf.as_ptr() as u64, 0);
        if result < 0 {
            return Err(error_of(result));
        }
        Ok(())
    }

    fn close(&mut self, handle: Handle) -> Result<(), Error> {
        let result = syscall1(SYS_HANDLE_CLOSE, handle.0);
        if result < 0 {
            return Err(error_of(result));
        }
        Ok(())
    }

    fn unmap(&mut self, base: u64, len: u64) -> Result<(), Error> {
        let result = syscall2(SYS_MEMORY_UNMAP, base, len);
        if result < 0 {
            return Err(error_of(result));
        }
        Ok(())
    }

    fn memory_create(&mut self, bytes: u64) -> Result<Handle, Error> {
        let args = MemoryCreateArgs {
            size: MemoryCreateArgs::WIRE_SIZE as u32,
            version: 2,
            flags: 0,
            bytes,
            constraints: MemoryConstraint(0),
            alignment: 0,
            address_limit: 0,
        };
        let mut buf = [0u8; MemoryCreateArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let handle = syscall2(SYS_MEMORY_CREATE, buf.as_ptr() as u64, 0);
        if handle < 0 {
            return Err(error_of(handle));
        }
        Ok(Handle(handle as u64))
    }

    fn channel_create(&mut self) -> Result<(Endpoint, Endpoint), Error> {
        // Written by the kernel, so it is read back through the barrier every
        // kernel-filled buffer in this program goes through: a plain read
        // would see what this program stored.
        let record = [0u8; ChannelCreateRecord::WIRE_SIZE];
        let args = ChannelCreateArgs {
            size: ChannelCreateArgs::WIRE_SIZE as u32,
            version: 2,
            flags: 0,
            end0_rights: ChannelRights(ChannelRights::READ.bits() | ChannelRights::TRANSFER.bits()),
            end1_rights: ChannelRights(
                ChannelRights::WRITE.bits() | ChannelRights::TRANSFER.bits(),
            ),
            record_ptr: record.as_ptr() as u64,
        };
        let mut buf = [0u8; ChannelCreateArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let result = syscall2(SYS_CHANNEL_CREATE, buf.as_ptr() as u64, 0);
        if result < 0 {
            return Err(error_of(result));
        }
        let filled = read_kernel_filled::<{ ChannelCreateRecord::WIRE_SIZE }>(&record);
        let record: ChannelCreateRecord = decode(&filled).map_err(|_| Error::Kernel(0))?;
        Ok((
            Endpoint(Handle(u64::from(record.end0))),
            Endpoint(Handle(u64::from(record.end1))),
        ))
    }

    fn memory_map(&mut self, memory: Handle, va: u64) -> Result<(), Error> {
        let args = MemoryMapArgs {
            size: MemoryMapArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            memory: HandleRef::new(u32::try_from(memory.0).map_err(|_| Error::TooLarge)?),
            rights: MapRights(MapRights::READ.bits() | MapRights::WRITE.bits()),
            vaddr: va,
        };
        let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let mapped = syscall2(SYS_MEMORY_MAP, buf.as_ptr() as u64, 0);
        if mapped < 0 {
            return Err(error_of(mapped));
        }
        Ok(())
    }

    fn memory_map_readable(&mut self, memory: Handle, va: u64) -> Result<(), Error> {
        let args = MemoryMapArgs {
            size: MemoryMapArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            memory: HandleRef::new(u32::try_from(memory.0).map_err(|_| Error::TooLarge)?),
            rights: MapRights(MapRights::READ.bits()),
            vaddr: va,
        };
        let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let mapped = syscall2(SYS_MEMORY_MAP, buf.as_ptr() as u64, 0);
        if mapped < 0 {
            return Err(error_of(mapped));
        }
        Ok(())
    }

    fn dma_attach(&mut self, device: Handle, memory: Handle) -> Result<u64, Error> {
        let args = DmaAttachArgs {
            size: DmaAttachArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            device: HandleRef::new(u32::try_from(device.0).map_err(|_| Error::TooLarge)?),
            memory: HandleRef::new(u32::try_from(memory.0).map_err(|_| Error::TooLarge)?),
        };
        let mut buf = [0u8; DmaAttachArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let address = syscall1(SYS_DMA_ATTACH, buf.as_ptr() as u64);
        if address < 0 {
            return Err(error_of(address));
        }
        Ok(address as u64)
    }

    fn dma_detach(&mut self, memory: Handle) -> Result<(), Error> {
        let args = DmaDetachArgs {
            size: DmaDetachArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            memory: HandleRef::new(u32::try_from(memory.0).map_err(|_| Error::TooLarge)?),
            reserved: 0,
        };
        let mut buf = [0u8; DmaDetachArgs::WIRE_SIZE];
        encode(&args, &mut buf).map_err(|_| Error::TooLarge)?;
        let done = syscall1(SYS_DMA_DETACH, buf.as_ptr() as u64);
        if done < 0 {
            return Err(error_of(done));
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
