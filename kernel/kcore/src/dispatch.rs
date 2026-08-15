// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The shared, frame-neutral syscall dispatcher (build/README.md, D79): one
//! implementation of the executive-substrate syscall semantics that every port
//! calls. A port captures its architecture's syscall frame (x86-64:
//! `SyscallFrame` from `rax` + `rdi/rsi/rdx/r10/r8/r9`; AArch64: the EL0 trap
//! frame's `x8` + `x0..x5`), normalizes it into a [`SyscallRequest`], builds a
//! [`DispatchEnv`] over its executive/process-table/frame-allocator statics,
//! and writes a [`DispatchOutcome::Return`] value back into the return register
//! (`rax` / `x0`).
//!
//! Dispatch covers the arms whose semantics are identical on every port: the
//! null syscall, the message-carrying channel operations
//! (recv/call/reply over the ISL `ChannelMsgArgs` struct), and the ring-3
//! driver-host pair `MapDevice`/`DmaAlloc` (over the ISL `MapDeviceArgs`/
//! `DmaAllocArgs` structs). Everything else returns
//! [`DispatchOutcome::Unhandled`] and stays port-local — deliberately so for
//! `DebugWrite` and `ProcessExit`, whose semantics genuinely diverge per port
//! (x86-64 prints a validated user string and runs its waiter-handoff exit
//! policy; AArch64's boot checks record a sink value and end the thread).
//!
//! Borrow discipline: a blocking channel operation (`call`/`receive`) parks the
//! calling thread's kernel stack — and with it this dispatch frame and its
//! `DispatchEnv` borrows — until a peer hands control back. The env is never
//! dereferenced while parked, and the process is re-derived from the table
//! after every blocking call (the peer mutated the table meanwhile). The port
//! states this invariant where it constructs the env.
//!
//! Normative: docs/api/01-system-call-interface.md ("ABI Rules"),
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels"),
//! docs/security/01-security-model.md ("Memory Safety")

use crate::exec::Executive;
use crate::handle::Handle;
use crate::ipc::TransferredHandle;
use crate::ipc::{EndpointId, MAX_INLINE_BYTES, MAX_MSG_HANDLES, Message, MessageHeader};
use crate::process::ProcessTable;
use crate::rights::Rights;
use crate::syscall::{
    self, PORT_EVENT_RECORD_SIZE, SyscallNumber, encode_port_event, encode_result, read_user,
    write_user,
};
use tessera_karch::{
    AddressSpaceOps, ContextOps, FRAME_SIZE, FrameSource, KError, PageFlags, PhysAddr, PhysFrame,
    VirtAddr,
};

/// A frame-neutral syscall request: the number and up to six register
/// arguments, in the port's argument-register order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SyscallRequest {
    /// The raw syscall number (`rax` / `x8`).
    pub number: u64,
    /// The raw argument registers (`rdi,rsi,rdx,r10,r8,r9` / `x0..x5`).
    pub args: [u64; 6],
}

/// What the port must do with a dispatched request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DispatchOutcome {
    /// The arm was covered here: write this ABI result into the syscall
    /// return register (`rax` / `x0`) and resume the caller.
    Return(i64),
    /// Not covered by the shared dispatcher — the port's local arms
    /// (`DebugWrite`, `ProcessExit`, its own demos, unknown numbers) decide.
    Unhandled,
}

/// The substrate a dispatch runs against, built fresh per syscall by the port
/// from its statics. See the module note on the parked-borrow discipline.
pub struct DispatchEnv<'a, A: AddressSpaceOps, C: ContextOps> {
    /// The executive owning the scheduler, channels, and device graph.
    pub exec: &'a mut Executive<C>,
    /// The process table the caller lives in.
    pub processes: &'a mut ProcessTable<A>,
    /// The calling thread's scheduler index.
    pub caller: usize,
    /// Frame source for page tables and DMA pages built inside a syscall.
    pub alloc: &'a mut dyn FrameSource,
}

/// Dispatches one syscall request. Covered arms return
/// [`DispatchOutcome::Return`]; everything else is [`DispatchOutcome::Unhandled`].
pub fn dispatch<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    req: &SyscallRequest,
) -> DispatchOutcome {
    let Some(number) = SyscallNumber::from_u64(req.number) else {
        return DispatchOutcome::Unhandled;
    };
    match number {
        SyscallNumber::Null => DispatchOutcome::Return(encode_result(Ok(0))),
        SyscallNumber::ChannelRecv => {
            DispatchOutcome::Return(channel_recv(env, req.args[0], req.args[1]))
        }
        SyscallNumber::ChannelCall => {
            DispatchOutcome::Return(channel_call(env, req.args[0], req.args[1]))
        }
        SyscallNumber::ChannelReply => {
            DispatchOutcome::Return(channel_reply(env, req.args[0], req.args[1], false))
        }
        SyscallNumber::ChannelReplyContinue => {
            DispatchOutcome::Return(channel_reply(env, req.args[0], req.args[1], true))
        }
        SyscallNumber::ChannelReplyRecv => {
            DispatchOutcome::Return(channel_reply_recv(env, req.args[0], req.args[1]))
        }
        SyscallNumber::PortWait => {
            DispatchOutcome::Return(port_wait(env, req.args[0], req.args[1]))
        }
        SyscallNumber::MapDevice => DispatchOutcome::Return(map_device(env, req.args[0])),
        SyscallNumber::DmaAlloc => DispatchOutcome::Return(dma_alloc(env, req.args[0])),
        _ => DispatchOutcome::Unhandled,
    }
}

/// Narrows a caller-supplied 64-bit handle argument to the handle space.
///
/// A value that does not fit is **rejected**, never truncated into range:
/// `0x1_0000_0005` must not become handle 5. Two distinct arguments naming the
/// same capability is a confusion the caller can exploit to disguise which
/// handle it meant, and on a 32-bit target the truncation would be wider still.
fn handle_from_arg(raw: u64) -> Result<Handle, KError> {
    u32::try_from(raw)
        .map(Handle::from_raw)
        .map_err(|_| KError::BadHandle)
}

/// Narrows a caller-supplied 64-bit length to `usize` without truncating.
///
/// A length too large for this target's pointer width saturates to `usize::MAX`
/// so that the bound check every caller applies next *caps* it, rather than a
/// truncation wrapping an absurd request into a plausible one. On a 64-bit
/// target the conversion never fails and this is the identity.
fn saturating_len(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Resolves the endpoint a channel syscall targets: looks the endpoint handle
/// up in the caller's table, checks it carries `need`, and maps its object id
/// back to the live `EndpointId` (the handle→endpoint bridge). Returns a
/// `Copy` id and drops every table borrow, so the caller may hand off without
/// a borrow spanning the switch.
pub fn resolve_endpoint<A: AddressSpaceOps, C: ContextOps>(
    exec: &Executive<C>,
    processes: &mut ProcessTable<A>,
    caller: usize,
    ep_handle: u64,
    need: Rights,
) -> Result<EndpointId, KError> {
    let process = processes
        .process_of_thread(caller)
        .ok_or(KError::BadHandle)?;
    let (obj, rights) = process.handles().lookup(handle_from_arg(ep_handle)?)?;
    if !rights.contains(need) {
        return Err(KError::AccessDenied);
    }
    exec.endpoint_of_object(obj).ok_or(KError::BadHandle)
}

/// Builds a `Message` from the caller's `ChannelMsgArgs`: validates and copies
/// the args struct, the inline payload, and — when `transfer` — the transfer
/// vector (each handle `take`n from the caller's table, conserving its object
/// reference). All reads run under the caller's active space; the returned
/// message owns the taken references. Every table borrow ends on return.
pub fn build_channel_message<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    caller: usize,
    args_ptr: u64,
    transfer: bool,
) -> Result<Message, KError> {
    let args = read_channel_msg_args(processes, caller, args_ptr)?;
    build_message_from_args(processes, caller, &args, transfer)
}

/// Reads and decodes the caller's `ChannelMsgArgs` descriptor.
fn read_channel_msg_args<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    caller: usize,
    args_ptr: u64,
) -> Result<syscall::ChannelMsgRequest, KError> {
    let process = processes
        .process_of_thread(caller)
        .ok_or(KError::BadHandle)?;
    let mut abuf = [0u8; syscall::CHANNEL_MSG_ARGS_SIZE];
    read_user(process, args_ptr, &mut abuf)?;
    syscall::decode_channel_msg_args(&abuf)
}

/// The build half of [`build_channel_message`], from an already-decoded
/// descriptor (so a caller that also needs the descriptor after a blocking
/// hop decodes exactly once, before blocking).
fn build_message_from_args<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    caller: usize,
    args: &syscall::ChannelMsgRequest,
    transfer: bool,
) -> Result<Message, KError> {
    let process = processes
        .process_of_thread(caller)
        .ok_or(KError::BadHandle)?;

    let inline_len = saturating_len(args.inline_len).min(MAX_INLINE_BYTES);
    let mut inline = [0u8; MAX_INLINE_BYTES];
    read_user(process, args.inline_ptr, &mut inline[..inline_len])?;

    let mut message = Message::new(MessageHeader::new(args.interface_id, args.method_id));
    // The kernel stamps the cause from the calling thread's ambient context —
    // `ChannelMsgArgs` carries no correlation field, so ring 3 has no way to
    // supply (or forge) one. Identity comes from the kernel, never from payload
    // bytes (docs/lifecycle/04; D60). `send`/`call` restamp this for kernel-
    // originated messages; here it makes a ring-3 send carry its sender's cause.
    message.set_correlation(crate::trace::current().correlation);
    message.set_inline(&inline[..inline_len])?;

    if transfer && args.handle_count > 0 {
        let count = saturating_len(args.handle_count).min(MAX_MSG_HANDLES);
        let mut hbuf = [0u8; MAX_MSG_HANDLES * 4];
        read_user(process, args.handles_ptr, &mut hbuf[..count * 4])?;
        for i in 0..count {
            let raw = u32::from_le_bytes([
                hbuf[i * 4],
                hbuf[i * 4 + 1],
                hbuf[i * 4 + 2],
                hbuf[i * 4 + 3],
            ]);
            let (object, rights) = process.handles_mut().take(Handle::from_raw(raw))?;
            message.add_handle(TransferredHandle { object, rights })?;
        }
    }
    Ok(message)
}

/// Installs every handle `message` transferred into the (re-derived) caller's
/// table — the capability crossing the address-space boundary. Shared by the
/// recv side and the call-reply side.
fn install_transferred_handles<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    caller: usize,
    message: &Message,
) {
    if let Some(process) = processes.process_of_thread(caller) {
        for transferred in message.handles() {
            // A full handle table drops the transferred capability — the
            // object reference conservation is the sender's `take`; install
            // failure is the receiver's loss, as on the x86-64 chan demo.
            let _ = process
                .handles_mut()
                .install(transferred.object, transferred.rights);
        }
    }
}

/// `ChannelCall` (client side): build the request from the caller's
/// `ChannelMsgArgs`, hand off synchronously to the server, and block for the
/// reply. The args buffer is **symmetric** (D81): `inline_ptr`/`inline_len`
/// is the request source before the call and the reply destination after it
/// (clamped to `inline_len`); the returned value is the reply length
/// delivered. The descriptor is decoded once, before blocking, and never
/// re-read after the peer ran. Every table borrow ends before `call`
/// switches; the reply's payload and transferred handles land after control
/// returns here.
#[inline(never)]
fn channel_call<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
    ep_handle: u64,
) -> i64 {
    let ep = match resolve_endpoint(
        env.exec,
        env.processes,
        env.caller,
        ep_handle,
        Rights::WRITE,
    ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    let args = match read_channel_msg_args(env.processes, env.caller, args_ptr) {
        Ok(args) => args,
        Err(e) => return encode_result(Err(e)),
    };
    let request = match build_message_from_args(env.processes, env.caller, &args, true) {
        Ok(msg) => msg,
        Err(e) => return encode_result(Err(e)),
    };
    let reply = match env.exec.call(ep, request) {
        Ok(reply) => reply,
        Err(e) => return encode_result(Err(e)),
    };
    // The caller's space is active again (the reply handed control back), and
    // the table may have changed while this frame was parked — re-derive.
    let inline = reply.inline();
    let n = inline.len().min(saturating_len(args.inline_len));
    if n > 0 {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::BadHandle));
        };
        if let Err(e) = write_user(process, args.inline_ptr, &inline[..n]) {
            return encode_result(Err(e));
        }
    }
    install_transferred_handles(env.processes, env.caller, &reply);
    encode_result(Ok(n as u64))
}

/// `ChannelRecv` (server side): the args struct's `inline_ptr`/`inline_len`
/// describe the receive buffer. The struct is read and validated **before**
/// blocking (fail fast, and the buffer descriptor must not be re-read after
/// the peer ran); the payload is copied out after a message arrives. Returns
/// the number of payload bytes delivered.
#[inline(never)]
fn channel_recv<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
    ep_handle: u64,
) -> i64 {
    let ep = match resolve_endpoint(env.exec, env.processes, env.caller, ep_handle, Rights::READ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    let args = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::BadHandle));
        };
        let mut abuf = [0u8; syscall::CHANNEL_MSG_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_channel_msg_args(&abuf) {
            Ok(args) => args,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let message = match env.exec.receive(ep) {
        Ok(message) => message,
        Err(e) => return encode_result(Err(e)),
    };
    let inline = message.inline();
    let n = inline.len().min(saturating_len(args.inline_len));
    if n > 0 {
        // Re-derive the process: this frame may have been parked and the
        // table mutated before the message arrived.
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::BadHandle));
        };
        if let Err(e) = write_user(process, args.inline_ptr, &inline[..n]) {
            return encode_result(Err(e));
        }
    }
    install_transferred_handles(env.processes, env.caller, &message);
    encode_result(Ok(n as u64))
}

/// `ChannelReply` (server side): build the response from the server's
/// `ChannelMsgArgs` and hand off directly back to the waiting caller.
/// `continue_running` selects `ChannelReplyContinue`'s variant, which readies
/// the caller instead of handing off so the server keeps running — what a
/// server waiting on a port instead of on this endpoint needs (D85).
#[inline(never)]
fn channel_reply<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
    ep_handle: u64,
    continue_running: bool,
) -> i64 {
    let ep = match resolve_endpoint(env.exec, env.processes, env.caller, ep_handle, Rights::READ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    let response = match build_channel_message(env.processes, env.caller, args_ptr, true) {
        Ok(msg) => msg,
        Err(e) => return encode_result(Err(e)),
    };
    let replied = if continue_running {
        env.exec.reply_and_continue(ep, response)
    } else {
        env.exec.reply(ep, response)
    };
    match replied {
        Ok(()) => encode_result(Ok(0)),
        Err(e) => encode_result(Err(e)),
    }
}

/// `ChannelReplyRecv` (server side): reply to the current caller and receive
/// the next request in one operation — the primitive a resident service
/// parks in between requests. The args buffer is **symmetric** like a call's
/// (D81/D82): the reply payload is read out of `inline_ptr` before blocking,
/// and the next request is copied back into it (clamped to `inline_len`)
/// after one arrives; the descriptor is decoded once, before blocking, and
/// never re-read after a peer ran. Returns the next request's length.
#[inline(never)]
fn channel_reply_recv<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
    ep_handle: u64,
) -> i64 {
    let ep = match resolve_endpoint(env.exec, env.processes, env.caller, ep_handle, Rights::READ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    let args = match read_channel_msg_args(env.processes, env.caller, args_ptr) {
        Ok(args) => args,
        Err(e) => return encode_result(Err(e)),
    };
    let response = match build_message_from_args(env.processes, env.caller, &args, true) {
        Ok(msg) => msg,
        Err(e) => return encode_result(Err(e)),
    };
    let request = match env.exec.reply_receive(ep, response) {
        Ok(request) => request,
        Err(e) => return encode_result(Err(e)),
    };
    // The server's space is active again (a call handed control back), and
    // the table may have changed while this frame was parked — re-derive.
    let inline = request.inline();
    let n = inline.len().min(saturating_len(args.inline_len));
    if n > 0 {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::BadHandle));
        };
        if let Err(e) = write_user(process, args.inline_ptr, &inline[..n]) {
            return encode_result(Err(e));
        }
    }
    install_transferred_handles(env.processes, env.caller, &request);
    encode_result(Ok(n as u64))
}

/// `PortWait`: block until the next event lands on the port named by the
/// caller's handle (needs `Rights::READ`), then return the drained event's
/// coalesced pending count. When `event_ptr` is non-zero the drained event is
/// also written there as a `PortEventRecord`, which names *which* binding
/// fired — that is what turns a multi-binding port into a select (D85). Zero
/// keeps the count-only shape a single-binding port needs (D84), so the
/// interrupt path is unchanged.
/// Parks like `receive` — the same parked-borrow discipline applies.
#[inline(never)]
fn port_wait<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    port_handle: u64,
    event_ptr: u64,
) -> i64 {
    let port = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::BadHandle));
        };
        let handle = match handle_from_arg(port_handle) {
            Ok(handle) => handle,
            Err(e) => return encode_result(Err(e)),
        };
        let (obj, rights) = match process.handles().lookup(handle) {
            Ok(v) => v,
            Err(e) => return encode_result(Err(e)),
        };
        if !rights.contains(Rights::READ) {
            return encode_result(Err(KError::AccessDenied));
        }
        match env.exec.port_of_object(obj) {
            Some(port) => port,
            None => return encode_result(Err(KError::BadHandle)),
        }
    };
    let event = match env.exec.port_wait(port) {
        Ok(event) => event,
        Err(e) => return encode_result(Err(e)),
    };
    if event_ptr != 0 {
        let mut record = [0u8; PORT_EVENT_RECORD_SIZE];
        if let Err(e) = encode_port_event(event.source, event.signal, event.pending, &mut record) {
            return encode_result(Err(e));
        }
        // Re-resolve the caller: the wait above may have parked this thread,
        // and only the resumed side may touch its user memory.
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::BadHandle));
        };
        if let Err(e) = write_user(process, event_ptr, &record) {
            return encode_result(Err(e));
        }
    }
    encode_result(Ok(event.pending as u64))
}

/// `MapDevice`: map the MMIO register window named by the caller's device
/// capability (which must carry `Rights::MAP`) into the caller's own address
/// space at the requested page-aligned VA. The window need not be page-aligned
/// (virtio-mmio slots are 0x200 bytes): the containing page is mapped and the
/// returned VA carries the intra-page offset. The mapping is deliberately
/// untracked device memory ([`crate::vm::AddressSpace::map_device_page`]).
#[inline(never)]
fn map_device<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::MAP_DEVICE_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_map_device_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let (object, rights) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.device) {
            Ok(v) => v,
            Err(e) => return encode_result(Err(e)),
        }
    };
    if !rights.contains(Rights::MAP) {
        return encode_result(Err(KError::AccessDenied));
    }
    let Some((phys, _len)) = env.exec.mmio_of_object(object) else {
        return encode_result(Err(KError::AccessDenied));
    };
    let va = request.vaddr;
    if va >= A::USER_ADDRESS_MAX || va & (FRAME_SIZE - 1) != 0 {
        return encode_result(Err(KError::InvalidMapping));
    }
    let page_base = phys & !(FRAME_SIZE - 1);
    let offset = phys & (FRAME_SIZE - 1);
    let Some(frame) = PhysFrame::from_base(PhysAddr::new(page_base)) else {
        return encode_result(Err(KError::Unaligned));
    };
    let mapped = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        process
            .space_mut()
            .map_device_page(VirtAddr::new(va), frame, env.alloc)
    };
    match mapped {
        Ok(()) => encode_result(Ok(va + offset)),
        Err(e) => encode_result(Err(e)),
    }
}

/// `DmaAlloc`: allocate one zero-filled page in the caller's own address space
/// at the requested page-aligned VA and return its physical address — the
/// device-visible name of the same memory. Authorized by a device capability
/// carrying `Rights::MAP` that resolves to a real MMIO-backed device. The
/// buffer is a **tracked** anonymous mapping, so teardown reclaims its frame.
#[inline(never)]
fn dma_alloc<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::DMA_ALLOC_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_dma_alloc_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let (object, rights) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.device) {
            Ok(v) => v,
            Err(e) => return encode_result(Err(e)),
        }
    };
    if !rights.contains(Rights::MAP) {
        return encode_result(Err(KError::AccessDenied));
    }
    if env.exec.mmio_of_object(object).is_none() {
        return encode_result(Err(KError::AccessDenied));
    }
    let va = request.vaddr;
    if va >= A::USER_ADDRESS_MAX || va & (FRAME_SIZE - 1) != 0 {
        return encode_result(Err(KError::InvalidMapping));
    }
    let phys = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        if let Err(e) = process.space_mut().map_anonymous(
            VirtAddr::new(va),
            FRAME_SIZE,
            PageFlags::rw().user(),
            env.alloc,
        ) {
            return encode_result(Err(e));
        }
        match process.space().arch().translate(VirtAddr::new(va)) {
            Some((frame, _)) => frame.base().as_u64(),
            None => return encode_result(Err(KError::NotMapped)),
        }
    };
    encode_result(Ok(phys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isl_binding::port::PortEventRecord;
    use crate::object::ObjectId;
    use crate::process::Process;
    use crate::thread::{Thread, ThreadId};
    use crate::vm::{AddressSpace, Asid};
    use std::boxed::Box;
    use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

    extern "C" fn never(_: usize) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    /// A page-aligned host buffer standing in for the caller's user memory:
    /// its host address is below the mock `USER_ADDRESS_MAX`, so mapping the
    /// same VA range in the mock space makes `validate_user_range` accept it
    /// and the raw copy read/write the real bytes.
    #[repr(align(4096))]
    struct UserPage([u8; 4096]);

    // Boxed: a `ProcessTable` is ~16 × (`HandleTable` + space bookkeeping) —
    // hundreds of kilobytes the kernel keeps in a static, far too large for a
    // test-thread stack once move copies pile up in a debug build.
    struct Harness {
        exec: Box<Executive<MockContextOps>>,
        processes: Box<ProcessTable<MockAddressSpace>>,
        frames: MockFrameSource,
        caller: usize,
    }

    /// One running thread whose process owns `handle 0` on `device_obj` with
    /// `rights`, its space mapping the user page at `upage`'s host address.
    fn harness(upage: &UserPage, rights: Rights) -> Harness {
        let mut frames = MockFrameSource::new(0x1000_0000, 256);
        let mut exec = Box::new(Executive::<MockContextOps>::new(4, 0));
        let device_obj = ObjectId::from_raw(21);
        exec.device_register_mmio(device_obj, 0x0a00_3e00, FRAME_SIZE)
            .expect("register mmio");

        let mut space =
            AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
                .expect("space");
        let uva = upage.0.as_ptr() as u64;
        assert!(uva + FRAME_SIZE <= MockAddressSpace::USER_ADDRESS_MAX);
        space
            .map_anonymous(
                VirtAddr::new(uva),
                FRAME_SIZE,
                PageFlags::rw().user(),
                &mut frames,
            )
            .expect("map user page");

        let thread = Thread::<MockContextOps>::spawn(
            ThreadId(1),
            never,
            0,
            VirtAddr::new(0xffff_e000_0000_0000),
            2,
            &mut space,
            &mut frames,
        )
        .expect("thread");
        let caller = exec.add_thread(thread).expect("add thread");
        exec.run();

        let mut processes = Box::new(ProcessTable::<MockAddressSpace>::new());
        let mut process = Process::new(device_obj, space);
        process.add_thread(caller).expect("own thread");
        process
            .handles_mut()
            .install(device_obj, rights)
            .expect("install");
        processes.insert(process).expect("insert");

        Harness {
            exec,
            processes,
            frames,
            caller,
        }
    }

    fn run(h: &mut Harness, number: SyscallNumber, args: [u64; 6]) -> DispatchOutcome {
        let req = SyscallRequest {
            number: number as u64,
            args,
        };
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            alloc: &mut h.frames,
        };
        dispatch(&mut env, &req)
    }

    fn device_args(upage: &mut UserPage, handle: u32, vaddr: u64) -> u64 {
        upage.0[0..4].copy_from_slice(&32u32.to_le_bytes());
        upage.0[4..8].copy_from_slice(&1u32.to_le_bytes());
        upage.0[8..16].copy_from_slice(&0u64.to_le_bytes());
        upage.0[16..20].copy_from_slice(&handle.to_le_bytes());
        upage.0[20..24].copy_from_slice(&0u32.to_le_bytes());
        upage.0[24..32].copy_from_slice(&vaddr.to_le_bytes());
        upage.0.as_ptr() as u64
    }

    #[test]
    fn null_returns_zero_and_unknown_is_unhandled() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        assert_eq!(
            run(&mut h, SyscallNumber::Null, [0; 6]),
            DispatchOutcome::Return(0)
        );
        let req = SyscallRequest {
            number: 0xffff,
            args: [0; 6],
        };
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            alloc: &mut h.frames,
        };
        assert_eq!(dispatch(&mut env, &req), DispatchOutcome::Unhandled);
    }

    #[test]
    fn port_divergent_arms_are_unhandled() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ);
        assert_eq!(
            run(&mut h, SyscallNumber::DebugWrite, [0; 6]),
            DispatchOutcome::Unhandled
        );
        assert_eq!(
            run(&mut h, SyscallNumber::ProcessExit, [0; 6]),
            DispatchOutcome::Unhandled
        );
    }

    #[test]
    fn map_device_maps_the_containing_page_and_returns_the_offset_va() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let outcome = run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);
        // The registered window sits at 0x0a00_3e00 — intra-page offset 0xe00.
        assert_eq!(outcome, DispatchOutcome::Return(0x4000_0e00));
        // The device page is mapped in the arch space but untracked.
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4000_0000))
                .is_some()
        );
        assert_eq!(process.space().rights_at(VirtAddr::new(0x4000_0000)), None);
    }

    #[test]
    fn map_device_without_map_rights_is_denied() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        let mut h = harness(&upage, Rights::READ);
        let outcome = run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);
        assert_eq!(
            outcome,
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
    }

    #[test]
    fn map_device_rejects_malformed_args_as_protocol() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        upage.0[4] = 2; // version = 2
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let outcome = run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);
        assert_eq!(
            outcome,
            DispatchOutcome::Return(encode_result(Err(KError::Protocol)))
        );
    }

    #[test]
    fn dma_alloc_returns_the_physical_base_of_a_tracked_page() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4001_0000);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let outcome = run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
        let DispatchOutcome::Return(value) = outcome else {
            panic!("dma_alloc not covered");
        };
        assert!(value > 0, "expected a physical address, got {value}");
        let process = h.processes.process_of_thread(h.caller).expect("process");
        // Tracked: the wrapper records the mapping, and the returned phys is
        // the mapped frame's base.
        assert_eq!(
            process.space().rights_at(VirtAddr::new(0x4001_0000)),
            Some(PageFlags::rw().user())
        );
        let (frame, _) = process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4001_0000))
            .expect("translated");
        assert_eq!(frame.base().as_u64(), value as u64);
    }

    #[test]
    fn dma_alloc_on_a_non_device_authority_is_denied() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 1, 0x4001_0000);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        // Install a second handle on an object with no MMIO window.
        let other = ObjectId::from_raw(99);
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(other, Rights::READ | Rights::MAP)
            .expect("install");
        assert_eq!(handle.raw(), 1);
        let outcome = run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
        assert_eq!(
            outcome,
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
    }

    #[test]
    fn channel_ops_reject_a_bad_endpoint_handle() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        // Handle 0 exists but is no endpoint object → BadHandle from the
        // endpoint bridge; handle 7 does not exist → BadHandle from lookup.
        for ep_handle in [0u64, 7] {
            let outcome = run(
                &mut h,
                SyscallNumber::ChannelRecv,
                [args_ptr, ep_handle, 0, 0, 0, 0],
            );
            assert_eq!(
                outcome,
                DispatchOutcome::Return(encode_result(Err(KError::BadHandle)))
            );
        }
    }

    #[test]
    fn channel_recv_copies_the_queued_payload_out_and_truncates() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);

        // A channel whose far end has a queued 8-byte message; the near end is
        // installed as handle 1 with READ.
        let (a, b) = h.exec.channel_create().expect("channel");
        let ep_obj = ObjectId::from_raw(50);
        h.exec.bind_endpoint_object(b, ep_obj);
        let mut m = Message::new(MessageHeader::new(0, 0));
        m.set_inline(b"\xfe\xca\x0d\xf0\xfe\xca\x0d\xf0")
            .expect("inline");
        h.exec.send(a, m).expect("send");
        {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            let handle = process
                .handles_mut()
                .install(ep_obj, Rights::READ)
                .expect("install ep");
            assert_eq!(handle.raw(), 1);
        }

        // ChannelMsgArgs at upage[+128]: recv buffer = upage base (len 6 — one
        // shorter than the payload, proving truncation to the caller's buffer).
        let base = upage.0.as_ptr() as u64;
        let args = &mut upage.0[128..200];
        args[0..4].copy_from_slice(&72u32.to_le_bytes());
        args[4..8].copy_from_slice(&1u32.to_le_bytes());
        args[40..48].copy_from_slice(&base.to_le_bytes()); // inline_ptr
        args[48..56].copy_from_slice(&6u64.to_le_bytes()); // inline_len
        let outcome = run(
            &mut h,
            SyscallNumber::ChannelRecv,
            [base + 128, 1, 0, 0, 0, 0],
        );
        assert_eq!(outcome, DispatchOutcome::Return(6));
        assert_eq!(&upage.0[..6], b"\xfe\xca\x0d\xf0\xfe\xca");
    }

    /// Writes a `ChannelMsgArgs` at `upage[+128]` describing the symmetric
    /// call buffer at the page base (request source and reply destination).
    /// Returns the args pointer.
    fn call_args(upage: &mut UserPage, inline_len: u64) -> u64 {
        let base = upage.0.as_ptr() as u64;
        let args = &mut upage.0[128..200];
        args.fill(0);
        args[0..4].copy_from_slice(&72u32.to_le_bytes());
        args[4..8].copy_from_slice(&1u32.to_le_bytes());
        args[40..48].copy_from_slice(&base.to_le_bytes()); // inline_ptr
        args[48..56].copy_from_slice(&inline_len.to_le_bytes()); // inline_len
        base + 128
    }

    /// A call harness: handle 1 = endpoint `a` with WRITE; a "reply" is
    /// pre-queued on `a` by sending from the peer end `b` (the mock context
    /// switch returns immediately, so `call` proceeds straight to dequeuing
    /// its reply — the synchronous round-trip collapsed for the host test).
    fn call_harness(upage: &UserPage, reply: &[u8]) -> Harness {
        let mut h = harness(upage, Rights::READ | Rights::MAP);
        let (a, b) = h.exec.channel_create().expect("channel");
        let ep_obj = ObjectId::from_raw(51);
        h.exec.bind_endpoint_object(a, ep_obj);
        let mut m = Message::new(MessageHeader::new(0, 0));
        m.set_inline(reply).expect("inline");
        h.exec.send(b, m).expect("queue reply");
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(ep_obj, Rights::WRITE)
            .expect("install ep");
        assert_eq!(handle.raw(), 1);
        h
    }

    #[test]
    fn channel_call_copies_the_reply_payload_out() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = call_args(&mut upage, 96);
        let mut h = call_harness(&upage, b"TESSERAV");
        let outcome = run(
            &mut h,
            SyscallNumber::ChannelCall,
            [args_ptr, 1, 0, 0, 0, 0],
        );
        assert_eq!(outcome, DispatchOutcome::Return(8));
        assert_eq!(&upage.0[..8], b"TESSERAV");
    }

    #[test]
    fn channel_call_truncates_the_reply_to_the_buffer() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = call_args(&mut upage, 4);
        let mut h = call_harness(&upage, b"TESSERAV");
        let outcome = run(
            &mut h,
            SyscallNumber::ChannelCall,
            [args_ptr, 1, 0, 0, 0, 0],
        );
        assert_eq!(outcome, DispatchOutcome::Return(4));
        assert_eq!(&upage.0[..4], b"TESS");
        assert_eq!(&upage.0[4..8], &[0u8; 4]);
    }

    #[test]
    fn channel_call_with_an_empty_reply_returns_zero_and_writes_nothing() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = call_args(&mut upage, 96);
        let mut h = call_harness(&upage, b"");
        let outcome = run(
            &mut h,
            SyscallNumber::ChannelCall,
            [args_ptr, 1, 0, 0, 0, 0],
        );
        assert_eq!(outcome, DispatchOutcome::Return(0));
        assert_eq!(&upage.0[..8], &[0u8; 8]);
    }

    /// A server harness for `ChannelReplyRecv`: handle 1 = endpoint `b` (the
    /// server side) with READ; `next_request` is pre-queued on `b` from the
    /// client end `a`, standing in for the next caller's request (the
    /// immediate-dequeue path of `reply_receive` — on hardware the sequential
    /// clients exercise the park-and-handoff path instead).
    fn reply_recv_harness(upage: &UserPage, next_request: &[u8]) -> (Harness, EndpointId) {
        let mut h = harness(upage, Rights::READ | Rights::MAP);
        let (a, b) = h.exec.channel_create().expect("channel");
        let ep_obj = ObjectId::from_raw(52);
        h.exec.bind_endpoint_object(b, ep_obj);
        let mut m = Message::new(MessageHeader::new(0, 0));
        m.set_inline(next_request).expect("inline");
        h.exec.send(a, m).expect("queue next request");
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(ep_obj, Rights::READ)
            .expect("install ep");
        assert_eq!(handle.raw(), 1);
        (h, a)
    }

    #[test]
    fn channel_reply_recv_sends_the_reply_and_returns_the_next_request() {
        let mut upage = UserPage([0; 4096]);
        // The symmetric buffer starts holding the reply payload.
        upage.0[..8].copy_from_slice(b"TESSERAV");
        let args_ptr = call_args(&mut upage, 96);
        let (mut h, client_end) = reply_recv_harness(&upage, b"\x18\0\0\0\x01\0\0\0");
        let outcome = run(
            &mut h,
            SyscallNumber::ChannelReplyRecv,
            [args_ptr, 1, 0, 0, 0, 0],
        );
        // The queued next request (8 bytes) was copied into the buffer…
        assert_eq!(outcome, DispatchOutcome::Return(8));
        assert_eq!(&upage.0[..8], b"\x18\0\0\0\x01\0\0\0");
        // …and the reply (96 bytes of the buffer, front = the old payload)
        // was delivered to the client end.
        let reply = h.exec.receive(client_end).expect("reply queued");
        assert_eq!(&reply.inline()[..8], b"TESSERAV");
        assert_eq!(reply.inline().len(), 96);
    }

    #[test]
    fn channel_reply_recv_truncates_the_next_request_to_the_buffer() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = call_args(&mut upage, 4);
        let (mut h, _client_end) = reply_recv_harness(&upage, b"TESSERA2");
        let outcome = run(
            &mut h,
            SyscallNumber::ChannelReplyRecv,
            [args_ptr, 1, 0, 0, 0, 0],
        );
        assert_eq!(outcome, DispatchOutcome::Return(4));
        assert_eq!(&upage.0[..4], b"TESS");
        assert_eq!(&upage.0[4..8], &[0u8; 4]);
    }

    #[test]
    fn port_wait_drains_a_pending_event() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let port = h.exec.port_create().expect("port");
        let port_obj = ObjectId::from_raw(60);
        h.exec.bind_port_object(port, port_obj);
        h.exec.port_bind(port, 0x30, 1).expect("bind");
        // Pre-signal so the wait drains without parking (the mock collapses
        // the park path anyway; the block/wake pair is covered in exec.rs).
        assert_eq!(h.exec.port_signal(0x30, 1, 3), 1);
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(port_obj, Rights::READ)
            .expect("install port");
        assert_eq!(handle.raw(), 1);
        let outcome = run(&mut h, SyscallNumber::PortWait, [1, 0, 0, 0, 0, 0]);
        assert_eq!(outcome, DispatchOutcome::Return(3));
    }

    #[test]
    fn port_wait_writes_the_event_record_naming_the_source() {
        // The select: two bindings on one port, and the drained record must
        // say which of them fired — that is what lets a server map the event
        // back to the endpoint handle it should receive on.
        let upage = UserPage([0; 4096]);
        let event_ptr = upage.0.as_ptr() as u64;
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let port = h.exec.port_create().expect("port");
        let port_obj = ObjectId::from_raw(60);
        h.exec.bind_port_object(port, port_obj);
        h.exec.port_bind(port, 0x30, 1).expect("bind a");
        h.exec.port_bind(port, 0x31, 2).expect("bind b");
        assert_eq!(h.exec.port_signal(0x31, 2, 1), 1);
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(port_obj, Rights::READ)
            .expect("install port");
        let outcome = run(
            &mut h,
            SyscallNumber::PortWait,
            [u64::from(handle.raw()), event_ptr, 0, 0, 0, 0],
        );
        assert_eq!(outcome, DispatchOutcome::Return(1));
        let field = |off: usize| u64::from_le_bytes(upage.0[off..off + 8].try_into().expect("8"));
        let word = |off: usize| u32::from_le_bytes(upage.0[off..off + 4].try_into().expect("4"));
        assert_eq!(word(0) as usize, PortEventRecord::WIRE_SIZE);
        assert_eq!(word(4), 1, "version");
        assert_eq!(field(16), 0x31, "source names the binding that fired");
        assert_eq!(word(24), 2, "signal");
        assert_eq!(word(28), 1, "pending");
    }

    #[test]
    fn port_wait_without_an_event_pointer_writes_nothing() {
        // The D84 interrupt shape: a single-binding port needs no record, and
        // passing zero must leave user memory untouched.
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let port = h.exec.port_create().expect("port");
        let port_obj = ObjectId::from_raw(60);
        h.exec.bind_port_object(port, port_obj);
        h.exec.port_bind(port, 0x30, 1).expect("bind");
        assert_eq!(h.exec.port_signal(0x30, 1, 2), 1);
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(port_obj, Rights::READ)
            .expect("install port");
        let outcome = run(
            &mut h,
            SyscallNumber::PortWait,
            [u64::from(handle.raw()), 0, 0, 0, 0, 0],
        );
        assert_eq!(outcome, DispatchOutcome::Return(2));
        assert_eq!(
            upage.0[..PORT_EVENT_RECORD_SIZE],
            [0u8; PORT_EVENT_RECORD_SIZE]
        );
    }

    #[test]
    fn port_wait_without_read_rights_is_denied() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let port = h.exec.port_create().expect("port");
        let port_obj = ObjectId::from_raw(61);
        h.exec.bind_port_object(port, port_obj);
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(port_obj, Rights::WRITE)
            .expect("install port");
        assert_eq!(handle.raw(), 1);
        let outcome = run(&mut h, SyscallNumber::PortWait, [1, 0, 0, 0, 0, 0]);
        assert_eq!(
            outcome,
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
    }

    #[test]
    fn channel_reply_recv_without_read_rights_is_denied() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = call_args(&mut upage, 96);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let (_a, b) = h.exec.channel_create().expect("channel");
        let ep_obj = ObjectId::from_raw(53);
        h.exec.bind_endpoint_object(b, ep_obj);
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(ep_obj, Rights::WRITE)
            .expect("install ep");
        assert_eq!(handle.raw(), 1);
        let outcome = run(
            &mut h,
            SyscallNumber::ChannelReplyRecv,
            [args_ptr, 1, 0, 0, 0, 0],
        );
        assert_eq!(
            outcome,
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
    }
}
