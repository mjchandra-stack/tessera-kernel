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

use crate::devmgr::DmaMapper;
use crate::exec::Executive;
use crate::handle::Handle;
use crate::ipc::TransferredHandle;
use crate::ipc::{EndpointId, MAX_INLINE_BYTES, MAX_MSG_HANDLES, Message, MessageHeader};
use crate::process::ProcessTable;
use crate::rights::Rights;
use crate::syscall::{
    self, HANDLE_TRANSFER_SIZE, PORT_EVENT_RECORD_SIZE, SyscallNumber, encode_port_event,
    encode_result, read_user, write_user,
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
    /// The IOMMU that enforces this machine's DMA apertures, if it has one.
    ///
    /// `None` is the honest state for a port with no IOMMU, not a default: a
    /// device that the graph says translates and that this cannot install a
    /// translation for is a refusal, never a fall back to a physical address.
    pub iommu: Option<&'a mut dyn DmaMapper>,
    /// The interrupt controller a departing capability's route is masked at.
    ///
    /// `None` is a port that routes no device interrupts through the kernel's
    /// port facility. It is **not** the honest state for one that does: a
    /// route ended in the graph but left unmasked at the controller is the
    /// half-teardown [`crate::devmgr::InterruptRouter`] exists to prevent, and
    /// the graph has no way to notice the omission.
    pub irqs: Option<&'a mut dyn crate::devmgr::InterruptRouter>,
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
        SyscallNumber::DeviceInfo => DispatchOutcome::Return(device_info(env, req.args[0])),
        SyscallNumber::DriverLifecycle => {
            DispatchOutcome::Return(driver_lifecycle(env, req.args[0]))
        }
        SyscallNumber::MemoryCreate => DispatchOutcome::Return(memory_create(env, req.args[0])),
        SyscallNumber::MemoryMap => DispatchOutcome::Return(memory_map(env, req.args[0])),
        SyscallNumber::DmaAttach => DispatchOutcome::Return(dma_attach(env, req.args[0])),
        SyscallNumber::DmaDetach => DispatchOutcome::Return(dma_detach(env, req.args[0])),
        SyscallNumber::HandleClose => DispatchOutcome::Return(handle_close(env, req.args[0])),
        SyscallNumber::DmaRenew => DispatchOutcome::Return(dma_renew(env, req.args[0])),
        SyscallNumber::DeviceChild => DispatchOutcome::Return(device_child(env, req.args[0])),
        SyscallNumber::WakeSource => DispatchOutcome::Return(wake_source(env, req.args[0])),
        SyscallNumber::WakeHold => DispatchOutcome::Return(wake_hold(env, req.args[0])),
        SyscallNumber::SystemSuspend => DispatchOutcome::Return(system_suspend(env, req.args[0])),
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
) -> Result<(Message, Departed), KError> {
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
///
/// Also reports which device objects **departed** the sender — those whose last
/// handle left with the message. A register window follows a capability out
/// from here (`revoke_device_windows_unless_held`), but a DMA lease lives in
/// the IOMMU and can only be reached through the executive, which this does not
/// have. So it reports rather than acts, and the callers — which do have it —
/// finish the departure.
fn build_message_from_args<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    caller: usize,
    args: &syscall::ChannelMsgRequest,
    transfer: bool,
) -> Result<(Message, Departed), KError> {
    let process = processes
        .process_of_thread(caller)
        .ok_or(KError::BadHandle)?;

    // **Over a limit is refused, never trimmed** (`docs/kernel/04`: *"Messages
    // exceeding a limit are rejected at send with a protocol error rather than
    // truncated"*). A sender whose 300-byte request silently became 256 bytes
    // gets a reply to a request it did not make, and a sender whose fifth
    // handle silently stayed home gets a receiver missing a capability it was
    // promised — both are wrong answers dressed as successful sends. This is
    // also what makes an out-of-line grant the *only* way to move a large
    // payload rather than a faster one.
    let inline_len = saturating_len(args.inline_len);
    if inline_len > MAX_INLINE_BYTES {
        return Err(KError::Protocol);
    }
    let mut inline = [0u8; MAX_INLINE_BYTES];
    read_user(process, args.inline_ptr, &mut inline[..inline_len])?;

    let mut departed: Departed = [None; MAX_MSG_HANDLES];
    let mut message = Message::new(MessageHeader::new(args.interface_id, args.method_id));
    // The kernel stamps the cause from the calling thread's ambient context —
    // `ChannelMsgArgs` carries no correlation field, so ring 3 has no way to
    // supply (or forge) one. Identity comes from the kernel, never from payload
    // bytes (docs/lifecycle/04; D60). `send`/`call` restamp this for kernel-
    // originated messages; here it makes a ring-3 send carry its sender's cause.
    message.set_correlation(crate::trace::current().correlation);
    message.set_inline(&inline[..inline_len])?;

    if transfer && args.handle_count > 0 {
        let count = saturating_len(args.handle_count);
        if count > MAX_MSG_HANDLES {
            return Err(KError::Protocol);
        }
        let mut hbuf = [0u8; MAX_MSG_HANDLES * HANDLE_TRANSFER_SIZE];
        read_user(
            process,
            args.handles_ptr,
            &mut hbuf[..count * HANDLE_TRANSFER_SIZE],
        )?;
        for i in 0..count {
            let descriptor = syscall::decode_handle_transfer(
                &hbuf[i * HANDLE_TRANSFER_SIZE..(i + 1) * HANDLE_TRANSFER_SIZE],
            )?;
            // The rights the capability is to *arrive* with, which may be fewer
            // than the sender holds — including without `TRANSFER`, so a grant
            // can be made non-delegable. `take_narrowed` enforces the subset
            // rule and still requires `TRANSFER` on the source.
            let (object, rights) = process
                .handles_mut()
                .take_narrowed(Handle::from_raw(descriptor.handle), descriptor.rights)?;
            // A transferred capability takes its mapping with it. Without this
            // the sender keeps register access to a device it has given away —
            // the grant would be copied rather than moved, and the receiver's
            // "exclusive" use would be exclusive only of other receivers.
            //
            // Done here rather than inside `take` because this is the only
            // place a capability moves *between* address spaces, and it is the
            // only place that holds both the handle table and the space. The
            // helper checks first whether any handle to the device remains: a
            // process that duplicated its capability and gave one copy away
            // keeps the authority, and so keeps the window.
            if process.revoke_device_windows_unless_held(
                object,
                crate::process::WindowRevokeReason::Transferred,
            ) {
                departed[i] = Some(object);
            }
            message.add_handle(TransferredHandle { object, rights })?;
        }
    }
    Ok((message, departed))
}

/// Device objects whose last handle left a process with one message — the
/// departures the caller must finish (see [`build_message_from_args`]).
type Departed = [Option<crate::object::ObjectId>; MAX_MSG_HANDLES];

/// Ends the DMA lease and the interrupt route of every device that just left
/// `env`'s caller — everything a departing capability authorized that does not
/// live in the sender's own address space.
///
/// **Called before the send hop, never after.** `call`, `reply` and
/// `reply_receive` all hand control to a peer, and the peer may be a driver
/// that immediately asks its new device for DMA and begins a lease of its own.
/// Ending leases after the hop would tear down *that* lease — the receiver's,
/// moments old — instead of the sender's. Same discipline as the module
/// header's rule about re-deriving the process after a blocking call: nothing
/// about the world before the hop stays true across it.
fn end_bindings_of_departed<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    departed: &Departed,
) {
    let Some(holder) = env.processes.process_of_thread(env.caller).map(|p| p.id()) else {
        return;
    };
    for object in departed.iter().flatten() {
        // A memory object is not a device, and running device teardown on one
        // would emit lease and route bookkeeping for something that has
        // neither. The graph is asked rather than the entry tagged, because
        // the graph is what knows.
        if env.exec.memory_owner_of(*object).is_some() {
            // **The sender's mapping goes with the capability.**
            // `docs/kernel/04`: *"ownership moves; the sender's handle and
            // mappings are gone on send, so post-send mutation is impossible
            // by construction."* Without this the sentence is false and the
            // receiver is validating a buffer the sender can still rewrite.
            if let Some(process) = env.processes.process_of_thread(env.caller) {
                process.revoke_memory_mappings_unless_held(
                    *object,
                    crate::process::WindowRevokeReason::Transferred,
                    env.alloc,
                );
            }
            // **And so does the device's reach.** A driver that handed a
            // buffer back while its device could still write into it would be
            // returning memory that is still moving — the receiver would
            // validate bytes a DMA engine is in the middle of changing, which
            // is the same race the mapping revocation above closes, arriving
            // through the device instead of through the sender's CPU.
            //
            // Done here rather than asked of the driver, because a driver that
            // cannot forget is better than one that must remember: forgetting
            // would not fail visibly, it would corrupt a client's buffer
            // occasionally.
            let mapper = env.iommu.as_deref_mut();
            env.exec.detach_memory(*object, mapper);
            continue;
        }
        env.exec.end_device_lease(
            holder,
            *object,
            crate::devmgr::LeaseEndReason::Transferred,
            env.iommu.as_deref_mut(),
        );
        env.exec.end_device_irq_route(
            holder,
            *object,
            crate::devmgr::RouteEndReason::Transferred,
            env.irqs.as_deref_mut(),
        );
    }
}

/// Moves ownership of every memory object in `message` to the receiver.
///
/// The other half of a transfer. The sender's mapping is revoked before the
/// hop (`end_bindings_of_departed`); this is where the pages acquire the
/// process that will free them, so that at every instant exactly one process
/// owns the object and a teardown anywhere reclaims it.
fn adopt_transferred_memory<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    message: &Message,
) {
    let Some(receiver) = env.processes.process_of_thread(env.caller).map(|p| p.id()) else {
        return;
    };
    for transferred in message.handles() {
        // A no-op for anything that is not a memory object, which is why this
        // needs no filtering of its own.
        env.exec.memory_set_owner(transferred.object, receiver);
    }
}

/// What the installed-handle report holds at a position whose capability did
/// not land — a receiver's table was full, so the sender's *i*th descriptor has
/// no handle on this side.
///
/// `u32::MAX` rather than 0, because 0 is a perfectly ordinary handle: the
/// first one a fresh table hands out. A sentinel a receiver could confuse with
/// a real capability is not a sentinel.
pub const HANDLE_NOT_INSTALLED: u32 = u32::MAX;

/// Installs every handle `message` transferred into the (re-derived) caller's
/// table — the capability crossing the address-space boundary. Shared by the
/// recv side and the call-reply side.
///
/// Returns the handle values it installed, because **the receiver cannot
/// otherwise learn them**. A handle is an index *and* a generation, and
/// `take` bumps the generation of the slot it vacates — so a capability
/// returning to a table it once lived in comes back with a different value at
/// the same index, and any number the receiver remembered is stale by
/// construction. That is the generation counter doing its job; the missing
/// piece was telling the receiver the answer.
///
/// **The report is positional: entry *i* is the sender's *i*th descriptor, or
/// [`HANDLE_NOT_INSTALLED`] if that one did not land.** It used to be a
/// compacted list of successes, which is a different thing and a dangerous one
/// the moment a payload names a handle by index (`docs/api/03`: *"Handles are
/// indexed references into the message's handle vector"*). A sender that
/// attached a buffer and an endpoint, whose endpoint was dropped for want of a
/// slot, produced a report of length one — so the receiver's own slot 1 kept
/// **whatever the previous message left there**, and a field naming index 1
/// would resolve to a stale handle number rather than to an error.
fn install_transferred_handles<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    caller: usize,
    message: &Message,
) -> ([u32; MAX_MSG_HANDLES], usize) {
    let mut installed = [HANDLE_NOT_INSTALLED; MAX_MSG_HANDLES];
    let mut count = 0usize;
    if let Some(process) = processes.process_of_thread(caller) {
        for transferred in message.handles() {
            if count >= MAX_MSG_HANDLES {
                break;
            }
            // A full handle table drops the transferred capability — the
            // object reference conservation is the sender's `take`; install
            // failure is the receiver's loss, as on the x86-64 chan demo. The
            // slot still advances, so the loss is *reported* at the position
            // it happened rather than closing the gap over it.
            if let Ok(handle) = process
                .handles_mut()
                .install(transferred.object, transferred.rights)
            {
                installed[count] = handle.raw();
            }
            count += 1;
        }
    }
    (installed, count)
}

/// Writes the handles a receive installed back into the caller's buffer, so
/// it can name the capabilities it was just given.
///
/// `installed_ptr`/`installed_cap` are their own fields rather than a reuse of
/// the send side's `handles_ptr`/`handle_count`, because a **call is a send
/// and a receive at once**: that vector is already the request's input
/// transfer list, so a caller that transfers nothing but expects a capability
/// back could not say so with one pair. Passing `installed_ptr = 0` opts out.
fn report_installed_handles<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    caller: usize,
    args: &syscall::ChannelMsgRequest,
    installed: &[u32; MAX_MSG_HANDLES],
    count: usize,
) {
    if args.installed_ptr == 0 || args.installed_cap == 0 || count == 0 {
        return;
    }
    let room = saturating_len(args.installed_cap)
        .min(count)
        .min(MAX_MSG_HANDLES);
    let mut bytes = [0u8; MAX_MSG_HANDLES * 4];
    for (i, raw) in installed.iter().take(room).enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&raw.to_le_bytes());
    }
    if let Some(process) = processes.process_of_thread(caller) {
        // A receiver that named an unwritable buffer loses the report, not the
        // capability — the handle is installed either way.
        let _ = write_user(process, args.installed_ptr, &bytes[..room * 4]);
    }
}

/// Writes the arrived message's method ordinal back into the receiver's
/// descriptor, so a server can dispatch on it.
///
/// **A receiver could not otherwise learn which method it was called with.**
/// The header carries `interface_id` and `method_id` and the kernel had been
/// dropping both on delivery, which was invisible while every service on this
/// system had exactly one method. A driver class contract has several, and
/// "which one" is the first thing a server needs — before this, a block driver
/// could only be a block *reader*, because reading was the only thing a
/// request could mean.
///
/// Written in place rather than into a side buffer, which is the same
/// symmetry `inline_ptr` already has: the descriptor is the operation, and
/// after a receive its `method_id` is the method that arrived. A receiver
/// whose descriptor is not writable loses the report and keeps the message —
/// the graceful degradation `report_installed_handles` has, and for the same
/// reason: the capability, or here the payload, is delivered either way.
fn report_method_id<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    caller: usize,
    args_ptr: u64,
    method_id: u32,
) {
    if let Some(process) = processes.process_of_thread(caller) {
        let _ = write_user(
            process,
            args_ptr + syscall::CHANNEL_MSG_METHOD_ID_OFFSET,
            &method_id.to_le_bytes(),
        );
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
        Ok((msg, departed)) => {
            end_bindings_of_departed(env, &departed);
            msg
        }
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
    let (installed, installed_count) =
        install_transferred_handles(env.processes, env.caller, &reply);
    report_installed_handles(
        env.processes,
        env.caller,
        &args,
        &installed,
        installed_count,
    );
    // A reply may carry a buffer back — which is how a caller gets its memory
    // returned after a driver has filled it — so the reply direction adopts
    // ownership exactly as the receive direction does.
    adopt_transferred_memory(env, &reply);
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
    let (installed, installed_count) =
        install_transferred_handles(env.processes, env.caller, &message);
    report_installed_handles(
        env.processes,
        env.caller,
        &args,
        &installed,
        installed_count,
    );
    report_method_id(
        env.processes,
        env.caller,
        args_ptr,
        message.header().method_id,
    );
    adopt_transferred_memory(env, &message);
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
        Ok((msg, departed)) => {
            end_bindings_of_departed(env, &departed);
            msg
        }
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
        Ok((msg, departed)) => {
            end_bindings_of_departed(env, &departed);
            msg
        }
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
    let (installed, installed_count) =
        install_transferred_handles(env.processes, env.caller, &request);
    report_installed_handles(
        env.processes,
        env.caller,
        &args,
        &installed,
        installed_count,
    );
    // A reply-receive is a receive: the next request's method has to reach the
    // server the same way a plain `ChannelRecv`'s does, or a resident server
    // could dispatch on its first request and on nothing after it.
    report_method_id(
        env.processes,
        env.caller,
        args_ptr,
        request.header().method_id,
    );
    adopt_transferred_memory(env, &request);
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
/// (virtio-mmio slots are 0x200 bytes): the containing pages are mapped and the
/// returned VA carries the intra-page offset. The mapping is deliberately
/// untracked device memory ([`crate::vm::AddressSpace::map_device_range`]).
///
/// **The whole window, not its first page.** A virtio-mmio slot fits in one
/// page and for a long time nothing did otherwise, so the length the resource
/// graph holds went unused. A PCI BAR is routinely larger — QEMU's
/// virtio-blk-pci spreads its configuration structures over four pages — and a
/// driver handed only the first page of its own device can reach a quarter of
/// it and fault on the rest.
///
/// Bounded at [`MAX_DEVICE_WINDOW_BYTES`], and **refused** rather than
/// truncated past it: a driver that asked for its device and got part of it
/// would discover the difference by faulting somewhere unrelated.
#[inline(never)]
fn map_device<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return map_refused(0, KError::AccessDenied, 0);
        };
        let mut abuf = [0u8; syscall::MAP_DEVICE_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return map_refused(0, e, 0);
        }
        match syscall::decode_map_device_args(&abuf) {
            Ok(request) => request,
            Err(e) => return map_refused(0, e, 0),
        }
    };
    let (object, rights) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return map_refused(0, KError::AccessDenied, request.vaddr);
        };
        match process.handles().lookup(request.device) {
            Ok(v) => v,
            // The handle named nothing, so there is no object to report.
            Err(e) => return map_refused(0, e, request.vaddr),
        }
    };
    if !rights.contains(Rights::MAP) {
        return map_refused(object.raw(), KError::AccessDenied, request.vaddr);
    }
    let Some((phys, len)) = env.exec.mmio_of_object(object) else {
        return map_refused(object.raw(), KError::AccessDenied, request.vaddr);
    };
    let va = request.vaddr;
    if va >= A::USER_ADDRESS_MAX || va & (FRAME_SIZE - 1) != 0 {
        return map_refused(object.raw(), KError::InvalidMapping, va);
    }
    let page_base = phys & !(FRAME_SIZE - 1);
    let offset = phys & (FRAME_SIZE - 1);
    // The window spans from its first page to the last byte it covers, so an
    // unaligned base can push a sub-page window across a page boundary.
    let span = offset.saturating_add(len.max(1));
    if span > MAX_DEVICE_WINDOW_BYTES {
        return map_refused(object.raw(), KError::LimitExceeded, va);
    }
    let pages = span.div_ceil(FRAME_SIZE);
    // The whole window must land inside the user half. One page never needed
    // this check; a window can now run off the end.
    let Some(end) = va.checked_add(pages * FRAME_SIZE) else {
        return map_refused(object.raw(), KError::InvalidMapping, va);
    };
    if end > A::USER_ADDRESS_MAX {
        return map_refused(object.raw(), KError::InvalidMapping, va);
    }
    let Some(frame) = PhysFrame::from_base(PhysAddr::new(page_base)) else {
        return map_refused(object.raw(), KError::Unaligned, va);
    };
    let mapped = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return map_refused(object.raw(), KError::AccessDenied, va);
        };
        // Recorded before the mapping is installed, so a window can never
        // exist that revocation does not know about. If the table is full the
        // mapping is refused outright: an unrecorded window would survive its
        // capability's departure, which is the hole this bookkeeping closes.
        if let Err(e) = process.record_device_window(object, va, pages) {
            return map_refused(object.raw(), e, va);
        }
        let result =
            process
                .space_mut()
                .map_device_range(VirtAddr::new(va), frame, pages, env.alloc);
        if result.is_err() {
            // Nothing is installed — `map_device_range` rolls back — so this
            // window must be forgotten. Only *this* one: a process may hold
            // others on the same device, and forgetting those would leave them
            // mapped with nothing left to revoke them.
            process.forget_device_window(object, va);
        }
        result
    };
    match mapped {
        Ok(()) => {
            crate::event::emit(
                crate::event::EventKind::DeviceWindowMapped,
                crate::event::Severity::Info,
                crate::event::Component::Driver,
                [object.raw() as u64, va, page_base, len],
            );
            encode_result(Ok(va + offset))
        }
        Err(e) => map_refused(object.raw(), e, va),
    }
}

/// The largest register window `MapDevice` will map.
///
/// A bound exists because D114's argument for enumerating PCI in the kernel was
/// that "`MapDevice` grants a single page against a window of 256 MiB" — an
/// unbounded grant would quietly re-open exactly that. 64 KiB is also
/// `uabi::layout::PROBE_WINDOW_STRIDE`, the spacing a device manager probes
/// devices at, so a window can never run into the next device's slot.
pub const MAX_DEVICE_WINDOW_BYTES: u64 = 0x1_0000;

/// Records a refused `MapDevice` and encodes its ABI result. A refusal is the
/// capability system working, and until now it left no kernel record at all —
/// the driver got an errno and the machine forgot. `object` is 0 where the
/// handle never resolved to one.
fn map_refused(object: u32, error: KError, va: u64) -> i64 {
    crate::event::emit(
        crate::event::EventKind::DeviceMapRefused,
        crate::event::Severity::Warning,
        crate::event::Component::Driver,
        [object as u64, error as u64, va, 0],
    );
    encode_result(Err(error))
}

/// `DeviceInfo`: report what the device named by the caller's capability is.
///
/// Holding the capability is the whole authority check — no `Rights::MAP` is
/// required, because this reads nothing from the device and maps nothing. It
/// answers a question about a capability the caller can already name, which is
/// the kind of query that makes a capability usable rather than stronger.
///
/// A device the graph has no identity for answers `UNKNOWN`. That is an
/// answer: a manager's documented response is to probe the device's own
/// registers, which is what it does for every virtio-mmio transport.
#[inline(never)]
fn device_info<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::DEVICE_INFO_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_device_info_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let object = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        // The handle must resolve; its rights do not matter. A caller that
        // cannot name the device cannot ask about it.
        match process.handles().lookup(request.device) {
            Ok((object, _rights)) => object,
            Err(e) => return encode_result(Err(e)),
        }
    };
    // Only a device object has an identity to report. Anything else is a
    // type confusion the caller should hear about.
    if env.exec.mmio_of_object(object).is_none() && env.exec.device_of_object(object).is_none() {
        return encode_result(Err(KError::WrongType));
    }
    let record = match syscall::encode_device_info(
        env.exec.identity_of_object(object),
        env.exec.layout_of_object(object),
    ) {
        Ok(record) => record,
        Err(e) => return encode_result(Err(e)),
    };
    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    if let Err(e) = write_user(process, request.record_ptr, &record) {
        return encode_result(Err(e));
    }
    encode_result(Ok(0))
}

/// `DeviceChild`: hand a bus controller a capability to one of the devices
/// behind it.
///
/// **The first grant produced from a capability rather than from a table.**
/// Every device capability before this one came out of the kernel's own
/// registration or out of a manager that had enumerated the machine. A bus
/// controller can ask neither: what is behind its bus is known to the resource
/// graph, and the graph will only say so to something holding the bus.
///
/// Three checks, and each rules out a different way of getting authority for
/// free:
///
/// 1. **`Rights::DERIVE` on the parent.** Holding a bus is not by itself the
///    authority to hand out what is on it — a controller may be granted a bus
///    to drive without being made its broker. Kept as a separate right rather
///    than folded into `MAP` or `TRANSFER` for exactly that reason.
/// 2. **The parent must be a device.** Otherwise any object with the right bit
///    set would be a lever on whatever the graph happened to root at that id.
/// 3. **The child comes from the graph's own edges**, never from the caller.
///    An `index` selects among the children the graph already records, so
///    there is no id in the request that could name something else.
///
/// **What the child handle carries is the graph's record for the child, not a
/// narrowing of the parent's.** `DeviceTable::rights_of_object` is documented as
/// the authority the graph holds over a device — *what a kernel-originated
/// hand-out of it carries* — and this is such a hand-out. The parent's `DERIVE`
/// is the gate on **whether** the kernel hands one out; what a capability to
/// that particular device is worth is the graph's business, and it is the same
/// answer reclaim-and-rebind gives.
///
/// Deriving the rights from the parent's instead looks more conservative and is
/// simply wrong here: a bus and the devices on it are different objects wanting
/// different authority. A root port would have to be granted `MAP` — authority
/// over its own register window, which nothing should want — purely so that the
/// endpoints below it could be mapped by their drivers.
///
/// **`DERIVE` is carried down**, so a controller can walk a subtree that has a
/// switch in it. Stopping at one level would make the deepest thing a bus
/// controller could ever reach its immediate children, which on the very
/// topology this milestone added is the switch's upstream port and nothing
/// beyond. Containment is the **edge**, not attenuation: `DeviceChild` walks
/// down from what the caller holds and can name nothing off that subtree. A
/// driver handed a device by a controller receives it over a channel, where
/// rights narrow on transfer (D113), and brokers nothing because it was not
/// given `DERIVE`.
#[inline(never)]
fn device_child<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::DEVICE_CHILD_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_device_child_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let (parent, rights) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.device) {
            Ok(v) => v,
            Err(e) => return encode_result(Err(e)),
        }
    };
    if !rights.contains(Rights::DERIVE) {
        return encode_result(Err(KError::AccessDenied));
    }
    if env.exec.mmio_of_object(parent).is_none() && env.exec.device_of_object(parent).is_none() {
        return encode_result(Err(KError::WrongType));
    }

    let mut children = [crate::object::ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
    let count = env.exec.device_children_of(parent, &mut children);
    // An index past the end is an answer, not a failure: a bus with nothing on
    // it is an ordinary bus, and a controller learns the count from the same
    // record rather than from a second syscall.
    let granted = match children.get(request.index as usize) {
        Some(child) if (request.index as usize) < count => {
            // The graph's record for the child, plus the authority to keep
            // walking down. A child the graph has no rights for is not
            // grantable at all — that is a node registered without any, and
            // inventing some here would be the kernel granting what nothing
            // recorded.
            let Some(node_rights) = env.exec.device_rights_of_object(*child) else {
                return encode_result(Err(KError::BadHandle));
            };
            let granted = Rights::from_bits(node_rights.bits() | Rights::DERIVE.bits());
            let Some(process) = env.processes.process_of_thread(env.caller) else {
                return encode_result(Err(KError::AccessDenied));
            };
            match process.handles_mut().install(*child, granted) {
                Ok(handle) => Some((handle.raw(), granted.bits())),
                Err(e) => return encode_result(Err(e)),
            }
        }
        _ => None,
    };

    let record = match syscall::encode_device_child(count as u32, granted) {
        Ok(record) => record,
        Err(e) => return encode_result(Err(e)),
    };
    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    if let Err(e) = write_user(process, request.record_ptr, &record) {
        return encode_result(Err(e));
    }
    encode_result(Ok(0))
}

/// `WakeSource`: arm or disarm a device's interrupt as a system wakeup source.
///
/// **`Rights::WAKE` and not the device's own authority.** Every driver holds a
/// device and most of them have an interrupt; if arming one came with the
/// device, the set of things able to wake this machine would be the driver
/// table — which nobody chose and nobody can audit. `docs/power/01` requires
/// that set to be explicit and profile-policed, and a separate bit is what
/// makes it a decision somebody took rather than a consequence of binding.
///
/// The brokering `docs/power/01` describes therefore happens where the right
/// is *granted* rather than in this call: a manager whose manifest says an
/// entry is wake-capable hands out a capability carrying `WAKE`. There is no
/// broker object in the path, which is the difference between a check that can
/// be audited by reading the manifest and one that can only be audited by
/// watching it run.
fn wake_source<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::WAKE_SOURCE_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_wake_source_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let (device, rights) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.device) {
            Ok(v) => v,
            Err(e) => return encode_result(Err(e)),
        }
    };
    if !rights.contains(Rights::WAKE) {
        return encode_result(Err(KError::AccessDenied));
    }
    // A lifecycle for a channel is a type confusion the caller should hear
    // about rather than have recorded, and so is a wakeup source for one.
    if env.exec.mmio_of_object(device).is_none() && env.exec.device_of_object(device).is_none() {
        return encode_result(Err(KError::WrongType));
    }
    match env.exec.set_wake_source(device, request.arm) {
        Ok(()) => encode_result(Ok(0)),
        Err(e) => encode_result(Err(e)),
    }
}

/// `WakeHold`: take or release a suspend blocker, or read the wake-event
/// counter.
///
/// The counter is readable under the same right that takes a hold, and
/// deliberately so: a caller reads it *in order to* decide whether to hold, and
/// splitting the two would put a second syscall in the middle of the race this
/// facility exists to close.
///
/// A hold is attributed to the **calling process**, not to a value it supplies.
/// That is what makes an abusive holder nameable, and what lets a departing
/// process's holds go with it — neither of which works if the holder is a field
/// anybody can write.
fn wake_hold<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::WAKE_HOLD_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_wake_hold_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let holder = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let rights = match process.handles().lookup(request.power) {
            Ok((_, rights)) => rights,
            Err(e) => return encode_result(Err(e)),
        };
        if !rights.contains(Rights::WAKE) {
            return encode_result(Err(KError::AccessDenied));
        }
        process.id()
    };

    match request.op {
        syscall::WakeHoldOperation::Acquire => {
            if let Err(crate::power::WakeError::NoSpace) =
                env.exec.acquire_wake_hold(holder, request.ticks)
            {
                // Refused rather than silently not taken: a hold somebody
                // believes they have and does not is a machine that suspends
                // under a component that asked it not to.
                return encode_result(Err(KError::LimitExceeded));
            }
        }
        syscall::WakeHoldOperation::Release => {
            // Releasing one that was never taken is an answer rather than an
            // error — a caller unwinding a path it is not sure it took must
            // not have to remember, and a machine cannot be harmed by a hold
            // going away twice.
            env.exec.release_wake_hold(holder);
        }
        syscall::WakeHoldOperation::Query => {}
    }

    let events = env.exec.wake_events();
    let held = env.exec.wake_holds_held() as u32;
    let ticks = env.exec.scheduler().ticks();
    let record = match syscall::encode_wake_hold(events, held, ticks) {
        Ok(record) => record,
        Err(e) => return encode_result(Err(e)),
    };
    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    if let Err(e) = write_user(process, request.record_ptr, &record) {
        return encode_result(Err(e));
    }
    encode_result(Ok(0))
}

/// `SystemSuspend`: stop the machine, and say what started it again.
///
/// **The lifecycle ordering and the freezing are the manager's; the commit is
/// the kernel's.** By the time this is reached, the driver hosts have been
/// suspended leaves-first — an ordering `declare_lifecycle` enforces against
/// the device tree rather than trusting — and user space is frozen. What is
/// left is the step that has to be right while nothing is running.
///
/// The call blocks. When it returns, the record names the wake source, which
/// `docs/power/01` requires of the first thing a resume reports and which is
/// the one fact that cannot be reconstructed afterwards.
fn system_suspend<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::SYSTEM_SUSPEND_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_system_suspend_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let rights = match process.handles().lookup(request.power) {
            Ok((_, rights)) => rights,
            Err(e) => return encode_result(Err(e)),
        };
        // `SLEEP`, not `WAKE`. Stopping the machine and saying what may
        // interrupt it are opposite authorities, and a driver host that
        // registers a wakeup source has no business doing this.
        if !rights.contains(Rights::SLEEP) {
            return encode_result(Err(KError::AccessDenied));
        }
    }

    let report = env.exec.system_suspend(request.snapshot);

    let record = match syscall::encode_system_suspend(
        report.outcome as u32,
        report.events,
        report.source.map_or(0, |id| u64::from(id.raw())),
    ) {
        Ok(record) => record,
        Err(e) => return encode_result(Err(e)),
    };
    // Re-resolve the caller: the commit above parked this thread for the
    // duration of the sleep, and only the resumed side may touch its memory.
    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    if let Err(e) = write_user(process, request.record_ptr, &record) {
        return encode_result(Err(e));
    }
    encode_result(Ok(0))
}

/// `DmaAlloc`: allocate one zero-filled page in the caller's own address space
/// at the requested page-aligned VA and return **the address the device uses to
/// reach it**. Authorized by a device capability carrying `Rights::MAP` that
/// resolves to a real MMIO-backed device. The buffer is a **tracked** anonymous
/// mapping, so teardown reclaims its frame.
///
/// Which address that is depends on whether the device translates. A device
/// with an aperture gets an **IOVA** installed through [`DmaMapper`], reaching
/// this page and nothing else; a device with no aperture gets the **physical
/// address**, which reaches everything, and the grant says so
/// (`DEVICE_DMA_UNSCOPED`). The caller's code is identical either way — it
/// programs the number it was handed — which is what lets one driver run on a
/// machine with an IOMMU and on a machine without one.
///
/// A device the graph says translates and the port cannot install a
/// translation for is **refused**. Three ways to get there, all refusals
/// rather than a physical address: the port has no mapper, the mapper does not
/// recognize the device, or the aperture is spent. Handing back a physical
/// address in any of them would answer a request for a scoped buffer with an
/// unscoped one under the same name.
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
    // **Which address the device gets, and say which kind it is.** With an
    // aperture the device reaches only what it was given; without one the
    // address returned is a physical address it can use to reach anything, and
    // the grant is unscoped. Both are legitimate — a machine may have no
    // IOMMU — but they are not the same grant, and letting the second pass for
    // the first is the silent degradation docs/lifecycle/04 forbids. Refusing
    // instead would leave every port without an IOMMU unable to run a driver
    // at all.
    //
    // **The mapper answers this, not the graph.** Whether a device translates
    // is a fact about how the machine is wired, and the IOMMU is the thing its
    // transactions arrive at. Asking the graph for a live lease instead would
    // be a different question wearing the same words: a scoped device that has
    // not leased yet would answer "no" and be handed a physical address with a
    // warning — a silent downgrade dressed as a rename.
    //
    // A live lease also settles it, and must: translations exist for this
    // device right now, so handing back a physical address would be wrong
    // whatever the mapper currently says. That arm is what refuses rather than
    // degrades when a port reaches this path without its IOMMU in hand.
    let scoped = env.exec.lease_holder_of_object(object).is_some()
        || env
            .iommu
            .as_deref()
            .is_some_and(|mapper| mapper.translates(object));
    let device_address = if scoped {
        match install_translation(env, object, phys) {
            Ok(iova) => iova,
            Err(e) => {
                // The buffer was mapped before it was known whether the device
                // could be given an address for it, and a refusal must not
                // leave the caller a page it will never use — the failing
                // driver is about to retry, or die, and either way the frame
                // is the kernel's to reclaim. The IOVA, if one was taken,
                // stays taken: an aperture never reissues an address
                // (`DeviceAperture`).
                if let Some(process) = env.processes.process_of_thread(env.caller) {
                    let _ =
                        process
                            .space_mut()
                            .reclaim_range(VirtAddr::new(va), FRAME_SIZE, env.alloc);
                }
                // No grant record: nothing was granted.
                return encode_result(Err(e));
            }
        }
    } else {
        phys
    };

    // The grant of a device-visible buffer, recorded with both names for the
    // same memory — emitted here, past every refusal, so a `DEVICE_DMA_GRANTED`
    // record means a driver is holding a buffer rather than that one was
    // attempted. Exactly one scoped/unscoped record follows it.
    crate::event::emit(
        crate::event::EventKind::DeviceDmaGranted,
        crate::event::Severity::Info,
        crate::event::Component::Driver,
        [object.raw() as u64, va, phys, FRAME_SIZE],
    );
    if scoped {
        crate::event::emit(
            crate::event::EventKind::DeviceDmaScoped,
            crate::event::Severity::Info,
            crate::event::Component::Driver,
            [object.raw() as u64, va, device_address, phys],
        );
    } else {
        crate::event::emit(
            crate::event::EventKind::DeviceDmaUnscoped,
            crate::event::Severity::Warning,
            crate::event::Component::Driver,
            [object.raw() as u64, va, phys, 0],
        );
    }
    encode_result(Ok(device_address))
}

/// Takes an address from `device`'s lease — beginning one if the caller does
/// not have it yet — and has the port's IOMMU make it name `phys`. Every
/// failure is a refusal, see [`dma_alloc`].
fn install_translation<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    object: crate::object::ObjectId,
    phys: u64,
) -> Result<u64, KError> {
    let Some(caller) = env.processes.process_of_thread(env.caller).map(|p| p.id()) else {
        return Err(KError::AccessDenied);
    };
    // **A lease is exclusive.** Two processes can hold handles to one device —
    // duplicate one and hand a copy on — and without this the second would
    // allocate out of the first's lease, then lose its buffers without warning
    // when the *first* gave the device up. Whose lease it is has to be a fact,
    // or the lease guarantees nothing.
    match env.exec.lease_holder_of_object(object) {
        Some(holder) if holder != caller => return Err(KError::AccessDenied),
        Some(_) => {}
        None => begin_lease(env, object, caller)?,
    }
    // The mapper is resolved *before* an address is taken from the lease. An
    // address is never reissued within a lease, so allocating first would spend
    // one permanently on a path that cannot succeed — a port misconfiguration
    // would eat the lease one failed call at a time.
    let mapper = env.iommu.as_deref_mut().ok_or(KError::InvalidMapping)?;
    let iova = env
        .exec
        .device_allocate_in_aperture(object, FRAME_SIZE)
        .ok_or(KError::OutOfMemory)?;
    mapper.map(object, iova, phys, FRAME_SIZE)?;
    Ok(iova)
}

/// `DriverLifecycle`: record that a device the caller holds moved between
/// lifecycle states.
///
/// The one syscall a **device manager** has that a driver does not need, and
/// the one that closes `docs/drivers/01`'s *"transitions are observable
/// through structured events"*. Before it, the thirteen states could only be a
/// manager's private bookkeeping — the ladder was described in a design
/// document and performed by nobody in particular.
///
/// Three things are checked, in order, and each is a different way the claim
/// can be wrong:
///
/// 1. **The caller holds the device, with `Rights::MAP`.** The same authority
///    `MapDevice` and `IrqComplete` require. A process that has merely heard
///    of a device cannot narrate its lifecycle.
/// 2. **The object is a device.** A lifecycle for a channel is a type
///    confusion the caller should hear about rather than have recorded.
/// 3. **The transition is consistent** with the table of legal edges and with
///    the state the kernel last recorded (`crate::lifecycle`).
fn driver_lifecycle<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::LIFECYCLE_TRANSITION_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_lifecycle_transition_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let object = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.device) {
            Ok((object, rights)) => {
                if !rights.contains(Rights::MAP) {
                    return encode_result(Err(KError::AccessDenied));
                }
                object
            }
            Err(e) => return encode_result(Err(e)),
        }
    };
    if env.exec.mmio_of_object(object).is_none() && env.exec.device_of_object(object).is_none() {
        return encode_result(Err(KError::WrongType));
    }
    match env.exec.declare_lifecycle(
        object,
        request.from,
        request.to,
        request.reason,
        request.detail,
    ) {
        Ok(()) => encode_result(Ok(0)),
        // **Out of order is distinguishable and the others are not.** The
        // three original refusals collapse to one code deliberately: the
        // manager's recovery is the same in each case (re-read the state and
        // try again), and a caller that could tell "you are stale" from "that
        // edge does not exist" could probe the table without holding anything.
        // An ordering refusal is different in kind — the edge is legal and the
        // device tree has not caught up — and the recovery is to suspend the
        // children first and come back, which is what `WouldBlock` says.
        Err(crate::lifecycle::TransitionError::OutOfOrder { .. }) => {
            encode_result(Err(KError::WouldBlock))
        }
        Err(_) => encode_result(Err(KError::Protocol)),
    }
}

/// `MemoryCreate`: allocate a range of zeroed pages as an object the caller
/// can map and hand on.
///
/// The out-of-line buffer primitive. What makes it a *capability* rather than
/// an allocation is that the answer is a handle: it can be transferred, and
/// transferring it moves the pages without copying them.
///
/// A length above the per-object ceiling is **refused, not clamped**. A caller
/// handed a smaller object than it asked for would overrun it and find out by
/// faulting somewhere unrelated.
fn memory_create<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::MEMORY_CREATE_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_memory_create_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    if request.bytes == 0 {
        return encode_result(Err(KError::InvalidMapping));
    }
    let pages = request.bytes.div_ceil(FRAME_SIZE);
    if pages > crate::memory::MAX_OBJECT_PAGES as u64 {
        return encode_result(Err(KError::LimitExceeded));
    }

    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    let owner = process.id();
    // The space is borrowed only to zero the frames — see `MemoryTable::create`
    // for why zeroing is structural rather than the caller's to remember.
    let object = match env
        .exec
        .memory_create(owner, pages as usize, process.space(), env.alloc)
    {
        Ok(object) => object,
        Err(e) => return encode_result(Err(e)),
    };

    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    // WRITE and MAP so the creator can fill it and map it; TRANSFER so it can
    // hand it on, which is the whole point. Deliberately **not** DUPLICATE:
    // duplicating a memory capability is what `share` mode needs, and share is
    // not implemented — a right that cannot be honoured is worse than one that
    // is absent, because a caller would plan around it.
    match process.handles_mut().install(
        object,
        Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
    ) {
        Ok(handle) => encode_result(Ok(u64::from(handle.raw()))),
        Err(e) => {
            // Nothing holds the object, so its frames must go back here or
            // they are lost with no handle able to name them. It was created a
            // moment ago and nothing has had the chance to attach it, so the
            // mapper is genuinely not needed rather than merely unavailable.
            env.exec.memory_destroy(object, env.alloc, None);
            encode_result(Err(e))
        }
    }
}

/// `MemoryMap`: map a memory object the caller holds into its own address
/// space.
///
/// **Mapping rights are checked against the capability, not silently reduced
/// to it** (`docs/kernel/02`: "Mapping rights are separate from object
/// ownership rights"). A caller that asked for write on a read-only grant is
/// refused; giving it a read-only mapping instead would have it discover the
/// truth by faulting in the middle of a write it believed had succeeded.
fn memory_map<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::MEMORY_MAP_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_memory_map_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };

    let object = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.memory) {
            Ok((object, held)) => {
                if !held.contains(Rights::MAP) {
                    return encode_result(Err(KError::AccessDenied));
                }
                // The mapping may not carry authority the capability does not.
                if request.rights.writable() && !held.contains(Rights::WRITE) {
                    return encode_result(Err(KError::AccessDenied));
                }
                if request.rights.executable() && !held.contains(Rights::EXECUTE) {
                    return encode_result(Err(KError::AccessDenied));
                }
                if !held.contains(Rights::READ) {
                    return encode_result(Err(KError::AccessDenied));
                }
                object
            }
            Err(e) => return encode_result(Err(e)),
        }
    };

    let mut frames = [PhysFrame::containing(PhysAddr::new(0)); crate::memory::MAX_OBJECT_PAGES];
    let pages = env.exec.memory_frames_of(object, &mut frames);
    if pages == 0 {
        // The handle resolves to something that is not a memory object.
        return encode_result(Err(KError::WrongType));
    }
    let len = pages as u64 * FRAME_SIZE;
    if request.vaddr % FRAME_SIZE != 0 {
        return encode_result(Err(KError::Unaligned));
    }
    let end = match request.vaddr.checked_add(len) {
        Some(end) => end,
        None => return encode_result(Err(KError::InvalidMapping)),
    };
    if end > A::USER_ADDRESS_MAX {
        return encode_result(Err(KError::InvalidMapping));
    }

    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    // Recorded **before** the mapping, so a full record table fails the call
    // with nothing mapped. The reverse order would leave a mapping whose
    // retains are taken and whose record cannot be written — unrevocable, and
    // its frames stranded.
    if let Err(e) = process.record_memory_mapping(object, request.vaddr, pages as u64) {
        return encode_result(Err(e));
    }
    if let Err(e) = process.space_mut().map_shared(
        VirtAddr::new(request.vaddr),
        request.rights,
        object,
        0,
        &frames[..pages],
        env.alloc,
    ) {
        // `map_shared` rolled back its own retains, so nothing is mapped and
        // nothing is held: forgetting the record is the whole undo.
        process.forget_memory_mapping(object, request.vaddr);
        return encode_result(Err(e));
    }
    encode_result(Ok(request.vaddr))
}

/// Begins `caller`'s lease on `object`: the IOMMU gives the device an address
/// space, and the graph records who holds it.
///
/// **Lazily, at first use rather than at bind.** The kernel has no bind event
/// to hook — a capability arrives by message at one chokepoint and by direct
/// install at several others — but the deciding reason is that a lease should
/// only begin where it can be made to end. Every departure route lives on this
/// path; the direct-install sites include processes torn down with no departure
/// at all, and a lease begun there would outlive its holder and, being
/// exclusive, lock the device out for good.
fn begin_lease<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    object: crate::object::ObjectId,
    caller: crate::object::ObjectId,
) -> Result<(), KError> {
    let mapper = env.iommu.as_deref_mut().ok_or(KError::InvalidMapping)?;
    let (base, len) = mapper.begin_lease(object)?;
    if let Err(e) = env.exec.device_set_aperture(
        object,
        caller,
        crate::devmgr::DeviceAperture::new(base, len),
        // A lease taken by a driver asking for DMA does not expire until the
        // driver asks for a deadline. Defaulting one on would give every
        // existing driver a lifetime it never agreed to, and expiry is a
        // contract between the holder and the kernel rather than a rule the
        // kernel imposes on a holder that has not heard of it.
        None,
    ) {
        // The hardware was configured and the graph was not, so nothing would
        // ever end this lease. Undo the half that took.
        mapper.end_lease(object);
        return Err(e);
    }
    crate::event::emit(
        crate::event::EventKind::DeviceDmaLeaseBegan,
        crate::event::Severity::Info,
        crate::event::Component::Driver,
        [object.raw() as u64, caller.raw() as u64, base, len],
    );
    Ok(())
}

/// `HandleClose`: give up a capability the caller holds.
///
/// **Without this a program frees a memory object by dying.** Nothing else in
/// the system releases one: `Process` deliberately forgets its handles on drop
/// (driver-restart conservation depends on it), and a transfer hands the object
/// on rather than releasing it. So a resident service that made a buffer per
/// request got `MAX_MEMORY_OBJECTS` requests and then stopped — a lifetime
/// measured in how much work it had done.
///
/// A capability can leave a process by being closed exactly as by being
/// transferred, and the same three things follow a device out
/// (`end_bindings_of_departed` is the sibling). What is new here is the fourth:
/// a memory object the caller **owns** goes back to the allocator, because a
/// close is the last moment anyone can say so.
fn handle_close<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    raw_handle: u64,
) -> i64 {
    let handle = Handle::from_raw(raw_handle as u32);
    // Dropped first, then asked about: after the drop the handle names nothing,
    // so "is this object still held" is a question about the *remaining*
    // handles, which is the question that matters.
    let (object, still_held, owner) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let object = match process.handles_mut().drop_handle(handle) {
            Ok(object) => object,
            Err(e) => return encode_result(Err(e)),
        };
        (object, process.handles().holds(object), process.id())
    };
    if still_held {
        // A process holding the same capability twice has not given it up.
        return encode_result(Ok(0));
    }

    // A memory object this process owns: detach it from any device, then let
    // the frames go. Ownership is what decides it, and it must — a *receiver*
    // closing a handle to a buffer it was lent must not free the sender's
    // memory, and ownership is the single-valued fact that tells them apart.
    if env.exec.memory_owner_of(object) == Some(owner) {
        if let Some(process) = env.processes.process_of_thread(env.caller) {
            process.revoke_memory_mappings_unless_held(
                object,
                crate::process::WindowRevokeReason::HandleClosed,
                env.alloc,
            );
        }
        let mapper = env.iommu.as_deref_mut();
        let released = env.exec.memory_destroy(object, env.alloc, mapper);
        return encode_result(Ok(released as u64));
    }

    // A device: the register window, the DMA lease and the interrupt route all
    // followed the capability in, and all three follow it out.
    if let Some(process) = env.processes.process_of_thread(env.caller)
        && process.revoke_device_windows_unless_held(
            object,
            crate::process::WindowRevokeReason::HandleClosed,
        )
    {
        let mapper = env.iommu.as_deref_mut();
        env.exec.end_device_lease(
            owner,
            object,
            crate::devmgr::LeaseEndReason::HandleClosed,
            mapper,
        );
        let router = env.irqs.as_deref_mut();
        env.exec.end_device_irq_route(
            owner,
            object,
            crate::devmgr::RouteEndReason::HandleClosed,
            router,
        );
    }
    encode_result(Ok(0))
}

/// `DmaAttach`: make a memory object the caller holds reachable by a device it
/// holds, and return the address the device uses.
///
/// **This is what makes an out-of-line grant a mechanism rather than a
/// demonstration.** Without it a driver handed a buffer can only copy through a
/// page of its own that `DmaAlloc` already made device-visible, so the CPU
/// touches every byte — and the classes this exists for move bytes no CPU
/// should touch.
///
/// The shape mirrors [`dma_alloc`] deliberately: same authority, same
/// scoped-versus-unscoped decision, same three events. What differs is where
/// the memory comes from — an object the caller already holds, rather than a
/// page allocated on the spot — and that is the whole of the change.
fn dma_attach<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::DMA_ATTACH_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_dma_attach_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };

    // Both capabilities, both with MAP. The device's is the authority
    // `MapDevice` and `DmaAlloc` require; the memory's is what lets a client
    // hand out a buffer that may be read and written but not exposed to a
    // device, by narrowing MAP away before it transfers it.
    let (device, memory) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let device = match process.handles().lookup(request.device) {
            Ok((object, rights)) if rights.contains(Rights::MAP) => object,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        };
        let memory = match process.handles().lookup(request.memory) {
            Ok((object, rights)) if rights.contains(Rights::MAP) => object,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        };
        (device, memory)
    };
    if env.exec.mmio_of_object(device).is_none() {
        return encode_result(Err(KError::AccessDenied));
    }
    if env.exec.memory_owner_of(memory).is_none() {
        // Not a memory object. A type confusion the caller should hear about,
        // rather than an attachment of whatever else that id names.
        return encode_result(Err(KError::WrongType));
    }
    if env.exec.memory_attachment_of(memory).is_some() {
        return encode_result(Err(KError::AlreadyMapped));
    }

    let mut frames = [tessera_karch::PhysFrame::containing(tessera_karch::PhysAddr::new(0));
        crate::memory::MAX_OBJECT_PAGES];
    let pages = env.exec.memory_frames_of(memory, &mut frames);
    if pages == 0 {
        return encode_result(Err(KError::BadHandle));
    }
    let len = pages as u64 * FRAME_SIZE;

    // The same authority on scoped-ness as `dma_alloc`, and for the same
    // reason: the mapper knows how the machine is wired, and a live lease
    // settles it whatever the mapper currently says.
    let scoped = env.exec.lease_holder_of_object(device).is_some()
        || env
            .iommu
            .as_deref()
            .is_some_and(|mapper| mapper.translates(device));

    let address = if scoped {
        match attach_translations(env, device, memory, &frames[..pages]) {
            Ok(base) => base,
            Err(e) => return encode_result(Err(e)),
        }
    } else {
        // **No IOMMU: the address is the frame's own, and one frame is all
        // this can honestly serve.** Physical frames are not contiguous, so a
        // multi-page object has no single base — returning the first would
        // hand the device an address that runs off the end of one page and
        // into whatever the allocator put next to it.
        if pages > 1 {
            return encode_result(Err(KError::NotSupported));
        }
        frames[0].base().as_u64()
    };

    if let Err(e) = env.exec.memory_attach(
        memory,
        crate::memory::Attachment {
            device,
            address,
            len,
            scoped,
        },
    ) {
        // The record is what every revocation path reads. Without it the
        // translations would be unreachable — installed, and nothing able to
        // name them — so they come back out before the refusal is returned.
        if scoped {
            let mapper = env.iommu.as_deref_mut();
            if let Some(mapper) = mapper {
                let _ = mapper.unmap(device, address, len);
            }
        }
        return encode_result(Err(e));
    }

    crate::event::emit(
        crate::event::EventKind::DeviceDmaGranted,
        crate::event::Severity::Info,
        crate::event::Component::Driver,
        [device.raw() as u64, memory.raw() as u64, address, len],
    );
    if scoped {
        crate::event::emit(
            crate::event::EventKind::DeviceDmaScoped,
            crate::event::Severity::Info,
            crate::event::Component::Driver,
            [
                device.raw() as u64,
                memory.raw() as u64,
                address,
                frames[0].base().as_u64(),
            ],
        );
    } else {
        crate::event::emit(
            crate::event::EventKind::DeviceDmaUnscoped,
            crate::event::Severity::Warning,
            crate::event::Component::Driver,
            [device.raw() as u64, memory.raw() as u64, address, len],
        );
    }
    encode_result(Ok(address))
}

/// Takes one contiguous run of device addresses for the whole object and points
/// each page of it at the object's corresponding frame.
///
/// **One run, so the device gets one address.** Per-page allocation would give
/// a multi-page object addresses with no relationship to each other, and the
/// only way to describe it to a device would be a descriptor per frame — which
/// is scatter-gather, a different interface with a different return value.
fn attach_translations<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    device: crate::object::ObjectId,
    memory: crate::object::ObjectId,
    frames: &[tessera_karch::PhysFrame],
) -> Result<u64, KError> {
    let Some(caller) = env.processes.process_of_thread(env.caller).map(|p| p.id()) else {
        return Err(KError::AccessDenied);
    };
    // A lease is exclusive, exactly as in `install_translation`: two processes
    // can hold handles to one device, and without this the second would
    // allocate out of the first's lease and lose its addresses without warning
    // when the first gave the device up.
    match env.exec.lease_holder_of_object(device) {
        Some(holder) if holder != caller => return Err(KError::AccessDenied),
        Some(_) => {}
        None => begin_lease(env, device, caller)?,
    }
    let len = frames.len() as u64 * FRAME_SIZE;
    // Mapper before address, for the reason `install_translation` gives: an
    // address is never reissued within a lease, so allocating first would spend
    // one permanently on a path that cannot succeed.
    if env.iommu.is_none() {
        return Err(KError::InvalidMapping);
    }
    // **The address this object had here before, if it had one.** Re-attaching
    // is what a driver does on every request for a buffer it serves more than
    // once, and taking a fresh address each time would spend the aperture in
    // proportion to how much work the driver had done rather than to how many
    // buffers it uses. Reissuing this one names the frames it already named —
    // see `MemoryObject::last_attachment`.
    let base = match env.exec.memory_remembered_address(memory, device) {
        Some(address) => address,
        None => env
            .exec
            .device_allocate_in_aperture(device, len)
            .ok_or(KError::OutOfMemory)?,
    };
    for (page, frame) in frames.iter().enumerate() {
        let at = base + page as u64 * FRAME_SIZE;
        let mapper = env.iommu.as_deref_mut().ok_or(KError::InvalidMapping)?;
        if let Err(e) = mapper.map(device, at, frame.base().as_u64(), FRAME_SIZE) {
            // Undo the pages that did land. A half-attached object would let
            // the device read part of a buffer and fault on the rest, which is
            // a worse thing to debug than a clean refusal.
            for done in 0..page {
                let _ = mapper.unmap(device, base + done as u64 * FRAME_SIZE, FRAME_SIZE);
            }
            return Err(e);
        }
    }
    Ok(base)
}

/// `DmaRenew`: say a DMA lease is still wanted, and until when.
///
/// **The only way a holder can tell the kernel it is still there.** Everything
/// else a lease ends by is an event — a capability moved, a device faulted, a
/// holder died. Expiry is the absence of one, and this is the syscall whose
/// absence it detects.
fn dma_renew<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::DMA_RENEW_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_dma_renew_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let (device, holder) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let device = match process.handles().lookup(request.device) {
            Ok((object, rights)) if rights.contains(Rights::MAP) => object,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        };
        (device, process.id())
    };
    // `renew_lease` refuses for a device with no live lease *and* for a caller
    // that is not the holder, and both are `NotMapped` here rather than
    // separate answers: from ring 3 they are the same situation — you do not
    // have a lease on this device — and telling the two apart would report
    // whether somebody *else* holds one.
    if env
        .exec
        .renew_device_lease(device, holder, request.expires_at)
    {
        encode_result(Ok(0))
    } else {
        encode_result(Err(KError::NotMapped))
    }
}

/// `DmaDetach`: stop a device reaching a memory object the caller holds.
///
/// After this the device's next transaction to the address `DmaAttach` returned
/// faults. A driver need not call it before handing the buffer back — the
/// transfer detaches it — so this is for a driver that wants a buffer back in
/// CPU-land while continuing to hold it.
fn dma_detach<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let handle = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::DMA_DETACH_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_dma_detach_args(&abuf) {
            Ok(handle) => handle,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let memory = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(handle) {
            Ok((object, rights)) if rights.contains(Rights::MAP) => object,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        }
    };
    if env.exec.memory_attachment_of(memory).is_none() {
        // Nothing to end. `NotMapped` rather than success, so a driver that
        // detached twice — or detached something it never attached — hears
        // about the mistake instead of believing a device stopped reaching
        // memory that was never reachable in the first place.
        return encode_result(Err(KError::NotMapped));
    }
    let mapper = env.iommu.as_deref_mut();
    match env.exec.detach_memory(memory, mapper) {
        Some(_) => encode_result(Ok(0)),
        // The mapper refused, so the translation may still be live. Reported
        // as a failure and the record kept: the caller must go on treating
        // that memory as reachable by the device.
        None => encode_result(Err(KError::InvalidMapping)),
    }
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
        /// The port's IOMMU, absent unless a test installs one — the state of
        /// four of the five ports.
        iommu: Option<MockMapper>,
        /// The port's interrupt controller, absent unless a test installs one.
        irqs: Option<MockRouter>,
    }

    /// An interrupt-controller stand-in, recording every line it was told to
    /// stop delivering. A test cannot otherwise tell a route the graph merely
    /// forgot from one that was actually masked — which is the whole
    /// difference between revocation and bookkeeping.
    #[derive(Default)]
    struct MockRouter {
        masked: std::vec::Vec<u32>,
    }

    impl crate::devmgr::InterruptRouter for MockRouter {
        fn mask(&mut self, intid: u32) {
            self.masked.push(intid);
        }
    }

    /// An IOMMU stand-in: it records what it was asked to install and every
    /// lease it began or ended, which is the only way a test can tell an IOVA
    /// that was *installed* from a number that merely came back, or a lease
    /// that was *torn down* from one the graph merely forgot.
    #[derive(Default)]
    struct MockMapper {
        installed: std::vec::Vec<(ObjectId, u64, u64, u64)>,
        /// Ranges the mapper was told to stop translating, so a test can see
        /// that a detach reached the hardware rather than only the record.
        removed: std::vec::Vec<(ObjectId, u64, u64)>,
        began: std::vec::Vec<ObjectId>,
        ended: std::vec::Vec<ObjectId>,
        /// Devices this unit is in front of. Empty means an IOMMU that exists
        /// but has nothing behind it — every grant is honestly unscoped.
        behind: std::vec::Vec<ObjectId>,
        /// The range a lease gets, so a test can size exhaustion.
        window: (u64, u64),
        /// A mapper that refuses — hardware whose tables cannot describe the
        /// range, which must not become a physical address handed back.
        refuses: bool,
    }

    impl MockMapper {
        fn over(device: ObjectId, base: u64, len: u64) -> Self {
            Self {
                behind: std::vec![device],
                window: (base, len),
                ..Self::default()
            }
        }
    }

    impl DmaMapper for MockMapper {
        fn translates(&self, device: ObjectId) -> bool {
            self.behind.contains(&device)
        }

        fn begin_lease(&mut self, device: ObjectId) -> Result<(u64, u64), KError> {
            if self.refuses {
                return Err(KError::InvalidMapping);
            }
            self.began.push(device);
            Ok(self.window)
        }

        fn map(&mut self, device: ObjectId, iova: u64, phys: u64, len: u64) -> Result<(), KError> {
            if self.refuses {
                return Err(KError::InvalidMapping);
            }
            self.installed.push((device, iova, phys, len));
            Ok(())
        }

        fn unmap(&mut self, device: ObjectId, iova: u64, len: u64) -> Result<(), KError> {
            if self.refuses {
                return Err(KError::InvalidMapping);
            }
            self.removed.push((device, iova, len));
            Ok(())
        }

        fn end_lease(&mut self, device: ObjectId) {
            self.ended.push(device);
            self.installed.retain(|(d, ..)| *d != device);
        }
    }

    /// One running thread whose process owns `handle 0` on `device_obj` with
    /// `rights`, its space mapping the user page at `upage`'s host address.
    fn harness(upage: &UserPage, rights: Rights) -> Harness {
        let mut frames = MockFrameSource::new(0x1000_0000, 256);
        let mut exec = Box::new(Executive::<MockContextOps>::new(4, 0));
        let device_obj = ObjectId::from_raw(21);
        exec.device_register_mmio(
            device_obj,
            0x0a00_3e00,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
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
            iommu: None,
            irqs: None,
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
            iommu: h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper),
            irqs: h
                .irqs
                .as_mut()
                .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
        };
        dispatch(&mut env, &req)
    }

    /// The object id `harness` registers its device under — what the
    /// event-reading tests filter on, so records emitted concurrently by other
    /// tests cannot be mistaken for theirs.
    const HARNESS_DEVICE: u64 = 21;

    /// Serializes the tests that *read* the global event ring. Concurrent
    /// emission is harmless (every assertion filters by device object), but a
    /// concurrent drain would steal the records under test.
    static EVENT_RING: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn blank_event() -> crate::event::KernelEvent {
        crate::event::record(
            crate::event::EventKind::EventsDropped,
            crate::event::Severity::Debug,
            crate::event::Component::Observability,
            0,
            crate::trace::TraceContext::NONE,
            [0; 4],
        )
    }

    /// Takes the ring lock and drains what is already buffered, so the ring has
    /// room for the records the test is about to cause — a full ring drops at
    /// the source, and an assertion on a dropped record would fail for a reason
    /// that has nothing to do with the code under test.
    fn event_ring_guard() -> std::sync::MutexGuard<'static, ()> {
        let guard = EVENT_RING.lock().unwrap_or_else(|e| e.into_inner());
        let mut sink = [blank_event(); crate::event::EVENT_RING_CAPACITY];
        while crate::event::drain(&mut sink) > 0 {}
        guard
    }

    /// Every buffered record naming the harness device, in emission order.
    fn drained_device_events() -> std::vec::Vec<crate::event::KernelEvent> {
        let mut sink = [blank_event(); crate::event::EVENT_RING_CAPACITY];
        let n = crate::event::drain(&mut sink);
        sink[..n]
            .iter()
            .filter(|e| e.component == crate::event::Component::Driver && e.arg0 == HARNESS_DEVICE)
            .copied()
            .collect()
    }

    /// Writes a `HandleTransfer` descriptor into the user page at offset 2048 —
    /// the transfer vector the message-building tests point `handles_ptr` at.
    /// `rights` is what the capability is to *arrive* with.
    fn write_transfer(upage: &mut UserPage, handle: u32, rights: Rights) -> u64 {
        let at = 2048;
        upage.0[at..at + syscall::HANDLE_TRANSFER_SIZE].fill(0);
        upage.0[at..at + 4].copy_from_slice(&handle.to_le_bytes());
        upage.0[at + 8..at + 16].copy_from_slice(&rights.bits().to_le_bytes());
        upage.0.as_ptr() as u64 + at as u64
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
            iommu: None,
            irqs: None,
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

    /// Registers the harness device over a different region, for the tests
    /// that care how big a window is rather than who holds it.
    fn rewindow(h: &mut Harness, base: u64, len: u64) {
        h.exec
            .device_register_mmio(
                ObjectId::from_raw(0x5a),
                base,
                len,
                Rights::READ | Rights::MAP,
            )
            .expect("register");
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ObjectId::from_raw(0x5a), Rights::READ | Rights::MAP)
            .expect("install");
    }

    /// A window is not a page. A PCI BAR spans several, and a driver handed
    /// only the first page of its own device reaches a quarter of it — which is
    /// exactly what blocked the ring-3 virtio-pci driver.
    #[test]
    fn map_device_maps_every_page_of_a_multi_page_window() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        rewindow(&mut h, 0x0b00_0000, 4 * FRAME_SIZE);
        let handle = 1; // the second handle this process was given
        let args_ptr = device_args(&mut upage, handle, 0x4100_0000);

        assert_eq!(
            run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Ok(0x4100_0000)))
        );
        let process = h.processes.process_of_thread(h.caller).expect("process");
        for page in 0..4 {
            assert!(
                process
                    .space()
                    .arch()
                    .translate(VirtAddr::new(0x4100_0000 + page * FRAME_SIZE))
                    .is_some(),
                "page {page} of the window is not mapped",
            );
        }
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4100_0000 + 4 * FRAME_SIZE))
                .is_none(),
            "and the window stops where it ends",
        );
        // One record for the window, not one per page — see the event summary.
        assert_eq!(process.device_window_count(), 1);
    }

    /// Builds a `LifecycleTransitionArgs` in the user page.
    fn lifecycle_args(
        upage: &mut UserPage,
        handle: u32,
        from: crate::lifecycle::DriverState,
        to: crate::lifecycle::DriverState,
    ) -> u64 {
        let at = 384;
        let args = crate::isl_binding::lifecycle::LifecycleTransitionArgs {
            size: syscall::LIFECYCLE_TRANSITION_ARGS_SIZE as u32,
            version: 1,
            flags: 0,
            device: tessera_isl_runtime::HandleRef::new(handle),
            from,
            to,
            reason: crate::lifecycle::TransitionReason::Enumerated,
            detail: 0xbeef,
        };
        tessera_isl_runtime::encode(
            &args,
            &mut upage.0[at..at + syscall::LIFECYCLE_TRANSITION_ARGS_SIZE],
        )
        .expect("encode");
        upage.0.as_ptr() as u64 + at as u64
    }

    /// A manager declares a transition for a device it holds, and the kernel
    /// records it — the syscall that makes `docs/drivers/01`'s "transitions
    /// are observable through structured events" true rather than aspirational.
    #[test]
    fn a_held_devices_lifecycle_transition_is_recorded() {
        use crate::lifecycle::DriverState::*;
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
        let args = lifecycle_args(&mut upage, 0, Discovered, Matched);
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DriverLifecycle,
                [args, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(0),
        );
        assert_eq!(h.exec.lifecycle_of_object(device), Some(Matched));

        let events = drained_device_events();
        let record = events
            .iter()
            .find(|e| e.kind == crate::event::EventKind::DriverLifecycleTransition)
            .expect("the transition was not recorded");
        assert_eq!(record.arg0, HARNESS_DEVICE, "the device");
        assert_eq!(record.arg1, Discovered as u64);
        assert_eq!(record.arg2, Matched as u64);
        // The manager's uninterpreted detail rides in the envelope's flags.
        assert_eq!(record.flags, 0xbeef);
    }

    /// A process that does not hold the device cannot narrate its lifecycle.
    /// Without `Rights::MAP` a bystander could write a plausible history for
    /// hardware it has only heard of, and nothing downstream could tell.
    #[test]
    fn a_lifecycle_transition_needs_the_device_authority() {
        use crate::lifecycle::DriverState::*;
        let mut upage = UserPage([0; 4096]);
        // READ only: enough to name the device, not enough to speak for it.
        let mut h = harness(&upage, Rights::READ);
        let args = lifecycle_args(&mut upage, 0, Discovered, Matched);
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DriverLifecycle,
                [args, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
        );
        assert_eq!(
            h.exec
                .lifecycle_of_object(ObjectId::from_raw(HARNESS_DEVICE as u32)),
            None,
            "and nothing was recorded",
        );
        let _ = drained_device_events();
    }

    /// A transition the table does not contain is refused, and the recorded
    /// state is unchanged — the difference between a record stream and a
    /// sequence.
    #[test]
    fn an_inconsistent_lifecycle_transition_is_refused() {
        use crate::lifecycle::DriverState::*;
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
        let open = lifecycle_args(&mut upage, 0, Discovered, Matched);
        run(
            &mut h,
            SyscallNumber::DriverLifecycle,
            [open, 0, 0, 0, 0, 0],
        );

        // Matched -> Active skips Starting and Probing: a legal-looking claim
        // that could not have happened.
        let skip = lifecycle_args(&mut upage, 0, Matched, Active);
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DriverLifecycle,
                [skip, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(encode_result(Err(KError::Protocol))),
        );
        assert_eq!(h.exec.lifecycle_of_object(device), Some(Matched));

        // And so is a transition from a state the device is not in.
        let stale = lifecycle_args(&mut upage, 0, Active, Degraded);
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DriverLifecycle,
                [stale, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(encode_result(Err(KError::Protocol))),
        );
        assert_eq!(h.exec.lifecycle_of_object(device), Some(Matched));

        let events = drained_device_events();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.kind == crate::event::EventKind::DriverLifecycleTransition)
                .count(),
            1,
            "only the one that was accepted",
        );
    }

    /// A receiver learns which method it was called with.
    ///
    /// Before this the kernel carried `method_id` in the header and dropped it
    /// on delivery, which was invisible while every service here had exactly
    /// one method — a block driver could only be a block *reader*, because
    /// reading was the only thing a request could mean. A class contract has
    /// several methods, and "which one" is the first thing a server needs.
    #[test]
    fn a_receive_reports_the_method_the_message_named() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);

        let (a, b) = h.exec.channel_create().expect("channel");
        let ep_obj = ObjectId::from_raw(51);
        h.exec.bind_endpoint_object(b, ep_obj);
        let handle = h
            .processes
            .process_of_thread(h.caller)
            .expect("process")
            .handles_mut()
            .install(ep_obj, Rights::READ)
            .expect("install");
        let mut message = Message::new(MessageHeader::new(0x99, 7));
        message.set_inline(&[1, 2, 3, 4]).expect("inline");
        h.exec.send(a, message).expect("queued");

        // A descriptor naming method 0 — the value every caller writes when it
        // is not sending.
        let base = upage.0.as_ptr() as u64;
        let args_at = 512usize;
        {
            let args = &mut upage.0[args_at..args_at + syscall::CHANNEL_MSG_ARGS_SIZE];
            args.fill(0);
            args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
            args[4..8].copy_from_slice(&4u32.to_le_bytes());
            args[40..48].copy_from_slice(&(base + 1024).to_le_bytes()); // inline_ptr
            args[48..56].copy_from_slice(&64u64.to_le_bytes()); // inline_len
        }
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::ChannelRecv,
                [base + args_at as u64, u64::from(handle.raw()), 0, 0, 0, 0],
            ),
            DispatchOutcome::Return(4),
        );

        // The descriptor now names the method that arrived, written in place.
        let at = args_at + syscall::CHANNEL_MSG_METHOD_ID_OFFSET as usize;
        assert_eq!(
            u32::from_le_bytes([
                upage.0[at],
                upage.0[at + 1],
                upage.0[at + 2],
                upage.0[at + 3]
            ]),
            7,
        );
    }

    /// Builds a `MemoryCreateArgs` in the user page and returns its pointer.
    fn memory_create_args(upage: &mut UserPage, bytes: u64) -> u64 {
        let at = 640;
        let args = crate::isl_binding::memory::MemoryCreateArgs {
            size: syscall::MEMORY_CREATE_ARGS_SIZE as u32,
            version: 1,
            flags: 0,
            bytes,
        };
        tessera_isl_runtime::encode(
            &args,
            &mut upage.0[at..at + syscall::MEMORY_CREATE_ARGS_SIZE],
        )
        .expect("encode");
        upage.0.as_ptr() as u64 + at as u64
    }

    /// Builds a `MemoryMapArgs` in the user page and returns its pointer.
    fn memory_map_args(upage: &mut UserPage, handle: u32, vaddr: u64, rights: u32) -> u64 {
        let at = 704;
        let args = crate::isl_binding::memory::MemoryMapArgs {
            size: syscall::MEMORY_MAP_ARGS_SIZE as u32,
            version: 1,
            flags: 0,
            memory: tessera_isl_runtime::HandleRef::new(handle),
            rights: crate::isl_binding::memory::MapRights(rights),
            vaddr,
        };
        tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::MEMORY_MAP_ARGS_SIZE])
            .expect("encode");
        upage.0.as_ptr() as u64 + at as u64
    }

    /// A VA well clear of the harness's user page and device windows.
    const GRANT_VA: u64 = 0x5000_0000;
    const MAP_RW: u32 = 0x1 | 0x2;

    /// Create, then map: the caller gets pages it can write, and the object
    /// knows who owns them.
    #[test]
    fn a_created_memory_object_maps_into_its_creator() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let args = memory_create_args(&mut upage, FRAME_SIZE);
        let handle = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u32,
            other => panic!("create failed: {other:?}"),
        };

        let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
        assert_eq!(
            run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(GRANT_VA as i64),
        );
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(GRANT_VA))
                .is_some(),
            "the page is mapped",
        );
        assert_eq!(process.memory_mapping_count(), 1);
        // And the kernel can copy into it, which is what makes it usable as a
        // payload buffer rather than only as ring-3 memory.
        assert!(syscall::validate_user_range(process.space(), GRANT_VA, FRAME_SIZE, true).is_ok(),);
    }

    /// A length above the per-object ceiling is **refused, not clamped**. A
    /// caller handed a smaller object than it asked for would overrun it and
    /// find out by faulting somewhere unrelated.
    #[test]
    fn an_oversized_object_is_refused_rather_than_trimmed() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let too_big = (crate::memory::MAX_OBJECT_PAGES as u64 + 1) * FRAME_SIZE;
        let args = memory_create_args(&mut upage, too_big);
        assert_eq!(
            run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::LimitExceeded))),
        );
        // And zero is not a request for nothing, it is a request that cannot
        // be honoured.
        let args = memory_create_args(&mut upage, 0);
        assert_eq!(
            run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping))),
        );
    }

    /// **Mapping rights are checked against the capability, never silently
    /// reduced to it.** A caller that asked for write on a read-only grant and
    /// got a read-only mapping would discover the truth by faulting in the
    /// middle of a write it believed had succeeded.
    #[test]
    fn a_mapping_cannot_carry_authority_the_capability_lacks() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let args = memory_create_args(&mut upage, FRAME_SIZE);
        let handle = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u32,
            other => panic!("create failed: {other:?}"),
        };
        // Narrow the capability to read-only, then ask for a writable mapping.
        {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .replace_rights(
                    crate::handle::Handle::from_raw(handle),
                    Rights::READ | Rights::MAP,
                )
                .expect("narrow");
        }
        let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
        assert_eq!(
            run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
        );
        // Read-only is granted, because that the capability does carry.
        let args = memory_map_args(&mut upage, handle, GRANT_VA, 0x1);
        assert_eq!(
            run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(GRANT_VA as i64),
        );
    }

    /// A handle that is not a memory object is a type confusion the caller
    /// should hear about, not a mapping of whatever happens to be nearby.
    #[test]
    fn mapping_something_that_is_not_a_memory_object_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        // Handle 0 is the harness's *device*, which carries READ | MAP — so
        // a read-only request clears the authority checks and reaches the
        // question this is about: it is not a memory object.
        let args = memory_map_args(&mut upage, 0, GRANT_VA, 0x1);
        assert_eq!(
            run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::WrongType))),
        );
    }

    /// **The sentence the mode is named for.** `docs/kernel/04`: *"ownership
    /// moves; the sender's handle and mappings are gone on send, so post-send
    /// mutation is impossible by construction."* Without the revocation the
    /// receiver would be validating a buffer the sender can still rewrite —
    /// a time-of-check race by construction rather than by accident.
    #[test]
    fn transferring_a_buffer_takes_the_senders_mapping_with_it() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        let args = memory_create_args(&mut upage, FRAME_SIZE);
        let handle = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u32,
            other => panic!("create failed: {other:?}"),
        };
        let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
        run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]);

        // Hand it on.
        let handles_ptr = write_transfer(
            &mut upage,
            handle,
            Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
        );
        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        let (_msg, departed) =
            build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
        {
            let mut env = DispatchEnv {
                exec: &mut h.exec,
                processes: &mut h.processes,
                caller: h.caller,
                alloc: &mut h.frames,
                iommu: None,
                irqs: None,
            };
            end_bindings_of_departed(&mut env, &departed);
        }

        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(GRANT_VA))
                .is_none(),
            "the sender's page is gone",
        );
        assert_eq!(process.memory_mapping_count(), 0, "and so is the record");
        // The kernel will not copy through the revoked range either — the
        // property a stale tracked record would silently destroy.
        assert!(
            syscall::validate_user_range(process.space(), GRANT_VA, FRAME_SIZE, false).is_err(),
        );
    }

    /// A capability's departure takes the **whole** window with it. Unmapping
    /// only the first page would leave a driver reading registers it no longer
    /// holds the capability for.
    #[test]
    fn revocation_unmaps_every_page_of_a_multi_page_window() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        rewindow(&mut h, 0x0b00_0000, 4 * FRAME_SIZE);
        let args_ptr = device_args(&mut upage, 1, 0x4100_0000);
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = crate::handle::Handle::from_raw(1);
        let mut objects = crate::object::ObjectTable::new();
        let _ = process.handles_mut().close(&mut objects, handle);
        process.revoke_device_windows_unless_held(
            ObjectId::from_raw(0x5a),
            crate::process::WindowRevokeReason::HandleClosed,
        );

        for page in 0..4 {
            assert!(
                process
                    .space()
                    .arch()
                    .translate(VirtAddr::new(0x4100_0000 + page * FRAME_SIZE))
                    .is_none(),
                "page {page} survived the revocation",
            );
        }
        assert_eq!(process.device_window_count(), 0);
    }

    /// A window that collides part-way through rolls back to nothing.
    ///
    /// Device pages are deliberately untracked, so the space's overlap check is
    /// blind to them and a collision is only discovered when the arch layer
    /// refuses the page — part-way in. A half-installed window is worse than
    /// none: the caller is told it has no mapping while some pages are live,
    /// and the window record does not describe them.
    #[test]
    fn a_window_that_collides_part_way_leaves_nothing_behind() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        rewindow(&mut h, 0x0b00_0000, 4 * FRAME_SIZE);

        // Something already occupies the third page of where the window goes.
        {
            let Harness {
                processes,
                frames,
                caller,
                ..
            } = &mut h;
            let process = processes.process_of_thread(*caller).expect("process");
            process
                .space_mut()
                .map_anonymous(
                    VirtAddr::new(0x4100_2000),
                    FRAME_SIZE,
                    PageFlags::rw().user(),
                    frames,
                )
                .expect("occupy");
        }

        let args_ptr = device_args(&mut upage, 1, 0x4100_0000);
        assert_eq!(
            run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AlreadyMapped)))
        );

        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert_eq!(process.device_window_count(), 0, "the record is gone");
        for page in [0u64, 1] {
            assert!(
                process
                    .space()
                    .arch()
                    .translate(VirtAddr::new(0x4100_0000 + page * FRAME_SIZE))
                    .is_none(),
                "page {page} was installed before the collision and stayed",
            );
        }
        // The occupant is untouched — the rollback took back only its own.
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4100_2000))
                .is_some(),
        );
    }

    /// A window larger than the kernel will grant is **refused**, not
    /// truncated. A driver given part of its device would find out by faulting
    /// somewhere it had no reason to expect.
    #[test]
    fn an_oversized_window_is_refused_rather_than_truncated() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        rewindow(&mut h, 0x0b00_0000, MAX_DEVICE_WINDOW_BYTES + FRAME_SIZE);
        let args_ptr = device_args(&mut upage, 1, 0x4100_0000);

        assert_eq!(
            run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::LimitExceeded)))
        );
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert_eq!(process.device_window_count(), 0, "and nothing was recorded");
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4100_0000))
                .is_none(),
            "and nothing was mapped",
        );
    }

    /// **One record per grant, whatever the window's size.** The event summary
    /// reads a device granted twice as a rebind; a four-page window counted
    /// once per page would make a single mapping look like four, and the
    /// driver-rebind check would pass on evidence that never happened.
    #[test]
    fn a_multi_page_window_is_one_grant_record_carrying_its_length() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        rewindow(&mut h, 0x0b00_0000, 4 * FRAME_SIZE);
        let args_ptr = device_args(&mut upage, 1, 0x4100_0000);

        let _guard = event_ring_guard();
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        let mut sink = [blank_event(); crate::event::EVENT_RING_CAPACITY];
        let n = crate::event::drain(&mut sink);
        let grants: std::vec::Vec<_> = sink[..n]
            .iter()
            .filter(|e| e.kind == crate::event::EventKind::DeviceWindowMapped && e.arg0 == 0x5a)
            .collect();
        assert_eq!(grants.len(), 1, "one grant, not one per page");
        assert_eq!(grants[0].arg3, 4 * FRAME_SIZE, "carrying the real length");
    }

    #[test]
    fn map_device_records_a_window_so_the_grant_can_be_revoked() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert_eq!(process.device_window_count(), 0);

        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert_eq!(process.device_window_count(), 1);
    }

    /// Narrowing, through the syscall path a ring-3 sender actually uses: the
    /// descriptor names fewer rights than the sender holds, and the message
    /// carries exactly those.
    #[test]
    fn a_transfer_descriptor_narrows_the_rights_that_travel() {
        let mut upage = UserPage([0; 4096]);
        // The sender holds READ|MAP|TRANSFER and grants only READ|MAP — the
        // capability arrives unable to be handed on.
        let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);

        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        let message =
            build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
        let transferred = message.0.handles().next().expect("one handle");
        assert_eq!(transferred.rights, Rights::READ | Rights::MAP);
        assert!(!transferred.rights.contains(Rights::TRANSFER));
    }

    /// A sender cannot mint authority it does not have by asking for it on the
    /// way out, and a refused transfer leaves the handle where it was.
    #[test]
    fn a_transfer_descriptor_cannot_widen_rights() {
        let mut upage = UserPage([0; 4096]);
        let handles_ptr = write_transfer(
            &mut upage,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::WRITE,
        );
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);

        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        assert_eq!(
            build_message_from_args(&mut h.processes, h.caller, &args, true).err(),
            Some(KError::AccessDenied)
        );
        // The capability did not move.
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(process.handles().rights(Handle::from_raw(0)).is_ok());
    }

    /// A reserved field with something in it describes a wire format this
    /// kernel does not implement, so the message is refused rather than
    /// decoded around.
    /// Builds a `DmaAttachArgs` in the user page and returns its pointer.
    fn attach_args(upage: &mut UserPage, device: u32, memory: u32) -> u64 {
        let at = 768;
        let args = crate::isl_binding::memory::DmaAttachArgs {
            size: syscall::DMA_ATTACH_ARGS_SIZE as u32,
            version: 1,
            flags: 0,
            device: tessera_isl_runtime::HandleRef::new(device),
            memory: tessera_isl_runtime::HandleRef::new(memory),
        };
        tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::DMA_ATTACH_ARGS_SIZE])
            .expect("encode");
        upage.0.as_ptr() as u64 + at as u64
    }

    /// Builds a `DmaDetachArgs` in the user page and returns its pointer.
    fn detach_args(upage: &mut UserPage, memory: u32) -> u64 {
        let at = 832;
        let args = crate::isl_binding::memory::DmaDetachArgs {
            size: syscall::DMA_DETACH_ARGS_SIZE as u32,
            version: 1,
            flags: 0,
            memory: tessera_isl_runtime::HandleRef::new(memory),
            reserved: 0,
        };
        tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::DMA_DETACH_ARGS_SIZE])
            .expect("encode");
        upage.0.as_ptr() as u64 + at as u64
    }

    /// Creates a one-page object and returns its handle.
    fn make_object(h: &mut Harness, upage: &mut UserPage) -> u32 {
        let args = memory_create_args(upage, FRAME_SIZE);
        match run(h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u32,
            other => panic!("create failed: {other:?}"),
        }
    }

    /// **The milestone's sentence.** A device reaches a buffer the driver
    /// never allocated and never mapped, at an address the IOMMU translates —
    /// which is what lets a full-sector transfer happen without a CPU copy.
    #[test]
    fn a_memory_object_becomes_reachable_by_a_device_at_a_translated_address() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let memory = make_object(&mut h, &mut upage);

        let args = attach_args(&mut upage, 0, memory);
        let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u64,
            other => panic!("attach failed: {other:?}"),
        };
        // The address is the device's, not the memory's: translating is
        // precisely the difference between the two.
        let mapper = h.iommu.as_ref().expect("iommu");
        assert_eq!(mapper.installed.len(), 1);
        let (device, iova, phys, len) = mapper.installed[0];
        assert_eq!(device, ObjectId::from_raw(21));
        assert_eq!(iova, address);
        assert_eq!(len, FRAME_SIZE);
        assert_ne!(
            iova, phys,
            "an IOVA that equalled the phys translates nothing"
        );
    }

    /// Detach unmaps exactly what attach mapped, and the record goes with it.
    #[test]
    fn detaching_stops_the_device_reaching_it() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let memory = make_object(&mut h, &mut upage);
        let args = attach_args(&mut upage, 0, memory);
        let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u64,
            other => panic!("attach failed: {other:?}"),
        };

        let args = detach_args(&mut upage, memory);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaDetach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0),
        );
        assert_eq!(
            h.iommu.as_ref().expect("iommu").removed,
            std::vec![(ObjectId::from_raw(21), address, FRAME_SIZE)],
        );
        // Detaching twice is an error, not a comfortable no-op: a driver that
        // hears "fine" for something that did not happen learns nothing.
        let args = detach_args(&mut upage, memory);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaDetach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::NotMapped))),
        );
    }

    /// A second attach is refused **and the first survives**. Replacing the
    /// record would leave a translation installed that nothing can name, and
    /// therefore that nothing will ever remove.
    #[test]
    fn attaching_twice_is_refused_and_leaves_the_first_alone() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let memory = make_object(&mut h, &mut upage);
        let args = attach_args(&mut upage, 0, memory);
        let first = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u64,
            other => panic!("attach failed: {other:?}"),
        };
        let args = attach_args(&mut upage, 0, memory);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AlreadyMapped))),
        );
        let mapper = h.iommu.as_ref().expect("iommu");
        assert_eq!(mapper.installed.len(), 1, "no second translation");
        assert!(mapper.removed.is_empty(), "and the first was not torn down");
        assert_eq!(
            h.exec
                .memory_attachment_of(ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE))
                .expect("attachment")
                .address,
            first,
        );
    }

    /// **Handing the buffer on takes the device's reach with it**, without the
    /// driver having to remember. A driver that returned a buffer its device
    /// was still writing into would hand back memory that is still moving.
    #[test]
    fn transferring_an_attached_buffer_detaches_it() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let memory = make_object(&mut h, &mut upage);
        let args = attach_args(&mut upage, 0, memory);
        let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u64,
            other => panic!("attach failed: {other:?}"),
        };

        let handles_ptr = write_transfer(
            &mut upage,
            memory,
            Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
        );
        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        let (_msg, departed) =
            build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
        {
            let mut env = DispatchEnv {
                exec: &mut h.exec,
                processes: &mut h.processes,
                caller: h.caller,
                alloc: &mut h.frames,
                iommu: h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper),
                irqs: None,
            };
            end_bindings_of_departed(&mut env, &departed);
        }
        assert_eq!(
            h.iommu.as_ref().expect("iommu").removed,
            std::vec![(ObjectId::from_raw(21), address, FRAME_SIZE)],
            "the device stopped reaching it when the capability left",
        );
    }

    /// **The device's lease ending clears the record without unmapping.** The
    /// translations are already gone and the address range belongs to whoever
    /// leases next — an `unmap` into it would be reaching into someone else's
    /// address space, and a record that survived would make the object look
    /// reachable by a device that can now reach nothing.
    #[test]
    fn a_lease_ending_forgets_the_attachment_without_unmapping() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let memory = make_object(&mut h, &mut upage);
        let args = attach_args(&mut upage, 0, memory);
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]);
        let object = ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE);
        assert!(h.exec.memory_attachment_of(object).is_some());

        let holder = h
            .processes
            .process_of_thread(h.caller)
            .expect("process")
            .id();
        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        h.exec.end_device_lease(
            holder,
            ObjectId::from_raw(21),
            crate::devmgr::LeaseEndReason::Transferred,
            mapper,
        );

        assert!(
            h.exec.memory_attachment_of(object).is_none(),
            "the record went with the lease",
        );
        assert!(
            h.iommu.as_ref().expect("iommu").removed.is_empty(),
            "and nothing was unmapped into a range that is no longer ours",
        );
        assert_eq!(
            h.iommu.as_ref().expect("iommu").ended,
            std::vec![ObjectId::from_raw(21)]
        );
    }

    /// **A multi-page object on a device with no IOMMU is refused.** Physical
    /// frames are not contiguous, so there is no single address to return —
    /// and returning the first page's would hand the device an address that
    /// runs off the end of that page into whatever the allocator put next.
    #[test]
    fn an_unscoped_attach_of_more_than_one_page_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        // No IOMMU installed — the state of four of the five ports.
        let args = memory_create_args(&mut upage, 2 * FRAME_SIZE);
        let memory = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u32,
            other => panic!("create failed: {other:?}"),
        };
        let args = attach_args(&mut upage, 0, memory);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::NotSupported))),
        );

        // One page is served, and the address is the frame's own.
        let args = memory_create_args(&mut upage, FRAME_SIZE);
        let single = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u32,
            other => panic!("create failed: {other:?}"),
        };
        let args = attach_args(&mut upage, 0, single);
        assert!(matches!(
            run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(v) if v > 0,
        ));
    }

    /// Attaching needs `MAP` on **both** capabilities. Narrowing it away from
    /// the memory is how a client hands out a buffer that may be read and
    /// written but not exposed to a device.
    #[test]
    fn attaching_without_map_on_either_handle_is_denied() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let memory = make_object(&mut h, &mut upage);
        {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .replace_rights(crate::handle::Handle::from_raw(memory), Rights::READ)
                .expect("narrow");
        }
        let args = attach_args(&mut upage, 0, memory);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
        );
        assert!(h.iommu.as_ref().expect("iommu").installed.is_empty());
    }

    /// **`Removed` becomes reachable.** It has been a terminal lifecycle state
    /// with a full table of transitions into it since the driver framework
    /// landed, and until a removal existed nothing could put a device there —
    /// a state the design described and the machine could never enter.
    #[test]
    fn removal_records_the_terminal_state_nothing_could_reach_before() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let device = ObjectId::from_raw(21);
        // A device that got as far as serving before it was pulled.
        for (from, to) in [
            (
                crate::lifecycle::DriverState::Discovered,
                crate::lifecycle::DriverState::Matched,
            ),
            (
                crate::lifecycle::DriverState::Matched,
                crate::lifecycle::DriverState::Starting,
            ),
            (
                crate::lifecycle::DriverState::Starting,
                crate::lifecycle::DriverState::Probing,
            ),
            (
                crate::lifecycle::DriverState::Probing,
                crate::lifecycle::DriverState::Active,
            ),
        ] {
            h.exec
                .declare_lifecycle(
                    device,
                    from,
                    to,
                    crate::lifecycle::TransitionReason::Unspecified,
                    0,
                )
                .expect("transition");
        }

        h.exec.remove_device(
            device,
            crate::lifecycle::TransitionReason::Removed,
            &mut h.processes,
            None,
            None,
        );
        assert_eq!(
            h.exec.lifecycle_state_of(device),
            Some(crate::lifecycle::DriverState::Removed),
            "a device pulled while Active is Removed, not still Active",
        );
    }

    /// **A lease that stops being renewed ends itself**    /// **A lease that stops being renewed ends itself**, through the very path
    /// a departure uses — `LeaseEndReason::Expired` is a third caller of
    /// `end_one_lease`, not a second teardown. A lease that expired into a
    /// different state from one that was given up would be a second way for
    /// the machine to be quiet about a device still translating.
    #[test]
    fn a_lease_nobody_renews_expires_the_way_a_departure_ends() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let device = ObjectId::from_raw(21);
        let args = device_args(&mut upage, 0, 0x4001_0000);
        run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);

        let holder = h
            .processes
            .process_of_thread(h.caller)
            .expect("process")
            .id();
        assert!(h.exec.renew_device_lease(device, holder, Some(100)));

        // Before the deadline nothing happens, and that is as much a part of
        // the mechanism as the expiry: a sweep that ended leases early would
        // be indistinguishable from one that worked.
        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        assert_eq!(h.exec.expire_leases(99, mapper), 0);
        assert!(h.exec.lease_holder_of_object(device).is_some());

        // Renewal moves it out of reach again.
        assert!(h.exec.renew_device_lease(device, holder, Some(200)));
        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        assert_eq!(h.exec.expire_leases(150, mapper), 0);
        assert!(h.exec.lease_holder_of_object(device).is_some());

        // And past it, the lease goes exactly as a departure would take it.
        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        assert_eq!(h.exec.expire_leases(200, mapper), 1);
        assert!(h.exec.lease_holder_of_object(device).is_none());
        assert_eq!(
            h.iommu.as_ref().expect("iommu").ended,
            std::vec![device],
            "the hardware teardown is the same one",
        );
    }

    /// The syscall a driver actually calls: renew from ring 3, and the lease
    /// survives a sweep past where it would otherwise have expired.
    #[test]
    fn a_driver_can_renew_its_own_lease_through_the_syscall() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let device = ObjectId::from_raw(21);
        let args = device_args(&mut upage, 0, 0x4001_0000);
        run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);

        let renew = |upage: &mut UserPage, ticks: u64| -> u64 {
            let at = 896;
            let args = crate::isl_binding::memory::DmaRenewArgs {
                size: syscall::DMA_RENEW_ARGS_SIZE as u32,
                version: 1,
                flags: 0,
                device: tessera_isl_runtime::HandleRef::new(0),
                reserved: 0,
                ticks,
            };
            tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::DMA_RENEW_ARGS_SIZE])
                .expect("encode");
            upage.0.as_ptr() as u64 + at as u64
        };

        let ptr = renew(&mut upage, 100);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaRenew, [ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0),
        );
        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        assert_eq!(h.exec.expire_leases(99, mapper), 0);

        // Renewed again, it outlives the deadline it used to have.
        let ptr = renew(&mut upage, 500);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaRenew, [ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0),
        );
        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        assert_eq!(h.exec.expire_leases(200, mapper), 0);
        assert!(h.exec.lease_holder_of_object(device).is_some());

        // And past the new one it goes, through the departure path.
        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        assert_eq!(h.exec.expire_leases(500, mapper), 1);
        assert!(h.exec.lease_holder_of_object(device).is_none());

        // Renewing a lease that is gone is refused, not quietly accepted.
        let ptr = renew(&mut upage, 900);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaRenew, [ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::NotMapped))),
        );
    }

    /// A renewal is the **holder's** statement about its own lease. Anyone
    /// else making it would keep alive a lease its owner had stopped wanting,
    /// which is the whole thing expiry exists to notice.
    #[test]
    fn only_the_holder_can_renew_its_lease() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let device = ObjectId::from_raw(21);
        let args = device_args(&mut upage, 0, 0x4001_0000);
        run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);

        assert!(
            !h.exec
                .renew_device_lease(device, ObjectId::from_raw(0xfeed), Some(500)),
            "a stranger cannot extend somebody else's lease",
        );
        // And a device with no lease at all has nothing to renew.
        assert!(!h.exec.renew_device_lease(
            ObjectId::from_raw(0x99),
            ObjectId::from_raw(0x99),
            Some(500),
        ));
    }

    /// A lease with no deadline never expires. Every driver that predates this
    /// has one, and giving them all a lifetime they never agreed to would be
    /// the mechanism breaking its own users on the way in.
    #[test]
    fn a_lease_with_no_deadline_outlives_every_sweep() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let args = device_args(&mut upage, 0, 0x4001_0000);
        run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);

        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        assert_eq!(h.exec.expire_leases(u64::MAX, mapper), 0);
        assert!(
            h.exec
                .lease_holder_of_object(ObjectId::from_raw(21))
                .is_some()
        );
    }

    /// **The departure nobody chose.** Every other route a capability leaves by
    /// is something its holder did; this one runs while the holder is alive and
    /// using the device. Two processes hold it, and afterwards neither does.
    #[test]
    fn removing_a_device_takes_it_from_every_holder() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let device = ObjectId::from_raw(21);
        // A second process holding the same device — two drivers, or a manager
        // and the driver it granted to.
        let second = {
            let mut frames = MockFrameSource::new(0x2000_0000, 64);
            let space =
                AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_9000_0000_0000, Asid(2))
                    .expect("space");
            let mut process = Process::new(ObjectId::from_raw(0x71), space);
            process
                .handles_mut()
                .install(device, Rights::READ | Rights::MAP)
                .expect("install");
            h.processes.insert(process).expect("insert")
        };
        assert!(
            h.processes
                .get_mut(second)
                .expect("p")
                .handles()
                .holds(device)
        );

        let report = h.exec.remove_device(
            device,
            crate::lifecycle::TransitionReason::Removed,
            &mut h.processes,
            None,
            None,
        );
        assert!(report.existed);
        assert_eq!(report.holders, 2, "both holders, not just the first");
        assert!(
            !h.processes
                .get_mut(second)
                .expect("p")
                .handles()
                .holds(device),
            "the capability was taken from a living holder",
        );
        let caller = h.processes.process_of_thread(h.caller).expect("process");
        assert!(!caller.handles().holds(device));
    }

    /// **What makes the capability invalid rather than merely unheld.** The
    /// node is gone, so every syscall that reaches a device refuses — and not
    /// one of them had to learn a new rule.
    #[test]
    fn every_device_syscall_refuses_once_the_device_is_removed() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let device = ObjectId::from_raw(21);
        // Re-install a handle after the removal, so what is being tested is the
        // *device* being gone rather than the handle being taken.
        h.exec.remove_device(
            device,
            crate::lifecycle::TransitionReason::Removed,
            &mut h.processes,
            None,
            None,
        );
        let handle = {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .install(device, Rights::READ | Rights::MAP)
                .expect("install")
                .raw()
        };

        let args = device_args(&mut upage, handle, 0x4002_0000);
        assert_eq!(
            run(&mut h, SyscallNumber::MapDevice, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
        );
        let args = device_args(&mut upage, handle, 0x4003_0000);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
        );
        let memory = make_object(&mut h, &mut upage);
        let args = attach_args(&mut upage, handle, memory);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
        );
    }

    /// The window is unmapped in the holder that had one — a driver must not
    /// keep register access to a device that is no longer in the machine.
    #[test]
    fn removal_unmaps_the_register_window_it_finds() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let args = device_args(&mut upage, 0, 0x4001_0000);
        assert!(matches!(
            run(&mut h, SyscallNumber::MapDevice, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(v) if v >= 0,
        ));
        assert!(
            h.processes
                .process_of_thread(h.caller)
                .expect("process")
                .space()
                .arch()
                .translate(VirtAddr::new(0x4001_0000))
                .is_some(),
        );

        let report = h.exec.remove_device(
            ObjectId::from_raw(21),
            crate::lifecycle::TransitionReason::Removed,
            &mut h.processes,
            None,
            None,
        );
        assert_eq!(report.windows, 1);
        assert!(
            h.processes
                .process_of_thread(h.caller)
                .expect("process")
                .space()
                .arch()
                .translate(VirtAddr::new(0x4001_0000))
                .is_none(),
            "register access went with the device",
        );
    }

    /// **The lease and the route end before any handle moves**, and the mock is
    /// what can tell: a device that has been pulled must stop translating
    /// whatever else succeeds.
    #[test]
    fn removal_ends_the_lease_before_it_touches_a_handle() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let args = device_args(&mut upage, 0, 0x4001_0000);
        run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);
        assert!(
            h.exec
                .lease_holder_of_object(ObjectId::from_raw(21))
                .is_some()
        );

        let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
        h.exec.remove_device(
            ObjectId::from_raw(21),
            crate::lifecycle::TransitionReason::Removed,
            &mut h.processes,
            mapper,
            None,
        );
        assert_eq!(
            h.iommu.as_ref().expect("iommu").ended,
            std::vec![ObjectId::from_raw(21)],
        );
        assert!(
            h.exec
                .lease_holder_of_object(ObjectId::from_raw(21))
                .is_none()
        );
    }

    /// Removing something already removed is a no-op, not an error: a bus may
    /// report one disappearance twice, and the second report is not a bug in
    /// the reporter.
    #[test]
    fn removing_a_device_twice_is_harmless() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let device = ObjectId::from_raw(21);
        assert!(
            h.exec
                .remove_device(
                    device,
                    crate::lifecycle::TransitionReason::Removed,
                    &mut h.processes,
                    None,
                    None
                )
                .existed
        );
        let second = h.exec.remove_device(
            device,
            crate::lifecycle::TransitionReason::Removed,
            &mut h.processes,
            None,
            None,
        );
        assert!(!second.existed);
        assert_eq!(second.holders, 0);
    }

    /// **A bus controller does not leave alone.** Pulling a switch takes the
    /// ports and the endpoints below it in one physical event; a graph that
    /// removed only the node named would leave the children resolving,
    /// mapping and authorizing DMA for hardware that is not there.
    #[test]
    fn removing_a_controller_removes_everything_behind_it() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        // The harness' device 21 becomes the root port, with a switch's two
        // ports and an endpoint below it — the hotplug machine's topology.
        let bridge = ObjectId::from_raw(21);
        let below = [0x51, 0x52, 0x53].map(ObjectId::from_raw);
        for (index, id) in below.iter().enumerate() {
            h.exec
                .device_register_mmio(
                    *id,
                    0x0a00_5000 + 0x1000 * index as u64,
                    FRAME_SIZE,
                    Rights::READ | Rights::MAP,
                )
                .expect("register");
        }
        h.exec.device_set_parent(below[0], bridge).expect("edge");
        h.exec.device_set_parent(below[1], below[0]).expect("edge");
        h.exec.device_set_parent(below[2], below[1]).expect("edge");

        // A driver holding the endpoint at the bottom, which has asked nobody
        // about any of this.
        {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .install(below[2], Rights::READ | Rights::MAP)
                .expect("install");
        }

        let report = h.exec.remove_device(
            bridge,
            crate::lifecycle::TransitionReason::Removed,
            &mut h.processes,
            None,
            None,
        );
        assert!(report.existed);
        assert_eq!(
            report.subtree, 4,
            "the port, both switch ports, the endpoint"
        );

        // Every node is gone, so every device syscall refuses for all of them
        // — the deepest one included, which is the node a single removal would
        // have left behind.
        for id in [bridge, below[0], below[1], below[2]] {
            assert!(
                h.exec.mmio_of_object(id).is_none(),
                "{id:?} still resolves after its bus was pulled",
            );
        }
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(
            !process.handles().holds(below[2]),
            "the endpoint's holder was never asked, and holds nothing",
        );
    }

    /// The other half: a leaf leaving must not take its bus with it. Removal
    /// walks down from what was named, never up.
    #[test]
    fn removing_a_leaf_leaves_its_bus_and_its_siblings_alone() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let bridge = ObjectId::from_raw(21);
        let siblings = [0x61, 0x62].map(ObjectId::from_raw);
        for (index, id) in siblings.iter().enumerate() {
            h.exec
                .device_register_mmio(
                    *id,
                    0x0a00_7000 + 0x1000 * index as u64,
                    FRAME_SIZE,
                    Rights::READ | Rights::MAP,
                )
                .expect("register");
            h.exec.device_set_parent(*id, bridge).expect("edge");
        }

        let report = h.exec.remove_device(
            siblings[0],
            crate::lifecycle::TransitionReason::Removed,
            &mut h.processes,
            None,
            None,
        );
        assert_eq!(report.subtree, 1, "one function, not the bus it sat on");
        assert!(
            h.exec.mmio_of_object(bridge).is_some(),
            "the bus is still there"
        );
        assert!(
            h.exec.mmio_of_object(siblings[1]).is_some(),
            "so is its sibling"
        );
        assert!(h.exec.mmio_of_object(siblings[0]).is_none());
    }

    /// **The bound this milestone exists to remove.** A device address is never
    /// reissued within a lease, so before this every request a driver served
    /// spent one — and the SMMU machine's lease is two pages. Re-attaching the
    /// same object lands where it landed before, so a driver serving one
    /// buffer runs as long as it likes.
    #[test]
    fn reattaching_one_object_reuses_its_address_forever() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        // An aperture of exactly two pages — the real one on the SMMU machine.
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            2 * FRAME_SIZE,
        ));
        let memory = make_object(&mut h, &mut upage);

        let mut seen = None;
        for round in 0..8 {
            let args = attach_args(&mut upage, 0, memory);
            let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
                DispatchOutcome::Return(v) if v >= 0 => v as u64,
                other => panic!("attach {round} failed: {other:?}"),
            };
            match seen {
                None => seen = Some(address),
                Some(first) => assert_eq!(address, first, "round {round} moved"),
            }
            let args = detach_args(&mut upage, memory);
            assert_eq!(
                run(&mut h, SyscallNumber::DmaDetach, [args, 0, 0, 0, 0, 0]),
                DispatchOutcome::Return(0),
            );
        }
        // Eight rounds through a two-page aperture. Every one of them mapped
        // and unmapped for real — the reuse is of the address, not of the
        // translation.
        let mapper = h.iommu.as_ref().expect("iommu");
        assert_eq!(mapper.installed.len(), 8);
        assert_eq!(mapper.removed.len(), 8);
    }

    /// A **different** object still gets a different address, and the aperture
    /// still runs out. That is the rule intact: what is reissued is an address
    /// for the memory it already named, never for other memory.
    #[test]
    fn a_second_object_gets_its_own_address_and_the_aperture_still_ends() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            2 * FRAME_SIZE,
        ));
        let first = make_object(&mut h, &mut upage);
        let second = make_object(&mut h, &mut upage);
        let third = make_object(&mut h, &mut upage);

        let args = attach_args(&mut upage, 0, first);
        let a = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u64,
            other => panic!("attach failed: {other:?}"),
        };
        let args = attach_args(&mut upage, 0, second);
        let b = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u64,
            other => panic!("attach failed: {other:?}"),
        };
        assert_ne!(a, b, "two objects must not share one address");

        // The aperture holds two pages and both are spent. A third object is
        // refused rather than handed one of theirs.
        let args = attach_args(&mut upage, 0, third);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::OutOfMemory))),
        );
    }

    /// **Closing the last handle to a buffer you own gives the frames back.**
    /// Before this the only ways were dying and handing it on, so a resident
    /// service's lifetime was measured in how much work it had done.
    #[test]
    fn closing_an_owned_memory_object_releases_its_frames() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let memory = make_object(&mut h, &mut upage);
        let before = h.frames.free_list_depth();

        assert_eq!(
            run(
                &mut h,
                SyscallNumber::HandleClose,
                [u64::from(memory), 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(1),
        );
        assert_eq!(
            h.frames.free_list_depth(),
            before + 1,
            "the object's frame came back",
        );
        // The handle is gone with it, so a second close is a bad handle rather
        // than a second release.
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::HandleClose,
                [u64::from(memory), 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(encode_result(Err(KError::BadHandle))),
        );
    }

    /// Closing **one of two** handles to the same object frees nothing: the
    /// process has not given the capability up, it has given up one name for
    /// it.
    #[test]
    fn closing_one_of_two_handles_keeps_the_object() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let memory = make_object(&mut h, &mut upage);
        let object = ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE);
        let second = {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .install(object, Rights::READ | Rights::MAP)
                .expect("second handle")
                .raw()
        };
        let before = h.frames.free_list_depth();
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::HandleClose,
                [u64::from(memory), 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(0),
        );
        assert_eq!(h.frames.free_list_depth(), before, "nothing was released");
        // And the surviving handle still names it.
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::HandleClose,
                [u64::from(second), 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(1),
        );
    }

    /// **A receiver closing a lent buffer must not free the sender's memory.**
    /// Ownership is the single-valued fact that tells the two apart, and this
    /// is the case it exists for.
    #[test]
    fn closing_a_buffer_you_do_not_own_frees_nothing() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let memory = make_object(&mut h, &mut upage);
        let object = ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE);
        // Somebody else owns it now — the state a driver is in while it holds
        // a client's transferred buffer.
        h.exec.memory_set_owner(object, ObjectId::from_raw(0xbeef));

        let before = h.frames.free_list_depth();
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::HandleClose,
                [u64::from(memory), 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(0),
        );
        assert_eq!(
            h.frames.free_list_depth(),
            before,
            "the owner's frames are not the closer's to release",
        );
        assert!(
            h.exec.memory_owner_of(object).is_some(),
            "and it still exists"
        );
    }

    /// Closing an attached object detaches it first — the frames must not go
    /// back to the allocator while a device can still write into them.
    #[test]
    fn closing_an_attached_object_detaches_before_freeing() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let memory = make_object(&mut h, &mut upage);
        let args = attach_args(&mut upage, 0, memory);
        let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u64,
            other => panic!("attach failed: {other:?}"),
        };
        let before = h.frames.free_list_depth();

        assert_eq!(
            run(
                &mut h,
                SyscallNumber::HandleClose,
                [u64::from(memory), 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(1),
        );
        assert_eq!(
            h.iommu.as_ref().expect("iommu").removed,
            std::vec![(ObjectId::from_raw(21), address, FRAME_SIZE)],
            "the device stopped reaching it before the frame moved",
        );
        assert_eq!(
            h.frames.free_list_depth(),
            before + 1,
            "and then the frame moved",
        );
    }

    /// Closing a **device** capability takes its register window, its DMA
    /// lease and its interrupt route out with it — the same three that follow
    /// it out on a transfer.
    #[test]
    fn closing_a_device_ends_what_the_capability_was_holding() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        // Take a lease by asking for a DMA buffer.
        let args_ptr = device_args(&mut upage, 0, 0x4001_0000);
        run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
        assert!(
            h.exec
                .lease_holder_of_object(ObjectId::from_raw(21))
                .is_some()
        );

        assert_eq!(
            run(&mut h, SyscallNumber::HandleClose, [0, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0),
        );
        assert!(
            h.exec
                .lease_holder_of_object(ObjectId::from_raw(21))
                .is_none(),
            "the lease left with the capability",
        );
        assert_eq!(
            h.iommu.as_ref().expect("iommu").ended,
            std::vec![ObjectId::from_raw(21)],
        );
    }

    /// **A capability that did not land is reported at its own position.** The
    /// report is what a payload's handle index resolves against, so a report
    /// that closed the gap over a dropped capability would leave the
    /// receiver's slot holding whatever the *previous* message left there —
    /// and a field naming that index would resolve to a stale handle number
    /// instead of to an error.
    #[test]
    fn a_dropped_capability_holds_its_place_in_the_installed_report() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ);
        let mut message = crate::ipc::Message::new(crate::ipc::MessageHeader::new(0, 0));
        for object in [ObjectId::from_raw(0x900), ObjectId::from_raw(0x901)] {
            message
                .add_handle(crate::ipc::TransferredHandle {
                    object,
                    rights: Rights::READ,
                })
                .expect("attach");
        }
        // Fill the receiver's table so neither capability can be installed.
        {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            while process
                .handles_mut()
                .install(ObjectId::from_raw(0xf00), Rights::READ)
                .is_ok()
            {}
        }

        let (installed, count) = install_transferred_handles(&mut h.processes, h.caller, &message);
        // Two descriptors, two positions — the count is what the sender sent,
        // not what survived.
        assert_eq!(count, 2);
        assert_eq!(installed[0], HANDLE_NOT_INSTALLED);
        assert_eq!(installed[1], HANDLE_NOT_INSTALLED);
        // And the sentinel is not a handle number anyone could hold: 0 is the
        // first handle a fresh table hands out, so a zero-filled report would
        // read as "you were given handle 0".
        assert_ne!(HANDLE_NOT_INSTALLED, 0);
    }

    /// **A message over a limit is refused, not trimmed** (`docs/kernel/04`).
    /// Truncating is the failure mode that looks like success: the send
    /// returns, the receiver answers a shorter request than the one the sender
    /// wrote, and the disagreement surfaces as a wrong answer rather than an
    /// error.
    #[test]
    fn an_oversized_message_is_refused_rather_than_truncated() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        let base = upage.0.as_ptr() as u64;
        let mut args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: base,
            inline_len: MAX_INLINE_BYTES as u64 + 1,
            handles_ptr: 0,
            handle_count: 0,
            installed_ptr: 0,
            installed_cap: 0,
        };
        assert_eq!(
            build_message_from_args(&mut h.processes, h.caller, &args, false).err(),
            Some(KError::Protocol),
        );
        // Exactly at the limit is a message, not an error — the boundary
        // belongs on the inside.
        args.inline_len = MAX_INLINE_BYTES as u64;
        assert!(build_message_from_args(&mut h.processes, h.caller, &args, false).is_ok());

        // The same for the transfer vector: a fifth handle silently staying
        // home would leave the receiver short of a capability it was promised.
        args.inline_len = 0;
        args.handles_ptr = base + 2048;
        args.handle_count = MAX_MSG_HANDLES as u64 + 1;
        assert_eq!(
            build_message_from_args(&mut h.processes, h.caller, &args, true).err(),
            Some(KError::Protocol),
        );
    }

    #[test]
    fn a_transfer_descriptor_asking_to_share_is_refused_before_the_handle_moves() {
        let mut upage = UserPage([0; 4096]);
        let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP);
        // Mode 1 is SHARE — defined by the ABI, not built here.
        upage.0[2052..2056].copy_from_slice(&1u32.to_le_bytes());
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);

        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        assert_eq!(
            build_message_from_args(&mut h.processes, h.caller, &args, true).err(),
            Some(KError::NotSupported)
        );
        // **And the handle is still the sender's.** `take_narrowed` cannot be
        // undone, so a mode checked after the take would leave the capability
        // belonging to nobody — refused-and-intact is the only safe order.
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(process.handles().lookup(Handle::from_raw(0)).is_ok());
    }

    /// The point of the bookkeeping: handing a device capability to another
    /// process must take the register window with it. Otherwise the sender
    /// keeps everything the capability was protecting, and the receiver's
    /// exclusive use is exclusive only of *other receivers* — which is how a
    /// device manager ends up more privileged than anything it serves.
    #[test]
    fn transferring_a_device_capability_takes_its_mapping_with_it() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        // The transfer vector has to live in *user* memory the process maps, so
        // it goes in the same page the args do; the device is handle 0.
        let handles_ptr =
            write_transfer(&mut upage, 0, Rights::READ | Rights::MAP | Rights::TRANSFER);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        // The window is live before the transfer.
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4000_0000))
                .is_some()
        );

        // Hand the device capability away.
        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        let message = build_message_from_args(&mut h.processes, h.caller, &args, true)
            .expect("transfer the device capability");
        assert_eq!(message.0.handles().count(), 1);

        // The mapping is gone with it, and so is the bookkeeping.
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4000_0000))
                .is_none(),
            "the sender kept register access to a device it gave away"
        );
        assert_eq!(process.device_window_count(), 0);
    }

    /// Where a `DeviceInfoRecord` lands in the user page — clear of the args
    /// and of the transfer vector the other tests use.
    const RECORD_AT: usize = 3072;

    /// Builds a `DeviceInfoArgs` in the user page and returns its pointer.
    fn device_info_args(upage: &mut UserPage, handle: u32) -> (u64, u64) {
        let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
        let at = 256;
        upage.0[at..at + syscall::DEVICE_INFO_ARGS_SIZE].fill(0);
        upage.0[at..at + 4].copy_from_slice(&(syscall::DEVICE_INFO_ARGS_SIZE as u32).to_le_bytes());
        upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
        upage.0[at + 24..at + 32].copy_from_slice(&record_ptr.to_le_bytes());
        (upage.0.as_ptr() as u64 + at as u64, record_ptr)
    }

    // -----------------------------------------------------------------------
    // DeviceChild — a bus controller derives the devices behind it.
    // -----------------------------------------------------------------------

    /// Builds a `DeviceChildArgs` in the user page and returns
    /// `(args_ptr, record_ptr)`.
    fn device_child_args(upage: &mut UserPage, handle: u32, index: u32) -> (u64, u64) {
        let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
        let at = 512;
        upage.0[at..at + syscall::DEVICE_CHILD_ARGS_SIZE].fill(0);
        upage.0[at..at + 4]
            .copy_from_slice(&(syscall::DEVICE_CHILD_ARGS_SIZE as u32).to_le_bytes());
        upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
        upage.0[at + 20..at + 24].copy_from_slice(&index.to_le_bytes());
        upage.0[at + 24..at + 32].copy_from_slice(&record_ptr.to_le_bytes());
        (upage.0.as_ptr() as u64 + at as u64, record_ptr)
    }

    /// Reads back a `DeviceChildRecord` as `(count, child, rights)`.
    fn device_child_record(upage: &UserPage) -> (u32, u32, u64) {
        let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_CHILD_RECORD_SIZE];
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("word"));
        let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("long"));
        (word(16), word(20), long(24))
    }

    // -----------------------------------------------------------------------
    // WakeSource / WakeHold — what may wake this machine, and what stops it
    // sleeping.
    // -----------------------------------------------------------------------

    /// Builds a `WakeSourceArgs` in the user page and returns its pointer.
    fn wake_source_args(upage: &mut UserPage, handle: u32, arm: u32) -> u64 {
        let at = 768;
        upage.0[at..at + syscall::WAKE_SOURCE_ARGS_SIZE].fill(0);
        upage.0[at..at + 4].copy_from_slice(&(syscall::WAKE_SOURCE_ARGS_SIZE as u32).to_le_bytes());
        upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
        upage.0[at + 20..at + 24].copy_from_slice(&arm.to_le_bytes());
        upage.0.as_ptr() as u64 + at as u64
    }

    /// Builds a `WakeHoldArgs` in the user page and returns its pointer.
    fn wake_hold_args(upage: &mut UserPage, handle: u32, op: u32, ticks: u64) -> u64 {
        let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
        let at = 1024;
        upage.0[at..at + syscall::WAKE_HOLD_ARGS_SIZE].fill(0);
        upage.0[at..at + 4].copy_from_slice(&(syscall::WAKE_HOLD_ARGS_SIZE as u32).to_le_bytes());
        upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
        upage.0[at + 20..at + 24].copy_from_slice(&op.to_le_bytes());
        upage.0[at + 24..at + 32].copy_from_slice(&ticks.to_le_bytes());
        upage.0[at + 32..at + 40].copy_from_slice(&record_ptr.to_le_bytes());
        upage.0.as_ptr() as u64 + at as u64
    }

    /// Reads back a `WakeHoldRecord` as `(events, held, ticks)`.
    fn wake_hold_record(upage: &UserPage) -> (u64, u32, u64) {
        let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::WAKE_HOLD_RECORD_SIZE];
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("word"));
        let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("long"));
        (long(16), word(24), long(32))
    }

    /// The arming, end to end: a capability carrying `WAKE` over a device with
    /// an interrupt makes that line able to wake the machine, and the graph is
    /// where the answer lives.
    #[test]
    fn a_capability_with_wake_arms_the_line_it_names() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = wake_source_args(&mut upage, 0, 1);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
        let device = ObjectId::from_raw(21);
        h.exec.device_set_mmio_irq(device, 34).expect("intid");

        assert_eq!(
            run(&mut h, SyscallNumber::WakeSource, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        assert!(h.exec.is_wake_source(device));
        // And the interrupt bridge can find it by the line it arrives on,
        // which is the direction an interrupt actually comes from.
        assert_eq!(h.exec.record_wake(34), Some(device));
        assert_eq!(h.exec.wake_events(), 1);
    }

    /// Holding a device is not authority to let it wake the machine. Without
    /// this, the set of things able to wake a device would be the driver
    /// table — which nobody chose and nobody can audit.
    #[test]
    fn arming_a_wakeup_source_without_the_wake_right_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = wake_source_args(&mut upage, 0, 1);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let device = ObjectId::from_raw(21);
        h.exec.device_set_mmio_irq(device, 34).expect("intid");

        assert_eq!(
            run(&mut h, SyscallNumber::WakeSource, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
        assert!(!h.exec.is_wake_source(device), "and nothing was armed");
        assert_eq!(h.exec.record_wake(34), None, "so the line wakes nothing");
    }

    /// A device with no interrupt cannot be a wakeup source. Recorded, it
    /// would look exactly like one that has not fired yet, and a machine that
    /// suspended trusting it would never come back.
    #[test]
    fn arming_a_device_that_cannot_interrupt_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = wake_source_args(&mut upage, 0, 1);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);

        assert_eq!(
            run(&mut h, SyscallNumber::WakeSource, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::InvalidArgument)))
        );
        assert!(!h.exec.is_wake_source(ObjectId::from_raw(21)));
    }

    /// Disarming is not removal, and a line that was armed stops waking the
    /// machine the moment it is disarmed — which is what makes runtime idle
    /// reversible rather than one-way.
    #[test]
    fn disarming_stops_the_line_waking_the_machine() {
        let mut upage = UserPage([0; 4096]);
        let mut h = {
            let armed = wake_source_args(&mut upage, 0, 1);
            let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
            h.exec
                .device_set_mmio_irq(ObjectId::from_raw(21), 34)
                .expect("intid");
            run(&mut h, SyscallNumber::WakeSource, [armed, 0, 0, 0, 0, 0]);
            h
        };
        assert!(h.exec.is_wake_source(ObjectId::from_raw(21)));

        let disarm = wake_source_args(&mut upage, 0, 0);
        assert_eq!(
            run(&mut h, SyscallNumber::WakeSource, [disarm, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        assert_eq!(h.exec.record_wake(34), None);
        // The counter is untouched by disarming: it counts events, and none
        // happened.
        assert_eq!(h.exec.wake_events(), 0);
    }

    /// The counter is readable, and a hold is taken and released under the
    /// same right — a caller reads the count *in order to* decide whether to
    /// hold, so splitting them would put a syscall in the middle of the race.
    #[test]
    fn a_hold_is_taken_released_and_the_counter_is_readable() {
        let mut upage = UserPage([0; 4096]);
        let mut h = {
            let query = wake_hold_args(&mut upage, 0, 3, 0);
            let mut h = harness(&upage, Rights::READ | Rights::WAKE);
            assert_eq!(
                run(&mut h, SyscallNumber::WakeHold, [query, 0, 0, 0, 0, 0]),
                DispatchOutcome::Return(0)
            );
            h
        };
        let (events, held, _) = wake_hold_record(&upage);
        assert_eq!((events, held), (0, 0), "nothing has happened yet");

        let acquire = wake_hold_args(&mut upage, 0, 1, 0);
        assert_eq!(
            run(&mut h, SyscallNumber::WakeHold, [acquire, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        assert_eq!(wake_hold_record(&upage).1, 1, "a hold is live");
        assert_eq!(h.exec.wake_holds_held(), 1);

        let release = wake_hold_args(&mut upage, 0, 2, 0);
        assert_eq!(
            run(&mut h, SyscallNumber::WakeHold, [release, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        assert_eq!(wake_hold_record(&upage).1, 0);
        // Releasing one that was never taken is an answer, not an error: a
        // caller unwinding a path it is unsure it took must not have to
        // remember, and nothing is harmed by a hold going away twice.
        assert_eq!(
            run(&mut h, SyscallNumber::WakeHold, [release, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
    }

    /// A wake hold is a suspend blocker, so taking one must need the same
    /// authority as saying what may wake the machine — the two halves of one
    /// power authority.
    #[test]
    fn a_hold_without_the_wake_right_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let acquire = wake_hold_args(&mut upage, 0, 1, 0);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        assert_eq!(
            run(&mut h, SyscallNumber::WakeHold, [acquire, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
        assert_eq!(h.exec.wake_holds_held(), 0);
    }

    /// A wake through the syscall boundary: the counter moves, and the grace
    /// hold it takes for itself vetoes a commit — which is what stops an event
    /// arriving just after a resume from being swallowed by an immediate
    /// re-suspend.
    #[test]
    fn a_wake_counts_and_holds_the_machine_awake_briefly() {
        let mut upage = UserPage([0; 4096]);
        let arm = wake_source_args(&mut upage, 0, 1);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
        h.exec
            .device_set_mmio_irq(ObjectId::from_raw(21), 34)
            .expect("intid");
        run(&mut h, SyscallNumber::WakeSource, [arm, 0, 0, 0, 0, 0]);

        h.exec.record_wake(34);
        let query = wake_hold_args(&mut upage, 0, 3, 0);
        assert_eq!(
            run(&mut h, SyscallNumber::WakeHold, [query, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        let (events, held, _) = wake_hold_record(&upage);
        assert_eq!(events, 1, "the wake was counted");
        assert_eq!(held, 1, "and it holds the machine awake for a moment");
        // Attributed to the source rather than to nobody, so a machine that
        // will not sleep can name what is keeping it up.
        assert_eq!(h.exec.wake_hold_holder(), Some(ObjectId::from_raw(21)));
    }

    /// A line nobody armed is not a wake. Most interrupts on a running machine
    /// are ordinary, and counting them would make the counter a number that
    /// changes constantly and therefore says nothing.
    #[test]
    fn an_unarmed_line_is_not_a_wake() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
        h.exec
            .device_set_mmio_irq(ObjectId::from_raw(21), 34)
            .expect("intid");
        assert_eq!(h.exec.record_wake(34), None);
        assert_eq!(h.exec.record_wake(99), None);
        assert_eq!(h.exec.wake_events(), 0);
        assert_eq!(h.exec.wake_holds_held(), 0);
    }

    // -----------------------------------------------------------------------
    // SystemSuspend — the final commit.
    // -----------------------------------------------------------------------

    /// Builds a `SystemSuspendArgs` in the user page and returns its pointer.
    fn suspend_args(upage: &mut UserPage, handle: u32, snapshot: u64) -> u64 {
        let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
        let at = 1280;
        upage.0[at..at + syscall::SYSTEM_SUSPEND_ARGS_SIZE].fill(0);
        upage.0[at..at + 4]
            .copy_from_slice(&(syscall::SYSTEM_SUSPEND_ARGS_SIZE as u32).to_le_bytes());
        upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
        upage.0[at + 24..at + 32].copy_from_slice(&snapshot.to_le_bytes());
        upage.0[at + 32..at + 40].copy_from_slice(&record_ptr.to_le_bytes());
        upage.0.as_ptr() as u64 + at as u64
    }

    /// Reads back a `SystemSuspendRecord` as `(status, events, source)`.
    fn suspend_record(upage: &UserPage) -> (u32, u64, u64) {
        let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::SYSTEM_SUSPEND_RECORD_SIZE];
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("word"));
        let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("long"));
        (word(16), long(24), long(32))
    }

    /// **The lost-wakeup race, closed by counting.** A snapshot taken before a
    /// wake and presented after it does not match, and the entry aborts —
    /// which is the whole mechanism, since whether the event arrived before,
    /// during or after the snapshot cannot be established any other way.
    #[test]
    fn a_stale_snapshot_aborts_the_commit() {
        let mut upage = UserPage([0; 4096]);
        let arm = wake_source_args(&mut upage, 0, 1);
        let mut h = harness(
            &upage,
            Rights::READ | Rights::MAP | Rights::WAKE | Rights::SLEEP,
        );
        h.exec
            .device_set_mmio_irq(ObjectId::from_raw(21), 34)
            .expect("intid");
        run(&mut h, SyscallNumber::WakeSource, [arm, 0, 0, 0, 0, 0]);

        let snapshot = h.exec.wake_events();
        h.exec.record_wake(34);

        let args = suspend_args(&mut upage, 0, snapshot);
        assert_eq!(
            run(&mut h, SyscallNumber::SystemSuspend, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0),
            "the call answers rather than failing — an abort is an outcome",
        );
        let (status, events, source) = suspend_record(&upage);
        assert_eq!(status, 2, "SuspendOutcome::WAKE_ARRIVED");
        assert_eq!(events, snapshot + 1);
        assert_eq!(source, 0);
    }

    /// A wake hold vetoes the commit, and the refusal names the holder — a
    /// machine that will not sleep must be able to say what is keeping it up.
    #[test]
    fn a_wake_hold_vetoes_the_commit_and_names_its_holder() {
        let mut upage = UserPage([0; 4096]);
        let acquire = wake_hold_args(&mut upage, 0, 1, 0);
        let mut h = harness(&upage, Rights::READ | Rights::WAKE | Rights::SLEEP);
        run(&mut h, SyscallNumber::WakeHold, [acquire, 0, 0, 0, 0, 0]);

        let args = suspend_args(&mut upage, 0, h.exec.wake_events());
        assert_eq!(
            run(&mut h, SyscallNumber::SystemSuspend, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        let (status, _, source) = suspend_record(&upage);
        assert_eq!(status, 3, "SuspendOutcome::VETOED");
        assert_ne!(source, 0, "and it says who");
    }

    /// Stopping the machine and saying what may interrupt it are opposite
    /// authorities: `WAKE` is not enough.
    #[test]
    fn committing_without_the_sleep_right_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let args = suspend_args(&mut upage, 0, 0);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
        assert_eq!(
            run(&mut h, SyscallNumber::SystemSuspend, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
    }

    // -----------------------------------------------------------------------
    // Suspend ordering — leaves before parents, enforced against the graph.
    // -----------------------------------------------------------------------

    /// Brings `device` up to `Active` the way a device manager would.
    fn bring_up(h: &mut Harness, device: ObjectId) {
        use crate::lifecycle::{DriverState as S, TransitionReason as R};
        for (from, to) in [
            (S::Discovered, S::Matched),
            (S::Matched, S::Starting),
            (S::Starting, S::Probing),
            (S::Probing, S::Active),
        ] {
            h.exec
                .declare_lifecycle(device, from, to, R::Bound, 0)
                .expect("bring up");
        }
    }

    /// **Leaves before parents, and the kernel is what says so.** A manager
    /// whose walk is wrong would otherwise produce a perfectly legal record of
    /// a bus powered down under a live device, and nothing downstream could
    /// tell.
    #[test]
    fn a_bus_cannot_suspend_under_a_live_device() {
        use crate::lifecycle::{DriverState as S, TransitionError, TransitionReason as R};
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let parent = ObjectId::from_raw(21);
        let children = children_behind(&mut h, parent, 1);
        bring_up(&mut h, parent);
        bring_up(&mut h, children[0]);

        assert_eq!(
            h.exec
                .declare_lifecycle(parent, S::Active, S::Suspending, R::Power, 0),
            Err(TransitionError::OutOfOrder {
                neighbour: children[0],
                state: S::Active,
            }),
        );
        // Refused means unchanged: the bus is still in service, so a manager
        // that ignored the answer would not find its own belief confirmed.
        assert_eq!(h.exec.lifecycle_of_object(parent), Some(S::Active));

        // In the right order both go.
        h.exec
            .declare_lifecycle(children[0], S::Active, S::Suspending, R::Power, 0)
            .expect("child suspending");
        h.exec
            .declare_lifecycle(children[0], S::Suspending, S::Suspended, R::Power, 0)
            .expect("child suspended");
        h.exec
            .declare_lifecycle(parent, S::Active, S::Suspending, R::Power, 0)
            .expect("now the bus may go");
    }

    /// The mirror, which is the half a manager is most likely to get wrong:
    /// resume runs parent-first, because a leaf coming up through a bus that is
    /// still down would be a driver talking to nothing.
    #[test]
    fn a_device_cannot_resume_through_a_suspended_bus() {
        use crate::lifecycle::{DriverState as S, TransitionError, TransitionReason as R};
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let parent = ObjectId::from_raw(21);
        let children = children_behind(&mut h, parent, 1);
        bring_up(&mut h, parent);
        bring_up(&mut h, children[0]);
        for device in [children[0], parent] {
            h.exec
                .declare_lifecycle(device, S::Active, S::Suspending, R::Power, 0)
                .expect("suspending");
            h.exec
                .declare_lifecycle(device, S::Suspending, S::Suspended, R::Power, 0)
                .expect("suspended");
        }

        assert_eq!(
            h.exec
                .declare_lifecycle(children[0], S::Suspended, S::Resuming, R::Power, 0),
            Err(TransitionError::OutOfOrder {
                neighbour: parent,
                state: S::Suspended,
            }),
        );
        // Parent first, and then the leaf may follow.
        h.exec
            .declare_lifecycle(parent, S::Suspended, S::Resuming, R::Power, 0)
            .expect("bus resuming");
        h.exec
            .declare_lifecycle(parent, S::Resuming, S::Active, R::Power, 0)
            .expect("bus back");
        h.exec
            .declare_lifecycle(children[0], S::Suspended, S::Resuming, R::Power, 0)
            .expect("now the leaf may follow");
    }

    /// Registers `count` children behind the harness' device and returns their
    /// ids.
    fn children_behind(h: &mut Harness, parent: ObjectId, count: usize) -> [ObjectId; 2] {
        let ids = [0x81, 0x82].map(ObjectId::from_raw);
        for id in ids.iter().take(count) {
            h.exec
                .device_register_mmio(
                    *id,
                    0x0a00_9000 + 0x1000 * (id.raw() as u64 & 0xf),
                    FRAME_SIZE,
                    Rights::READ | Rights::MAP,
                )
                .expect("register");
            h.exec.device_set_parent(*id, parent).expect("edge");
        }
        ids
    }

    /// The grant a bus controller could get from nowhere else: the manager does
    /// not know what is behind a bus only the controller's capability names.
    #[test]
    fn a_controller_derives_a_capability_to_the_device_behind_its_bus() {
        let mut upage = UserPage([0; 4096]);
        let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
        let parent = ObjectId::from_raw(21);
        let children = children_behind(&mut h, parent, 2);

        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DeviceChild,
                [args_ptr, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(0)
        );
        let (count, child, rights) = device_child_record(&upage);
        assert_eq!(count, 2, "both devices on the bus");
        assert_ne!(child, HANDLE_NOT_INSTALLED, "a capability was installed");

        // The handle names the first child, and nothing the caller supplied
        // could have chosen it — the id came from the graph's own edges.
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let (object, held) = process
            .handles()
            .lookup(crate::handle::Handle::from_raw(child))
            .expect("the derived handle resolves");
        assert_eq!(object, children[0]);

        // **The graph's record for the child, not a narrowing of the bus's.**
        // The child was registered READ|MAP and that is what came back — the
        // parent's TRANSFER is not on it, and MAP would not be there at all if
        // the rights had been inherited from a bus that has no business
        // holding MAP over its own window.
        assert!(held.contains(Rights::MAP), "usable as a device");
        assert!(
            !held.contains(Rights::TRANSFER),
            "the bus's rights are not the child's",
        );
        assert_eq!(rights, held.bits(), "the record echoes what was installed");
    }

    /// Holding a bus is not by itself authority to hand out what is on it — a
    /// controller may be granted a bus to drive without being made its broker.
    #[test]
    fn deriving_without_the_derive_right_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let parent = ObjectId::from_raw(21);
        children_behind(&mut h, parent, 1);

        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DeviceChild,
                [args_ptr, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
    }

    /// A bus with nothing on it is an ordinary bus, and an index past the end
    /// is an ordinary answer. Reported as a distinguished handle rather than
    /// zero, because zero is a legitimate handle number.
    #[test]
    fn asking_past_the_end_of_a_bus_answers_rather_than_fails() {
        let mut upage = UserPage([0; 4096]);
        let (args_ptr, _) = device_child_args(&mut upage, 0, 3);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
        children_behind(&mut h, ObjectId::from_raw(21), 1);

        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DeviceChild,
                [args_ptr, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(0)
        );
        let (count, child, _) = device_child_record(&upage);
        assert_eq!(count, 1);
        assert_eq!(child, HANDLE_NOT_INSTALLED);
    }

    /// A leaf answers zero children — which is how a controller discovers it is
    /// not one, without a second syscall to ask.
    #[test]
    fn a_device_with_nothing_behind_it_answers_a_count_of_zero() {
        let mut upage = UserPage([0; 4096]);
        let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);

        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DeviceChild,
                [args_ptr, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(0)
        );
        let (count, child, _) = device_child_record(&upage);
        assert_eq!(count, 0);
        assert_eq!(child, HANDLE_NOT_INSTALLED);
    }

    /// **A controller can walk a subtree that has a switch in it.** Stopping at
    /// one level would make the deepest thing a bus controller could reach its
    /// immediate children — on the topology this milestone added, the switch's
    /// upstream port and nothing beyond it. Containment is the edge, not
    /// attenuation.
    #[test]
    fn a_derived_capability_keeps_walking_down_the_subtree() {
        let mut upage = UserPage([0; 4096]);
        let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
        let parent = ObjectId::from_raw(21);
        let children = children_behind(&mut h, parent, 1);
        // A grandchild, so there is something for a second derive to find.
        let grandchild = ObjectId::from_raw(0x8a);
        h.exec
            .device_register_mmio(grandchild, 0x0a00_b000, FRAME_SIZE, Rights::READ)
            .expect("register");
        h.exec
            .device_set_parent(grandchild, children[0])
            .expect("edge");

        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DeviceChild,
                [args_ptr, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(0)
        );
        let (_, child, _) = device_child_record(&upage);

        // Now ask the *derived* handle for its own child — the grandchild.
        let (second_args, _) = device_child_args(&mut upage, child, 0);
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DeviceChild,
                [second_args, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(0),
        );
        let (count, deeper, _) = device_child_record(&upage);
        assert_eq!(count, 1);
        assert_ne!(deeper, HANDLE_NOT_INSTALLED);
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let (object, _) = process
            .handles()
            .lookup(crate::handle::Handle::from_raw(deeper))
            .expect("the grandchild resolves");
        assert_eq!(object, grandchild, "two levels down from where it started");
    }

    /// And what *does* stop a driver brokering: it never held `DERIVE`. A
    /// controller hands a device on over a channel, where rights narrow on
    /// transfer (D113), and what arrives cannot walk anywhere.
    #[test]
    fn a_device_handed_on_without_derive_brokers_nothing() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let parent = ObjectId::from_raw(21);
        children_behind(&mut h, parent, 1);
        // The shape a driver is in: it holds the bus, but was handed it without
        // the authority to hand anything on.
        let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DeviceChild,
                [args_ptr, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
    }

    /// The right bit on some other object must not be a lever on whatever the
    /// graph happens to root at that id.
    #[test]
    fn deriving_from_something_that_is_not_a_device_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
        let not_a_device = ObjectId::from_raw(0x400);
        let handle = {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .install(not_a_device, Rights::READ | Rights::DERIVE)
                .expect("install")
                .raw()
        };
        let (args_ptr, _) = device_child_args(&mut upage, handle, 0);
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::DeviceChild,
                [args_ptr, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(encode_result(Err(KError::WrongType)))
        );
    }

    /// A virtio-mmio transport has no identity in the graph — it says what it
    /// is in its own registers. `UNKNOWN` is the answer, not an error: a
    /// manager's response is to map it and read them.
    #[test]
    fn a_device_with_no_recorded_identity_answers_unknown() {
        let mut upage = UserPage([0; 4096]);
        let (args_ptr, _) = device_info_args(&mut upage, 0);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);

        assert_eq!(
            run(&mut h, SyscallNumber::DeviceInfo, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        // The record landed in the user page, which is ordinary memory this
        // test owns — reading it back needs no raw pointer.
        let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_INFO_RECORD_SIZE];
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        assert_eq!(word(0), syscall::DEVICE_INFO_RECORD_SIZE as u32);
        // kind == UNKNOWN (0)
        assert_eq!(word(16), 0);
        // And no layout, which is the honest answer for a device whose
        // structures the kernel never resolved — not zeroes that a driver
        // might read as offsets, but a flag saying there is nothing here.
        assert_eq!(word(44), 0, "layout_valid");
    }

    /// **Where the device's structures are, handed back to a holder.**
    ///
    /// The last thing between a granted register window and a driver able to
    /// use it. A virtio-pci function says where its controls are in config
    /// space, and config space is not per-device — no capability to it can be
    /// handed out — so a driver holding the right window had no way to find
    /// anything in it. The kernel reads it while enumerating, and this is how
    /// a capability holder asks.
    ///
    /// The offsets are relative to the granted window and never absolute: the
    /// first is usable by a process that mapped a capability, and the second
    /// is a fact about the machine no driver should be given.
    #[test]
    fn a_holder_is_told_where_its_devices_structures_are() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let device = ObjectId::from_raw(23);
        h.exec
            .device_register_identified(
                device,
                0x4000_0000,
                FRAME_SIZE,
                Rights::READ | Rights::MAP,
                crate::devmgr::DeviceIdentity {
                    revision: 1,
                    bus: crate::devmgr::DeviceBus::Pci,
                    class_code: 0x01_00_00,
                    vendor: 0x1af4,
                    device: 0x1042,
                    bdf: 0x08,
                },
            )
            .expect("register");
        h.exec
            .device_set_layout(
                device,
                crate::devmgr::DeviceLayout {
                    common: 0,
                    notify: 0x3000,
                    notify_multiplier: 4,
                    isr: 0x1000,
                    device_config: 0x2000,
                },
            )
            .expect("layout");
        let handle = {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .install(device, Rights::READ)
                .expect("install")
        };
        let (args_ptr, _) = device_info_args(&mut upage, handle.raw());
        assert_eq!(
            run(&mut h, SyscallNumber::DeviceInfo, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );

        let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_INFO_RECORD_SIZE];
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        assert_eq!(word(36), 1, "the revision — a binding input of its own");
        assert_eq!(word(40), 1, "bus = PCI");
        assert_eq!(word(44), 1, "layout_valid");
        // Offset zero is a real offset. `layout_valid` is what distinguishes
        // a structure at the start of the window from no structure at all,
        // and a driver that inferred otherwise would refuse to drive exactly
        // the devices that work.
        assert_eq!(word(48), 0, "common");
        assert_eq!(word(52), 0x3000, "notify");
        assert_eq!(word(56), 4, "notify multiplier");
        assert_eq!(word(60), 0x1000, "isr");
        assert_eq!(word(64), 0x2000, "device config");
    }

    /// What the kernel learned enumerating a bus, handed back to a holder.
    #[test]
    fn an_enumerated_device_reports_the_identity_the_kernel_recorded() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        // Register a second device carrying an identity, as a PCI walk does.
        h.exec
            .device_register_identified(
                ObjectId::from_raw(22),
                0x4000_0000,
                FRAME_SIZE,
                Rights::READ | Rights::MAP,
                crate::devmgr::DeviceIdentity {
                    revision: 3,
                    bus: crate::devmgr::DeviceBus::Pci,
                    class_code: 0x01_08_00,
                    vendor: 0x1af4,
                    device: 0x1042,
                    bdf: 0x0100,
                },
            )
            .expect("register");
        let handle = {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .install(ObjectId::from_raw(22), Rights::READ)
                .expect("install")
        };
        let (args_ptr, _) = device_info_args(&mut upage, handle.raw());

        assert_eq!(
            run(&mut h, SyscallNumber::DeviceInfo, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_INFO_RECORD_SIZE];
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        assert_eq!(word(16), 1, "kind == PCI");
        assert_eq!(word(20), 0x01_08_00, "class code");
        assert_eq!(word(24), 0x1af4, "vendor");
        assert_eq!(word(28), 0x1042, "device");
    }

    /// Asking about something that is not a device is a type error, not a
    /// record full of zeros that reads like a real answer.
    #[test]
    fn asking_about_a_non_device_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        let handle = {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            process
                .handles_mut()
                .install(ObjectId::from_raw(0x99), Rights::READ)
                .expect("install")
        };
        let (args_ptr, _) = device_info_args(&mut upage, handle.raw());
        assert_eq!(
            run(&mut h, SyscallNumber::DeviceInfo, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::WrongType)))
        );
    }

    /// A device with no aperture gets a physical address, and the system is
    /// told so. The grant is legitimate — a machine may have no IOMMU — but an
    /// unscoped grant must not read like a scoped one.
    #[test]
    fn an_unscoped_dma_grant_says_that_it_is_unscoped() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4001_0000);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);

        let _guard = event_ring_guard();
        run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);

        let events = drained_device_events();
        assert!(
            events
                .iter()
                .any(|e| e.kind == crate::event::EventKind::DeviceDmaGranted),
            "the grant itself is recorded"
        );
        let unscoped = events
            .iter()
            .find(|e| e.kind == crate::event::EventKind::DeviceDmaUnscoped)
            .expect("an unscoped grant must say so");
        assert_eq!(unscoped.severity, crate::event::Severity::Warning);
    }

    /// Puts the harness device behind an IOMMU whose leases run `[base, len)`.
    ///
    /// No lease is created here, and that is the point: a device is *scoped*
    /// because of how the machine is wired, and *leased* because a driver asked
    /// it for DMA. Pre-installing one would hide every question about when a
    /// lease begins.
    fn scoped(h: &mut Harness, base: u64, len: u64) {
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(HARNESS_DEVICE as u32),
            base,
            len,
        ));
    }

    /// The VA the DMA tests ask for their buffer at.
    const DMA_TEST_VA: u64 = 0x4001_0000;

    /// The same grant for a device that *does* have an aperture carries no
    /// such record — otherwise the report would be noise rather than a
    /// distinction.
    #[test]
    fn a_scoped_dma_grant_carries_no_unscoped_report() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, 0x1000);

        let _guard = event_ring_guard();
        run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);

        let events = drained_device_events();
        assert!(
            !events
                .iter()
                .any(|e| e.kind == crate::event::EventKind::DeviceDmaUnscoped)
        );
        let scoped = events
            .iter()
            .find(|e| e.kind == crate::event::EventKind::DeviceDmaScoped)
            .expect("a scoped grant says so positively, not by staying silent");
        assert_eq!(scoped.arg1, DMA_TEST_VA, "the user VA");
        assert_eq!(scoped.arg2, 0x8000_0000, "the IOVA the device sees");
        assert_ne!(
            scoped.arg2, scoped.arg3,
            "the device's address is not the physical one — that is what translating means",
        );
    }

    /// The claim this whole seam exists for: a driver on a device with an
    /// aperture is handed an **IOVA**, and it is an IOVA the IOMMU was
    /// actually told about. Checking the return value alone would pass for an
    /// implementation that allocated an address and installed nothing.
    #[test]
    fn a_scoped_device_returns_an_iova_the_iommu_was_given() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, 0x2000);

        let outcome = run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
        let DispatchOutcome::Return(iova) = outcome else {
            panic!("dma_alloc not covered");
        };
        assert_eq!(iova, 0x8000_0000, "the first address in the aperture");

        let phys = h
            .processes
            .process_of_thread(h.caller)
            .expect("process")
            .space()
            .arch()
            .translate(VirtAddr::new(DMA_TEST_VA))
            .expect("the buffer is mapped")
            .0
            .base()
            .as_u64();
        assert_eq!(
            h.iommu.as_ref().expect("iommu").installed,
            std::vec![(
                ObjectId::from_raw(HARNESS_DEVICE as u32),
                0x8000_0000,
                phys,
                FRAME_SIZE
            )],
            "the IOVA handed back names the buffer's page, for that device only",
        );
    }

    /// A device with a **live lease**, reached on a path that has lost its
    /// IOMMU, is a refusal. Its translations exist right now, so answering with
    /// a physical address would answer a request for a scoped buffer with an
    /// unscoped one — and the caller has no way to tell.
    #[test]
    fn a_leased_device_with_no_iommu_in_hand_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, 0x2000);

        // One good grant, so a lease is live.
        let first = device_args(&mut upage, 0, DMA_TEST_VA);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [first, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Ok(0x8000_0000)))
        );

        h.iommu = None;
        let second = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [second, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping)))
        );
        assert!(
            h.processes
                .process_of_thread(h.caller)
                .expect("process")
                .space()
                .arch()
                .translate(VirtAddr::new(DMA_TEST_VA + FRAME_SIZE))
                .is_none(),
            "a refusal leaves no buffer behind",
        );
    }

    /// A device behind nothing is not scoped, and the grant says so rather
    /// than refusing — the state of every device on four of the five ports.
    #[test]
    fn a_device_behind_no_iommu_is_unscoped_not_refused() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        // An IOMMU exists, but this device is not behind it.
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(0x99),
            0x8000_0000,
            0x1000,
        ));

        let _guard = event_ring_guard();
        let outcome = run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
        let DispatchOutcome::Return(addr) = outcome else {
            panic!("dma_alloc not covered");
        };
        assert!(addr > 0, "a physical address, not a refusal");
        assert!(
            drained_device_events()
                .iter()
                .any(|e| e.kind == crate::event::EventKind::DeviceDmaUnscoped)
        );
        assert!(h.iommu.as_ref().expect("iommu").began.is_empty());
    }

    /// An IOMMU that cannot describe the range refuses too, and the buffer
    /// comes back down with it — a driver that retries must not lose a frame
    /// per attempt.
    #[test]
    fn an_iommu_that_refuses_leaves_no_buffer_behind() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, 0x1000);
        h.iommu = Some(MockMapper {
            refuses: true,
            ..MockMapper::over(
                ObjectId::from_raw(HARNESS_DEVICE as u32),
                0x8000_0000,
                0x1000,
            )
        });

        let mapped_before = h
            .processes
            .process_of_thread(h.caller)
            .expect("process")
            .space()
            .mapping_count();
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping)))
        );
        assert_eq!(
            h.processes
                .process_of_thread(h.caller)
                .expect("process")
                .space()
                .mapping_count(),
            mapped_before,
            "the page mapped before the refusal was reclaimed",
        );
    }

    /// A refusal records **no grant**. `DEVICE_DMA_GRANTED` means a driver is
    /// holding a buffer, not that one was attempted — an audit that cannot
    /// tell those apart counts grants that never happened, and would see a
    /// grant here with neither a scoped nor an unscoped record after it.
    #[test]
    fn a_refused_grant_is_not_recorded_as_a_grant() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.iommu = Some(MockMapper {
            refuses: true,
            ..MockMapper::over(
                ObjectId::from_raw(HARNESS_DEVICE as u32),
                0x8000_0000,
                0x1000,
            )
        });

        let _guard = event_ring_guard();
        run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);

        let events = drained_device_events();
        assert!(
            !events
                .iter()
                .any(|e| e.kind == crate::event::EventKind::DeviceDmaGranted),
            "nothing was granted",
        );
    }

    /// A lease begins on the **first** grant and is reused by the next — one
    /// lease per driver, not one per buffer. A mapper told to begin twice would
    /// be re-configuring the device's translation under a driver mid-flight.
    #[test]
    fn the_first_grant_begins_a_lease_and_the_second_reuses_it() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, 0x2000);
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
        assert_eq!(h.exec.lease_holder_of_object(device), None, "none yet");

        let first = device_args(&mut upage, 0, DMA_TEST_VA);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [first, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Ok(0x8000_0000)))
        );
        let holder = h
            .processes
            .process_of_thread(h.caller)
            .expect("process")
            .id();
        assert_eq!(h.exec.lease_holder_of_object(device), Some(holder));

        let second = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [second, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Ok(0x8000_1000)))
        );
        assert_eq!(
            h.iommu.as_ref().expect("iommu").began,
            std::vec![device],
            "one lease, two buffers",
        );
    }

    /// A second process holding a handle to the same device cannot allocate out
    /// of the first's lease. Without this its buffers would vanish when the
    /// *other* process gave the device up — a lease that guarantees nothing.
    #[test]
    fn a_process_that_does_not_hold_the_lease_is_refused() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, 0x2000);
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);

        let first = device_args(&mut upage, 0, DMA_TEST_VA);
        run(&mut h, SyscallNumber::DmaAlloc, [first, 0, 0, 0, 0, 0]);

        // Someone else already holds it.
        h.exec
            .device_set_aperture(
                device,
                ObjectId::from_raw(0xfeed),
                crate::devmgr::DeviceAperture::new(0x8000_0000, 0x2000),
                None,
            )
            .expect("re-hold");

        let second = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [second, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
        );
    }

    /// A dying holder loses its lease, and the mapper is told — the route a
    /// register window does not have, because a window dies with the address
    /// space and a translation in an IOMMU does not.
    #[test]
    fn a_dying_holder_loses_its_lease() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, 0x2000);
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
        run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);

        let _guard = event_ring_guard();
        let Harness {
            exec,
            processes,
            iommu,
            caller,
            ..
        } = &mut h;
        let process = processes.process_of_thread(*caller).expect("process");
        let ended =
            exec.end_device_leases(process, iommu.as_mut().map(|m| m as &mut dyn DmaMapper));

        assert_eq!(ended, 1);
        assert_eq!(h.iommu.as_ref().expect("iommu").ended, std::vec![device]);
        assert!(
            h.iommu.as_ref().expect("iommu").installed.is_empty(),
            "its translations went with it",
        );
        assert_eq!(h.exec.lease_holder_of_object(device), None);
        let record = drained_device_events()
            .into_iter()
            .find(|e| e.kind == crate::event::EventKind::DeviceDmaLeaseEnded)
            .expect("the end of a lease is recorded");
        assert_eq!(
            record.arg2,
            crate::devmgr::LeaseEndReason::HolderGone as u64
        );
    }

    /// **The D120 unlock.** A lease that ends returns its addresses, so the
    /// next driver starts from the same base rather than from wherever its
    /// predecessor stopped. Without the intervening end, a rebound driver
    /// would exhaust the window a few restarts in.
    #[test]
    fn the_next_lease_reuses_the_addresses_the_last_one_spent() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, 2 * FRAME_SIZE);
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);

        // Spend the whole lease.
        let a = device_args(&mut upage, 0, DMA_TEST_VA);
        run(&mut h, SyscallNumber::DmaAlloc, [a, 0, 0, 0, 0, 0]);
        let b = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
        run(&mut h, SyscallNumber::DmaAlloc, [b, 0, 0, 0, 0, 0]);
        let c = device_args(&mut upage, 0, DMA_TEST_VA + 2 * FRAME_SIZE);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [c, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::OutOfMemory))),
            "spent",
        );

        {
            let Harness {
                exec,
                processes,
                iommu,
                caller,
                ..
            } = &mut h;
            let process = processes.process_of_thread(*caller).expect("process");
            exec.end_device_leases(process, iommu.as_mut().map(|m| m as &mut dyn DmaMapper));
        }

        let d = device_args(&mut upage, 0, DMA_TEST_VA + 3 * FRAME_SIZE);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [d, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Ok(0x8000_0000))),
            "the new lease reissues the old lease's first address",
        );
        assert_eq!(
            h.iommu.as_ref().expect("iommu").began,
            std::vec![device, device],
            "and it is a second lease, not a continuation of the first",
        );
    }

    /// A spent aperture is out of memory, not a licence to hand back a
    /// physical address. D120 made "no aperture" and "aperture exhausted"
    /// distinguishable in the graph; this is the behaviour that distinction
    /// exists for.
    #[test]
    fn a_spent_aperture_refuses_rather_than_falling_back() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        scoped(&mut h, 0x8000_0000, FRAME_SIZE);

        let first = device_args(&mut upage, 0, DMA_TEST_VA);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [first, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Ok(0x8000_0000)))
        );
        let second = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaAlloc, [second, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(encode_result(Err(KError::OutOfMemory)))
        );
        assert_eq!(
            h.iommu.as_ref().expect("iommu").installed.len(),
            1,
            "nothing was installed for the refused call",
        );
    }

    /// A granted register window is a record, not just a return value
    /// (docs/drivers/01: lifecycle transitions are observable through
    /// structured events). It carries both names for the window — the user VA
    /// the driver got and the physical base the capability authorized — so the
    /// grant can be audited without trusting the driver's account of it.
    #[test]
    fn a_granted_device_window_is_recorded() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);

        let _guard = event_ring_guard();
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        let events = drained_device_events();
        let grant = events
            .iter()
            .find(|e| e.kind == crate::event::EventKind::DeviceWindowMapped)
            .expect("the grant was not recorded");
        assert_eq!(grant.arg1, 0x4000_0000, "the user VA the driver was given");
        // The harness registers the window at 0x0a00_3e00, which is not page
        // aligned — the record names the *page* that was mapped.
        assert_eq!(grant.arg2, 0x0a00_3000, "the physical page base");
        assert_eq!(grant.arg3, FRAME_SIZE, "the graph's window length");
        assert_eq!(grant.severity, crate::event::Severity::Info);
    }

    /// A refusal is the capability system working, and it used to leave no
    /// kernel record at all — the caller got an errno and the machine forgot.
    /// The record names the error as a stable domain value, never a string.
    #[test]
    fn a_refused_device_mapping_is_recorded_with_its_error() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        // READ without MAP: the handle names the device but carries no
        // authority to map it.
        let mut h = harness(&upage, Rights::READ);

        let _guard = event_ring_guard();
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        let events = drained_device_events();
        let refusal = events
            .iter()
            .find(|e| e.kind == crate::event::EventKind::DeviceMapRefused)
            .expect("the refusal was not recorded");
        assert_eq!(refusal.arg1, KError::AccessDenied as u64);
        assert_eq!(refusal.arg2, 0x4000_0000, "the VA that was asked for");
        assert_eq!(refusal.severity, crate::event::Severity::Warning);
        // And nothing claimed a grant.
        assert!(
            !events
                .iter()
                .any(|e| e.kind == crate::event::EventKind::DeviceWindowMapped)
        );
    }

    /// The revocation record says which of the two routes the capability left
    /// by — the distinction `revoke_device_windows_unless_held` documents but
    /// could not previously report. A transfer and a close are different
    /// events with the same effect, and an auditor needs to tell them apart.
    #[test]
    fn a_revoked_window_records_the_route_the_capability_left_by() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        let handles_ptr =
            write_transfer(&mut upage, 0, Rights::READ | Rights::MAP | Rights::TRANSFER);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        let _guard = event_ring_guard();
        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");

        let events = drained_device_events();
        let revoke = events
            .iter()
            .find(|e| e.kind == crate::event::EventKind::DeviceWindowRevoked)
            .expect("the revocation was not recorded");
        assert_eq!(revoke.arg1, 0x4000_0000, "the VA that came down");
        assert_eq!(
            revoke.arg2,
            crate::process::WindowRevokeReason::Transferred as u64
        );
        assert_eq!(revoke.arg3, 0, "the page came down cleanly");
    }

    /// Handing the capability on ends the lease with it. The register window
    /// and the DMA lease follow the same departure, and the sender must not
    /// keep either — otherwise a driver that gave its device away could still
    /// reach memory through it.
    #[test]
    fn transferring_the_capability_ends_the_lease() {
        let mut upage = UserPage([0; 4096]);
        let dma_args = device_args(&mut upage, 0, DMA_TEST_VA);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        scoped(&mut h, 0x8000_0000, 0x2000);
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
        run(&mut h, SyscallNumber::DmaAlloc, [dma_args, 0, 0, 0, 0, 0]);
        assert!(h.exec.lease_holder_of_object(device).is_some());

        let handles_ptr =
            write_transfer(&mut upage, 0, Rights::READ | Rights::MAP | Rights::TRANSFER);
        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        let (_msg, departed) =
            build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
        {
            let mut env = DispatchEnv {
                exec: &mut h.exec,
                processes: &mut h.processes,
                caller: h.caller,
                alloc: &mut h.frames,
                iommu: h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper),
                irqs: h
                    .irqs
                    .as_mut()
                    .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
            };
            end_bindings_of_departed(&mut env, &departed);
        }

        assert_eq!(h.exec.lease_holder_of_object(device), None);
        assert_eq!(h.iommu.as_ref().expect("iommu").ended, std::vec![device]);
        assert!(h.iommu.as_ref().expect("iommu").installed.is_empty());
    }

    /// Handing the capability on takes the **interrupt route** with it too.
    ///
    /// This is the third thing that follows a capability out, and the one with
    /// the least in common with the other two. A register window dies with the
    /// address space; a DMA lease lives in the IOMMU; a route lives in the
    /// interrupt controller *and* in the kernel's own port table, and both
    /// outlive the sender completely. Left standing, it keeps waking a port
    /// whose holder no longer has any authority over the device.
    #[test]
    fn transferring_the_capability_ends_the_interrupt_route() {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        h.irqs = Some(MockRouter::default());
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
        h.exec.device_set_mmio_irq(device, 79).expect("irq");
        let port = h.exec.port_create().expect("port");
        let holder = h
            .processes
            .process_of_thread(h.caller)
            .expect("process")
            .id();
        h.exec
            .device_route_irq(device, port, holder)
            .expect("route");
        assert_eq!(h.exec.port_signal(79, crate::exec::IRQ_PORT_SIGNAL, 1), 1);

        let handles_ptr =
            write_transfer(&mut upage, 0, Rights::READ | Rights::MAP | Rights::TRANSFER);
        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        let (_msg, departed) =
            build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
        {
            let mut env = DispatchEnv {
                exec: &mut h.exec,
                processes: &mut h.processes,
                caller: h.caller,
                alloc: &mut h.frames,
                iommu: None,
                irqs: h
                    .irqs
                    .as_mut()
                    .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
            };
            end_bindings_of_departed(&mut env, &departed);
        }

        assert_eq!(h.exec.irq_route_of_object(device), None);
        assert_eq!(
            h.irqs.as_ref().expect("router").masked,
            std::vec![79],
            "the controller stopped delivering, not just the graph",
        );
        // And the port no longer receives the line at all.
        assert_eq!(h.exec.port_signal(79, crate::exec::IRQ_PORT_SIGNAL, 1), 0);

        let events = drained_device_events();
        let revoked = events
            .iter()
            .find(|e| e.kind == crate::event::EventKind::DeviceIrqRevoked)
            .expect("the revocation was not recorded");
        assert_eq!(revoked.arg1, 79);
        assert_eq!(
            revoked.arg2,
            crate::devmgr::RouteEndReason::Transferred as u64
        );
    }

    /// A dying driver's route goes with it. Nothing else can take it down: the
    /// process's handle table is reclaimed in bulk, so by teardown there is
    /// nobody left to ask what it was receiving — which is why the graph
    /// records the holder rather than deriving it.
    #[test]
    fn a_dead_holders_interrupt_route_is_swept_up() {
        let upage = UserPage([0; 4096]);
        let mut h = harness(&upage, Rights::READ | Rights::MAP);
        h.irqs = Some(MockRouter::default());
        let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
        h.exec.device_set_mmio_irq(device, 79).expect("irq");
        let port = h.exec.port_create().expect("port");
        let holder = h
            .processes
            .process_of_thread(h.caller)
            .expect("process")
            .id();
        h.exec
            .device_route_irq(device, port, holder)
            .expect("route");

        let Harness {
            mut exec,
            mut processes,
            mut irqs,
            caller,
            ..
        } = h;
        {
            let process = processes.process_of_thread(caller).expect("process");
            assert_eq!(
                exec.end_device_irq_routes(
                    process,
                    irqs.as_mut()
                        .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
                ),
                1,
            );
        }
        assert_eq!(exec.irq_route_of_object(device), None);
        assert_eq!(irqs.as_ref().expect("router").masked, std::vec![79]);
        let events = drained_device_events();
        let revoked = events
            .iter()
            .find(|e| e.kind == crate::event::EventKind::DeviceIrqRevoked)
            .expect("the revocation was not recorded");
        assert_eq!(
            revoked.arg2,
            crate::devmgr::RouteEndReason::HolderGone as u64
        );
    }

    /// A process that duplicated its device capability and gave one copy away
    /// still holds the authority, so it keeps the window — and emits nothing,
    /// because nothing was revoked. A record here would be a false report of a
    /// revocation that did not happen.
    #[test]
    fn keeping_the_authority_records_no_revocation() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        let handles_ptr =
            write_transfer(&mut upage, 1, Rights::READ | Rights::MAP | Rights::TRANSFER);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);
        // A second handle to the same device — handle 1, the one transferred.
        {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            let (object, rights) = process
                .handles()
                .lookup(Handle::from_raw(0))
                .expect("device handle");
            let duplicate = process.handles_mut().install(object, rights).expect("dup");
            assert_eq!(duplicate.raw(), 1);
        }

        let _guard = event_ring_guard();
        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");

        let events = drained_device_events();
        assert!(
            !events
                .iter()
                .any(|e| e.kind == crate::event::EventKind::DeviceWindowRevoked),
            "reported a revocation while the process still held the authority"
        );
    }

    /// A process that duplicated its device capability and gave one copy away
    /// still holds the authority, so it keeps the window. Revocation asks
    /// whether the *capability* left the table, not whether a handle did.
    #[test]
    fn transferring_one_of_two_handles_to_a_device_keeps_the_window() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        // The duplicate lands at handle 1; transfer that one.
        let handles_ptr =
            write_transfer(&mut upage, 1, Rights::READ | Rights::MAP | Rights::TRANSFER);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        let device = {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            let (object, rights) = process
                .handles()
                .lookup(crate::handle::Handle::from_raw(0))
                .expect("device handle");
            let duplicate = process.handles_mut().install(object, rights).expect("dup");
            assert_eq!(duplicate.raw(), 1);
            object
        };

        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");

        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(
            process.handles().holds(device),
            "the original handle remains"
        );
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4000_0000))
                .is_some(),
            "a process that still holds the capability lost its window"
        );
        assert_eq!(process.device_window_count(), 1);
    }

    /// A window that is *not* transferred stays exactly where it was — the
    /// revocation must key on the capability that moved, not fire on any
    /// transfer at all.
    #[test]
    fn transferring_something_else_leaves_a_device_window_alone() {
        let mut upage = UserPage([0; 4096]);
        let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
        // The device is handle 0, so the unrelated object below lands at 1.
        let handles_ptr = write_transfer(&mut upage, 1, Rights::READ | Rights::TRANSFER);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

        // Install an unrelated object and transfer *that*.
        let other = ObjectId::from_raw(99);
        {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            let handle = process
                .handles_mut()
                .install(other, Rights::READ | Rights::TRANSFER)
                .expect("install");
            assert_eq!(handle.raw(), 1);
        }
        let args = syscall::ChannelMsgRequest {
            interface_id: 0,
            method_id: 0,
            msg_flags: 0,
            inline_ptr: 0,
            inline_len: 0,
            handles_ptr,
            handle_count: 1,
            installed_ptr: 0,
            installed_cap: 0,
        };
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");

        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4000_0000))
                .is_some()
        );
        assert_eq!(process.device_window_count(), 1);
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
        let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
        args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
        args[4..8].copy_from_slice(&4u32.to_le_bytes());
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
        let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
        args.fill(0);
        args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
        args[4..8].copy_from_slice(&4u32.to_le_bytes());
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
