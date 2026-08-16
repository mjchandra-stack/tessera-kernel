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
        SyscallNumber::ChannelRecvAny => {
            DispatchOutcome::Return(channel_recv_any(env, req.args[0]))
        }
        SyscallNumber::ChannelSend => {
            DispatchOutcome::Return(channel_send(env, req.args[0], req.args[1]))
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
        SyscallNumber::PortSignal => {
            DispatchOutcome::Return(port_signal(env, req.args[0], req.args[1]))
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
        SyscallNumber::FirmwareLoad => DispatchOutcome::Return(firmware_load(env, req.args[0])),
        SyscallNumber::MemoryClassify => DispatchOutcome::Return(memory_classify(env, req.args[0])),
        SyscallNumber::DeviceDeclare => DispatchOutcome::Return(device_declare(env, req.args[0])),
        SyscallNumber::MapConfig => DispatchOutcome::Return(map_config(env, req.args[0])),
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

/// Resolves what an `IrqComplete` re-arms: reads the caller's args struct,
/// checks the handle it names carries `Rights::MAP` (the driver authority),
/// and writes **every** interrupt line the graph has for that device into
/// `out`, returning how many.
///
/// The syscall stays port-local — re-arming is an interrupt-controller
/// register write, and the controller is the one thing a port cannot share
/// (D79's class of exception) — but nothing above that write is
/// architectural. Which lines a device has is the resource graph's answer, and
/// the graph is [`crate::devmgr`]'s, so a port answering it alone can only
/// answer it differently.
///
/// Every line rather than the first, because a multi-queue controller raises
/// one interrupt per queue and a driver that took one completion cannot name
/// the line it arrived on: the port it woke on identifies the queue, not the
/// INTID. Re-enabling a line already enabled costs nothing; leaving one masked
/// costs that queue's next completion, and nothing reports it.
///
/// The INTIDs come from the capability, never from the caller.
pub fn resolve_irq_lines<A: AddressSpaceOps, C: ContextOps>(
    exec: &Executive<C>,
    processes: &mut ProcessTable<A>,
    caller: usize,
    args_ptr: u64,
    out: &mut [u32; crate::devmgr::MAX_IRQ_LINES],
) -> Result<usize, KError> {
    let object = {
        let process = processes
            .process_of_thread(caller)
            .ok_or(KError::AccessDenied)?;
        let mut abuf = [0u8; syscall::IRQ_COMPLETE_ARGS_SIZE];
        read_user(process, args_ptr, &mut abuf)?;
        let handle = syscall::decode_irq_complete_args(&abuf)?;
        let (object, rights) = process.handles().lookup(handle)?;
        if !rights.contains(Rights::MAP) {
            return Err(KError::AccessDenied);
        }
        object
    };
    match exec.intids_of_object(object, out) {
        // A device with no line wired is not a device this can re-arm, and
        // saying so is what stops a driver waiting on an interrupt the graph
        // never routed.
        0 => Err(KError::AccessDenied),
        count => Ok(count),
    }
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

/// `ChannelSend`: hand a message to the peer with **nobody waiting for it** —
/// no reply expected, no request outstanding, no handoff.
///
/// Every message this system had moved until now was an answer to somebody's
/// request: a call, a reply, or the reply-receive a resident server parks in.
/// That shape suits a device a client reads from and cannot describe one that
/// speaks first. A frame arrives because a machine on the other side of the
/// wire sent one, and a driver holding it has no call to answer — which is why
/// `docs/drivers/02`'s network class makes a received frame an *event* and not
/// a completed read.
///
/// The executive already had the mechanism ([`Executive::send`]): enqueue on
/// the peer, wake a parked receiver without switching to it, and raise the
/// arrival on the destination endpoint's object so a server selecting across
/// per-client endpoints learns which one has work. Only the syscall was
/// missing.
///
/// **`Rights::WRITE`**, the same right a call needs, and for the same reason:
/// this puts a message in somebody else's queue. Reading their replies is what
/// `READ` is for, and a sender needs neither.
///
/// Handles and memory objects travel exactly as a request's do, which is what
/// lets an event *give something away* rather than describe it.
///
/// **A full queue is `WouldBlock` to the sender**, and the message — with the
/// handles it had already taken — is gone. That is the same bargain
/// [`channel_call`] strikes, and on this path it is the honest one: a sender
/// whose queue is full has a receiver that is not keeping up, and holding the
/// buffer for it is how a receive path stalls on its slowest client. The
/// sender learns, and says so; what it must not do is call the frame delivered.
#[inline(never)]
fn channel_send<A: AddressSpaceOps, C: ContextOps>(
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
    let message = match build_message_from_args(env.processes, env.caller, &args, true) {
        Ok((msg, departed)) => {
            end_bindings_of_departed(env, &departed);
            msg
        }
        Err(e) => return encode_result(Err(e)),
    };
    // Taken before the message moves, because after it there is nothing left
    // here to ask.
    let sent = message.inline().len() as u64;
    match env.exec.send(ep, message) {
        Ok(()) => encode_result(Ok(sent)),
        Err(e) => encode_result(Err(e)),
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

/// `ChannelMsgArgs.msg_flags` bit 0: return `WouldBlock` rather than parking
/// when no message is queued. ABI; append only.
pub const MSG_FLAG_NONBLOCKING: u32 = 0x1;

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
    // **`msg_flags` bit 0: do not block.** A server holding one endpoint has no
    // use for it — parking on the only channel it has is exactly right. A
    // server holding two does: a blocking receive would commit it to whichever
    // client spoke first and leave the other unheard for as long as the first
    // stayed quiet, which is not a bug in the server but what a blocking
    // receive means.
    let message = if args.msg_flags & MSG_FLAG_NONBLOCKING != 0 {
        match env.exec.try_receive(ep) {
            Ok(message) => message,
            Err(e) => return encode_result(Err(e)),
        }
    } else {
        match env.exec.receive(ep) {
            Ok(message) => message,
            Err(e) => return encode_result(Err(e)),
        }
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

/// Endpoints one `ChannelRecvAny` may wait on. Bounded like every vector that
/// crosses this boundary; a server with more clients than this is one whose
/// fan-out belongs to a router rather than to a syscall.
pub const MAX_RECV_ANY: usize = 8;

/// `ChannelRecvAny` (server side): wait on several endpoints and take from
/// whichever speaks first.
///
/// The endpoint handles come in the args' `handles_ptr`/`handle_count`, which
/// are unused in the receive direction — nothing is transferred *out* on a
/// receive, and what came *in* is reported through `installed_ptr`. The index
/// of the endpoint that answered goes back in `msg_flags`, because it is the
/// one thing a server that waited on several cannot work out from the message
/// it got, and it needs it to know where to reply.
#[inline(never)]
fn channel_recv_any<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let args = match read_channel_msg_args(env.processes, env.caller, args_ptr) {
        Ok(args) => args,
        Err(e) => return encode_result(Err(e)),
    };
    let count = saturating_len(args.handle_count);
    if count == 0 || count > MAX_RECV_ANY {
        return encode_result(Err(KError::InvalidArgument));
    }
    let mut raw = [0u8; MAX_RECV_ANY * 4];
    {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::BadHandle));
        };
        if let Err(e) = read_user(process, args.handles_ptr, &mut raw[..count * 4]) {
            return encode_result(Err(e));
        }
    }
    let mut endpoints = [crate::ipc::EndpointId {
        channel: 0,
        side: 0,
    }; MAX_RECV_ANY];
    for (index, slot) in endpoints[..count].iter_mut().enumerate() {
        let at = index * 4;
        let handle = u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        *slot = match resolve_endpoint(
            env.exec,
            env.processes,
            env.caller,
            u64::from(handle),
            Rights::READ,
        ) {
            Ok(ep) => ep,
            Err(e) => return encode_result(Err(e)),
        };
    }

    let (which, message) = match env.exec.receive_any(&endpoints[..count]) {
        Ok(answered) => answered,
        Err(e) => return encode_result(Err(e)),
    };
    let inline = message.inline();
    let n = inline.len().min(saturating_len(args.inline_len));
    if n > 0 {
        // Re-derive the process: this frame may have been parked and the table
        // mutated before the message arrived.
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
    if let Some(process) = env.processes.process_of_thread(env.caller) {
        let _ = write_user(
            process,
            args_ptr + syscall::CHANNEL_MSG_FLAGS_OFFSET,
            &(which as u32).to_le_bytes(),
        );
    }
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

/// `PortSignal`: raise a software edge on a port the caller was granted.
///
/// **The first thing `Rights::SIGNAL` gates.** Every other signal a port
/// carries comes from the machine — an interrupt line, a channel edge, a
/// device leaving — and the kernel raises it because it saw it happen. This
/// one is raised by a driver that saw something the machine cannot report: a
/// GPIO controller multiplexes eight lines onto one interrupt output, so which
/// line fired is known only to whoever read the status register.
///
/// Two things make that safe to expose. The signal goes to **the port named**
/// and not to every port bound to the source, so a driver cannot wake a client
/// waiting on somebody else's line by naming it. And the port must already be
/// **bound** to the source, so what a holder may raise was decided when the
/// port was made rather than by the argument it passes.
#[inline(never)]
fn port_signal<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    port_handle: u64,
    source: u64,
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
        // Waiting on a port and waking one are different authorities, and a
        // holder may well have one and not the other: the client watching a
        // GPIO line reads it, and the driver that demultiplexed the edge
        // raises it, and neither should be able to do the other's half.
        if !rights.contains(Rights::SIGNAL) {
            return encode_result(Err(KError::AccessDenied));
        }
        match env.exec.port_of_object(obj) {
            Some(port) => port,
            None => return encode_result(Err(KError::BadHandle)),
        }
    };
    match env
        .exec
        .port_signal_one(port, source, crate::exec::SOFTWARE_PORT_SIGNAL, 1)
    {
        Ok(()) => encode_result(Ok(0)),
        Err(e) => encode_result(Err(e)),
    }
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
    // A bus controller's window is bounded differently from a driver's, and has
    // to be: its whole job is to reach the configuration slot of every function
    // behind it, which is a bus's worth of space rather than one device's
    // registers.
    let ceiling = if env.exec.bus_window_of_object(object).is_some() {
        MAX_BUS_WINDOW_BYTES
    } else {
        MAX_DEVICE_WINDOW_BYTES
    };
    map_physical_window(env, object, request.vaddr, phys, len, ceiling)
}

/// Installs a physical window in the caller's space, with the bookkeeping every
/// window needs: the revocation record before the mapping, rollback if the
/// mapping fails, and an event either way.
///
/// Shared by `MapDevice` and `MapConfig` because the *window* is the same
/// mechanism in both — what differs is which window the capability names and
/// how large one may be, and both of those are decided before this runs.
fn map_physical_window<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    object: crate::object::ObjectId,
    va: u64,
    phys: u64,
    len: u64,
    ceiling: u64,
) -> i64 {
    if va >= A::USER_ADDRESS_MAX || va & (FRAME_SIZE - 1) != 0 {
        return map_refused(object.raw(), KError::InvalidMapping, va);
    }
    let page_base = phys & !(FRAME_SIZE - 1);
    let offset = phys & (FRAME_SIZE - 1);
    // The window spans from its first page to the last byte it covers, so an
    // unaligned base can push a sub-page window across a page boundary.
    let span = offset.saturating_add(len.max(1));
    if span > ceiling {
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

/// The largest **bus** window `MapDevice` will map: eight buses' worth of
/// configuration space, 256 functions of 4 KiB each.
///
/// A separate bound rather than a raised one. D114's argument for enumerating
/// PCI inside the kernel was that a driver granted a window gets a page against
/// a 256 MiB space; that argument is about *drivers*, and the answer to it —
/// scope the grant — is exactly what this bound does for a controller. What a
/// bus controller may reach is the buses it was given and no more, so a machine
/// with bridges behind bus 0 hands over more window or hands over more buses,
/// deliberately, rather than a controller quietly reaching them.
pub const MAX_BUS_WINDOW_BYTES: u64 = 0x80_0000;

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
    //
    // Asked as "does the graph know this device" rather than "where are its
    // registers", because a declared child may legitimately have none — an SD
    // card is reached through its controller — and a device manager still has
    // to be able to ask what it is.
    if !env.exec.device_known(object) {
        return encode_result(Err(KError::WrongType));
    }
    let record = match syscall::encode_device_info(
        env.exec.identity_of_object(object),
        env.exec.layout_of_object(object),
        env.exec.bus_window_of_object(object),
        env.exec.config_of_object(object).is_some(),
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

/// `DeviceDeclare`: a bus controller says a device exists.
///
/// **The first node in the resource graph that the kernel did not walk the
/// hardware to find.** `device_child` reads edges; this makes one. Everything
/// downstream — bind-by-class, `DeviceInfo`, reclaim-on-death — then works on a
/// device nothing privileged ever looked at, which is what moving enumeration
/// out of the kernel means in practice.
///
/// **Three checks, and the last two are the whole safety argument.**
///
/// 1. `Rights::DERIVE` on the bus, for the reason `device_child` needs it:
///    holding a bus is not by itself authority to populate it.
/// 2. The function's configuration slot must lie inside the window the bus's
///    own capability covers.
/// 3. Its register window must lie inside the memory the bus **forwards**.
///
/// Without the last two a controller declares a device whose "registers" are
/// the kernel's page tables and then maps them. A bus driver is exactly the
/// component to assume hostile: it is the one that touches every unknown device
/// on the machine before anything has classified it.
///
/// What is *not* checked is the identity. The controller read it out of
/// configuration space, which is the only place it exists, so there is nothing
/// to check it against — and saying so is better than a check that consists of
/// believing it twice. A driver that cares reads config space itself, through
/// the capability this hands back.
#[inline(never)]
fn device_declare<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::DEVICE_DECLARE_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_device_declare_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let (bus, bus_rights) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.bus) {
            Ok(v) => v,
            Err(e) => return encode_result(Err(e)),
        }
    };
    if !bus_rights.contains(Rights::DERIVE) {
        return encode_result(Err(KError::AccessDenied));
    }
    // Only something registered as a bus can contain anything.
    if !env.exec.device_known(bus) {
        return encode_result(Err(KError::WrongType));
    }
    let Some(window) = env.exec.bus_window_of_object(bus) else {
        return encode_result(Err(KError::WrongType));
    };

    // **A bus whose children have no configuration space of their own.** PCI's
    // children each own a slot; an SD card owns nothing — it is reached through
    // its controller, and a capability to it grants no memory at all. That is
    // the honest description rather than a gap: `docs/drivers/01`'s "where
    // hardware lacks separation, transfers relay through the bus host". A bus
    // declaring `config_len` zero says its children are of that kind, and the
    // slot arithmetic below has nothing to compute.
    let config = if window.config_len > 0 {
        let Some((config_base, config_len)) = env.exec.mmio_of_object(bus) else {
            return encode_result(Err(KError::WrongType));
        };
        // The function's slot, computed by the kernel from the bus's own base
        // rather than taken from the caller: an address a controller supplied
        // would be a number to validate, and a slot derived from a BDF is one
        // that cannot name anything outside the window by construction.
        //
        // Relative to the window's first bus, because the window starts *at*
        // that bus — a bridge advertising `bus-range = <4 8>` puts bus 4 at
        // offset zero, and treating the number as absolute would place every
        // slot four megabytes past where it is.
        let first = u64::from(window.first_bus) << 8;
        let Some(index) = u64::from(request.bdf).checked_sub(first) else {
            return encode_result(Err(KError::InvalidArgument));
        };
        let slot = index * CONFIG_SLOT_LEN;
        let Some(slot_end) = slot.checked_add(CONFIG_SLOT_LEN) else {
            return encode_result(Err(KError::InvalidArgument));
        };
        if slot_end > config_len || slot_end > window.config_len {
            return encode_result(Err(KError::InvalidArgument));
        }
        let Some(config_at) = config_base.checked_add(slot) else {
            return encode_result(Err(KError::InvalidArgument));
        };
        Some((config_at, CONFIG_SLOT_LEN))
    } else {
        None
    };

    // The register window, contained in what the bus forwards. A zero-length
    // window is a function with no BAR, which is ordinary — a bridge, a device
    // driven entirely through configuration space, an SD card — and is
    // registered as such rather than refused.
    //
    // **A bus that forwards nothing may declare no window at all**, and that is
    // a narrowing rather than a relaxation: it closes the case where the
    // no-window path could be used to smuggle a window past the containment
    // check by describing a bus with nothing to contain it in.
    let register = if request.register_len > 0 {
        if window.forward_len == 0 {
            return encode_result(Err(KError::AccessDenied));
        }
        let Some(end) = request.register_base.checked_add(request.register_len) else {
            return encode_result(Err(KError::InvalidArgument));
        };
        let Some(forward_end) = window.forward_cpu_base.checked_add(window.forward_len) else {
            return encode_result(Err(KError::InvalidArgument));
        };
        if request.register_base < window.forward_cpu_base || end > forward_end {
            return encode_result(Err(KError::AccessDenied));
        }
        Some((request.register_base, request.register_len))
    } else {
        None
    };

    // **A device inherits the kind of bus it was declared on.** It was
    // hard-coded to PCI while PCI was the only bus that declared anything, and
    // that is a fact about the device rather than about the declaration: what
    // transport a driver must speak is a binding input (`docs/drivers/01`), and
    // a platform device recorded as PCI would be offered to drivers written for
    // a bus it is not on. A bus the graph has no identity for keeps the old
    // answer, which is what every existing declaration produced.
    let bus_kind = env
        .exec
        .identity_of_object(bus)
        .map_or(crate::devmgr::DeviceBus::Pci, |identity| identity.bus);
    let identity = crate::devmgr::DeviceIdentity {
        class_code: request.class_code,
        vendor: request.vendor,
        device: request.device,
        bdf: request.bdf,
        revision: request.revision,
        bus: bus_kind,
    };
    // What the declared device is worth holding. Narrowed from the bus's own
    // grant, so a controller cannot mint a capability stronger than the one it
    // was given — and DERIVE travels down, because a declared device may itself
    // be a bridge with more behind it.
    let granted = bus_rights.intersection(
        Rights::READ
            | Rights::WRITE
            | Rights::MAP
            | Rights::TRANSFER
            | Rights::CONFIGURE
            | Rights::DERIVE,
    );
    let object = match env.exec.mint_declared_device_id() {
        Ok(object) => object,
        Err(e) => return encode_result(Err(e)),
    };
    if let Err(e) = env
        .exec
        .device_register_declared(object, register, config, granted, identity)
    {
        return encode_result(Err(e));
    }
    // **The interrupt, contained the way the window is.** A bus may declare a
    // device on a line inside the range its own capability carries and on no
    // other — without that, a bus driver could declare a device on somebody
    // else's INTID and have the graph route that line to itself, which is
    // claiming a wire it was not given.
    //
    // Zero is "this device has no interrupt", which is most of them, and it
    // needs no range at all: a bus that forwards no lines can still describe
    // devices, it just cannot say how they interrupt.
    if request.intid != 0 {
        let first = window.first_intid;
        let past = match first.checked_add(window.intid_count) {
            Some(past) => past,
            None => return encode_result(Err(KError::InvalidArgument)),
        };
        if window.intid_count == 0 || request.intid < first || request.intid >= past {
            return encode_result(Err(KError::AccessDenied));
        }
        if let Err(e) = env.exec.device_set_mmio_irq(object, request.intid) {
            return encode_result(Err(e));
        }
    }
    if let Err(e) = env.exec.device_set_parent(object, bus) {
        return encode_result(Err(e));
    }
    // **A device declared by a bus that forwards nothing is itself such a bus.**
    //
    // A relaying bus's children own no memory, and one of those children can
    // itself be a relaying bus: a USB hub holds devices that are reached
    // through it and then through the controller above it. Without this, the
    // `DERIVE` that travels down in `granted` is a right with nothing to
    // exercise — the holder can name the hub and cannot populate it, so a tree
    // of relaying buses is flat in the graph however deep it is in the machine,
    // and the path arithmetic that was supposed to count the hops counts one.
    //
    // A narrow grant, not a general one. Only a bus with nothing to forward and
    // no configuration space produces such a child, and the child inherits
    // exactly that: its own children can have no register window and no config
    // slot either. Nothing mappable is created at any depth.
    if window.config_len == 0
        && window.forward_len == 0
        && let Err(e) = env
            .exec
            .device_set_bus_window(object, crate::devmgr::BusWindow::default())
    {
        return encode_result(Err(e));
    }

    let installed = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles_mut().install(object, granted) {
            Ok(handle) => Some((handle.raw(), granted.bits())),
            // The device is in the graph and the caller has no handle to it.
            // Reported as such rather than unwound: the node is real, the
            // controller can ask the bus for it again with `DeviceChild`, and a
            // rollback here would delete a device because one table was full.
            Err(_) => None,
        }
    };
    let record = match syscall::encode_device_declare(installed) {
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

/// Bytes of configuration space one PCI function owns.
const CONFIG_SLOT_LEN: u64 = 4096;

/// `MapConfig`: map this function's own configuration space, and nothing else.
///
/// **`Rights::CONFIGURE`, not `Rights::MAP`.** They are different authorities
/// over the same device: configuration space is where bus mastering is turned
/// on, where a BAR can be moved out from under whoever placed it, and where MSI
/// is armed. A driver may be trusted with a device's registers and not with
/// those, and a bus controller can only make that distinction because the two
/// rights are separate.
///
/// A device with no configuration window answers `NotSupported`. That is every
/// device the kernel itself registered — none of them has a slot, because a
/// slot is what a *declaration* records — and answering it plainly beats
/// mapping something adjacent and letting the driver find out.
#[inline(never)]
fn map_config<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::MAP_CONFIG_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_map_config_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let object = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let (object, rights) = match process.handles().lookup(request.device) {
            Ok(v) => v,
            Err(e) => return encode_result(Err(e)),
        };
        if !rights.contains(Rights::CONFIGURE) {
            return encode_result(Err(KError::AccessDenied));
        }
        object
    };
    let Some((base, len)) = env.exec.config_of_object(object) else {
        return encode_result(Err(KError::NotSupported));
    };
    map_physical_window(env, object, request.vaddr, base, len, CONFIG_SLOT_LEN)
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
    let object = match env.exec.memory_create(
        owner,
        pages as usize,
        request.placement,
        process.space(),
        env.alloc,
    ) {
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

/// `FirmwareLoad`: verify a named image from the system store, admit it against
/// policy, and hand it back as a memory object.
///
/// **The split between who asks and who decides is the whole design.**
/// `docs/drivers/01` says firmware loading is mediated by the driver framework,
/// which is a ring-3 manager; the store is verified against anchors compiled
/// into this kernel, and giving those anchors to a manager would move the root
/// of trust into ring 3. So the manager holds `Rights::FIRMWARE` and asks, and
/// this measures, judges, and produces the bytes.
///
/// The image arrives as an **object** rather than a copy into a caller buffer
/// for the same reason `MemoryCreate` answers with one: it can be transferred,
/// and transferring it moves the pages. A manager fetching firmware on a
/// driver's behalf then hands it over exactly as it hands over the device.
///
/// The object is installed **without `WRITE`**. A driver is meant to measure
/// what it was given and program it into hardware; one that could edit it first
/// would make the digest in the provenance record a statement about bytes that
/// no longer exist.
///
/// The report is written on **both** paths. A refusal that produced no report
/// would tell a caller that policy said no and leave it unable to say which
/// policy — and those two refusals are two different conversations.
fn firmware_load<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::FIRMWARE_LOAD_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_firmware_load_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };

    // The authority, and it is the only access decision here. A device handle
    // without FIRMWARE is a caller that may drive the device and may not put
    // code on it — which is exactly the state a driver is left in when the
    // manager narrows the right away on transfer.
    let device = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.device) {
            Ok((object, rights)) if rights.contains(Rights::FIRMWARE) => object,
            Ok((object, _)) => {
                crate::firmware::record_refusal(object.raw() as u64, KError::AccessDenied);
                return encode_result(Err(KError::AccessDenied));
            }
            Err(e) => {
                crate::firmware::record_refusal(0, e);
                return encode_result(Err(e));
            }
        }
    };

    let Some(name) = request.name_str() else {
        crate::firmware::record_refusal(device.raw() as u64, KError::Protocol);
        return encode_result(Err(KError::Protocol));
    };

    let need = tessera_firmware::Requirement {
        min_image_version: request.min_image_version,
    };
    let admitted = match crate::firmware::load(device.raw() as u64, name, need) {
        Ok(admitted) => admitted,
        Err(error) => {
            // The report first, then the error. A caller that reads the report
            // learns which policy spoke and **which version was refused** —
            // the number a rollback has to be compared against a floor with —
            // while one that only checks the return value still learns that
            // policy said no.
            let image = error.image();
            let bytes = syscall::encode_firmware_report(
                error.refusal(),
                image.map_or(0, |image| image.svn),
                image.map_or(0, |image| image.image_version),
                0,
                [0; 32],
            );
            if let (Ok(bytes), Some(process)) = (bytes, env.processes.process_of_thread(env.caller))
            {
                let _ = write_user(process, request.report_ptr, &bytes);
            }
            return encode_result(Err(error.code()));
        }
    };

    // Round up to whole pages: an object is pages, and an image that does not
    // fill its last one leaves the tail zeroed by `MemoryTable::create` rather
    // than carrying whatever the frame held before.
    let pages = (admitted.bytes.len() as u64).div_ceil(FRAME_SIZE);
    if pages == 0 || pages > crate::memory::MAX_OBJECT_PAGES as u64 {
        return encode_result(Err(KError::LimitExceeded));
    }

    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    let owner = process.id();
    // No placement constraints: a firmware image is read by the CPU and copied
    // into a device by whatever loads it, so where its pages sit is nothing's
    // business. A constraint invented here would spend physical runs on
    // hardware that never asked.
    let object = match env.exec.memory_create(
        owner,
        pages as usize,
        crate::memory::Placement::default(),
        process.space(),
        env.alloc,
    ) {
        Ok(object) => object,
        Err(e) => return encode_result(Err(e)),
    };

    // Fill it through the direct map, frame by frame — the same primitive the
    // ELF loader populates a not-yet-active address space with, and for the
    // same reason: the object belongs to a process whose tables are not the
    // ones running.
    let mut frames = [PhysFrame::containing(PhysAddr::new(0)); crate::memory::MAX_OBJECT_PAGES];
    let found = env.exec.memory_frames_of(object, &mut frames);
    let mut written = 0usize;
    {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        for frame in frames.iter().take(found) {
            let remaining = admitted.bytes.len() - written;
            let take = remaining.min(FRAME_SIZE as usize);
            process.space().arch().write_bytes_to_frame(
                *frame,
                0,
                &admitted.bytes[written..written + take],
            );
            written += take;
        }
    }

    let Some(process) = env.processes.process_of_thread(env.caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    // READ | MAP | TRANSFER, and deliberately not WRITE: see above.
    match process
        .handles_mut()
        .install(object, Rights::READ | Rights::MAP | Rights::TRANSFER)
    {
        Ok(handle) => {
            let bytes = syscall::encode_firmware_report(
                crate::isl_binding::firmware::FirmwareRefusal::None,
                admitted.svn,
                admitted.image_version,
                admitted.bytes.len() as u64,
                admitted.digest,
            );
            let Some(process) = env.processes.process_of_thread(env.caller) else {
                return encode_result(Err(KError::AccessDenied));
            };
            match bytes {
                Ok(bytes) => {
                    if let Err(e) = write_user(process, request.report_ptr, &bytes) {
                        return encode_result(Err(e));
                    }
                }
                Err(e) => return encode_result(Err(e)),
            }
            encode_result(Ok(u64::from(handle.raw())))
        }
        Err(e) => {
            // Nothing holds the object, so its frames go back here or they are
            // lost with no handle able to name them — the `MemoryCreate`
            // argument, and it applies the same way to an object filled with
            // an image nobody received.
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

/// `MemoryClassify`: put a memory object on a handling path.
///
/// **Requires `WRITE` on the memory, not `MAP`.** Raising a class restricts what
/// may be done with the object from then on, so it is a modification of the
/// object rather than an opinion about it — and a holder with a read-only view
/// has no business changing what everyone else may do with memory it can only
/// look at.
///
/// A request that would *lower* the class is refused by the table
/// ([`crate::memory::MemoryTable::classify`]); the record below is emitted only
/// for a request that took effect, so the event stream carries the moment memory
/// became protected rather than every restatement of it.
fn memory_classify<A: AddressSpaceOps, C: ContextOps>(
    env: &mut DispatchEnv<'_, A, C>,
    args_ptr: u64,
) -> i64 {
    let request = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; syscall::MEMORY_CLASSIFY_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        match syscall::decode_memory_classify_args(&abuf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let (object, owner) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let object = match process.handles().lookup(request.memory) {
            Ok((object, rights)) if rights.contains(Rights::WRITE) => object,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        };
        (object, process.id())
    };
    let Some(was) = env.exec.memory_class_of(object) else {
        return encode_result(Err(KError::WrongType));
    };
    if let Err(e) = env.exec.memory_classify(object, request.class) {
        return encode_result(Err(e));
    }
    if was != request.class {
        crate::event::emit(
            crate::event::EventKind::MemoryClassified,
            crate::event::Severity::Notice,
            crate::event::Component::Security,
            [
                object.raw() as u64,
                request.class as u32 as u64,
                was as u32 as u64,
                owner.raw() as u64,
            ],
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
    let (device, device_rights, memory) = {
        let Some(process) = env.processes.process_of_thread(env.caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let (device, device_rights) = match process.handles().lookup(request.device) {
            Ok((object, rights)) if rights.contains(Rights::MAP) => (object, rights),
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        };
        let memory = match process.handles().lookup(request.memory) {
            Ok((object, rights)) if rights.contains(Rights::MAP) => object,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        };
        (device, device_rights, memory)
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

    // **The IOMMU-first rule** (`docs/hardware/04`, "Contiguity Contract"):
    // physical contiguity is honoured only for hardware that genuinely needs
    // it — no scatter-gather capability and no IOMMU on its path — and a device
    // behind one must ask for *device-visible* contiguity instead, which the
    // broker satisfies by laying scattered pages out at consecutive device
    // addresses.
    //
    // Refused rather than quietly accepted, because accepting is what makes the
    // rule decorative: a run of physical memory spent on a device that did not
    // need one is memory nothing can defragment, and the caller would never
    // learn it had over-asked. Answered with `PolicyRefused` so it reads as a
    // policy saying no rather than as memory running out — the caller's fix is
    // to ask for `DEVICE_CONTIGUOUS`, and an `OutOfMemory` would send it away
    // to retry a request that can never succeed.
    let placement = env.exec.memory_placement_of(memory).unwrap_or_default();
    let needs_physical = env.exec.device_requires_contiguity(device);
    if placement.physically_contiguous && !needs_physical {
        crate::event::emit(
            crate::event::EventKind::DmaContiguityRefused,
            crate::event::Severity::Warning,
            crate::event::Component::Driver,
            [device.raw() as u64, memory.raw() as u64, 0, 0],
        );
        return encode_result(Err(KError::PolicyRefused));
    }

    // **Protected memory reaches a device only if the device is authorized for
    // it** (`docs/drivers/01`, "DMA Safety"; `docs/security/01`, "Memory
    // Classification"). The authority is on the *device* handle, because which
    // hardware may be trusted with protected content is a platform fact rather
    // than a decision each buffer's owner should make — and it narrows away on
    // transfer, so a driver handed a device is handed that answer with it.
    //
    // **Checked here, before anything is allocated.** Everything below draws on
    // the device's aperture, and a refusal that had already consumed address
    // space would let a caller exhaust a device's translations with requests it
    // was never allowed to make.
    let class = env
        .exec
        .memory_class_of(memory)
        .unwrap_or(crate::memory::MemoryClass::Unclassified);
    if !crate::memory::attach_permitted(class, device_rights) {
        crate::event::emit(
            crate::event::EventKind::DmaProtectedRefused,
            crate::event::Severity::Warning,
            crate::event::Component::Security,
            [
                device.raw() as u64,
                memory.raw() as u64,
                class as u32 as u64,
                device_rights.bits(),
            ],
        );
        return encode_result(Err(KError::AccessDenied));
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
#[path = "tests/dispatch.rs"]
mod tests;
