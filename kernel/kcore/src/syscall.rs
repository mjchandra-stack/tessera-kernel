// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Syscall dispatch logic: the architecture-independent, host-testable core of
//! the user↔kernel boundary. The port (`karch-x86_64/src/syscall.rs`) captures
//! the register frame and the kernel crate orchestrates effects (console,
//! scheduler); everything that decides *validity* and *outcome* lives here.
//!
//! Two rules from the ABI (docs/api/01 "ABI Rules", docs/api/03 "Kernel ABI
//! Subset") are enforced here: **validate before interpret** — argument structs
//! are checked for `size`/`version`/`flags`/reserved-zero before any field is
//! used; and **strict user↔kernel copy validation** — a user pointer/length is
//! checked to lie wholly within user-accessible mappings of the caller's
//! address space before any copy (docs/security/01). Every argument struct
//! decodes through its **ISL-generated** binding (`crate::isl_binding`, from the
//! `process_abi`/`handle_abi`/`channel_msg` schemas — the schema is the
//! wire-layout source of truth, no hand-rolled serialization; build/README.md
//! D24/D54); the generated `WireDecode` extracts + shape-checks the fields, and
//! the kernel enforces the semantic header (`size`/`version`/`flags`[/`reserved`])
//! on the typed result.
//!
//! Results are a single `i64`: non-negative is success (a value — a new handle,
//! a rights mask, or 0); negative encodes `-((domain << 16) | code)` over the
//! six stable error domains (docs/api/01 "Error Model").
//!
//! Normative: docs/api/01-system-call-interface.md,
//! docs/api/03-interface-schema-language.md ("Kernel ABI Subset"),
//! docs/security/01-security-model.md ("Memory Safety")
//! Budget: B1 (null syscall), B2 (handle op) — the dispatch bodies; unmeasured
//! until the perf rig lands (build/README.md, D26)

use crate::handle::Handle;
use crate::isl_binding::channel::{ChannelCreateArgs, ChannelMsgArgs};
use crate::isl_binding::device::{DmaAllocArgs, IrqCompleteArgs, MapDeviceArgs};
use crate::isl_binding::handle::DuplicateArgs;
use crate::isl_binding::port::PortEventRecord;
use crate::isl_binding::process::{AddressSpaceMapArgs, ProcessCreateArgs, ProcessStartArgs};
use crate::object::ObjectTable;
use crate::process::Process;
use crate::rights::Rights;
use crate::vm::AddressSpace;
use tessera_isl_runtime::{Reader, WireDecode};
use tessera_karch::{AddressSpaceOps, FRAME_SIZE, KError, VirtAddr};

/// The minimal syscall set this milestone implements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum SyscallNumber {
    /// Validated no-op — the B1 null-syscall path.
    Null = 0,
    /// Write a validated user buffer to the debug console: `arg0` = pointer,
    /// `arg1` = length.
    DebugWrite = 1,
    /// Duplicate a handle with reduced rights: `arg0` = pointer to a
    /// `DuplicateArgs` struct. The B2 handle-op path.
    HandleDuplicate = 2,
    /// Query a handle's rights: `arg0` = handle. Returns the rights mask.
    HandleQueryRights = 3,
    /// Close a handle: `arg0` = handle. Returns 1 if the object was destroyed.
    HandleClose = 4,
    /// Terminate the calling process: `arg0` = exit code.
    ProcessExit = 5,
    /// Futex-style wait: block iff `*arg0 == arg1`. `arg0` = a 4-byte-aligned
    /// user pointer to a `u32` word; `arg1` = the expected value. Returns 0 on
    /// wake, or `WouldBlock` if the word already differs (the B6 path).
    WaitOnAddress = 6,
    /// Wake up to `arg1` threads waiting on the address `arg0`. Returns the
    /// number woken.
    WakeAddress = 7,
    /// Create an empty, not-yet-started process under a parent job's
    /// `create-process` authority (`docs/api/01`, the three-phase model):
    /// `arg0` = pointer to a `ProcessCreateArgs` struct. Returns a process
    /// handle. The loader/component-manager surface — the in-kernel loader
    /// exercises the same create/populate/start path; the ring-3 caller and the
    /// object/handle bridge are deferred (build/README.md, D42).
    ProcessCreate = 8,
    /// Map memory into a created, not-yet-started process's address space (the
    /// loader operation): `arg0` = pointer to an `AddressSpaceMapArgs` struct.
    AddressSpaceMap = 9,
    /// Start a created + populated process at an entry point: `arg0` = pointer
    /// to a `ProcessStartArgs` struct.
    ProcessStart = 10,
    /// Create a channel, returning its two endpoint handles: `arg0` = pointer to
    /// a `ChannelCreateArgs` struct. Ring-3 create (two-handle write-back) is
    /// deferred; the bootstrap channel is installed by the component-manager
    /// context before start (build/README.md, D45).
    ChannelCreate = 11,
    /// Send a message one-way on an endpoint (async, no reply): `arg0` = pointer
    /// to a `ChannelMsgArgs` struct, `arg1` = endpoint handle.
    ChannelSend = 12,
    /// Receive the next message on an endpoint, blocking until one arrives:
    /// `arg0` = pointer to a `ChannelMsgArgs` struct (describing where to place
    /// the header/observation), `arg1` = endpoint handle.
    ChannelRecv = 13,
    /// Synchronous call: send a request and block for the reply, handing off
    /// directly to the server: `arg0` = pointer to a `ChannelMsgArgs` struct,
    /// `arg1` = endpoint handle. The B3 round-trip path.
    ChannelCall = 14,
    /// Reply to the outstanding call on an endpoint, handing off back to the
    /// waiting caller: `arg0` = pointer to a `ChannelMsgArgs` struct, `arg1` =
    /// endpoint handle.
    ChannelReply = 15,
    /// Create a port (async event object), returning its handle. No arguments.
    /// The driver-host substrate — a port receives a device interrupt as an
    /// event (build/README.md, D46).
    PortCreate = 16,
    /// Bind a port to an event source+signal: `arg0` = port handle, `arg1` =
    /// source id, `arg2` = signal. Scalars in registers (no args struct).
    PortBind = 17,
    /// Wait for the next event on a port, blocking until one arrives: `arg0` =
    /// port handle. Returns the drained event's pending count.
    PortWait = 18,
    /// Read a device register through a device-I/O capability: `arg0` = device
    /// handle, `arg1` = register offset. Returns the byte read.
    DeviceIoRead = 19,
    /// Write a device register through a device-I/O capability: `arg0` = device
    /// handle, `arg1` = register offset, `arg2` = byte value.
    DeviceIoWrite = 20,
    /// A ring-3 pager (filesystem service) waits for the next page-in request on
    /// its endpoint: `arg0` = endpoint handle. Returns the faulting object offset
    /// so the service can locate the page in its backing store (build/README.md,
    /// D48).
    PageServe = 21,
    /// A ring-3 pager supplies the pending page-in from its own buffer and waits
    /// for the next request: `arg0` = endpoint handle, `arg1` = source page
    /// pointer (in the service's buffer). Returns the next request's offset.
    PageSupply = 22,
    /// Map a device's MMIO register window — named by a Device capability whose
    /// resource-graph payload is a physical `(base, len)` window — into the
    /// caller's own address space: `arg0` = device handle (needs `Rights::MAP`),
    /// `arg1` = the desired page-aligned user virtual address. Returns the mapped
    /// VA. The window is mapped Device-memory + user-readable; the physical base
    /// comes solely from the capability, never the caller. The first step of the
    /// ring-3 driver host (build/README.md, D77).
    MapDevice = 23,
    /// Allocate a DMA buffer for a ring-3 driver: `arg0` = device handle (the
    /// driver's authority; needs `Rights::MAP`), `arg1` = the desired
    /// page-aligned user virtual address. Maps a fresh zero-filled page there and
    /// returns its **physical address**, so the driver can both fill the buffer
    /// through its VA and hand the device the physical address it DMAs against.
    /// The second step of the ring-3 driver host (build/README.md, D78).
    DmaAlloc = 24,
    /// Reply to the current caller and receive the next request in one
    /// operation — the server-loop primitive a resident service parks in.
    /// `arg0` = pointer to a `ChannelMsgArgs` struct (the symmetric buffer:
    /// the reply payload is read out of `inline_ptr`, then the next request
    /// is copied back into it, clamped to `inline_len`); `arg1` = the
    /// endpoint handle (needs `Rights::READ`). Returns the next request's
    /// length. The third step of the ring-3 driver host (build/README.md,
    /// D82).
    ChannelReplyRecv = 25,
    /// Re-enable the interrupt line of the device named by the caller's
    /// Device capability (which needs `Rights::MAP` and a wired INTID), after
    /// the driver acknowledged the device through its own mapped window — the
    /// re-arm half of the mask-on-deliver interrupt protocol (D84). `arg0` =
    /// pointer to an `IrqCompleteArgs` struct. Arch-coupled (the enable is an
    /// interrupt-controller operation), so the arm is port-local, like
    /// `DebugWrite`/`ProcessExit`.
    IrqComplete = 26,
    /// Replies to the outstanding call on an endpoint and **keeps running**.
    /// `arg0` = pointer to a `ChannelMsgArgs` struct (the reply payload is
    /// read out of `inline_ptr`); `arg1` = the endpoint handle (needs
    /// `Rights::WRITE`). Returns 0.
    ///
    /// [`ChannelReply`](Self::ChannelReply) hands off to the caller and
    /// *blocks* the server, which is right for a server whose next wake is
    /// the next `call` on that same endpoint — the handoff itself resumes it.
    /// A server that selects across several endpoints is woken by its *port*
    /// instead, so blocking in the reply strands it forever: nothing ever
    /// hands back. This is the reply such a server uses (build/README.md,
    /// D85).
    ChannelReplyContinue = 27,
}

impl SyscallNumber {
    /// Decodes a raw syscall number, or `None` for an unknown one.
    pub fn from_u64(number: u64) -> Option<Self> {
        Some(match number {
            0 => Self::Null,
            1 => Self::DebugWrite,
            2 => Self::HandleDuplicate,
            3 => Self::HandleQueryRights,
            4 => Self::HandleClose,
            5 => Self::ProcessExit,
            6 => Self::WaitOnAddress,
            7 => Self::WakeAddress,
            8 => Self::ProcessCreate,
            9 => Self::AddressSpaceMap,
            10 => Self::ProcessStart,
            11 => Self::ChannelCreate,
            12 => Self::ChannelSend,
            13 => Self::ChannelRecv,
            14 => Self::ChannelCall,
            15 => Self::ChannelReply,
            16 => Self::PortCreate,
            17 => Self::PortBind,
            18 => Self::PortWait,
            19 => Self::DeviceIoRead,
            20 => Self::DeviceIoWrite,
            21 => Self::PageServe,
            22 => Self::PageSupply,
            23 => Self::MapDevice,
            24 => Self::DmaAlloc,
            25 => Self::ChannelReplyRecv,
            26 => Self::IrqComplete,
            27 => Self::ChannelReplyContinue,
            _ => return None,
        })
    }
}

/// The six stable, machine-readable error domains (docs/api/01 "Error Model").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum ErrorDomain {
    Kernel = 1,
    SecurityPolicy = 2,
    Resource = 3,
    Protocol = 4,
    Device = 5,
    Virtualization = 6,
}

/// Result for a syscall number the kernel does not implement.
pub const ENOSYS: i64 = -((ErrorDomain::Kernel as i64) << 16);

/// Which domain a `KError` belongs to when it crosses the syscall boundary.
fn domain_of(error: KError) -> ErrorDomain {
    match error {
        KError::AccessDenied => ErrorDomain::SecurityPolicy,
        KError::OutOfMemory | KError::LimitExceeded => ErrorDomain::Resource,
        KError::Protocol => ErrorDomain::Protocol,
        _ => ErrorDomain::Kernel,
    }
}

/// Encodes a syscall outcome as the ABI result word: non-negative success value,
/// or `-((domain << 16) | code)` for an error.
pub fn encode_result(result: Result<u64, KError>) -> i64 {
    match result {
        Ok(value) => value as i64,
        Err(error) => {
            let domain = domain_of(error) as i64;
            let code = error as u16 as i64;
            -((domain << 16) | code)
        }
    }
}

/// Validates that `[ptr, ptr + len)` lies wholly within user-accessible
/// mappings of `space` before any copy crosses the boundary (docs/security/01,
/// "Strict user-kernel copy validation"). `need_write` additionally requires
/// write permission. A zero length is trivially valid. This is the up-front
/// check that stands in for a fault-capable copy helper this milestone (D22).
pub fn validate_user_range<A: AddressSpaceOps>(
    space: &AddressSpace<A>,
    ptr: u64,
    len: u64,
    need_write: bool,
) -> Result<(), KError> {
    if len == 0 {
        return Ok(());
    }
    let end = ptr.checked_add(len).ok_or(KError::AccessDenied)?;
    if end > A::USER_ADDRESS_MAX {
        return Err(KError::AccessDenied);
    }
    let mut page = ptr & !(FRAME_SIZE - 1);
    while page < end {
        let flags = space
            .rights_at(VirtAddr::new(page))
            .ok_or(KError::AccessDenied)?;
        if !flags.is_user() || !flags.readable() {
            return Err(KError::AccessDenied);
        }
        if need_write && !flags.writable() {
            return Err(KError::AccessDenied);
        }
        page += FRAME_SIZE;
    }
    Ok(())
}

/// Wire size of the `DuplicateArgs` `@abi` struct (`handle_abi.isl`).
pub const DUPLICATE_ARGS_SIZE: usize = 32;

/// Decodes and validates a `DuplicateArgs` struct from raw user bytes: checks
/// `size`/`version`/`flags`/reserved-padding before interpreting the source
/// handle and requested rights (docs/api/03, validate before interpret). Layout
/// (little-endian, mirrors `handle_abi.isl`): size:u32, version:u32, flags:u64,
/// source:handle(u32), reserved:u32, new_rights:u64.
pub fn decode_duplicate_args(bytes: &[u8]) -> Result<(Handle, Rights), KError> {
    // The struct has no explicit `reserved` field — the 4-byte gap before
    // `new_rights` is padding the generated decode validates as zero.
    let args = DuplicateArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != DUPLICATE_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok((
        Handle::from_raw(args.source.index()),
        Rights::from_bits(args.new_rights.bits()),
    ))
}

// Every syscall argument struct is decoded through its ISL-generated binding
// (`crate::isl_binding`); the hand-rolled `le_u32`/`le_u64` byte readers they
// used to share are gone (D24 closed).

/// Wire size of `ProcessCreateArgs` (`process_abi.isl`).
pub const PROCESS_CREATE_ARGS_SIZE: usize = 24;

/// Decodes a `ProcessCreateArgs` (Phase 1) and returns the parent `job` handle
/// whose `create-process` authority the creation runs under. Decoded through the
/// ISL-generated binding (the `process_abi.isl` schema is the wire-layout source
/// of truth); the generated `WireDecode` extracts and shape-checks the fields,
/// and the kernel enforces the semantic header (size/version/flags/reserved-zero)
/// on the typed result.
pub fn decode_process_create_args(bytes: &[u8]) -> Result<Handle, KError> {
    let args = ProcessCreateArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != PROCESS_CREATE_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(Handle::from_raw(args.job.index()))
}

/// A decoded `AddressSpaceMapArgs` (Phase 2 — the loader map+copy operation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressSpaceMapRequest {
    /// Handle to the target (created, not-yet-started) process.
    pub process: Handle,
    /// Destination virtual address in the child (page-aligned).
    pub vaddr: u64,
    /// Byte length to map.
    pub length: u64,
    /// Final page rights (W^X enforced by the kernel).
    pub rights: Rights,
    /// Caller-buffer source address to copy from, or `0` for zero-filled.
    pub src: u64,
}

/// Wire size of `AddressSpaceMapArgs` (`process_abi.isl`, D44: +`src`).
pub const ADDRESS_SPACE_MAP_ARGS_SIZE: usize = 56;

/// Decodes an `AddressSpaceMapArgs` (Phase 2): validates the header before
/// interpreting the target process, range, rights, and copy source. Layout (LE):
/// size:u32, version:u32, flags:u64, process:handle(u32), reserved:u32,
/// vaddr:u64, length:u64, rights:u64, src:u64.
pub fn decode_address_space_map_args(bytes: &[u8]) -> Result<AddressSpaceMapRequest, KError> {
    let args =
        AddressSpaceMapArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != ADDRESS_SPACE_MAP_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(AddressSpaceMapRequest {
        process: Handle::from_raw(args.process.index()),
        vaddr: args.vaddr,
        length: args.length,
        rights: Rights::from_bits(args.rights.bits()),
        src: args.src,
    })
}

/// A decoded `ProcessStartArgs` (Phase 3 — start the initial thread).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessStartRequest {
    /// Handle to the created + populated process to start.
    pub process: Handle,
    /// Initial thread entry point.
    pub entry: u64,
    /// Initial thread stack pointer.
    pub stack: u64,
    /// Initial argument passed to the entry point.
    pub arg: u64,
}

/// Wire size of `ProcessStartArgs` (`process_abi.isl`).
pub const PROCESS_START_ARGS_SIZE: usize = 48;

/// Decodes a `ProcessStartArgs` (Phase 3): validates the header before
/// interpreting the target process, entry, stack, and argument. Layout (LE):
/// size:u32, version:u32, flags:u64, process:handle(u32), reserved:u32,
/// entry:u64, stack:u64, arg:u64.
pub fn decode_process_start_args(bytes: &[u8]) -> Result<ProcessStartRequest, KError> {
    let args = ProcessStartArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != PROCESS_START_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(ProcessStartRequest {
        process: Handle::from_raw(args.process.index()),
        entry: args.entry,
        stack: args.stack,
        arg: args.arg,
    })
}

/// Wire size of `ChannelCreateArgs` (`channel_msg.isl`).
pub const CHANNEL_CREATE_ARGS_SIZE: usize = 32;

/// Decodes a `ChannelCreateArgs`: validates the size/version/flags header before
/// returning the initial rights for each of the two endpoint handles. Layout
/// (LE): size:u32, version:u32, flags:u64, end0_rights:u64, end1_rights:u64.
pub fn decode_channel_create_args(bytes: &[u8]) -> Result<(Rights, Rights), KError> {
    let args = ChannelCreateArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != CHANNEL_CREATE_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok((
        Rights::from_bits(args.end0_rights.bits()),
        Rights::from_bits(args.end1_rights.bits()),
    ))
}

/// A decoded `ChannelMsgArgs` — the message-carrying channel operations
/// (send/call/recv/reply). The target endpoint is passed in a register, not in
/// the struct, so it is not a field here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChannelMsgRequest {
    /// Interface id in the message header.
    pub interface_id: u64,
    /// Method id in the message header.
    pub method_id: u32,
    /// Message header flags.
    pub msg_flags: u32,
    /// Caller-buffer pointer to the inline payload bytes.
    pub inline_ptr: u64,
    /// Inline payload length in bytes.
    pub inline_len: u64,
    /// Caller-buffer pointer to the transfer-handle vector (`u32` handle values).
    pub handles_ptr: u64,
    /// Number of handles in the transfer vector.
    pub handle_count: u64,
}

/// Wire size of `ChannelMsgArgs` (`channel_msg.isl`).
pub const CHANNEL_MSG_ARGS_SIZE: usize = 72;

/// Decodes a `ChannelMsgArgs`: validates the size/version/flags header before
/// interpreting the header fields and the inline/handle-vector descriptors.
/// `txn_id` is stamped by the kernel on a call, so it is not surfaced. Layout
/// (LE): size:u32, version:u32, flags:u64, interface_id:u64, txn_id:u64,
/// method_id:u32, msg_flags:u32, inline_ptr:u64, inline_len:u64, handles_ptr:u64,
/// handle_count:u64.
pub fn decode_channel_msg_args(bytes: &[u8]) -> Result<ChannelMsgRequest, KError> {
    let args = ChannelMsgArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != CHANNEL_MSG_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    // `args.txn_id` is decoded but ignored — the kernel stamps its own on a call.
    Ok(ChannelMsgRequest {
        interface_id: args.interface_id,
        method_id: args.method_id,
        msg_flags: args.msg_flags,
        inline_ptr: args.inline_ptr,
        inline_len: args.inline_len,
        handles_ptr: args.handles_ptr,
        handle_count: args.handle_count,
    })
}

/// A decoded `MapDeviceArgs` — map the MMIO window named by the device
/// capability into the caller's own address space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MapDeviceRequest {
    /// Handle to the device capability (must carry `Rights::MAP`).
    pub device: Handle,
    /// Desired page-aligned user virtual address.
    pub vaddr: u64,
}

/// A decoded `DmaAllocArgs` — allocate a device-visible DMA page in the
/// caller's own address space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DmaAllocRequest {
    /// Handle to the authorizing device capability (must carry `Rights::MAP`
    /// and resolve to a real MMIO-backed device).
    pub device: Handle,
    /// Desired page-aligned user virtual address.
    pub vaddr: u64,
}

/// Wire size of `MapDeviceArgs` (`device_abi.isl`).
pub const MAP_DEVICE_ARGS_SIZE: usize = 32;

/// Wire size of `DmaAllocArgs` (`device_abi.isl`).
pub const DMA_ALLOC_ARGS_SIZE: usize = 32;

/// Decodes a `MapDeviceArgs`: validates the size/version/flags/reserved header
/// before interpreting the device handle and destination VA. Layout (LE):
/// size:u32, version:u32, flags:u64, device:handle(u32), reserved:u32,
/// vaddr:u64.
pub fn decode_map_device_args(bytes: &[u8]) -> Result<MapDeviceRequest, KError> {
    let args = MapDeviceArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != MAP_DEVICE_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(MapDeviceRequest {
        device: Handle::from_raw(args.device.index()),
        vaddr: args.vaddr,
    })
}

/// Decodes a `DmaAllocArgs`: same header discipline as `MapDeviceArgs`.
pub fn decode_dma_alloc_args(bytes: &[u8]) -> Result<DmaAllocRequest, KError> {
    let args = DmaAllocArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != DMA_ALLOC_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(DmaAllocRequest {
        device: Handle::from_raw(args.device.index()),
        vaddr: args.vaddr,
    })
}

/// Wire size of `IrqCompleteArgs` (`device_abi.isl`).
pub const IRQ_COMPLETE_ARGS_SIZE: usize = 24;

/// Decodes an `IrqCompleteArgs`: validates the size/version/flags/reserved
/// header before interpreting the device handle. Layout (LE): size:u32,
/// version:u32, flags:u64, device:handle(u32), reserved:u32.
pub fn decode_irq_complete_args(bytes: &[u8]) -> Result<Handle, KError> {
    let args = IrqCompleteArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != IRQ_COMPLETE_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(Handle::from_raw(args.device.index()))
}

/// Wire size of `PortEventRecord` (`port_event.isl`).
pub const PORT_EVENT_RECORD_SIZE: usize = 32;

/// Encodes a drained port event into its ISL wire record (the select result
/// a `PortWait` hands back, D85).
pub fn encode_port_event(
    source: u64,
    signal: u8,
    pending: u32,
    buf: &mut [u8; PORT_EVENT_RECORD_SIZE],
) -> Result<(), KError> {
    let record = PortEventRecord {
        size: PORT_EVENT_RECORD_SIZE as u32,
        version: 1,
        flags: 0,
        source,
        signal: u32::from(signal),
        pending,
    };
    tessera_isl_runtime::encode(&record, buf).map_err(|_| KError::Protocol)?;
    Ok(())
}

/// Reads `buf.len()` bytes from the caller's user memory at `ptr`, after
/// validating the whole range lies in user-readable mappings of the caller's
/// (active) address space. The one shared user→kernel copy site (D22): both
/// ports used to duplicate this validate+copy pair in their boot glue.
pub fn read_user<A: AddressSpaceOps>(
    process: &Process<A>,
    ptr: u64,
    buf: &mut [u8],
) -> Result<(), KError> {
    validate_user_range(process.space(), ptr, buf.len() as u64, false)?;
    // SAFETY: the range was validated to lie wholly in user-readable tracked
    // mappings of the caller's active address space, so this bounded copy
    // cannot fault (D22 up-front validation stands in for a fault-capable
    // copy helper).
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), buf.len()) };
    Ok(())
}

/// Writes `buf` into the caller's user memory at `ptr`, after validating the
/// whole range lies in user-writable mappings. The kernel→user twin of
/// [`read_user`].
pub fn write_user<A: AddressSpaceOps>(
    process: &Process<A>,
    ptr: u64,
    buf: &[u8],
) -> Result<(), KError> {
    validate_user_range(process.space(), ptr, buf.len() as u64, true)?;
    // SAFETY: the range was validated to lie wholly in user-writable tracked
    // mappings of the caller's active address space, so this bounded copy
    // cannot fault (D22 up-front validation stands in for a fault-capable
    // copy helper).
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), ptr as *mut u8, buf.len()) };
    Ok(())
}

/// `sys_handle_duplicate`: duplicate `source` in the process handle table with
/// `new_rights` (which must be a subset — the kernel narrows, never expands).
/// Returns the raw new handle value.
pub fn sys_handle_duplicate<A: AddressSpaceOps>(
    process: &mut Process<A>,
    objects: &mut ObjectTable,
    source: Handle,
    new_rights: Rights,
) -> Result<u64, KError> {
    let new = process
        .handles_mut()
        .duplicate(objects, source, new_rights)?;
    Ok(new.raw() as u64)
}

/// `sys_handle_query_rights`: the rights mask a handle carries (the B2 query).
pub fn sys_handle_query_rights<A: AddressSpaceOps>(
    process: &Process<A>,
    handle: Handle,
) -> Result<u64, KError> {
    Ok(process.handles().rights(handle)?.bits())
}

/// `sys_handle_close`: close a handle. Returns 1 if the object was destroyed.
pub fn sys_handle_close<A: AddressSpaceOps>(
    process: &mut Process<A>,
    objects: &mut ObjectTable,
    handle: Handle,
) -> Result<u64, KError> {
    let destroyed = process.handles_mut().close(objects, handle)?;
    Ok(destroyed as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectId, ObjectTable, ObjectType};
    use crate::vm::{AddressSpace, Asid};
    use tessera_karch::PageFlags;
    use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

    fn user_space_with_mapping(
        base: u64,
        len: u64,
        flags: PageFlags,
    ) -> AddressSpace<MockAddressSpace> {
        let mut frames = MockFrameSource::new(0x40_0000, 128);
        let mut space =
            AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
                .expect("space");
        space
            .map_anonymous(VirtAddr::new(base), len, flags, &mut frames)
            .expect("map");
        space
    }

    fn process_with_handle(
        rights: Rights,
    ) -> (Process<MockAddressSpace>, ObjectTable, Handle, ObjectId) {
        let mut frames = MockFrameSource::new(0x80_0000, 64);
        let space =
            AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(2))
                .expect("space");
        let mut process = Process::new(ObjectId::from_raw(1), space);
        let mut objects = ObjectTable::new();
        let object = objects.create(ObjectType::Channel).expect("create");
        let handle = process
            .handles_mut()
            .insert(object, rights)
            .expect("insert");
        (process, objects, handle, object)
    }

    // --- error-domain encoding ---

    #[test]
    fn encodes_success_and_error_domains() {
        assert_eq!(encode_result(Ok(0)), 0);
        assert_eq!(encode_result(Ok(0x1234)), 0x1234);
        // AccessDenied -> security-policy domain (2), code 8.
        assert_eq!(
            encode_result(Err(KError::AccessDenied)),
            -(((ErrorDomain::SecurityPolicy as i64) << 16) | 8)
        );
        // Protocol -> protocol domain (4), code 10.
        assert_eq!(
            encode_result(Err(KError::Protocol)),
            -(((ErrorDomain::Protocol as i64) << 16) | 10)
        );
        // Errors are always negative, successes never.
        assert!(encode_result(Err(KError::OutOfMemory)) < 0);
        assert!(encode_result(Ok(u32::MAX as u64)) >= 0);
    }

    // --- user-range validation ---

    #[test]
    fn validates_user_range() {
        const BASE: u64 = 0x0000_0010_0000_0000;
        let space = user_space_with_mapping(BASE, FRAME_SIZE, PageFlags::rw().user());
        // Fully inside, read and write.
        assert!(validate_user_range(&space, BASE, 16, false).is_ok());
        assert!(validate_user_range(&space, BASE, 16, true).is_ok());
        // Zero length is trivially valid.
        assert!(validate_user_range(&space, BASE, 0, false).is_ok());
        // Unmapped just past the page.
        assert_eq!(
            validate_user_range(&space, BASE + FRAME_SIZE, 8, false),
            Err(KError::AccessDenied)
        );
        // A kernel address is never valid.
        assert_eq!(
            validate_user_range(&space, 0xffff_8000_0000_0000, 8, false),
            Err(KError::AccessDenied)
        );
    }

    #[test]
    fn read_only_user_range_rejects_write() {
        const BASE: u64 = 0x0000_0020_0000_0000;
        let space = user_space_with_mapping(BASE, FRAME_SIZE, PageFlags::ro().user());
        assert!(validate_user_range(&space, BASE, 16, false).is_ok());
        assert_eq!(
            validate_user_range(&space, BASE, 16, true),
            Err(KError::AccessDenied)
        );
    }

    #[test]
    fn user_range_rejects_kernel_only_mapping() {
        const BASE: u64 = 0x0000_0030_0000_0000;
        // A global (kernel) mapping is not user-accessible.
        let space = user_space_with_mapping(BASE, FRAME_SIZE, PageFlags::rw().global());
        assert_eq!(
            validate_user_range(&space, BASE, 16, false),
            Err(KError::AccessDenied)
        );
    }

    // --- @abi arg decode: validate before interpret ---

    fn duplicate_args(
        size: u32,
        version: u32,
        flags: u64,
        source: u32,
        reserved: u32,
        rights: u64,
    ) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&size.to_le_bytes());
        b[4..8].copy_from_slice(&version.to_le_bytes());
        b[8..16].copy_from_slice(&flags.to_le_bytes());
        b[16..20].copy_from_slice(&source.to_le_bytes());
        b[20..24].copy_from_slice(&reserved.to_le_bytes());
        b[24..32].copy_from_slice(&rights.to_le_bytes());
        b
    }

    #[test]
    fn decodes_valid_duplicate_args() {
        let bytes = duplicate_args(32, 1, 0, 0x0005, 0, Rights::READ.bits());
        let (handle, rights) = decode_duplicate_args(&bytes).expect("decode");
        assert_eq!(handle.raw(), 0x0005);
        assert_eq!(rights, Rights::READ);
    }

    #[test]
    fn rejects_malformed_duplicate_args() {
        // Too short.
        assert_eq!(decode_duplicate_args(&[0u8; 8]), Err(KError::Protocol));
        // Wrong size field.
        assert_eq!(
            decode_duplicate_args(&duplicate_args(31, 1, 0, 0, 0, 0)),
            Err(KError::Protocol)
        );
        // Wrong version.
        assert_eq!(
            decode_duplicate_args(&duplicate_args(32, 2, 0, 0, 0, 0)),
            Err(KError::Protocol)
        );
        // Nonzero flags.
        assert_eq!(
            decode_duplicate_args(&duplicate_args(32, 1, 1, 0, 0, 0)),
            Err(KError::Protocol)
        );
        // Nonzero reserved padding.
        assert_eq!(
            decode_duplicate_args(&duplicate_args(32, 1, 0, 0, 0xdead, 0)),
            Err(KError::Protocol)
        );
    }

    // --- process-lifecycle @abi arg decode (M14) ---

    #[test]
    fn decodes_process_create_args() {
        let mut b = [0u8; PROCESS_CREATE_ARGS_SIZE];
        b[0..4].copy_from_slice(&(PROCESS_CREATE_ARGS_SIZE as u32).to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[16..20].copy_from_slice(&0x0007u32.to_le_bytes()); // job handle
        assert_eq!(
            decode_process_create_args(&b).expect("decode").raw(),
            0x0007
        );
        // Too short / bad header.
        assert_eq!(decode_process_create_args(&[0u8; 8]), Err(KError::Protocol));
        b[4] = 2; // version = 2
        assert_eq!(decode_process_create_args(&b), Err(KError::Protocol));
    }

    #[test]
    fn decodes_address_space_map_args() {
        let mut b = [0u8; ADDRESS_SPACE_MAP_ARGS_SIZE];
        b[0..4].copy_from_slice(&(ADDRESS_SPACE_MAP_ARGS_SIZE as u32).to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[16..20].copy_from_slice(&0x0003u32.to_le_bytes()); // process handle
        b[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes()); // vaddr
        b[32..40].copy_from_slice(&0x1000u64.to_le_bytes()); // length
        b[40..48].copy_from_slice(&(Rights::READ.bits() | Rights::EXECUTE.bits()).to_le_bytes());
        b[48..56].copy_from_slice(&0x1000_2000u64.to_le_bytes()); // src
        let req = decode_address_space_map_args(&b).expect("decode");
        assert_eq!(req.process.raw(), 0x0003);
        assert_eq!(req.vaddr, 0x40_0000);
        assert_eq!(req.length, 0x1000);
        assert_eq!(req.rights, Rights::READ | Rights::EXECUTE);
        assert_eq!(req.src, 0x1000_2000);
        // Nonzero reserved padding is rejected.
        b[20] = 1;
        assert_eq!(decode_address_space_map_args(&b), Err(KError::Protocol));
    }

    #[test]
    fn decodes_process_start_args() {
        let mut b = [0u8; PROCESS_START_ARGS_SIZE];
        b[0..4].copy_from_slice(&(PROCESS_START_ARGS_SIZE as u32).to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[16..20].copy_from_slice(&0x0003u32.to_le_bytes()); // process handle
        b[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes()); // entry
        b[32..40].copy_from_slice(&0x7000_0000u64.to_le_bytes()); // stack
        b[40..48].copy_from_slice(&0x2au64.to_le_bytes()); // arg
        let req = decode_process_start_args(&b).expect("decode");
        assert_eq!(req.process.raw(), 0x0003);
        assert_eq!(req.entry, 0x40_0000);
        assert_eq!(req.stack, 0x7000_0000);
        assert_eq!(req.arg, 0x2a);
        // Nonzero flags is rejected.
        b[8] = 1;
        assert_eq!(decode_process_start_args(&b), Err(KError::Protocol));
    }

    #[test]
    fn decodes_channel_create_args() {
        let mut b = [0u8; CHANNEL_CREATE_ARGS_SIZE];
        b[0..4].copy_from_slice(&(CHANNEL_CREATE_ARGS_SIZE as u32).to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[16..24].copy_from_slice(&(Rights::READ.bits() | Rights::WRITE.bits()).to_le_bytes());
        b[24..32].copy_from_slice(&Rights::READ.bits().to_le_bytes());
        let (e0, e1) = decode_channel_create_args(&b).expect("decode");
        assert_eq!(e0, Rights::READ | Rights::WRITE);
        assert_eq!(e1, Rights::READ);
        // Too short / bad version rejected.
        assert_eq!(decode_channel_create_args(&[0u8; 8]), Err(KError::Protocol));
        b[4] = 2;
        assert_eq!(decode_channel_create_args(&b), Err(KError::Protocol));
    }

    #[test]
    fn decodes_channel_msg_args() {
        let mut b = [0u8; CHANNEL_MSG_ARGS_SIZE];
        b[0..4].copy_from_slice(&(CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[16..24].copy_from_slice(&0xabcdu64.to_le_bytes()); // interface_id
        b[32..36].copy_from_slice(&7u32.to_le_bytes()); // method_id
        b[36..40].copy_from_slice(&0u32.to_le_bytes()); // msg_flags
        b[40..48].copy_from_slice(&0x40_0000u64.to_le_bytes()); // inline_ptr
        b[48..56].copy_from_slice(&4u64.to_le_bytes()); // inline_len
        b[56..64].copy_from_slice(&0x68_0000u64.to_le_bytes()); // handles_ptr
        b[64..72].copy_from_slice(&1u64.to_le_bytes()); // handle_count
        let req = decode_channel_msg_args(&b).expect("decode");
        assert_eq!(req.interface_id, 0xabcd);
        assert_eq!(req.method_id, 7);
        assert_eq!(req.msg_flags, 0);
        assert_eq!(req.inline_ptr, 0x40_0000);
        assert_eq!(req.inline_len, 4);
        assert_eq!(req.handles_ptr, 0x68_0000);
        assert_eq!(req.handle_count, 1);
        // Too short / bad size / nonzero flags rejected.
        assert_eq!(decode_channel_msg_args(&[0u8; 8]), Err(KError::Protocol));
        b[0] = 0x49; // size = 73
        assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
        b[0] = 0x48;
        b[8] = 1; // nonzero flags
        assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
    }

    // --- device @abi arg decode (D79) ---

    fn device_args(size: u32, version: u32, flags: u64, handle: u32, vaddr: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&size.to_le_bytes());
        b[4..8].copy_from_slice(&version.to_le_bytes());
        b[8..16].copy_from_slice(&flags.to_le_bytes());
        b[16..20].copy_from_slice(&handle.to_le_bytes());
        b[24..32].copy_from_slice(&vaddr.to_le_bytes());
        b
    }

    #[test]
    fn decodes_map_device_args() {
        let b = device_args(32, 1, 0, 5, 0x0000_1000_0040_0000);
        let req = decode_map_device_args(&b).expect("decode");
        assert_eq!(req.device.raw(), 5);
        assert_eq!(req.vaddr, 0x0000_1000_0040_0000);
        // Too short / bad size / bad version / nonzero flags / nonzero reserved.
        assert_eq!(decode_map_device_args(&[0u8; 8]), Err(KError::Protocol));
        assert_eq!(
            decode_map_device_args(&device_args(31, 1, 0, 5, 0)),
            Err(KError::Protocol)
        );
        assert_eq!(
            decode_map_device_args(&device_args(32, 2, 0, 5, 0)),
            Err(KError::Protocol)
        );
        assert_eq!(
            decode_map_device_args(&device_args(32, 1, 1, 5, 0)),
            Err(KError::Protocol)
        );
        let mut bad = device_args(32, 1, 0, 5, 0);
        bad[20] = 1; // nonzero reserved
        assert_eq!(decode_map_device_args(&bad), Err(KError::Protocol));
    }

    #[test]
    fn decodes_dma_alloc_args() {
        let b = device_args(32, 1, 0, 0, 0x0000_1000_0050_0000);
        let req = decode_dma_alloc_args(&b).expect("decode");
        assert_eq!(req.device.raw(), 0);
        assert_eq!(req.vaddr, 0x0000_1000_0050_0000);
        assert_eq!(decode_dma_alloc_args(&[0u8; 8]), Err(KError::Protocol));
        assert_eq!(
            decode_dma_alloc_args(&device_args(32, 2, 0, 0, 0)),
            Err(KError::Protocol)
        );
        let mut bad = device_args(32, 1, 0, 0, 0);
        bad[20] = 1; // nonzero reserved
        assert_eq!(decode_dma_alloc_args(&bad), Err(KError::Protocol));
    }

    #[test]
    fn decodes_irq_complete_args() {
        let mut b = [0u8; IRQ_COMPLETE_ARGS_SIZE];
        b[0..4].copy_from_slice(&(IRQ_COMPLETE_ARGS_SIZE as u32).to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[16..20].copy_from_slice(&0u32.to_le_bytes()); // device handle 0
        assert_eq!(decode_irq_complete_args(&b).expect("decode").raw(), 0);
        assert_eq!(decode_irq_complete_args(&[0u8; 8]), Err(KError::Protocol));
        b[4] = 2; // version = 2
        assert_eq!(decode_irq_complete_args(&b), Err(KError::Protocol));
        b[4] = 1;
        b[20] = 1; // nonzero reserved
        assert_eq!(decode_irq_complete_args(&b), Err(KError::Protocol));
    }

    // --- handle-op dispatch outcomes ---

    #[test]
    fn duplicate_narrows_and_rejects_expansion() {
        let (mut process, mut objects, handle, object) =
            process_with_handle(Rights::READ | Rights::WRITE | Rights::DUPLICATE);
        // Narrowing succeeds and adds a reference.
        let new_raw = sys_handle_duplicate(&mut process, &mut objects, handle, Rights::READ)
            .expect("duplicate");
        assert_eq!(objects.refcount(object), Some(2));
        // The new handle carries exactly the narrowed rights.
        let new = Handle::from_raw(new_raw as u32);
        assert_eq!(
            sys_handle_query_rights(&process, new).expect("query"),
            Rights::READ.bits()
        );
        // Expansion is rejected (AccessDenied), reference count unchanged.
        assert_eq!(
            sys_handle_duplicate(&mut process, &mut objects, handle, Rights::ADMIN),
            Err(KError::AccessDenied)
        );
        assert_eq!(objects.refcount(object), Some(2));
    }

    #[test]
    fn close_drops_reference_and_reports_destruction() {
        let (mut process, mut objects, handle, object) = process_with_handle(Rights::READ);
        // Only reference: closing destroys the object.
        assert_eq!(sys_handle_close(&mut process, &mut objects, handle), Ok(1));
        assert!(!objects.is_live(object));
        // A stale handle no longer resolves.
        assert_eq!(
            sys_handle_query_rights(&process, handle),
            Err(KError::BadHandle)
        );
    }
}
