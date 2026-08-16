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

use crate::dispatch::HANDLE_NOT_INSTALLED;
use crate::handle::Handle;
use crate::isl_binding::channel::{
    ChannelCreateArgs, ChannelMsgArgs, HandleTransfer, TransferMode,
};
use crate::isl_binding::device::{
    DeviceBusKind, DeviceChildArgs, DeviceChildRecord, DeviceDeclareArgs, DeviceDeclareRecord,
    DeviceInfoArgs, DeviceInfoKind, DeviceInfoRecord, DmaAllocArgs, IrqCompleteArgs, MapConfigArgs,
    MapDeviceArgs, SystemSuspendArgs, SystemSuspendRecord, WakeHoldArgs, WakeHoldOp,
    WakeHoldRecord, WakeSourceArgs,
};
use crate::isl_binding::firmware::{FirmwareLoadArgs, FirmwareRefusal, FirmwareReport};
use crate::isl_binding::handle::DuplicateArgs;
use crate::isl_binding::memory::{
    DmaAttachArgs, DmaDetachArgs, DmaRenewArgs, MapRights, MemoryClass, MemoryClassifyArgs,
    MemoryConstraint, MemoryCreateArgs, MemoryMapArgs,
};
use crate::isl_binding::port::PortEventRecord;
use crate::isl_binding::process::{AddressSpaceMapArgs, ProcessCreateArgs, ProcessStartArgs};
use crate::object::ObjectTable;
use crate::process::Process;
use crate::rights::Rights;
use crate::vm::AddressSpace;
use tessera_isl_runtime::{Reader, WireDecode};
use tessera_karch::{AddressSpaceOps, FRAME_SIZE, KError, PageFlags, VirtAddr};

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
    /// Ask what a device is, for a device the caller holds a capability to:
    /// `arg0` = pointer to a `DeviceInfoArgs` struct. The kernel writes a
    /// `DeviceInfoRecord` to the struct's `record_ptr`. Grants nothing — the
    /// answer is about a capability the caller can already name (D114).
    DeviceInfo = 28,
    /// Record a driver-lifecycle transition for a device the caller holds:
    /// `arg0` = pointer to a `LifecycleTransitionArgs` struct. The device
    /// handle must carry `Rights::MAP` — the authority that distinguishes the
    /// process responsible for a device from any process that has heard of it.
    ///
    /// The kernel validates the transition against the table of legal edges
    /// and against the state it has already recorded, then emits
    /// `DRIVER_LIFECYCLE_TRANSITION`. It does not model the lifecycle — that
    /// is the device manager's — but it will not record a history that
    /// contradicts itself (build/README.md, D128; closes D112's deferral of a
    /// ring-3 emit path).
    DriverLifecycle = 29,
    /// Create a memory object: `arg0` = pointer to a `MemoryCreateArgs`
    /// struct. Returns a handle to `ObjectType::Memory` backed by zeroed
    /// anonymous pages. The out-of-line buffer primitive
    /// (build/README.md, D131).
    MemoryCreate = 30,
    /// Map a memory object the caller holds into its own address space:
    /// `arg0` = pointer to a `MemoryMapArgs` struct. Requires `Rights::MAP`.
    /// Returns the mapped base VA.
    MemoryMap = 31,
    /// Make a memory object the caller holds reachable by a device it holds:
    /// `arg0` = pointer to a `DmaAttachArgs` struct. Requires `Rights::MAP` on
    /// both. Returns the address the device uses.
    DmaAttach = 32,
    /// Stop a device reaching a memory object: `arg0` = pointer to a
    /// `DmaDetachArgs` struct. Returns 0.
    DmaDetach = 33,
    /// Say a DMA lease is still wanted, and until when: `arg0` = pointer to a
    /// `DmaRenewArgs` struct. Requires `Rights::MAP`. Returns 0.
    DmaRenew = 34,
    /// Ask a bus controller's capability for one of the devices behind it:
    /// `arg0` = pointer to a `DeviceChildArgs` struct. Requires `Rights::DERIVE`
    /// on the parent. Installs a capability to the child and returns 0.
    DeviceChild = 35,
    /// Arm or disarm a device's interrupt as a system wakeup source: `arg0` =
    /// pointer to a `WakeSourceArgs` struct. Requires `Rights::WAKE` on the
    /// device. Returns 0.
    WakeSource = 36,
    /// Take or release a wake hold, or read the system wake-event counter:
    /// `arg0` = pointer to a `WakeHoldArgs` struct. Requires `Rights::WAKE` on
    /// the power object. Returns 0 and writes a `WakeHoldRecord`.
    WakeHold = 37,
    /// Commit the system to sleep and return when it resumes: `arg0` = pointer
    /// to a `SystemSuspendArgs` struct. Requires `Rights::SLEEP`. Returns 0 and
    /// writes a `SystemSuspendRecord`.
    SystemSuspend = 38,
    /// Verify a named firmware image from the system store, admit it against
    /// policy, and return it as a memory object: `arg0` = pointer to a
    /// `FirmwareLoadArgs` struct. Requires `Rights::FIRMWARE` on the device the
    /// image is destined for. Returns the object's handle and writes a
    /// `FirmwareReport`; `KError::PolicyRefused` is the report's to explain.
    FirmwareLoad = 39,
    /// Put a memory object on a handling path: `arg0` = pointer to a
    /// `MemoryClassifyArgs` struct. Requires `Rights::WRITE` on the memory.
    /// The class may rise and never fall; a request that would lower it is
    /// `AccessDenied`.
    MemoryClassify = 40,
    /// A bus controller says a device exists: `arg0` = pointer to a
    /// `DeviceDeclareArgs`. Requires `Rights::DERIVE` on the bus, and the
    /// declared config slot and register window must lie inside what the bus
    /// covers and forwards. Installs a handle to the new device and writes a
    /// `DeviceDeclareRecord`.
    DeviceDeclare = 41,
    /// Map this function's own configuration space: `arg0` = pointer to a
    /// `MapConfigArgs`. Requires `Rights::CONFIGURE` on the device. Maps
    /// exactly the slot recorded when the device was declared, so a driver
    /// holding one function cannot reach the next one.
    MapConfig = 42,
    /// Receive on **any** of several endpoints: `arg0` = pointer to a
    /// `ChannelMsgArgs` whose `handles_ptr`/`handle_count` name the endpoint
    /// handles to wait on, `arg1` unused. Blocks until one of them has a
    /// message, and writes the index of the endpoint that answered back into
    /// the args' `msg_flags` so the server knows where to reply.
    ///
    /// **What a server with more than one client needs.** A blocking receive
    /// on one endpoint commits a server to that client until it speaks; a
    /// server holding two would serve whichever spoke first and never hear the
    /// other. Polling them instead is not an answer in a system whose
    /// scheduler is cooperative: a server that never blocks is a server no
    /// other thread runs behind.
    ChannelRecvAny = 43,
    /// Raise a software edge on a port: `arg0` = a port handle carrying
    /// `Rights::SIGNAL`, `arg1` = the source to raise. Delivers one edge to
    /// **that** port, on a source it is already bound to.
    ///
    /// **The first use of `Rights::SIGNAL`**, which has been in the catalog
    /// since it was written with nothing to gate. What it gates is the ability
    /// to wake somebody: a controller that multiplexes several lines onto one
    /// interrupt output has to say which line fired, and that is a fact only
    /// the driver holding the controller knows. Raising it is authority, so it
    /// is a right on a capability rather than a number anyone may pass.
    PortSignal = 44,
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
            28 => Self::DeviceInfo,
            29 => Self::DriverLifecycle,
            30 => Self::MemoryCreate,
            31 => Self::MemoryMap,
            32 => Self::DmaAttach,
            33 => Self::DmaDetach,
            34 => Self::DmaRenew,
            35 => Self::DeviceChild,
            36 => Self::WakeSource,
            37 => Self::WakeHold,
            38 => Self::SystemSuspend,
            39 => Self::FirmwareLoad,
            40 => Self::MemoryClassify,
            41 => Self::DeviceDeclare,
            42 => Self::MapConfig,
            43 => Self::ChannelRecvAny,
            44 => Self::PortSignal,
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
    /// Caller-buffer pointer the kernel writes the *installed* handle values
    /// to on a receive — the receive direction's counterpart to
    /// `handles_ptr`. Zero opts out, which is what every send-only caller
    /// passes.
    pub installed_ptr: u64,
    /// How many handle values `installed_ptr` has room for.
    pub installed_cap: u64,
}

/// Wire size of `ChannelMsgArgs` (`channel_msg.isl`).
pub const CHANNEL_MSG_ARGS_SIZE: usize = 88;

/// Byte offset of `ChannelMsgArgs.method_id`.
///
/// The receive direction writes the arrived message's method back here, so a
/// server can dispatch. Named as a constant with the wire size beside it
/// because it is the one field the kernel writes *in place* in a caller's
/// descriptor, and a wrong offset would silently corrupt the neighbouring
/// pointer rather than fail to compile.
pub const CHANNEL_MSG_METHOD_ID_OFFSET: u64 = 32;
/// Offset of `msg_flags`, which a `ChannelRecvAny` writes the index of the
/// answering endpoint into — the one thing a server that waited on several
/// cannot work out from the message itself.
pub const CHANNEL_MSG_FLAGS_OFFSET: u64 = 36;

/// Decodes a `ChannelMsgArgs`: validates the size/version/flags header before
/// interpreting the header fields and the inline/handle-vector descriptors.
/// `txn_id` is stamped by the kernel on a call, so it is not surfaced. Layout
/// (LE): size:u32, version:u32, flags:u64, interface_id:u64, txn_id:u64,
/// method_id:u32, msg_flags:u32, inline_ptr:u64, inline_len:u64, handles_ptr:u64,
/// handle_count:u64.
pub fn decode_channel_msg_args(bytes: &[u8]) -> Result<ChannelMsgRequest, KError> {
    let args = ChannelMsgArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    // Version 2 added the installed-handle report; version 3 made the outgoing
    // handle vector a `HandleTransfer` descriptor carrying the rights each
    // capability is to arrive with; version 4 gave each descriptor a
    // `TransferMode` (api/isl/examples/channel_msg.isl).
    //
    // **This check is what stands between a stale producer and a misparse.** A
    // version-1 producer describes a shorter struct and is caught by `size`
    // alone, but versions 2, 3 and 4 are the *same 88 bytes* — only the vector
    // `handles_ptr` addresses differs. Accepting a v2 descriptor would read a
    // vector of bare `u32` handle values as 16-byte entries, putting a handle
    // number where a rights mask belongs. Refusing beats reinterpreting.
    //
    // Version 3 is refused even though a v3 descriptor is byte-identical to a
    // v4 one requesting `TRANSFER`, because "identical today" is a property of
    // this kernel's mode set rather than of the format: the moment a third
    // mode exists, a v3 producer's zero would mean whichever mode happened to
    // be numbered zero. The gate is what keeps that from being a silent
    // reinterpretation later.
    if args.size != CHANNEL_MSG_ARGS_SIZE as u32 || args.version != 4 || args.flags != 0 {
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
        installed_ptr: args.installed_ptr,
        installed_cap: args.installed_cap,
    })
}

/// Wire size of one `HandleTransfer` descriptor (`channel_msg.isl`) — an entry
/// in the outgoing transfer vector `handles_ptr` addresses.
pub const HANDLE_TRANSFER_SIZE: usize = 16;

/// A decoded `HandleTransfer` — a handle to move and the rights it is to
/// arrive with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HandleTransferRequest {
    /// The sender's handle to move out of its table.
    pub handle: u32,
    /// The rights the capability arrives with. Must be a subset of what the
    /// sender holds; enforced by `HandleTable::take_narrowed`, not here.
    pub rights: Rights,
}

/// Decodes one `HandleTransfer`. Layout (LE): handle:u32, mode:u32, rights:u64.
///
/// A mode this kernel does not implement is refused **here**, before the
/// handle leaves the sender's table, because `take_narrowed` is not undoable:
/// discovering the mode was unsupported afterwards would leave the capability
/// belonging to nobody. So the only mode that reaches the caller is the one
/// whose semantics the caller then goes on to implement.
///
/// `SHARE` is `NotSupported` rather than `Protocol`: the sender described a
/// message this ABI defines and this kernel has not built, which is a
/// different fact from a malformed descriptor and leads to a different fix.
pub fn decode_handle_transfer(bytes: &[u8]) -> Result<HandleTransferRequest, KError> {
    let descriptor =
        HandleTransfer::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    match descriptor.mode {
        TransferMode::Transfer => {}
        // Sharing needs both holders' references counted, and three of the
        // five ports have no object table to count in (`build/README.md`,
        // D131). Refusing is the honest answer until they do.
        _ => return Err(KError::NotSupported),
    }
    Ok(HandleTransferRequest {
        handle: descriptor.handle,
        rights: Rights::from_bits(descriptor.rights),
    })
}

/// Wire size of `DmaAttachArgs` (`memory_abi.isl`).
pub const DMA_ATTACH_ARGS_SIZE: usize = 24;
/// Wire size of `DmaDetachArgs` (`memory_abi.isl`).
pub const DMA_DETACH_ARGS_SIZE: usize = 24;

/// A decoded `DmaAttachArgs`: which device is to reach which object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DmaAttachRequest {
    pub device: Handle,
    pub memory: Handle,
}

/// Decodes a `DmaAttachArgs`.
pub fn decode_dma_attach_args(bytes: &[u8]) -> Result<DmaAttachRequest, KError> {
    let args = DmaAttachArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != DMA_ATTACH_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok(DmaAttachRequest {
        device: Handle::from_raw(args.device.index()),
        memory: Handle::from_raw(args.memory.index()),
    })
}

/// Decodes a `DmaDetachArgs`, returning the memory handle.
pub fn decode_dma_detach_args(bytes: &[u8]) -> Result<Handle, KError> {
    let args = DmaDetachArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != DMA_DETACH_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(Handle::from_raw(args.memory.index()))
}

/// Wire size of `DmaRenewArgs` (`memory_abi.isl`).
pub const DMA_RENEW_ARGS_SIZE: usize = 32;

/// A decoded `DmaRenewArgs`: which lease, and how long it is still wanted for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DmaRenewRequest {
    pub device: Handle,
    /// The tick after which the lease is no longer held, or `None` for a lease
    /// that does not expire. Zero on the wire means `None`.
    pub expires_at: Option<u64>,
}

/// Decodes a `DmaRenewArgs`.
pub fn decode_dma_renew_args(bytes: &[u8]) -> Result<DmaRenewRequest, KError> {
    let args = DmaRenewArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != DMA_RENEW_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(DmaRenewRequest {
        device: Handle::from_raw(args.device.index()),
        expires_at: (args.ticks != 0).then_some(args.ticks),
    })
}

/// Wire size of `MemoryCreateArgs` (`memory_abi.isl`).
pub const MEMORY_CREATE_ARGS_SIZE: usize = 48;
/// Wire size of `MemoryMapArgs` (`memory_abi.isl`).
pub const MEMORY_MAP_ARGS_SIZE: usize = 32;

/// A decoded `MemoryCreateArgs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryCreateRequest {
    /// The requested length in bytes, before rounding up to whole pages.
    pub bytes: u64,
    /// Where the object has to be, if anywhere.
    pub placement: crate::memory::Placement,
}

/// Decodes a `MemoryCreateArgs`, validating the header before interpreting the
/// length and the placement constraints.
///
/// An alignment that is not a power of two is a **protocol error** rather than
/// a constraint to round: it is a request nothing can satisfy exactly, and the
/// only alternatives to refusing are to weaken it or to loop forever looking
/// for an address that cannot exist.
pub fn decode_memory_create_args(bytes: &[u8]) -> Result<MemoryCreateRequest, KError> {
    let args = MemoryCreateArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != MEMORY_CREATE_ARGS_SIZE as u32 || args.version != 2 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    if args.alignment != 0 && !args.alignment.is_power_of_two() {
        return Err(KError::Protocol);
    }
    Ok(MemoryCreateRequest {
        bytes: args.bytes,
        placement: crate::memory::Placement {
            device_contiguous: args.constraints.0 & MemoryConstraint::DEVICE_CONTIGUOUS.bits() != 0,
            physically_contiguous: args.constraints.0
                & MemoryConstraint::PHYSICALLY_CONTIGUOUS.bits()
                != 0,
            alignment: args.alignment,
            address_limit: args.address_limit,
        },
    })
}

/// A decoded `MemoryMapArgs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryMapRequest {
    pub memory: Handle,
    /// The rights the **mapping** is to carry, which are separate from the
    /// object's ownership rights (`docs/kernel/02`, "Memory Objects").
    pub rights: PageFlags,
    pub vaddr: u64,
}

/// Decodes a `MemoryMapArgs`, validating the header and translating the
/// requested mapping rights into page flags.
///
/// A request naming no rights at all is refused: a mapping nobody may read is
/// address space consumed for nothing, and accepting it would make a caller's
/// mistake look like a working call.
pub fn decode_memory_map_args(bytes: &[u8]) -> Result<MemoryMapRequest, KError> {
    let args = MemoryMapArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != MEMORY_MAP_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    let bits = args.rights.bits();
    let known = MapRights::READ.bits() | MapRights::WRITE.bits() | MapRights::EXECUTE.bits();
    if bits == 0 || bits & !known != 0 {
        return Err(KError::Protocol);
    }
    // Every mapping a memory object gets is user-accessible; a kernel-only
    // mapping of a capability ring 3 holds would be a mapping nobody asked for.
    let mut rights = PageFlags::none().user();
    if bits & MapRights::READ.bits() != 0 {
        rights = rights.read();
    }
    if bits & MapRights::WRITE.bits() != 0 {
        rights = rights.write();
    }
    if bits & MapRights::EXECUTE.bits() != 0 {
        rights = rights.execute();
    }
    if rights.is_wx() {
        return Err(KError::WXViolation);
    }
    Ok(MemoryMapRequest {
        memory: Handle::from_raw(args.memory.index()),
        rights,
        vaddr: args.vaddr,
    })
}

/// Wire size of `LifecycleTransitionArgs` (`driver_lifecycle.isl`).
pub const LIFECYCLE_TRANSITION_ARGS_SIZE: usize = 40;

/// A decoded `LifecycleTransitionArgs` — a manager declaring that a device it
/// holds moved between lifecycle states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LifecycleTransitionRequest {
    /// Handle to the device whose lifecycle this is.
    pub device: Handle,
    pub from: crate::lifecycle::DriverState,
    pub to: crate::lifecycle::DriverState,
    pub reason: crate::lifecycle::TransitionReason,
    /// Reason-specific and uninterpreted here: a probe's exit code, a crash's
    /// fault address, a restart's launch index.
    pub detail: u64,
}

/// Decodes a `LifecycleTransitionArgs`, validating the size/version/flags
/// header before interpreting the handle and the states.
///
/// The state and reason fields need no range check of their own: they are
/// `strict enum`s, so the generated decoder has already refused any value the
/// schema does not name. That is the point of the enums being ABI rather than
/// bare integers — an unknown state cannot arrive as a plausible one.
pub fn decode_lifecycle_transition_args(
    bytes: &[u8],
) -> Result<LifecycleTransitionRequest, KError> {
    let args =
        crate::isl_binding::lifecycle::LifecycleTransitionArgs::decode(&mut Reader::new(bytes))
            .map_err(|_| KError::Protocol)?;
    if args.size != LIFECYCLE_TRANSITION_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok(LifecycleTransitionRequest {
        device: Handle::from_raw(args.device.index()),
        from: args.from,
        to: args.to,
        reason: args.reason,
        detail: args.detail,
    })
}

/// Wire size of `DeviceInfoArgs` (`device_abi.isl`).
pub const DEVICE_INFO_ARGS_SIZE: usize = 32;

/// Wire size of `DeviceInfoRecord` (`device_abi.isl`), version 4.
pub const DEVICE_INFO_RECORD_SIZE: usize = 136;

/// A decoded `DeviceInfoArgs` — ask what a held device is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceInfoRequest {
    /// Handle to the device capability being asked about.
    pub device: Handle,
    /// Where to write the answer, in the caller's address space.
    pub record_ptr: u64,
}

/// Decodes a `DeviceInfoArgs`, validating the size/version/flags/reserved
/// header before interpreting the handle and destination pointer.
pub fn decode_device_info_args(bytes: &[u8]) -> Result<DeviceInfoRequest, KError> {
    let args = DeviceInfoArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != DEVICE_INFO_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(DeviceInfoRequest {
        device: Handle::from_raw(args.device.index()),
        record_ptr: args.record_ptr,
    })
}

/// Encodes a `DeviceInfoRecord` for write-back. `identity` is `None` when the
/// graph holds no normalized identity, which is reported as `UNKNOWN` rather
/// than as an error — the caller's documented response is to ask the device.
pub fn encode_device_info(
    identity: Option<crate::devmgr::DeviceIdentity>,
    layout: Option<crate::devmgr::DeviceLayout>,
    bus: Option<crate::devmgr::BusWindow>,
    config: bool,
) -> Result<[u8; DEVICE_INFO_RECORD_SIZE], KError> {
    // `layout_valid` is reported rather than inferred from zero offsets,
    // because offset zero is a legitimate place for a structure to be.
    let resolved = layout.unwrap_or_default();
    // Same rule for the bus window: a host bridge that forwards nothing is a
    // real answer, and a different one from a device that is not a bus.
    let window = bus.unwrap_or_default();
    let record = match identity {
        Some(id) => DeviceInfoRecord {
            size: DEVICE_INFO_RECORD_SIZE as u32,
            version: 4,
            flags: 0,
            kind: DeviceInfoKind::Pci,
            class_code: id.class_code,
            vendor: u32::from(id.vendor),
            device: u32::from(id.device),
            bdf: u32::from(id.bdf),
            revision: u32::from(id.revision),
            bus: match id.bus {
                crate::devmgr::DeviceBus::Pci => DeviceBusKind::Pci,
                crate::devmgr::DeviceBus::VirtioMmio => DeviceBusKind::VirtioMmio,
                crate::devmgr::DeviceBus::Platform => DeviceBusKind::Platform,
                crate::devmgr::DeviceBus::Unknown => DeviceBusKind::Unknown,
            },
            layout_valid: u32::from(layout.is_some()),
            common_offset: resolved.common,
            notify_offset: resolved.notify,
            notify_multiplier: resolved.notify_multiplier,
            isr_offset: resolved.isr,
            device_config_offset: resolved.device_config,
            reserved: 0,
            bus_valid: u32::from(bus.is_some()),
            config_len: window.config_len,
            forward_cpu_base: window.forward_cpu_base,
            forward_bus_base: window.forward_bus_base,
            forward_len: window.forward_len,
            first_bus: u32::from(window.first_bus),
            last_bus: u32::from(window.last_bus),
            first_intid: window.first_intid,
            intid_count: window.intid_count,
            config_valid: u32::from(config),
        },
        None => DeviceInfoRecord {
            size: DEVICE_INFO_RECORD_SIZE as u32,
            version: 4,
            flags: 0,
            kind: DeviceInfoKind::Unknown,
            class_code: 0,
            vendor: 0,
            device: 0,
            bdf: 0,
            revision: 0,
            bus: DeviceBusKind::Unknown,
            layout_valid: 0,
            common_offset: 0,
            notify_offset: 0,
            notify_multiplier: 0,
            isr_offset: 0,
            device_config_offset: 0,
            reserved: 0,
            bus_valid: u32::from(bus.is_some()),
            config_len: window.config_len,
            forward_cpu_base: window.forward_cpu_base,
            forward_bus_base: window.forward_bus_base,
            forward_len: window.forward_len,
            first_bus: u32::from(window.first_bus),
            last_bus: u32::from(window.last_bus),
            first_intid: window.first_intid,
            intid_count: window.intid_count,
            config_valid: u32::from(config),
        },
    };
    let mut out = [0u8; DEVICE_INFO_RECORD_SIZE];
    tessera_isl_runtime::encode(&record, &mut out).map_err(|_| KError::Protocol)?;
    Ok(out)
}

/// Wire size of `DeviceChildArgs` (`device_abi.isl`).
pub const DEVICE_CHILD_ARGS_SIZE: usize = 32;

/// Wire size of `DeviceChildRecord` (`device_abi.isl`).
pub const DEVICE_CHILD_RECORD_SIZE: usize = 32;

/// A decoded `DeviceChildArgs` — ask a bus for one of the devices behind it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceChildRequest {
    /// Handle to the parent's capability (must carry `Rights::DERIVE`).
    pub device: Handle,
    /// Which child, counting from zero.
    pub index: u32,
    /// Where to write the answer, in the caller's address space.
    pub record_ptr: u64,
}

/// Decodes a `DeviceChildArgs`, validating the header before interpreting the
/// handle, index and destination pointer.
pub fn decode_device_child_args(bytes: &[u8]) -> Result<DeviceChildRequest, KError> {
    let args = DeviceChildArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != DEVICE_CHILD_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok(DeviceChildRequest {
        device: Handle::from_raw(args.device.index()),
        index: args.index,
        record_ptr: args.record_ptr,
    })
}

/// Encodes a `DeviceChildRecord` for write-back.
///
/// `child` is `None` when no capability was installed — an index past the end
/// of a bus, which is an ordinary answer and not an error. It is reported as a
/// distinguished value rather than as zero, because zero is a legitimate handle
/// number and a caller that read it as failure would drop a real child.
pub fn encode_device_child(
    count: u32,
    child: Option<(u32, u64)>,
) -> Result<[u8; DEVICE_CHILD_RECORD_SIZE], KError> {
    let (handle, rights) = child.unwrap_or((HANDLE_NOT_INSTALLED, 0));
    let record = DeviceChildRecord {
        size: DEVICE_CHILD_RECORD_SIZE as u32,
        version: 1,
        flags: 0,
        count,
        child: handle,
        rights,
    };
    let mut out = [0u8; DEVICE_CHILD_RECORD_SIZE];
    tessera_isl_runtime::encode(&record, &mut out).map_err(|_| KError::Protocol)?;
    Ok(out)
}

/// Wire size of `DeviceDeclareArgs` (`device_abi.isl`), version 2.
pub const DEVICE_DECLARE_ARGS_SIZE: usize = 72;

/// Wire size of `DeviceDeclareRecord` (`device_abi.isl`).
pub const DEVICE_DECLARE_RECORD_SIZE: usize = 32;

/// A decoded `DeviceDeclareArgs` — a bus controller says a device exists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceDeclareRequest {
    /// Handle to the bus (must carry `Rights::DERIVE`).
    pub bus: Handle,
    /// The function's bus/device/function, which names its config slot.
    pub bdf: u16,
    /// Its register window, as the CPU addresses it.
    pub register_base: u64,
    pub register_len: u64,
    /// What the controller read out of configuration space.
    pub class_code: u32,
    pub vendor: u16,
    pub device: u16,
    pub revision: u8,
    /// Where to write the answer, in the caller's address space.
    pub record_ptr: u64,
    /// The line this device interrupts on, or zero for one with no wire —
    /// which is most of them, and a real answer rather than an absent field.
    pub intid: u32,
    /// How that line signals, where the description said so; zero for a
    /// description that did not.
    pub trigger: u32,
}

/// Decodes a `DeviceDeclareArgs`.
///
/// The identity fields are narrowed here rather than where they are used: a
/// vendor id is sixteen bits on every bus that has one, and a declaration
/// carrying more than fits is a caller disagreeing with the wire format about
/// what it is describing — which is a protocol error and not a value to
/// truncate into range.
pub fn decode_device_declare_args(bytes: &[u8]) -> Result<DeviceDeclareRequest, KError> {
    let args = DeviceDeclareArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != DEVICE_DECLARE_ARGS_SIZE as u32 || args.version != 2 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    let bdf = u16::try_from(args.bdf).map_err(|_| KError::Protocol)?;
    let vendor = u16::try_from(args.vendor).map_err(|_| KError::Protocol)?;
    let device = u16::try_from(args.device_id).map_err(|_| KError::Protocol)?;
    let revision = u8::try_from(args.revision).map_err(|_| KError::Protocol)?;
    Ok(DeviceDeclareRequest {
        bus: Handle::from_raw(args.bus.index()),
        bdf,
        register_base: args.register_base,
        register_len: args.register_len,
        class_code: args.class_code,
        vendor,
        device,
        revision,
        record_ptr: args.record_ptr,
        intid: args.intid,
        trigger: args.trigger,
    })
}

/// Encodes a `DeviceDeclareRecord` for write-back. `device` is `None` when the
/// caller's table had no room for the capability — reported as a distinguished
/// value rather than as zero, which is a legitimate handle number.
pub fn encode_device_declare(
    device: Option<(u32, u64)>,
) -> Result<[u8; DEVICE_DECLARE_RECORD_SIZE], KError> {
    let (handle, rights) = device.unwrap_or((HANDLE_NOT_INSTALLED, 0));
    let record = DeviceDeclareRecord {
        size: DEVICE_DECLARE_RECORD_SIZE as u32,
        version: 1,
        flags: 0,
        device: handle,
        rights,
    };
    let mut out = [0u8; DEVICE_DECLARE_RECORD_SIZE];
    tessera_isl_runtime::encode(&record, &mut out).map_err(|_| KError::Protocol)?;
    Ok(out)
}

/// Wire size of `MapConfigArgs` (`device_abi.isl`).
pub const MAP_CONFIG_ARGS_SIZE: usize = 32;

/// A decoded `MapConfigArgs` — map this function's own configuration space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MapConfigRequest {
    /// Handle to the device (must carry `Rights::CONFIGURE`).
    pub device: Handle,
    /// Where the caller wants it in its own address space.
    pub vaddr: u64,
}

/// Decodes a `MapConfigArgs`.
pub fn decode_map_config_args(bytes: &[u8]) -> Result<MapConfigRequest, KError> {
    let args = MapConfigArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != MAP_CONFIG_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(MapConfigRequest {
        device: Handle::from_raw(args.device.index()),
        vaddr: args.vaddr,
    })
}

/// Wire size of `WakeSourceArgs` (`device_abi.isl`).
pub const WAKE_SOURCE_ARGS_SIZE: usize = 32;

/// Wire size of `WakeHoldArgs` (`device_abi.isl`).
pub const WAKE_HOLD_ARGS_SIZE: usize = 40;

/// Wire size of `WakeHoldRecord` (`device_abi.isl`).
pub const WAKE_HOLD_RECORD_SIZE: usize = 40;

/// A decoded `WakeSourceArgs` — arm or disarm a device's interrupt as a system
/// wakeup source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WakeSourceRequest {
    /// Handle to the device (must carry `Rights::WAKE`).
    pub device: Handle,
    /// Whether to arm it.
    pub arm: bool,
}

/// Decodes a `WakeSourceArgs`.
pub fn decode_wake_source_args(bytes: &[u8]) -> Result<WakeSourceRequest, KError> {
    let args = WakeSourceArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != WAKE_SOURCE_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok(WakeSourceRequest {
        device: Handle::from_raw(args.device.index()),
        // Any non-zero value arms, so a caller that writes `1` and one that
        // writes `true`-as-anything agree. Zero is the only disarm, which is
        // the direction where being wrong is dangerous.
        arm: args.arm != 0,
    })
}

/// What a `WakeHold` call is asking for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WakeHoldOperation {
    Acquire,
    Release,
    Query,
}

/// A decoded `WakeHoldArgs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WakeHoldRequest {
    /// Handle to the power object (must carry `Rights::WAKE`).
    pub power: Handle,
    pub op: WakeHoldOperation,
    /// Lifetime in scheduler ticks; zero means until released.
    pub ticks: u64,
    /// Where to write the answer, in the caller's address space.
    pub record_ptr: u64,
}

/// Decodes a `WakeHoldArgs`.
pub fn decode_wake_hold_args(bytes: &[u8]) -> Result<WakeHoldRequest, KError> {
    let args = WakeHoldArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != WAKE_HOLD_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok(WakeHoldRequest {
        power: Handle::from_raw(args.power.index()),
        op: match args.op {
            WakeHoldOp::Acquire => WakeHoldOperation::Acquire,
            WakeHoldOp::Release => WakeHoldOperation::Release,
            WakeHoldOp::Query => WakeHoldOperation::Query,
        },
        ticks: args.ticks,
        record_ptr: args.record_ptr,
    })
}

/// Encodes a `WakeHoldRecord` for write-back.
pub fn encode_wake_hold(
    events: u64,
    held: u32,
    ticks: u64,
) -> Result<[u8; WAKE_HOLD_RECORD_SIZE], KError> {
    let record = WakeHoldRecord {
        size: WAKE_HOLD_RECORD_SIZE as u32,
        version: 1,
        flags: 0,
        events,
        held,
        reserved: 0,
        ticks,
    };
    let mut out = [0u8; WAKE_HOLD_RECORD_SIZE];
    tessera_isl_runtime::encode(&record, &mut out).map_err(|_| KError::Protocol)?;
    Ok(out)
}

/// Wire size of `SystemSuspendArgs` (`device_abi.isl`).
pub const SYSTEM_SUSPEND_ARGS_SIZE: usize = 40;

/// Wire size of `SystemSuspendRecord` (`device_abi.isl`).
pub const SYSTEM_SUSPEND_RECORD_SIZE: usize = 40;

/// A decoded `SystemSuspendArgs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SystemSuspendRequest {
    /// Handle to a capability carrying `Rights::SLEEP`.
    pub power: Handle,
    /// The wake-event counter as the caller last read it.
    pub snapshot: u64,
    /// Where to write the answer, in the caller's address space.
    pub record_ptr: u64,
}

/// Decodes a `SystemSuspendArgs`.
pub fn decode_system_suspend_args(bytes: &[u8]) -> Result<SystemSuspendRequest, KError> {
    let args = SystemSuspendArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != SYSTEM_SUSPEND_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok(SystemSuspendRequest {
        power: Handle::from_raw(args.power.index()),
        snapshot: args.snapshot,
        record_ptr: args.record_ptr,
    })
}

/// Encodes a `SystemSuspendRecord` for write-back.
pub fn encode_system_suspend(
    status: u32,
    events: u64,
    source: u64,
) -> Result<[u8; SYSTEM_SUSPEND_RECORD_SIZE], KError> {
    let record = SystemSuspendRecord {
        size: SYSTEM_SUSPEND_RECORD_SIZE as u32,
        version: 1,
        flags: 0,
        status,
        reserved: 0,
        events,
        source,
    };
    let mut out = [0u8; SYSTEM_SUSPEND_RECORD_SIZE];
    tessera_isl_runtime::encode(&record, &mut out).map_err(|_| KError::Protocol)?;
    Ok(out)
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
pub fn sys_handle_close<A: AddressSpaceOps, C: tessera_karch::ContextOps>(
    process: &mut Process<A>,
    objects: &mut ObjectTable,
    exec: &mut crate::exec::Executive<C>,
    iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    irqs: Option<&mut (dyn crate::devmgr::InterruptRouter + '_)>,
    handle: Handle,
) -> Result<u64, KError> {
    // The object is read before the close, because afterwards the handle names
    // nothing and there would be no way to ask what just left.
    let (object, _rights) = process.handles().lookup(handle)?;
    let destroyed = process.handles_mut().close(objects, handle)?;
    // A capability can leave a process by being closed just as well as by being
    // transferred, and none of a register window, a DMA lease, or an interrupt
    // route outlives it. Without this a process could drop its device
    // capability and keep driving the device — the same hole the transfer path
    // closes, reached by the other route.
    if process
        .revoke_device_windows_unless_held(object, crate::process::WindowRevokeReason::HandleClosed)
    {
        exec.end_device_lease(
            process.id(),
            object,
            crate::devmgr::LeaseEndReason::HandleClosed,
            iommu,
        );
        exec.end_device_irq_route(
            process.id(),
            object,
            crate::devmgr::RouteEndReason::HandleClosed,
            irqs,
        );
    }
    Ok(destroyed as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectId, ObjectTable, ObjectType};
    use crate::vm::{AddressSpace, Asid};
    use tessera_karch::{PageFlags, PhysAddr, PhysFrame};
    use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

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

    /// Closing the last handle to a device takes its register window with it.
    /// A capability can leave by being closed just as well as by being handed
    /// on, and the window outlives neither.
    #[test]
    fn closing_the_last_device_handle_revokes_its_window() {
        let (mut process, mut objects, handle, object) = process_with_handle(Rights::READ);
        let mut frames = MockFrameSource::new(0x90_0000, 64);
        let window = VirtAddr::new(0x2000_0000);
        let frame = PhysFrame::from_base(PhysAddr::new(0x0a00_3000)).expect("mmio frame");
        process
            .space_mut()
            .map_device_page(window, frame, &mut frames)
            .expect("map device");
        process
            .record_device_window(object, window.as_u64(), 1)
            .expect("record");
        assert!(process.space().arch().translate(window).is_some());

        let mut exec = crate::exec::Executive::<MockContextOps>::new(1, 0);
        sys_handle_close(&mut process, &mut objects, &mut exec, None, None, handle).expect("close");

        assert!(
            process.space().arch().translate(window).is_none(),
            "a process kept register access after dropping its capability"
        );
        assert_eq!(process.device_window_count(), 0);
    }

    /// ...but only when the last one goes. A duplicate still names the device,
    /// so the authority — and the window — remain.
    #[test]
    fn closing_one_of_two_device_handles_keeps_the_window() {
        let (mut process, mut objects, handle, object) =
            process_with_handle(Rights::READ | Rights::DUPLICATE);
        let mut frames = MockFrameSource::new(0x90_0000, 64);
        let window = VirtAddr::new(0x2000_0000);
        let frame = PhysFrame::from_base(PhysAddr::new(0x0a00_3000)).expect("mmio frame");
        process
            .space_mut()
            .map_device_page(window, frame, &mut frames)
            .expect("map device");
        process
            .record_device_window(object, window.as_u64(), 1)
            .expect("record");
        process
            .handles_mut()
            .install(object, Rights::READ)
            .expect("duplicate");

        let mut exec = crate::exec::Executive::<MockContextOps>::new(1, 0);
        sys_handle_close(&mut process, &mut objects, &mut exec, None, None, handle).expect("close");

        assert!(process.handles().holds(object));
        assert!(
            process.space().arch().translate(window).is_some(),
            "a process that still holds the capability lost its window"
        );
        assert_eq!(process.device_window_count(), 1);
    }

    /// Teardown needs no revocation of its own, and this pins the property it
    /// relies on: a device window is **untracked**, so the whole-space teardown
    /// — which walks only tracked mappings — cannot hand an MMIO frame to the
    /// frame allocator. Returning device registers to the pool the kernel
    /// serves anonymous memory from would be about the worst outcome available.
    #[test]
    fn teardown_never_returns_a_device_window_frame_to_the_allocator() {
        let mut frames = MockFrameSource::new(0x40_0000, 128);
        let mut space =
            AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(3))
                .expect("space");
        let window = VirtAddr::new(0x2000_0000);
        // Physical address well outside anything the allocator owns.
        let frame = PhysFrame::from_base(PhysAddr::new(0x0a00_3000)).expect("mmio frame");
        space
            .map_device_page(window, frame, &mut frames)
            .expect("map device");
        // The window is deliberately absent from the tracked mapping table.
        assert_eq!(space.mapping_count(), 0);

        let before = frames.free_list_depth();
        space.teardown(&mut frames);
        assert_eq!(
            frames.free_list_depth(),
            before,
            "teardown returned an MMIO frame to the allocator"
        );
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
        b[4..8].copy_from_slice(&4u32.to_le_bytes());
        b[16..24].copy_from_slice(&0xabcdu64.to_le_bytes()); // interface_id
        b[32..36].copy_from_slice(&7u32.to_le_bytes()); // method_id
        b[36..40].copy_from_slice(&0u32.to_le_bytes()); // msg_flags
        b[40..48].copy_from_slice(&0x40_0000u64.to_le_bytes()); // inline_ptr
        b[48..56].copy_from_slice(&4u64.to_le_bytes()); // inline_len
        b[56..64].copy_from_slice(&0x68_0000u64.to_le_bytes()); // handles_ptr
        b[64..72].copy_from_slice(&1u64.to_le_bytes()); // handle_count
        b[72..80].copy_from_slice(&0x70_0000u64.to_le_bytes()); // installed_ptr
        b[80..88].copy_from_slice(&2u64.to_le_bytes()); // installed_cap
        let req = decode_channel_msg_args(&b).expect("decode");
        assert_eq!(req.interface_id, 0xabcd);
        assert_eq!(req.method_id, 7);
        assert_eq!(req.msg_flags, 0);
        assert_eq!(req.inline_ptr, 0x40_0000);
        assert_eq!(req.inline_len, 4);
        assert_eq!(req.handles_ptr, 0x68_0000);
        assert_eq!(req.handle_count, 1);
        assert_eq!(req.installed_ptr, 0x70_0000);
        assert_eq!(req.installed_cap, 2);
        // Too short / bad size / nonzero flags rejected.
        assert_eq!(decode_channel_msg_args(&[0u8; 8]), Err(KError::Protocol));
        b[0] = 0x49; // size = 73
        assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
        b[0] = 0x48;
        b[8] = 1; // nonzero flags
        assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
        // A version-2 producer is the same 88 bytes and differs only in what
        // `handles_ptr` addresses, so nothing but this check tells the two
        // apart — accepting one would read bare u32 handle values as 16-byte
        // transfer descriptors.
        b[8] = 0;
        b[4] = 2;
        assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
        // Version 3 is refused too, even though every v3 descriptor is a
        // byte-identical v4 one today. What is identical is this kernel's mode
        // numbering, not the format — and a gate that opens once a version is
        // "compatible enough" is a gate that has to be re-argued every time
        // the mode set grows.
        b[4] = 3;
        assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
    }

    #[test]
    fn decodes_a_handle_transfer_descriptor() {
        let mut b = [0u8; HANDLE_TRANSFER_SIZE];
        b[0..4].copy_from_slice(&5u32.to_le_bytes()); // handle
        b[8..16].copy_from_slice(&(Rights::READ | Rights::MAP).bits().to_le_bytes());
        let d = decode_handle_transfer(&b).expect("decode");
        assert_eq!(d.handle, 5);
        assert_eq!(d.rights, Rights::READ | Rights::MAP);

        // The rights word is 64 bits wide, so the rights above bit 31 survive
        // the trip — a 32-bit field would have dropped them silently.
        b[8..16].copy_from_slice(&Rights::REVOKE.bits().to_le_bytes());
        assert_eq!(
            decode_handle_transfer(&b).expect("decode").rights,
            Rights::REVOKE
        );

        // Share is a mode the ABI defines and this kernel has not built, so
        // it is `NotSupported` — a different fact from a malformed descriptor,
        // and one that leads somewhere different.
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(decode_handle_transfer(&b), Err(KError::NotSupported));

        // A mode nobody has defined is a misparse, not a feature request.
        b[4..8].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(decode_handle_transfer(&b), Err(KError::Protocol));
        b[4..8].copy_from_slice(&0u32.to_le_bytes());

        // A short buffer is a protocol error, never a partial read.
        assert_eq!(decode_handle_transfer(&[0u8; 8]), Err(KError::Protocol));
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
        let mut exec = crate::exec::Executive::<MockContextOps>::new(1, 0);
        assert_eq!(
            sys_handle_close(&mut process, &mut objects, &mut exec, None, None, handle),
            Ok(1)
        );
        assert!(!objects.is_live(object));
        // A stale handle no longer resolves.
        assert_eq!(
            sys_handle_query_rights(&process, handle),
            Err(KError::BadHandle)
        );
    }
}

// ---------------------------------------------------------------------------
// FirmwareLoad — a verified image, admitted by policy (`firmware.isl`).
// ---------------------------------------------------------------------------

/// Wire size of `FirmwareLoadArgs` (`firmware.isl`), version 1.
pub const FIRMWARE_LOAD_ARGS_SIZE: usize = 64;

/// Wire size of `FirmwareReport` (`firmware.isl`), version 1.
pub const FIRMWARE_REPORT_SIZE: usize = 72;

/// The fixed width of a store entry name, mirrored from the container format so
/// a name that fits an entry fits a request. Widening one without the other
/// would truncate silently at the boundary between them.
pub const FIRMWARE_NAME_LEN: usize = 24;

/// A decoded `FirmwareLoadArgs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FirmwareLoadRequest {
    /// The device the image is destined for; `Rights::FIRMWARE` is required.
    pub device: Handle,
    /// What the caller requires of the image's version.
    pub min_image_version: u32,
    /// The store entry name, NUL-padded.
    pub name: [u8; FIRMWARE_NAME_LEN],
    /// Where to write the `FirmwareReport`.
    pub report_ptr: u64,
}

impl FirmwareLoadRequest {
    /// The requested name as a string, or `None` when it is not one.
    ///
    /// Validated here rather than at the store, so a name that could never
    /// match anything is a protocol error about the request instead of a
    /// missing image — two different things for whoever has to act on it.
    pub fn name_str(&self) -> Option<&str> {
        let len = self
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(FIRMWARE_NAME_LEN);
        if len == 0 || self.name[len..].iter().any(|byte| *byte != 0) {
            return None;
        }
        core::str::from_utf8(&self.name[..len]).ok()
    }
}

/// Decodes a `FirmwareLoadArgs`, validating the envelope before interpreting
/// the handle, the requirement and the destination pointer.
pub fn decode_firmware_load_args(bytes: &[u8]) -> Result<FirmwareLoadRequest, KError> {
    let args = FirmwareLoadArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != FIRMWARE_LOAD_ARGS_SIZE as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != 0
    {
        return Err(KError::Protocol);
    }
    Ok(FirmwareLoadRequest {
        device: Handle::from_raw(args.device.index()),
        min_image_version: args.min_image_version,
        name: args.name,
        report_ptr: args.report_ptr,
    })
}

/// Encodes a `FirmwareReport` for write-back.
///
/// Written on **both** paths, which is why every field is an argument rather
/// than being read back off a successful load: a refusal has a security version
/// to report — the number somebody has to compare against the floor — and a
/// report that only existed on success would leave that unsayable.
pub fn encode_firmware_report(
    refusal: FirmwareRefusal,
    svn: u32,
    image_version: u32,
    length: u64,
    digest: [u8; 32],
) -> Result<[u8; FIRMWARE_REPORT_SIZE], KError> {
    let record = FirmwareReport {
        size: FIRMWARE_REPORT_SIZE as u32,
        version: 1,
        flags: 0,
        refusal,
        svn,
        image_version,
        reserved: 0,
        length,
        digest,
    };
    let mut bytes = [0u8; FIRMWARE_REPORT_SIZE];
    let mut writer = tessera_isl_runtime::Writer::new(&mut bytes);
    tessera_isl_runtime::WireEncode::encode(&record, &mut writer).map_err(|_| KError::Protocol)?;
    Ok(bytes)
}

/// Wire size of `MemoryClassifyArgs` (`memory_abi.isl`), version 1.
pub const MEMORY_CLASSIFY_ARGS_SIZE: usize = 24;

/// A decoded `MemoryClassifyArgs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryClassifyRequest {
    pub memory: Handle,
    pub class: MemoryClass,
}

/// Decodes a `MemoryClassifyArgs`, validating the envelope first.
pub fn decode_memory_classify_args(bytes: &[u8]) -> Result<MemoryClassifyRequest, KError> {
    let args = MemoryClassifyArgs::decode(&mut Reader::new(bytes)).map_err(|_| KError::Protocol)?;
    if args.size != MEMORY_CLASSIFY_ARGS_SIZE as u32 || args.version != 1 || args.flags != 0 {
        return Err(KError::Protocol);
    }
    Ok(MemoryClassifyRequest {
        memory: Handle::from_raw(args.memory.index()),
        class: args.class,
    })
}
