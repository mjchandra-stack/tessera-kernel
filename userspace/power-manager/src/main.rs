// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **power and thermal manager**: the service that takes votes and
//! decides what a power domain is driven to.
//!
//! `docs/power/01-power-management.md` lists it in the service roster and
//! draws its boundary: the service owns policy — suspend and idle decisions,
//! vote arbitration across the power dependency graph, thermal mapping — and
//! the kernel owns the mechanisms whose decision rate cannot tolerate a
//! service round trip. This program is the policy half, and it is a program
//! rather than a table for the same reason the device manager is: the answer
//! depends on who is asking and on what else has asked, which is a
//! computation.
//!
//! **Almost none of the interesting logic is here.** The arbitration rule and
//! the vote table live in `//api/power`, host-tested against every ordered
//! pair of levels, a full table, a withdrawal of a vote nobody cast, and both
//! ceilings binding at once. What is here is the part that genuinely cannot be
//! tested on a host: the channel transport, the port select that says which
//! voter spoke, and the lifecycle transitions that make a resolution *happen*
//! to a device rather than merely be computed about one.
//!
//! # Two programs in one image
//!
//! The same ELF is both the manager and a voter, selected by the startup
//! argument, exactly as `blk-probe` multiplexes its modes. A voter is a couple
//! of dozen lines — encode a request, call, check the reply — and a separate
//! crate and linker script for that would be more build graph than program.
//! What makes the voters real rather than a loop inside the manager is that
//! each is its own **process** with its own endpoint capability, so the
//! manager's attribution of a vote to a voter is the kernel's rather than a
//! field anybody sent.
//!
//! # What a voter is identified by
//!
//! The endpoint the message arrived on. Not a field in the request: a body can
//! be forged by any sender, and a manager that trusted a `voter` field would
//! let one program withdraw another's vote. The same reasoning that makes
//! `driver_bind.isl` key a device's return on the transferred capability
//! rather than on a flag.
//!
//! Normative: docs/power/01-power-management.md,
//! docs/hardware/03-component-interaction-model.md ("Power Domains")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod suspend;
mod wake;

use channel_msg::ChannelMsgArgs;
use driver_lifecycle::{DriverState, LifecycleTransitionArgs, TransitionReason};
use port_event::PortEventRecord;
use power_manager::{PowerError, PowerLevel, PowerManager, PowerVoteReply, PowerVoteRequest};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_power::{PowerPolicy, Resolution, Vote, VoteTable, VoterClass};
use tessera_uabi::{fail, read_kernel_filled, syscall1, syscall2};

/// Syscall numbers — kcore `SyscallNumber` ordinals, the stable ABI.
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
pub(crate) const SYS_PORT_WAIT: u64 = 18;
/// **Continue**, not plain `ChannelReply`: a server that replies and loops
/// back to its own receive is Blocked without being a registered receiver, so
/// the *second* request deadlocks. This has bitten twice (D85, D91), and the
/// symptom both times was a hang after exactly one successful exchange.
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_DRIVER_LIFECYCLE: u64 = 29;

// --- The bootstrap contract -------------------------------------------------

/// Manager mode: the service port boot binds every voter endpoint to, so one
/// wait is a select that names which voter spoke.
const SERVICE_PORT_HANDLE: u64 = 0;
/// Manager mode: the first voter endpoint. Voter *n* sits at `1 + n`.
const FIRST_VOTER_HANDLE: u32 = 1;
/// Manager mode: the device a resolution is applied to.
///
/// Narrating a lifecycle needs `Rights::MAP` — deliberately, since D128: it is
/// the same authority `MapDevice` and `IrqComplete` require, so a process that
/// has merely heard of a device cannot tell its story. What bounds this
/// manager is therefore the *node* rather than the right: it is granted a
/// device with no register window, so there is nothing behind the capability
/// to reach.
const DEVICE_HANDLE: u32 = 4;

/// Voter mode: this voter's endpoint to the manager, its only capability.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;

/// Voters this manager serves.
const VOTERS: usize = 3;

/// Endpoint object ids boot binds to the service port, in voter order.
///
/// A port event names the *object* that was signalled, and a handle table is
/// per-process, so a server selecting over several endpoints has to hold the
/// mapping. Compiled in, like `device-host`'s: boot and this program agree on
/// the numbering, and the agreement is the bootstrap contract.
const VOTER_ENDPOINT_OBJECTS: [u64; VOTERS] = [70, 71, 72];

/// `kcore::ipc::SIGNAL_MESSAGE` — a message arrived on the named endpoint.
const SIGNAL_MESSAGE: u32 = 2;

/// The power domain this machine's block device belongs to
/// (`binding::ManifestEntry.power_domain`, delivered to a driver in its
/// `BindReply`). One domain today, because the machine has one device whose
/// power anybody votes on.
const BLOCK_DOMAIN: u32 = 1;

/// What this installation permits of a power domain.
///
/// Compiled in rather than read from a configuration service, because there is
/// no configuration service — the same honest interim the device manager's
/// manifest is. `allow_boost` is false: nothing on this machine implements a
/// boost state, and a policy permitting one nothing implements would be
/// describing a system that does not exist.
pub(crate) const POLICY: PowerPolicy = PowerPolicy {
    floor: tessera_power::PowerLevel::Off,
    ceiling: None,
    allow_boost: false,
};

/// The largest message this program sends or receives — `PowerVoteReply` is
/// 40 bytes and `PowerVoteRequest` 32, and the call buffer is symmetric.
const MSG_BUF_LEN: usize = 48;

// --- Mode selection ---------------------------------------------------------

/// Set in the startup argument to select voter mode. Clear means manager mode,
/// whose remaining bits are the number of requests to serve.
const VOTER_MODE: u64 = 1 << 63;

/// Set in the startup argument to select idle-and-wake mode: let an unused
/// domain fall out of service and wait for something to bring it back.
const WAKE_MODE: u64 = 1 << 62;

/// Set in the startup argument to select suspend mode: stop the whole machine,
/// leaves before parents, and bring it back.
const SUSPEND_MODE: u64 = 1 << 61;

const VOTER_LEVEL_SHIFT: u32 = 0;
const VOTER_CLASS_SHIFT: u32 = 8;
const VOTER_STEP_SHIFT: u32 = 16;
const VOTER_FIELD_MASK: u64 = 0xff;

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    syscall1(SYS_DEBUG_WRITE, value);
    syscall1(SYS_PROCESS_EXIT, 0);
    // The kernel does not return from ProcessExit; this exists so the
    // function's type is honest.
    loop {
        core::hint::spin_loop();
    }
}

/// Encodes a `ChannelMsgArgs` descriptor over the message buffer.
///
/// The symmetric call-buffer convention every protocol here uses: the inline
/// descriptor is the request source *and* the reply destination, so the buffer
/// must hold the larger of the two structs.
fn channel_args(
    buf_ptr: u64,
    buf_len: u64,
    method: u32,
) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: PowerManager::INTERFACE_ID,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: buf_len,
        handles_ptr: 0,
        handle_count: 0,
        // No capability travels in either direction, so no report is asked
        // for: a vote is a statement, and the thing it is about is already
        // held by whoever is voting.
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(1, 0xe)),
    }
}

/// The arrived message's method ordinal, which the kernel writes back into the
/// descriptor in place (`kcore::syscall::CHANNEL_MSG_METHOD_ID_OFFSET`).
///
/// Volatile, for the reason every kernel-filled read in these programs is: the
/// compiler has no idea a syscall wrote here and would otherwise reuse the
/// value this program encoded a moment ago.
fn read_method_id(args: &[u8; ChannelMsgArgs::WIRE_SIZE]) -> u32 {
    const AT: usize = 32;
    let mut bytes = [0u8; 4];
    for (i, byte) in bytes.iter_mut().enumerate() {
        // SAFETY: a bounds-checked byte of this program's own stack buffer;
        // volatile only forbids the compiler assuming the value it encoded is
        // still there.
        *byte = unsafe { core::ptr::read_volatile(&args[AT + i]) };
    }
    u32::from_le_bytes(bytes)
}

// --- The two vocabularies ---------------------------------------------------

/// The wire's level as the arbiter's.
///
/// Two enums for one concept, and deliberately so: the generated one is the
/// ABI and the crate's is `Ord`, because the arbitration rule *compares*
/// levels. Bolting an ordering onto generated code would put a load-bearing
/// property somewhere that is regenerated from a schema, and the schema's
/// conformance test pins the numbers precisely so this mapping cannot drift.
fn to_arbiter(level: PowerLevel) -> tessera_power::PowerLevel {
    match level {
        PowerLevel::Off => tessera_power::PowerLevel::Off,
        PowerLevel::Retention => tessera_power::PowerLevel::Retention,
        PowerLevel::LowPowerActive => tessera_power::PowerLevel::LowPowerActive,
        PowerLevel::FullActive => tessera_power::PowerLevel::FullActive,
        PowerLevel::PerformanceBoost => tessera_power::PowerLevel::PerformanceBoost,
    }
}

/// The arbiter's level as the wire's.
fn to_wire(level: tessera_power::PowerLevel) -> PowerLevel {
    match level {
        tessera_power::PowerLevel::Off => PowerLevel::Off,
        tessera_power::PowerLevel::Retention => PowerLevel::Retention,
        tessera_power::PowerLevel::LowPowerActive => PowerLevel::LowPowerActive,
        tessera_power::PowerLevel::FullActive => PowerLevel::FullActive,
        tessera_power::PowerLevel::PerformanceBoost => PowerLevel::PerformanceBoost,
    }
}

/// The wire's voter class as the arbiter's, refusing `POLICY`.
///
/// `POLICY` is the installation itself and never appears in a request — it
/// exists so that a clamp the installation applied has something to name. A
/// sender claiming it would be claiming to be the policy, which is refused
/// rather than quietly reinterpreted.
fn to_arbiter_class(class: power_manager::VoterClass) -> Option<VoterClass> {
    match class {
        power_manager::VoterClass::User => Some(VoterClass::User),
        power_manager::VoterClass::Service => Some(VoterClass::Service),
        power_manager::VoterClass::Driver => Some(VoterClass::Driver),
        power_manager::VoterClass::Thermal => Some(VoterClass::Thermal),
        power_manager::VoterClass::Policy => None,
    }
}

// --- Manager mode -----------------------------------------------------------

/// One resolution, packed for the report.
///
/// Every field of a `PowerVoteReply` a check can be wrong about, in one word:
/// what the domain resolved to, what was taken away and by whom, and who won.
/// Rotated per step so successive reports compose by XOR without cancelling —
/// the report sink's convention.
fn resolution_word(step: u32, reply: &PowerVoteReply) -> u64 {
    let packed = u64::from(reply.resolved as u32)
        | (u64::from(reply.clamped_from) << 8)
        | (u64::from(reply.clamped_by) << 16)
        | (u64::from(reply.winner) << 24)
        | (u64::from(reply.status) << 32);
    packed.rotate_left(8 * step)
}

/// What the manager itself reports when it stops: how many requests it served,
/// what the domain ended up at, and whether the device is in service.
fn manager_word(served: u32, last: tessera_power::PowerLevel, active: bool) -> u64 {
    (u64::from(served) | (u64::from(last.raw()) << 8) | (u64::from(active) << 16)).rotate_left(40)
}

/// Declares that the device moved from `from` to `to`, because power said so.
///
/// Answers whether the kernel accepted it. A refusal is never carried past:
/// the kernel holds the device's history and refuses a transition that
/// contradicts it, so a manager continuing as though a refused transition had
/// been recorded would keep a private state the rest of the system disagrees
/// with.
pub(crate) fn declare(handle: u32, from: DriverState, to: DriverState) -> bool {
    declare_raw(handle, from, to) >= 0
}

/// The same, answering the raw syscall result — for a caller that needs to
/// know *which* refusal it got rather than only that it was refused.
pub(crate) fn declare_raw(handle: u32, from: DriverState, to: DriverState) -> i64 {
    let args = LifecycleTransitionArgs {
        size: LifecycleTransitionArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        from,
        to,
        reason: TransitionReason::Power,
        detail: 0,
    };
    let mut buf = [0u8; LifecycleTransitionArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return i64::MIN;
    }
    syscall2(SYS_DRIVER_LIFECYCLE, buf.as_ptr() as u64, 0)
}

/// Drives the device to `level`, through the states a power transition is
/// defined to pass through.
///
/// **A suspend is a sequence, not a flag.** `Active -> Suspended` is not a
/// legal edge and the kernel refuses it: the intermediate state is exactly
/// where a suspend can fail, and a device that jumped over it would have no
/// state to fail *in*. The same on the way up.
///
/// `active` is what this manager last recorded, returned updated — so its
/// belief and the kernel's record move together or not at all.
fn apply(level: tessera_power::PowerLevel, active: bool) -> Result<bool, u64> {
    // The line between serving and not: below it the device has stopped, at or
    // above it there is something to serve with.
    let wants_active = level >= tessera_power::PowerLevel::LowPowerActive;
    if wants_active == active {
        return Ok(active);
    }
    if wants_active {
        if !declare(DEVICE_HANDLE, DriverState::Suspended, DriverState::Resuming)
            || !declare(DEVICE_HANDLE, DriverState::Resuming, DriverState::Active)
        {
            return Err(fail(3, 1));
        }
    } else if !declare(DEVICE_HANDLE, DriverState::Active, DriverState::Suspending)
        || !declare(
            DEVICE_HANDLE,
            DriverState::Suspending,
            DriverState::Suspended,
        )
    {
        return Err(fail(3, 2));
    }
    Ok(wants_active)
}

/// Builds the reply for a resolution.
fn reply_for(status: u32, resolution: &Resolution) -> PowerVoteReply {
    PowerVoteReply {
        size: PowerVoteReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        status,
        resolved: to_wire(resolution.level),
        // Zero rather than a level when nothing was taken away, which is what
        // `PowerLevel` starting at 1 buys: one field says both "clamped from
        // here" and "not clamped".
        clamped_from: resolution.clamp.map_or(0, |c| c.from.raw()),
        clamped_by: resolution.clamp.map_or(0, |c| c.by.raw()),
        winner: resolution.winner.unwrap_or(0),
        reserved: 0,
    }
}

/// Serves `requests` vote messages, then reports and stops.
///
/// **A resident service does not stop**, and this one does — because boot has
/// to get an answer out of a machine whose only output is a report. The count
/// arrives as the startup argument rather than as a compiled-in constant, so
/// the stopping condition is boot's: the service itself has no opinion about
/// how long it should live.
fn serve(requests: u32) -> u64 {
    let mut table = VoteTable::new();
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let args = match channel_args(msg_buf.as_ptr() as u64, msg_buf.len() as u64, 0) {
        Ok(args) => args,
        Err(code) => return code,
    };
    let mut event_buf = [0u8; PortEventRecord::WIRE_SIZE];
    // The device is Active when this manager starts: boot brought its
    // lifecycle up to service the way a device manager would have, because
    // binding is not this program's business.
    let mut active = true;
    let mut last = tessera_power::PowerLevel::Off;

    for _ in 0..requests {
        // **Which voter spoke.** One wait over every endpoint: a manager that
        // received on one endpoint at a time would deadlock the moment a
        // different voter called first.
        let waited = syscall2(
            SYS_PORT_WAIT,
            SERVICE_PORT_HANDLE,
            event_buf.as_mut_ptr() as u64,
        );
        if waited < 0 {
            return fail(4, (-waited) as u64);
        }
        let bytes = read_kernel_filled::<{ PortEventRecord::WIRE_SIZE }>(&event_buf);
        let Ok(event) = decode::<PortEventRecord>(&bytes) else {
            return fail(4, 0xd);
        };
        if event.signal != SIGNAL_MESSAGE {
            return fail(4, 0x100 | u64::from(event.signal));
        }
        let Some(index) = VOTER_ENDPOINT_OBJECTS
            .iter()
            .position(|object| *object == event.source)
        else {
            return fail(4, 0x200 | (event.source & 0xff));
        };
        // **The voter's identity is the endpoint it spoke on**, which is the
        // kernel's answer rather than anybody's claim.
        let voter = FIRST_VOTER_HANDLE + index as u32;
        let endpoint = u64::from(voter);

        let received = syscall2(SYS_CHANNEL_RECV, args.as_ptr() as u64, endpoint);
        if received < 0 {
            return fail(5, (-received) as u64);
        }
        let method = read_method_id(&args);
        // Exactly the request's wire size, not the buffer's: the decoder
        // requires the buffer be fully consumed, so handing it the whole
        // symmetric call buffer would fail on the slack rather than on
        // anything wrong with the message.
        let bytes = read_kernel_filled::<{ PowerVoteRequest::WIRE_SIZE }>(&msg_buf);
        let request: PowerVoteRequest = match decode(&bytes) {
            Ok(request) => request,
            Err(_) => return fail(5, 0xd),
        };

        // Apply the request to the table, then resolve. Two steps because
        // `Describe` does the second without the first.
        let status = match (method, to_arbiter_class(request.class)) {
            (PowerManager::VOTE, Some(class)) => {
                let vote = Vote {
                    voter,
                    class,
                    level: to_arbiter(request.level),
                };
                match table.cast(request.domain, vote) {
                    Ok(()) => PowerError::Ok as u32,
                    // Reported, never dropped: a vote nobody recorded is a
                    // device held at the wrong level with nothing saying why.
                    Err(_) => PowerError::NoSpace as u32,
                }
            }
            (PowerManager::WITHDRAW, _) => {
                // Whether there was a vote to withdraw is answered rather than
                // glossed: a confused voter and a correct one must not get the
                // same reply.
                if table.withdraw(request.domain, voter) {
                    PowerError::Ok as u32
                } else {
                    PowerError::NoSuchDomain as u32
                }
            }
            (PowerManager::DESCRIBE, _) => PowerError::Ok as u32,
            _ => PowerError::Protocol as u32,
        };

        let resolution = table.resolve(request.domain, &POLICY);
        // The resolution *happens*. A manager that computed a level and did
        // nothing with it would be an opinion rather than a manager.
        if request.domain == BLOCK_DOMAIN {
            active = match apply(resolution.level, active) {
                Ok(active) => active,
                Err(code) => return code,
            };
            last = resolution.level;
        }

        let reply = reply_for(status, &resolution);
        if encode(&reply, &mut msg_buf[..PowerVoteReply::WIRE_SIZE]).is_err() {
            return fail(6, 0xe);
        }
        let replied = syscall2(SYS_CHANNEL_REPLY_CONTINUE, args.as_ptr() as u64, endpoint);
        if replied < 0 {
            return fail(6, (-replied) as u64);
        }
    }

    manager_word(requests, last, active)
}

// --- Voter mode -------------------------------------------------------------

/// The level a voter's startup argument names.
fn level_from_arg(raw: u64) -> Option<PowerLevel> {
    match raw {
        1 => Some(PowerLevel::Off),
        2 => Some(PowerLevel::Retention),
        3 => Some(PowerLevel::LowPowerActive),
        4 => Some(PowerLevel::FullActive),
        5 => Some(PowerLevel::PerformanceBoost),
        _ => None,
    }
}

/// The voter class a voter's startup argument names.
fn class_from_arg(raw: u64) -> Option<power_manager::VoterClass> {
    match raw {
        1 => Some(power_manager::VoterClass::User),
        2 => Some(power_manager::VoterClass::Service),
        3 => Some(power_manager::VoterClass::Driver),
        4 => Some(power_manager::VoterClass::Thermal),
        _ => None,
    }
}

/// Casts one vote and reports what the domain resolved to.
///
/// The whole of a voter: it states what it needs and is told what it got. That
/// the two can differ — and that the reply says by how much and because of
/// whom — is the property this program exists to demonstrate from the outside.
fn vote(arg: u64) -> u64 {
    let Some(level) = level_from_arg((arg >> VOTER_LEVEL_SHIFT) & VOTER_FIELD_MASK) else {
        return fail(7, 1);
    };
    let Some(class) = class_from_arg((arg >> VOTER_CLASS_SHIFT) & VOTER_FIELD_MASK) else {
        return fail(7, 2);
    };
    let step = ((arg >> VOTER_STEP_SHIFT) & VOTER_FIELD_MASK) as u32;

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let request = PowerVoteRequest {
        size: PowerVoteRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        domain: BLOCK_DOMAIN,
        level,
        class,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..PowerVoteRequest::WIRE_SIZE]).is_err() {
        return fail(7, 0xe);
    }
    let args = match channel_args(
        msg_buf.as_ptr() as u64,
        msg_buf.len() as u64,
        PowerManager::VOTE,
    ) {
        Ok(args) => args,
        Err(code) => return code,
    };
    let called = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if called < 0 {
        return fail(8, (-called) as u64);
    }
    let bytes = read_kernel_filled::<{ PowerVoteReply::WIRE_SIZE }>(&msg_buf);
    let reply: PowerVoteReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return fail(8, 0xd),
    };
    resolution_word(step, &reply)
}

// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: usize) -> ! {
    let arg = arg as u64;
    if arg & VOTER_MODE != 0 {
        exit_reporting(vote(arg))
    } else if arg & WAKE_MODE != 0 {
        exit_reporting(wake::idle_and_wake())
    } else if arg & SUSPEND_MODE != 0 {
        exit_reporting(suspend::suspend_and_resume())
    } else {
        exit_reporting(serve(arg as u32))
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit_reporting(fail(0xff, 0))
}
