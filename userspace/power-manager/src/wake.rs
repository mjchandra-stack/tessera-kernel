// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Runtime idle and the wake capability: the mode in which this service lets a
//! domain nobody is using fall out of service, and arranges for something to
//! bring it back.
//!
//! **This module touches no device register.** Boot owns the wakeup source
//! itself — a real-time clock, which belongs to no driver — arms its alarm and
//! clears it afterwards. What the manager holds is a capability to that device
//! carrying `Rights::WAKE`, a port its interrupts are routed to, and the
//! device whose lifecycle it narrates. That split is the design rather than a
//! convenience: registering a wakeup source is a power manager's business and
//! driving a clock is not.
//!
//! The decision itself is `tessera_power::runtime_idle`, host-tested against a
//! busy domain, a quiet one that has not been quiet long enough, and a state
//! whose resume latency exceeds what the domain's users tolerate. What is here
//! is what a host cannot run: the syscalls, and parking on a port until real
//! hardware raises a real interrupt.
//!
//! Normative: docs/power/01-power-management.md ("Wakeup Sources And Wake
//! Holds")

use device_abi::{WakeHoldArgs, WakeHoldOp, WakeHoldRecord, WakeSourceArgs};
use driver_lifecycle::DriverState;
use port_event::PortEventRecord;
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_power::{IdleDecision, IdlePolicy, PowerLevel, arbitrate, runtime_idle};
use tessera_uabi::{fail, read_kernel_filled, syscall1, syscall2};

use crate::{POLICY, SYS_PORT_WAIT, declare};

const SYS_WAKE_SOURCE: u64 = 36;
const SYS_WAKE_HOLD: u64 = 37;

/// `KError::AccessDenied`. The syscall boundary negates `(domain << 16) | code`,
/// so the code is the low half — checked on its own rather than against the
/// whole word, because which *domain* an error is filed under is the kernel's
/// taxonomy and not this program's business.
pub(crate) const KERROR_ACCESS_DENIED: i64 = 8;

/// Whether a syscall result is a refusal for the given reason.
pub(crate) fn refused_with(result: i64, code: i64) -> bool {
    result < 0 && (-result) & 0xffff == code
}

// --- The bootstrap contract for this mode ---

/// The port the wakeup source's interrupts are routed to.
const WAKE_PORT_HANDLE: u64 = 0;
/// The wakeup source, with `Rights::WAKE`.
const WAKE_SOURCE_HANDLE: u32 = 1;
/// The capability that says this machine must not sleep.
pub(crate) const POWER_HANDLE: u32 = 2;
/// The device whose lifecycle a resolution is applied to.
const IDLE_DEVICE_HANDLE: u32 = 3;
/// **The same wakeup source, without `Rights::WAKE`.** The negative check is a
/// handle rather than a second boot: one capability can arm this line and the
/// other cannot, and the only difference between them is the right.
const UNWAKEABLE_HANDLE: u32 = 4;

/// When an unused domain drops, and how far.
///
/// `after_ticks` is zero here and that is deliberate rather than an oversight:
/// the timeout is policy, exercised exhaustively in `//api/power`'s host tests
/// against a domain that has not been quiet long enough, and a boot check that
/// spun waiting for scheduler ticks to accumulate would be testing the timer
/// rather than the idle path. What the boot proves is the part a host cannot:
/// that the decision reaches a device, and that a real interrupt undoes it.
const IDLE: IdlePolicy = IdlePolicy {
    after_ticks: 0,
    level: PowerLevel::Retention,
    // The resume latency this domain's users tolerate. Bounded rather than
    // absent so the clause is live: a device slower to wake than this is left
    // warm and the refusal says both numbers.
    max_resume_latency_us: 100_000,
};

/// What the device whose lifecycle this mode narrates reports as its resume
/// latency — `BlockDescribeReply.resume_latency_us`, which the class contracts
/// have carried since D128 and which nothing read until now.
const DEVICE_RESUME_LATENCY_US: u64 = 0;

/// Reads the system wake-event counter and the live hold count.
pub(crate) fn query() -> Result<(u64, u32), u64> {
    hold_call(WakeHoldOp::Query, 0)
}

/// One `WakeHold` call, answering `(events, held)`.
pub(crate) fn hold_call(op: WakeHoldOp, ticks: u64) -> Result<(u64, u32), u64> {
    let mut record = [0u8; WakeHoldRecord::WIRE_SIZE];
    let args = WakeHoldArgs {
        size: WakeHoldArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        power: HandleRef::new(POWER_HANDLE),
        op,
        ticks,
        record_ptr: record.as_mut_ptr() as u64,
    };
    let mut buf = [0u8; WakeHoldArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x10, 0xe));
    }
    let answered = syscall1(SYS_WAKE_HOLD, buf.as_ptr() as u64);
    if answered < 0 {
        return Err(fail(0x10, (-answered) as u64));
    }
    let bytes = read_kernel_filled::<{ WakeHoldRecord::WIRE_SIZE }>(&record);
    match decode::<WakeHoldRecord>(&bytes) {
        Ok(record) => Ok((record.events, record.held)),
        Err(_) => Err(fail(0x10, 0xd)),
    }
}

/// Arms or disarms `handle`'s interrupt as a system wakeup source, answering
/// the raw syscall result so a *refusal* can be checked rather than only a
/// success.
pub(crate) fn wake_source(handle: u32, arm: bool) -> Result<i64, u64> {
    let args = WakeSourceArgs {
        size: WakeSourceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        arm: u32::from(arm),
        reserved: 0,
    };
    let mut buf = [0u8; WakeSourceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x11, 0xe));
    }
    Ok(syscall1(SYS_WAKE_SOURCE, buf.as_ptr() as u64))
}

/// Parks until the wakeup source fires, answering the line it arrived on.
fn park() -> Result<u64, u64> {
    let mut event = [0u8; PortEventRecord::WIRE_SIZE];
    let waited = syscall2(SYS_PORT_WAIT, WAKE_PORT_HANDLE, event.as_mut_ptr() as u64);
    if waited < 0 {
        return Err(fail(0x12, (-waited) as u64));
    }
    let bytes = read_kernel_filled::<{ PortEventRecord::WIRE_SIZE }>(&event);
    match decode::<PortEventRecord>(&bytes) {
        Ok(record) => Ok(record.source),
        Err(_) => Err(fail(0x12, 0xd)),
    }
}

/// Lets an unused domain fall out of service, and waits for something to bring
/// it back.
///
/// The report packs the five facts a check can be wrong about: how far the
/// wake-event counter moved, whether a hold was keeping the machine awake when
/// the manager looked, what the idle decision was, whether the capability
/// without `WAKE` was refused, and whether the device came back.
pub fn idle_and_wake() -> u64 {
    let (events_before, _) = match query() {
        Ok(answer) => answer,
        Err(code) => return code,
    };

    // Nobody is voting on this domain, so it resolves to the policy floor with
    // no winner — which is what "unused" means, as distinct from "somebody is
    // asking for very little".
    let resolution = arbitrate(&[], &POLICY);
    let decision = runtime_idle(&resolution, 0, DEVICE_RESUME_LATENCY_US, &IDLE);
    let idle_level = match decision {
        IdleDecision::Idle(level) => level,
        // Every other answer is a reason not to idle, and each is reported
        // rather than folded into "nothing happened": a domain that never
        // idles because of a latency budget and one whose timer is wrong look
        // identical from outside, and only one of them is somebody's mistake.
        IdleDecision::InUse { .. } => return fail(0x13, 1),
        IdleDecision::TooSoon { .. } => return fail(0x13, 2),
        IdleDecision::TooSlowToResume { .. } => return fail(0x13, 3),
    };
    let _ = idle_level;

    // **The negative check, before the positive one.** A capability to the
    // very same device, differing only in the right it carries, cannot arm
    // this line. Done first so that a machine where arming somehow always
    // succeeds fails here rather than passing on the strength of the second
    // call.
    let refused = match wake_source(UNWAKEABLE_HANDLE, true) {
        Ok(result) => refused_with(result, KERROR_ACCESS_DENIED),
        Err(code) => return code,
    };
    if !refused {
        return fail(0x14, 1);
    }
    match wake_source(WAKE_SOURCE_HANDLE, true) {
        Ok(result) if result >= 0 => {}
        Ok(result) => return fail(0x14, (-result) as u64),
        Err(code) => return code,
    }

    // Out of service. Through the intermediate state, because `Active ->
    // Suspended` is not a legal edge and the intermediate is where a suspend
    // can fail.
    if !declare(
        IDLE_DEVICE_HANDLE,
        DriverState::Active,
        DriverState::Suspending,
    ) || !declare(
        IDLE_DEVICE_HANDLE,
        DriverState::Suspending,
        DriverState::Suspended,
    ) {
        return fail(0x15, 1);
    }

    // Nothing spins. The next thing that runs in this process is whatever the
    // hardware decides to do.
    if let Err(code) = park() {
        return code;
    }

    let (events_after, held) = match query() {
        Ok(answer) => answer,
        Err(code) => return code,
    };

    // Back in service, mirror image of the way down.
    let resumed = declare(
        IDLE_DEVICE_HANDLE,
        DriverState::Suspended,
        DriverState::Resuming,
    ) && declare(
        IDLE_DEVICE_HANDLE,
        DriverState::Resuming,
        DriverState::Active,
    );

    // Disarm: a domain back in service does not need its wakeup source, and a
    // source left armed is one more thing able to wake a machine than anybody
    // asked for.
    match wake_source(WAKE_SOURCE_HANDLE, false) {
        Ok(result) if result >= 0 => {}
        Ok(result) => return fail(0x16, (-result) as u64),
        Err(code) => return code,
    }

    // A boolean rather than the count, and deliberately: what is being claimed
    // is that a wake takes a short hold, not that exactly one hold existed at
    // the instant this program looked. The count is a race with the grace
    // period's own expiry; its existence is not.
    let grace_seen = held >= 1;
    events_after.wrapping_sub(events_before)
        | (u64::from(grace_seen) << 8)
        | (1u64 << 16)
        | (u64::from(refused) << 24)
        | (u64::from(resumed) << 32)
}
