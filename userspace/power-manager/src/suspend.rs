// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! System suspend and resume, ordered by the device tree.
//!
//! `docs/power/01-power-management.md` sequences the entry: applications are
//! frozen, driver hosts suspend **in reverse dependency-graph order — leaves
//! before parents** — arming their wakeup sources as they go, and only then
//! does the kernel take the final commit, comparing the wake-event counter
//! against the snapshot the manager took before it began.
//!
//! **The manager does not know the tree; it walks it.** The parent is the only
//! device it is handed, and `DeviceChild` — Phase 2's syscall, unchanged —
//! answers what sits behind it. A manager that was told its topology would be
//! trusting a list somebody maintains; this one asks the graph that the
//! ordering is enforced against, which is the same graph.
//!
//! And the ordering is *enforced*, not merely followed: this module asks in
//! the wrong order on purpose, twice, and the kernel refuses both times. That
//! is the difference between an ordering that is a property of the machine and
//! one that is a property of this loop.
//!
//! Normative: docs/power/01-power-management.md ("Suspend Entry And Resume")

use device_abi::{
    DeviceChildArgs, DeviceChildRecord, SystemSuspendArgs, SystemSuspendRecord, WakeHoldOp,
};
use driver_lifecycle::DriverState;
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall1};

use crate::wake::{hold_call, query, refused_with, wake_source};
use crate::{declare, declare_raw};

const SYS_DEVICE_CHILD: u64 = 35;
const SYS_SYSTEM_SUSPEND: u64 = 38;

/// `KError::WouldBlock`. What an out-of-order power transition answers: the
/// edge is legal and the device tree has not caught up, so the recovery is to
/// suspend the children first and come back — which is what this code means
/// rather than what "protocol error" would.
const KERROR_WOULD_BLOCK: i64 = 11;

// --- The bootstrap contract for this mode ---

/// The wakeup source, with `Rights::WAKE`. Handle 0 is its port, held for the
/// same reason the idle mode holds one: the route has to go somewhere.
const WAKE_SOURCE_HANDLE: u32 = 1;
/// The capability carrying `Rights::WAKE` and `Rights::SLEEP`.
const POWER_HANDLE: u32 = 2;
/// The **bus**, and the only device this manager is handed. What is behind it
/// comes from the graph.
const BUS_HANDLE: u32 = 3;

/// `kcore::dispatch::HANDLE_NOT_INSTALLED`.
const HANDLE_NOT_INSTALLED: u32 = u32::MAX;

/// The device behind `BUS_HANDLE`, and how many there are.
fn child_of_bus() -> Result<(u32, u32), u64> {
    let mut record = [0u8; DeviceChildRecord::WIRE_SIZE];
    let args = DeviceChildArgs {
        size: DeviceChildArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(BUS_HANDLE),
        index: 0,
        record_ptr: record.as_mut_ptr() as u64,
    };
    let mut buf = [0u8; DeviceChildArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x20, 0xe));
    }
    let answered = syscall1(SYS_DEVICE_CHILD, buf.as_ptr() as u64);
    if answered < 0 {
        return Err(fail(0x20, (-answered) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceChildRecord::WIRE_SIZE }>(&record);
    let record: DeviceChildRecord = match decode(&bytes) {
        Ok(record) => record,
        Err(_) => return Err(fail(0x20, 0xd)),
    };
    if record.child == HANDLE_NOT_INSTALLED {
        return Err(fail(0x20, 1));
    }
    Ok((record.child, record.count))
}

/// One `SystemSuspend` call, answering `(status, events, source)`.
fn commit(snapshot: u64) -> Result<(u32, u64, u64), u64> {
    let mut record = [0u8; SystemSuspendRecord::WIRE_SIZE];
    let args = SystemSuspendArgs {
        size: SystemSuspendArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        power: HandleRef::new(POWER_HANDLE),
        reserved: 0,
        snapshot,
        record_ptr: record.as_mut_ptr() as u64,
    };
    let mut buf = [0u8; SystemSuspendArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x21, 0xe));
    }
    let answered = syscall1(SYS_SYSTEM_SUSPEND, buf.as_ptr() as u64);
    if answered < 0 {
        return Err(fail(0x21, (-answered) as u64));
    }
    let bytes = read_kernel_filled::<{ SystemSuspendRecord::WIRE_SIZE }>(&record);
    match decode::<SystemSuspendRecord>(&bytes) {
        Ok(record) => Ok((record.status, record.events, record.source)),
        Err(_) => Err(fail(0x21, 0xd)),
    }
}

/// Declares one power transition and answers whether the kernel refused it
/// **as out of order specifically** — for the two places this asks in the
/// wrong order on purpose.
///
/// The specific code matters. A refusal for some other reason — a stale
/// `from`, an illegal edge — would make the wrong-order ask look successful at
/// proving something it did not prove, and the whole point of these two calls
/// is that the *tree* is what refused them.
fn refused_out_of_order(handle: u32, from: DriverState, to: DriverState) -> bool {
    refused_with(declare_raw(handle, from, to), KERROR_WOULD_BLOCK)
}

/// Suspends the machine and brings it back.
///
/// The report packs the seven facts a check can be wrong about: both
/// wrong-order refusals, the commit's outcome and whether it named a source,
/// the stale-snapshot abort, the wake-hold veto, and whether both devices
/// ended up back in service.
pub fn suspend_and_resume() -> u64 {
    let (bus_child, count) = match child_of_bus() {
        Ok(answer) => answer,
        Err(code) => return code,
    };
    if count != 1 {
        return fail(0x22, u64::from(count));
    }

    // **The wrong order, on purpose.** A bus going down under a device that is
    // still serving is the failure the ordering exists to prevent, and asking
    // for it is the only way to show the kernel is the thing that prevents it.
    let suspend_refused =
        refused_out_of_order(BUS_HANDLE, DriverState::Active, DriverState::Suspending);
    if !suspend_refused {
        return fail(0x23, 1);
    }

    // Leaves before parents.
    if !declare(bus_child, DriverState::Active, DriverState::Suspending)
        || !declare(bus_child, DriverState::Suspending, DriverState::Suspended)
        || !declare(BUS_HANDLE, DriverState::Active, DriverState::Suspending)
        || !declare(BUS_HANDLE, DriverState::Suspending, DriverState::Suspended)
    {
        return fail(0x24, 1);
    }

    // And the mirror, which is the half a manager is most likely to get wrong:
    // a leaf cannot come up through a bus that is still down.
    let resume_refused =
        refused_out_of_order(bus_child, DriverState::Suspended, DriverState::Resuming);
    if !resume_refused {
        return fail(0x23, 2);
    }

    // Arm the wakeup source *before* the snapshot, so anything it produces
    // from here on is something the snapshot can be compared against.
    match wake_source(WAKE_SOURCE_HANDLE, true) {
        Ok(result) if result >= 0 => {}
        Ok(result) => return fail(0x25, (-result) as u64),
        Err(code) => return code,
    }
    let (snapshot, _) = match query() {
        Ok(answer) => answer,
        Err(code) => return code,
    };

    // The commit. This does not return until the machine resumes.
    let (status, _, source) = match commit(snapshot) {
        Ok(answer) => answer,
        Err(code) => return code,
    };

    // **The stale snapshot, and it is a real one.** The counter moved because
    // of the wake that just ended the sleep, so presenting the same snapshot
    // again is exactly the race the comparison exists to catch — rather than a
    // fabricated number, which would prove only that the kernel can compare
    // two integers.
    let (stale, _, _) = match commit(snapshot) {
        Ok(answer) => answer,
        Err(code) => return code,
    };

    // The veto: a hold makes the machine refuse to stop, whatever the counter
    // says.
    let (fresh, _) = match query() {
        Ok(answer) => answer,
        Err(code) => return code,
    };
    if let Err(code) = hold_call(WakeHoldOp::Acquire, 0) {
        return code;
    }
    let (vetoed, _, _) = match commit(fresh) {
        Ok(answer) => answer,
        Err(code) => return code,
    };
    if let Err(code) = hold_call(WakeHoldOp::Release, 0) {
        return code;
    }

    // Resume runs parent-first — the reverse of the way down.
    let back = declare(BUS_HANDLE, DriverState::Suspended, DriverState::Resuming)
        && declare(BUS_HANDLE, DriverState::Resuming, DriverState::Active)
        && declare(bus_child, DriverState::Suspended, DriverState::Resuming)
        && declare(bus_child, DriverState::Resuming, DriverState::Active);

    match wake_source(WAKE_SOURCE_HANDLE, false) {
        Ok(result) if result >= 0 => {}
        Ok(result) => return fail(0x26, (-result) as u64),
        Err(code) => return code,
    }

    u64::from(suspend_refused)
        | (u64::from(resume_refused) << 8)
        | (u64::from(status) << 16)
        | (u64::from(source != 0) << 24)
        | (u64::from(stale) << 32)
        | (u64::from(vetoed) << 40)
        | (u64::from(back) << 48)
}
