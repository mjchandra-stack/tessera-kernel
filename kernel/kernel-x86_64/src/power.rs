// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Power: the transitions a machine makes when more than one program has an
//! opinion about them.
//!
//! Three voters ask a manager for a device's power state, one after another,
//! and each is told what the machine resolved rather than what it asked for.
//! The second vote is the negative one, in line rather than in a second boot:
//! it asks for full activity and is given it with nothing clamped, so the
//! third's clamp is a decision the manager made and not a state it always
//! returns.
//!
//! **The resolution happens to a device**, and the kernel's edge table is what
//! says so: the manager drives it through the states a power transition is
//! defined to pass through, and had it failed to resume the device after the
//! second vote, the third's `Active -> Suspending` would have been declared
//! from `Suspended` and refused. The transcript is enforced rather than counted.
//!
//! **The device does not exist.** It is registered with a base and a length of
//! zero and granted `MAP` and nothing behind it, because what the manager may
//! do to it is say what state it is in — narrating a lifecycle requires that
//! right — and what it may not do is touch it.
//!
//! Split out of `main.rs` by area (build/README.md, D265).
//!
//! Normative: docs/kernel/08-power-management.md

use crate::*;

pub(crate) const POWER_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x1e0);
pub(crate) const POWER_SERVICE_PORT_OBJ: ObjectId = ObjectId::from_raw(0x1e1);
/// **The numbers `power-manager` is compiled with**, not this check's own.
/// A port event names the object that was signalled and a handle table is
/// per-process, so a server selecting over several endpoints holds the mapping
/// — and it holds it as a constant. Boot and the program agree on the
/// numbering, and that agreement is the bootstrap contract; a check that
/// numbered them to suit itself would leave the manager unable to say who
/// spoke.
const POWER_SERVER_OBJS: [u32; 3] = [70, 71, 72];
const POWER_CLIENT_OBJS: [u32; 3] = [73, 74, 75];
pub(crate) const POWER_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x1e8);
const POWER_VOTER_PROC_OBJS: [u32; 3] = [0x1e9, 0x1ea, 0x1eb];

/// The startup bit that tells `power-manager` to be a voter rather than the
/// manager, and the fields a voter's argument carries: what level it needs,
/// which class of caller it is, and which step of the sequence it is.
const POWER_VOTER_MODE: usize = 1 << 63;
const fn power_voter_arg(level: u64, class: u64, step: u64) -> usize {
    (POWER_VOTER_MODE as u64 | level | (class << 8) | (step << 16)) as usize
}

/// The three votes, in the order they are cast. The middle one is the negative
/// check and it is in line rather than in a second boot: it asks for full
/// activity and is given it with nothing clamped, so the third's clamp is a
/// decision the manager made rather than a state it always returns.
const POWER_VOTES: [usize; 3] = [
    power_voter_arg(2, 3, 1),
    power_voter_arg(4, 1, 2),
    power_voter_arg(2, 4, 3),
];

/// What each vote must be told, and what the manager reports when it is done.
///
/// Restated here rather than shared: these are the values the *other* port
/// expects of the same program, which is what makes agreement a check rather
/// than a definition.
const fn power_vote_word(step: u32, resolved: u64, from: u64, by: u64, winner: u64) -> u64 {
    (resolved | (from << 8) | (by << 16) | (winner << 24)).rotate_left(8 * step)
}
const POWER_STEP_1: u64 = power_vote_word(1, 2, 0, 0, 1);
const POWER_STEP_2: u64 = power_vote_word(2, 4, 0, 0, 2);
const POWER_STEP_3: u64 = power_vote_word(3, 2, 4, 4, 2);
const POWER_MANAGER_WORD: u64 = (3u64 | (2u64 << 8)).rotate_left(40);

/// What the run established.
pub(crate) struct PowerOutcome {
    pub(crate) replies: [u64; 3],
    pub(crate) manager: u64,
    /// Records this check left in the ring, taken back so a later reader of it
    /// is not handed a lifecycle nobody caused.
    pub(crate) drained: u64,
}

/// Runs three voters against one manager over a device that does not exist.
pub(crate) fn power_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<Option<PowerOutcome>, u32> {
    use kcore::lifecycle::{DriverState, TransitionReason};
    use kcore::rights::Rights;

    if components::power_manager().is_empty() {
        return Ok(None);
    }

    // SAFETY: the boot CPU alone; a fresh table and executive for this check.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(4);
    }
    exec_ref()
        .device_register_mmio(POWER_DEVICE_OBJ, 0, 0, Rights::READ | Rights::MAP)
        .map_err(|_| 1u32)?;
    // Boot brings the device up to service the way a device manager would have.
    // Binding is not the power manager's business, and a lifecycle that opened
    // at `Suspending` would be a history nobody lived.
    for (from, to, reason) in [
        (
            DriverState::Discovered,
            DriverState::Matched,
            TransitionReason::Bound,
        ),
        (
            DriverState::Matched,
            DriverState::Starting,
            TransitionReason::Launched,
        ),
        (
            DriverState::Starting,
            DriverState::Probing,
            TransitionReason::Launched,
        ),
        (
            DriverState::Probing,
            DriverState::Active,
            TransitionReason::ProbeSucceeded,
        ),
    ] {
        exec_ref()
            .declare_lifecycle(POWER_DEVICE_OBJ, from, to, reason, 0)
            .map_err(|_| 2u32)?;
    }

    // **One channel per voter, and one port bound to every server endpoint.** A
    // message on any of them raises `SIGNAL_MESSAGE` on that endpoint's object,
    // so the manager's single `PortWait` is a select that names who spoke. A
    // manager receiving on one endpoint at a time would deadlock the moment a
    // different voter called first.
    let port = exec_ref().port_create().map_err(|_| 3u32)?;
    exec_ref().bind_port_object(port, POWER_SERVICE_PORT_OBJ);
    for index in 0..POWER_SERVER_OBJS.len() {
        let (server, client) = exec_ref().channel_create().map_err(|_| 4u32)?;
        let server_obj = ObjectId::from_raw(POWER_SERVER_OBJS[index]);
        exec_ref().bind_endpoint_object(server, server_obj);
        exec_ref().bind_endpoint_object(client, ObjectId::from_raw(POWER_CLIENT_OBJS[index]));
        exec_ref()
            .port_bind(
                port,
                u64::from(server_obj.raw()),
                kcore::ipc::SIGNAL_MESSAGE,
            )
            .map_err(|_| 5u32)?;
    }

    let kstacks = kstack_mark();

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(bind_observer);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    crate::syscalls::publish_frames(frames);

    // The manager spawns first and parks on its port before anybody calls —
    // the server-first pattern every check here uses.
    let (manager_thread, manager_proc) = spawn_elf_process(
        components::power_manager(),
        POWER_SERVER_OBJS.len(),
        POWER_MANAGER_PROC_OBJ,
        kernel_vm,
        frames,
        10,
    )?;
    // SAFETY: the boot CPU alone; the process table is quiescent between spawns.
    unsafe {
        let manager = (&mut *&raw mut PROCESSES)
            .get_mut(manager_proc)
            .ok_or(20u32)?;
        manager
            .handles_mut()
            .install(POWER_SERVICE_PORT_OBJ, Rights::READ)
            .map_err(|_| 21u32)?;
        for object in POWER_SERVER_OBJS {
            manager
                .handles_mut()
                .install(ObjectId::from_raw(object), Rights::READ)
                .map_err(|_| 22u32)?;
        }
        manager
            .handles_mut()
            .install(POWER_DEVICE_OBJ, Rights::READ | Rights::MAP)
            .map_err(|_| 23u32)?;
    }

    let mut voter_threads = [0usize; 3];
    let mut voter_procs = [0usize; 3];
    for index in 0..POWER_SERVER_OBJS.len() {
        let (thread, proc_idx) = spawn_elf_process(
            components::power_manager(),
            POWER_VOTES[index],
            ObjectId::from_raw(POWER_VOTER_PROC_OBJS[index]),
            kernel_vm,
            frames,
            30 + index as u32 * 10,
        )?;
        voter_threads[index] = thread;
        voter_procs[index] = proc_idx;
        // SAFETY: as above.
        unsafe {
            (&mut *&raw mut PROCESSES)
                .get_mut(proc_idx)
                .ok_or(60u32)?
                .handles_mut()
                .install(ObjectId::from_raw(POWER_CLIENT_OBJS[index]), Rights::WRITE)
                .map_err(|_| 61u32)?;
        }
        // **Run to a standstill before the next voter is spawned.** The votes
        // are a sequence — each is told what the ones before it resolved — and
        // three voters racing would put their replies in the sink in whichever
        // order the scheduler produced.
        exec_ref().run();
    }

    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    // **What this check declared, drained.** Its four lifecycle transitions are
    // made from boot context, which is not a thread and carries no cause — so
    // they are records of a ladder's own kinds with no correlation on them, and
    // the supervision check three steps later reads its ladder out of the same
    // ring. On a boot where the filesystem check runs, that drain would have
    // cleared them; on one where it skips, nothing would (build/README.md,
    // D334).
    let drained = crate::observability::drain_ring();
    let outcome = judge_power().map(|mut outcome| {
        outcome.drained = drained;
        outcome
    });

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in voter_threads.into_iter().chain([manager_thread]) {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in voter_procs.into_iter().chain([manager_proc]) {
            if let Some(mut gone) = processes.remove(process) {
                exec_ref().release_memory_of(gone.id(), frames, None);
                gone.space_mut().teardown(frames);
            }
        }
    }
    kstack_release(kernel_vm, kstacks, BIND_KSTACK_PAGES);
    outcome.map(Some)
}

/// Reads what the votes left.
fn judge_power() -> Result<PowerOutcome, u32> {
    use kcore::lifecycle::DriverState;

    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(70);
    }
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 4 {
        return Err(71);
    }
    let mut replies = [
        BIND_REPORTS[0].load(Ordering::SeqCst),
        BIND_REPORTS[1].load(Ordering::SeqCst),
        BIND_REPORTS[2].load(Ordering::SeqCst),
    ];
    if replies[0] != POWER_STEP_1 {
        return Err(72);
    }
    if replies[1] != POWER_STEP_2 {
        return Err(73);
    }
    // The third voter and the manager both become runnable on the same reply,
    // so which of them reports first is the scheduler's business and not this
    // check's. Both values are required, in either order — the alternative
    // would be a check that passes or fails on a detail neither program
    // controls. Matched as a pair rather than folded together, so one report
    // cannot stand in for the other.
    let tail = [replies[2], BIND_REPORTS[3].load(Ordering::SeqCst)];
    let thermal = if tail == [POWER_STEP_3, POWER_MANAGER_WORD] {
        tail[0]
    } else if tail == [POWER_MANAGER_WORD, POWER_STEP_3] {
        tail[1]
    } else {
        return Err(74);
    };
    replies[2] = thermal;

    // **The resolution happened to a device.** The manager drove it through the
    // states a power transition is defined to pass through; the kernel refused
    // none of them and has the state to prove it.
    let state = exec_ref()
        .lifecycle_of_object(POWER_DEVICE_OBJ)
        .ok_or(75u32)?;
    if state != DriverState::Suspended {
        return Err(76);
    }
    Ok(PowerOutcome {
        replies,
        manager: POWER_MANAGER_WORD,
        drained: 0,
    })
}
