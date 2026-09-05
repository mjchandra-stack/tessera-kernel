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

// --- The wake source: the mc146818 real-time clock (D335) --------------------

/// The RTC's index and data ports, and the line it raises.
///
/// **A wake source on this machine is an I/O-port device, not a register
/// window.** The other port's PL031 is a page a driver maps; this one is two
/// bytes of the ISA address space that every x86 has had since the AT, reached
/// with `in` and `out`. What that changes for the check is only how the kernel
/// touches it — the graph node, the route, the right and the arming are the
/// same story.
const RTC_INDEX_PORT: u16 = 0x70;
const RTC_DATA_PORT: u16 = 0x71;
const RTC_IRQ_LINE: u8 = 8;

/// Registers: seconds, the alarm's seconds, and the two control registers.
const RTC_SECONDS: u8 = 0x00;
const RTC_SECONDS_ALARM: u8 = 0x01;
const RTC_MINUTES_ALARM: u8 = 0x03;
const RTC_HOURS_ALARM: u8 = 0x05;
const RTC_REG_A: u8 = 0x0a;
const RTC_REG_B: u8 = 0x0b;
const RTC_REG_C: u8 = 0x0c;

/// Register B: the alarm interrupt, and whether the registers are binary.
const RTC_B_ALARM_ENABLE: u8 = 1 << 5;
const RTC_B_BINARY: u8 = 1 << 2;
/// Register A: an update is in progress and the time registers are moving.
const RTC_A_UPDATE_IN_PROGRESS: u8 = 1 << 7;
/// An alarm byte in this range matches every value — "don't care".
const RTC_ALARM_ANY: u8 = 0xff;

/// Reads one CMOS register.
///
/// The index port's top bit masks the non-maskable interrupt, and the
/// convention every x86 kernel follows is to leave it as it found it: this
/// writes the index alone, which is what the firmware left set.
fn rtc_read(register: u8) -> u8 {
    // SAFETY: the two CMOS ports, which no other code on this machine touches
    // while a check is running; reading the data port has no side effect for
    // the registers named above except register C, whose read is the
    // acknowledgement it is read for.
    unsafe {
        tessera_karch_x86_64::device_out(RTC_INDEX_PORT, register);
        tessera_karch_x86_64::device_in(RTC_DATA_PORT)
    }
}

/// Writes one CMOS register.
fn rtc_write(register: u8, value: u8) {
    // SAFETY: as `rtc_read`; the registers written here are the alarm's and
    // register B, which is what arming an alarm consists of.
    unsafe {
        tessera_karch_x86_64::device_out(RTC_INDEX_PORT, register);
        tessera_karch_x86_64::device_out(RTC_DATA_PORT, value);
    }
}

/// Arms the alarm `seconds` from now, and returns nothing to un-arm with: the
/// hook below reads register C, which is both the acknowledgement and the
/// disarm.
///
/// **Hours and minutes are "don't care".** The alarm this check wants is "a
/// couple of seconds from now", and a match on the second alone is exactly
/// that once a minute — which is once more than this check needs. Reading the
/// seconds register while an update is in progress returns a value that is
/// about to change, so the read waits for that bit to clear.
fn rtc_arm_alarm(seconds: u8) {
    // Bounded: a clock that never leaves its update window is a clock this
    // check cannot use, and spinning for ever would hide that.
    for _ in 0..1_000_000u32 {
        if rtc_read(RTC_REG_A) & RTC_A_UPDATE_IN_PROGRESS == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    let now = rtc_read(RTC_SECONDS);
    let binary = rtc_read(RTC_REG_B) & RTC_B_BINARY != 0;
    let now = if binary {
        now
    } else {
        // Binary-coded decimal, which is what this device answers in unless
        // the firmware said otherwise.
        (now >> 4) * 10 + (now & 0x0f)
    };
    let at = (now + seconds) % 60;
    let at = if binary {
        at
    } else {
        ((at / 10) << 4) | (at % 10)
    };
    rtc_write(RTC_HOURS_ALARM, RTC_ALARM_ANY);
    rtc_write(RTC_MINUTES_ALARM, RTC_ALARM_ANY);
    rtc_write(RTC_SECONDS_ALARM, at);
    let control = rtc_read(RTC_REG_B);
    rtc_write(RTC_REG_B, control | RTC_B_ALARM_ENABLE);
}

/// Stops the alarm, whatever state it is in.
fn rtc_disarm() {
    let control = rtc_read(RTC_REG_B);
    rtc_write(RTC_REG_B, control & !RTC_B_ALARM_ENABLE);
    // Register C is read-to-clear: a pending flag left set stops the device
    // raising the line again, which would make the next check's alarm silent.
    let _ = rtc_read(RTC_REG_C);
}

/// The line this check routes, and how many times it was taken.
pub(crate) static WAKE_DELIVERIES: AtomicU64 = AtomicU64::new(0);

/// The bridge from the RTC's line to the port the manager parks on.
///
/// **Register C is read here and nowhere else.** The device holds its alarm
/// flag until somebody reads that register, and a line left asserted is one
/// the controller raises again the moment it is acknowledged — the storm this
/// hook exists to end. Reading it is the device's acknowledgement; the
/// controller's is the trap path's.
pub(crate) fn wake_irq_hook(vector: u64) {
    if vector != u64::from(tessera_karch_x86_64::IRQ_BASE_LINE + RTC_IRQ_LINE) {
        return;
    }
    let _ = rtc_read(RTC_REG_C);
    // The line is masked here, not left live: an alarm the device holds
    // asserted is one the controller raises again the moment it is
    // acknowledged, and the machine is about to be awake anyway.
    tessera_karch_x86_64::mask_irq(RTC_IRQ_LINE);
    WAKE_DELIVERIES.fetch_add(1, Ordering::SeqCst);
    // A device interrupt is where the outside world becomes work, so what the
    // woken manager does is attributed to a fresh cause rather than to whatever
    // thread the line landed on.
    kcore::trace::set_current_correlation(kcore::trace::mint());
    // **Recorded as a wake, then delivered.** The port event is what wakes the
    // program; the record is what the machine knows happened — and the manager
    // reads the second, because a program cannot count the wakes of a machine
    // it was not running on.
    exec_ref().record_wake(vector as u32);
    exec_ref().port_signal(vector, 1, 1);
}

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

// --- The wake check ---------------------------------------------------------

pub(crate) const WAKE_RTC_OBJ: ObjectId = ObjectId::from_raw(0x1f0);
pub(crate) const WAKE_POWER_OBJ: ObjectId = ObjectId::from_raw(0x1f1);
pub(crate) const WAKE_DEVICE_OBJ: ObjectId = ObjectId::from_raw(0x1f2);
pub(crate) const WAKE_PORT_OBJ: ObjectId = ObjectId::from_raw(0x1f3);
pub(crate) const WAKE_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0x1f4);

/// The startup argument that asks the power manager to run its idle-and-wake
/// mode. Must match `WAKE_MODE` there.
const POWER_MANAGER_WAKE_MODE: usize = 1 << 62;

/// What the manager must report: one wake counted, the grace hold seen, the
/// domain idled, the capability without `Rights::WAKE` refused, and the device
/// back in service. One byte each, so a failure names which of the five went
/// wrong rather than only that something did.
const WAKE_EXPECTED: u64 = 1 | (1 << 8) | (1 << 16) | (1 << 24) | (1 << 32);

/// Seconds ahead the alarm is set. Two rather than one: a one-second alarm set
/// just before a second boundary can be a match the device has already passed.
const WAKE_ALARM_SECONDS: u8 = 2;

/// The wall clock the run is allowed, which is the alarm plus room. A run that
/// reaches its claims leaves the moment it does.
const WAKE_BUDGET_MS: u64 = 8_000;

/// What the wake run established.
pub(crate) struct WakeOutcome {
    pub(crate) reported: u64,
    pub(crate) deliveries: u64,
}

/// Idles a machine and wakes it with a real device.
///
/// The manager holds the RTC twice: once with `Rights::WAKE` and once without,
/// which is the negative case in line rather than in a second boot — one
/// capability can arm this line and the other cannot, and the difference is the
/// right rather than the device.
pub(crate) fn wake_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<Option<WakeOutcome>, u32> {
    use kcore::lifecycle::{DriverState, TransitionReason};
    use kcore::rights::Rights;

    if components::power_manager().is_empty() {
        return Ok(None);
    }
    let vector = u32::from(tessera_karch_x86_64::IRQ_BASE_LINE + RTC_IRQ_LINE);

    // SAFETY: the boot CPU alone; a fresh table and executive for this check.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(4);
    }
    // The RTC as a graph node. **`WAKE` is on the node's own rights**, because
    // that is what a kernel-originated hand-out of it carries: a device nobody
    // said may wake this machine could not be armed however it were granted.
    // Its window is the two CMOS ports rather than a page, so the node carries
    // no length at all — what a holder of it may do is arm a line.
    exec_ref()
        .device_register_mmio(WAKE_RTC_OBJ, 0, 0, Rights::READ | Rights::WAKE)
        .map_err(|_| 1u32)?;
    exec_ref()
        .device_set_mmio_irq(WAKE_RTC_OBJ, vector)
        .map_err(|_| 2u32)?;
    // The power domain the manager idles, and the device that goes with it:
    // windowless, so the capability carries the authority to narrate a
    // lifecycle and nothing else.
    exec_ref()
        .device_register_mmio(WAKE_POWER_OBJ, 0, 0, Rights::READ | Rights::WAKE)
        .map_err(|_| 3u32)?;
    exec_ref()
        .device_register_mmio(WAKE_DEVICE_OBJ, 0, 0, Rights::READ | Rights::MAP)
        .map_err(|_| 4u32)?;
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
            .declare_lifecycle(WAKE_DEVICE_OBJ, from, to, reason, 0)
            .map_err(|_| 5u32)?;
    }
    // The route: the RTC's line, delivered to a port the manager holds, through
    // the graph rather than as a bare port binding — so the wake is something
    // the graph can end when the holder goes away.
    let port = exec_ref().port_create().map_err(|_| 6u32)?;
    exec_ref().bind_port_object(port, WAKE_PORT_OBJ);
    exec_ref()
        .device_route_irq(WAKE_RTC_OBJ, port, WAKE_MANAGER_PROC_OBJ)
        .map_err(|_| 7u32)?;

    let kstacks = kstack_mark();

    // SAFETY: one-shot registration before this check's ring-3 thread runs.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(bind_observer);
    tessera_karch_x86_64::set_device_irq_hook(wake_irq_hook);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    WAKE_DELIVERIES.store(0, Ordering::SeqCst);
    crate::syscalls::publish_frames(frames);

    let (manager_thread, manager_proc) = spawn_elf_process(
        components::power_manager(),
        POWER_MANAGER_WAKE_MODE,
        WAKE_MANAGER_PROC_OBJ,
        kernel_vm,
        frames,
        10,
    )?;
    // SAFETY: the boot CPU alone; the process table is quiescent here.
    unsafe {
        let manager = (&mut *&raw mut PROCESSES)
            .get_mut(manager_proc)
            .ok_or(20u32)?;
        for (object, rights) in [
            (WAKE_PORT_OBJ, Rights::READ),
            (WAKE_RTC_OBJ, Rights::READ | Rights::WAKE),
            (WAKE_POWER_OBJ, Rights::READ | Rights::WAKE),
            (WAKE_DEVICE_OBJ, Rights::READ | Rights::MAP),
            // **The same device, without the right.** In line rather than a
            // second boot: one capability can arm this line and the other
            // cannot, and what differs between them is the right alone.
            (WAKE_RTC_OBJ, Rights::READ),
        ] {
            manager
                .handles_mut()
                .install(object, rights)
                .map_err(|_| 21u32)?;
        }
    }

    // Arm the alarm and let the line through, strictly around the run.
    rtc_arm_alarm(WAKE_ALARM_SECONDS);
    tessera_karch_x86_64::unmask_irq(RTC_IRQ_LINE);
    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    // **Bounded by the clock, not by passes.** The manager parks on its port
    // with nothing else runnable, and what ends that is a device that fires on
    // a wall-clock second — however many times this loop goes round.
    let truncated = crate::msi::pump_for("wake", WAKE_BUDGET_MS, || {
        BIND_REPORT_COUNT.load(Ordering::SeqCst) >= 1
    });
    tessera_karch_x86_64::USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    tessera_karch_x86_64::mask_irq(RTC_IRQ_LINE);
    rtc_disarm();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    let outcome = if truncated { Err(30) } else { judge_wake() };

    // SAFETY: transient raw access; every thread is off-CPU, released once.
    unsafe {
        exec_ref().scheduler().reap(manager_thread);
        if let Some(mut gone) = (&mut *&raw mut PROCESSES).remove(manager_proc) {
            exec_ref().release_memory_of(gone.id(), frames, None);
            gone.space_mut().teardown(frames);
        }
    }
    // What this check declared from boot context goes back, for the reason the
    // votes above give.
    let _ = crate::observability::drain_ring();
    kstack_release(kernel_vm, kstacks, BIND_KSTACK_PAGES);
    outcome.map(Some)
}

/// Reads what the wake run left.
fn judge_wake() -> Result<WakeOutcome, u32> {
    use kcore::lifecycle::DriverState;

    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(31);
    }
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(32);
    }
    let reported = BIND_REPORTS[0].load(Ordering::SeqCst);
    if reported != WAKE_EXPECTED {
        return Err(33);
    }
    // **A real device raised it.** The manager's own count is what it saw; this
    // is what the machine saw, and one without the other would leave a report
    // nobody could corroborate.
    let deliveries = WAKE_DELIVERIES.load(Ordering::SeqCst);
    if deliveries == 0 {
        return Err(34);
    }
    // The device the manager idled is back in service, and the RTC is no longer
    // armed: the wake ended the arming rather than leaving a line live.
    if exec_ref().lifecycle_of_object(WAKE_DEVICE_OBJ) != Some(DriverState::Active) {
        return Err(35);
    }
    if exec_ref().is_wake_source(WAKE_RTC_OBJ) {
        return Err(36);
    }
    Ok(WakeOutcome {
        reported,
        deliveries,
    })
}
