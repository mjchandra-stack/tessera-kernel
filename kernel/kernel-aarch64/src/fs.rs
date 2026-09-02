// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A file read off a real ext2 volume, through the whole stack.
//!
//! Four programs, each already proved at its own level and none of that
//! establishing that they compose: `device-host` drives the disk,
//! `block-service` is the layer between, `fs-service` reads ext2 through it,
//! and `fs-client` asks what is in `/hello.txt` and checks every byte against
//! what `mke2fs` wrote there.
//!
//! **The volume is the second disk, and that is what keeps the two checks
//! apart.** The scratch disk every other check uses is written to — the
//! out-of-line round trip puts a sector on it — and those writes land where an
//! ext2 superblock lives. So a machine that runs this carries two, and this
//! check registers only the second: a fresh executive per check means the
//! device graph is this check's alone, and a one-disk machine simply skips.
//!
//! Normative: docs/storage/02-file-io-and-caching.md

use crate::host::{DeviceHostStack, bring_up_device_host, ring3_host_spawn};
use crate::{EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KernelAddressSpace, components};
use core::sync::atomic::Ordering;
use tessera_karch::FRAME_SIZE;
use tessera_karch::TimerControl;
use tessera_kcore as kcore;
use tessera_kcore::kprintln;

/// Object ids for this check's own topology, in a block of its own.
const FS_SERVICE_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c0);
const FS_SERVICE_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c1);
const FS_BLOCK_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c2);
const FS_BLOCK_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c3);
const FS_BLOCK_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c4);
const FS_SERVICE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c5);
const FS_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c6);
/// The endpoint the filesystem service answers **page requests** on.
const FS_PAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c7);
/// Its peer — the kernel's end, which no process is given a handle to. That is
/// what lets the kernel call the service without a process owning the caller's
/// side of the channel.
const FS_PAGER_KERNEL_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c8);

const FS_BLOCK_KSTACK_VA: u64 = 0xffff_000c_a000_0000;
const FS_SERVICE_KSTACK_VA: u64 = 0xffff_000c_b000_0000;
const FS_CLIENT_KSTACK_VA: u64 = 0xffff_000c_c000_0000;

/// Thirty-two pages for the client, where every other program here gets eight.
///
/// **Because it is the one that calls `ProcessCreate`**, which builds a 30 KB
/// `Process` inside a syscall, on the calling thread's kernel stack — the
/// arithmetic and what the overflow looks like on this port are in
/// [`ring3_host_spawn_with_stack`](crate::host::ring3_host_spawn_with_stack).
/// The root task has carried this number since D252 with a comment saying a
/// child that started processes of its own would need the same; this is that
/// child.
const FS_CLIENT_KSTACK_PAGES: u64 = 32;

/// The job the client is seeded, and the whole of what makes it a loader.
const FS_JOB_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c9);

/// What the program on the volume reports when it runs
/// (`userspace/disk-program`).
///
/// **A value nothing else in this tree writes.** The sink composes reporters by
/// XOR, so this term is in the expected sum exactly when a program that is in
/// no store, no accessor and no kernel image ran from the disk it was placed
/// on — which is the whole of Phase 2's third bullet.
pub(crate) const FS_DISK_PROGRAM_REPORT: u64 = 0x0d15_c0de_0d15_c0de;

/// What `fs-client` reports when it has opened `/hello.txt`, read it, checked
/// every byte against what `mke2fs` wrote, and seen a missing path refused.
///
/// Rotated like every other client's report so the sink is a value only this
/// sequence produces.
pub(crate) const FS_CLIENT_REPORT: u64 = u64::from_le_bytes(*b"TESSERAF").rotate_left(8);

/// What the sink holds when the check has passed.
///
/// The client's report **and the driver's**: `device-host` completes its ARP
/// round trip on the way up and reports the gateway MAC, and the sink composes
/// reporters by XOR. Both are load-bearing — a run where the driver never came
/// up, or one where the client never answered, gives a different value — which
/// is the whole reason the sink composes rather than overwrites.
/// The client's report, the driver's net round trip, **and the flush**.
///
/// The third is the durability chain made checkable in this stack too: a
/// `Sync` that this service answered from its own confidence, rather than
/// passing down to the device, never reaches `device-host` — and `device-host`
/// reports having seen exactly one flush per boot. Without it in the sum, a
/// filesystem that acknowledged durability it had not obtained would pass.
/// The fourth is **the program off the disk**: the client reads it through the
/// same filesystem path as every byte above, loads it into a process of its own
/// making, and starts it — and what lands in the sink is the child's own report
/// (`build/README.md`, D294). A boot that read the image and did not run it, or
/// ran something else, sums to a different value.
///
/// **The fifth is the program this machine made** (D304). The client reads a
/// *source* off the volume, compiles it, writes the program it produced back to
/// the same volume, reads that back and runs it — and what lands in the sink is
/// that program's own report. It is the one term here whose value exists in no
/// artifact the build produced.
/// What the program this machine **compiled** reports (`docs/roadmap/04` Phase
/// 2, D304).
///
/// **This number is in no build artifact.** It is what `/source.tsm` describes
/// — `0xc0de << 12, + 0xbee, << 4, + 0xf` — computed at run time by AArch64
/// instructions a program on this machine chose, in an image that program wrote
/// to the volume and then read back. Change the source and this changes; a
/// generator that emitted a fixed image would have to carry this constant, and
/// nothing does.
pub(crate) const FS_BUILT_PROGRAM_REPORT: u64 = 0xc0de_beef;

/// How many programs this machine compiled are expected to run: the one
/// `fs-client` builds itself, and the one `tsmc` builds when it is driven as a
/// program (D304, D307).
pub(crate) const FS_BUILT_PROGRAM_RUNS: usize = 2;

/// **The compiled programs are absent from this sum on purpose** (D309). Both
/// report the same value — they are built from the same source — and XOR
/// cancels a pair, so including one term would be wrong and including two would
/// be the same as including none. What says they ran is
/// [`FS_BUILT_PROGRAM_RUNS`], counted in the ordered reports, which is the axis
/// a sink does not have.
/// What the program **a previous boot compiled** reports (`docs/roadmap/04`
/// Phase 6).
///
/// `0x5e1f << 12, + 0xb00, << 4, + 7` — what `/gate.tsm` describes, performed by
/// instructions a boot of this machine chose, in an image that boot wrote to
/// the volume and did not run. This value is on no disk the build produced and
/// in no kernel image; what is here is the *expectation*, which is the only
/// half a check is allowed to carry.
pub(crate) const FS_GATE_PROGRAM_REPORT: u64 = 0x5e1f_b007;

/// What `fs-client` says about which half of the gate this boot performed.
///
/// Declared here as well as in the client for the reason every report constant
/// is: the check states what it expects and the program states what happened,
/// and a single shared definition would make agreement automatic rather than
/// checked.
pub(crate) const FS_GATE_STAGED_REPORT: u64 = 0x5e1f_ba5e_0000_0001;
pub(crate) const FS_GATE_RAN_REPORT: u64 = 0x5e1f_ba5e_0000_0002;

/// Which half of the gate a boot performed.
///
/// The volume decides, not the kernel: this is read back out of what the client
/// reported, and the two are different claims in the verdict because a boot
/// that staged a program and a boot that ran one have proved different things.
pub(crate) enum Gate {
    Staged,
    Ran,
}

pub(crate) const FS_SINK_EXPECTED: u64 = FS_CLIENT_REPORT
    ^ crate::host::RING3_NET_EXPECTED
    ^ crate::host::RING3_FLUSH_SEEN_EXPECTED
    ^ FS_DISK_PROGRAM_REPORT;

/// The check's executive, through one place rather than seven.
///
/// Every module here reaches the static the same way, and clippy objects to
/// the shape each time — its suggested fix is to name the `static mut`
/// directly, which edition 2024 forbids, so the finding is unactionable
/// wherever it appears (D183). Funnelling it through one function means this
/// module adds one instance of that argument rather than seven.
///
/// # Safety
///
/// The boot CPU alone. The caller must not keep this borrow across a channel
/// handoff — which is the obligation that can be met. "No other borrow" cannot
/// be: threads parked inside blocking executive methods hold theirs for as
/// long as they are parked (`kcore::exec::occupancy`, build/README.md D230).
unsafe fn exec() -> Option<&'static mut kcore::exec::Executive<crate::ContextSwitch>> {
    // SAFETY: the caller's obligation, restated: the boot CPU alone, with no
    // other live borrow.
    unsafe { crate::kcore_exec() }
}

/// The process table, through one place for the same reason.
///
/// # Safety
///
/// The boot CPU alone, with no other live borrow of the table.
unsafe fn processes() -> &'static mut kcore::process::ProcessTable<KernelAddressSpace> {
    // SAFETY: the caller's obligation, restated.
    unsafe { crate::kcore_processes() }
}

/// Runs the filesystem stack against the second disk.
///
/// `Ok(None)` when the machine has one disk, which is every other check's
/// machine: a skip, said out loud, rather than a pass nobody earned.
pub(crate) fn fs_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    ext2_base: Option<(u64, u64)>,
    blk_intid: Option<u32>,
    net_base: u64,
) -> Result<Option<(u64, Gate)>, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    let Some((ext2_base, _)) = ext2_base else {
        return Ok(None);
    };
    if components::fs_service().is_empty() || components::fs_client().is_empty() {
        return Ok(None);
    }

    // The shared bring-up, with the *ext2* volume as this check's block
    // device. Everything past it is this check's own.
    let DeviceHostStack {
        mut kernel_space,
        manager_idx,
        manager_proc,
        driver_idx,
        driver_proc,
        client_a_obj,
        client_b_obj: _,
        device_obj: _,
        blk_intid: intid,
    } = bring_up_device_host(high, frames, ext2_base, blk_intid, net_base)?;

    // Two more channels: the block service's, and the filesystem service's.
    // SAFETY: transient raw access to the static executive; the boot CPU alone.
    unsafe {
        let exec = exec().ok_or(600u32)?;
        let block = exec.channel_create().map_err(|_| 601u32)?;
        exec.bind_endpoint_object(block.0, FS_BLOCK_SERVER_OBJ);
        exec.bind_endpoint_object(block.1, FS_BLOCK_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 602u32)?;
        exec.bind_endpoint_object(service.0, FS_SERVICE_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, FS_SERVICE_CLIENT_OBJ);
        let pager = exec.channel_create().map_err(|_| 603u32)?;
        exec.bind_endpoint_object(pager.0, FS_PAGER_SERVER_OBJ);
        exec.bind_endpoint_object(pager.1, FS_PAGER_KERNEL_OBJ);
    }

    // Server-first the whole way down: each program must be parked on `recv`
    // before the one above it calls.
    let (block_idx, block_proc) = ring3_host_spawn(
        components::block_service(),
        FS_BLOCK_KSTACK_VA,
        0,
        FS_BLOCK_PROC_OBJ,
        &mut kernel_space,
        frames,
        610,
    )?;
    let (service_idx, service_proc) = ring3_host_spawn(
        components::fs_service(),
        FS_SERVICE_KSTACK_VA,
        0,
        FS_SERVICE_PROC_OBJ,
        &mut kernel_space,
        frames,
        620,
    )?;
    let (client_idx, client_proc) = crate::host::ring3_host_spawn_with_stack(
        components::fs_client(),
        FS_CLIENT_KSTACK_VA,
        FS_CLIENT_KSTACK_PAGES,
        0,
        FS_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        630,
    )?;

    // Each program holds exactly one channel down and one up, which is the
    // whole authority of a layer that drives no hardware.
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = processes();
        {
            let block = processes.get_mut(block_proc).ok_or(640u32)?;
            block
                .handles_mut()
                .install(client_a_obj, Rights::WRITE)
                .map_err(|_| 640u32)?;
            block
                .handles_mut()
                .install(FS_BLOCK_SERVER_OBJ, Rights::READ)
                .map_err(|_| 640u32)?;
        }
        {
            let service = processes.get_mut(service_proc).ok_or(641u32)?;
            service
                .handles_mut()
                .install(FS_BLOCK_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 641u32)?;
            service
                .handles_mut()
                .install(FS_SERVICE_SERVER_OBJ, Rights::READ)
                .map_err(|_| 641u32)?;
            // Handle 2: the endpoint page requests arrive on, and the authority
            // to answer for the objects bound to it. `SUPPLY` is what
            // `MemoryCreatePaged` requires of the endpoint it names as pager —
            // a service that could not supply must not be able to promise it.
            service
                .handles_mut()
                .install(FS_PAGER_SERVER_OBJ, Rights::READ | Rights::SUPPLY)
                .map_err(|_| 641u32)?;
        }
        {
            let client = processes.get_mut(client_proc).ok_or(642u32)?;
            // `TRANSFER` as well as `WRITE`, and the difference is the whole
            // of what this client became (D307). `WRITE` is the right to talk
            // to the service; `TRANSFER` is the right to let somebody *else*
            // talk to it, which is what a parent composing a child needs and
            // what `ProcessGrant` refuses without — `AccessDenied`, from a
            // grant of a capability this program legitimately held.
            //
            // Given here rather than assumed: a client that only reads files
            // still gets `WRITE` alone, and this one is a client that starts a
            // compiler.
            client
                .handles_mut()
                .install(FS_SERVICE_CLIENT_OBJ, Rights::WRITE | Rights::TRANSFER)
                .map_err(|_| 642u32)?;
            // **Handle 1: a job, and one right over it.** This is the seed that
            // makes the client a loader — everything else it needs to run a
            // program it reads for itself. Two capabilities, a filesystem and a
            // job, in one process: that composition is the whole of Phase 2's
            // third bullet, and nothing in this tree held both before.
            client
                .handles_mut()
                .install(FS_JOB_OBJ, Rights::CREATE_PROCESS)
                .map_err(|_| 642u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator to the syscall hook for the run only. Without
    // it every covered syscall fails at a distinct fault sink rather than
    // dereferencing null — which is how this check reported `0xbad2` the first
    // time it ran.
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        crate::EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    // **And the loader seam**, which the process-lifecycle syscalls are gated
    // on. It was the root task's alone, published for the duration of that
    // check and `None` everywhere else — an honest state while no other check
    // started a process. This one does, and it publishes the same seam the same
    // way: the mechanism was never the root task's, only its use of it.
    //
    // `kernel_space` moves in and is taken back below, because the loader is
    // what maps a child's kernel stack and the reclaim at the end of this
    // function needs the same space back.
    // SAFETY: the boot CPU alone; taken after the run, so no syscall can reach
    // a stale kernel space through it.
    unsafe {
        crate::roottask::ROOT_LOADER = Some(crate::roottask::AArch64Loader { kernel_space });
    }
    tessera_karch_aarch64::set_el0_sync_hook(crate::el0_dispatch_hook);
    // The driver's interrupt, wired strictly around the run.
    crate::RING3_DRIVER_INTID.store(intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(intid) };

    // The interrupt pump (D84/D85). A disk completion is asynchronous, so it
    // can land after every thread has parked — the driver on its interrupt
    // port, everyone above it inside a call — and `run()` returns with nothing
    // runnable. Without this the whole chain simply stops, which is what this
    // check reported the first time it ran: nobody exited.
    //
    // IRQs are unmasked every iteration, not once: returning from a thread
    // switch restores the boot context with `DAIF.I` set again, and `wfi`
    // wakes on a pending-but-masked interrupt without ever taking it.
    tessera_karch_aarch64::GenericTimer::start_periodic_this_cpu(crate::TICK_HZ);
    // **Either terminal sink, because this boot has two** (`docs/roadmap/04`
    // Phase 6). The pump's job is to know when the composition has finished,
    // and the gate gives a boot two ways to finish: it staged a program, or it
    // ran one an earlier boot staged. Judging *which* one it should have been
    // is the block after the loop — a termination test that also judged would
    // be one condition doing two jobs.
    //
    // **A stale constant here does not fail, it truncates.** The loop gives up
    // after its budget with every thread still parked mid-call, so the run ends
    // at whatever it happened to reach — and the point it stops at moves when
    // anything above it is reordered, which is what makes it read like
    // exhaustion in a different table each time (D310).
    let staged_sink = FS_SINK_EXPECTED ^ FS_GATE_STAGED_REPORT;
    let ran_sink = FS_SINK_EXPECTED ^ FS_GATE_RAN_REPORT ^ FS_GATE_PROGRAM_REPORT;
    let done = || {
        let log = EL0_SINK_LOG.load(Ordering::SeqCst);
        EL0_SINK_EXITED.load(Ordering::SeqCst) && (log == staged_sink || log == ran_sink)
    };
    // **Measured, not guessed, and it was the binding limit** (D310). This was
    // 500, which the composition before the gate used almost all of; adding a
    // third compiler run and a program to load took it past, and running out
    // does not *fail* — it returns with every thread parked mid-call, so the
    // boot ends wherever it happened to reach. That reads like a different
    // table being exhausted every time anything above is reordered, which is
    // how it was read three times before it was measured: 565 iterations for
    // the boot that stages the program and 727 for the boot that runs it.
    // Derived (D315): **three times the largest count ever observed, rounded
    // up to the next hundred, with a hundred as the floor.** Measured at **738** across
    // 26 runs including `--jobs=8`, so the rule wants 2214 — **more than the
    // 2000 this had**. It was set from a 727 measurement in D310 and the
    // composition has grown past it since; of the eight budgets derived here it
    // is the only one the rule *raises*, and the only one that was under it.
    const PUMP_BUDGET: u32 = 2300;
    // SAFETY: the boot CPU alone, and no other borrow of the executive is
    // live here — every thread is inside the run this drives.
    let pump_truncated = unsafe { crate::el0::pump("fs", PUMP_BUDGET, done) };
    // **A truncated run has not earned a verdict either way** (D311).
    // Judging the sink after the loop gave up compares a half-finished
    // composition against a complete one, and what comes back names
    // whichever call the last thread happened to be parked in. This is
    // measured headroom, not a guess: this uses 730 of 2000 at its heaviest.
    if pump_truncated {
        return Err(656);
    }

    crate::RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    // SAFETY: the boot CPU alone; the hook is done (every thread is off-CPU).
    unsafe { crate::EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the run is over; no syscall can reach the seam again.
    let loader = unsafe {
        (&raw mut crate::roottask::ROOT_LOADER)
            .as_mut()
            .and_then(Option::take)
    };
    let mut kernel_space = loader.ok_or(653u32)?.kernel_space;

    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    let faulted = EL0_SINK_FAULT.load(Ordering::SeqCst);
    let exited = EL0_SINK_EXITED.load(Ordering::SeqCst);

    // Back to the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    // **Before a single frame goes back.** The ring-3 driver registered its
    // queues with these transports and is about to stop existing; the devices
    // hold those physical addresses until reset, and the frames behind them
    // are handed to the next check within this boot. Found as a bogus
    // descriptor index in the log of the boot that first wrote to a disk.
    crate::virtio::quiesce(ext2_base);
    if net_base != 0 {
        crate::virtio::quiesce(net_base);
    }
    // SAFETY: transient raw access; every thread is off-CPU, removed once.
    unsafe {
        if let Some(exec) = exec() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(service_idx);
            exec.scheduler().reap(block_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
        let processes = processes();
        for (_idx, proc) in [
            (client_idx, client_proc),
            (service_idx, service_proc),
            (block_idx, block_proc),
            (driver_idx, driver_proc),
            (manager_idx, manager_proc),
        ] {
            if let Some(mut gone) = processes.remove(proc) {
                gone.space_mut().teardown(frames);
            }
        }
    }
    // The client's window is its own size, not the shared one: reclaiming eight
    // pages of a thirty-two-page stack would leave twenty-four mapped and their
    // frames unaccounted, which is the kind of leak only an exact count catches.
    for (kstack, pages) in [
        (FS_CLIENT_KSTACK_VA, FS_CLIENT_KSTACK_PAGES),
        (FS_SERVICE_KSTACK_VA, crate::host::RING3_HOST_KSTACK_PAGES),
        (FS_BLOCK_KSTACK_VA, crate::host::RING3_HOST_KSTACK_PAGES),
        (
            crate::host::RING3_DRIVER_KSTACK_VA,
            crate::host::RING3_HOST_KSTACK_PAGES,
        ),
        (
            crate::host::RING3_MANAGER_KSTACK_VA,
            crate::host::RING3_HOST_KSTACK_PAGES,
        ),
    ] {
        let _ = kernel_space.reclaim_range(
            tessera_karch::VirtAddr::new(kstack),
            pages * FRAME_SIZE,
            frames,
        );
    }

    // The fault value and the report are both carried out rather than folded
    // into a code, because "something faulted" and "which program, at what"
    // are different questions and only the second is actionable.
    if faulted != 0 {
        kprintln!(
            "fs: a ring-3 program faulted, sink {faulted:#x} at {:#x}, report {report:#x}",
            crate::EL0_SINK_FAULT_ADDR.load(Ordering::SeqCst),
        );
        // **Here too, and for the same reason** (D309, D310). A fault says a
        // program died and never which one; the ordered reports say how far the
        // composition got, which is the half that names it. This path was left
        // out when the sink path gained it, and every hour that cost was spent
        // on the difference.
        crate::el0::print_el0_reports("fs");
        return Err(650);
    }
    // Whether anyone exited separates a deadlock from a wrong answer, and the
    // two need different things looking at.
    if !exited {
        kprintln!("fs: nobody exited — every thread parked, report {report:#x}");
        return Err(652);
    }
    // **Which half of the gate this boot performed, read out of the ordered
    // reports rather than out of the sink.** Exactly one of the two is present
    // in any boot: the client emits `Staged` when it found no program on the
    // volume and compiled one, and `Ran` when it found one an earlier boot left
    // and ran it. Neither, or both, means the leg did not do what it says.
    let staged = crate::el0::el0_reports_equal_to(FS_GATE_STAGED_REPORT);
    let ran = crate::el0::el0_reports_equal_to(FS_GATE_RAN_REPORT);
    let gate = match (staged, ran) {
        (1, 0) => Gate::Staged,
        (0, 1) => Gate::Ran,
        _ => {
            kprintln!(
                "fs: the gate said staged {staged} time(s) and ran {ran}, wanted one of them once"
            );
            crate::el0::print_el0_reports("fs");
            return Err(654);
        }
    };
    // The two halves put different things in the sink, and the difference is
    // exactly what they did differently: the boot that ran the program carries
    // that program's own report and the boot that only staged it cannot.
    let expected = FS_SINK_EXPECTED
        ^ match gate {
            Gate::Staged => FS_GATE_STAGED_REPORT,
            Gate::Ran => FS_GATE_RAN_REPORT ^ FS_GATE_PROGRAM_REPORT,
        };
    if report != expected {
        kprintln!("fs: report {report:#x}, wanted {expected:#x}");
        // **The reports, not just their XOR.** A sink and a disagreement say
        // that something is wrong and never which program; this is the half
        // that names one (D309).
        crate::el0::print_el0_reports("fs");
        return Err(651);
    }
    // **And the compiled programs, counted rather than summed.** They report
    // the same value, so the sink cannot see them; this is what says both the
    // program `fs-client` built and the one `tsmc` built actually ran.
    let built = crate::el0::el0_reports_equal_to(FS_BUILT_PROGRAM_REPORT);
    if built != FS_BUILT_PROGRAM_RUNS {
        kprintln!("fs: {built} compiled program(s) ran, wanted {FS_BUILT_PROGRAM_RUNS}");
        crate::el0::print_el0_reports("fs");
        return Err(653);
    }
    // **And on the boot that ran it, the gate program said the right thing.**
    // The sink above already carries this term, but only as part of a sum: a
    // count says *this* program reported *this* value, which is the difference
    // between "the total is right" and "the program ran".
    if matches!(gate, Gate::Ran) {
        let seen = crate::el0::el0_reports_equal_to(FS_GATE_PROGRAM_REPORT);
        if seen != 1 {
            kprintln!("fs: the staged program reported {seen} time(s), wanted once");
            crate::el0::print_el0_reports("fs");
            return Err(655);
        }
    }
    Ok(Some((report, gate)))
}
