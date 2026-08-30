// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A driver host crashes, is reclaimed, and is restarted.
//!
//! A real CPU fault in ring 3, contained; the supervisor reclaims the host's
//! resources, revokes and rebinds its device, and restarts it — until a budget
//! says to stop, which is the half that has to be shown too.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- Driver-host restart on crash ----------------------------------------
//
// A ring-3 driver host (the M16 service driver) crashes via a REAL CPU fault
// (#PF), the kernel contains it, and a kernel-driven supervisor reclaims the
// crashed host (M20 primitives), revokes + rebinds its device, and restarts it
// per a (countdown, budget) policy until it comes up clean and services the
// client. Closes the Stage-0 exit gate "kill-a-driver-host-under-load recovers"
// (docs/roadmap/01) and the Crash-Recovery ladder (docs/drivers/01, L221-233:
// revoke mappings/interrupts -> mark degraded -> restart host -> restore
// binding). All of it lives here in main.rs, reusing M16's driver/device path
// and M20's reclaim; no kcore change. See build/README.md D51.
//
// Normative: docs/architecture/01-system-architecture.md ("Failure Model":
// "Driver host restart after crash", "Device reset and rebind"),
// docs/drivers/01-driver-framework.md ("Crash Recovery").

/// The driver host + its client: ASIDs and kstack windows (a distinct VMAP
/// window each, clear of every prior demo's — 0x50-0x5c and 0x60 are taken by
/// M16/M17/M18/perf, so use the free 0x5e/0x62 windows). The host window is
/// reused every restart: M20 `reclaim_range` frees it on each crash before the
/// next spawn, and supervision is synchronous (one host alive at a time).
/// Hard cap on host launches (a persistently-crashing host is given up on),
/// well under the object/handle-table bounds; and the distinct give-up code the
/// supervisor reports (176 is the component manager's `CM_GIVEUP_CODE`).
pub(crate) const DRIVER_RESTART_BUDGET: u32 = 8;
pub(crate) const DRIVER_RESTART_GIVEUP_CODE: i32 = 177;
/// The budget the give-up self-test runs against — deliberately smaller than
/// its crash countdown, so the budget is what stops the loop. Named because
/// the ladder's event check derives its expected crash count from it rather
/// than repeating the number.
pub(crate) const DRIVER_RESTART_BUDGET_SELFTEST_BUDGET: u32 = 4;

// The restartable-driver blob: the M16 service driver, gated by a crash countdown passed
// in the ring-3 entry `arg` (rdi). While the countdown is non-zero the host
// null-derefs (a real #PF that routes to `driver_fault_handler`); at zero it runs
// the real device-service path (the code page is rx-only, so `arg`/rdi is the
// only channel for the supervisor's countdown).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global restartable_driver_program_start
.global restartable_driver_program_end
restartable_driver_program_start:
    test rdi, rdi                      # arg = crash countdown (entry arg in rdi)
    jz 2f                              # 0 -> serve path
    xor rcx, rcx                       # crash: deliberate null read -> #PF (RPL 3)
    mov rax, [rcx]                     #   -> driver_fault_handler
2:
    mov eax, 16                        # PortCreate -> port handle (raw 2)
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # PortBind
    syscall
    xor edi, edi                       # recv: arg0 unused
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # ChannelRecv (blocks for the client)
    syscall
    mov edi, 1                         # arg0 = device handle (raw 1)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte -> raises IRQ3 in ring 3
    mov eax, 20                        # DeviceIoWrite
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov eax, 18                        # PortWait -> drains the IRQ's port event
    syscall
    mov edi, 1                         # arg0 = device handle (raw 1)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # DeviceIoRead -> the looped byte
    syscall
    lea rdi, [rip + restartable_driver_reply_args]    # arg0 = ChannelMsgArgs (reply)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 15                        # ChannelReply (-> hands back to the client)
    syscall
1:
    jmp 1b
.balign 8
restartable_driver_reply_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + restartable_driver_pong_body - restartable_driver_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0
    .quad 0
restartable_driver_pong_body:
    .ascii "pong"
restartable_driver_program_end:
.text
"#
);

// SAFETY: names the restartable-driver blob bounds from the global_asm above; the extern
// block only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static restartable_driver_program_start: u8;
    pub(crate) static restartable_driver_program_end: u8;
}

/// The registered ring-3 fault handler for the driver-host supervisor. Like
/// `user_fault_handler`, but on the EXEC substrate (`EXEC`/`PROCESSES`, not the
/// single-process `USER_SCHEDULER`/`USER_PROCESS`): it contains a driver-host
/// crash (a real #PF), records it for the supervisor, marks the faulting process
/// `Exited`, terminates its thread, and `yield_to_boot`s so the kernel supervisor
/// loop (around `exec_ref().run()`) resumes to reclaim + restart it (D23 default
/// policy: contain and terminate; the kernel survives).
pub(crate) fn driver_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    USER_FAULT_ADDR.store(tessera_karch_x86_64::read_cr2(), Ordering::Relaxed);
    DRIVER_HOST_FAULTED.store(true, Ordering::Relaxed);
    DRIVER_HOST_FAULTS_SEEN.fetch_add(1, Ordering::Relaxed);
    // The dying host's cause, saved for the supervisor. Everything the
    // supervisor then does — contain, reclaim, rebind, restart — is *caused by*
    // this crash, so the ladder's records belong on this thread's trace rather
    // than on a fresh one. It has to be captured here because `yield_to_boot`
    // is about to leave this thread's context behind.
    DRIVER_HOST_CRASH_CORRELATION.store(kcore::trace::current().correlation, Ordering::Relaxed);
    report_contained_fault(frame.vector, tessera_karch_x86_64::read_cr2());
    // Both, and for the two different things each names: the identity resolves
    // the process in the machine-wide table, the slot is a scheduler operation
    // on this CPU.
    let slot = chan_current_index();
    let idx = chan_current_id();
    if let Some(idx) = idx {
        // SAFETY: the boot CPU alone; PROCESSES is populated before the ring-3 host runs
        // and touched only on this boot CPU.
        let processes = unsafe { &mut *&raw mut PROCESSES };
        if let Some(process) = processes.process_of_thread(idx) {
            process.exit(-1);
        }
    }
    // Terminate the faulting thread (skipped by `pop_ready`) and yield to boot;
    // the supervisor reaps + reclaims it after `run()` returns. Any `PROCESSES`
    // borrow above has ended before we touch the scheduler.
    if let Some(slot) = slot {
        exec_ref().scheduler().terminate(slot);
    }
    exec_ref().scheduler().yield_to_boot();
    // yield_to_boot switched to the boot context; this thread never resumes.
    loop {
        core::hint::spin_loop();
    }
}

/// Reclaims a crashed (or exited) driver host on the EXEC substrate — the M20
/// reclaim block adapted to `EXEC`/`PROCESSES`: frees the host's scheduler slot +
/// kernel stack (`reap` + `reclaim_range`), its process slot + address space
/// (`remove` + `teardown`), and releases its process object. It MUST NOT close
/// the host's device handle: dropping the host `Process` forgets that handle
/// *without* releasing it (there is no `Process` Drop impl), so the shared Device
/// capability's reference is conserved (rc stays 1) for the rebind into the next
/// host. The caller must re-activate `kernel_vm` first (the crashed host's CR3 is
/// active when the fault handler yields), so the kstack window is edited through
/// the direct map, not the active CR3 (one CPU here; invlpg suffices — a shootdown would
/// need a shootdown, deferred D50/D51).
pub(crate) fn reclaim_crashed_driver_host(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    host_tidx: usize,
    proc_obj: ObjectId,
) {
    if let Some(host_thread) = exec_ref().scheduler().reap(host_tidx) {
        let _ = kernel_vm.reclaim_range(
            host_thread.kernel_stack_base(),
            host_thread.stack_bytes(),
            frames,
        );
    }
    // SAFETY: the boot CPU alone; PROCESSES is populated before the host ran and touched
    // only on this boot CPU. The borrow ends before the OBJECTS access below.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    if let Some(pidx) = processes.index_of_id(proc_obj)
        && let Some(mut host) = processes.remove(pidx)
    {
        host.space_mut().teardown(frames);
    }
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS on this boot CPU.
    // Release the process object (bounds the object table across restarts); the
    // device object is deliberately left untouched (conserved for the rebind).
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let _ = objects.release(proc_obj);
}

/// Isolated driver-crash self-test: one driver host, built with a non-zero crash countdown,
/// null-derefs in ring 3; `driver_fault_handler` contains it and the supervisor
/// reclaims it. Proves the fault path + EXEC-substrate reclaim + device-capability
/// conservation, before the full restart loop.
pub(crate) fn driver_crash_reclaim_selftest(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::com2;
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(driver_fault_handler);
    DRIVER_HOST_FAULTED.store(false, Ordering::Relaxed);
    DRIVER_HOST_FAULTS_SEEN.store(0, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(u64::MAX, Ordering::Relaxed);
    USER_FAULT_ADDR.store(u64::MAX, Ordering::Relaxed);
    com2::init_loopback();
    // SAFETY: the boot CPU alone; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("driver-crash: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);

    let handed_before = frames.handed_out();
    let dblob = &raw const restartable_driver_program_start;
    let dlen = (&raw const restartable_driver_program_end as usize)
        - (&raw const restartable_driver_program_start as usize);
    let (mut host, tidx) = chan_build_process(
        kernel_vm,
        frames,
        driver_host_asid().0,
        dblob,
        dlen,
        driver_host_kstack_window(),
        1, // arg = crash countdown 1 -> null-derefs immediately
    );
    let proc_obj = host.id();
    if host
        .handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("driver-crash: FAIL — install device capability");
    }
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { host.space().activate(kcore::percpu::current_index()) };
    host.set_running();
    if processes_insert(host).is_err() {
        return kprintln!("driver-crash: FAIL — insert host process");
    }
    exec_ref().run(); // host null-derefs -> driver_fault_handler -> yield_to_boot
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    reclaim_crashed_driver_host(kernel_vm, frames, tidx, proc_obj);

    let faulted = DRIVER_HOST_FAULTED.load(Ordering::Relaxed);
    let vector = USER_FAULT_VECTOR.load(Ordering::Relaxed);
    let addr = USER_FAULT_ADDR.load(Ordering::Relaxed);
    let live = objects.is_live(dev_obj);
    let rc = objects.refcount(dev_obj);
    let net = frames.handed_out() - handed_before;
    let pass = faulted && vector == 14 && addr == 0 && live && rc == Some(1);
    report(&verdict(
        DemoId::DriverCrash,
        pass,
        [net, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "driver-crash: FAIL — faulted={faulted} vector={vector} addr={addr:#x} live={live} rc={rc:?} net={net}"
        );
    }
}

/// What one supervised driver-host run produced: launches + real crashes observed, whether
/// it reached a clean serve or gave up at the budget, the serve results (the M16
/// client round trip), the device capability's post-run liveness/refcount (the
/// conservation proof), and the run's bounded frame draw.
pub(crate) struct DriverRestartOutcome {
    pub(crate) launches: u64,
    pub(crate) faults: u64,
    pub(crate) served: bool,
    pub(crate) gave_up: bool,
    pub(crate) saw_ping: bool,
    pub(crate) saw_pong: bool,
    pub(crate) byte: u64,
    pub(crate) woken: bool,
    pub(crate) client_exit: i32,
    pub(crate) dev_live: bool,
    pub(crate) dev_rc: Option<usize>,
    pub(crate) handed_out_delta: u64,
    pub(crate) reclaim_overflows: u64,
}

/// Builds a fresh driver host from the restartable-driver blob with crash countdown `arg` (in
/// rdi) and **rebinds** the persistent device capability `dev_obj` into it (the
/// Crash-Recovery ladder's "restore binding"). `ep_obj` is the host's channel
/// endpoint on a clean serve attempt (installed at raw 0, device at raw 1);
/// `None` on a crash attempt (device at raw 0 — the host crashes before touching
/// any handle). Returns the host, its scheduler thread index, and its object id.
pub(crate) fn build_driver_host(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    arg: usize,
    dev_obj: ObjectId,
    ep_obj: Option<ObjectId>,
) -> Result<(Process<KernelAddressSpace>, usize, ObjectId), &'static str> {
    let dblob = &raw const restartable_driver_program_start;
    let dlen = (&raw const restartable_driver_program_end as usize)
        - (&raw const restartable_driver_program_start as usize);
    let (mut host, tidx) = chan_build_process(
        kernel_vm,
        frames,
        driver_host_asid().0,
        dblob,
        dlen,
        driver_host_kstack_window(),
        arg,
    );
    let proc_obj = host.id();
    if let Some(ep) = ep_obj {
        host.handles_mut()
            .install(ep, Rights::READ | Rights::WRITE)
            .map_err(|_| "install endpoint")?;
    }
    // The rebind: re-install the persistent device capability (refcount-neutral,
    // so the shared Device object stays rc=1 across every restart).
    host.handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .map_err(|_| "install device")?;
    Ok((host, tidx, proc_obj))
}

/// The driver-host supervise-restart loop. One `EXEC`/`PROCESSES`/`dev_obj` for the whole
/// run; the driver host is launched with a crash countdown, and each crash is
/// contained (`driver_fault_handler`), reclaimed (`reclaim_crashed_driver_host`), its device
/// binding revoked (implicit on teardown; `mask_irq`), then rebound into a fresh
/// host — until the countdown reaches 0 and the host comes up clean and services a
/// client, or the restart `budget` is spent (give up). `dev_obj` is created once
/// so it outlives every host; its reference is conserved (rc=1) throughout.
pub(crate) fn run_supervised_driver_host(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    countdown: u32,
    budget: u32,
) -> Result<DriverRestartOutcome, &'static str> {
    use tessera_karch_x86_64::{USER_IF_ON_ENTRY, com2, mask_irq, set_device_irq_hook, unmask_irq};
    // SAFETY: one-shot registration before this run's ring-3 threads run.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(driver_fault_handler);
    set_device_irq_hook(com2_driver_bridge_hook);
    DRIVER_HOST_FAULTED.store(false, Ordering::Relaxed);
    DRIVER_HOST_FAULTS_SEEN.store(0, Ordering::Relaxed);
    DRIVER_HOST_LAUNCHES.store(0, Ordering::Relaxed);
    CHAN_SERVER_SAW_PING.store(false, Ordering::Relaxed);
    CHAN_CLIENT_SAW_PONG.store(false, Ordering::Relaxed);
    CHAN_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    CHAN_CLIENT_TIDX.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0);
    // SAFETY: the boot CPU alone; fresh process table + executive for this run.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    // The device object + its DeviceTable node are created ONCE, before the loop,
    // so they outlive every (re)started host — the persistent binding target.
    let dev_obj = objects
        .create(ObjectType::Device)
        .map_err(|_| "device object")?;
    register_com2_device(dev_obj);

    let handed_before = frames.handed_out();
    let overflows_before = frames.reclaim_overflows();
    let mut cd = countdown;
    // The ladder's policy and its three records live in kcore
    // (`supervise::RestartSupervisor`), shared with every other port that runs
    // a supervisor. What stays here is the architecture work it cannot do:
    // building a host, containing its fault, and reclaiming the corpse.
    let mut sup = kcore::supervise::RestartSupervisor::new(budget);
    let mut served = false;

    loop {
        if cd == 0 {
            // CLEAN attempt: the host comes up and services a client (M16 wiring).
            served = true;
            let (driver_ep, client_ep) =
                exec_ref().channel_create().map_err(|_| "channel_create")?;
            let driver_ep_obj = objects
                .create(ObjectType::Channel)
                .map_err(|_| "driver ep object")?;
            let client_ep_obj = objects
                .create(ObjectType::Channel)
                .map_err(|_| "client ep object")?;
            exec_ref().bind_endpoint_object(driver_ep, driver_ep_obj);
            exec_ref().bind_endpoint_object(client_ep, client_ep_obj);
            let (mut host, _tidx, _proc_obj) =
                build_driver_host(kernel_vm, frames, 0, dev_obj, Some(driver_ep_obj))?;
            DRIVER_HOST_LAUNCHES.fetch_add(1, Ordering::Relaxed);
            sup.launched();
            let cblob = &raw const com2_driver_client_program_start;
            let clen = (&raw const com2_driver_client_program_end as usize)
                - (&raw const com2_driver_client_program_start as usize);
            let (mut client, client_tidx) = chan_build_process(
                kernel_vm,
                frames,
                alloc_asid().0,
                cblob,
                clen,
                alloc_kstack(USER_KSTACK_PAGES).as_u64(),
                0,
            );
            client
                .handles_mut()
                .install(client_ep_obj, Rights::READ | Rights::WRITE)
                .map_err(|_| "install client endpoint")?;
            CHAN_CLIENT_TIDX.store(
                thread_id_of(client_tidx).map_or(u64::MAX, |t| t.0),
                Ordering::Relaxed,
            );
            // SAFETY: the user space shares the kernel higher-half; the direct map
            // and boot stack stay mapped after the CR3 load.
            unsafe { host.space().activate(kcore::percpu::current_index()) };
            host.set_running();
            client.set_running();
            if processes_insert(host).is_err() {
                return Err("insert host");
            }
            if processes_insert(client).is_err() {
                return Err("insert client");
            }
            unmask_irq(COM2_IRQ_LINE);
            USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
            exec_ref().run();
            USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
            mask_irq(COM2_IRQ_LINE);
            // SAFETY: the kernel space maps this code and stack; active at boot.
            unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
            break;
        }
        if !sup.may_restart() {
            // Ladder's end: a host that keeps crashing is not restarted for
            // ever. The give-up is the loudest thing the supervisor does and
            // was previously only a console line.
            sup.give_up(DRIVER_RESTART_GIVEUP_CODE as u64);
            break;
        }
        // CRASH attempt: host only, crash countdown `cd` (non-zero → null-deref).
        DRIVER_HOST_FAULTED.store(false, Ordering::Relaxed);
        let (mut host, tidx, proc_obj) =
            build_driver_host(kernel_vm, frames, cd as usize, dev_obj, None)?;
        DRIVER_HOST_LAUNCHES.fetch_add(1, Ordering::Relaxed);
        sup.launched();
        // SAFETY: the host space maps its code/stack; the direct map + boot stack
        // stay mapped after the CR3 load.
        unsafe { host.space().activate(kcore::percpu::current_index()) };
        host.set_running();
        if processes_insert(host).is_err() {
            return Err("insert crash host");
        }
        exec_ref().run(); // host null-derefs → driver_fault_handler → yield_to_boot
        // SAFETY: the kernel space maps this code and stack; active at boot. Must
        // precede reclaim (the crashed host's CR3 was active when it yielded).
        unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
        // Ladder step 1, recorded: the host faulted and the kernel did not.
        // The vector and address come from the contained-fault handler, so the
        // record says what killed the host rather than merely that one died.
        //
        // Adopt the dead host's cause first. `run()` returned through
        // `yield_to_boot`, which left the ambient context on boot's own id, so
        // without this the ladder would root a fresh trace and nothing would
        // join a restart to the crash that provoked it — the exact failure the
        // envelope assertion in `report_driver_host_ladder` catches.
        kcore::trace::set_current_correlation(
            DRIVER_HOST_CRASH_CORRELATION.load(Ordering::Relaxed),
        );
        sup.crashed(
            USER_FAULT_VECTOR.load(Ordering::Relaxed),
            USER_FAULT_ADDR.load(Ordering::Relaxed),
        );
        mask_irq(COM2_IRQ_LINE); // ladder steps 1-2: revoke interrupts, mark degraded
        // The free-list depth, not `handed_out`: the latter is cumulative
        // ("frames handed out so far") and never decreases, so a delta across a
        // reclaim is always zero. Reclaim pushes the corpse's frames onto the
        // free list, and measuring either side of this one call is what
        // attributes them to this launch rather than to the boot.
        let free_before_reclaim = frames.free_list_depth();
        reclaim_crashed_driver_host(kernel_vm, frames, tidx, proc_obj);
        cd -= 1;
        // Ladder steps 6-7: the corpse is reclaimed and the loop will rebind
        // the conserved device into a fresh host. Frames reclaimed rides along
        // because a restart that leaks is still a restart — the leak has to be
        // visible per launch, not only in a final total.
        sup.restarted(frames.free_list_depth().saturating_sub(free_before_reclaim) as u64);
    }

    Ok(DriverRestartOutcome {
        launches: DRIVER_HOST_LAUNCHES.load(Ordering::Relaxed),
        faults: DRIVER_HOST_FAULTS_SEEN.load(Ordering::Relaxed),
        served,
        gave_up: sup.outcome().gave_up,
        saw_ping: CHAN_SERVER_SAW_PING.load(Ordering::Relaxed),
        saw_pong: CHAN_CLIENT_SAW_PONG.load(Ordering::Relaxed),
        byte: COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed),
        woken: COM2_DRIVER_WOKEN.load(Ordering::Relaxed),
        client_exit: CHAN_CLIENT_EXIT.load(Ordering::Relaxed),
        dev_live: objects.is_live(dev_obj),
        dev_rc: objects.refcount(dev_obj),
        handed_out_delta: frames.handed_out() - handed_before,
        reclaim_overflows: frames.reclaim_overflows() - overflows_before,
    })
}

/// The driver-host-restart gate: a driver host **crashes via a real #PF** a fixed number of times,
/// each crash contained + reclaimed + its device rebound, then it comes up clean
/// and services a client. Countdown 2, budget 8 → 2 crashes then a clean serve.
/// Closes the Stage-0 "kill-a-driver-host-under-load recovers" gate (docs/roadmap/01).
pub(crate) fn driver_restart_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    let outcome = match run_supervised_driver_host(kernel_vm, frames, 2, DRIVER_RESTART_BUDGET) {
        Ok(o) => o,
        Err(m) => return kprintln!("driver-restart: FAIL — {m}"),
    };
    // 2 real crashes (each reclaimed + rebound), then a 3rd launch comes up clean
    // and completes the M16 client round trip; the device cap is conserved (rc=1)
    // across the whole crash→reclaim→rebind→restart cycle, with no lost frames.
    let pass = outcome.faults == 2
        && outcome.launches == 3
        && outcome.served
        && outcome.saw_ping
        && outcome.saw_pong
        && outcome.byte == 0x5a
        && outcome.woken
        && outcome.client_exit == 0
        && outcome.dev_live
        && outcome.dev_rc == Some(1)
        && outcome.reclaim_overflows == 0;
    report(&verdict(
        DemoId::DriverRestart,
        pass,
        [outcome.faults, outcome.handed_out_delta, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "driver-restart: FAIL — faults={} launches={} served={} ping={} pong={} byte={:#x} woken={} client_exit={} rc={:?} overflows={}",
            outcome.faults,
            outcome.launches,
            outcome.served,
            outcome.saw_ping,
            outcome.saw_pong,
            outcome.byte,
            outcome.woken,
            outcome.client_exit,
            outcome.dev_rc,
            outcome.reclaim_overflows
        );
    }
}

/// Negative self-test: a driver host that keeps crashing is restarted only up
/// to the budget, then the supervisor gives up (it never runs away). Countdown 10
/// (never reaches 0) with budget 4 → exactly 4 crash launches then give-up; the
/// device binding is revoked and its reference is not leaked (rc stays 1).
pub(crate) fn driver_restart_budget_selftest(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    let outcome = match run_supervised_driver_host(
        kernel_vm,
        frames,
        10,
        DRIVER_RESTART_BUDGET_SELFTEST_BUDGET,
    ) {
        Ok(o) => o,
        Err(m) => return kprintln!("driver-restart-budget: FAIL — {m}"),
    };
    let pass = outcome.gave_up
        && !outcome.served
        && outcome.launches == u64::from(DRIVER_RESTART_BUDGET_SELFTEST_BUDGET)
        && outcome.faults == u64::from(DRIVER_RESTART_BUDGET_SELFTEST_BUDGET)
        && outcome.dev_live
        && outcome.dev_rc == Some(1)
        && outcome.reclaim_overflows == 0;
    report(&verdict(
        DemoId::DriverRestartBudget,
        pass,
        [
            outcome.launches,
            DRIVER_RESTART_GIVEUP_CODE as u64,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    ));
    if !pass {
        kprintln!(
            "driver-restart-budget: FAIL — gave_up={} served={} launches={} faults={} rc={:?} overflows={}",
            outcome.gave_up,
            outcome.served,
            outcome.launches,
            outcome.faults,
            outcome.dev_rc,
            outcome.reclaim_overflows
        );
    }
}
