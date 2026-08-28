// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **root task on the second port**: what this machine lends
//! `kcore::loader`, and the check that a root task composes a system here.
//!
//! **This is what turns D251 from a refactor into a portability claim.** Moving
//! the process lifecycle out of x86-64's `main.rs` and into `kcore` proved
//! nothing on its own — a facility with one caller is a facility shaped like
//! its caller. What it has to survive is a second port whose every relevant
//! detail differs: this machine builds a user address space with
//! `build_low_space` (a third signature, after x86-64's `new_user` and the
//! RISC-V ports'), links its programs at `0x1000_0000_0000` rather than
//! `0x400000`, and needs twelve pages of user stack where x86-64 needs four.
//! None of that reached `kcore` — the seam is the same six methods
//! (build/README.md, D252).
//!
//! The check is the same composition x86-64 runs, from the same root-task
//! source: create a channel, load a real ELF, grant one endpoint into the
//! child, start it, supervise a service across restarts, and read back the
//! message the child sent on the capability it was given.
//!
//! Normative: docs/api/01-system-call-interface.md ("Process And Thread"),
//! docs/roadmap/03-composition-and-self-hosting.md (Phase 1)

// The crate root holds this machine's statics, its layout constants and its
// object ids, and every check reaches for them. Naming them one by one would be
// a list to maintain rather than a boundary.
use crate::host::components;
use crate::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tessera_karch::KError;

/// Kernel-stack windows the root task's children run on.
///
/// **A pool rather than the named constants the rest of this port uses.** Every
/// other EL0 program here has a window of its own picked at compile time
/// (`RING3_MANAGER_KSTACK_VA` and friends), which works because the boot glue
/// knows how many programs there are. A root task does not: it starts as many
/// children as its policy asks for, and the supervision check starts
/// forty-five. So they are taken at start and given back at reclaim, exactly as
/// x86-64 does it — the same shape, because the constraint is the mechanism's
/// and not the port's.
///
/// Well clear of the `0xffff_0000_?000_0000` windows the driver-host checks
/// use, so a boot that runs both does not have one standing on the other.
const ROOT_CHILD_KSTACK_BASE: u64 = 0xffff_0000_2000_0000;
const ROOT_CHILD_KSTACK_STRIDE: u64 = 0x0000_0000_1000_0000;
const MAX_ROOT_CHILDREN: usize = 4;
static ROOT_KSTACK_BUSY: [AtomicBool; MAX_ROOT_CHILDREN] =
    [const { AtomicBool::new(false) }; MAX_ROOT_CHILDREN];

/// Launches this check counted, so the boot can assert the supervisor ran its
/// policy exactly rather than approximately.
static ROOT_LAUNCHES: AtomicU64 = AtomicU64::new(0);

/// Launches the root task's run must produce: one for the grant probe,
/// forty-one to bring the recovering service up, three for the one it gives up
/// on, and two for the driver framework — the device manager and the driver it
/// binds.
///
/// Two more than x86-64 expects, and the difference is the whole of what this
/// port adds: the same program composes a framework here because this machine
/// seeded it a bus, and composes none there because that one did not.
pub(crate) const EXPECTED_ROOT_LAUNCHES: u64 = 1 + 41 + 3 + 2;

/// Counts one launch. Called by the port's dispatch hook on a start that
/// succeeded, because what a run produced is the check's question rather than
/// the mechanism's.
pub(crate) fn note_launch() {
    ROOT_LAUNCHES.fetch_add(1, Ordering::Relaxed);
}

/// What this machine lends `kcore::loader`.
///
/// Six methods, and each is here because `kcore` cannot answer it: how this
/// port builds a user address space, which alias of the kernel half a child's
/// stack goes in, where its kstack windows live, and how big the two stacks
/// are. The lifecycle itself is not here and must not be.
pub(crate) struct AArch64Loader {
    /// The kernel-high alias a child's kernel stack is mapped into, and whose
    /// windows the reclaim unmaps.
    pub(crate) kernel_space: kcore::vm::AddressSpace<KernelAddressSpace>,
}

impl kcore::loader::LoaderSupport<KernelAddressSpace> for AArch64Loader {
    fn new_user_space(
        &mut self,
        alloc: &mut dyn tessera_karch::FrameSource,
    ) -> Result<kcore::vm::AddressSpace<KernelAddressSpace>, KError> {
        use kcore::vm::{AddressSpace, Asid};
        // `build_low_space` rather than `new_user`: this port's user space
        // carries the device range identity-mapped, which is a fact about the
        // machine that `kcore` has no way to know.
        let arch = build_low_space(alloc, DIRECT_MAP_BASE, DEVICE_RANGE)?;
        Ok(AddressSpace::from_arch(arch, Asid(alloc_asid()), 0))
    }

    fn kernel_space(&mut self) -> &mut kcore::vm::AddressSpace<KernelAddressSpace> {
        &mut self.kernel_space
    }

    fn take_kernel_stack(&mut self) -> Option<VirtAddr> {
        for (slot, busy) in ROOT_KSTACK_BUSY.iter().enumerate() {
            if !busy.swap(true, Ordering::Relaxed) {
                return Some(VirtAddr::new(
                    ROOT_CHILD_KSTACK_BASE + slot as u64 * ROOT_CHILD_KSTACK_STRIDE,
                ));
            }
        }
        None
    }

    fn release_kernel_stack(&mut self, window: VirtAddr) {
        let offset = window.as_u64().wrapping_sub(ROOT_CHILD_KSTACK_BASE);
        let slot = (offset / ROOT_CHILD_KSTACK_STRIDE) as usize;
        if slot < MAX_ROOT_CHILDREN && offset.is_multiple_of(ROOT_CHILD_KSTACK_STRIDE) {
            ROOT_KSTACK_BUSY[slot].store(false, Ordering::Relaxed);
        }
    }

    fn user_stack_pages(&self) -> u64 {
        // The same twelve every compiled program on this port gets: a
        // `no_std` Rust program here holds buffers a blob never did, and the
        // measured floor is ten (`host::RING3_HOST_USER_STACK_PAGES`).
        crate::host::RING3_HOST_USER_STACK_PAGES
    }

    fn kernel_stack_pages(&self) -> u64 {
        // Eight, like every other EL0 program here: a channel operation parks
        // its whole dispatch frame on the kernel stack across a handoff.
        //
        // The root task's own is far larger (`ROOT_TASK_KSTACK_PAGES`) because
        // it is the one that calls `ProcessCreate`. A child that wanted to
        // start processes of its own would need the same, which is a thing to
        // discover when something does rather than to pay for now.
        crate::host::RING3_HOST_KSTACK_PAGES
    }
}

/// What the run produced.
pub(crate) struct RootTaskReport {
    /// The root task's own exit code. Zero only if every step it checked held.
    pub(crate) exit: i32,
    /// Launches the supervisor made.
    pub(crate) launches: u64,
    /// Rights the grant installed in the child, from the kernel's own record.
    pub(crate) granted: u64,
    /// What the driver the root task composed reported, or zero if it never
    /// reported at all.
    pub(crate) driver_report: u64,
    /// The interrupt line the root task routed to a port of its own, or zero
    /// on a machine that seeded it no device to route.
    pub(crate) irq: u32,
    /// Interrupts the kernel's own bridge delivered on that line during the
    /// run — the machine's count, independent of what the root task said about
    /// itself.
    pub(crate) irq_deliveries: u64,
}

/// Runs the root task: the kernel starts one process and nothing else.
///
/// **The whole of what boot does here is seed one job.** The root task creates
/// the channel, loads the programs, decides what each child holds, starts them
/// and supervises them. A check that still passed with the root task removed
/// would be measuring the boot glue it was meant to replace, which is why the
/// assertions below are about what the *root task* produced.
pub(crate) fn root_task_check(
    rtc: Option<&tessera_devicetree::MmioDevice>,
    high: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<Option<RootTaskReport>, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    if components::root_task().is_empty() {
        return Ok(None);
    }
    // A fresh executive: this check's threads are its own.
    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        crate::el0::kcore_exec_restart(7);
    }
    ROOT_LAUNCHES.store(0, Ordering::Relaxed);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &EL0_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    for busy in ROOT_KSTACK_BUSY.iter() {
        busy.store(false, Ordering::Relaxed);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down, and the loader maps children's kernel stacks through it.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // The root task's own process, built by boot because somebody has to start
    // the first one. Its kernel stack is a window of its own, outside the
    // children's pool.
    let root_obj = kcore::object::ObjectId::from_raw(70);
    let mut root_kernel = {
        // SAFETY: as above.
        let arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
        AddressSpace::from_arch(arch, Asid(0), 0)
    };
    let (root_thread, root_proc) = crate::host::ring3_host_spawn_with_stack(
        components::root_task(),
        ROOT_TASK_KSTACK_VA,
        ROOT_TASK_KSTACK_PAGES,
        // **The root task's own startup word, which it forwards to the driver
        // it composes.** Which report a machine's check expects is a fact about
        // the machine: this port's device is synthetic — registered with no
        // window, so that a machine with no disk attached still answers the
        // question the check is about — and the relay report is what such a
        // device can honestly answer. x86-64 seeds a real PCI function and asks
        // for the full probe. Passed rather than compiled in, so the root task
        // needs no `cfg` to serve both (build/README.md, D256).
        ROOT_DRIVER_RELAY_REPORT,
        root_obj,
        &mut root_kernel,
        frames,
        700,
    )?;

    // **The two seeds, and there are no others.** A job carrying
    // `create-process`, and a bus carrying the authority to enumerate what is
    // behind it. Every other capability in this run is one the root task made
    // or handed on — including every device the manager binds, which it
    // derives from this bus rather than being given.
    //
    // A small graph stands behind the bus, and its shape is the *driver's*
    // rather than this check's invention: `blk-probe` asks its manager for a
    // block device, then for another, then for a network device, and packs
    // all three answers into one word. Synthetic rather than the machine's
    // real virtio disk, because what this check is about is who composed the
    // framework — one that needed a disk attached would answer a different
    // question on a machine without one.
    let job_obj = kcore::object::ObjectId::from_raw(71);
    let bus_obj = kcore::object::ObjectId::from_raw(72);
    let device_obj = kcore::object::ObjectId::from_raw(73);
    let far_hub_obj = kcore::object::ObjectId::from_raw(74);
    let far_device_obj = kcore::object::ObjectId::from_raw(75);
    let far_net_obj = kcore::object::ObjectId::from_raw(76);
    let rtc_obj = kcore::object::ObjectId::from_raw(77);
    let bus_rights = Rights::READ | Rights::DERIVE;
    // SAFETY: transient raw access to the static executive; no thread runs.
    unsafe {
        let exec = crate::el0::kcore_exec().ok_or(715u32)?;
        // **The vendor is not decoration.** A manager charges a device's data
        // path by what the hubs above it are, and it can only do that for hubs
        // it can identify — a hub whose identity the manifest does not know is
        // refused `PathUndeclared` rather than treated as free. Giving the
        // bridges the storage vendor is exactly that case, and it is how this
        // check first came to report a refusal for all three binds.
        let identity = |class_code, vendor, device| kcore::devmgr::DeviceIdentity {
            class_code,
            vendor,
            device,
            bdf: 0,
            revision: 0,
            bus: kcore::devmgr::DeviceBus::Pci,
        };
        let bridge = |device| {
            identity(
                crate::power::RELAY_CLASS_BRIDGE,
                crate::power::RELAY_REDHAT_VENDOR,
                device,
            )
        };
        let function =
            |class_code, device| identity(class_code, crate::power::RELAY_VIRTIO_VENDOR, device);
        exec.device_register_identified(bus_obj, 0, 0, bus_rights, bridge(0x0001))
            .map_err(|_| 716u32)?;
        exec.device_register_identified(
            device_obj,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            function(crate::power::RELAY_CLASS_STORAGE, 0x1042),
        )
        .map_err(|_| 717u32)?;
        exec.device_set_parent(device_obj, bus_obj)
            .map_err(|_| 718u32)?;
        // The near device is registered before the hub that leads away from
        // it: the manager walks the graph in slot order and binds the first
        // *held* device of a class, so registering the hub first would send
        // the walk down the far branch and swap which device each answer is
        // about.
        exec.device_register_identified(far_hub_obj, 0, 0, bus_rights, bridge(0x0002))
            .map_err(|_| 716u32)?;
        exec.device_set_parent(far_hub_obj, bus_obj)
            .map_err(|_| 718u32)?;
        exec.device_register_identified(
            far_device_obj,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            function(crate::power::RELAY_CLASS_STORAGE, 0x1042),
        )
        .map_err(|_| 717u32)?;
        exec.device_set_parent(far_device_obj, far_hub_obj)
            .map_err(|_| 718u32)?;
        exec.device_register_identified(
            far_net_obj,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            function(crate::power::RELAY_CLASS_NETWORK, 0x1041),
        )
        .map_err(|_| 717u32)?;
        exec.device_set_parent(far_net_obj, far_hub_obj)
            .map_err(|_| 718u32)?;

        // **A real device, with a real interrupt line.** Everything above is
        // synthetic — a graph shaped like the one a bus controller would find,
        // standing in for hardware this machine may not have. This is not: it
        // is the machine's own real-time clock, at its own physical address,
        // on the line the device tree says it is on.
        //
        // The RTC for the reason D141 and D104 both chose it: it is real, on
        // its own line, and **owned by no driver**. A virtio device only
        // interrupts for a request somebody made, so using one would mean the
        // root task had to become a virtio driver before it could prove it
        // could route an interrupt — two claims tangled into one.
        //
        // `BIND` is the right that matters here and it is the whole point of
        // the seed: `MAP` lets the root task reach the registers, and `BIND`
        // is separately the authority to say where the line goes. A capability
        // with one and not the other is the negative this check inverts on.
        if let Some(rtc) = rtc
            && let Some(intid) = rtc.intid
        {
            exec.device_register_mmio(
                rtc_obj,
                rtc.base,
                FRAME_SIZE,
                Rights::READ | Rights::MAP | Rights::BIND | Rights::TRANSFER,
            )
            .map_err(|_| 720u32)?;
            exec.device_set_mmio_irq(rtc_obj, intid)
                .map_err(|_| 721u32)?;
        }
    }
    // SAFETY: transient raw access to the static process table; no thread runs.
    unsafe {
        let processes = crate::el0::kcore_processes();
        let root = processes.get_mut(root_proc).ok_or(710u32)?;
        root.handles_mut()
            .install(job_obj, Rights::CREATE_PROCESS)
            .map_err(|_| 711u32)?;
        // `TRANSFER` on top of what the manager will hold: handing a capability
        // on is itself an authority, and this is the process that hands it on.
        root.handles_mut()
            .install(bus_obj, bus_rights | Rights::TRANSFER)
            .map_err(|_| 719u32)?;
        // The third seed, on a machine that has an RTC: a device the root task
        // maps and whose interrupts it routes for itself. Where the first two
        // are authority over *making* things, this one is a piece of hardware —
        // which somebody has to be given, because nothing in a capability
        // system can conjure a device that was not there.
        if rtc.is_some_and(|rtc| rtc.intid.is_some()) {
            root.handles_mut()
                .install(rtc_obj, Rights::READ | Rights::MAP | Rights::BIND)
                .map_err(|_| 722u32)?;
        }
    }

    // Publish the loader seam and the boot allocator for the dispatch hook,
    // then run. The allocator is what every syscall that maps anything draws
    // from, and the hook ends a thread outright rather than dereferencing a
    // null one — so a check that forgets it gets a program that dies at its
    // first syscall with nothing to say.
    // SAFETY: the boot CPU alone; both are cleared after the run, and read
    // only from the hook while this run is on the CPU.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        ROOT_LOADER = Some(AArch64Loader { kernel_space });
        // The transmute only erases the borrow's lifetime; the pointer is used
        // strictly inside that borrow.
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(crate::el0_dispatch_hook);

    // **Let the device's line through, strictly around this run.** The bridge
    // that turns a GIC interrupt into a port signal claims exactly the INTID
    // published here (`ipc::virtio_irq_hook`), so a line enabled outside the
    // window a check owns the Executive in would have nowhere safe to land.
    let wired = rtc.and_then(|rtc| rtc.intid).unwrap_or(0);
    if wired != 0 {
        crate::ipc::RING3_IRQ_DELIVERIES.store(0, Ordering::SeqCst);
        crate::ipc::RING3_DRIVER_INTID.store(wired, Ordering::SeqCst);
        // SAFETY: enabling a GIC line is an interrupt-controller register
        // write.
        unsafe { tessera_karch_aarch64::enable_irq(wired) };
        tessera_karch_aarch64::GenericTimer::start_periodic_this_cpu(crate::TICK_HZ);
    }

    // The run, and on a machine with a wakeup source it is a **pump**.
    //
    // `run` returns when nothing is runnable, and a root task parked on a port
    // waiting for its device's interrupt is exactly that: the only thread on
    // the machine, blocked, with the thing that will wake it still a second
    // away. Without a boot context that waits for the line, the interrupt
    // arrives after everything has given up and the wake is orphaned.
    //
    // Unmasking every iteration is required rather than tidy — `wfi` returns
    // from a pending-but-masked interrupt without ever taking it, and coming
    // back from a thread switch restores the boot context with IRQs masked
    // again (D84, D141).
    let mut pump = ROOT_PUMP_BUDGET;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable
        // (a parked thread may become Ready from interrupt context).
        unsafe {
            crate::el0::kcore_exec().ok_or(712u32)?.run();
        }
        if wired == 0 || pump == 0 {
            break;
        }
        // SAFETY: transient raw access to the static process table; the run
        // has yielded the CPU back to boot and no thread is on it.
        let done = unsafe {
            matches!(
                crate::el0::kcore_processes()
                    .get(root_proc)
                    .map(kcore::process::Process::state),
                Some(kcore::process::ProcessState::Exited(_)) | None
            )
        };
        if done {
            break;
        }
        pump -= 1;
        // SAFETY: the boot context owns the CPU here; the only handler that
        // can run is the interrupt bridge, which touches the port facility,
        // never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    if wired != 0 {
        tessera_karch_aarch64::stop_timer();
        crate::ipc::RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
        // SAFETY: disabling a GIC line is an interrupt-controller register
        // write.
        unsafe { tessera_karch_aarch64::disable_irq(wired) };
    }
    // SAFETY: the run is over; the hook can no longer fire on this pointer.
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the run is over; no syscall can reach the seam again.
    let loader = unsafe { (&raw mut ROOT_LOADER).as_mut().and_then(Option::take) };
    let mut kernel_space = loader.ok_or(713u32)?.kernel_space;

    // SAFETY: transient raw access to the static process table; the run ended.
    let exit = unsafe {
        let processes = crate::el0::kcore_processes();
        match processes.get(root_proc).map(kcore::process::Process::state) {
            Some(kcore::process::ProcessState::Exited(code)) => code,
            // Not exited means the root task never got to. The EL0 sinks are
            // what say why: `0xbad2` is a check that forgot to publish the boot
            // allocator, `0xbad1` a syscall this port answers for nothing.
            other => {
                kprintln!(
                    "roottask: state {other:?} fault {:#x} exited={} reports={}",
                    EL0_SINK_FAULT.load(Ordering::SeqCst),
                    EL0_SINK_EXITED.load(Ordering::SeqCst),
                    EL0_REPORT_COUNT.load(Ordering::SeqCst),
                );
                return Err(714);
            }
        }
    };
    let granted = granted_rights_from_events();
    // What the driver reported through `DebugWrite`. The root task's own
    // report is the last entry, so the driver's is the one before it — but the
    // tag is what identifies it, not the position.
    // The driver reports first and the root task last, so slot 0 is the
    // driver's. Taken by position rather than by a tag, because the value it
    // packs has no spare bit to tag with — and reading a *tag* out of it was
    // how an earlier version of this check came to assert the opposite of what
    // it meant: `blk-probe`'s failure code has bit 61 set and its success does
    // not.
    let driver_report = EL0_REPORTS[0].load(Ordering::SeqCst);

    // **Teardown, and it has to be complete.** `ProcessWait` reclaims every
    // child; the root task itself is boot's to clean up, and a check that left
    // it behind would hand the next one a process table with a corpse in it —
    // a reaped thread still claimed by a `Process` is the shape that shows up
    // later as `AccessDenied` on a valid pointer.
    // SAFETY: transient raw access to the static executive and process table;
    // the run has ended and the thread is off-CPU.
    unsafe {
        let processes = crate::el0::kcore_processes();
        if let Some(exec) = crate::el0::kcore_exec()
            && let Some(thread) = exec.scheduler().reap(root_thread)
        {
            let _ = kernel_space.reclaim_range(
                thread.kernel_stack_base(),
                thread.stack_bytes(),
                frames,
            );
            if let Some(process) = processes.get_mut(root_proc) {
                process.forget_thread(thread.id());
            }
        }
        if let Some(mut process) = processes.remove(root_proc) {
            process.space_mut().teardown(frames);
        }
    }
    Ok(Some(RootTaskReport {
        exit,
        launches: ROOT_LAUNCHES.load(Ordering::Relaxed),
        granted,
        driver_report,
        irq: wired,
        irq_deliveries: crate::ipc::RING3_IRQ_DELIVERIES.load(Ordering::SeqCst),
    }))
}

/// The rights the most recent `PROCESS_GRANTED` event recorded, or zero if the
/// record is no longer in the ring.
///
/// **An observable, not the assertion.** The grant happens in the first few
/// syscalls of a run that then makes forty-five more launches, each emitting
/// events of its own, so the record is usually gone from a 256-entry ring by
/// the time this reads it. A boot where it survives prints it; a boot where it
/// does not is not a boot where the grant failed.
///
/// What the check asserts instead is stronger: the child *spoke* on the
/// endpoint it was granted, and the root task exits non-zero if that message
/// did not arrive. An audit record says a grant was made; a message arriving on
/// the far end of a channel the parent created says the capability it installed
/// actually carried authority.
fn granted_rights_from_events() -> u64 {
    use kcore::event;
    let blank = event::record(
        event::EventKind::EventsDropped,
        event::Severity::Debug,
        event::Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );
    let mut tail = [blank; 64];
    let n = event::tail(&mut tail);
    tail[..n]
        .iter()
        .rev()
        .find(|e| e.kind == event::EventKind::ProcessGranted)
        // `arg2` is the rights the *child* got, which is the number worth
        // asserting: the interesting mistake is a grant wider than intended.
        .map_or(0, |e| e.arg2)
}

/// The startup word this port gives its root task: `blk-probe`'s relay-report
/// mode (its own `RELAY_REPORT`, bit 61).
///
/// The root task hands it on to the driver unread. What it selects is a report
/// this port's *synthetic* device can answer — a bind status and how many relay
/// hops the path cost — where a real function would be asked for its identity
/// and a word from beyond its first page.
const ROOT_DRIVER_RELAY_REPORT: usize = 1 << 61;

/// How many times boot will park waiting for the root task's device to
/// interrupt before giving up.
///
/// **A bound, not a timeout.** The PL031 counts at 1 Hz, so the alarm the root
/// task arms is a whole second away and the pump ticks far faster than that.
/// What this number buys is that a line which never fires ends the run with the
/// root task merely parked — which the check reports as a state that is not
/// `Exited` — rather than hanging the machine until the harness kills it.
const ROOT_PUMP_BUDGET: u32 = 600;

/// The root task's own kernel stack, distinct from its children's pool and from
/// every driver-host window.
const ROOT_TASK_KSTACK_VA: u64 = 0xffff_0000_1000_0000;

/// Thirty-two pages, because a `ProcessCreate` builds a 30 KB `Process` inside
/// a syscall and eight are not enough — see
/// [`crate::host::ring3_host_spawn_with_stack`] for the arithmetic and for what
/// the overflow looks like on this port.
const ROOT_TASK_KSTACK_PAGES: u64 = 32;

/// The loader seam, published for the duration of a root-task run.
///
/// A static because the dispatch hook is a bare function the trap path calls
/// with nothing but a trap frame — the same reason `EL0_DISPATCH_FRAMES` is one.
/// `None` outside a run is the honest state: every other check on this port
/// starts no processes, and a syscall reaching the loader arms then is refused
/// rather than served against a stale kernel space.
pub(crate) static mut ROOT_LOADER: Option<AArch64Loader> = None;

/// The loader seam, through one place — the funnelling
/// `tools/ci/arch-lint-baseline.txt` asks for.
///
/// # Safety
///
/// The boot CPU alone, inside a root-task run, with no other live borrow.
pub(crate) unsafe fn root_loader() -> Option<&'static mut AArch64Loader> {
    // SAFETY: the caller's contract, restated.
    unsafe { (&raw mut ROOT_LOADER).as_mut().and_then(Option::as_mut) }
}
