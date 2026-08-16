// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 driver host: the programs this image carries, the verified
//! image store, and spawning a host to serve a class.
//!
//! Normative: docs/drivers/01-driver-framework.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

/// The ring-3 programs this image carries.
///
/// Under Bazel this is `//components:<arch>`, generated from the one list of
/// what the image is composed of. Under the cargo inner loop there is no such
/// crate — cargo builds no ring-3 ELFs — so the programs are absent and every
/// check that needs one reports it absent rather than failing to build.
#[cfg(has_components)]
pub(crate) use tessera_components as components;
#[cfg(not(has_components))]
pub(crate) mod components {
    pub fn device_host() -> &'static [u8] {
        &[]
    }
    pub fn device_manager() -> &'static [u8] {
        &[]
    }
    pub fn blk_probe() -> &'static [u8] {
        &[]
    }
    pub fn power_manager() -> &'static [u8] {
        &[]
    }
    pub fn blk_client() -> &'static [u8] {
        &[]
    }
    pub fn sd_host() -> &'static [u8] {
        &[]
    }
    pub fn nvme_driver() -> &'static [u8] {
        &[]
    }
    pub fn crypto_driver() -> &'static [u8] {
        &[]
    }
    pub fn crypto_client() -> &'static [u8] {
        &[]
    }
    pub fn certifier() -> &'static [u8] {
        &[]
    }
    pub fn gpu_driver() -> &'static [u8] {
        &[]
    }
    pub fn gpu_client() -> &'static [u8] {
        &[]
    }
    pub fn snd_driver() -> &'static [u8] {
        &[]
    }
    pub fn snd_client() -> &'static [u8] {
        &[]
    }
    pub fn platform_bus() -> &'static [u8] {
        &[]
    }
    pub fn gpio_driver() -> &'static [u8] {
        &[]
    }
    pub fn gpio_client() -> &'static [u8] {
        &[]
    }
    pub fn usb_host() -> &'static [u8] {
        &[]
    }
    pub fn usb_storage() -> &'static [u8] {
        &[]
    }
    pub fn usb_hid() -> &'static [u8] {
        &[]
    }
    pub fn input_client() -> &'static [u8] {
        &[]
    }
    pub fn pci_bus() -> &'static [u8] {
        &[]
    }
    pub fn net_driver() -> &'static [u8] {
        &[]
    }
    pub fn net_client() -> &'static [u8] {
        &[]
    }
}




/// The system image's verified store, where the build embedded one. Only the
/// Bazel build assembles it (`//store:system_store_image`); the cargo inner
/// loop builds without it and the check reports it absent, exactly as the
/// ring-3 images do.
#[cfg(has_system_store)]
pub(crate) fn system_store() -> &'static [u8] {
    &system_store_image::SYSTEM_STORE
}
#[cfg(not(has_system_store))]
pub(crate) fn system_store() -> &'static [u8] {
    &[]
}

/// Room for a working copy of the store. Sized for the container the build
/// produces with headroom; a store that outgrew it is refused loudly rather
/// than silently checked in part. Its size is this port's business — the check
/// itself is `kcore::store::self_check`, driven identically by every port.
pub(crate) const STORE_SCRATCH: usize = 8192;

/// Kernel stacks for the two host processes, distinct from every other EL0
/// kstack window. Both are 8 pages: a channel op parks its whole dispatch
/// frame on the kernel stack across the handoff (the IPC-check precedent).
pub(crate) const RING3_DRIVER_KSTACK_VA: u64 = 0xffff_0000_c000_0000;
pub(crate) const RING3_MANAGER_KSTACK_VA: u64 = 0xffff_0000_f000_0000;
pub(crate) const RING3_CLIENT_A_KSTACK_VA: u64 = 0xffff_0000_d000_0000;
pub(crate) const RING3_CLIENT_B_KSTACK_VA: u64 = 0xffff_0000_e000_0000;
pub(crate) const RING3_HOST_KSTACK_PAGES: u64 = 8;
/// The host programs run real compiled Rust: 4 user stack pages each.
pub(crate) const RING3_HOST_USER_STACK_PAGES: u64 = 4;
/// The clients' success reports: the disk magic rotated by each client's id
/// (1 and 2). The sink XOR-accumulates both plus the driver's net report, so
/// the expected value needs all three — each is load-bearing, and the
/// rotations keep the two clients' magic-dependent reports from cancelling.
pub(crate) const RING3_HOST_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");
/// The host's own net report: an "AR" tag over the SLIRP gateway's MAC
/// (52:55:0a:00:02:02 for 10.0.2.2 — deterministic), LE-packed. Matches the
/// device-host program's NET_REPORT_TAG construction.
pub(crate) const RING3_NET_EXPECTED: u64 = (0x4152 << 48) | 0x0202_000a_5552;
/// The driver's report that the kernel refused to make a client's buffer
/// reachable by its device — the protected-memory refusal, seen from the side
/// that asked for the attachment. Matches `device-host`'s `ATTACH_REFUSED_TAG`.
///
/// **Exactly one per boot**, because exactly one client classifies its buffer
/// and repeats one request. A second refusal, or none, changes the sink and
/// fails the check — which is what makes this evidence rather than decoration.
pub(crate) const RING3_ATTACH_REFUSED_EXPECTED: u64 = 0x4152_5f52 << 32;
pub(crate) const RING3_HOST_EXPECTED: u64 = RING3_HOST_MAGIC.rotate_left(8)
    ^ RING3_HOST_MAGIC.rotate_left(16)
    ^ RING3_NET_EXPECTED
    ^ RING3_ATTACH_REFUSED_EXPECTED;


/// Builds one host process from its ELF: fresh TTBR0 space, loaded segments,
/// user stack, kernel stack (in the shared `kernel_space` alias so the check
/// can unmap it at teardown), thread + process registered on the shared
/// executive substrate. Installs NO handles — the caller grants each process
/// exactly its authority. Error codes `base_err..base_err+10`.
pub(crate) fn ring3_host_spawn(
    image: &[u8],
    kstack_va: u64,
    arg: usize,
    process_obj: kcore::object::ObjectId,
    kernel_space: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch =
        build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| base_err + 7)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    let entry = kcore::elf::load_into(image, &mut user_space, frames, kcore::elf::Machine::AArch64, base_err)?;

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(kstack_va),
        VirtAddr::new(entry),
        arg,
        VirtAddr::new(USER_STACK_VA),
        RING3_HOST_USER_STACK_PAGES,
        VirtAddr::new(kstack_va),
        RING3_HOST_KSTACK_PAGES,
        process_obj,
        user_root,
        &mut user_space,
        kernel_space,
        frames,
    )
    .map_err(|_| base_err + 8)?;

    // SAFETY: transient raw access to the static executive and process table.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 9)?
            .scheduler()
            .add_thread(thread)
            .map_err(|_| base_err + 9)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(process_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 10)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| base_err + 10)?;
        }
    }
    Ok((thread_idx, proc_idx))
}

/// Proves the ring-3 driver **host** end-to-end (D81 + the resident serve
/// loop, D82): the blk driver self-tests its device, then serves TWO client
/// processes over one channel through the `ChannelReplyRecv` server loop —
/// each client `ChannelCall`s a `BlockReadRequest` for sectors 0 and 1, the
/// driver performs each virtio read and replies a `BlockReadReply` with the
/// sector's first bytes, and each client verifies its per-sector disk magic
/// crossed process, channel, and device. The payload protocol is a
/// user↔user ISL contract the kernel never decodes.
pub(crate) fn ring3_host_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blk_base: u64,
    blk_intid: Option<u32>,
    net_base: u64,
) -> Result<usize, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    // A fresh executive on the shared static: the scheduler, the channel, and
    // the device resource graph.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // The device tree must carry the blk device's interrupt — a missing one
    // is a fatal misconfiguration, never a silent poll downgrade (D84).
    let blk_intid = blk_intid.ok_or(190u32)?;
    let device_obj = kcore::object::ObjectId::from_raw(22);
    let net_device_obj = kcore::object::ObjectId::from_raw(23);
    let irq_port_obj = kcore::object::ObjectId::from_raw(40);
    let service_port_obj = kcore::object::ObjectId::from_raw(41);
    // One channel PER CLIENT (D85): each caller gets its own endpoint and so
    // its own outstanding-caller slot, which is what makes concurrent,
    // interrupt-driven serving correct (the D82 crossing was one shared slot).
    let server_a_obj = kcore::object::ObjectId::from_raw(50);
    let client_a_obj = kcore::object::ObjectId::from_raw(51);
    let server_b_obj = kcore::object::ObjectId::from_raw(52);
    let client_b_obj = kcore::object::ObjectId::from_raw(53);
    // The bind channel: the driver's only inbound authority at startup, and
    // the one thing it is told rather than discovers.
    let manager_proc_obj = kcore::object::ObjectId::from_raw(24);
    let manager_server_obj = kcore::object::ObjectId::from_raw(60);
    let manager_client_obj = kcore::object::ObjectId::from_raw(61);
    // SAFETY: transient raw access to the static executive.
    let (_channel_a, _channel_b) = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(156u32)?;
        exec.device_register_mmio(
            device_obj,
            blk_base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 157u32)?;
        exec.device_register_mmio(
            net_device_obj,
            net_base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 189u32)?;
        exec.device_set_mmio_irq(device_obj, blk_intid)
            .map_err(|_| 191u32)?;
        // The IRQ→port bridge, recorded in the graph as a **route** rather
        // than installed as a bare port binding.
        //
        // The difference is what happens when the driver goes. A bare binding
        // is a fact only the boot glue knows, so nothing takes it down: the
        // line keeps firing into a port whose holder is gone, and the next
        // driver granted this device finds its own interrupts arriving
        // somewhere it cannot reach. Routing it through the graph makes the
        // interrupt follow the capability the way the register window and the
        // DMA lease already do (D93, D123).
        //
        // The holder named here is `device_obj` because that is also the
        // driver's process object in this check — `ring3_host_spawn` is given
        // it as the process id below. One value, two roles, which is a quirk
        // of this check's numbering and not of the mechanism.
        let irq_port = exec.port_create().map_err(|_| 192u32)?;
        exec.bind_port_object(irq_port, irq_port_obj);
        exec.device_route_irq(device_obj, irq_port, device_obj)
            .map_err(|_| 193u32)?;

        // A per-client channel each, and one SERVICE port bound to both
        // server-side endpoint objects: a message arriving on either raises
        // SIGNAL_MESSAGE on that endpoint's object, so the host's single
        // `PortWait` is a select that names which client to serve (D85).
        let a = exec.channel_create().map_err(|_| 158u32)?;
        exec.bind_endpoint_object(a.0, server_a_obj);
        exec.bind_endpoint_object(a.1, client_a_obj);
        let b = exec.channel_create().map_err(|_| 194u32)?;
        exec.bind_endpoint_object(b.0, server_b_obj);
        exec.bind_endpoint_object(b.1, client_b_obj);

        // The manager's service channel. Not bound to the service port: the
        // driver *calls* the manager at startup and then never hears from it
        // again, so it is not part of the select.
        let m = exec.channel_create().map_err(|_| 199u32)?;
        exec.bind_endpoint_object(m.0, manager_server_obj);
        exec.bind_endpoint_object(m.1, manager_client_obj);

        let service_port = exec.port_create().map_err(|_| 195u32)?;
        exec.bind_port_object(service_port, service_port_obj);
        exec.port_bind(
            service_port,
            u64::from(server_a_obj.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 196u32)?;
        exec.port_bind(
            service_port,
            u64::from(server_b_obj.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 197u32)?;
        (a, b)
    };

    // One kernel-high alias holds both kernel stacks, so teardown can unmap
    // them. SAFETY: `high` is the active kernel high-half; the alias is never
    // torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // The manager spawns first, for the same server-first reason the driver
    // does: it must be parked on `recv` before the driver's bind call. A
    // racing call would queue and park harmlessly either way.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        RING3_MANAGER_KSTACK_VA,
        // Its startup argument is the number of device capabilities installed
        // below — the whole of its bootstrap contract with boot.
        2,
        manager_proc_obj,
        &mut kernel_space,
        frames,
        200,
    )?;
    // The driver spawns next so it parks on `recv` before the clients call
    // (the M38 server-first pattern).
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::device_host(),
        RING3_DRIVER_KSTACK_VA,
        0,
        device_obj,
        &mut kernel_space,
        frames,
        160,
    )?;
    // Two clients (ids 1 and 2 → their report rotations), each on its OWN
    // channel. That is what makes concurrent interrupt-driven serving correct:
    // the driver may park on its device interrupt mid-request while the other
    // client calls, and each caller's reply is matched by its own endpoint's
    // outstanding-caller slot rather than one shared one (D82 → D85).
    let (client_a_idx, client_a_proc) = ring3_host_spawn(
        components::blk_client(),
        RING3_CLIENT_A_KSTACK_VA,
        1,
        client_a_obj,
        &mut kernel_space,
        frames,
        172,
    )?;
    let (client_b_idx, client_b_proc) = ring3_host_spawn(
        components::blk_client(),
        RING3_CLIENT_B_KSTACK_VA,
        2,
        client_b_obj,
        &mut kernel_space,
        frames,
        198,
    )?;

    // Each process gets exactly its authority, and the device capabilities no
    // longer go to the driver. The **manager** holds every device: its service
    // endpoint at handle 0, then the blk and net capabilities at 1 and 2, with
    // TRANSFER — handing a capability to another process is itself a right,
    // granted here and nowhere else. The driver holds no device at all until
    // it asks for one by class; it starts with the bind channel at handle 0,
    // its interrupt port at 1, the service port at 2, and the two per-client
    // server endpoints at 3 and 4. Client: only its endpoint, at handle 0.
    //
    // Install order is still the bootstrap ABI each program mirrors — what
    // changed is that no entry in it says *which device* anything is.
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(201u32)?;
            manager
                .handles_mut()
                .install(manager_server_obj, Rights::READ)
                .map_err(|_| 201u32)?;
            manager
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
                .map_err(|_| 201u32)?;
            manager
                .handles_mut()
                .install(
                    net_device_obj,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 201u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(183u32)?;
            driver
                .handles_mut()
                .install(manager_client_obj, Rights::WRITE)
                .map_err(|_| 183u32)?;
            driver
                .handles_mut()
                .install(irq_port_obj, Rights::READ)
                .map_err(|_| 183u32)?;
            driver
                .handles_mut()
                .install(service_port_obj, Rights::READ)
                .map_err(|_| 183u32)?;
            driver
                .handles_mut()
                .install(server_a_obj, Rights::READ)
                .map_err(|_| 183u32)?;
            driver
                .handles_mut()
                .install(server_b_obj, Rights::READ)
                .map_err(|_| 183u32)?;
        }
        for (proc_idx, endpoint) in [(client_a_proc, client_a_obj), (client_b_proc, client_b_obj)] {
            let client = processes.get_mut(proc_idx).ok_or(183u32)?;
            client
                .handles_mut()
                .install(endpoint, Rights::WRITE)
                .map_err(|_| 183u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator to the hook for the run only.
    // SAFETY: `frames` outlives the run; the pointer is cleared before returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // Wire and enable the device interrupt strictly around the run (the x86
    // COM2 discipline): boot code never touches the Executive inside this
    // window, so the interrupt-context port_signal cannot alias a live
    // borrow.
    RING3_DRIVER_INTID.store(blk_intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(blk_intid) };
    // The interrupt pump (D84): a device completion is asynchronous, so it
    // can land after every thread has parked (the host on its interrupt
    // port, the clients in their calls) — `run()` then returns with nothing
    // runnable and the wake would be orphaned. The boot context is the idle
    // loop: re-run whenever an interrupt lands (each wait bounded by the
    // periodic tick), until the check completes or the budget is spent.
    // Between runs boot touches only atomics — never the Executive — so the
    // interrupt-context bridge stays alias-free.
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // The boot context masks IRQs at reset and nothing has unmasked them
    // since: only a kernel thread's trampoline (`daifclr, #2`) and an EL0
    // thread's SPSR run with `DAIF.I` clear. So an interrupt taken "while
    // idle" is a contradiction unless boot unmasks here — `wfi` wakes on a
    // pending-but-masked interrupt and returns without ever taking it, and
    // the pump spins its whole budget while the completion sits asserted.
    // (D85: the reason a driver parked with no other thread runnable was
    // never woken; D84 only ever took its one interrupt because a client
    // thread happened to be running when it landed.) Unmasking is re-done
    // every iteration: returning from a thread switch restores the boot
    // context with IRQs masked again.
    let done = || {
        EL0_SINK_EXITED.load(Ordering::SeqCst)
            && EL0_SINK_LOG.load(Ordering::SeqCst) == RING3_HOST_EXPECTED
    };
    let mut pump_budget = 500u32;
    loop {
        // SAFETY: transient raw access; `run` returns when no thread is
        // runnable (parked threads may become Ready from interrupt context).
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if done() || pump_budget == 0 {
            break;
        }
        pump_budget -= 1;
        // Sleep until any interrupt (the device's, or the bounding tick);
        // the handler runs here at EL1 and may ready the host.
        // SAFETY: the boot context owns the CPU here; the only handler that
        // can run is the interrupt bridge, which touches atomics and the
        // port facility, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();
    // **The driver's interrupt route ends with the driver, and the kernel is
    // what ends it.** Everything above this line is the D84 bridge working;
    // this is the half that was missing. The supervisor names no INTID and no
    // port — it does not know which interrupts this driver was receiving, and
    // does not need to, exactly as it does not know which devices it held. The
    // graph does.
    //
    // Done before the corpse is torn down, for the reason a DMA lease is: a
    // route lives in the GIC and in the port table, both of which would
    // outlive the process entirely.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let routes_ended = unsafe {
        let mut router = GicRouter;
        match (
            (*(&raw mut KCORE_EXEC)).as_mut(),
            (*(&raw mut KCORE_PROCESSES)).get_mut(driver_proc),
        ) {
            (Some(exec), Some(driver)) => exec.end_device_irq_routes(driver, Some(&mut router)),
            _ => 0,
        }
    };
    if routes_ended != 1 {
        return Err(186);
    }
    // The route is gone and the line is masked by the revocation above, so
    // this is belt-and-braces on a line the driver's departure already closed.
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(blk_intid) };
    RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    // Nothing routes this device's interrupts any more — the claim, checked
    // rather than assumed, because "the graph forgot" and "the graph was never
    // told" look identical afterwards.
    // SAFETY: transient raw access; every thread is off-CPU.
    if unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
        .and_then(|exec| exec.irq_route_of_object(device_obj))
        .is_some()
    {
        return Err(187);
    }
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(184);
    }
    // The accumulated report: both clients' rotated-magic DebugWrites XORed
    // on success; any failure code from any of the three programs perturbs
    // it (surfaced by the FATAL line for diagnosis).
    if EL0_SINK_LOG.load(Ordering::SeqCst) != RING3_HOST_EXPECTED {
        return Err(185);
    }

    // Teardown: reap all three threads (clients Exited, the resident driver
    // parked Blocked inside its reply-receive — reap accepts an off-CPU
    // Blocked thread), free the kernel stacks, and remove the processes
    // (reclaiming segments, stacks, and the DMA buffer — tracked mappings).
    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_a_idx);
            exec.scheduler().reap(client_b_idx);
            exec.scheduler().reap(driver_idx);
            // The manager is parked in `recv` on its bind channel, having
            // handed out both devices and heard nothing since.
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        RING3_DRIVER_KSTACK_VA,
        RING3_CLIENT_A_KSTACK_VA,
        RING3_CLIENT_B_KSTACK_VA,
        RING3_MANAGER_KSTACK_VA,
    ] {
        for page in 0..RING3_HOST_KSTACK_PAGES {
            if let Ok(frame) = kernel_space
                .arch_mut()
                .unmap(VirtAddr::new(kstack + page * FRAME_SIZE))
            {
                frames.free_frame(frame);
            }
        }
    }
    // SAFETY: transient raw access; each process is removed and torn down once.
    let mut grant_frames_released = 0usize;
    unsafe {
        for proc_idx in [client_a_proc, client_b_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                // **A memory object outlives its creator's handle table.** A
                // process forgets its handles on drop by design (driver
                // restart depends on it), so nothing else would ever release
                // the frames behind a grant that was still held at exit — and
                // an object is exactly the thing whose owner may have died
                // holding it. Runs before teardown, though the refcounting
                // makes either order sound: teardown releases the *mapping's*
                // reference and this releases the object's.
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    // No mapper: this host runs on a machine with no SMMU in
                    // front of its virtio transports, so every attachment here
                    // is unscoped and has no translation to tear down. A
                    // machine that did would hand its `Smmu` in, and passing
                    // `None` there would leave a device reaching freed frames.
                    grant_frames_released += exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }

    Ok(grant_frames_released)
}

// --- The network class, served from ring 3 (D150) --------------------------

pub(crate) const NET_CLASS_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe0);
pub(crate) const NET_CLASS_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe1);
pub(crate) const NET_CLASS_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe2);
pub(crate) const NET_CLASS_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe3);
pub(crate) const NET_CLASS_EVENT_DRIVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe4);
pub(crate) const NET_CLASS_EVENT_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe5);
pub(crate) const NET_CLASS_MANAGER_SERVER_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xe6);
pub(crate) const NET_CLASS_MANAGER_CLIENT_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xe7);
pub(crate) const NET_CLASS_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe8);
pub(crate) const NET_CLASS_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe9);
pub(crate) const NET_CLASS_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xea);

pub(crate) const NET_CLASS_MANAGER_KSTACK_VA: u64 = 0xffff_0004_a000_0000;
pub(crate) const NET_CLASS_DRIVER_KSTACK_VA: u64 = 0xffff_0004_b000_0000;
pub(crate) const NET_CLASS_CLIENT_KSTACK_VA: u64 = 0xffff_0004_c000_0000;

/// What the client must report, and every bit of it is load-bearing.
///
/// Low 48 bits: the gateway's MAC as the ARP resolved it (`52:55:0a:00:02:02`,
/// SLIRP's), which only a completed round trip through the granted buffer can
/// produce. Then, in order: the frame arrived **in a memory object** rather
/// than copied inline; both link transitions were announced; a transmit while
/// the link was down answered `LINK_DOWN`; and the class conformance suite came
/// back *complete* — every rule reached and held, not merely nothing failed.
/// The top byte tags the reporter.
pub(crate) const NET_CLASS_EXPECTED: u64 = 0x4e0f_0202_000a_5552;

