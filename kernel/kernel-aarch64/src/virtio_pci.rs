// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! virtio over PCI: finding a function's regions, and what happens when one
//! is removed while a driver holds it.
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// The stream id a PCI function's DMA arrives at the SMMU under.
///
/// It is the function's RID, because this machine's `iommu-map` is the
/// identity map (verified from the device tree). A machine with a non-identity
/// map needs the property parsed; this one would report a different stream in
/// its fault records, which is how it would be caught.
pub(crate) fn stream_id_of(function: &tessera_pci::Function) -> u32 {
    (u32::from(function.bdf.bus) << 8)
        | (u32::from(function.bdf.device) << 3)
        | u32::from(function.bdf.function)
}

/// Resolves a virtio-pci function's configuration structures to direct-map
/// addresses by walking its vendor capabilities.
///
/// A virtio-pci device does not say where its controls are in any register —
/// it says so in **config space**, one vendor-specific capability per
/// structure, each naming a BAR and an offset within it. There are several of
/// them, which is why the walk has to be resumable
/// ([`tessera_pci::find_capability_from`]): stopping at the first match finds
/// whichever structure the device happened to list first and misses the rest.
pub(crate) fn virtio_pci_regions(
    host: &tessera_devicetree::PciHost,
    function: &tessera_pci::Function,
) -> Option<virtio::PciRegions> {
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let cfg = EcamWindow {
        base: host.ecam_base,
    };
    let device_type = tessera_virtio::pci::device_type(function.device)?;

    let mut regions = virtio::PciRegions {
        common: 0,
        notify: 0,
        notify_multiplier: 0,
        isr: 0,
        device_cfg: 0,
        device_type,
        bar_base: 0,
        bar_len: 0,
        capabilities: 0,
    };
    let mut at = None;
    // Bounded by the capability list itself; `find_capability_from` refuses a
    // chain that loops or runs past the header.
    while let Ok(Some(offset)) =
        tessera_pci::find_capability_from(&bridge, &cfg, function.bdf, tessera_pci::CAP_VENDOR, at)
    {
        at = Some(offset);
        regions.capabilities += 1;
        let word = |i: u16| bridge.read(&cfg, function.bdf, offset + i * 4).unwrap_or(0);
        let cap = tessera_virtio::pci::decode_cap([word(0), word(1), word(2), word(3)]);
        let Some((bar_base, bar_len)) = function.bars.get(cap.bar as usize).copied().flatten()
        else {
            continue; // a structure in a BAR that was not placed is unreachable
        };
        // The device's own numbers, so they are checked before they are trusted.
        if u64::from(cap.offset) + u64::from(cap.length) > bar_len {
            continue;
        }
        let at_addr = DIRECT_MAP_BASE + bar_base + u64::from(cap.offset);
        match cap.cfg_type {
            tessera_virtio::pci::cfg_type::COMMON => {
                regions.common = at_addr;
                // The BAR the controls are in is the one a driver must be
                // granted; the structures are offsets within it.
                regions.bar_base = bar_base;
                regions.bar_len = bar_len;
            }
            tessera_virtio::pci::cfg_type::NOTIFY => {
                regions.notify = at_addr;
                // The multiplier follows the standard capability, and only a
                // notify capability carries it.
                regions.notify_multiplier = word(4);
            }
            tessera_virtio::pci::cfg_type::ISR => regions.isr = at_addr,
            tessera_virtio::pci::cfg_type::DEVICE => regions.device_cfg = at_addr,
            _ => {}
        }
    }
    // Without all three there is no transport to build; saying so beats
    // building one over address zero.
    if regions.common == 0 || regions.notify == 0 || regions.isr == 0 {
        return None;
    }
    Some(regions)
}

/// The PCI base class the manager maps to `DeviceClass::Block`. The kernel
/// needs it only to pick a function worth handing the manager; the
/// classification itself is the manager's, from the identity the graph holds.
pub(crate) const PCI_CLASS_MASS_STORAGE: u32 = 0x01;

/// Whether `f` is a **virtio** mass-storage function.
///
/// The class alone stopped being enough when a second storage transport
/// arrived: an NVMe controller is mass storage too, and every check that went
/// looking for "the block device" by class found whichever the walk listed
/// first. The one that hunts for virtio capabilities then declared a fatal
/// error about a controller that never claimed to have any.
pub(crate) fn is_virtio_storage(f: &tessera_pci::Function) -> bool {
    f.class_code >> 16 == PCI_CLASS_MASS_STORAGE && f.vendor == RELAY_VIRTIO_VENDOR
}
/// The PCI class byte for a network controller.
pub(crate) const PCI_CLASS_NETWORK: u32 = 0x02;
/// Base class 0x06 subclass 0x04 — a PCI-to-PCI bridge, which is what a
/// `pcie-root-port` presents as and what a device sits behind to be removable.
pub(crate) const PCI_CLASS_PCI_BRIDGE: u32 = 0x0604;

/// How far into a device's window the ring-3 driver reads to show it was
/// granted the whole thing. Must match `FAR_OFFSET` in `userspace/blk-probe`.
pub(crate) const FAR_WINDOW_OFFSET: u64 = 0x2000;

/// The tag `blk-probe` folds into a report about a device it was told the
/// identity of rather than read — `"PC"`, so a report cannot be mistaken for a
/// register value. Must match `userspace/blk-probe`.
pub(crate) const PCI_REPORT_TAG: u64 = 0x5043 << 48;

/// The device object the `edu` function is registered under for both DMA
/// checks. One constant because the SMMU keys a stream's translation by object
/// id: the check that registers the stream and the check that leases it must
/// name the same device, and each check builds its own executive.
pub(crate) const SMMU_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(23);

/// The DMA driver process's own object id.
///
/// Distinct from the device it drives, which is not a formality: a lease
/// records its holder, and a process whose id *is* the device object would make
/// every holder comparison in the check true for the wrong reason.
pub(crate) const SCOPED_DMA_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(24);

/// Object ids for the chain the hotplug check registers, from the root port
/// down: `[root port, switch upstream, switch downstream, endpoint]`.
///
/// Four, because what is pulled here is a **switch** rather than a function,
/// and the whole point is that the graph knows what was behind it. The root
/// port stays in the machine and is registered so that the removal can be shown
/// to stop at the edge of the subtree rather than at the edge of the array.
pub(crate) const HOTPLUG_CHAIN_OBJ: [kcore::object::ObjectId; 4] = [
    kcore::object::ObjectId::from_raw(0x64),
    kcore::object::ObjectId::from_raw(0x66),
    kcore::object::ObjectId::from_raw(0x67),
    kcore::object::ObjectId::from_raw(0x68),
];
/// The process that holds them while the switch is pulled.
pub(crate) const HOTPLUG_HOLDER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x65);

/// How long to wait for the device to be pulled, in config reads. Generous:
/// the harness has to notice a serial marker, connect to QMP and issue a
/// command, and a bound that expired first would make this check fail for
/// reasons that have nothing to do with the kernel.
pub(crate) const HOTPLUG_POLL_LIMIT: u64 = 200_000_000;

/// What the removal check observed.
pub(crate) struct RemovalOutcome {
    /// Config reads before the function stopped answering.
    pub(crate) polls: u64,
    /// Holders the removal took the capability from.
    pub(crate) holders: usize,
    /// Whether the graph could still find the device afterwards.
    pub(crate) still_known: bool,
    /// Nodes the removal took — the switch and everything that was behind it.
    pub(crate) subtree: usize,
}

/// **A device is pulled out from under a holder that is still using it.**
///
/// Everything else in this file that ends a capability's life is something the
/// holder did — it handed the device on, or it died. This is the case the
/// resource graph could describe (`Removed` has been a terminal lifecycle state
/// since the driver framework landed) and nothing could perform.
///
/// The proof has a half only the machine can supply. The kernel's bookkeeping
/// would agree with itself whatever it did, so what makes this a check rather
/// than an assertion is that **QEMU really removes the function**: its config
/// space stops answering, which is how surprise removal is detected on this bus
/// and not something the kernel can arrange for itself.
///
/// **What is pulled here is a switch, not a function** (M97). A bus controller
/// does not leave alone: unplugging the switch takes its downstream port and
/// the endpoint below it in one physical event, and three functions stop
/// answering at once. A graph that removed only the node it was told about
/// would leave the other two resolving, mapping and authorizing DMA for
/// hardware that is not there — the exact condition removal exists to prevent,
/// reintroduced one level down.
///
/// The root port is registered too, and **must survive**. It is still in the
/// machine, and a removal that walked upward as readily as downward would take
/// it — which no amount of counting the nodes that went would reveal.
///
/// `chain` is the enumeration, from which the topology is read off the parent
/// edges rather than guessed from bus numbers.
pub(crate) fn pci_removal_check(
    host: &tessera_devicetree::PciHost,
    chain: &[tessera_pci::Function],
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    kernel_space: &KernelAddressSpace,
) -> Result<RemovalOutcome, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};

    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };

    // **The topology, read off the parent edges the walk recorded.** The root
    // port is the bridge on the host's own bus; the switch is the bridge behind
    // it; the endpoint is whatever mass-storage function is below that. Reading
    // it from the edges rather than from bus numbers is the difference between
    // knowing the tree and re-deriving it from an encoding that happens to be
    // ordered today.
    let root_port = chain
        .iter()
        .find(|f| f.class_code >> 8 == PCI_CLASS_PCI_BRIDGE && f.parent.is_none())
        .ok_or(204u32)?;
    let switch = chain
        .iter()
        .find(|f| f.class_code >> 8 == PCI_CLASS_PCI_BRIDGE && f.parent == Some(root_port.bdf))
        .ok_or(205u32)?;
    let downstream = chain
        .iter()
        .find(|f| f.class_code >> 8 == PCI_CLASS_PCI_BRIDGE && f.parent == Some(switch.bdf))
        .ok_or(206u32)?;
    let endpoint = chain.iter().find(|f| is_virtio_storage(f)).ok_or(207u32)?;
    // The endpoint must be under the downstream port, or the machine is not the
    // one this check was written for and what it proves is not what it claims.
    if endpoint.parent != Some(downstream.bdf) {
        return Err(208);
    }
    let bdf = switch.bdf;

    // A fresh executive holding the function as a device, and a process holding
    // a capability to it — the state a bound driver is in.
    // A fresh executive; the process table is **not** rebuilt.
    //
    // `KCORE_PROCESSES` is a `static mut` with a const initializer, so it is
    // already a valid empty table living in .bss. Writing a new one over it
    // means constructing a `ProcessTable` **on the stack** and copying — and a
    // table is sixteen `Process`es, each carrying a 1024-entry handle table,
    // which is a couple of hundred kilobytes the boot stack does not have. It
    // overflows, and the fault arrives somewhere with no stack left to report
    // it from, which is why this failed with no diagnosis at all.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 190u32)?;
    let user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);
    // A holder for every node in the chain — the root port included, so the
    // check can tell "the subtree went" from "everything went".
    let holder_index = {
        let mut process = kcore::process::Process::new(HOTPLUG_HOLDER_OBJ, user_space);
        for object in HOTPLUG_CHAIN_OBJ {
            process
                .handles_mut()
                .install(object, Rights::READ | Rights::MAP)
                .map_err(|_| 191u32)?;
        }
        // SAFETY: transient raw access to the static process table.
        unsafe {
            (*(&raw mut KCORE_PROCESSES))
                .insert(process)
                .map_err(|_| 192u32)?
        }
    };
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(193u32)?;
        // The window is nominal — nothing here maps one, and what is being
        // checked is the graph's knowledge of the machine's shape.
        for (index, object) in HOTPLUG_CHAIN_OBJ.iter().enumerate() {
            exec.device_register_mmio(
                *object,
                host.ecam_base + (index as u64) * FRAME_SIZE,
                FRAME_SIZE,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 194u32)?;
        }
        // The edges, root port downward. Registered as a chain because that is
        // what the machine is.
        for pair in HOTPLUG_CHAIN_OBJ.windows(2) {
            exec.device_set_parent(pair[1], pair[0])
                .map_err(|_| 209u32)?;
        }
    }
    let _ = kernel_space;

    // Say so before waiting, because the harness outside is watching for this
    // line and will not pull the device until it sees it.
    kprintln!(
        "hotplug: armed — holding the switch at {:02x}:{:02x}.{} and the {} functions behind it, awaiting removal",
        bdf.bus,
        bdf.device,
        bdf.function,
        HOTPLUG_CHAIN_OBJ.len() - 2
    );
    kcore::verdict::claims(&["hotplug.armed"]);

    // **Poll two things, and the second is the guest's half of hotplug.**
    //
    // A hot-pluggable slot does not simply lose its device. The port raises an
    // eject request and *waits*, because the software using the device is the
    // only thing that knows whether it is in the middle of something — so a
    // guest that never answers is a guest the device never leaves. Answering
    // is what this loop does that the machine cannot do for itself.
    //
    // The other half is watching config space, because acknowledging is a
    // request to de-energize the slot rather than an instruction: what makes
    // the device *gone* is that it stops answering, and only that is worth
    // acting on.
    let mut polls = 0u64;
    let mut answered = false;
    loop {
        match bridge.read(&config, bdf, 0) {
            Ok(0xffff_ffff) | Err(_) => break,
            Ok(_) => {}
        }
        // **At the root port, not at the switch.** A slot's registers belong to
        // the port the card is plugged into, and what is being ejected here is
        // the switch itself — so the port that raises the request is the one
        // above it. Answering at the switch would be asking the thing that is
        // leaving whether it may leave.
        if !answered
            && tessera_pci::eject_requested(&bridge, &config, root_port.bdf).unwrap_or(false)
        {
            tessera_pci::acknowledge_eject(&bridge, &mut config, root_port.bdf)
                .map_err(|_| 202u32)?;
            // Once, not every round: the status bits are cleared by the
            // acknowledgement, so a second pass would find nothing to answer
            // and a *third* request would be a different removal.
            answered = true;
        }
        polls += 1;
        if polls >= HOTPLUG_POLL_LIMIT {
            return Err(195);
        }
        core::hint::spin_loop();
    }
    if !answered {
        // The device left without the slot ever asking. Possible on a bus with
        // surprise removal, and not on this one — so it means the check was
        // watching the wrong port, and its acknowledgement proved nothing.
        return Err(203);
    }

    // **One call, naming the switch.** Nothing tells the kernel what was behind
    // it — the graph already knows, and that is the whole claim.
    let switch_obj = HOTPLUG_CHAIN_OBJ[1];
    let root_obj = HOTPLUG_CHAIN_OBJ[0];
    // SAFETY: transient raw access to the statics; single-threaded, every
    // thread off-CPU (none was ever started).
    let (holders, subtree, still_known, root_survived) = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(196u32)?;
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let report = exec.remove_device(
            switch_obj,
            kcore::lifecycle::TransitionReason::Removed,
            processes,
            None,
            None,
        );
        if !report.existed {
            return Err(197);
        }
        (
            report.holders,
            report.subtree,
            HOTPLUG_CHAIN_OBJ[1..]
                .iter()
                .any(|object| exec.mmio_of_object(*object).is_some()),
            exec.mmio_of_object(root_obj).is_some(),
        )
    };
    // Three nodes: the switch, its downstream port, and the endpoint. Two would
    // mean the walk stopped one level short, which is precisely the defect a
    // flat graph has.
    if subtree != HOTPLUG_CHAIN_OBJ.len() - 1 {
        return Err(210);
    }
    // One process held all four, and the removal reached it once per node it
    // took. Counting holders rather than asserting a number keeps this honest
    // if the check ever grows a second holder.
    if holders != subtree {
        return Err(198);
    }
    if still_known {
        // The graph would still hand one of these out. Every device syscall
        // resolves through it, so a node left behind is a capability that goes
        // on working for hardware that is not there.
        return Err(199);
    }
    if !root_survived {
        // **The removal walked upward.** The root port is still in the machine
        // and still answering; taking it would be a subtree teardown that does
        // not know where the subtree ends, and no count of removed nodes would
        // have shown it.
        return Err(211);
    }
    // And the holder lost exactly the subtree, without having been consulted —
    // while keeping the one capability that names hardware still present.
    // SAFETY: as above.
    let (holds_removed, holds_root) = unsafe {
        let process = (*(&raw mut KCORE_PROCESSES))
            .get_mut(holder_index)
            .ok_or(200u32)?;
        (
            HOTPLUG_CHAIN_OBJ[1..]
                .iter()
                .any(|object| process.handles().holds(*object)),
            process.handles().holds(root_obj),
        )
    };
    if holds_removed {
        return Err(201);
    }
    if !holds_root {
        return Err(212);
    }

    Ok(RemovalOutcome {
        polls,
        holders,
        still_known,
        subtree,
    })
}

/// The object ids the queue-child check registers: the controller function, the
/// queue behind it, and the child process.
pub(crate) const MQ_CONTROLLER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x70);
pub(crate) const MQ_QUEUE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x71);
pub(crate) const MQ_CHILD_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x72);
/// The child's kernel-stack window.
pub(crate) const MQ_CHILD_KSTACK_VA: u64 = 0xffff_c000_0090_0000;
/// The startup argument that asks `blk-probe` to run as a queue child. Must
/// match `QUEUE_CHILD` there.
pub(crate) const BLK_PROBE_QUEUE_CHILD: usize = 1 << 62;
/// Where a queue child finds the rings of the queue it was given. Must match
/// `tessera_uabi::layout::QUEUE_RING_VA`, which the kernel cannot depend on:
/// `uabi` is built for the user targets, and this is the same agreement
/// `DEVICE_MMIO_VA` already is.
pub(crate) const QUEUE_RING_VA: u64 = 0x0000_1000_00b0_0000;

/// What the ring-3 child established.
pub(crate) struct QueueChildOutcome {
    /// The doorbell VA the child reported mapping — its own report, not the
    /// kernel's belief about it.
    pub(crate) reported: u64,
    /// Bytes the read the *child* published brought back.
    pub(crate) magic: u64,
    /// Pages of register window the child's process holds. One is the claim:
    /// a queue, and not the controller.
    pub(crate) window_pages: usize,
}

/// **A ring-3 child holds one queue and drives it.**
///
/// The half `pci_mq_check` cannot do: it proves the *hardware* separates
/// queues, and this proves the *system* hands one over. The child is started
/// holding a capability to the controller with `Rights::DERIVE` and nothing
/// else — it derives the queue itself (`DeviceChild`, D136/D137), maps that
/// queue's doorbell page, publishes a request the controller formed, and rings
/// its own doorbell.
///
/// **What it does not hold is the finding.** No capability to the controller's
/// register window, no mapping of queue 0, no channel to another process to
/// submit on its behalf — a transfer from here crosses no extra process
/// (`docs/drivers/01`, "Bus Topology And Data Paths"). The check reads the
/// child's register-window count back to say so as a number rather than as a
/// claim about what the code does.
///
/// The descriptors are the controller's, and deliberately: a chain names
/// buffers by their device-visible addresses, which a child has no way to know.
/// The child does the half that makes a request a request — the available-ring
/// index and the doorbell.
pub(crate) fn queue_child_check(
    outcome: &virtio::MqOutcome,
    high: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<QueueChildOutcome, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if components::blk_probe().is_empty() {
        return Err(1);
    }
    // A second read, formed but not published — so what completes can only be
    // the child's doing.
    let status_phys = virtio::mq_arm_child_read(outcome, 1, frames).map_err(|e| 10 + e)?;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(20u32)?;
        // The controller: a node the child may derive from and must not map.
        // No `Rights::MAP` on it at all, so "the child never reached the
        // controller's registers" is enforced rather than observed.
        exec.device_register_mmio(MQ_CONTROLLER_OBJ, 0, 0, Rights::READ | Rights::DERIVE)
            .map_err(|_| 21u32)?;
        // The queue: one page, which is the doorbell and nothing else.
        exec.device_register_mmio(
            MQ_QUEUE_OBJ,
            outcome.q1_doorbell_phys,
            FRAME_SIZE,
            Rights::READ | Rights::MAP,
        )
        .map_err(|_| 22u32)?;
        exec.device_set_parent(MQ_QUEUE_OBJ, MQ_CONTROLLER_OBJ)
            .map_err(|_| 23u32)?;
    }

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();

    let (child_idx, child_proc) = ring3_host_spawn(
        components::blk_probe(),
        MQ_CHILD_KSTACK_VA,
        BLK_PROBE_QUEUE_CHILD,
        MQ_CHILD_OBJ,
        &mut kernel_space,
        frames,
        30,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let child = processes.get_mut(child_proc).ok_or(40u32)?;
        child
            .handles_mut()
            .install(MQ_CONTROLLER_OBJ, Rights::READ | Rights::DERIVE)
            .map_err(|_| 41u32)?;
        // Its queue's rings, mapped rather than allocated: this is memory the
        // *device* reads, placed by whoever brought the controller up, and the
        // child never learns its physical address because a descriptor names
        // buffers and not rings.
        let ring = PhysFrame::containing(tessera_karch::PhysAddr::new(outcome.q1_ring_phys));
        child
            .space_mut()
            .map_shared(
                VirtAddr::new(QUEUE_RING_VA),
                PageFlags::rw().user(),
                MQ_QUEUE_OBJ,
                0,
                &[ring],
                frames,
            )
            .map_err(|_| 42u32)?;
    }

    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    let reported = EL0_REPORTS[0].load(Ordering::SeqCst);
    let _ = child_idx;

    // The device must have served a request nobody in the kernel published.
    if !virtio::mq_poll_used(outcome.q1_used_phys, 2) {
        return Err(50);
    }
    // SAFETY: the status byte of the chain armed above, in a frame this boot
    // allocated and the device has just reported written.
    let ok = unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + status_phys) as *const u8) };
    if ok != 0 {
        return Err(51);
    }
    // SAFETY: the first word of the data frame the device filled.
    let magic =
        unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + outcome.data_phys) as *const u64) };
    // **A different sector than the controller read.** The landing zone was
    // zeroed before the child ran, so stale bytes could not survive — but every
    // sector of this image begins with the same four-byte tag, and a check that
    // compared only those would agree with a read of the wrong sector. This is
    // the one comparison that distinguishes "the child's request was served"
    // from "something was served".
    if magic == outcome.magic {
        return Err(53);
    }

    // SAFETY: transient raw access to the static process table.
    let window_pages = unsafe {
        (*(&raw mut KCORE_PROCESSES))
            .get_mut(child_proc)
            .ok_or(52u32)?
            .device_window_count()
    };

    // **Tear the child down before returning.** The process table is shared
    // across every check in this boot, and a leftover process is not inert: it
    // still owns a thread index and a handle table, so the next check's driver
    // is inserted beside a corpse and its crash ladder counts the wrong
    // incarnations. That is how this first failed — three checks further on,
    // with a message about a driver that would not die.
    //
    // The ring page is deliberately *not* freed with it: it is the queue's, the
    // device still has its address, and it was mapped here rather than
    // allocated here.
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(child_proc) {
            process.space_mut().teardown(frames);
        }
    }
    // SAFETY: the run is over; clear what was published for it.
    unsafe {
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }
    Ok(QueueChildOutcome {
        reported,
        magic,
        window_pages,
    })
}

// --- Power vote arbitration: three voters and a service that weighs them (D140) ---

/// Kernel objects this check creates. Local to its own Executive, which every
/// check builds fresh.
pub(crate) const POWER_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x80);
pub(crate) const POWER_SERVICE_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x81);
/// The manager's endpoint objects, in voter order. **Must match
/// `VOTER_ENDPOINT_OBJECTS` in `userspace/power-manager`**: a port event names
/// the object that was signalled, and a handle table is per-process, so boot
/// and the manager have to agree on the numbering. The same bootstrap
/// agreement `device-host` has for its two client endpoints.
pub(crate) const POWER_SERVER_OBJS: [u32; 3] = [70, 71, 72];
pub(crate) const POWER_CLIENT_OBJS: [u32; 3] = [73, 74, 75];
pub(crate) const POWER_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x90);
pub(crate) const POWER_VOTER_PROC_OBJS: [u32; 3] = [0x91, 0x92, 0x93];

pub(crate) const POWER_MANAGER_KSTACK_VA: u64 = 0xffff_0003_0000_0000;
pub(crate) const POWER_VOTER_KSTACK_VAS: [u64; 3] = [
    0xffff_0003_1000_0000,
    0xffff_0003_2000_0000,
    0xffff_0003_3000_0000,
];

/// Voter-mode bit in the power manager's startup argument. Must match
/// `VOTER_MODE` there.
pub(crate) const POWER_VOTER_MODE: usize = 1 << 63;

/// The startup argument for a voter: which level it asks for, what kind of
/// voter it is, and which report slot rotation it uses.
pub(crate) const fn power_voter_arg(level: u64, class: u64, step: u64) -> usize {
    (POWER_VOTER_MODE as u64 | level | (class << 8) | (step << 16)) as usize
}

/// One voter's expected report, packed the way `resolution_word` packs it.
pub(crate) const fn power_vote_word(step: u32, resolved: u64, from: u64, by: u64, winner: u64) -> u64 {
    (resolved | (from << 8) | (by << 16) | (winner << 24)).rotate_left(8 * step)
}

/// The three votes, in the order they are cast, and what each must be told.
///
/// **The middle two rows are the negative check, and they are in-line rather
/// than in a second boot.** Step 2's reply is `FULL_ACTIVE` with nothing
/// clamped; step 3's is `RETENTION` with `clamped_from = FULL_ACTIVE` and
/// `clamped_by = THERMAL`. Same voters, same domain, same manager — one extra
/// message. That is stronger evidence that the ceiling did something than a
/// separate run with the thermal voter deleted would be, because nothing else
/// about the machine differs between the two lines.
pub(crate) const POWER_STEP_1: u64 = power_vote_word(1, 2, 0, 0, 1);
pub(crate) const POWER_STEP_2: u64 = power_vote_word(2, 4, 0, 0, 2);
pub(crate) const POWER_STEP_3: u64 = power_vote_word(3, 2, 4, 4, 2);
/// The manager's own report: three requests served, the domain left at
/// `RETENTION`, and the device not in service.
pub(crate) const POWER_MANAGER_WORD: u64 = (3u64 | (2u64 << 8)).rotate_left(40);

