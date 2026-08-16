// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Firmware loading: what the driver measured, what the manifest required,
//! and the refusals in between.
//!
//! Normative: docs/lifecycle/03-boot-sequence-and-update-mechanics.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// What the driver must report about the image it was handed.
///
/// The low word is the leading four bytes of the digest **the driver measured
/// itself**, which the check compares against what the kernel measures from the
/// same store — the one comparison in this milestone that neither side can
/// satisfy by echoing the other. Then the image version, the security version,
/// and zero for the driver's own attempt to load firmware, which must be
/// refused `AccessDenied`.
pub(crate) fn firmware_report_expected(digest_lead: u32) -> u64 {
    u64::from(digest_lead) | (FIRMWARE_GOOD_VERSION << 32) | (FIRMWARE_GOOD_SVN << 40)
}

/// What the run produced.
pub(crate) struct FirmwareReportPair {
    pub(crate) refusals: u64,
    pub(crate) driver: u64,
    /// Whether the incoming system's stricter driver set would strand an image
    /// already in the store — `docs/drivers/01`'s update-compatibility check.
    pub(crate) update_would_strand: bool,
}

/// Proves **firmware loading, mediated by the driver framework** —
/// `docs/drivers/01`, "Firmware Loading".
///
/// Five claims, and each is a different outcome from one code path:
///
/// 1. A manager holding `Rights::FIRMWARE` fetches a verified image and hands
///    it to a driver beside the device, as a second capability.
/// 2. The driver **measures what it received** and gets the digest the kernel
///    measured from the store — the only check here that neither side can
///    satisfy by trusting the other.
/// 3. An image below the system's rollback floor is refused **while measuring
///    perfectly**: `docs/security/02`'s "rejected even if correctly signed".
/// 4. An image the floor accepts and the manifest entry does not is refused
///    *differently*, because those are two authorities and two fixes.
/// 5. The driver asks for firmware itself and is refused, because the manager
///    narrowed the right away when it handed the device on. Without this the
///    right would be a bit nobody had watched refuse anything.
///
/// And the update-compatibility rule runs over the store's real contents: a
/// driver set requiring a version above what is installed would strand it, and
/// the one that is installed would not.
pub(crate) fn firmware_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<FirmwareReportPair, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if components::device_manager().is_empty() || components::blk_probe().is_empty() || system_store().is_empty() {
        return Err(1);
    }

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // **FIRMWARE is granted here and nowhere else.** Boot gives it to the
        // manager because the manager is the framework; the manager does not
        // pass it on, and the driver's refusal later is that decision working.
        exec.device_register_identified(
            FIRMWARE_DEVICE_OBJ,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::FIRMWARE,
            kcore::devmgr::DeviceIdentity {
                class_code: RELAY_CLASS_STORAGE,
                vendor: RELAY_VIRTIO_VENDOR,
                // The product id the one firmware-declaring manifest entry
                // names. Every other block device in this tree keeps binding
                // with no firmware at all, which is the normal case.
                device: FIRMWARE_BLOCK_PRODUCT,
                bdf: 0,
                revision: 0,
                bus: kcore::devmgr::DeviceBus::Pci,
            },
        )
        .map_err(|_| 11u32)?;

        let channel = exec.channel_create().map_err(|_| 12u32)?;
        exec.bind_endpoint_object(channel.0, FIRMWARE_SERVER_OBJ);
        exec.bind_endpoint_object(channel.1, FIRMWARE_CLIENT_OBJ);
    }

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
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);

    let (manager, probe) = relay_pair(
        FIRMWARE_DEVICE_OBJ,
        // The device itself, with the authority to fetch its firmware. The
        // manager spends it and narrows it away on the transfer.
        Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::FIRMWARE,
        FIRMWARE_SERVER_OBJ,
        FIRMWARE_CLIENT_OBJ,
        FIRMWARE_MANAGER_PROC_OBJ,
        FIRMWARE_PROBE_PROC_OBJ,
        FIRMWARE_MANAGER_KSTACK_VA,
        FIRMWARE_PROBE_KSTACK_VA,
        DEVICE_MANAGER_FIRMWARE_PROBE,
        BLK_PROBE_FIRMWARE_REPORT,
        &mut kernel_space,
        frames,
        20,
    )?;

    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    // Two reports: the manager's refusals first (it writes before it serves),
    // then the driver's.
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        return Err(60);
    }
    let refusals = EL0_REPORTS[0].load(Ordering::SeqCst);
    let driver = EL0_REPORTS[1].load(Ordering::SeqCst);

    // SAFETY: transient raw access; every thread is off-CPU by here, and each
    // thread and process is released once. Reaping alone is not teardown — see
    // `relay_check` for why `forget_thread` follows it.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            for thread in [manager.thread, probe.thread] {
                exec.scheduler().reap(thread);
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        for pair in [manager, probe] {
            processes.forget_thread(pair.thread);
            if let Some(mut process) = processes.remove(pair.process) {
                process.space_mut().teardown(frames);
            }
        }
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    if refusals != FIRMWARE_REFUSALS_EXPECTED {
        return Err(61);
    }

    Ok(FirmwareReportPair {
        refusals,
        driver,
        update_would_strand: firmware_update_would_strand(),
    })
}

/// Runs `docs/drivers/01`'s update-compatibility check over the store's **real**
/// contents.
///
/// The question an update has to answer is whether the machine still works
/// afterwards, so it is asked of the images that are *in use*: an image today's
/// policy already refuses is not stranded by an update, because nothing is
/// running it. Filtering by the current rule first is what makes the answer
/// about the update rather than about the store's contents.
///
/// Two candidate driver sets against that set: the one installed, which still
/// admits everything, and a stricter one requiring a version above what is
/// there, which does not. Both are checked, because a rule that refused
/// everything would look correct with only the second.
///
/// The update is hypothetical — this system has no update mechanism, and that
/// is a recorded deviation — but the images and the rule are real.
pub(crate) fn firmware_update_would_strand() -> bool {
    let Ok(store) = kcore::store::mount(system_store()) else {
        return false;
    };
    let installed = tessera_firmware::Requirement {
        min_image_version: BLOCK_FIRMWARE_MIN_VERSION,
    };
    let incoming = tessera_firmware::Requirement {
        min_image_version: FIRMWARE_GOOD_VERSION as u32 + 1,
    };
    let policy = kcore::firmware::POLICY;

    let mut in_use = [tessera_firmware::Image {
        svn: 0,
        image_version: 0,
    }; 8];
    let mut count = 0;
    for index in 0..store.len().min(in_use.len()) {
        let Ok(entry) = store.entry(index) else {
            continue;
        };
        // Firmware only: the store carries other things, and an answer about a
        // blob no driver loads would be noise.
        if !entry.name().starts_with("firmware") {
            continue;
        }
        let image = tessera_firmware::Image {
            svn: entry.svn,
            image_version: entry.image_version,
        };
        if tessera_firmware::admit(&image, &installed, &policy).is_ok() {
            in_use[count] = image;
            count += 1;
        }
    }
    let in_use = &in_use[..count];
    if in_use.is_empty() {
        return false;
    }
    tessera_firmware::update_compatible(in_use, &installed, &policy).is_ok()
        && tessera_firmware::update_compatible(in_use, &incoming, &policy).is_err()
}

