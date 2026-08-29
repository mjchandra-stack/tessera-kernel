// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The real thing: a compiled ring-3 driver reads a disk.
//!
//! The first `Machine::RiscV64` ELF the loader takes, driving the unchanged
//! `tessera-virtio` core from U-mode (D105).
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// ---------------------------------------------------------------------------
// The real thing: a compiled ring-3 driver reads a disk
// ---------------------------------------------------------------------------

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
    pub fn blk_driver() -> &'static [u8] {
        &[]
    }
    pub fn device_manager() -> &'static [u8] {
        &[]
    }
    pub fn blk_probe() -> &'static [u8] {
        &[]
    }
    pub fn root_task() -> &'static [u8] {
        &[]
    }
}

/// The magic sector 0 of the test disk carries. The driver reports the eight
/// bytes it read; this is what they must be.
pub(crate) const DISK_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");

pub(crate) const BLK_DRIVER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xba00_0000;
/// The driver is compiled Rust with a real call stack, not a blob: four pages
/// of user stack, and eight of kernel stack because a blocking `PortWait`
/// parks a whole dispatch frame on it.
pub(crate) const BLK_DRIVER_USER_STACK_PAGES: u64 = 4;
pub(crate) const BLK_DRIVER_KSTACK_PAGES: u64 = 8;
pub(crate) const BLK_DRIVER_USER_STACK_VA: u64 = 0x3000_0000;
pub(crate) const BLK_DRIVER_ASID: u16 = 10;

/// A compiled ring-3 driver reads sector 0 of a real disk.
///
/// Every previous milestone on this port ran a hand-written blob, which proves
/// a mechanism but not that the mechanisms compose into something a person
/// would write. This runs an ELF built from ordinary Rust that reuses
/// `tessera-virtio` **unchanged** — the same transport core the AArch64 driver
/// and the in-kernel proof use — and its only privileged actions are the
/// syscalls the last five milestones added.
///
/// Returns the eight bytes it read from the disk.
pub(crate) fn blk_driver_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    device: tessera_devicetree::MmioDevice,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    let image = components::blk_driver();
    if image.is_empty() {
        return Err(1);
    }
    let Some(intid) = device.intid else {
        return Err(2);
    };

    // SAFETY: the boot CPU alone; written before any thread runs.
    unsafe {
        kcore_exec_restart(1);
    }
    let device_obj = kcore::object::ObjectId::from_raw(60);
    let port_obj = kcore::object::ObjectId::from_raw(61);
    substrate_exec()
        .device_register_mmio(
            device_obj,
            device.base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 3u32)?;
    substrate_exec()
        .device_set_mmio_irq(device_obj, intid)
        .map_err(|_| 4u32)?;
    // A route, not a bare binding — see the identical wiring in the blob-based
    // IRQ check above for why the graph has to know who is receiving this.
    let port = substrate_exec().port_create().map_err(|_| 5u32)?;
    substrate_exec().bind_port_object(port, port_obj);
    substrate_exec()
        .device_route_irq(device_obj, port, device_obj)
        .map_err(|_| 6u32)?;

    let user_arch = kernel_space
        .new_user(frames, BLK_DRIVER_ASID)
        .map_err(|_| 7u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(BLK_DRIVER_ASID), 0);
    let entry = kcore::elf::load_into(
        image,
        &mut user_space,
        frames,
        kcore::elf::Machine::RiscV64,
        10,
    )?;

    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // the kernel stack and is never torn down.
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(entry),
        0,
        VirtAddr::new(BLK_DRIVER_USER_STACK_VA),
        BLK_DRIVER_USER_STACK_PAGES,
        VirtAddr::new(BLK_DRIVER_KSTACK_VA),
        BLK_DRIVER_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 20u32)?;

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(21u32)?
            .add_thread(thread)
            .map_err(|_| 22u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 23u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process
                .add_thread(thread_id_of(thread_idx)?)
                .map_err(|_| 24u32)?;
            // Exactly the authority the driver needs and no more: the device
            // it drives, and the port its interrupt arrives on.
            process
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 25u32)?;
            process
                .handles_mut()
                .install(port_obj, Rights::READ)
                .map_err(|_| 26u32)?;
        }
    }

    REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);
    IRQ_DELIVERED.store(0, Ordering::SeqCst);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);
    tessera_karch_riscv64::set_device_irq_hook(rtc_irq_hook);
    // SAFETY: the PLIC source is the one the device tree named for this device.
    unsafe { tessera_karch_riscv64::enable_irq(intid) };
    WIRED_INTID.store(intid, Ordering::SeqCst);

    // The same pump as the interrupt check, and for the same reason: the
    // driver parks on its device, so the kernel's boot context is what waits
    // for the line. The tick is what makes the bound below reachable.
    <SupervisorTimer as tessera_karch::TimerControl>::start_periodic_this_cpu(TICK_HZ);
    let mut pumps = 0u64;
    const PUMP_LIMIT: u64 = 500;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.run();
            }
        }
        if REPORT_COUNT.load(Ordering::SeqCst) > 0 || USER_FAULT.load(Ordering::SeqCst) != 0 {
            break;
        }
        if pumps >= PUMP_LIMIT {
            break;
        }
        <Cpu as tessera_karch::InterruptControl>::enable();
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
        pumps += 1;
    }
    tessera_karch_riscv64::stop_timer();
    WIRED_INTID.store(0, Ordering::SeqCst);
    // SAFETY: masking the line the check armed, now that nothing serves it.
    unsafe { tessera_karch_riscv64::disable_irq(intid) };
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(30);
    }
    if REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(31);
    }
    let reported = REPORTS[0].load(Ordering::SeqCst);
    if reported != DISK_MAGIC {
        // The driver reports a staged failure code rather than a wrong value
        // when something refuses it, so printing it names the stage.
        kprintln!("blk: the driver reported {reported:#018x}, not the disk magic");
        return Err(32);
    }
    // The read was interrupt-driven, not polled: the driver parked and the
    // kernel's own counter saw the device wake it.
    if IRQ_DELIVERED.load(Ordering::SeqCst) == 0 {
        return Err(33);
    }

    // SAFETY: transient raw access; the thread is Exited and off-CPU, and the
    // process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for page in 0..BLK_DRIVER_KSTACK_PAGES {
        if let Ok(frame) =
            kernel_alias.unmap(VirtAddr::new(BLK_DRIVER_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }

    Ok(reported)
}
