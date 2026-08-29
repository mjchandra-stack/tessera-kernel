// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A capability crosses a channel: one process hands a device to another.
//!
//! Handles are `u32` vectors on this port, the sending side needs `Rights::TRANSFER`,
//! and the receiving slot carries a generation so the handle it reports cannot be
//! guessed (D103).
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
// A capability crosses a channel: one process hands a device to another
// ---------------------------------------------------------------------------

/// The two processes' mappings. Both have their own roots, so both use the
/// same addresses — and the grant process's fourth address is where *it* maps
/// the device before giving it away.
pub(crate) const GRANT_USER_CODE_VA: u64 = 0x1400_0000;
pub(crate) const GRANT_USER_STACK_VA: u64 = 0x2400_0000;

pub(crate) const GRANT_MANAGER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xbe00_0000;
pub(crate) const GRANT_DRIVER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xbf00_0000;
pub(crate) const GRANT_MANAGER_ASID: u16 = 7;
pub(crate) const GRANT_DRIVER_ASID: u16 = 8;

/// Handle numbers **boot** installs, which is the only thing either program
/// may assume. The device handle the driver ends up using is deliberately not
/// here: it does not exist until the kernel installs it, and the driver is
/// told the number rather than agreeing on one.
pub(crate) const GRANT_ENDPOINT_HANDLE: u64 = 0;
pub(crate) const GRANT_DEVICE_HANDLE: u32 = 1;

// The manager: receive a request, reply with the device capability attached,
// exit. It never says *what* the device is — the reply body is empty, and the
// entire payload is the transferred handle.
//
// Stack layout: an 8-byte inline buffer at sp+0, ChannelMsgArgs at sp+16
// (88 bytes, so through sp+103), and the outgoing transfer vector — one
// 16-byte `HandleTransfer` descriptor — at sp+104. The descriptor moved out of
// the 8 bytes at sp+8 when it stopped being a bare handle value and started
// carrying the rights the capability arrives with (D113).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl grant_manager_blob_start
grant_manager_blob_start:
    addi    sp, sp, -128
    sd      zero, 0(sp)
    li      t0, 88
    sw      t0, 16(sp)          // size
    li      t0, 4
    sw      t0, 20(sp)          // version
    sd      zero, 24(sp)        // flags
    sd      zero, 32(sp)        // interface_id
    sd      zero, 40(sp)        // txn_id
    sw      zero, 48(sp)        // method_id
    sw      zero, 52(sp)        // msg_flags
    mv      t0, sp
    sd      t0, 56(sp)          // inline_ptr
    li      t0, 8
    sd      t0, 64(sp)          // inline_len
    sd      zero, 72(sp)        // handles_ptr — nothing transferred inbound
    sd      zero, 80(sp)        // handle_count
    sd      zero, 88(sp)        // installed_ptr — expects nothing back
    sd      zero, 96(sp)        // installed_cap

    addi    a0, sp, 16
    li      a1, 0
    li      a7, 13              // ChannelRecv — park until the driver calls
    ecall
    bltz    a0, 91f

    // Attach the device capability to the reply: one HandleTransfer
    // descriptor naming the handle and the rights it is to arrive with. This
    // check is about the transfer mechanism, so the capability travels with
    // the rights boot granted (READ|MAP|TRANSFER) rather than a narrowed set —
    // the framework's own grant is where narrowing is exercised.
    li      t0, 1
    sw      t0, 104(sp)         // handle — the one boot installed at index 1
    sw      zero, 108(sp)       // mode = TransferMode::TRANSFER
    li      t0, 0x85
    sd      t0, 112(sp)         // rights: READ|MAP|TRANSFER
    addi    t0, sp, 104
    sd      t0, 72(sp)          // handles_ptr
    li      t0, 1
    sd      t0, 80(sp)          // handle_count
    sd      zero, 64(sp)        // inline_len = 0: the capability *is* the reply

    addi    a0, sp, 16
    li      a1, 0
    li      a7, 27              // ChannelReplyContinue
    ecall
    bltz    a0, 91f

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
91:
    li      a7, 1               // report the refusal rather than pressing on
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl grant_manager_blob_end
grant_manager_blob_end:

// The driver: ask for a device, be told which handle it arrived as, and use
// it. It holds exactly one handle to begin with — its endpoint — and cannot
// name a device until the kernel installs one and reports the number.
//
// Stack layout: inline buffer at sp+0, the installed-handle report (one u32)
// at sp+8, ChannelMsgArgs at sp+16, MapDeviceArgs at sp+112.
.globl grant_driver_blob_start
grant_driver_blob_start:
    addi    sp, sp, -160
    sd      zero, 0(sp)
    sd      zero, 8(sp)
    li      t0, 88
    sw      t0, 16(sp)
    li      t0, 4
    sw      t0, 20(sp)
    sd      zero, 24(sp)
    sd      zero, 32(sp)
    sd      zero, 40(sp)
    sw      zero, 48(sp)
    sw      zero, 52(sp)
    mv      t0, sp
    sd      t0, 56(sp)          // inline_ptr
    li      t0, 8
    sd      t0, 64(sp)          // inline_len
    sd      zero, 72(sp)        // handles_ptr — transfers nothing outbound
    sd      zero, 80(sp)        // handle_count
    addi    t0, sp, 8
    sd      t0, 88(sp)          // installed_ptr — "tell me what I was given"
    li      t0, 1
    sd      t0, 96(sp)          // installed_cap

    addi    a0, sp, 16
    li      a1, 0
    li      a7, 14              // ChannelCall
    ecall
    bltz    a0, 92f

    lwu     s0, 8(sp)           // the handle the *kernel* chose, not a constant
    mv      a0, s0
    li      a7, 1               // DebugWrite — report 0: which handle arrived
    ecall

    li      t0, 32
    sw      t0, 112(sp)         // MapDeviceArgs.size
    li      t0, 1
    sw      t0, 116(sp)         // version
    sd      zero, 120(sp)       // flags
    sw      s0, 128(sp)         // device — the handle just reported to us
    sw      zero, 132(sp)       // reserved
    li      t0, 0x33000000
    sd      t0, 136(sp)         // vaddr = USER_MMIO_VA
    addi    a0, sp, 112
    li      a7, 23              // MapDevice
    ecall
    bltz    a0, 92f

    lwu     a1, 0(a0)           // MAGIC_VALUE
    lwu     a2, 8(a0)           // DEVICE_ID
    slli    a2, a2, 32
    or      a0, a1, a2
    li      a7, 1               // DebugWrite — report 1: what the device says
    ecall

    li      a0, 0
    li      a7, 5
    ecall
    unimp
92:
    li      a7, 1
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl grant_driver_blob_end
grant_driver_blob_end:
"#
);

// SAFETY: declares the blobs' bounding symbols, defined above.
unsafe extern "C" {
    pub(crate) static grant_manager_blob_start: u8;
    pub(crate) static grant_manager_blob_end: u8;
    pub(crate) static grant_driver_blob_start: u8;
    pub(crate) static grant_driver_blob_end: u8;
}

/// Builds one process for the capability-transfer check: its own root, its
/// program, stacks, and the handles boot grants it. `device` is `Some` only
/// for the manager — the driver's whole point is that it starts without one.
#[allow(clippy::too_many_arguments)]
pub(crate) fn grant_spawn_process(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blob: &[u8],
    kstack_va: u64,
    asid: u16,
    endpoint_object: kcore::object::ObjectId,
    device: Option<kcore::object::ObjectId>,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch = kernel_space.new_user(frames, asid).map_err(|_| base_err)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(asid), 0);

    user_space
        .map_anonymous(
            VirtAddr::new(GRANT_USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| base_err + 1)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(GRANT_USER_CODE_VA))
        .map(|(frame, _)| frame)
        .ok_or(base_err + 2)?;
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(GRANT_USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // the kernel stack and is never torn down (it owns no tables).
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(GRANT_USER_CODE_VA),
        0,
        VirtAddr::new(GRANT_USER_STACK_VA),
        1,
        VirtAddr::new(kstack_va),
        IPC_KSTACK_PAGES,
        endpoint_object,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| base_err + 3)?;
    if user_space
        .arch()
        .translate(VirtAddr::new(kstack_va))
        .is_none()
    {
        return Err(base_err + 4);
    }

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 5)?
            .add_thread(thread)
            .map_err(|_| base_err + 6)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(endpoint_object, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 7)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process
                .add_thread(thread_id_of(thread_idx)?)
                .map_err(|_| base_err + 8)?;
            // Handle 0 in every fresh table: the endpoint.
            process
                .handles_mut()
                .install(endpoint_object, Rights::READ | Rights::WRITE)
                .map_err(|_| base_err + 9)?;
            if device.is_none() {
                // The driver's slot 1 is given a *history* before the device
                // arrives in it: a placeholder capability is installed and
                // taken away again, which bumps the slot's generation.
                //
                // This is not scene-setting. A handle is an index **and** a
                // generation, so the value the driver is about to be told is
                // `(1 << 16) | 1`, not `1` — a number no program could have
                // arrived at by counting install order, and one that a program
                // guessing "the device will be handle 1" fails the generation
                // check on. It is also the ordinary case rather than a
                // contrived one: any table that has ever held a capability in
                // a slot behaves this way, which is precisely why D94 had to
                // add the installed-handle report at all.
                let placeholder = kcore::object::ObjectId::from_raw(43);
                let handle = process
                    .handles_mut()
                    .install(placeholder, Rights::TRANSFER)
                    .map_err(|_| base_err + 12)?;
                process
                    .handles_mut()
                    .take(handle)
                    .map_err(|_| base_err + 13)?;
            }
            if let Some(device) = device {
                // Handle 1, the manager's only: the device. **TRANSFER** is
                // what makes it giveable — handing a capability on is itself
                // a right, and without it `take` refuses (D91 learned this
                // the hard way).
                let handle = process
                    .handles_mut()
                    .install(device, Rights::READ | Rights::MAP | Rights::TRANSFER)
                    .map_err(|_| base_err + 10)?;
                if handle.raw() != GRANT_DEVICE_HANDLE {
                    // The program names this number, so it is checked rather
                    // than assumed to fall out of install order.
                    return Err(base_err + 11);
                }
            }
        }
    }
    Ok((thread_idx, proc_idx))
}

/// One process hands a device capability to another over a channel, and the
/// receiver uses it.
///
/// This is the last mechanism a driver framework needs: until now a device
/// could only be granted by **boot**, which is a shared constant wearing a
/// capability's clothes. Three separate things are proven, and the third is
/// the one that makes it a *transfer* rather than a copy:
///
/// 1. The driver starts with no device and ends up mapping one.
/// 2. It learns the handle number **from the kernel**, in the installed-handle
///    report — it cannot have agreed on one in advance, because the handle did
///    not exist until the receive installed it.
/// 3. The manager no longer holds the capability afterwards. The reference is
///    conserved, so "one driver per device" is arithmetic rather than policy.
///
/// Returns `(the handle the driver was given, the packed magic|device-id it
/// then read through it)`.
pub(crate) fn grant_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    window: u64,
) -> Result<(u64, u64), u32> {
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // SAFETY: the boot CPU alone; written before any thread runs.
    unsafe {
        kcore_exec_restart(1);
    }
    let device_obj = kcore::object::ObjectId::from_raw(40);
    substrate_exec()
        .device_register_mmio(
            device_obj,
            window,
            FRAME_SIZE,
            kcore::rights::Rights::READ
                | kcore::rights::Rights::MAP
                | kcore::rights::Rights::TRANSFER,
        )
        .map_err(|_| 1u32)?;

    let (server_ep, client_ep) = substrate_exec().channel_create().map_err(|_| 2u32)?;
    let manager_obj = kcore::object::ObjectId::from_raw(41);
    let driver_obj = kcore::object::ObjectId::from_raw(42);
    substrate_exec().bind_endpoint_object(server_ep, manager_obj);
    substrate_exec().bind_endpoint_object(client_ep, driver_obj);

    // SAFETY: linker-provided bounds of the read-only blobs above.
    let (manager_blob, driver_blob) = unsafe {
        (
            core::slice::from_raw_parts(
                &raw const grant_manager_blob_start,
                (&raw const grant_manager_blob_end as usize)
                    - (&raw const grant_manager_blob_start as usize),
            ),
            core::slice::from_raw_parts(
                &raw const grant_driver_blob_start,
                (&raw const grant_driver_blob_end as usize)
                    - (&raw const grant_driver_blob_start as usize),
            ),
        )
    };

    // The manager first, so it is parked in `receive` before the driver calls.
    let (manager_idx, manager_proc) = grant_spawn_process(
        kernel_space,
        frames,
        manager_blob,
        GRANT_MANAGER_KSTACK_VA,
        GRANT_MANAGER_ASID,
        manager_obj,
        Some(device_obj),
        10,
    )?;
    let (driver_idx, driver_proc) = grant_spawn_process(
        kernel_space,
        frames,
        driver_blob,
        GRANT_DRIVER_KSTACK_VA,
        GRANT_DRIVER_ASID,
        driver_obj,
        None,
        30,
    )?;

    REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);

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

    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.run();
        }
    }
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(50);
    }
    let reports = REPORT_COUNT.load(Ordering::SeqCst);
    if reports != 2 {
        if reports == 1 {
            kprintln!(
                "grant: a program reported {} and stopped",
                REPORTS[0].load(Ordering::SeqCst) as i64
            );
        }
        return Err(51);
    }

    // 1. The driver was told a handle number it could not have guessed. Not
    //    its endpoint, and — the sharper part — carrying a **non-zero
    //    generation**, so it is not any value install order alone produces. A
    //    program that assumed "the device will be handle 1" would fail the
    //    generation check in `lookup`, which the negative check confirms.
    let installed = REPORTS[0].load(Ordering::SeqCst);
    if installed == GRANT_ENDPOINT_HANDLE || installed >> 16 == 0 {
        return Err(52);
    }
    // 2. Reading through that handle reached the real device.
    let packed = REPORTS[1].load(Ordering::SeqCst);
    let (kernel_magic, kernel_id) = virtio_identity(window);
    if packed & 0xffff_ffff != u64::from(kernel_magic)
        || packed >> 32 != u64::from(kernel_id)
        || kernel_magic != tessera_virtio::MAGIC
    {
        return Err(53);
    }
    // 3. The capability *moved*. The driver holds it and the manager does not,
    //    which is what makes one-driver-per-device conservation rather than
    //    policy — and is checked on both sides, because "the driver has it"
    //    alone would also be true of a copy.
    // SAFETY: transient raw access to the static process table; the run is
    // over and no thread is on CPU.
    let (driver_holds, manager_holds) = unsafe {
        let table = &*(&raw const KCORE_PROCESSES);
        (
            table
                .get(driver_proc)
                .is_some_and(|p| p.handles().holds(device_obj)),
            table
                .get(manager_proc)
                .is_some_and(|p| p.handles().holds(device_obj)),
        )
    };
    if !driver_holds || manager_holds {
        return Err(54);
    }

    // SAFETY: transient raw access; both threads are Exited and off-CPU, and
    // each process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
        for proc_idx in [driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
    }
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for base in [GRANT_MANAGER_KSTACK_VA, GRANT_DRIVER_KSTACK_VA] {
        for page in 0..IPC_KSTACK_PAGES {
            if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(base + page * FRAME_SIZE)) {
                frames.free_frame(frame);
            }
        }
    }

    Ok((installed, packed))
}
