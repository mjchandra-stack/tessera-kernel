// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Capability-gated MMIO and DMA: the two favours a ring-3 driver needs.
//!
//! A window onto a device's registers, and a buffer with a user VA and a
//! device-visible physical address. Device reads are `lwu`, not `lw` — a sign
//! extension here reads as a different register (D102).
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
// Capability-gated MMIO and DMA: the two favours a ring-3 driver needs
// ---------------------------------------------------------------------------

/// The device process's mappings. All four sit inside one gigabyte, which the
/// teardown count below depends on and states.
pub(crate) const DEVICE_USER_CODE_VA: u64 = 0x1300_0000;
pub(crate) const DEVICE_USER_STACK_VA: u64 = 0x2300_0000;
/// Where the program asks for the device's registers, and for its DMA buffer.
/// Both are the program's choice, not the kernel's — a driver names its own
/// address space; what it cannot name is the *physical* window behind the
/// first, which is exactly what the capability supplies.
pub(crate) const USER_MMIO_VA: u64 = 0x3300_0000;
pub(crate) const USER_DMA_VA: u64 = 0x3400_0000;
const _: () = assert!(
    USER_MMIO_VA.is_multiple_of(FRAME_SIZE) && USER_DMA_VA.is_multiple_of(FRAME_SIZE),
    "both must be page-aligned; the syscalls refuse anything else",
);

/// The device process's kernel stack, in the direct map's gigabyte slot — the
/// D100 constraint on any kernel mapping made after a process root is copied.
pub(crate) const DEVICE_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xbc00_0000;
pub(crate) const DEVICE_ASID: u16 = 6;

/// What the ring-3 program writes into its DMA page, and what the kernel then
/// looks for at the physical address the program was told to give the device.
pub(crate) const DMA_SENTINEL: u64 = 0xd1a0_d1a0_0000_0007;

/// Table frames plus tracked leaf frames a fully-populated device process
/// returns at teardown.
///
/// Exact, not a lower bound, and the difference matters here more than
/// anywhere else on this port: the MMIO page is mapped **untracked** by
/// `map_device`, so `teardown` must never see it. A device register block
/// returned to the anonymous-memory pool is a bug that would show up much
/// later as memory that reads back as hardware. A lower bound would not
/// notice, exactly as D99's `>= 2` did not notice `free_tables` freeing the
/// kernel's own tables.
///
/// Derivation: the four user addresses above all lie below 1 GiB, so one root
/// and one level-1 table cover them, and their level-1 indices differ, so
/// each needs its own level-0 table — 1 + 1 + 4 = 6. The tracked leaves are
/// the code page, the user stack page and the DMA page — 3. The device window
/// is not among them.
pub(crate) const DEVICE_TEARDOWN_FRAMES: usize = 6 + 3;

// The ring-3 driver's two favours, in one program.
//
// `MapDeviceArgs` and `DmaAllocArgs` are byte-identical 32-byte structs
// (api/isl/examples/device_abi.isl), so the struct is built once and reissued
// with a different syscall number and `vaddr`. That is a property of the ABI,
// not a shortcut: both syscalls ask the same question — "authorised by this
// device handle, put something at this address".
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl device_blob_start
device_blob_start:
    addi    sp, sp, -32
    li      t0, 32
    sw      t0, 0(sp)           // size
    li      t0, 1
    sw      t0, 4(sp)           // version
    sd      zero, 8(sp)         // flags
    sw      zero, 16(sp)        // device — handle 0, the only one installed
    sw      zero, 20(sp)        // reserved
    li      t0, 0x33000000
    sd      t0, 24(sp)          // vaddr = USER_MMIO_VA
    mv      a0, sp
    li      a7, 23              // MapDevice
    ecall
    bltz    a0, 90f             // a refusal must be reported, never ignored

    // a0 is the register base: the page we asked for plus the window's
    // intra-page offset. Read the transport's identity through our *own*
    // mapping — the kernel read the same two registers through the direct
    // map, and the check compares them.
    lwu     a1, 0(a0)           // MAGIC_VALUE @ 0x000
    lwu     a2, 8(a0)           // DEVICE_ID   @ 0x008
    slli    a2, a2, 32          // lwu, not lw: lw sign-extends on RV64 and a
    or      a0, a1, a2          // register with bit 31 set would arrive wrong
    li      a7, 1               // DebugWrite — report 0
    ecall

    li      t0, 0x34000000
    sd      t0, 24(sp)          // vaddr = USER_DMA_VA
    mv      a0, sp
    li      a7, 24              // DmaAlloc
    ecall
    bltz    a0, 90f

    // a0 is the page's physical address — the name the *device* would use for
    // the memory this program is about to write through its own virtual one.
    mv      t1, a0
    li      t2, 0x34000000
    li      t3, 0xd1a0d1a0
    slli    t3, t3, 32
    addi    t3, t3, 7           // DMA_SENTINEL
    sd      t3, 0(t2)
    mv      a0, t1
    li      a7, 1               // DebugWrite — report 1
    ecall

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
90:                             // a0 holds the negative error code
    li      a7, 1
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl device_blob_end
device_blob_end:
"#
);

// SAFETY: declares the blob's bounding symbols, defined above.
unsafe extern "C" {
    pub(crate) static device_blob_start: u8;
    pub(crate) static device_blob_end: u8;
}

/// A ring-3 process is granted a Device capability, maps the device's
/// registers into its own address space, reads them, and allocates a buffer
/// the device could address.
///
/// These are the only two privileged favours a driver needs, and neither one
/// tells the program anything it could have guessed: the physical window lives
/// inside the capability and never crosses the ABI, and the DMA page's
/// physical address is *returned* rather than requested. What the program
/// chooses is only where in its own space each lands.
///
/// Returns `(the packed magic|device-id the program read, the DMA physical
/// address it was given)`.
pub(crate) fn device_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    window: u64,
) -> Result<(u64, u64), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // SAFETY: the boot CPU alone; written before any thread runs.
    unsafe {
        kcore_exec_restart(1);
    }

    // The window enters the resource graph as a Device object. This is the
    // only place its physical address is named; from here on it travels as a
    // capability, and the program that uses it never learns it.
    let device_obj = kcore::object::ObjectId::from_raw(30);
    substrate_exec()
        .device_register_mmio(
            device_obj,
            window,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 1u32)?;

    // SAFETY: linker-provided bounds of the read-only blob above.
    let blob = unsafe {
        core::slice::from_raw_parts(
            &raw const device_blob_start,
            (&raw const device_blob_end as usize) - (&raw const device_blob_start as usize),
        )
    };

    let user_arch = kernel_space
        .new_user(frames, DEVICE_ASID)
        .map_err(|_| 2u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(DEVICE_ASID), 0);

    user_space
        .map_anonymous(
            VirtAddr::new(DEVICE_USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 3u32)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(DEVICE_USER_CODE_VA))
        .map(|(frame, _)| frame)
        .ok_or(4u32)?;
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(DEVICE_USER_CODE_VA), FRAME_SIZE);

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
        VirtAddr::new(DEVICE_USER_CODE_VA),
        0,
        VirtAddr::new(DEVICE_USER_STACK_VA),
        1,
        VirtAddr::new(DEVICE_KSTACK_VA),
        IPC_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 5u32)?;
    if user_space
        .arch()
        .translate(VirtAddr::new(DEVICE_KSTACK_VA))
        .is_none()
    {
        return Err(6);
    }

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(7u32)?
            .add_thread(thread)
            .map_err(|_| 8u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 9u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process
                .add_thread(thread_id_of(thread_idx)?)
                .map_err(|_| 10u32)?;
            // Handle 0: the Device capability, with MAP and nothing else it
            // does not need. READ lets it be looked up; MAP is the right the
            // two syscalls actually check.
            process
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 11u32)?;
        }
    }

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
    // The same hook the IPC check installs, unchanged: `MapDevice` and
    // `DmaAlloc` are already arms of `kcore::dispatch`, so a port that reached
    // the substrate gets them without writing a line of syscall code.
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
        return Err(20);
    }
    let reports = REPORT_COUNT.load(Ordering::SeqCst);
    if reports != 2 {
        // The program reports a refused syscall's code rather than pressing
        // on, so a short run has already said why in its one report. Printing
        // it turns "the count was wrong" into the actual reason — the
        // difference between a rights failure and a bad address is exactly
        // what a reader needs here.
        if reports == 1 {
            kprintln!(
                "mmio: the program reported {} and stopped",
                REPORTS[0].load(Ordering::SeqCst) as i64
            );
        }
        return Err(21);
    }

    // 1. The identity the program read through its own capability mapping, and
    //    the same two registers as the kernel reads them through the direct
    //    map. Two disjoint paths to one register block.
    let packed = REPORTS[0].load(Ordering::SeqCst);
    let (kernel_magic, kernel_id) = virtio_identity(window);
    if packed & 0xffff_ffff != u64::from(kernel_magic)
        || packed >> 32 != u64::from(kernel_id)
        || kernel_magic != tessera_virtio::MAGIC
    {
        return Err(22);
    }

    // 2. The DMA page. The program wrote a sentinel through its *virtual*
    //    address; the kernel looks for it at the *physical* one the program
    //    was told to hand the device. Finding it is what proves the two names
    //    denote the same memory — which is the entire content of `DmaAlloc`,
    //    and is checked here through a path the program never touched.
    let dma_phys = REPORTS[1].load(Ordering::SeqCst);
    if dma_phys & (FRAME_SIZE - 1) != 0 {
        return Err(23);
    }
    // SAFETY: `dma_phys` was returned by `DmaAlloc`, which allocated it from
    // this allocator, so it is a RAM frame the direct map covers read-write.
    // The read is 8 aligned bytes inside it.
    let seen = unsafe { ((DIRECT_MAP_BASE + dma_phys) as *const u64).read_volatile() };
    if seen != DMA_SENTINEL {
        return Err(24);
    }

    // 3. Teardown, counted exactly — see `DEVICE_TEARDOWN_FRAMES`.
    // SAFETY: transient raw access; the thread is Exited and off-CPU, and the
    // process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
    }
    let before = frames.free_list_depth();
    // SAFETY: as above.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }
    let reclaimed = frames.free_list_depth() - before;
    if reclaimed != DEVICE_TEARDOWN_FRAMES {
        return Err(25);
    }
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for page in 0..IPC_KSTACK_PAGES {
        if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(DEVICE_KSTACK_VA + page * FRAME_SIZE)) {
            frames.free_frame(frame);
        }
    }

    Ok((packed, dma_phys))
}
