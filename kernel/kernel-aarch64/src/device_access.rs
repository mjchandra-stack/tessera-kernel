// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What a ring-3 driver may reach: a mapped register window, a DMA page, and
//! the grant that scopes both.
//!
//! Normative: docs/hardware/04-dma-and-memory-management.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

/// Proves a ring-3 process can safely touch device registers: an EL0 process is
/// granted a Device capability whose payload is the virtio-mmio window, maps it
/// into its own address space with `map_device`, and reads the identity
/// registers directly — capability-gated MMIO, the foundation of a ring-3 driver
/// host. Read-only, so the in-kernel `virtio::check` still runs afterward.
/// Returns the packed `MAGIC | (DEVICE_ID << 32)` the driver read.
pub(crate) fn mmio_map_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    mmio_base: u64,
    mmio_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // A fresh executive on the shared static: it owns the scheduler that runs the
    // process and the device resource graph the capability resolves against.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }

    // Register the virtio window as an MMIO Device object in the resource graph.
    let device_obj = kcore::object::ObjectId::from_raw(20);
    // SAFETY: transient raw access to the static executive.
    unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(100u32)?
            .device_register_mmio(
                device_obj,
                mmio_base,
                mmio_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 101u32)?;
    }

    // Build the process: a fresh low-half space with the program at USER_CODE_VA.
    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 102u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    let code = frames.alloc().ok_or(103u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 104u32)?;
    user_space
        .arch()
        .write_bytes_to_frame(code, 0, MMIO_PROBE_BLOB);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kstack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(MMIO_KSTACK_VA),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(MMIO_KSTACK_VA),
        EL0_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| 105u32)?;

    // SAFETY: transient raw access to the static executive and process table.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(106u32)?
            .scheduler()
            .add_thread(thread)
            .map_err(|_| 107u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 108u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| 109u32)?;
            // The first install in a fresh handle table lands at handle 0, which
            // the program names — the Device capability, with READ|MAP only.
            p.handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 110u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator to the hook for the duration of the run only.
    // SAFETY: `frames` outlives the run (it lives in `kmain`'s frame); the raw
    // pointer is cleared before this function returns, so the hook dereferences
    // it only while it is valid. `frames` is not otherwise touched during `run`.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // SAFETY: transient raw access; `run` returns when the thread yields to boot.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }

    // The pointer must not outlive this frame; clear it before anything else.
    // SAFETY: single-threaded; the hook is done (the thread yielded to boot).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(111);
    }
    let packed = EL0_SINK_LOG.load(Ordering::SeqCst);
    // The ring-3 read must be the real virtio signature: MAGIC in the low word,
    // the block DeviceID in the high word.
    if packed & 0xffff_ffff != tessera_virtio::MAGIC as u64
        || packed >> 32 != tessera_virtio::DEVICE_ID_BLOCK as u64
    {
        return Err(112);
    }

    // Teardown: reap the thread, free its kernel stack (mapped in the aliased
    // kernel space), and remove the process. The device page is an untracked raw
    // mapping, so teardown frees only the table frames, never the MMIO phys.
    // SAFETY: the thread is Exited and off-CPU, so reap is valid.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
    }
    for page in 0..EL0_KSTACK_PAGES {
        if let Ok(frame) = kernel_space
            .arch_mut()
            .unmap(VirtAddr::new(MMIO_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }

    Ok(packed)
}

// --- DmaAlloc: a ring-3 driver allocates a DMA buffer (D78) ---

/// The user VA the ring-3 driver asks `dma_alloc` to place its DMA buffer at.
pub(crate) const DMA_VA: u64 = 0x0000_1000_0050_0000;
const _: () = assert!(
    DMA_VA < 0x0000_8000_0000_0000 && DMA_VA % FRAME_SIZE == 0,
    "DMA_VA must be a page-aligned user address",
);
/// The DMA process's kernel stack, distinct from the other EL0 kstacks.
pub(crate) const DMA_KSTACK_VA: u64 = 0xffff_0000_b000_0000;
/// The pattern the ring-3 driver writes into its DMA buffer through its user VA;
/// the kernel reads it back through the direct map at the returned physical
/// address (also encoded in `DMA_PROBE_BLOB`'s `movz`/`movk` of x3).
pub(crate) const DMA_MAGIC: u64 = 0xd4a0_cafe_d4a0_cafe;

/// A ring-3 driver program: build a `DmaAllocArgs` (32 bytes, the ISL struct —
/// D79: device handle 0, vaddr `DMA_VA`) on the tracked user stack page,
/// `DmaAlloc`(24), write `DMA_MAGIC` into the buffer through the user VA, then
/// `DebugWrite`(1) the returned physical address and `ProcessExit`(5). Register
/// ABI: x0=args-struct ptr, x8=number; DmaAlloc returns the phys in x0.
pub(crate) const DMA_PROBE_BLOB: &[u8] = &[
    0x09, 0x02, 0xa0, 0xd2, // movz x9, #0x10, lsl #16
    0x09, 0x00, 0xc2, 0xf2, // movk x9, #0x1000, lsl #32   (x9 = USER_STACK_VA)
    0x0a, 0x04, 0x80, 0xd2, // movz x10, #0x20        (size = 32)
    0x2a, 0x00, 0xc0, 0xf2, // movk x10, #0x1, lsl #32     (| version 1 << 32)
    0x2a, 0x01, 0x00, 0xf9, // str x10, [x9]          (size|version)
    0x3f, 0x05, 0x00, 0xf9, // str xzr, [x9, #8]      (flags = 0)
    0x3f, 0x09, 0x00, 0xf9, // str xzr, [x9, #16]     (device handle 0 | reserved)
    0x0b, 0x0a, 0xa0, 0xd2, // movz x11, #0x50, lsl #16
    0x0b, 0x00, 0xc2, 0xf2, // movk x11, #0x1000, lsl #32  (x11 = DMA_VA)
    0x2b, 0x0d, 0x00, 0xf9, // str x11, [x9, #24]     (vaddr)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0x08, 0x03, 0x80, 0xd2, // movz x8, #24           (DmaAlloc)
    0x01, 0x00, 0x00, 0xd4, // svc #0                 (x0 = physical address)
    0xe2, 0x03, 0x00, 0xaa, // mov x2, x0             (save phys)
    0xc3, 0x5f, 0x99, 0xd2, // movz x3, #0xcafe
    0x03, 0x94, 0xba, 0xf2, // movk x3, #0xd4a0, lsl #16
    0xc3, 0x5f, 0xd9, 0xf2, // movk x3, #0xcafe, lsl #32
    0x03, 0x94, 0xfa, 0xf2, // movk x3, #0xd4a0, lsl #48   (x3 = DMA_MAGIC)
    0x63, 0x01, 0x00, 0xf9, // str x3, [x11]          (write magic via user VA)
    0xe0, 0x03, 0x02, 0xaa, // mov x0, x2             (report phys)
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1            (DebugWrite)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0xa8, 0x00, 0x80, 0xd2, // movz x8, #5            (ProcessExit)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

// The `DmaAlloc` semantics (capability resolution, `Rights::MAP` + real
// device-cap gate, tracked anonymous page, physical-address return) live in
// the shared kcore dispatcher (`kcore::dispatch`, D79); this check only grants
// the capability and verifies the VA/phys aliasing.

/// Proves a ring-3 driver can obtain DMA-capable memory: an EL0 process holding
/// a Device capability allocates a DMA buffer with `dma_alloc`, writes a magic
/// through its user VA, and reports the returned physical address; the kernel
/// then reads that physical address through the direct map and finds the magic —
/// proving the driver's VA and the device-visible physical address alias the
/// same memory (the property virtio's descriptor rings depend on). Returns the
/// physical address the driver was given.
pub(crate) fn dma_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    mmio_base: u64,
    mmio_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    // A fresh executive on the shared static, holding the device authority.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let device_obj = kcore::object::ObjectId::from_raw(21);
    // SAFETY: transient raw access to the static executive.
    unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(120u32)?
            .device_register_mmio(
                device_obj,
                mmio_base,
                mmio_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 121u32)?;
    }

    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 122u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    let code = frames.alloc().ok_or(123u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 124u32)?;
    user_space
        .arch()
        .write_bytes_to_frame(code, 0, DMA_PROBE_BLOB);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kstack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(DMA_KSTACK_VA),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(DMA_KSTACK_VA),
        EL0_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| 125u32)?;

    // SAFETY: transient raw access to the static executive and process table.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(126u32)?
            .scheduler()
            .add_thread(thread)
            .map_err(|_| 127u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 128u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| 129u32)?;
            p.handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 130u32)?;
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
    // SAFETY: transient raw access; `run` returns when the thread yields to boot.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: single-threaded; the hook is done (the thread yielded to boot).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(131);
    }
    let phys = EL0_SINK_LOG.load(Ordering::SeqCst);
    if phys == 0 {
        return Err(132);
    }
    // Read the buffer through the direct map at the physical address the driver
    // was given: the magic it wrote through its own user VA must be there,
    // proving the two views alias the same physical memory (same-core, so the
    // normal-memory write is cache-coherent with this read — a real device DMA
    // would additionally need cache maintenance + barriers, as the in-kernel
    // virtio driver does).
    // SAFETY: `phys` is a RAM frame just mapped into the (not-yet-torn-down)
    // process; the direct map covers all RAM, so this aligned read is in bounds.
    let seen = unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + phys) as *const u64) };
    if seen != DMA_MAGIC {
        return Err(133);
    }

    // Teardown: reap the thread, free its kernel stack, and remove the process —
    // reclaiming the DMA buffer (a tracked anonymous mapping, so teardown frees
    // its frame) and its space.
    // SAFETY: the thread is Exited and off-CPU, so reap is valid.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
    }
    use tessera_karch::FrameSource;
    for page in 0..EL0_KSTACK_PAGES {
        if let Ok(frame) = kernel_space
            .arch_mut()
            .unmap(VirtAddr::new(DMA_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }

    Ok(phys)
}

// --- DmaAlloc through an aperture: the address ring-3 gets is an IOVA ---

/// The DMA process's kernel stack for the scoped check, distinct from every
/// other EL0 kstack window.
pub(crate) const SCOPED_DMA_KSTACK_VA: u64 = 0xffff_0000_b100_0000;

/// What [`scoped_dma_check`] proves, in the three numbers that say it.
pub(crate) struct ScopedGrant {
    /// What `dma_alloc` returned — the address the driver will program into
    /// its device.
    pub(crate) iova: u64,
    /// The physical page behind it. Different from `iova`, which is what
    /// translating means.
    pub(crate) phys: u64,
    /// What the device brought back out of the driver's buffer, reached
    /// through `iova`.
    pub(crate) echoed: u64,
    /// The address the SMMU refused **after** the lease ended — the same
    /// `iova` that worked a moment earlier, which is the whole point.
    pub(crate) revoked_at: u64,
    /// Where the device reached a **memory object** that was attached to it —
    /// memory the driver allocated as an object rather than as a DMA page.
    pub(crate) attached_at: u64,
    /// What the device wrote into that object, read back through the direct
    /// map. Proof the attachment reached the hardware.
    pub(crate) attach_echoed: u64,
}

/// Proves the sentence the whole seam exists for: **a ring-3 driver asks for a
/// DMA buffer and is handed an address that reaches its buffer and nothing
/// else.**
///
/// Every earlier milestone handed a driver a physical address and trusted it.
/// D119 showed hardware could bound a device, but with tables the boot built
/// by hand for an address ring-3 never saw. This closes the gap: the EL0
/// program is the *unchanged* D78 probe — it calls `dma_alloc`, writes a magic
/// through its own user VA, and reports what it got back — and the number it
/// reports is now an IOVA, because its device has an aperture.
///
/// The proof is that the **device** honours it. The kernel makes `edu` read 8
/// bytes from the driver's buffer through the returned address; it comes back
/// carrying the magic ring-3 wrote through its VA, so the IOVA and the user VA
/// name the same page from two sides. Then the same transfer to an address
/// outside the aperture is refused by hardware, with the SMMU naming the
/// stream — otherwise "the device wrote where we said" would be equally true
/// of a device that can write anywhere.
pub(crate) fn scoped_dma_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    smmu: &mut Smmu,
    function: &tessera_pci::Function,
) -> Result<ScopedGrant, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let (bar, bar_len) = function.first_bar().ok_or(140u32)?;
    let stream = smmu.stream_of(SMMU_DEVICE_OBJ).ok_or(141u32)?;

    // A fresh executive holding the device authority — and, this time, the
    // record that the device translates. The aperture starts clear of the page
    // `smmu_check` mapped by hand, because the graph must never hand out an
    // address the boot already used for something else.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(142u32)?;
        exec.device_register_mmio(
            SMMU_DEVICE_OBJ,
            bar,
            bar_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 143u32)?;
        // **No aperture is installed here.** The device is behind an SMMU and
        // the SMMU knows it; the lease is the driver's to take, and taking it
        // is what the check is watching for.
    }

    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 145u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    let code = frames.alloc().ok_or(146u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 147u32)?;
    // The same program as the unscoped check (D78): what changed is the answer
    // it gets, not the question it asks. A driver does not know, and does not
    // need to know, whether the address it was handed is translated.
    user_space
        .arch()
        .write_bytes_to_frame(code, 0, DMA_PROBE_BLOB);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kstack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(SCOPED_DMA_KSTACK_VA),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(SCOPED_DMA_KSTACK_VA),
        EL0_KSTACK_PAGES,
        SMMU_DEVICE_OBJ,
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| 148u32)?;

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(149u32)?
            .scheduler()
            .add_thread(thread)
            .map_err(|_| 150u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(SCOPED_DMA_PROC_OBJ, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 151u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| 152u32)?;
            p.handles_mut()
                .install(SMMU_DEVICE_OBJ, Rights::READ | Rights::MAP)
                .map_err(|_| 153u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator **and the SMMU** to the hook for the run only.
    // SAFETY: both outlive the run; the pointers are cleared before returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
        EL0_DISPATCH_IOMMU = smmu;
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // SAFETY: transient raw access; `run` returns when the thread yields to boot.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: single-threaded; the hook is done (the thread yielded to boot).
    unsafe {
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
        EL0_DISPATCH_IOMMU = core::ptr::null_mut();
    }

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(154);
    }
    let iova = EL0_SINK_LOG.load(Ordering::SeqCst);

    // What the driver was handed must be an address from *its* lease. A
    // physical address that happened to work would fail here, which is the
    // point: this check exists to catch the fallback, not just the fault.
    //
    // And it must be the lease's **first** address — `smmu_check` spent this
    // same range a moment ago and gave it back, so a driver starting anywhere
    // else would mean the release did not happen and the window is being eaten
    // one driver at a time.
    if iova != LEASE_BASE {
        return Err(155);
    }
    // SAFETY: transient raw access to the static executive.
    if unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
        .and_then(|exec| exec.lease_holder_of_object(SMMU_DEVICE_OBJ))
        != Some(SCOPED_DMA_PROC_OBJ)
    {
        return Err(156);
    }
    let phys = {
        // SAFETY: transient raw access to the static process table; the
        // process is still resident (teardown is below).
        let process = unsafe { (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) }.ok_or(156u32)?;
        process
            .space()
            .arch()
            .translate(VirtAddr::new(DMA_VA))
            .ok_or(157u32)?
            .0
            .base()
            .as_u64()
    };
    if iova == phys {
        // Not a translation at all — the two names for this memory must differ,
        // or the aperture is decorative.
        return Err(158);
    }

    // Now the device. It reads 8 bytes out of the driver's buffer **through
    // the IOVA the kernel handed ring-3**, and hands them back.
    let mut edu = BarWindow { base: bar };
    edu_dma(&mut edu, iova, EDU_BUFFER, 8, EDU_DMA_START);
    // SAFETY: `phys` is a RAM frame mapped into the (not-yet-torn-down)
    // process; the direct map covers all RAM, so this aligned write is in
    // bounds. Clearing it first is what makes the read-back meaningful — the
    // magic that comes back came from the device, not from being left there.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + phys) as *mut u64, 0) };
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as the write above.
    let echoed = unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + phys) as *const u64) };
    if echoed != DMA_MAGIC {
        return Err(159);
    }

    // And the other half: the same device, the same transfer, to an address it
    // was not given. Without this, "the device reached the buffer" is equally
    // true of a device that can reach everything.
    //
    // Drain first, so the record read afterwards is this transfer's and not an
    // earlier check's.
    smmu.drain_events();
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        OUTSIDE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    let record = smmu.drain_events().ok_or(160u32)?;
    if record.kind != tessera_smmu::event::F_TRANSLATION || record.stream != stream {
        return Err(161);
    }

    // --- A memory object, attached and then detached ------------------------
    //
    // Everything above is `DmaAlloc`: a page the kernel allocated *for* the
    // device. This is the thing D131 could not do — an object that already
    // exists, owned by a process, made reachable by a device and then not.
    //
    // Driven through the executive rather than through a ring-3 syscall,
    // because the syscall half is covered by unit tests and the half that is
    // not is whether `Smmu::unmap` reaches the hardware. That is what this
    // answers, and only a real SMMU can.
    // SAFETY: transient raw access to the static process table and executive;
    // single-threaded boot, and the process is resident (its thread exited but
    // teardown is below). The two statics are distinct, so the borrows do not
    // alias.
    let (object, object_phys, attached_at) = unsafe {
        let process = (*(&raw mut KCORE_PROCESSES))
            .get_mut(proc_idx)
            .ok_or(165u32)?;
        let owner = process.id();
        // The space is borrowed only so the new frames can be zeroed — see
        // `MemoryTable::create`, where zeroing is structural rather than the
        // caller's to remember.
        let space = process.space();
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(166u32)?;
        let object = exec
            .memory_create(owner, 1, kcore::memory::Placement::default(), space, frames)
            .map_err(|_| 167u32)?;
        let mut object_frames = [PhysFrame::containing(PhysAddr::new(0)); 16];
        if exec.memory_frames_of(object, &mut object_frames) != 1 {
            return Err(168);
        }
        let object_phys = object_frames[0].base().as_u64();
        let at = exec
            .device_allocate_in_aperture(SMMU_DEVICE_OBJ, FRAME_SIZE)
            .ok_or(169u32)?;
        kcore::devmgr::DmaMapper::map(smmu, SMMU_DEVICE_OBJ, at, object_phys, FRAME_SIZE)
            .map_err(|_| 170u32)?;
        exec.memory_attach(
            object,
            kcore::memory::Attachment {
                device: SMMU_DEVICE_OBJ,
                address: at,
                len: FRAME_SIZE,
                scoped: true,
            },
        )
        .map_err(|_| 171u32)?;
        (object, object_phys, at)
    };

    // The device writes into the object through the address it was given.
    // SAFETY: `object_phys` is a RAM frame the kernel just allocated and
    // zeroed; the direct map covers all RAM, so this aligned read is in bounds.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + object_phys) as *mut u64, 0) };
    edu_dma(&mut edu, iova, EDU_BUFFER, 8, EDU_DMA_START);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        attached_at,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as the write above.
    let attach_echoed =
        unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + object_phys) as *const u64) };
    if attach_echoed != DMA_MAGIC {
        return Err(172);
    }

    // **Past the aperture, on purpose.** The lease is two pages and
    // `dma_alloc` already took one, so these rounds have exactly one address
    // between them. Each attaches, is reached, and detaches; without an
    // address remembered across the detach the second round would be refused
    // for want of aperture — which is the bound this loop exists to disprove.
    let mut rounds = 0u32;
    while rounds < 6 {
        // SAFETY: transient raw access to the static executive; single-threaded.
        let at = unsafe {
            let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(178u32)?;
            exec.detach_memory(object, Some(smmu)).ok_or(179u32)?;
            let remembered = exec
                .memory_remembered_address(object, SMMU_DEVICE_OBJ)
                .ok_or(180u32)?;
            kcore::devmgr::DmaMapper::map(
                smmu,
                SMMU_DEVICE_OBJ,
                remembered,
                object_phys,
                FRAME_SIZE,
            )
            .map_err(|_| 181u32)?;
            exec.memory_attach(
                object,
                kcore::memory::Attachment {
                    device: SMMU_DEVICE_OBJ,
                    address: remembered,
                    len: FRAME_SIZE,
                    scoped: true,
                },
            )
            .map_err(|_| 182u32)?;
            remembered
        };
        // The same address every round — a driver serving one buffer does not
        // spend its aperture on how long it has been running.
        if at != attached_at {
            return Err(183);
        }
        rounds += 1;
    }
    // And the device still reaches it on the last round, so the rounds were
    // real attachments rather than bookkeeping that happened to agree.
    // SAFETY: `object_phys` is a resident RAM frame the direct map covers.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + object_phys) as *mut u64, 0) };
    edu_dma(&mut edu, iova, EDU_BUFFER, 8, EDU_DMA_START);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        attached_at,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as above.
    if unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + object_phys) as *const u64) }
        != DMA_MAGIC
    {
        return Err(184);
    }

    // Detach, and the same address stops resolving. **This is the property the
    // whole mechanism rests on**: a buffer handed back to its owner while the
    // device could still write into it would be memory that is still moving.
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(173u32)?;
        if exec.detach_memory(object, Some(smmu)).is_none() {
            return Err(174);
        }
    }
    // Clear it, so anything found there afterwards came from the device rather
    // than from being left behind by the transfer above.
    // SAFETY: `object_phys` is a resident RAM frame the direct map covers; an
    // aligned 8-byte write in bounds.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + object_phys) as *mut u64, 0) };
    smmu.drain_events();
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        attached_at,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as above.
    if unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + object_phys) as *const u64) } != 0 {
        // The device still reached it. Bookkeeping said detached and the
        // hardware disagreed, which is the one outcome that must never pass.
        return Err(175);
    }
    let record = smmu.drain_events().ok_or(176u32)?;
    if record.kind != tessera_smmu::event::F_TRANSLATION || record.stream != stream {
        return Err(177);
    }

    // --- The lease ends, and the device stops reaching what it was reaching ---
    //
    // **This runs before teardown, and the order is part of the claim.** If the
    // frames went back to the allocator first, a revocation that silently did
    // nothing would let the device write into memory the kernel had already
    // handed to something else — the check would cause the bug it exists to
    // catch, and pass while doing it.
    // SAFETY: transient raw access to the static executive and process table;
    // the thread has exited, so the process is quiescent but still resident.
    let ended = unsafe {
        let process = (*(&raw mut KCORE_PROCESSES))
            .get_mut(proc_idx)
            .ok_or(162u32)?;
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(163u32)?
            .end_device_leases(process, Some(smmu))
    };
    if ended != 1 {
        return Err(164);
    }

    // Clear the page, so what comes back came from the device.
    // SAFETY: as the accesses above — still mapped, still resident.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + phys) as *mut u64, 0) };
    // Empty the queue, so the refusal read below is this transfer's alone.
    smmu.drain_events();
    // The same device, the same transfer, to the address it was using moments
    // ago and is no longer entitled to.
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as above.
    if unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + phys) as *const u64) } != 0 {
        // It still reached the buffer. The lease ended on paper only.
        return Err(165);
    }
    // And the SMMU's account of it, naming the very address that worked before.
    // `next_event` consumes, so this is *this* refusal and not the one above.
    let revoked = smmu.drain_events().ok_or(166u32)?;
    // The fault names the **page**, not necessarily the first byte of it: an
    // 8-byte transfer is split into narrower transactions, so the last record
    // of a refused one sits partway into the page (`iova + 4` here). Requiring
    // the exact base would fail for a reason that has nothing to do with
    // revocation.
    if revoked.kind != tessera_smmu::event::F_TRANSLATION
        || revoked.stream != stream
        || revoked.address & !(FRAME_SIZE - 1) != iova
    {
        return Err(167);
    }

    // Teardown: reap the thread, free its kernel stack, and remove the process,
    // reclaiming the DMA buffer's frame with it — safe to do now, and only now,
    // because the device can no longer name that frame.
    // SAFETY: the thread is Exited and off-CPU, so reap is valid.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
    }
    use tessera_karch::FrameSource;
    for page in 0..EL0_KSTACK_PAGES {
        if let Ok(frame) = kernel_space
            .arch_mut()
            .unmap(VirtAddr::new(SCOPED_DMA_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }

    Ok(ScopedGrant {
        iova,
        phys,
        echoed,
        revoked_at: revoked.address,
        attached_at,
        attach_echoed,
    })
}

// --- Ring-3 driver host: the EL0 blk driver serves a client over IPC (D80/D81) ---
