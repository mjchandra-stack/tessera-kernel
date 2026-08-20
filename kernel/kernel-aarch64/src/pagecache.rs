// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! One ring-3 program reads bytes another ring-3 program supplied, through
//! pages the kernel holds.
//!
//! This is the first time `docs/storage/02`'s *"there is one cache: the
//! kernel-held pages of pager-backed memory objects"* describes something that
//! exists. The object is created with no frames at all; a **pager** fills one
//! of its pages with `PageSupply`; a **client** maps it with `MapObject` and
//! reads what the pager put there. Nothing copied through a channel, and the
//! client never met the pager.
//!
//! What makes it a cache rather than a transfer is the page nobody supplied:
//! it stays absent through all of it, and the kernel says so after the run.
//! An object that quietly became fully resident would satisfy a check that
//! only read the byte the client reported.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("External Pager
//! Protocol"), docs/storage/02-file-io-and-caching.md ("Caching Model")

use crate::ipc::ipc_spawn_process;
use crate::{
    EL0_DISPATCH_FRAMES, EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KCORE_EXEC,
    KernelAddressSpace,
};
use core::sync::atomic::Ordering;
use tessera_karch::{FRAME_SIZE, VirtAddr};
use tessera_kcore as kcore;

/// Where the client maps the object. Two pages, clear of the code, stack, data
/// and MMIO windows this port's other checks use.
///
/// Encoded in the client program below, in the `movz`/`movk` that builds `x12`.
const CACHE_VA: u64 = 0x0000_1000_0060_0000;
/// Pages in the object. Two, because one is supplied and one is not, and the
/// second is the half that says this is a cache.
const CACHE_PAGES: u64 = 2;

/// Kernel stacks, in the block `dpage` opened and clear of every hand-picked
/// window in the other modules.
const PAGER_KSTACK_VA: u64 = 0xffff_0001_1000_0000;
const CLIENT_KSTACK_VA: u64 = 0xffff_0001_2000_0000;
const CACHE_KSTACK_PAGES: u64 = 8;
const _: () = assert!(PAGER_KSTACK_VA != crate::dpage::DPAGE_KSTACK_VA);
const _: () = assert!(CLIENT_KSTACK_VA != crate::dpage::DPAGE_KSTACK_VA);
const _: () = assert!(PAGER_KSTACK_VA != CLIENT_KSTACK_VA);

/// The bytes the kernel seeds into the pager's data page, which the pager
/// supplies and the client reads back. Every word of the page is this value,
/// so the client reading the *wrong page* reads zeros and fails.
pub(crate) const CACHE_MAGIC: u64 = 0xca6e_face_ca6e_face;

/// What the pager reports: this, XORed with its `PageSupply` result. A refused
/// supply perturbs it, so the pager cannot report success for a page it failed
/// to place.
const PAGER_OK: u64 = 0x5099_1e40_5099_1e40;

/// The sink both programs XOR into: the pager's verdict and the word the client
/// read. Both are load-bearing — neither alone would notice the other failing.
pub(crate) const CACHE_SINK_EXPECTED: u64 = PAGER_OK ^ CACHE_MAGIC;

/// Object ids for this check's topology, in a block of its own.
const CACHE_PAGER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e0);
const CACHE_CLIENT_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e1);

/// The handle number both programs expect the object at: handle 0 is the
/// endpoint `ipc_spawn_process` installs, so the object is 1. Asserted after
/// installing rather than assumed, because the programs have it as a constant.
const OBJECT_HANDLE: u32 = 1;

// The two ring-3 programs. Absolute user VAs — each runs at `USER_CODE_VA` in
// its own space and the addresses below are fixed by this check, so nothing
// here is an in-blob label needing relocation.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.globl cache_pager_start
.globl cache_pager_end
cache_pager_start:
    // PageSupplyArgs, built on the tracked user stack page.
    movz x11, #0x0010, lsl #16
    movk x11, #0x1000, lsl #32      // x11 = USER_STACK_VA
    movz x10, #40                   // size = 40
    movk x10, #1, lsl #32           // | version 1
    str  x10, [x11]
    str  xzr, [x11, #8]             // flags = 0
    movz x10, #1                    // memory = handle 1, reserved = 0
    str  x10, [x11, #16]
    str  xzr, [x11, #24]            // offset = 0 (the object's first page)
    movz x12, #0x0030, lsl #16
    movk x12, #0x1000, lsl #32      // x12 = USER_DATA_VA, seeded by the kernel
    str  x12, [x11, #32]            // source
    mov  x0, x11
    movz x8, #22                    // PageSupply
    svc  #0
    // Report PAGER_OK ^ result: no branch, and a refusal cannot report success.
    mov  x1, x0
    movz x0, #0x1e40
    movk x0, #0x5099, lsl #16
    movk x0, #0x1e40, lsl #32
    movk x0, #0x5099, lsl #48
    eor  x0, x0, x1
    movz x8, #1                     // DebugWrite
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
cache_pager_end:

.balign 16
.globl cache_client_start
.globl cache_client_end
cache_client_start:
    // MemoryMapArgs, built on the tracked user stack page.
    movz x11, #0x0010, lsl #16
    movk x11, #0x1000, lsl #32      // x11 = USER_STACK_VA
    movz x10, #32                   // size = 32
    movk x10, #1, lsl #32           // | version 1
    str  x10, [x11]
    str  xzr, [x11, #8]             // flags = 0
    movz x10, #1                    // memory = handle 1
    movk x10, #1, lsl #32           // | rights = READ
    str  x10, [x11, #16]
    movz x12, #0x0060, lsl #16
    movk x12, #0x1000, lsl #32      // x12 = CACHE_VA
    str  x12, [x11, #24]            // vaddr
    mov  x0, x11
    movz x8, #46                    // MapObject
    svc  #0
    // Read the supplied page. A failed map leaves nothing here and this
    // faults, which the check reports as a fault rather than a wrong value.
    ldr  x0, [x12]
    movz x8, #1                     // DebugWrite
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
cache_client_end:
.text
"#
);

// SAFETY: these name the two blobs' bounds, defined by the `global_asm!` block
// above; the extern block declares them and performs no unsafe operation.
unsafe extern "C" {
    static cache_pager_start: u8;
    static cache_pager_end: u8;
    static cache_client_start: u8;
    static cache_client_end: u8;
}

/// One blob's bytes, from the symbols the assembler placed.
///
/// # Safety
///
/// `start` and `end` must bound one contiguous `.rodata` object, `end` at or
/// after `start`.
unsafe fn blob(start: *const u8, end: *const u8) -> &'static [u8] {
    // SAFETY: the caller's obligation, restated. Both objects are emitted by
    // the `global_asm!` above and immutable for the kernel's lifetime.
    unsafe { core::slice::from_raw_parts(start, (end as usize) - (start as usize)) }
}

/// Runs the check. `Ok(report)` is the accumulated sink.
pub(crate) fn pagecache_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    // A fresh executive, like every other check on this substrate.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the executive this check just built.
    unsafe {
        let exec = crate::kcore_exec().ok_or(800u32)?;
        let (a, b) = exec.channel_create().map_err(|_| 801u32)?;
        exec.bind_endpoint_object(a, CACHE_PAGER_EP_OBJ);
        exec.bind_endpoint_object(b, CACHE_CLIENT_EP_OBJ);
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Frames held by more than one owner, before anything of this check exists.
    // The supplied page will be one: the object holds it as its cache and the
    // mapping that installed it holds it too, and the count is how that is
    // checked. A missing reference is invisible until whichever owner is torn
    // down first frees a frame the other is still reading.
    let shared_before = frames.shared_frame_count();

    // The pager is built first so it schedules first: the client's map installs
    // whatever is already in the cache, and there would be nothing there yet if
    // the two ran the other way round.
    // SAFETY: the symbols bound the blobs emitted above.
    let pager_blob = unsafe { blob(&raw const cache_pager_start, &raw const cache_pager_end) };
    let (pager_idx, pager_proc) = ipc_spawn_process(
        high,
        frames,
        pager_blob,
        PAGER_KSTACK_VA,
        CACHE_PAGER_EP_OBJ,
        &CACHE_MAGIC.to_le_bytes(),
        810,
    )?;
    // SAFETY: the symbols bound the blobs emitted above.
    let client_blob = unsafe { blob(&raw const cache_client_start, &raw const cache_client_end) };
    let (client_idx, client_proc) = ipc_spawn_process(
        high,
        frames,
        client_blob,
        CLIENT_KSTACK_VA,
        CACHE_CLIENT_EP_OBJ,
        &[0u8; 8],
        820,
    )?;

    // **The object, with nothing behind it.** Created here rather than by the
    // pager because the client needs a handle to the same object and no handle
    // has crossed a channel in this check — `MemoryCreatePaged`'s own ring-3
    // path is covered by the dispatch host tests.
    //
    // SAFETY: transient raw access; no thread is running yet.
    let object = unsafe {
        let owner = crate::kcore_processes()
            .get_mut(pager_proc)
            .ok_or(830u32)?
            .id();
        let exec = crate::kcore_exec().ok_or(831u32)?;
        exec.memory_create_paged(owner, CACHE_PAGES as usize, CACHE_PAGER_EP_OBJ)
            .map_err(|_| 832u32)?
    };
    // Two handles to one object, and the difference between them is the
    // point: the pager may answer for the contents, the client may only read
    // and map them.
    // SAFETY: transient raw access; no thread is running yet.
    unsafe {
        let processes = crate::kcore_processes();
        let pager_handle = processes
            .get_mut(pager_proc)
            .ok_or(833u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::SUPPLY)
            .map_err(|_| 834u32)?;
        if pager_handle.raw() != OBJECT_HANDLE {
            return Err(835);
        }
        let client_handle = processes
            .get_mut(client_proc)
            .ok_or(836u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::MAP)
            .map_err(|_| 837u32)?;
        if client_handle.raw() != OBJECT_HANDLE {
            return Err(838);
        }
    }

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(crate::el0_dispatch_hook);

    // SAFETY: transient raw access; `run` returns when both threads yield.
    unsafe {
        if let Some(exec) = crate::kcore_exec() {
            exec.run();
        }
    }
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Back to the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(840);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(841);
    }
    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    if report != CACHE_SINK_EXPECTED {
        return Err(842);
    }

    // **The page nobody supplied.** The client read the right bytes, which says
    // the supplied page arrived; this says the other one never did. Without it
    // an object that quietly became fully resident would pass.
    // SAFETY: transient raw access; both threads are off-CPU.
    unsafe {
        let exec = crate::kcore_exec().ok_or(843u32)?;
        if exec.memory_resident_pages(object) != 1 {
            return Err(844);
        }
        if exec.memory_frame_at(object, 1).is_some() {
            return Err(845);
        }
        let client = crate::kcore_processes()
            .get_mut(client_proc)
            .ok_or(846u32)?;
        if client
            .space()
            .arch()
            .translate(VirtAddr::new(CACHE_VA + FRAME_SIZE))
            .is_some()
        {
            return Err(847);
        }
    }

    // **Held twice, and counted.** One supplied page, one mapping of it: the
    // object keeps it as its cache and the client's space keeps it as a mapped
    // frame. Exactly one frame should have gained a second owner. Zero here
    // means `install_object_page` handed the mapping a frame it never took a
    // reference to, and the first teardown would free it under the other.
    if frames.shared_frame_count() != shared_before + 1 {
        return Err(848);
    }

    // Teardown: reap both threads, remove both processes, then the object —
    // last, because a mapping holds a reference of its own and the frame must
    // outlive whichever of the two goes first.
    // SAFETY: transient raw access; both threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = crate::kcore_exec() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(pager_idx);
        }
        for proc_idx in [client_proc, pager_proc] {
            if let Some(mut process) = crate::kcore_processes().remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
        if let Some(exec) = crate::kcore_exec() {
            exec.memory_destroy(object, frames, None);
        }
    }
    // Both owners are gone, so the page has no second owner and the frame it
    // held is back. The complement of the check above: that one catches a
    // reference never taken, this one catches one never given back.
    if frames.shared_frame_count() != shared_before {
        return Err(849);
    }

    // The kernel stacks, which `teardown` does not reach: they live in the
    // kernel half, and a check that leaves one mapped fails the next spawn at
    // that address with a number about nothing in particular.
    {
        use tessera_karch::FrameSource;
        // SAFETY: `high` is the active kernel high-half space; the alias only
        // unmaps this check's own stack pages and is never torn down.
        let kernel_arch =
            unsafe { KernelAddressSpace::from_root(high.root_phys(), crate::DIRECT_MAP_BASE) };
        let mut kernel_space =
            kcore::vm::AddressSpace::from_arch(kernel_arch, kcore::vm::Asid(0), 0);
        for base in [PAGER_KSTACK_VA, CLIENT_KSTACK_VA] {
            for page in 0..CACHE_KSTACK_PAGES {
                if let Ok(frame) = kernel_space
                    .arch_mut()
                    .unmap(VirtAddr::new(base + page * FRAME_SIZE))
                {
                    frames.free_frame(frame);
                }
            }
        }
    }

    Ok(report)
}
