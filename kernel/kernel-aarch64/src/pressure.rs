// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The machine runs out of memory, and the page cache pays for it.
//!
//! D212 gave the cache a ceiling of its own, which is what stops it growing.
//! This is the other direction: memory the cache is holding on the *guess* that
//! somebody will read it again, given back when the machine needs it for
//! anything at all. `docs/kernel/03` reclaims clean pages "under memory
//! pressure" — pressure meaning the allocator, not a budget the cache set for
//! itself, and a cache well inside its own ceiling can still be the only memory
//! left to take.
//!
//! **The pressure is real.** Nothing here simulates a low-memory flag or lowers
//! a threshold: the check carves a small run of frames out of the boot
//! allocator, builds a second allocator over exactly that run, and hands it to
//! the syscall path for the duration. When it says there is nothing left, there
//! is nothing left — the frames are real, they are owned by this check, and the
//! only way to get another one is for a cached page to go back.
//!
//! What that buys is a run that would otherwise stop: a reader walks an object
//! bigger than the memory the machine has, and finishes.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Write-Back And
//! Eviction Flow" — clean-page reclaim under memory pressure)

use crate::ipc::ipc_spawn_process;
use crate::{
    EL0_DISPATCH_FRAMES, EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KCORE_EXEC,
    KernelAddressSpace,
};
use core::sync::atomic::Ordering;
use tessera_karch::{FRAME_SIZE, MemoryKind, MemoryRegion, PhysAddr, VirtAddr};
use tessera_kcore as kcore;

/// Where the reader maps the object. Encoded in the program below.
const PR_VA: u64 = 0x0000_1000_00c0_0000;
/// Pages in the object.
const PR_PAGES: u64 = 12;

/// Frames the constrained allocator gets.
///
/// **Tighter than the cache's own ceiling**, which is the whole point and took
/// measuring to get right. The first version handed the pool forty frames; the
/// walk finished, the check passed, and it proved nothing new — with that much
/// memory the *budget* from D212 stopped the cache at six pages and the
/// allocator was never short at all. Only a pool whose usable part is smaller
/// than that budget makes memory pressure the binding constraint.
///
/// Usable means above the watermark: the frames below it are what page tables
/// and DMA buffers draw on, and they are never spent on cache pages.
const PR_FRAMES: u64 = kcore::dispatch::RECLAIM_WATERMARK + 4;

/// Kernel stacks, continuing the block `dpage` opened.
const PR_PAGER_KSTACK_VA: u64 = 0xffff_0001_c000_0000;
const PR_READER_KSTACK_VA: u64 = 0xffff_0001_d000_0000;
const PR_KSTACK_PAGES: u64 = 8;

/// The reader's report: the sum of the first word of every page, which the
/// pager fills with the page's own index plus one.
const PR_EXPECTED_SUM: u64 = PR_PAGES * (PR_PAGES + 1) / 2;

/// Object ids for this check's topology, in a block of its own.
const PR_PAGER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x240);
const PR_KERNEL_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x241);
const PR_READER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x242);
const PR_READER_PEER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x243);

/// The handle each program holds the object at.
const OBJECT_HANDLE: u32 = 1;

// The two ring-3 programs: the same shapes `evict` uses — a resident pager that
// stamps each page with its own index, and a reader that walks the object once
// summing what it finds.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.globl pr_pager_start
.globl pr_pager_end
pr_pager_start:
    movz x9, #0x0010, lsl #16
    movk x9, #0x1000, lsl #32       // x9 = USER_STACK_VA
    movz x10, #0x58
    movk x10, #4, lsl #32           // size 88 | version 4
    str  x10, [x9]
    str  xzr, [x9, #8]
    str  xzr, [x9, #16]
    str  xzr, [x9, #24]
    str  xzr, [x9, #32]
    str  xzr, [x9, #56]
    str  xzr, [x9, #64]
    str  xzr, [x9, #72]
    str  xzr, [x9, #80]
    add  x12, x9, #256
    movz x20, #0x0030, lsl #16
    movk x20, #0x1000, lsl #32      // the staging page

3:  str  x12, [x9, #40]
    movz x10, #64
    str  x10, [x9, #48]
    mov  x0, x9
    movz x1, #0
    movz x8, #13                    // ChannelRecv
    svc  #0

    ldr  x13, [x12, #24]            // the offset asked for
    lsr  x14, x13, #12
    add  x14, x14, #1
    str  x14, [x20]                 // stamp the page with its index + 1

    add  x15, x9, #512
    movz x10, #40
    movk x10, #1, lsl #32
    str  x10, [x15]
    str  xzr, [x15, #8]
    movz x10, #1
    str  x10, [x15, #16]
    str  x13, [x15, #24]
    str  x20, [x15, #32]
    mov  x0, x15
    movz x8, #22                    // PageSupply
    svc  #0
    mov  x21, x0

    add  x17, x9, #640
    movz x10, #24
    movk x10, #1, lsl #32
    str  x10, [x17]
    str  xzr, [x17, #8]
    cmp  x21, #0
    cset w16, eq
    str  xzr, [x17, #16]
    strb w16, [x17, #16]
    str  x17, [x9, #40]
    movz x10, #24
    str  x10, [x9, #48]
    mov  x0, x9
    movz x1, #0
    movz x8, #27                    // ChannelReplyContinue
    svc  #0
    b    3b
pr_pager_end:

.balign 16
.globl pr_reader_start
.globl pr_reader_end
pr_reader_start:
    movz x11, #0x0010, lsl #16
    movk x11, #0x1000, lsl #32
    movz x10, #32
    movk x10, #1, lsl #32
    str  x10, [x11]
    str  xzr, [x11, #8]
    movz x10, #1
    movk x10, #1, lsl #32           // rights = READ
    str  x10, [x11, #16]
    movz x12, #0x00c0, lsl #16
    movk x12, #0x1000, lsl #32      // x12 = PR_VA
    str  x12, [x11, #24]
    mov  x0, x11
    movz x8, #46                    // MapObject
    svc  #0

    mov  x13, x12
    movz x0, #0
    movz x1, {PAGES}
4:  ldr  x2, [x13]
    add  x0, x0, x2
    add  x13, x13, #1, lsl #12
    subs x1, x1, #1
    b.ne 4b

    movz x8, #1                     // DebugWrite: the sum
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
pr_reader_end:
.text
"#,
    PAGES = const PR_PAGES,
);

// SAFETY: these name the two blobs' bounds, defined by the `global_asm!` block
// above; the extern block declares them and performs no unsafe operation.
unsafe extern "C" {
    static pr_pager_start: u8;
    static pr_pager_end: u8;
    static pr_reader_start: u8;
    static pr_reader_end: u8;
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

/// Runs the check. `Ok(low_water)` is the fewest frames the constrained
/// allocator ever had.
pub(crate) fn pressure_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // **The constrained allocator's memory, taken from the real one.** A
    // contiguous run this check owns for its duration, described to a second
    // allocator as the whole of the memory that exists. Nothing is simulated:
    // when it says it is empty, these frames are all genuinely spoken for.
    let run = frames.alloc_contiguous(PR_FRAMES).ok_or(1140u32)?;
    let region = [MemoryRegion {
        base: run,
        len: PR_FRAMES * FRAME_SIZE,
        kind: MemoryKind::Usable,
    }];
    let mut small = kcore::pmem::BumpFrameAllocator::new(&region);
    if small.frames_available() != Some(PR_FRAMES) {
        return Err(1141);
    }

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the executive this check just built.
    unsafe {
        let exec = crate::kcore_exec().ok_or(1142u32)?;
        let (pager_side, kernel_side) = exec.channel_create().map_err(|_| 1143u32)?;
        exec.bind_endpoint_object(pager_side, PR_PAGER_EP_OBJ);
        exec.bind_endpoint_object(kernel_side, PR_KERNEL_EP_OBJ);
        let (reader_side, peer_side) = exec.channel_create().map_err(|_| 1144u32)?;
        exec.bind_endpoint_object(reader_side, PR_READER_EP_OBJ);
        exec.bind_endpoint_object(peer_side, PR_READER_PEER_OBJ);
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // The processes are built out of the **boot** allocator: spawning is not
    // what this check is about, and a spawn that failed for want of memory
    // would look exactly like the thing being measured.
    // SAFETY: the symbols bound the blobs emitted above.
    let pager_blob = unsafe { blob(&raw const pr_pager_start, &raw const pr_pager_end) };
    let (pager_idx, pager_proc) = ipc_spawn_process(
        high,
        frames,
        pager_blob,
        PR_PAGER_KSTACK_VA,
        PR_PAGER_EP_OBJ,
        &[0u8; 8],
        1145,
    )?;
    // SAFETY: the symbols bound the blobs emitted above.
    let reader_blob = unsafe { blob(&raw const pr_reader_start, &raw const pr_reader_end) };
    let (reader_idx, reader_proc) = ipc_spawn_process(
        high,
        frames,
        reader_blob,
        PR_READER_KSTACK_VA,
        PR_READER_EP_OBJ,
        &[0u8; 8],
        1150,
    )?;

    // SAFETY: transient raw access; no thread is running yet.
    let object = unsafe {
        let owner = crate::kcore_processes()
            .get_mut(pager_proc)
            .ok_or(1155u32)?
            .id();
        let exec = crate::kcore_exec().ok_or(1156u32)?;
        let object = exec
            .memory_create_paged(owner, PR_PAGES as usize, PR_PAGER_EP_OBJ)
            .map_err(|_| 1157u32)?;
        exec.paging_bind(object, PR_PAGER_EP_OBJ)
            .map_err(|_| 1158u32)?;
        object
    };
    // SAFETY: transient raw access; no thread is running yet.
    unsafe {
        let processes = crate::kcore_processes();
        let pager_handle = processes
            .get_mut(pager_proc)
            .ok_or(1159u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::SUPPLY)
            .map_err(|_| 1160u32)?;
        if pager_handle.raw() != OBJECT_HANDLE {
            return Err(1161);
        }
        let reader_handle = processes
            .get_mut(reader_proc)
            .ok_or(1162u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::MAP)
            .map_err(|_| 1163u32)?;
        if reader_handle.raw() != OBJECT_HANDLE {
            return Err(1164);
        }
    }

    // **The small allocator is what the syscall path gets**, so every page-in,
    // every page table and every mapping the run needs comes out of a pool of
    // this size — and the reader's object is bigger than the pool.
    let small_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = &mut small;
    // SAFETY: the transmute only erases the borrow lifetime; the pointer is
    // used solely while this check runs, and `small` outlives the run.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(small_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(crate::el0_dispatch_hook);

    // SAFETY: transient raw access.
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
        return Err(1170);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(1171);
    }
    // **The walk finished, and every page was right.** An object bigger than
    // the memory behind it can only be walked if pages were given back, and a
    // reclaim that took the wrong page changes the sum.
    if EL0_SINK_LOG.load(Ordering::SeqCst) != PR_EXPECTED_SUM {
        return Err(1172);
    }

    // The pool really was the constraint: what is resident cannot exceed what
    // the pool holds, and the object is larger than either.
    // SAFETY: transient raw access; both threads are off-CPU.
    let resident = unsafe {
        crate::kcore_exec()
            .ok_or(1173u32)?
            .memory_resident_pages(object)
    };
    if resident as u64 >= PR_PAGES {
        return Err(1174);
    }
    if resident as u64 >= PR_FRAMES {
        return Err(1175);
    }
    // **Fewer pages resident than the cache's own budget allows**, which is
    // what says *memory pressure* was the constraint rather than the ceiling
    // D212 added. With a roomy pool this number sits at the budget and the run
    // proves only that eviction works; here it is below, so the pages went back
    // because the machine needed them and not because the cache was full.
    let ceiling = (kcore::exec::CACHE_FRAME_BUDGET - kcore::exec::CACHE_WRITE_BACK_RESERVE) as u64;
    if resident as u64 >= ceiling {
        return Err(1177);
    }

    let left = small.frames_available().ok_or(1176u32)?;
    // **The pool never ran dry**, which is what the watermark is for: a
    // page-table walk is handed a bare frame source with no way back to the
    // cache, so it must never be the thing that discovers memory is gone. That
    // it ended with frames in hand — while an object twice its size was walked
    // through it — is the whole claim.
    //
    // Stated as `> 0` rather than as `>= RECLAIM_WATERMARK`, and the difference
    // matters: the first version compared against the very constant the
    // mechanism uses, so setting that constant to zero moved the goalpost with
    // it and the check passed with the watermark deleted. An assertion phrased
    // in terms of the thing it is testing is not an assertion.
    if left == 0 {
        return Err(1178);
    }
    // And it was genuinely leaned on. A pool that ended as full as it started
    // is one nothing was ever short of.
    if left >= PR_FRAMES {
        return Err(1179);
    }

    // The reader can still reach exactly what is still cached, and nothing
    // more. A mapping surviving its page would be reading memory the pool has
    // handed to something else.
    // SAFETY: transient raw access; both threads are off-CPU.
    unsafe {
        let reader = crate::kcore_processes().get_mut(reader_proc).ok_or(1180u32)?;
        let mut reachable = 0usize;
        for page in 0..PR_PAGES {
            if reader
                .space()
                .arch()
                .translate(VirtAddr::new(PR_VA + page * FRAME_SIZE))
                .is_some()
            {
                reachable += 1;
            }
        }
        if reachable != resident {
            return Err(1181);
        }
    }

    // Teardown. The small allocator's frames go back to the boot allocator as
    // one run — individually they would overflow its free list, which is
    // exactly the `MEM_RECLAIM_OVERFLOW` case `MAX_OBJECT_PAGES` is sized
    // against.
    // SAFETY: transient raw access; both threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = crate::kcore_exec() {
            exec.scheduler().reap(reader_idx);
            exec.scheduler().reap(pager_idx);
        }
        for proc_idx in [reader_proc, pager_proc] {
            if let Some(mut process) = crate::kcore_processes().remove(proc_idx) {
                process.space_mut().teardown(&mut small);
            }
        }
        if let Some(exec) = crate::kcore_exec() {
            exec.memory_destroy(object, &mut small, None);
        }
    }
    {
        // SAFETY: `high` is the active kernel high-half space; the alias only
        // unmaps this check's own stack pages and is never torn down.
        let kernel_arch =
            unsafe { KernelAddressSpace::from_root(high.root_phys(), crate::DIRECT_MAP_BASE) };
        let mut kernel_space =
            kcore::vm::AddressSpace::from_arch(kernel_arch, kcore::vm::Asid(0), 0);
        for base in [PR_PAGER_KSTACK_VA, PR_READER_KSTACK_VA] {
            for page in 0..PR_KSTACK_PAGES {
                if let Ok(frame) = kernel_space
                    .arch_mut()
                    .unmap(VirtAddr::new(base + page * FRAME_SIZE))
                {
                    frames.free_frame(frame);
                }
            }
        }
    }
    let _ = PhysAddr::new(run.as_u64());

    Ok(left)
}
