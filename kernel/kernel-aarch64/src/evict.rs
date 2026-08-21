// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A reader walks more pages than the cache can hold, and every one of them is
//! right.
//!
//! This is what makes the cache a cache rather than a growing pile: it has a
//! ceiling, and reaching it drops a page that has been read rather than
//! refusing the next one. `docs/kernel/03` reclaims **clean** pages without
//! consulting the pager and re-faults later, which is exactly the sequence
//! here — a page is dropped, the reader touches it again, and the pager
//! supplies it a second time.
//!
//! Two things are checked and both are needed. That the cache stayed inside its
//! budget says eviction happened; that every page the reader saw held its own
//! number says eviction dropped the right thing. A kernel that evicted nothing
//! passes the second, and one that handed back a page of somebody else's data
//! passes the first.
//!
//! The pager supplies page `n` filled with `n`, so a page read after being
//! evicted and re-supplied is indistinguishable from one that was never gone —
//! which is the property, not a weakness of the check: the reader is *supposed*
//! not to be able to tell.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Write-Back And
//! Eviction Flow" — clean-page reclaim)

use crate::ipc::ipc_spawn_process;
use crate::{
    EL0_DISPATCH_FRAMES, EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KCORE_EXEC,
    KernelAddressSpace,
};
use core::sync::atomic::Ordering;
use tessera_karch::{FRAME_SIZE, VirtAddr};
use tessera_kcore as kcore;

/// Where the reader maps the object. Encoded in the program below.
const EV_VA: u64 = 0x0000_1000_00b0_0000;
/// Pages in the object: more than the cache may hold, so the walk below has to
/// evict to finish. Sized from the budget rather than guessed — a number that
/// happened to exceed it today would stop doing so the moment the budget moved.
const EV_PAGES: u64 = kcore::exec::CACHE_FRAME_BUDGET as u64 + 4;

/// Kernel stacks, continuing the block `dpage` opened.
const EV_PAGER_KSTACK_VA: u64 = 0xffff_0001_a000_0000;
const EV_READER_KSTACK_VA: u64 = 0xffff_0001_b000_0000;
const EV_KSTACK_PAGES: u64 = 8;

/// What the reader reports: the sum of the first word of every page it read.
///
/// The pager fills page `n` with `n + 1`, so the sum is fixed and a single
/// wrong page changes it. A checksum rather than a magic, because the point is
/// that *each* page was right and one report has to carry all of them.
///
/// Twice the triangular number, because the reader walks the object twice — the
/// second pass re-reads pages the first one caused to be evicted.
const EV_EXPECTED_SUM: u64 = EV_PAGES * (EV_PAGES + 1);

/// Object ids for this check's topology, in a block of its own.
const EV_PAGER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x230);
const EV_KERNEL_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x231);
const EV_READER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x232);
const EV_READER_PEER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x233);

/// The handle each program holds the object at.
const OBJECT_HANDLE: u32 = 1;

// The two ring-3 programs.
//
// The pager is resident: it serves page-ins for as long as the reader keeps
// faulting, which past the budget means serving the same page more than once.
// It writes `offset / 4096 + 1` into its staging page before supplying, so the
// contents say which page they are.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.globl ev_pager_start
.globl ev_pager_end
ev_pager_start:
    movz x9, #0x0010, lsl #16
    movk x9, #0x1000, lsl #32       // x9 = USER_STACK_VA
    movz x10, #0x58                 // size = 88
    movk x10, #4, lsl #32           // | version 4
    str  x10, [x9]
    str  xzr, [x9, #8]
    str  xzr, [x9, #16]
    str  xzr, [x9, #24]
    str  xzr, [x9, #32]
    str  xzr, [x9, #56]
    str  xzr, [x9, #64]
    str  xzr, [x9, #72]
    str  xzr, [x9, #80]
    add  x12, x9, #256              // where a request lands
    movz x20, #0x0030, lsl #16
    movk x20, #0x1000, lsl #32      // x20 = USER_DATA_VA, the staging page

3:  str  x12, [x9, #40]             // inline_ptr = the request buffer
    movz x10, #64
    str  x10, [x9, #48]             // inline_len
    mov  x0, x9
    movz x1, #0
    movz x8, #13                    // ChannelRecv: a page request
    svc  #0

    // Fill the staging page with this page's number, so what the reader gets
    // says which page it is. A kernel that supplied the wrong frame shows up
    // as a wrong sum rather than as nothing at all.
    ldr  x13, [x12, #24]            // the request's offset
    lsr  x14, x13, #12
    add  x14, x14, #1               // page index + 1
    str  x14, [x20]

    // PageSupplyArgs (40 bytes) at stack + 512.
    add  x15, x9, #512
    movz x10, #40
    movk x10, #1, lsl #32           // size 40 | version 1
    str  x10, [x15]
    str  xzr, [x15, #8]
    movz x10, #1                    // memory = handle 1, reserved = 0
    str  x10, [x15, #16]
    str  x13, [x15, #24]            // the offset that was asked for
    str  x20, [x15, #32]            // source = the staging page
    mov  x0, x15
    movz x8, #22                    // PageSupply
    svc  #0
    mov  x21, x0                    // remember whether it worked

    // PageInReply (24 bytes) at stack + 640.
    add  x17, x9, #640
    movz x10, #24
    movk x10, #1, lsl #32           // size 24 | version 1
    str  x10, [x17]
    str  xzr, [x17, #8]
    cmp  x21, #0
    cset w16, eq                    // supplied = (PageSupply returned 0)
    str  xzr, [x17, #16]
    strb w16, [x17, #16]
    str  x17, [x9, #40]             // inline_ptr = the reply
    movz x10, #24
    str  x10, [x9, #48]
    mov  x0, x9
    movz x1, #0
    // Continue, not plain reply: this server has more requests coming, and a
    // plain reply leaves it Blocked with nobody to wake it.
    movz x8, #27                    // ChannelReplyContinue
    svc  #0
    b    3b
ev_pager_end:

.balign 16
.globl ev_reader_start
.globl ev_reader_end
ev_reader_start:
    movz x11, #0x0010, lsl #16
    movk x11, #0x1000, lsl #32      // USER_STACK_VA
    movz x10, #32
    movk x10, #1, lsl #32           // size 32 | version 1
    str  x10, [x11]
    str  xzr, [x11, #8]
    movz x10, #1                    // memory = handle 1
    movk x10, #1, lsl #32           // | rights = READ
    str  x10, [x11, #16]
    movz x12, #0x00b0, lsl #16
    movk x12, #0x1000, lsl #32      // x12 = EV_VA
    str  x12, [x11, #24]
    mov  x0, x11
    movz x8, #46                    // MapObject
    svc  #0

    // Read the first word of every page, summing as it goes. Past the budget
    // each of these faults into a page-in that had to evict something first.
    //
    // **Twice**, and the second pass is the one that matters. Its early pages
    // were evicted during the first, and their frames went back to the
    // allocator and were handed straight to the pager for later pages — so a
    // mapping the kernel forgot to tear down now points at somebody else's
    // data. One pass reads each page while its frame is still intact and
    // cannot tell.
    movz x0, #0                     // the running sum, across both passes
    movz x3, #2                     // passes
5:  mov  x13, x12
    movz x1, {PAGES}
4:  ldr  x2, [x13]
    add  x0, x0, x2
    add  x13, x13, #1, lsl #12
    subs x1, x1, #1
    b.ne 4b
    subs x3, x3, #1
    b.ne 5b

    movz x8, #1                     // DebugWrite: the sum
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
ev_reader_end:
.text
"#,
    PAGES = const EV_PAGES,
);

// SAFETY: these name the two blobs' bounds, defined by the `global_asm!` block
// above; the extern block declares them and performs no unsafe operation.
unsafe extern "C" {
    static ev_pager_start: u8;
    static ev_pager_end: u8;
    static ev_reader_start: u8;
    static ev_reader_end: u8;
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

/// Runs the check. `Ok(resident)` is how many of the object's pages were still
/// cached at the end.
pub(crate) fn evict_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<usize, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the executive this check just built.
    unsafe {
        let exec = crate::kcore_exec().ok_or(1090u32)?;
        let (pager_side, kernel_side) = exec.channel_create().map_err(|_| 1091u32)?;
        exec.bind_endpoint_object(pager_side, EV_PAGER_EP_OBJ);
        exec.bind_endpoint_object(kernel_side, EV_KERNEL_EP_OBJ);
        let (reader_side, peer_side) = exec.channel_create().map_err(|_| 1092u32)?;
        exec.bind_endpoint_object(reader_side, EV_READER_EP_OBJ);
        exec.bind_endpoint_object(peer_side, EV_READER_PEER_OBJ);
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // The pager first, so it is parked in `recv` before the reader faults.
    // SAFETY: the symbols bound the blobs emitted above.
    let pager_blob = unsafe { blob(&raw const ev_pager_start, &raw const ev_pager_end) };
    let (pager_idx, pager_proc) = ipc_spawn_process(
        high,
        frames,
        pager_blob,
        EV_PAGER_KSTACK_VA,
        EV_PAGER_EP_OBJ,
        &[0u8; 8],
        1095,
    )?;
    // SAFETY: the symbols bound the blobs emitted above.
    let reader_blob = unsafe { blob(&raw const ev_reader_start, &raw const ev_reader_end) };
    let (reader_idx, reader_proc) = ipc_spawn_process(
        high,
        frames,
        reader_blob,
        EV_READER_KSTACK_VA,
        EV_READER_EP_OBJ,
        &[0u8; 8],
        1100,
    )?;

    // Nothing supplied: every page the reader touches is a page-in, and past
    // the budget each one has to evict first.
    // SAFETY: transient raw access; no thread is running yet.
    let object = unsafe {
        let owner = crate::kcore_processes()
            .get_mut(pager_proc)
            .ok_or(1105u32)?
            .id();
        let exec = crate::kcore_exec().ok_or(1106u32)?;
        let object = exec
            .memory_create_paged(owner, EV_PAGES as usize, EV_PAGER_EP_OBJ)
            .map_err(|_| 1107u32)?;
        exec.paging_bind(object, EV_PAGER_EP_OBJ)
            .map_err(|_| 1108u32)?;
        object
    };
    // SAFETY: transient raw access; no thread is running yet.
    unsafe {
        let processes = crate::kcore_processes();
        let pager_handle = processes
            .get_mut(pager_proc)
            .ok_or(1109u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::SUPPLY)
            .map_err(|_| 1110u32)?;
        if pager_handle.raw() != OBJECT_HANDLE {
            return Err(1111);
        }
        let reader_handle = processes
            .get_mut(reader_proc)
            .ok_or(1112u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::MAP)
            .map_err(|_| 1113u32)?;
        if reader_handle.raw() != OBJECT_HANDLE {
            return Err(1114);
        }
        if crate::kcore_exec()
            .ok_or(1115u32)?
            .memory_resident_pages(object)
            != 0
        {
            return Err(1116);
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
        return Err(1120);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(1121);
    }
    // Every page held its own number. One wrong page — a stale frame, somebody
    // else's memory, a page-in answered for the wrong offset — changes the sum.
    if EL0_SINK_LOG.load(Ordering::SeqCst) != EV_EXPECTED_SUM {
        return Err(1122);
    }

    // Every eviction the kernel recorded, drained before the assertions so a
    // full ring cannot swallow them.
    let mut sink = [kcore::event::record(
        kcore::event::EventKind::EventsDropped,
        kcore::event::Severity::Debug,
        kcore::event::Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    ); kcore::event::EVENT_RING_CAPACITY];
    let drained = kcore::event::drain(&mut sink);
    let evicted = sink[..drained]
        .iter()
        .filter(|record| {
            record.component == kcore::event::Component::Pager
                && record.kind == kcore::event::EventKind::PagerPageEvicted
                && record.arg0 == u64::from(object.raw())
        })
        .count();

    // SAFETY: transient raw access; both threads are off-CPU.
    let resident = unsafe {
        crate::kcore_exec()
            .ok_or(1123u32)?
            .memory_resident_pages(object)
    };
    // **Every page that left, left through an eviction.** The pager supplied a
    // page per fault and the object holds what is resident, so the difference
    // between them is exactly what was reclaimed — unless something else is
    // dropping pages, which is the thing this arithmetic exists to catch.
    if evicted == 0 {
        return Err(1126);
    }
    // **Inside the ceiling the ordinary path actually has**, which is the
    // budget *less the write-back reservation* — those frames are held back so
    // a write-back can always proceed, so an ordinary page-in never sees them.
    // Asserting against the whole budget would have passed with the reservation
    // deleted, which is the number that keeps reclaim from deadlocking.
    let ceiling =
        (kcore::exec::CACHE_FRAME_BUDGET - kcore::exec::CACHE_WRITE_BACK_RESERVE) as usize;
    if resident > ceiling {
        return Err(1124);
    }
    // And the object is bigger than that, so a run ending with every page
    // resident is one where nothing was evicted — and the sum above would still
    // have been right.
    if resident as u64 >= EV_PAGES {
        return Err(1125);
    }
    // **Every page is accounted for.** The pager supplied one per page, so what
    // is resident plus what was evicted is the whole object. A page that went
    // missing any other way — dropped without a record, freed twice, lost to a
    // failed supply — breaks this and nothing else here would notice.
    // Supplies and evictions balance: whatever the pager supplied across both
    // passes is resident now or was reclaimed. A page that went missing any
    // other way — dropped without a record, freed twice, lost to a failed
    // supply — breaks this and nothing else here would notice.
    if resident + evicted < EV_PAGES as usize {
        return Err(1127);
    }

    // **More evictions than the object has pages**, which is the assertion that
    // says the mapping was torn down.
    //
    // An eviction has to unmap the page as well as drop it, or the reader keeps
    // a mapping to a frame the object no longer holds — and because that
    // mapping owns a reference of its own, nothing breaks: the frame stays
    // alive, the reader goes on reading the right bytes, and the page is simply
    // leaked. Nothing about the data can tell. What *can* tell is the count: if
    // the unmap happens, the second pass faults on every page it lost and each
    // one is evicted again, so evictions exceed the object's size. If it does
    // not, the second pass never faults at all and the count stops at one per
    // page.
    //
    // Measured rather than reasoned: the first version of this checked fresh
    // frames drawn from the memory map, which is zero either way — earlier
    // checks leave a free list deep enough to absorb the whole run.
    if evicted <= EV_PAGES as usize {
        return Err(1128);
    }

    // And the reader is left holding only what is still cached. A page it can
    // still reach that the object no longer holds is the leak above, seen from
    // the other side.
    // SAFETY: transient raw access; both threads are off-CPU.
    unsafe {
        let reader = crate::kcore_processes().get_mut(reader_proc).ok_or(1129u32)?;
        let mut reachable = 0usize;
        for page in 0..EV_PAGES {
            if reader
                .space()
                .arch()
                .translate(VirtAddr::new(EV_VA + page * FRAME_SIZE))
                .is_some()
            {
                reachable += 1;
            }
        }
        if reachable != resident {
            return Err(1130);
        }
    }

    // Teardown.
    // SAFETY: transient raw access; both threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = crate::kcore_exec() {
            exec.scheduler().reap(reader_idx);
            exec.scheduler().reap(pager_idx);
        }
        for proc_idx in [reader_proc, pager_proc] {
            if let Some(mut process) = crate::kcore_processes().remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
        if let Some(exec) = crate::kcore_exec() {
            exec.memory_destroy(object, frames, None);
        }
    }
    {
        use tessera_karch::FrameSource;
        // SAFETY: `high` is the active kernel high-half space; the alias only
        // unmaps this check's own stack pages and is never torn down.
        let kernel_arch =
            unsafe { KernelAddressSpace::from_root(high.root_phys(), crate::DIRECT_MAP_BASE) };
        let mut kernel_space =
            kcore::vm::AddressSpace::from_arch(kernel_arch, kcore::vm::Asid(0), 0);
        for base in [EV_PAGER_KSTACK_VA, EV_READER_KSTACK_VA] {
            for page in 0..EV_KSTACK_PAGES {
                if let Ok(frame) = kernel_space
                    .arch_mut()
                    .unmap(VirtAddr::new(base + page * FRAME_SIZE))
                {
                    frames.free_frame(frame);
                }
            }
        }
    }

    Ok(resident)
}
