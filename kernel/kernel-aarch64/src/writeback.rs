// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A writer runs out of dirty pages, and the service persists one so it can
//! carry on.
//!
//! `docs/kernel/03` says a producer that dirties faster than its pager writes
//! back is **throttled at the write fault** — held until there is room, not
//! refused. Holding needs something to release the hold, and this is it: the
//! writing thread blocks inside its own store while the kernel asks the
//! object's service to persist a page, and resumes when the answer comes.
//!
//! The writer is never the service, which is what makes the hold safe to take
//! inline: a client at the bound is not the thread that answers the write-back.
//! A service that faulted on an object it serves is the self-paging case, and
//! it is refused rather than blocked.
//!
//! What is checked is that the writer got through **and** that it cost exactly
//! one write-back: a kernel that raised the bound, ignored it, or wrote back
//! every page would each satisfy some of that and not the rest.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Write-Back And
//! Eviction Flow", "Write-Back Under Memory Pressure")

use crate::ipc::ipc_spawn_process;
use crate::{
    EL0_DISPATCH_FRAMES, EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KernelAddressSpace,
};
use core::sync::atomic::Ordering;
use tessera_karch::{FRAME_SIZE, VirtAddr};
use tessera_kcore as kcore;

/// Where the writer maps the object. Encoded in the program below.
const WB_VA: u64 = 0x0000_1000_00a0_0000;
/// Pages in the object — as many as one may hold, so the bound sits inside it.
const WB_PAGES: u64 = kcore::memory::MAX_OBJECT_PAGES as u64;
/// Pages the writer touches: one past the bound, so exactly one write-back is
/// needed. Writing more would need more drains and stop the count from saying
/// anything precise.
const WB_WRITES: u64 = (kcore::memory::MAX_OBJECT_PAGES as u64 / 2) + 1;

/// Kernel stacks, continuing the block `dpage` opened.
const WB_SERVICE_KSTACK_VA: u64 = 0xffff_0001_8000_0000;
const WB_WRITER_KSTACK_VA: u64 = 0xffff_0001_9000_0000;
const WB_KSTACK_PAGES: u64 = 8;

/// What the service reports when it has answered a write-back.
const WB_SERVICE_TAG: u64 = 0x0b_ac_0b_ac_0b_ac_0b_ac;
/// What the writer reports when every store landed.
const WB_WRITER_TAG: u64 = 0x_1a_1d_1a_1d_1a_1d_1a_1d;
/// Both, XORed: neither alone would notice the other failing.
pub(crate) const WB_SINK_EXPECTED: u64 = WB_SERVICE_TAG ^ WB_WRITER_TAG;

/// Object ids for this check's topology, in a block of its own.
const WB_SERVICE_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x220);
const WB_KERNEL_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x221);
const WB_WRITER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x222);
const WB_WRITER_PEER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x223);

/// The handle each program holds the object at.
const OBJECT_HANDLE: u32 = 1;

// The two ring-3 programs.
//
// The service answers exactly one write-back and reports that it did. The
// writer stores to one page more than the bound allows; the store that hits the
// bound is the one that blocks and is released by the service's answer.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.globl wb_service_start
.globl wb_service_end
wb_service_start:
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
    movz x19, #1                    // report the tag once, on the first reply

    // **A resident server, because more than one page gets written back.** The
    // writer dirties past the bound, is released by a write-back, and then
    // writes the drained page again — which meets the bound a second time and
    // needs a second answer. A service that answered once left the writer's
    // last store refused, and the check reported a fault.
3:  str  x12, [x9, #40]             // inline_ptr = the request buffer
    movz x10, #64
    str  x10, [x9, #48]             // inline_len
    mov  x0, x9
    movz x1, #0
    movz x8, #13                    // ChannelRecv
    svc  #0

    // Read the page the kernel mapped for it, so a window that was never
    // mapped faults here rather than being reported persisted.
    ldr  x14, [x12, #32]            // the request's `source`
    ldr  x15, [x14]

    // WriteBackReply (24 bytes) at stack + 640: persisted = 1.
    add  x17, x9, #640
    movz x10, #24
    movk x10, #1, lsl #32           // size 24 | version 1
    str  x10, [x17]
    str  xzr, [x17, #8]
    movz x16, #1
    str  xzr, [x17, #16]
    strb w16, [x17, #16]            // persisted
    str  x17, [x9, #40]             // inline_ptr = the reply
    movz x10, #24
    str  x10, [x9, #48]             // inline_len
    mov  x0, x9
    movz x1, #0
    // **Continue, not plain reply.** `ChannelReply` hands off to the caller and
    // leaves the replier Blocked, which is right only for a server whose next
    // wake is the next call on this endpoint. This one has more to do, and with
    // a plain reply it never runs again: the check saw the writer get through —
    // so the write-back plainly worked — with the sink short by this half alone.
    movz x8, #27                    // ChannelReplyContinue
    svc  #0

    cbz  x19, 3b                    // already reported: just serve again
    movz x19, #0
    movz x0, #0x0bac
    movk x0, #0x0bac, lsl #16
    movk x0, #0x0bac, lsl #32
    movk x0, #0x0bac, lsl #48
    movz x8, #1                     // DebugWrite, once — XOR would cancel a
    svc  #0                         // second copy of the same tag
    b    3b
wb_service_end:

.balign 16
.globl wb_writer_start
.globl wb_writer_end
wb_writer_start:
    movz x11, #0x0010, lsl #16
    movk x11, #0x1000, lsl #32      // USER_STACK_VA
    movz x10, #32
    movk x10, #1, lsl #32           // size 32 | version 1
    str  x10, [x11]
    str  xzr, [x11, #8]
    movz x10, #1                    // memory = handle 1
    movk x10, #3, lsl #32           // | rights = READ | WRITE
    str  x10, [x11, #16]
    movz x12, #0x00a0, lsl #16
    movk x12, #0x1000, lsl #32      // x12 = WB_VA
    str  x12, [x11, #24]
    mov  x0, x11
    movz x8, #46                    // MapObject
    svc  #0

    // One store per page, `x0` counting down. The store that meets the bound
    // blocks inside this instruction until the service answers.
    mov  x13, x12
    movz x0, {WRITES}
2:  str  x0, [x13]
    add  x13, x13, #1, lsl #12
    subs x0, x0, #1
    b.ne 2b

    // **And write the drained page again.** Page 0 was persisted to make room,
    // so it is clean — and a clean page that is still *writable* takes this
    // store with no fault, which means nothing records it and the write is
    // dropped by the next eviction. This is the store that says the fault was
    // put back.
    movz x1, #0xf00d
    str  x1, [x12]

    movz x0, #0x1a1d
    movk x0, #0x1a1d, lsl #16
    movk x0, #0x1a1d, lsl #32
    movk x0, #0x1a1d, lsl #48
    movz x8, #1                     // DebugWrite
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
wb_writer_end:
.text
"#,
    WRITES = const WB_WRITES,
);

// SAFETY: these name the two blobs' bounds, defined by the `global_asm!` block
// above; the extern block declares them and performs no unsafe operation.
unsafe extern "C" {
    static wb_service_start: u8;
    static wb_service_end: u8;
    static wb_writer_start: u8;
    static wb_writer_end: u8;
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

/// Runs the check. `Ok(dirty)` is how many pages were dirty at the end.
pub(crate) fn writeback_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u32, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        crate::el0::kcore_exec_restart(1);
    }
    // SAFETY: transient raw access to the executive this check just built.
    unsafe {
        let exec = crate::kcore_exec().ok_or(1040u32)?;
        let (service_side, kernel_side) = exec.channel_create().map_err(|_| 1041u32)?;
        exec.bind_endpoint_object(service_side, WB_SERVICE_EP_OBJ);
        exec.bind_endpoint_object(kernel_side, WB_KERNEL_EP_OBJ);
        let (writer_side, peer_side) = exec.channel_create().map_err(|_| 1042u32)?;
        exec.bind_endpoint_object(writer_side, WB_WRITER_EP_OBJ);
        exec.bind_endpoint_object(peer_side, WB_WRITER_PEER_OBJ);
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // The service is built first so it is parked in `recv` before the writer
    // can reach the bound. A write-back request arriving at an endpoint nobody
    // waits on would queue, and the writer would block on an answer that only
    // comes when it yields — which it cannot, because it is the one blocked.
    // SAFETY: the symbols bound the blobs emitted above.
    let service_blob = unsafe { blob(&raw const wb_service_start, &raw const wb_service_end) };
    let (service_idx, service_proc) = ipc_spawn_process(
        high,
        frames,
        service_blob,
        WB_SERVICE_KSTACK_VA,
        WB_SERVICE_EP_OBJ,
        &[0u8; 8],
        1045,
    )?;
    // SAFETY: the symbols bound the blobs emitted above.
    let writer_blob = unsafe { blob(&raw const wb_writer_start, &raw const wb_writer_end) };
    let (writer_idx, writer_proc) = ipc_spawn_process(
        high,
        frames,
        writer_blob,
        WB_WRITER_KSTACK_VA,
        WB_WRITER_EP_OBJ,
        &[0u8; 8],
        1050,
    )?;

    // The object, fully supplied: this check is about writing, and a page-in
    // in the middle would be a second mechanism under test.
    // SAFETY: transient raw access; no thread is running yet.
    let object = unsafe {
        let owner = crate::kcore_processes()
            .get_mut(service_proc)
            .ok_or(1055u32)?
            .id();
        let exec = crate::kcore_exec().ok_or(1056u32)?;
        let object = exec
            .memory_create_paged(owner, WB_PAGES as usize, WB_SERVICE_EP_OBJ)
            .map_err(|_| 1057u32)?;
        exec.paging_bind(object, WB_SERVICE_EP_OBJ)
            .map_err(|_| 1058u32)?;
        for page in 0..WB_PAGES {
            let frame = frames.alloc().ok_or(1059u32)?;
            exec.memory_supply(object, page as usize, frame)
                .map_err(|_| 1060u32)?;
        }
        object
    };
    // SAFETY: transient raw access; no thread is running yet.
    unsafe {
        let processes = crate::kcore_processes();
        // The service holds `SUPPLY`: it answers for the contents, which is
        // what a write-back is.
        let service_handle = processes
            .get_mut(service_proc)
            .ok_or(1061u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::SUPPLY)
            .map_err(|_| 1062u32)?;
        if service_handle.raw() != OBJECT_HANDLE {
            return Err(1063);
        }
        let writer_handle = processes
            .get_mut(writer_proc)
            .ok_or(1064u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::WRITE | Rights::MAP)
            .map_err(|_| 1065u32)?;
        if writer_handle.raw() != OBJECT_HANDLE {
            return Err(1066);
        }
        if crate::kcore_exec()
            .ok_or(1067u32)?
            .memory_dirty_count(object)
            != 0
        {
            return Err(1068);
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
        return Err(1070);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(1071);
    }
    // Both reported: the writer got through every store, and the service
    // answered a write-back. Either alone would leave the sink wrong.
    if EL0_SINK_LOG.load(Ordering::SeqCst) != WB_SINK_EXPECTED {
        return Err(1072);
    }

    // SAFETY: transient raw access; both threads are off-CPU.
    let dirty = unsafe {
        crate::kcore_exec()
            .ok_or(1073u32)?
            .memory_dirty_count(object)
    };
    // Exactly the bound: the writer dirtied one page more than it allows, and
    // exactly one page was persisted to make room. A kernel that ignored the
    // bound would show one more; one that wrote back everything, far fewer.
    // The bound, exactly. The writer dirtied one page past it, one page was
    // persisted to make room, and then that page was written again — so the
    // object sits at its ceiling. A kernel that ignored the bound would show
    // one more; one that wrote back everything, far fewer.
    let bound = (kcore::memory::MAX_OBJECT_PAGES / 2) as u32;
    if dirty != bound {
        return Err(1074);
    }
    // **The drained page is dirty again**, because the writer stored to it
    // after it was persisted. That is the whole of re-protection: without it
    // the store lands on a still-writable page, nothing faults, nothing is
    // recorded, and the write is thrown away by the eviction that believes the
    // page unchanged. A page still clean here is a lost write.
    // SAFETY: transient raw access; both threads are off-CPU.
    unsafe {
        let exec = crate::kcore_exec().ok_or(1075u32)?;
        if !exec.memory_is_dirty(object, 0) {
            return Err(1076);
        }
    }

    // And the writer's mapping of the drained page is writable again, because
    // its re-write was granted. A page left read-only here would mean the
    // second store faulted and never landed.
    // SAFETY: transient raw access; both threads are off-CPU.
    unsafe {
        let writer = crate::kcore_processes()
            .get_mut(writer_proc)
            .ok_or(1077u32)?;
        let flags = writer
            .space()
            .arch()
            .translate(VirtAddr::new(WB_VA))
            .ok_or(1078u32)?
            .1;
        if !flags.writable() {
            return Err(1079);
        }
    }

    // Teardown.
    // SAFETY: transient raw access; both threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = crate::kcore_exec() {
            exec.scheduler().reap(writer_idx);
            exec.scheduler().reap(service_idx);
        }
        for proc_idx in [writer_proc, service_proc] {
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
        for base in [WB_SERVICE_KSTACK_VA, WB_WRITER_KSTACK_VA] {
            for page in 0..WB_KSTACK_PAGES {
                if let Ok(frame) = kernel_space
                    .arch_mut()
                    .unmap(VirtAddr::new(base + page * FRAME_SIZE))
                {
                    frames.free_frame(frame);
                }
            }
        }
    }

    Ok(dirty)
}
