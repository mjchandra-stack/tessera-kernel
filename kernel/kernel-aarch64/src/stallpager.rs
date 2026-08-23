// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A pager that never answers, and the reader that is told so.
//!
//! `docs/kernel/03` requires that a pager which does not respond leaves its
//! consumers observing **faulted ranges rather than indefinite hangs**. Before
//! this the second half was true only by luck: a page request that was never
//! answered left the faulting thread `Blocked` for ever, the run unwound to
//! boot, and nothing was ever delivered to the reader — no fault, no error, no
//! record. The thread simply stopped existing as far as anything could tell.
//!
//! Here the pager receives the request and parks in a second receive it will
//! never be woken from. The reader must come back with a **fault**, the object
//! must be left in the faulted state, and the deadline miss must be counted —
//! all three, because each one alone can be true for the wrong reason: a reader
//! can fault because the mapping was wrong, an object can be faulted without
//! anybody noticing, and a counter can move without a thread being released.
//!
//! **This is not a timeout.** On a cooperative scheduler the kernel does not
//! guess that the pager is late; it observes that nothing is runnable, which
//! means the answer would have to come from a thread that will not run again.
//! What is being checked is that this is *decided* rather than waited out.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Page-In Flow"
//! step 5, "Ownership, Resize, And Revocation")

use crate::ipc::ipc_spawn_process;
use crate::{
    EL0_DISPATCH_FRAMES, EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KernelAddressSpace,
};
use core::sync::atomic::Ordering;
use tessera_karch::{FRAME_SIZE, VirtAddr};
use tessera_kcore as kcore;

/// Where the reader maps the object. Encoded in the program below.
const STALL_VA: u64 = 0x0000_1000_0080_0000;

/// Kernel stacks, continuing the block `dpage` opened.
const STALL_PAGER_KSTACK_VA: u64 = 0xffff_0001_5000_0000;
const STALL_READER_KSTACK_VA: u64 = 0xffff_0001_6000_0000;
const STALL_KSTACK_PAGES: u64 = 8;

/// Object ids for this check's topology, in a block of its own.
const STALL_PAGER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x200);
/// The kernel's end of the pager channel, which no process holds.
const STALL_KERNEL_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x201);
const STALL_READER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x202);
const STALL_READER_PEER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x203);

/// The handle both programs hold the object at.
const OBJECT_HANDLE: u32 = 1;

// The two ring-3 programs.
//
// The pager takes the request and parks. The reader maps and loads, and is not
// expected to survive the load — the check asserts the fault, so the
// instructions after it are never reached.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.globl stall_pager_start
.globl stall_pager_end
stall_pager_start:
    movz x9, #0x0010, lsl #16
    movk x9, #0x1000, lsl #32       // x9 = USER_STACK_VA
    movz x10, #0x58                 // size = 88
    movk x10, #4, lsl #32           // | version 4
    str  x10, [x9]
    str  xzr, [x9, #8]
    str  xzr, [x9, #16]
    str  xzr, [x9, #24]
    str  xzr, [x9, #32]
    add  x12, x9, #256
    str  x12, [x9, #40]             // inline_ptr
    movz x10, #64
    str  x10, [x9, #48]             // inline_len
    str  xzr, [x9, #56]
    str  xzr, [x9, #64]
    str  xzr, [x9, #72]
    str  xzr, [x9, #80]
    mov  x0, x9
    movz x1, #0
    movz x8, #13                    // ChannelRecv: takes the page request
    svc  #0
    // And parks again, on an endpoint nothing will ever send to. Alive, in a
    // legitimate state, and never going to answer — which is the case that
    // used to strand the reader.
    mov  x0, x9
    movz x1, #0
    movz x8, #13                    // ChannelRecv
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
stall_pager_end:

.balign 16
.globl stall_reader_start
.globl stall_reader_end
stall_reader_start:
    movz x11, #0x0010, lsl #16
    movk x11, #0x1000, lsl #32      // USER_STACK_VA
    movz x10, #32
    movk x10, #1, lsl #32           // size 32 | version 1
    str  x10, [x11]
    str  xzr, [x11, #8]
    movz x10, #1                    // memory = handle 1
    movk x10, #1, lsl #32           // | rights = READ
    str  x10, [x11, #16]
    movz x12, #0x0080, lsl #16
    movk x12, #0x1000, lsl #32      // x12 = STALL_VA
    str  x12, [x11, #24]
    mov  x0, x11
    movz x8, #46                    // MapObject
    svc  #0
    // The load nobody will answer. It must come back as a fault; a reader that
    // got past this line read a page that does not exist.
    ldr  x0, [x12]
    movz x8, #1                     // DebugWrite: only reached if it resumed
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
stall_reader_end:
.text
"#
);

// SAFETY: these name the two blobs' bounds, defined by the `global_asm!` block
// above; the extern block declares them and performs no unsafe operation.
unsafe extern "C" {
    static stall_pager_start: u8;
    static stall_pager_end: u8;
    static stall_reader_start: u8;
    static stall_reader_end: u8;
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

/// Runs the check. `Ok(esr)` is the syndrome the reader faulted with.
pub(crate) fn stallpager_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        crate::el0::kcore_exec_restart(1);
    }
    // SAFETY: transient raw access to the executive this check just built.
    unsafe {
        let exec = crate::kcore_exec().ok_or(960u32)?;
        let (pager_side, kernel_side) = exec.channel_create().map_err(|_| 961u32)?;
        exec.bind_endpoint_object(pager_side, STALL_PAGER_EP_OBJ);
        exec.bind_endpoint_object(kernel_side, STALL_KERNEL_EP_OBJ);
        let (reader_side, peer_side) = exec.channel_create().map_err(|_| 962u32)?;
        exec.bind_endpoint_object(reader_side, STALL_READER_EP_OBJ);
        exec.bind_endpoint_object(peer_side, STALL_READER_PEER_OBJ);
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // SAFETY: the symbols bound the blobs emitted above.
    let pager_blob = unsafe { blob(&raw const stall_pager_start, &raw const stall_pager_end) };
    let (pager_idx, pager_proc) = ipc_spawn_process(
        high,
        frames,
        pager_blob,
        STALL_PAGER_KSTACK_VA,
        STALL_PAGER_EP_OBJ,
        &[0u8; 8],
        965,
    )?;
    // SAFETY: the symbols bound the blobs emitted above.
    let reader_blob = unsafe { blob(&raw const stall_reader_start, &raw const stall_reader_end) };
    let (reader_idx, reader_proc) = ipc_spawn_process(
        high,
        frames,
        reader_blob,
        STALL_READER_KSTACK_VA,
        STALL_READER_EP_OBJ,
        &[0u8; 8],
        970,
    )?;

    // SAFETY: transient raw access; no thread is running yet.
    let object = unsafe {
        let owner = crate::kcore_processes()
            .get_mut(pager_proc)
            .ok_or(975u32)?
            .id();
        let exec = crate::kcore_exec().ok_or(976u32)?;
        let object = exec
            .memory_create_paged(owner, 1, STALL_PAGER_EP_OBJ)
            .map_err(|_| 977u32)?;
        exec.paging_bind(object, STALL_PAGER_EP_OBJ)
            .map_err(|_| 978u32)?;
        object
    };
    // SAFETY: transient raw access; no thread is running yet.
    unsafe {
        let processes = crate::kcore_processes();
        let pager_handle = processes
            .get_mut(pager_proc)
            .ok_or(979u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::SUPPLY)
            .map_err(|_| 980u32)?;
        if pager_handle.raw() != OBJECT_HANDLE {
            return Err(981);
        }
        let reader_handle = processes
            .get_mut(reader_proc)
            .ok_or(982u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::MAP)
            .map_err(|_| 983u32)?;
        if reader_handle.raw() != OBJECT_HANDLE {
            return Err(984);
        }
    }

    // Nothing has been supplied, and nothing will be.
    // SAFETY: transient raw access; no thread is running yet.
    let (misses_before, escalations_before) = unsafe {
        let exec = crate::kcore_exec().ok_or(985u32)?;
        if exec.memory_resident_pages(object) != 0 {
            return Err(986);
        }
        (exec.page_in_misses(), exec.page_in_escalations())
    };

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

    // **The run must end.** If it does not, this check hangs and the harness
    // kills the machine — which is the honest way to fail a claim about not
    // hanging, and is what this did before the expiry existed.
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

    // What the kernel recorded while the reader was blocked, read before the
    // assertions below so a full ring cannot swallow it.
    let mut sink = [kcore::event::record(
        kcore::event::EventKind::EventsDropped,
        kcore::event::Severity::Debug,
        kcore::event::Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    ); kcore::event::EVENT_RING_CAPACITY];
    let drained = kcore::event::drain(&mut sink);
    let records = &sink[..drained];

    // 1. The reader was told. A fault is what `docs/kernel/03` step 5 requires
    //    be delivered to the faulting thread's exception path, and it is the
    //    difference between this and a thread that simply stopped.
    let esr = EL0_SINK_FAULT.load(Ordering::SeqCst);
    if esr == 0 {
        return Err(990);
    }
    // 2. And it never got past the load. A reader that reported anything read a
    //    page nobody supplied.
    if EL0_SINK_LOG.load(Ordering::SeqCst) != 0 {
        return Err(991);
    }

    // SAFETY: transient raw access; both threads are off-CPU.
    unsafe {
        let exec = crate::kcore_exec().ok_or(992u32)?;
        // 3. The object is faulted, so the next reader is refused immediately
        //    rather than waiting on a pager that has already failed once.
        if !exec.memory_is_faulted(object) {
            return Err(993);
        }
        // 4. And the miss was counted. Without this the first three could all
        //    be true because the mapping was broken rather than because a
        //    deadline was enforced.
        if exec.page_in_misses() != misses_before + 1 {
            return Err(994);
        }
        // One miss is not yet an escalation: the policy is three, and a check
        // that could not tell the two apart would pass with either.
        if exec.page_in_escalations() != escalations_before {
            return Err(995);
        }
        // 5. Nothing is left in flight — a record kept after the request was
        //    failed would make the next page-in look like a second one.
        if exec.paging_in_flight() != 0 {
            return Err(996);
        }
    }

    // 6. **And the reason is the true one.** Finding no reply on the endpoint
    //    also produces a failure — `PeerClosed` — so every assertion above
    //    holds just as well when the kernel never tells the faulter it gave up
    //    and the fault falls out of an empty queue instead. The peer here is
    //    alive and merely silent, and a caller told otherwise would stop
    //    retrying something that may work next time. This is the assertion that
    //    separates the two, and without it the code that distinguishes them can
    //    be deleted with every other check still green.
    let reason = records
        .iter()
        .find(|record| {
            record.component == kcore::event::Component::Pager
                && record.kind == kcore::event::EventKind::PagerObjectFaulted
                && record.arg0 == u64::from(object.raw())
        })
        .map(|record| record.arg2);
    if reason != Some(u64::from(tessera_karch::KError::TimedOut.code())) {
        return Err(997);
    }
    // 7. The reader's mapping is still empty. A fault that arrived *and* left
    //    a page behind would mean the kernel installed something before giving
    //    up, which is the one way this could look right and be wrong.
    // SAFETY: transient raw access; both threads are off-CPU.
    unsafe {
        let reader = crate::kcore_processes()
            .get_mut(reader_proc)
            .ok_or(997u32)?;
        if reader
            .space()
            .arch()
            .translate(VirtAddr::new(STALL_VA))
            .is_some()
        {
            return Err(999);
        }
    }

    // 8. And the miss itself was recorded, not merely counted.
    if !records.iter().any(|record| {
        record.component == kcore::event::Component::Pager
            && record.kind == kcore::event::EventKind::PagerDeadlineMiss
    }) {
        return Err(998);
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
        for base in [STALL_PAGER_KSTACK_VA, STALL_READER_KSTACK_VA] {
            for page in 0..STALL_KSTACK_PAGES {
                if let Ok(frame) = kernel_space
                    .arch_mut()
                    .unmap(VirtAddr::new(base + page * FRAME_SIZE))
                {
                    frames.free_frame(frame);
                }
            }
        }
    }

    Ok(esr)
}
