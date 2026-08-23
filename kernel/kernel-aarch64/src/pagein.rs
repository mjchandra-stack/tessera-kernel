// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A thread faults on a page nobody has, and a ring-3 service puts it there.
//!
//! This is the flow `docs/kernel/03` calls "Page-In": a thread touches a
//! resolvable, non-present page; the kernel blocks it and sends a request to
//! the object's pager; the pager supplies the contents; the kernel installs the
//! page and resumes the thread. Until now the kernel could hold pages a pager
//! had pushed to it ahead of time (D206) but had no way to *ask* — a fault on
//! an unsupplied page was reported like a protection violation.
//!
//! **The pager is an ordinary server.** It parks in `ChannelRecv`, gets a
//! `PageInRequest` on its endpoint, calls `PageSupply`, and replies. Nothing
//! about its shape says the caller is the kernel, which is what keeps a
//! filesystem service from having to be written against one.
//!
//! What the check turns on is that the client's read *cannot* succeed without
//! the round trip: the object is created empty, nothing is supplied before the
//! run, and the client's first instruction touching it is the fault.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Page-In Flow")
//! Budget: B10

use crate::ipc::ipc_spawn_process;
use crate::{
    EL0_DISPATCH_FRAMES, EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KCORE_EXEC,
    KernelAddressSpace,
};
use core::sync::atomic::Ordering;
use tessera_karch::{FRAME_SIZE, VirtAddr};
use tessera_kcore as kcore;

/// Where the client maps the object — one page, clear of every other window
/// this port's checks use. Encoded in the client program below.
const PAGEIN_VA: u64 = 0x0000_1000_0070_0000;

/// Kernel stacks, continuing the block `dpage` opened.
const PAGEIN_PAGER_KSTACK_VA: u64 = 0xffff_0001_3000_0000;
const PAGEIN_CLIENT_KSTACK_VA: u64 = 0xffff_0001_4000_0000;
const PAGEIN_KSTACK_PAGES: u64 = 8;

/// The bytes the kernel seeds into the pager's data page, which it supplies on
/// demand and the client reads back.
const PAGEIN_MAGIC: u64 = 0xfa17_ed10_fa17_ed10;

/// The sink: the one word the client read. The pager reports nothing — its
/// evidence is that the client read anything at all, since without the round
/// trip the read faults and the check fails on that instead.
pub(crate) const PAGEIN_SINK_EXPECTED: u64 = PAGEIN_MAGIC;

/// Object ids for this check's topology, in a block of its own.
const PAGEIN_PAGER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1f0);
/// The other side of the pager's channel. **Nobody holds it**: it is the
/// kernel's end, and the page request is sent from it.
const PAGEIN_KERNEL_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1f1);
const PAGEIN_CLIENT_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1f2);
const PAGEIN_CLIENT_PEER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1f3);

/// The handle both programs expect the object at: handle 0 is the endpoint
/// `ipc_spawn_process` installs, so the object is 1.
const OBJECT_HANDLE: u32 = 1;

// The two ring-3 programs.
//
// The pager works entirely out of its own stack page: the request buffer, the
// two argument structs and the reply all live at fixed offsets in it, so its
// data page can stay the pristine page it supplies.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.globl pagein_pager_start
.globl pagein_pager_end
pagein_pager_start:
    movz x9, #0x0010, lsl #16
    movk x9, #0x1000, lsl #32       // x9 = USER_STACK_VA

    // --- ChannelMsgArgs (88 bytes, version 4) for the receive ---
    movz x10, #0x58                 // size = 88
    movk x10, #4, lsl #32           // | version 4
    str  x10, [x9]
    str  xzr, [x9, #8]              // flags
    str  xzr, [x9, #16]             // interface_id (kernel stamps the request's)
    str  xzr, [x9, #24]             // txn_id
    str  xzr, [x9, #32]             // method_id | msg_flags
    add  x12, x9, #256              // the request lands here
    str  x12, [x9, #40]             // inline_ptr
    movz x10, #64
    str  x10, [x9, #48]             // inline_len (a PageInRequest is 32)
    str  xzr, [x9, #56]             // handles_ptr
    str  xzr, [x9, #64]             // handle_count
    str  xzr, [x9, #72]             // installed_ptr
    str  xzr, [x9, #80]             // installed_cap
    mov  x0, x9
    movz x1, #0                     // endpoint handle 0
    movz x8, #13                    // ChannelRecv
    svc  #0

    // --- PageSupplyArgs (40 bytes) at stack + 512 ---
    ldr  x13, [x12, #24]            // the request's offset field
    add  x14, x9, #512
    movz x10, #40
    movk x10, #1, lsl #32           // size 40 | version 1
    str  x10, [x14]
    str  xzr, [x14, #8]             // flags
    movz x10, #1                    // memory = handle 1, reserved = 0
    str  x10, [x14, #16]
    str  x13, [x14, #24]            // offset: the one that was asked for
    movz x15, #0x0030, lsl #16
    movk x15, #0x1000, lsl #32      // USER_DATA_VA, seeded by the kernel
    str  x15, [x14, #32]            // source
    mov  x0, x14
    movz x8, #22                    // PageSupply
    svc  #0

    // --- PageInReply (24 bytes) at stack + 640 ---
    cmp  x0, #0
    cset w16, eq                    // supplied = (PageSupply returned 0)
    add  x17, x9, #640
    movz x10, #24
    movk x10, #1, lsl #32           // size 24 | version 1
    str  x10, [x17]
    str  xzr, [x17, #8]             // flags
    str  xzr, [x17, #16]            // supplied byte + its padding, zeroed
    strb w16, [x17, #16]

    // --- reply on the same descriptor ---
    str  x17, [x9, #40]             // inline_ptr = the reply
    movz x10, #24
    str  x10, [x9, #48]             // inline_len
    mov  x0, x9
    movz x1, #0
    movz x8, #15                    // ChannelReply
    svc  #0

    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
pagein_pager_end:

.balign 16
.globl pagein_client_start
.globl pagein_client_end
pagein_client_start:
    // MemoryMapArgs (32 bytes) on the stack page.
    movz x11, #0x0010, lsl #16
    movk x11, #0x1000, lsl #32      // USER_STACK_VA
    movz x10, #32
    movk x10, #1, lsl #32           // size 32 | version 1
    str  x10, [x11]
    str  xzr, [x11, #8]             // flags
    movz x10, #1                    // memory = handle 1
    movk x10, #1, lsl #32           // | rights = READ
    str  x10, [x11, #16]
    movz x12, #0x0070, lsl #16
    movk x12, #0x1000, lsl #32      // x12 = PAGEIN_VA
    str  x12, [x11, #24]
    mov  x0, x11
    movz x8, #46                    // MapObject
    svc  #0

    // **The fault.** Nothing has been supplied, so this load has no page to
    // read: it traps, the kernel asks the pager, and the instruction runs
    // again with the page in place.
    ldr  x0, [x12]
    movz x8, #1                     // DebugWrite
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
pagein_client_end:
.text
"#
);

// SAFETY: these name the two blobs' bounds, defined by the `global_asm!` block
// above; the extern block declares them and performs no unsafe operation.
unsafe extern "C" {
    static pagein_pager_start: u8;
    static pagein_pager_end: u8;
    static pagein_client_start: u8;
    static pagein_client_end: u8;
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

/// Runs the check. `Ok(report)` is the word the client read.
pub(crate) fn pagein_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // Two channels. The pager's has a side nobody is given — that is the one
    // the kernel sends page requests from, and binding an object to it is what
    // makes it findable later.
    // SAFETY: transient raw access to the executive this check just built.
    unsafe {
        let exec = crate::kcore_exec().ok_or(900u32)?;
        let (pager_side, kernel_side) = exec.channel_create().map_err(|_| 901u32)?;
        exec.bind_endpoint_object(pager_side, PAGEIN_PAGER_EP_OBJ);
        exec.bind_endpoint_object(kernel_side, PAGEIN_KERNEL_EP_OBJ);
        let (client_side, peer_side) = exec.channel_create().map_err(|_| 902u32)?;
        exec.bind_endpoint_object(client_side, PAGEIN_CLIENT_EP_OBJ);
        exec.bind_endpoint_object(peer_side, PAGEIN_CLIENT_PEER_OBJ);
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // The pager is built first so it schedules first and is parked in `recv`
    // before the client can fault. A page request that arrived at an endpoint
    // nobody was waiting on would queue, and the faulting thread would block
    // until the pager got round to it — which happens never, because the pager
    // only runs when the faulter yields.
    // SAFETY: the symbols bound the blobs emitted above.
    let pager_blob = unsafe { blob(&raw const pagein_pager_start, &raw const pagein_pager_end) };
    let (pager_idx, pager_proc) = ipc_spawn_process(
        high,
        frames,
        pager_blob,
        PAGEIN_PAGER_KSTACK_VA,
        PAGEIN_PAGER_EP_OBJ,
        &PAGEIN_MAGIC.to_le_bytes(),
        910,
    )?;
    // SAFETY: the symbols bound the blobs emitted above.
    let client_blob = unsafe { blob(&raw const pagein_client_start, &raw const pagein_client_end) };
    let (client_idx, client_proc) = ipc_spawn_process(
        high,
        frames,
        client_blob,
        PAGEIN_CLIENT_KSTACK_VA,
        PAGEIN_CLIENT_EP_OBJ,
        &[0u8; 8],
        920,
    )?;

    // One page, empty, bound to the pager's endpoint.
    // SAFETY: transient raw access; no thread is running yet.
    let object = unsafe {
        let owner = crate::kcore_processes()
            .get_mut(pager_proc)
            .ok_or(930u32)?
            .id();
        let exec = crate::kcore_exec().ok_or(931u32)?;
        let object = exec
            .memory_create_paged(owner, 1, PAGEIN_PAGER_EP_OBJ)
            .map_err(|_| 932u32)?;
        exec.paging_bind(object, PAGEIN_PAGER_EP_OBJ)
            .map_err(|_| 933u32)?;
        object
    };
    // SAFETY: transient raw access; no thread is running yet.
    unsafe {
        let processes = crate::kcore_processes();
        let pager_handle = processes
            .get_mut(pager_proc)
            .ok_or(934u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::SUPPLY)
            .map_err(|_| 935u32)?;
        if pager_handle.raw() != OBJECT_HANDLE {
            return Err(936);
        }
        let client_handle = processes
            .get_mut(client_proc)
            .ok_or(937u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::MAP)
            .map_err(|_| 938u32)?;
        if client_handle.raw() != OBJECT_HANDLE {
            return Err(939);
        }
    }
    // Asserted, not assumed: if anything had supplied this page the client
    // would read it without ever faulting, and the check would be measuring
    // the mapping rather than the page-in.
    // SAFETY: transient raw access; no thread is running yet.
    unsafe {
        if crate::kcore_exec()
            .ok_or(940u32)?
            .memory_resident_pages(object)
            != 0
        {
            return Err(941);
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
            exec.scheduler().run();
        }
    }
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Back to the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(950);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(951);
    }
    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    if report != PAGEIN_SINK_EXPECTED {
        return Err(952);
    }

    // The page arrived, and the in-flight edge the cycle guard recorded was
    // cleared — a page-in that completed but left its edge would make the next
    // one look like a loop.
    // SAFETY: transient raw access; both threads are off-CPU.
    unsafe {
        let exec = crate::kcore_exec().ok_or(953u32)?;
        if exec.memory_resident_pages(object) != 1 {
            return Err(954);
        }
        if exec.paging_in_flight() != 0 {
            return Err(955);
        }
        // And the page landed where the client asked for it. The report says a
        // word arrived; this says it came from the mapping under test rather
        // than from anywhere else the client could have read.
        let client = crate::kcore_processes()
            .get_mut(client_proc)
            .ok_or(956u32)?;
        if client
            .space()
            .arch()
            .translate(VirtAddr::new(PAGEIN_VA))
            .is_none()
        {
            return Err(957);
        }
    }

    // Teardown: both threads, both processes, then the object.
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
    {
        use tessera_karch::FrameSource;
        // SAFETY: `high` is the active kernel high-half space; the alias only
        // unmaps this check's own stack pages and is never torn down.
        let kernel_arch =
            unsafe { KernelAddressSpace::from_root(high.root_phys(), crate::DIRECT_MAP_BASE) };
        let mut kernel_space =
            kcore::vm::AddressSpace::from_arch(kernel_arch, kcore::vm::Asid(0), 0);
        for base in [PAGEIN_PAGER_KSTACK_VA, PAGEIN_CLIENT_KSTACK_VA] {
            for page in 0..PAGEIN_KSTACK_PAGES {
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
