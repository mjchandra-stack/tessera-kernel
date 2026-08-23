// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A ring-3 program writes to a cached page, and the kernel knows it happened.
//!
//! Until now a mapped file could only be read. `Repair::WriteGranted` made the
//! page writable and recorded nothing (D205), so a store landed in a page the
//! kernel believed unchanged — and a page believed unchanged is one write-back
//! never persists and eviction throws away. That is why every object handed to
//! a client so far has been mapped read-only: the write path was not that it
//! was forbidden, it was that it would have been silently lost.
//!
//! What this proves is the software dirty bit end to end. A page is supplied
//! **read-only even though the mapping grants write** — that is not a mistake,
//! it is the mechanism: the first store faults, and that fault is the kernel's
//! only chance to notice. The page is recorded dirty, the write is granted, the
//! store lands, and a second store to the same page does not fault again.
//!
//! And the bound: an object may hold only so many dirty pages before a writer
//! is refused. This writes every page of an object and asserts that some were
//! refused with pages still clean — a ceiling nobody ever reaches is a number
//! in a struct.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Dirty tracking",
//! "Write-Back Under Memory Pressure")

use crate::ipc::ipc_spawn_process;
use crate::{
    EL0_DISPATCH_FRAMES, EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KCORE_EXEC,
    KernelAddressSpace,
};
use core::sync::atomic::Ordering;
use tessera_karch::{FRAME_SIZE, VirtAddr};
use tessera_kcore as kcore;

/// Where the writer maps the object. Encoded in the program below.
const DIRTY_VA: u64 = 0x0000_1000_0090_0000;
/// Pages in the object: every one supplied up front, so the run is about
/// writing rather than about paging in.
///
/// **As many as an object may hold**, because the dirty bound is a fraction of
/// that — an object smaller than the bound can never reach it, and the first
/// version of this check used four pages against a bound of eight and proved
/// nothing about throttling at all.
const DIRTY_PAGES: u64 = kcore::memory::MAX_OBJECT_PAGES as u64;

/// Kernel stacks, continuing the block `dpage` opened.
const DIRTY_KSTACK_VA: u64 = 0xffff_0001_7000_0000;
const DIRTY_KSTACK_PAGES: u64 = 8;

/// What the writer stores into the first page, and reads back.
const DIRTY_MAGIC: u64 = 0xd127_a9e5_d127_a9e5;

/// Object ids for this check's topology, in a block of its own.
const DIRTY_PAGER_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x210);
const DIRTY_KERNEL_EP_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x211);

/// The handle the program holds the object at.
const OBJECT_HANDLE: u32 = 1;

// The ring-3 program: map the object read-write, store, read back, store again.
//
// The second store is the one that says the grant stuck. If the kernel
// re-protected the page or never granted, it faults, and the check reports a
// fault rather than a wrong value.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.globl dirty_writer_start
.globl dirty_writer_end
dirty_writer_start:
    movz x11, #0x0010, lsl #16
    movk x11, #0x1000, lsl #32      // USER_STACK_VA
    movz x10, #32
    movk x10, #1, lsl #32           // size 32 | version 1
    str  x10, [x11]
    str  xzr, [x11, #8]
    movz x10, #1                    // memory = handle 1
    movk x10, #3, lsl #32           // | rights = READ | WRITE
    str  x10, [x11, #16]
    movz x12, #0x0090, lsl #16
    movk x12, #0x1000, lsl #32      // x12 = DIRTY_VA
    str  x12, [x11, #24]
    mov  x0, x11
    movz x8, #46                    // MapObject
    svc  #0

    movz x13, #0xa9e5
    movk x13, #0xd127, lsl #16
    movk x13, #0xa9e5, lsl #32
    movk x13, #0xd127, lsl #48      // x13 = DIRTY_MAGIC
    // The first store faults: the page is supplied read-only so that it does.
    str  x13, [x12]
    // The second must not. A page re-protected or never granted faults here,
    // and the check sees a fault instead of a report.
    str  x13, [x12, #8]
    ldr  x0, [x12]
    movz x8, #1                     // DebugWrite
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
dirty_writer_end:
.text
"#
);

// SAFETY: these name the blob's bounds, defined by the `global_asm!` block
// above; the extern block declares them and performs no unsafe operation.
unsafe extern "C" {
    static dirty_writer_start: u8;
    static dirty_writer_end: u8;
}

/// The blob's bytes, from the symbols the assembler placed.
fn program() -> &'static [u8] {
    let start = &raw const dirty_writer_start;
    let end = &raw const dirty_writer_end;
    // SAFETY: both symbols bound one contiguous `.rodata` object emitted by the
    // `global_asm!` above, and the bytes are immutable for the kernel's
    // lifetime.
    unsafe { core::slice::from_raw_parts(start, (end as usize) - (start as usize)) }
}

/// Runs the check. `Ok((dirty, refused))` is how many pages ended dirty and how
/// many writes the bound refused.
pub(crate) fn dirtypage_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u32, u64), u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the executive this check just built.
    unsafe {
        let exec = crate::kcore_exec().ok_or(1000u32)?;
        let (pager_side, kernel_side) = exec.channel_create().map_err(|_| 1001u32)?;
        exec.bind_endpoint_object(pager_side, DIRTY_PAGER_EP_OBJ);
        exec.bind_endpoint_object(kernel_side, DIRTY_KERNEL_EP_OBJ);
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    let (writer_idx, writer_proc) = ipc_spawn_process(
        high,
        frames,
        program(),
        DIRTY_KSTACK_VA,
        DIRTY_PAGER_EP_OBJ,
        &[0u8; 8],
        1005,
    )?;

    // The object, with every page already supplied: this check is about the
    // write fault, and a page-in in the middle of it would prove neither.
    // SAFETY: transient raw access; no thread is running yet.
    let object = unsafe {
        let owner = crate::kcore_processes()
            .get_mut(writer_proc)
            .ok_or(1010u32)?
            .id();
        let exec = crate::kcore_exec().ok_or(1011u32)?;
        let object = exec
            .memory_create_paged(owner, DIRTY_PAGES as usize, DIRTY_PAGER_EP_OBJ)
            .map_err(|_| 1012u32)?;
        for page in 0..DIRTY_PAGES {
            let frame = frames.alloc().ok_or(1013u32)?;
            exec.memory_supply(object, page as usize, frame)
                .map_err(|_| 1014u32)?;
        }
        object
    };
    // SAFETY: transient raw access; no thread is running yet.
    unsafe {
        let handle = crate::kcore_processes()
            .get_mut(writer_proc)
            .ok_or(1015u32)?
            .handles_mut()
            .install(object, Rights::READ | Rights::WRITE | Rights::MAP)
            .map_err(|_| 1016u32)?;
        if handle.raw() != OBJECT_HANDLE {
            return Err(1017);
        }
        // Nothing is dirty before anybody writes. Without this the assertions
        // below could be satisfied by an object that started that way.
        if crate::kcore_exec()
            .ok_or(1018u32)?
            .memory_dirty_count(object)
            != 0
        {
            return Err(1019);
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
        return Err(1020);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(1021);
    }
    // The writer read back what it wrote, so the store reached the page rather
    // than a copy of it.
    if EL0_SINK_LOG.load(Ordering::SeqCst) != DIRTY_MAGIC {
        return Err(1022);
    }

    // SAFETY: transient raw access; the thread is off-CPU.
    let dirty = unsafe {
        let exec = crate::kcore_exec().ok_or(1023u32)?;
        // The page it wrote is dirty, and the ones it did not are not — a
        // kernel that dirtied on any fault would pass a count and fail this.
        if !exec.memory_is_dirty(object, 0) {
            return Err(1024);
        }
        for page in 1..DIRTY_PAGES {
            if exec.memory_is_dirty(object, page * FRAME_SIZE) {
                return Err(1025);
            }
        }
        exec.memory_dirty_count(object)
    };
    if dirty != 1 {
        return Err(1026);
    }

    // And the page really is writable now, so the second store landed rather
    // than faulting into a resume loop.
    // SAFETY: transient raw access; the thread is off-CPU.
    unsafe {
        let writer = crate::kcore_processes()
            .get_mut(writer_proc)
            .ok_or(1027u32)?;
        let flags = writer
            .space()
            .arch()
            .translate(VirtAddr::new(DIRTY_VA))
            .ok_or(1028u32)?
            .1;
        if !flags.writable() {
            return Err(1029);
        }
    }

    // The bound, exercised on the kernel's side of the same object: every page
    // dirtied in turn until it refuses. Done here rather than from ring 3
    // because a refused write is a fault, and a program that took one would
    // stop before it could report how many it managed.
    // SAFETY: transient raw access; the thread is off-CPU.
    let refused = unsafe {
        let exec = crate::kcore_exec().ok_or(1030u32)?;
        let mut refused = 0u64;
        for page in 1..DIRTY_PAGES {
            if exec.memory_mark_dirty(object, page * FRAME_SIZE)
                == kcore::pager::DirtyOutcome::Throttle
            {
                refused += 1;
            }
        }
        refused
    };
    // Some were refused, and some were not: a bound that refused everything or
    // nothing would satisfy a check that only counted one of the two.
    if refused == 0 || refused >= DIRTY_PAGES - 1 {
        return Err(1031);
    }

    // Teardown.
    // SAFETY: transient raw access; the thread is off-CPU, removed once.
    unsafe {
        if let Some(exec) = crate::kcore_exec() {
            exec.scheduler().reap(writer_idx);
        }
        if let Some(mut process) = crate::kcore_processes().remove(writer_proc) {
            process.space_mut().teardown(frames);
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
        for page in 0..DIRTY_KSTACK_PAGES {
            if let Ok(frame) = kernel_space
                .arch_mut()
                .unmap(VirtAddr::new(DIRTY_KSTACK_VA + page * FRAME_SIZE))
            {
                frames.free_frame(frame);
            }
        }
    }

    Ok((dirty, refused))
}
