// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A ring-3 program touching pages that are not there yet.
//!
//! Until now an EL0 fault on this port meant one thing: the thread had done
//! something wrong, and it was ended. That made a whole class of mapping
//! impossible to have — a region recorded but not populated, filled by the
//! access that needs it — which is the mechanism a page cache is built out of.
//! x86-64 has had it since the demand-paging demo; the other four ports had the
//! classifier ([`kcore::vm::AddressSpace::resolve_fault`]) and no caller.
//!
//! What this proves is small and specific: a region mapped with
//! [`map_anonymous_demand`](kcore::vm::AddressSpace::map_anonymous_demand) has
//! no pages, a ring-3 read of one **faults, fills, and resumes**, the filled
//! page reads back as zero, and a store to it sticks. The zero matters as much
//! as the store: a demand page that arrived holding somebody else's bytes would
//! satisfy every check that only looked at what this program wrote.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Fault Taxonomy")
//! Budget: B8

use crate::ipc::ipc_spawn_process;
use crate::{
    EL0_DISPATCH_FRAMES, EL0_SINK_EXITED, EL0_SINK_FAULT, EL0_SINK_LOG, KCORE_EXEC,
    KernelAddressSpace,
};
use core::sync::atomic::Ordering;
use tessera_karch::{FRAME_SIZE, PageFlags, VirtAddr};
use tessera_kcore as kcore;

/// Where the demand-mapped region goes: two pages at a user address this port's
/// other checks leave free (`0x…10_0000` stack, `0x…30_0000` data,
/// `0x…40_0000` MMIO).
///
/// Also encoded in the program below, in the `movz`/`movk` pair that builds
/// `x9`; this constant is what the mapping is made at, and the two must agree
/// or the program faults on an address nothing covers.
pub(crate) const DPAGE_VA: u64 = 0x0000_1000_0050_0000;
const DPAGE_PAGES: u64 = 2;

/// The kernel stack for this check's one thread.
///
/// **In its own block, and reclaimed below.** These windows are hand-picked
/// constants spread across a dozen modules, and the first value tried here was
/// `0xffff_0000_a000_0000` — which is `MMIO_KSTACK_VA`. Nothing complained at
/// the collision: this check ran, left its stack mapped, and the *next* check
/// to spawn a thread failed inside `spawn_user` on an address already occupied,
/// reporting a number that says nothing about kernel stacks.
pub(crate) const DPAGE_KSTACK_VA: u64 = 0xffff_0001_0000_0000;
/// Kernel-stack pages per thread, matching what `ipc_spawn_process` maps.
const DPAGE_KSTACK_PAGES: u64 = 8;
const _: () = assert!(DPAGE_KSTACK_VA != crate::ipc::MMIO_KSTACK_VA);
const _: () = assert!(DPAGE_KSTACK_VA != crate::el0::IPC_SERVER_KSTACK_VA);
const _: () = assert!(DPAGE_KSTACK_VA != crate::el0::IPC_CLIENT_KSTACK_VA);

/// Written to the first demand page, then read back.
const DPAGE_MAGIC_A: u64 = 0xd00d_cafe;
/// Written to the second, so one report needs both pages.
const DPAGE_MAGIC_B: u64 = 0xfeed_beef;

/// What the program reports: both magics read back, XORed with its read of the
/// page *before* it wrote anything.
///
/// That last term is the zero-fill claim folded into the same number. A demand
/// page arrives zeroed, so the term vanishes and the report is the two magics;
/// a page that arrived holding anything else perturbs it and the check fails.
pub(crate) const DPAGE_EXPECTED: u64 = DPAGE_MAGIC_A ^ DPAGE_MAGIC_B;

/// The endpoint object the spawned process is handed at handle 0. It never uses
/// it — this program makes no IPC call — but every process built by
/// `ipc_spawn_process` gets one, and a real one is cheaper than a special case.
const DPAGE_ENDPOINT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d0);

// The ring-3 program. Absolute user VAs: it runs at `USER_CODE_VA` in its own
// space and the region below is mapped at a fixed address, so nothing here is
// an in-blob label and none of it needs relocating.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.globl dpage_program_start
.globl dpage_program_end
dpage_program_start:
    movz x9, #0x0050, lsl #16
    movk x9, #0x1000, lsl #32       // x9 = DPAGE_VA
    ldr  x4, [x9]                   // read before writing: demand-fills page 0,
                                    // and must come back zero
    movz x10, #0xcafe
    movk x10, #0xd00d, lsl #16      // x10 = DPAGE_MAGIC_A
    str  x10, [x9]
    add  x11, x9, #1, lsl #12       // page 1, still absent
    movz x12, #0xbeef
    movk x12, #0xfeed, lsl #16      // x12 = DPAGE_MAGIC_B
    str  x12, [x11]                 // a *store* to an absent page fills it too
    ldr  x5, [x9]
    ldr  x6, [x11]
    eor  x0, x5, x6
    eor  x0, x0, x4                 // folds in the pre-write read
    movz x8, #1                     // DebugWrite
    svc  #0
    movz x0, #0
    movz x8, #5                     // ProcessExit
    svc  #0
1:  b 1b
dpage_program_end:
.text
"#
);

// SAFETY: these name the bounds of the blob defined by the `global_asm!` block
// above; the extern block declares them and performs no unsafe operation.
unsafe extern "C" {
    static dpage_program_start: u8;
    static dpage_program_end: u8;
}

/// The blob as bytes, taken from the symbols the assembler placed.
fn program() -> &'static [u8] {
    let start = &raw const dpage_program_start;
    let end = &raw const dpage_program_end;
    // SAFETY: both symbols bound one contiguous `.rodata` object emitted by the
    // `global_asm!` above, `end` follows `start`, and the bytes are immutable
    // for the kernel's lifetime.
    unsafe { core::slice::from_raw_parts(start, (end as usize) - (start as usize)) }
}

/// Runs the check. `Ok(report)` is what the ring-3 program reported.
pub(crate) fn dpage_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use tessera_karch::AddressSpaceOps;

    // A fresh executive, like every other check on this substrate: the device
    // graph and the scheduler are this check's alone.
    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the executive this check just built.
    let endpoint = unsafe {
        let exec = crate::kcore_exec().ok_or(700u32)?;
        let (a, _b) = exec.channel_create().map_err(|_| 701u32)?;
        exec.bind_endpoint_object(a, DPAGE_ENDPOINT_OBJ);
        DPAGE_ENDPOINT_OBJ
    };

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    let (thread_idx, proc_idx) = ipc_spawn_process(
        high,
        frames,
        program(),
        DPAGE_KSTACK_VA,
        endpoint,
        &[0u8; 8],
        710,
    )?;

    // The region under test: recorded, deliberately not populated. Nothing here
    // allocates a frame for it — the first access does, through the fault.
    // SAFETY: transient raw access to the static process table; the borrow ends
    // before the scheduler runs.
    unsafe {
        let process = crate::kcore_processes().get_mut(proc_idx).ok_or(720u32)?;
        process
            .space_mut()
            .map_anonymous_demand(
                VirtAddr::new(DPAGE_VA),
                DPAGE_PAGES * FRAME_SIZE,
                PageFlags::rw().user(),
            )
            .map_err(|_| 721u32)?;
        // Asserted, not assumed: if anything had populated these the program
        // could report the right number without a fault ever happening, and
        // this check would be measuring nothing.
        for page in 0..DPAGE_PAGES {
            if process
                .space()
                .arch()
                .translate(VirtAddr::new(DPAGE_VA + page * FRAME_SIZE))
                .is_some()
            {
                return Err(722);
            }
        }
    }

    // The fault path allocates the pages it fills, so the hook needs the boot
    // allocator — a null pointer here is the 0xbad2 sink, not a fill.
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

    // SAFETY: transient raw access; `run` returns when the thread yields.
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
        return Err(730);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(731);
    }
    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    if report != DPAGE_EXPECTED {
        return Err(732);
    }

    // The report says the program read what it wrote. This says the pages it
    // read are pages that did not exist when it started — which is the whole
    // claim, and the half a report cannot make on its own.
    // SAFETY: transient raw access; the thread is off-CPU (it exited).
    unsafe {
        let process = crate::kcore_processes().get_mut(proc_idx).ok_or(733u32)?;
        for page in 0..DPAGE_PAGES {
            if process
                .space()
                .arch()
                .translate(VirtAddr::new(DPAGE_VA + page * FRAME_SIZE))
                .is_none()
            {
                return Err(734);
            }
        }
    }

    // Teardown: reap the thread and remove the process, which frees the table
    // slot so a later check's threads do not collide with this stale index.
    // SAFETY: transient raw access; the thread is off-CPU, removed once.
    unsafe {
        if let Some(exec) = crate::kcore_exec() {
            exec.scheduler().reap(thread_idx);
        }
        if let Some(mut process) = crate::kcore_processes().remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }
    // And give the kernel stack back. `teardown` above is the *user* space; the
    // stack lives in the kernel half, and a check that leaves one mapped hands
    // the next spawn at that address a failure with nothing in it about stacks.
    {
        use tessera_karch::FrameSource;
        // SAFETY: `high` is the active kernel high-half space; the alias only
        // unmaps this check's own stack pages and is never torn down.
        let kernel_arch =
            unsafe { KernelAddressSpace::from_root(high.root_phys(), crate::DIRECT_MAP_BASE) };
        let mut kernel_space =
            kcore::vm::AddressSpace::from_arch(kernel_arch, kcore::vm::Asid(0), 0);
        for page in 0..DPAGE_KSTACK_PAGES {
            if let Ok(frame) = kernel_space
                .arch_mut()
                .unmap(VirtAddr::new(DPAGE_KSTACK_VA + page * FRAME_SIZE))
            {
                frames.free_frame(frame);
            }
        }
    }

    Ok(report)
}
