// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Per-process address spaces.
//!
//! Two Sv39 roots, each with its own ASID, reading different data at one virtual
//! address. The kernel half is copied by value into every root, so a kernel
//! mapping made after a root is taken is not in it (D99).
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
// Per-process address spaces
// ---------------------------------------------------------------------------

/// What each process finds at [`USER_DATA_VA`]. Two values, one address.
pub(crate) const PROCESS_A_DATA: u64 = 0xa1a1_a1a1_0000_0001;
pub(crate) const PROCESS_B_DATA: u64 = 0xb2b2_b2b2_0000_0002;
/// What process A finds at [`USER_PRIVATE_VA`], which B does not map at all.
pub(crate) const PROCESS_A_PRIVATE: u64 = 0x0dd1_0dd1_0000_0003;

/// ASIDs. Non-zero and distinct: zero means the kernel space, and two live
/// spaces sharing one would read each other's cached translations.
pub(crate) const PROCESS_A_ASID: u16 = 1;
pub(crate) const PROCESS_B_ASID: u16 = 2;

/// Two processes, each with its own Sv39 root, running the same program.
///
/// The claim is narrow and checkable: the same virtual address means different
/// memory in each, the kernel is reachable from both without being reachable
/// *by* either, and tearing one down leaves the other and the kernel intact.
///
/// `code` is the frame the program's instructions already live in. Both
/// processes map it, which is deliberate — sharing a frame is what makes the
/// isolation being demonstrated a property of the page tables rather than of
/// the memory happening to be different.
///
/// **Not shared with the other ports' check of the same name, deliberately.**
/// The narrative is one, but every line that carries it is this port's: the
/// user program is entered by this port's assembly, its trap is reported
/// through this port's statics, and the table geometry that fixes the
/// teardown count is this port's paging. A joined version would take every
/// one of those as a closure and be a scaffold rather than a check (D190).
pub(crate) fn process_space_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    code: tessera_karch::PhysFrame,
) -> Result<(), u32> {
    use tessera_karch::AddressSpaceOps;

    let mut process_a = kernel_space
        .new_user(frames, PROCESS_A_ASID)
        .map_err(|_| 1u32)?;
    map_user_image(&mut process_a, frames, Some(code))?;
    tessera_boot_checks::map_user_bytes(
        &mut process_a,
        frames,
        USER_DATA_VA,
        &PROCESS_A_DATA.to_le_bytes(),
        6,
    )?;
    tessera_boot_checks::map_user_bytes(
        &mut process_a,
        frames,
        USER_PRIVATE_VA,
        &PROCESS_A_PRIVATE.to_le_bytes(),
        7,
    )?;

    let mut process_b = kernel_space
        .new_user(frames, PROCESS_B_ASID)
        .map_err(|_| 8u32)?;
    map_user_image(&mut process_b, frames, Some(code))?;
    tessera_boot_checks::map_user_bytes(
        &mut process_b,
        frames,
        USER_DATA_VA,
        &PROCESS_B_DATA.to_le_bytes(),
        9,
    )?;

    // 1. A reads its own data page. Reaching this line at all is already the
    //    kernel-half check: the instruction after `activate` is kernel text,
    //    and the trap the program's `ecall` takes is kernel text too, so a
    //    space that had not adopted the kernel's upper half would never get
    //    here to fail a comparison.
    // SAFETY: `process_a` maps this kernel's text, stacks and direct map by
    // construction (`new_user` copies them), so execution continues.
    unsafe { process_a.activate() };
    // SAFETY: the program and its stack are mapped user-accessible in the
    // now-active space, and no other user thread is running.
    unsafe { run_user(CHECK_READ_DATA) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != 0 {
        return Err(10);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != PROCESS_A_DATA {
        return Err(11);
    }

    // 2. B reads *the same address* and must find its own value. A stale
    //    translation, a shared table, or an ASID collision all show up here.
    // SAFETY: as above, for `process_b`.
    unsafe { process_b.activate() };
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_DATA) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != 0 {
        return Err(12);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != PROCESS_B_DATA {
        return Err(13);
    }
    kprintln!(
        "process: two Sv39 roots — {:#018x} reads {:#018x} in asid {} and {:#018x} in asid {}",
        USER_DATA_VA,
        PROCESS_A_DATA,
        PROCESS_A_ASID,
        PROCESS_B_DATA,
        PROCESS_B_ASID
    );

    // 3. B has no mapping where A has one. Checked in both directions, because
    //    "B faults" alone would also be satisfied by an address neither maps.
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_PRIVATE) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != EXCEPTION_LOAD_PAGE_FAULT {
        return Err(14);
    }
    if USER_TRAP_ADDRESS.load(Ordering::Relaxed) != USER_PRIVATE_VA {
        return Err(15);
    }
    // SAFETY: as above, back in `process_a`.
    unsafe { process_a.activate() };
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_PRIVATE) };
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != PROCESS_A_PRIVATE {
        return Err(16);
    }
    kprintln!(
        "process: {:#018x} is A's alone — B took a {} there, A read {:#018x}",
        USER_PRIVATE_VA,
        exception_name(EXCEPTION_LOAD_PAGE_FAULT),
        PROCESS_A_PRIVATE
    );

    // 4. Teardown. Back to the kernel's own space first — freeing the tables
    //    of the space you are running in would be a different kind of demo.
    // SAFETY: the kernel space maps everything this path touches; it is the
    // space the boot path was running in before any process existed.
    unsafe { kernel_space.activate() };
    let before = frames.free_list_depth();
    process_a.free_tables(frames);
    process_b.free_tables(frames);
    let reclaimed = frames.free_list_depth() - before;
    // Exactly, not at least. "At least" would pass for a teardown that walked
    // the whole root and freed the *shared* kernel tables too — which is not a
    // hypothetical: the first version of this check said `>= 2`, and the
    // negative check that broke `free_tables` on purpose sailed through it,
    // returning 18 frames and exiting 33. Over-freeing is silent precisely
    // because the kernel keeps working until something reuses a frame it still
    // points at.
    //
    // The number is derivable from the layout above rather than observed: A
    // maps four addresses spanning two gigabyte slots (root + 2 level-1 + 4
    // level-0 = 7), B maps three within one (root + 1 + 3 = 5).
    const EXPECTED_TABLE_FRAMES: usize = 7 + 5;
    if reclaimed != EXPECTED_TABLE_FRAMES {
        return Err(17);
    }
    // The kernel's own mappings are shared *by pointer* with both spaces that
    // were just torn down. If teardown had walked past the user half, this
    // translation would be gone — and so would the kernel.
    if kernel_space
        .translate(VirtAddr::new(&raw const __kernel_start as u64))
        .is_none()
    {
        return Err(18);
    }
    kprintln!(
        "process: teardown reclaimed {reclaimed} table frames and left the shared kernel half intact"
    );

    Ok(())
}
