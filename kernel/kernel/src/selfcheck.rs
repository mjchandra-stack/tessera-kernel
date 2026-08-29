// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Self-checks over the primitives the rest of the boot assumes.
//!
//! The runtime mapper, the stack guard page, and the handle/rights tables. Each
//! fails the boot where the defect is rather than letting it corrupt something
//! further along.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

/// Exercises the runtime mapper through the `AddressSpace` object: map two
/// anonymous pages, confirm they are zero-filled, write and read them back,
/// then unmap. A mapper or zero-fill defect fails the boot loudly here rather
/// than corrupting memory later — the paging analogue of the heap self-check.
pub(crate) fn mapper_self_check(
    space: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    let base = VirtAddr::new(KERNEL_VMAP_BASE);
    let len = 2 * FRAME_SIZE;
    if let Err(e) = space.map_anonymous(base, len, PageFlags::rw().global(), frames) {
        panic!("mapper self-check: map failed: {e:?}");
    }
    // The kernel space is active, so the mapping is live at `base`.
    // SAFETY: `[base, base + len)` was just mapped read-write in the active
    // kernel space and the mapper zero-filled its frames, so these in-bounds
    // volatile accesses are valid.
    unsafe {
        let ptr = base.as_u64() as *mut u8;
        let last = (len - 1) as usize;
        if ptr.read_volatile() != 0 || ptr.add(last).read_volatile() != 0 {
            panic!("mapper self-check: anonymous memory not zero-filled");
        }
        for i in 0..len as usize {
            ptr.add(i).write_volatile(0x5a);
        }
        if ptr.read_volatile() != 0x5a || ptr.add(last).read_volatile() != 0x5a {
            panic!("mapper self-check: readback mismatch");
        }
    }
    if let Err(e) = space.unmap_range(base, len) {
        panic!("mapper self-check: unmap failed: {e:?}");
    }
}

// --- Guard-page self-test (flag-gated) ---

/// Recurses, consuming ~512 bytes of stack per frame, until the stack
/// overflows into its guard page. The `black_box` uses force a real frame and
/// defeat tail-call elimination so the stack actually grows.
#[inline(never)]
pub(crate) fn consume_stack(depth: u64) -> u64 {
    let mut frame = [depth; 64];
    core::hint::black_box(&mut frame);
    let deeper = consume_stack(depth.wrapping_add(1));
    core::hint::black_box(frame[0]).wrapping_add(deeper)
}

/// Entry point of the overflowing test thread; never returns normally.
pub(crate) extern "C" fn stack_overflow_entry(_arg: usize) -> ! {
    let _ = consume_stack(0);
    panic!("stack-guard self-test: recursion returned without overflowing");
}

/// Spawns a thread on a small guarded stack and runs it; the deliberate
/// overflow must fault onto the exception stack, where `fatal_trap` reports a
/// kernel stack overflow and exits with failure. If control returns, the guard
/// did not fire — a bug — so this panics.
pub(crate) fn run_stack_guard_self_test(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    kprintln!("stack-guard self-test: overflowing a guarded kernel stack");
    let mut scheduler = Scheduler::<ContextSwitch>::new(1, 0);
    let thread = match Thread::<ContextSwitch>::spawn(
        stack_overflow_entry,
        0,
        alloc_kstack(4),
        4,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("stack-guard self-test: spawn failed: {e:?}"),
    };
    if scheduler.add_thread(thread).is_err() {
        panic!("stack-guard self-test: could not enqueue the thread");
    }
    scheduler.run();
    panic!("stack-guard self-test: overflow did not fault");
}

// --- Handle + rights self-check ---
//
// The object and handle tables are large fixed pools, so they live in .bss
// (never the boot stack). Touched only from this boot path, which the boot CPU alone runs.
pub(crate) static mut OBJECTS: ObjectTable = ObjectTable::new();
pub(crate) static mut HANDLES: HandleTable = HandleTable::new();

/// Exercises the capability system on real hardware, asserting each outcome:
/// create an object, take a full-rights handle, duplicate it with narrowed
/// rights, reject a rights-expansion attempt, replace rights, and confirm the
/// object is destroyed only when its last handle closes. A defect fails the
/// boot loudly here.
pub(crate) fn handle_self_check() {
    // SAFETY: `_start` runs on the boot CPU alone and these statics are touched only
    // here; this is the only reference taken to each.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let handles = unsafe { &mut *&raw mut HANDLES };

    let id = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => panic!("handle self-check: object create failed: {e:?}"),
    };
    let full = match handles.insert(id, Rights::all_core()) {
        Ok(handle) => handle,
        Err(e) => panic!("handle self-check: insert failed: {e:?}"),
    };

    // Duplicate with narrowed rights (read only).
    let read_only = match handles.duplicate(objects, full, Rights::READ) {
        Ok(handle) => handle,
        Err(e) => panic!("handle self-check: duplicate failed: {e:?}"),
    };
    if handles.rights(read_only) != Ok(Rights::READ) {
        panic!("handle self-check: duplicated rights not narrowed");
    }

    // A duplicate that asks for a right the source lacks must be rejected.
    let expansion = handles.duplicate(objects, read_only, Rights::READ | Rights::WRITE);
    if expansion != Err(KError::AccessDenied) {
        panic!("handle self-check: rights expansion was not rejected");
    }

    // Replace rights in place, narrowing only.
    if handles
        .replace_rights(full, Rights::READ | Rights::WRITE)
        .is_err()
    {
        panic!("handle self-check: replace_rights failed");
    }

    // Object lifetime: two handles reference it; it dies at the last close.
    if objects.refcount(id) != Some(2) {
        panic!("handle self-check: unexpected reference count");
    }
    match handles.close(objects, full) {
        Ok(false) => {}
        other => panic!("handle self-check: first close destroyed too early: {other:?}"),
    }
    match handles.close(objects, read_only) {
        Ok(true) => {}
        other => panic!("handle self-check: last close did not destroy: {other:?}"),
    }
    if objects.is_live(id) {
        panic!("handle self-check: object still live after last close");
    }

    kprintln!(
        "handles: rights narrowing + expansion rejected; object destroyed at last close ({} live)",
        objects.live_count()
    );
}
