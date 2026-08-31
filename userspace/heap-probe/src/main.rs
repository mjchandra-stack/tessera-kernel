// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **A ring-3 program that allocates.**
//!
//! The first one in this tree. Every other user-space program is fixed-buffer:
//! it names an address in `tessera_uabi::layout`, maps one object there, and
//! lives inside it. This one declares a `#[global_allocator]`, links `alloc`,
//! and builds a `Vec` whose size is not known where it is compiled — which is
//! `docs/roadmap/04` Phase 0's whole claim and the thing every phase after it
//! needs (`build/README.md`, D301).
//!
//! **What is under test is that allocation happens, not what is allocated.**
//! The work below is chosen to be impossible to satisfy without a working
//! heap and trivial to read: a vector grown past any fixed buffer this program
//! could have declared, freed in an order that forces the free list to
//! coalesce, and a second allocation that can only be served out of the space
//! the first gave back.
//!
//! **The allocator is here rather than in `//userspace/ualloc`** because it is
//! the syscall half, and this tree extracts a second copy rather than
//! anticipating one — the rule `//userspace/elfload` records, where the ELF
//! parser moved out of `roottask` only when a second loader needed it (D294).
//! The arithmetic is already shared; when a second program allocates, this
//! goes with it.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 0")

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

use memory_abi::{MapRights, MemoryConstraint, MemoryCreateArgs, MemoryMapArgs};
use tessera_isl_runtime::{HandleRef, encode};
use tessera_uabi::layout::{HEAP_BASE, HEAP_MAX_BYTES};
use tessera_uabi::syscall2;
use tessera_ualloc::{Extent, Extents, HeapError};

const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_MEMORY_CREATE: u64 = 30;
const SYS_MEMORY_MAP: u64 = 31;

/// What this program reports on success.
///
/// A value nothing else in the tree writes, so a console carrying it carries
/// it because *this* program ran and allocated.
const HEAP_OK: u64 = 0x4845_4150_0000_0001;

/// Reported instead when a step failed, with the step in the low byte so a
/// failing boot says which one rather than only that one did.
const HEAP_FAIL: u64 = 0x4845_4150_0000_0F00;

/// How many disjoint holes the free list may describe.
///
/// Sixteen because this program's allocation pattern makes at most three, and
/// the margin is what makes [`HeapError::TooFragmented`] a real refusal rather
/// than a bound this program sits against. A capacity chosen to just fit is a
/// capacity that reports fragmentation for every future change.
const HOLES: usize = 16;

/// How much is mapped per growth, and it is **the kernel's ceiling rather than
/// a tuning choice**.
///
/// `MAX_OBJECT_PAGES` is 16, so no memory object may exceed 64 KiB — a bound
/// `docs/api/01` sets against a harder one, that `MAX_FREE_FRAMES` is 256 and
/// an object too large to reclaim without overflowing the free list is a limit
/// that cannot be honoured on the way out.
///
/// **So a heap is many objects and not one**, which is the thing this milestone
/// found by running: a program wanting more than 64 KiB contiguous cannot ask
/// for it, and gets it only because consecutive objects are mapped adjacently
/// and the free list coalesces them. `Extents` does that without being told to,
/// and [`Heap::grow`] is what makes the addresses line up.
const GROW_BYTES: u64 = 64 * 1024;

/// The page this machine maps in, which growth must be a multiple of.
const PAGE: u64 = 4096;

struct State {
    extents: Extents<HOLES>,
    /// Bytes mapped so far, and so the offset of the next mapping from
    /// [`HEAP_BASE`]. The heap grows upward and never unmaps: giving a region
    /// back means telling the kernel to unmap it, and a program that did that
    /// while the free list still described the range would hand out addresses
    /// that fault. That is Phase 0's ceiling, recorded rather than hidden.
    mapped: u64,
}

struct Heap {
    state: UnsafeCell<State>,
}

// SAFETY: **the exclusion is the thread count, not the CPU count** — which is
// the distinction D225 made necessary. This process is created with one thread
// and calls nothing that makes another, so there is exactly one execution
// context in the whole system that can reach this cell. Which CPU that thread
// is scheduled on does not matter and may change: a thread runs on one CPU at
// a time, so one thread cannot race itself however many cores the machine has.
// A program here that spawned a second thread would need this behind a lock,
// and `Extents` is written so that such a lock could wrap it whole.
unsafe impl Sync for Heap {}

#[global_allocator]
static HEAP: Heap = Heap {
    state: UnsafeCell::new(State {
        extents: Extents::new(),
        mapped: 0,
    }),
};

impl Heap {
    /// Maps at least `want` more bytes at the end of the heap and gives the
    /// range to the free list.
    ///
    /// **The mapping is contiguous with what came before**, so the free list
    /// coalesces it onto the tail hole and a program that grows often does not
    /// run out of extents. It does not *rely* on that — `Extents::insert`
    /// handles a gap — but a kernel that refused the address would be reported
    /// rather than worked around, because a heap with a hole in the middle of
    /// its address range is a heap whose next growth is at an address it did
    /// not choose.
    fn grow(state: &mut State) -> Result<(), u64> {
        // One object, always the largest the kernel will make. A request bigger
        // than this is served by growing more than once: the caller retries the
        // take after each, and the extents coalesce because the addresses are
        // consecutive.
        let bytes = GROW_BYTES;
        let Some(after) = state.mapped.checked_add(bytes) else {
            return Err(1);
        };
        if after > HEAP_MAX_BYTES {
            return Err(2);
        }
        let va = HEAP_BASE + state.mapped;

        let create = MemoryCreateArgs {
            size: MemoryCreateArgs::WIRE_SIZE as u32,
            version: 2,
            flags: 0,
            bytes,
            constraints: MemoryConstraint(0),
            alignment: 0,
            address_limit: 0,
        };
        let mut buf = [0u8; MemoryCreateArgs::WIRE_SIZE];
        encode(&create, &mut buf).map_err(|_| 3u64)?;
        let handle = syscall2(SYS_MEMORY_CREATE, buf.as_ptr() as u64, 0);
        if handle < 0 {
            return Err(4);
        }

        let map = MemoryMapArgs {
            size: MemoryMapArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            memory: HandleRef::new(handle as u32),
            rights: MapRights(MapRights::READ.bits() | MapRights::WRITE.bits()),
            vaddr: va,
        };
        let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
        encode(&map, &mut buf).map_err(|_| 5u64)?;
        if syscall2(SYS_MEMORY_MAP, buf.as_ptr() as u64, 0) < 0 {
            return Err(6);
        }

        // Only now is the range real. Publishing it to the free list before
        // the map succeeded would hand out addresses that fault on first
        // touch, which is the one failure a heap must never have.
        let extent = Extent {
            start: va as usize,
            len: bytes as usize,
        };
        state.extents.insert(extent).map_err(|_| 7u64)?;
        state.mapped = after;
        Ok(())
    }
}

// SAFETY: `alloc` returns either null or the start of a range the free list
// held, which by construction lies inside a mapping this program made and
// overlaps no other live allocation — `Extents` refuses an overlapping insert
// rather than merging it, so a range handed out twice is a refusal and not a
// silent aliasing. `dealloc` is given the same `Layout` the allocation was made
// with, which is the trait's own contract, so the extent returned is exactly
// the one taken.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: one thread in this process, so this `&mut` is the only
        // reference to the cell in existence; see the `Sync` impl above.
        let state = unsafe { &mut *self.state.get() };
        let size = layout.size();
        let align = layout.align();
        match state.extents.take(size, align) {
            Ok(addr) => addr as *mut u8,
            Err(HeapError::NoSpace) => {
                // The one recoverable error: the heap is simply not big enough
                // yet. **Grown in a loop rather than once**, because one object
                // is capped at 64 KiB and a request larger than that needs
                // several — each mapped against the last, so the free list
                // coalesces them into the single run the request needs. The
                // loop terminates on the ceiling, which `grow` refuses at.
                loop {
                    if let Err(why) = Self::grow(state) {
                        // The reason travels with the refusal. A heap that
                        // could not grow and did not say why is a boot that
                        // reports one number for seven different faults.
                        report(HEAP_FAIL | 0x10 | why);
                        return core::ptr::null_mut();
                    }
                    match state.extents.take(size, align) {
                        Ok(addr) => return addr as *mut u8,
                        // Still short: another object, and the coalescing is
                        // what makes the next attempt see a longer run rather
                        // than one more hole of the same size.
                        Err(HeapError::NoSpace) => continue,
                        Err(_) => {
                            report(HEAP_FAIL | 0x18);
                            return core::ptr::null_mut();
                        }
                    }
                }
            }
            Err(_) => {
                // **Said out loud rather than returned as null alone.** A null
                // from here reaches `handle_alloc_error`, which aborts with
                // nothing on the wire; a heap that refused for a reason nobody
                // could see is the silent degradation `docs/lifecycle/04`
                // forbids.
                report(HEAP_FAIL | 0x19);
                core::ptr::null_mut()
            }
        }
    }

    // SAFETY: the caller's obligation, which is the trait's: `ptr` came from
    // this allocator and `layout` is the one it was allocated with. That is
    // what makes the extent reconstructed below exactly the extent taken —
    // this heap records the holes and not the allocations, so a wrong layout
    // here would free a range of the wrong length rather than be detected.
    // `Extents::insert` still refuses an overlap, so the damage a wrong layout
    // could do is bounded at a refusal rather than at aliasing.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: one thread in this process, as above, so no other reference
        // to the cell can exist while this one does.
        let state = unsafe { &mut *self.state.get() };
        let extent = Extent {
            start: ptr as usize,
            len: layout.size(),
        };
        if state.extents.insert(extent).is_err() {
            // A free that could not be recorded is memory this program can no
            // longer hand out. It is not lost to the machine — the mapping
            // stands — but it is lost to this heap, and that is a fact the
            // wire should carry.
            report(HEAP_FAIL | 0x1a);
        }
    }
}

fn report(code: u64) {
    syscall2(SYS_DEBUG_WRITE, code, 0);
}

/// The work. Returns the step that failed, or `None`.
///
/// Each step is something no fixed buffer in this program could satisfy, and
/// each is checked rather than assumed — a probe whose assertions are its own
/// success is a probe that passes when the mechanism is gone.
fn run() -> Option<u64> {
    // **Past any buffer this program could have declared.** Sixteen thousand
    // words is 128 KiB, which is more than one growth and so proves the grow
    // path runs more than once.
    let mut first: Vec<u64> = Vec::new();
    for i in 0..16_384u64 {
        first.push(i * 3);
    }
    if first.len() != 16_384 {
        return Some(1);
    }
    // Read it back: a `Vec` that grew across two mappings and lost its
    // contents at the seam would have the right length and the wrong bytes.
    if first.iter().enumerate().any(|(i, v)| *v != i as u64 * 3) {
        return Some(2);
    }

    // A second vector while the first is live, so the two cannot occupy the
    // same range.
    let second: Vec<u64> = (0..4_096u64).map(|i| i ^ 0xff).collect();
    if second.len() != 4_096 || first[16_383] != 16_383 * 3 {
        return Some(3);
    }

    // **Free the large one and allocate again.** The reuse is the claim: a
    // bump allocator that never reclaimed would pass everything above and fail
    // here, because the heap has not grown enough to serve this any other way.
    let high_water = HEAP.free_bytes_and_holes();
    drop(first);
    let third: Vec<u64> = (0..16_384u64).map(|i| i + 7).collect();
    if third.len() != 16_384 || third[0] != 7 {
        return Some(4);
    }
    let after = HEAP.free_bytes_and_holes();
    // The heap did not have to grow to serve it: mapped bytes are unchanged.
    if after.2 != high_water.2 {
        return Some(5);
    }
    if second[1] != (1 ^ 0xff) {
        return Some(6);
    }
    drop(second);
    drop(third);

    // Everything given back, and the free list says so with one hole: the
    // coalescing is what makes a long-running program possible, and a heap
    // that fragmented would report several.
    let (_, holes, _) = HEAP.free_bytes_and_holes();
    if holes != 1 {
        return Some(7);
    }
    None
}

impl Heap {
    /// `(free bytes, holes, mapped bytes)` — what the probe asserts against.
    fn free_bytes_and_holes(&self) -> (usize, usize, u64) {
        // SAFETY: one thread in this process, as the `Sync` impl records, and
        // this borrow is shared and ends before the caller can allocate again.
        let state = unsafe { &*self.state.get() };
        (
            state.extents.free_bytes(),
            state.extents.holes(),
            state.mapped,
        )
    }
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in this
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    match run() {
        None => report(HEAP_OK),
        Some(step) => report(HEAP_FAIL | step),
    }
    syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // A panic here is most likely `handle_alloc_error` after this allocator
    // returned null, and the reason will already be on the wire from `alloc`.
    report(HEAP_FAIL | 0xff);
    syscall2(SYS_PROCESS_EXIT, 1, 0);
    loop {
        core::hint::spin_loop();
    }
}
