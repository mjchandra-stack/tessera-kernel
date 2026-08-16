// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The fallible kernel heap: a first-fit, address-ordered free list with
//! coalescing. `try_alloc` returning `Err` is the primary API — there is no
//! infallible allocation path in the kernel, and exhaustion is a normal
//! outcome for callers to handle (docs/lifecycle/04, "Failure Discipline").
//!
//! Design notes for the invariants below: every hole and every allocation
//! is a multiple of `MIN_BLOCK` bytes and `MIN_BLOCK`-aligned. Because
//! `MIN_BLOCK` also bounds the header size, any split remainder is itself
//! representable as a hole — no bytes are ever silently swallowed, so
//! `dealloc` with the same layout reconstructs exactly the block that
//! `try_alloc` carved.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Memory Manager")
//! Budget: none (init paths this milestone; budgeted allocation arrives
//! with kernel objects)

use core::alloc::Layout;
use core::ptr::NonNull;

/// Allocation quantum: minimum size, minimum alignment, and at least
/// `size_of::<Hole>()` so every free block can hold its own header.
const MIN_BLOCK: usize = 16;

const _: () = assert!(core::mem::size_of::<Hole>() <= MIN_BLOCK);
const _: () = assert!(core::mem::align_of::<Hole>() <= MIN_BLOCK);

/// Allocation failure. Carries nothing: the only cause is exhaustion (or a
/// request no free region can satisfy), and the caller's layout is its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AllocError;

struct Hole {
    size: usize,
    next: Option<NonNull<Hole>>,
}

pub struct Heap {
    head: Option<NonNull<Hole>>,
    total: usize,
    used: usize,
}

// SAFETY: the heap owns its memory region exclusively; the raw hole
// pointers never alias anything outside it. Access is externally
// synchronized (the kernel wraps the heap in a lock).
unsafe impl Send for Heap {}

impl Heap {
    pub const fn empty() -> Self {
        Self {
            head: None,
            total: 0,
            used: 0,
        }
    }

    /// Adopts `[base, base + size)` as heap memory.
    ///
    /// # Safety
    ///
    /// The region must be exclusively owned by this heap for its entire
    /// lifetime, writable, and not overlap anything else the kernel uses.
    pub unsafe fn init(&mut self, base: NonNull<u8>, size: usize) {
        let addr = base.as_ptr() as usize;
        let aligned = (addr + MIN_BLOCK - 1) & !(MIN_BLOCK - 1);
        let end = (addr + size) & !(MIN_BLOCK - 1);
        if end <= aligned || end - aligned < MIN_BLOCK {
            return; // Too small to hold even one block: stay empty.
        }
        let usable = end - aligned;
        // SAFETY: `aligned..end` is inside the caller-owned region, aligned
        // and large enough for a hole header per the checks above.
        unsafe {
            let hole = base.as_ptr().add(aligned - addr).cast::<Hole>();
            hole.write(Hole {
                size: usable,
                next: None,
            });
            self.head = NonNull::new(hole);
        }
        self.total = usable;
        self.used = 0;
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn used(&self) -> usize {
        self.used
    }

    /// Allocates per `layout`; `Err(AllocError)` on exhaustion. Never
    /// panics.
    pub fn try_alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        let (size, align) = normalize(layout)?;
        // Cursor over the link that points at the current hole, so carving
        // can rewrite it in place.
        let mut link: *mut Option<NonNull<Hole>> = &mut self.head;
        loop {
            // SAFETY: `link` points either at `self.head` or at the `next`
            // field of a live hole; both are valid for reads.
            let Some(hole_ptr) = (unsafe { *link }) else {
                return Err(AllocError);
            };
            let hole_addr = hole_ptr.as_ptr() as usize;
            // SAFETY: holes are live headers inside our region.
            let (hole_size, hole_next) = unsafe {
                let hole = &*hole_ptr.as_ptr();
                (hole.size, hole.next)
            };
            // Both `hole_addr` and `align` are MIN_BLOCK-aligned, so `pad`
            // is 0 or a representable hole (>= MIN_BLOCK). Same for `tail`.
            let aligned_addr = match hole_addr.checked_add(align - 1) {
                Some(sum) => sum & !(align - 1),
                None => return Err(AllocError),
            };
            let pad = aligned_addr - hole_addr;
            let available = hole_size.saturating_sub(pad);
            if available < size {
                // SAFETY: taking the address of the live hole's next link.
                link = unsafe { &mut (*hole_ptr.as_ptr()).next };
                continue;
            }
            let tail = available - size;
            // SAFETY: all writes below stay inside this hole's span
            // [hole_addr, hole_addr + hole_size), which we own; `pad` and
            // `tail` are 0 or >= MIN_BLOCK so every written header fits.
            unsafe {
                let hole_u8 = hole_ptr.as_ptr().cast::<u8>();
                let tail_ptr = if tail > 0 {
                    let t = hole_u8.add(pad + size).cast::<Hole>();
                    t.write(Hole {
                        size: tail,
                        next: hole_next,
                    });
                    NonNull::new(t)
                } else {
                    hole_next
                };
                if pad > 0 {
                    (*hole_ptr.as_ptr()).size = pad;
                    (*hole_ptr.as_ptr()).next = tail_ptr;
                } else {
                    *link = tail_ptr;
                }
                self.used += size;
                return Ok(NonNull::new_unchecked(hole_u8.add(pad)));
            }
        }
    }

    /// Returns an allocation.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `try_alloc` on this heap with this exact
    /// `layout`, and must not be used afterwards.
    pub unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let Ok((size, _)) = normalize(layout) else {
            return; // try_alloc would have rejected it; nothing to free.
        };
        self.used -= size;
        // SAFETY: per contract the block is ours, unused, and exactly
        // `size` bytes.
        unsafe { self.insert_hole(ptr.as_ptr().cast::<Hole>(), size) };
    }

    /// Inserts a free block into the address-ordered list, coalescing with
    /// adjacent holes.
    ///
    /// # Safety
    ///
    /// `block` must point at `size` unused bytes owned by this heap.
    unsafe fn insert_hole(&mut self, block: *mut Hole, size: usize) {
        let addr = block as usize;
        let mut prev: Option<NonNull<Hole>> = None;
        let mut cursor = self.head;
        while let Some(c) = cursor {
            if (c.as_ptr() as usize) >= addr {
                break;
            }
            prev = cursor;
            // SAFETY: live hole in our list.
            cursor = unsafe { (*c.as_ptr()).next };
        }

        // Merge forward into `cursor` if adjacent.
        let (mut new_size, mut new_next) = (size, cursor);
        if let Some(c) = cursor
            && addr + size == c.as_ptr() as usize
        {
            // SAFETY: live hole; absorbing it into the new block.
            unsafe {
                new_size += (*c.as_ptr()).size;
                new_next = (*c.as_ptr()).next;
            }
        }

        match prev {
            Some(p) => {
                let p_addr = p.as_ptr() as usize;
                // SAFETY: live hole preceding the insertion point.
                unsafe {
                    if p_addr + (*p.as_ptr()).size == addr {
                        // Merge backward into `prev`.
                        (*p.as_ptr()).size += new_size;
                        (*p.as_ptr()).next = new_next;
                    } else {
                        block.write(Hole {
                            size: new_size,
                            next: new_next,
                        });
                        (*p.as_ptr()).next = NonNull::new(block);
                    }
                }
            }
            None => {
                // SAFETY: `block` is ours and unused per the caller.
                unsafe {
                    block.write(Hole {
                        size: new_size,
                        next: new_next,
                    });
                }
                self.head = NonNull::new(block);
            }
        }
    }
}

/// The kernel heap. Empty until the boot path donates memory via
/// `KERNEL_HEAP.lock().init(..)`.
pub static KERNEL_HEAP: crate::sync::SpinLock<Heap> = crate::sync::SpinLock::new(Heap::empty());

/// Rounds a layout up to the allocation quantum. `Err` for layouts no heap
/// state could ever satisfy (overflowing size).
fn normalize(layout: Layout) -> Result<(usize, usize), AllocError> {
    let align = layout.align().max(MIN_BLOCK);
    let size = layout
        .size()
        .max(1)
        .checked_add(MIN_BLOCK - 1)
        .ok_or(AllocError)?
        & !(MIN_BLOCK - 1);
    Ok((size, align))
}

#[cfg(test)]
#[path = "tests/heap.rs"]
mod tests;
