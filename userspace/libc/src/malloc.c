/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * The C heap: `malloc` and `free`, on this system's memory objects.
 *
 * **Where a libc starts** (`docs/roadmap/04`, Phase 4), and the second heap in
 * this tree. The first is `userspace/ualloc` plus `userspace/heap-probe`, in
 * Rust, and this file is not a binding to it. That was a live choice the
 * roadmap wrote down — *"the heap D301 built is Rust, so a C one either binds
 * to it across the ABI or is written again"* — and the reasons for the second
 * answer are worth having in the file that pays for it:
 *
 * - **`free` is not given the size.** `GlobalAlloc::dealloc` is handed the
 *   `Layout` its allocation was made with, and that is not an incidental
 *   convenience — it is the assumption `ualloc`'s whole design rests on. Its
 *   module note says so: sizes coming back on free are *"what makes
 *   out-of-line metadata affordable"*, because the array can then track free
 *   extents, of which there are few, rather than allocations, of which there
 *   are many. C's `free` takes one argument. So a C caller must record sizes
 *   itself whichever language the arithmetic is in, and a binding would not
 *   carry across the thing that made `ualloc` small.
 * - **It inverts the dependency this tier exists to remove.** A C library that
 *   cannot be built without the Rust toolchain is not a library a ported
 *   program can be compiled against, and being compiled against by programs
 *   written before this system is the entire point of Phase 4.
 *
 * **What that costs, stated rather than hidden**: the extent arithmetic below
 * is a second implementation of `ualloc::Extents` in a second language —
 * insert-with-coalescing and first-fit take, the same algorithm and the same
 * refusals. `ualloc` has host unit tests and this has a boot check, so they are
 * not held against each other by anything (`build/README.md`, D316).
 *
 * **The one thing C adds is a header word.** Sixteen bytes before every block
 * hold its total size, so `free` can reconstruct the extent `malloc` took. The
 * free list itself stays *outside* the heap, as `ualloc`'s does: the metadata a
 * conventional allocator scatters through the memory it manages is what makes
 * such an allocator impossible to reason about without real memory, and there
 * is no reason to accept that here just because the language changed.
 *
 * **Bounded, and it refuses rather than degrades.** Fragmentation grows the
 * extent array, which has a fixed capacity; a full array refuses the free and
 * says so on the debug channel rather than forgetting an extent, which would
 * leak memory no counter could find (`docs/lifecycle/04`, "No silent
 * fallback").
 *
 * Normative: docs/roadmap/04-self-hosting.md ("Phase 4"),
 * docs/lifecycle/04-coding-guidelines.md ("No silent fallback")
 * Budget: none (not on a data path)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <tessera/layout.h>
#include <tessera/memory_abi.h>
#include <tessera/syscall.h>

/* How many disjoint holes the free list may describe at once.
 *
 * **A fragmentation bound and not an allocation bound**: a heap of a thousand
 * live blocks with no gaps between them needs one extent. Sixteen matches
 * `heap-probe`'s, for its reason — a capacity chosen to just fit whatever runs
 * today is a capacity that reports fragmentation for every future change. */
#define HOLES 16

/* The alignment `malloc` promises: enough for any type this port has.
 *
 * Sixteen on both machines `tessera_c_binary` can target, which is what
 * `max_align_t` is there — the widest scalar either has is a 16-byte long
 * double or a vector the ABI aligns to 16. Spelled as a number because
 * `_Alignof(max_align_t)` needs `<stddef.h>` to have been written by a libc
 * that has one, and this is that libc. */
#define MALLOC_ALIGN ((size_t)16)

/* The per-block header: the block's total size, at its base.
 *
 * A whole `MALLOC_ALIGN` rather than a `size_t`, so that a base the free list
 * aligned to 16 yields a payload pointer that is also aligned to 16. The
 * fourteen bytes past the length are the price of that and are not used. */
#define MALLOC_HEADER MALLOC_ALIGN

/* How much is mapped per growth, and it is **the kernel's ceiling rather than
 * a tuning choice**. `MAX_OBJECT_PAGES` is 16, so no memory object may exceed
 * 64 KiB — which is why a heap here is many objects and not one. Consecutive
 * objects are mapped adjacently and the free list coalesces them, so a request
 * larger than an object is served by growing more than once. */
#define GROW_BYTES ((uint64_t)64 * 1024)

/* What this file reports when it refuses, with the reason in the low byte.
 *
 * `MALL` in the high half, so a value on the wire says which subsystem gave up
 * as well as why — the same shape `heap-probe` uses and for the same reason: a
 * heap that could not serve a request and did not say why is a boot that
 * reports one number for eight different faults. */
#define MALLOC_FAIL ((uint64_t)0x4d414c4c00000f00)

#define FAIL_GROW_CEILING 0x01
#define FAIL_GROW_CREATE 0x02
#define FAIL_GROW_MAP 0x03
#define FAIL_GROW_RECORD 0x04
#define FAIL_TAKE 0x05
#define FAIL_SIZE 0x06
#define FAIL_FREE_OVERLAP 0x11
#define FAIL_FREE_RECORD 0x12

/* A half-open range of addresses that is free. Never zero length — an empty
 * extent is absence, and absence is recorded by not holding the slot. */
struct extent {
    uintptr_t start;
    size_t len;
};

/* The free list, address-ordered and coalescing, and the heap's high-water
 * mark.
 *
 * **The heap grows upward and never unmaps.** Giving a region back means
 * telling the kernel to unmap it, and doing that while the free list still
 * described the range would hand out addresses that fault. That is the same
 * ceiling `heap-probe` records, recorded again rather than inherited silently.
 *
 * Static, so one heap per process. Nothing here is locked: a program that
 * created a second thread would need it to be, and every field below is
 * reachable only through the four functions in this file, which is what would
 * make wrapping them possible. */
static struct extent free_list[HOLES];
static size_t free_len;
static uint64_t mapped;

static void report(uint64_t code) { tessera_debug_report(MALLOC_FAIL | code); }

/* Rounds `value` up to a multiple of `align`, or returns 0 if that wraps.
 *
 * Zero is not a valid heap address here — `TESSERA_HEAP_BASE` is far above
 * it — so it can carry the refusal without a second output. */
static uintptr_t align_up(uintptr_t value, size_t align) {
    uintptr_t mask = (uintptr_t)align - 1;
    if (value > UINTPTR_MAX - mask) {
        return 0;
    }
    return (value + mask) & ~mask;
}

static void list_remove(size_t at) {
    for (size_t i = at; i + 1 < free_len; i++) {
        free_list[i] = free_list[i + 1];
    }
    free_len--;
}

/* Why an insert was refused. */
enum insert_result {
    INSERT_OK = 0,
    /* The array is full and this range touches nothing already in it. The
     * memory is not lost to the machine — it is still mapped — but it is lost
     * to this heap, which declines to pretend otherwise. */
    INSERT_FRAGMENTED,
    /* The range overlaps one already free: somebody freed twice, or freed
     * something they did not own. */
    INSERT_OVERLAP,
};

/* Adds `[start, start + len)` to the free list, coalescing with whatever it
 * touches.
 *
 * **Overlap is an error and not a merge.** Two free extents that overlap can
 * only mean the same memory was freed twice, and coalescing them would turn a
 * caller's bug into this allocator handing one address out to two callers. */
static enum insert_result list_insert(uintptr_t start, size_t len) {
    if (len == 0) {
        return INSERT_OK;
    }
    uintptr_t end = start + len;

    /* Where it belongs in address order, and whether it collides on the way.
     * Both answers come from one walk, and the walk may stop at the first
     * extent starting at or past `end` because the list is ordered. */
    size_t at = free_len;
    for (size_t i = 0; i < free_len; i++) {
        uintptr_t held_end = free_list[i].start + free_list[i].len;
        if (start < held_end && free_list[i].start < end) {
            return INSERT_OVERLAP;
        }
        if (free_list[i].start >= end) {
            at = i;
            break;
        }
    }

    /* **Coalescing is decided before anything is inserted**, because the
     * obvious order — insert, then merge with the neighbours — needs a free
     * slot to hold the extent in between, and the case where the array is full
     * is exactly the case where merging would have made one unnecessary. A
     * full list must still accept a free that closes a gap. */
    int joins_before = at > 0 && free_list[at - 1].start + free_list[at - 1].len == start;
    int joins_after = at < free_len && free_list[at].start == end;

    if (joins_before && joins_after) {
        free_list[at - 1].len += len + free_list[at].len;
        list_remove(at);
    } else if (joins_before) {
        free_list[at - 1].len += len;
    } else if (joins_after) {
        free_list[at].start = start;
        free_list[at].len += len;
    } else {
        /* Touches nothing, so it needs a slot of its own. This is the only
         * path that can be refused, and it is refused before the list is
         * touched. */
        if (free_len == HOLES) {
            return INSERT_FRAGMENTED;
        }
        for (size_t i = free_len; i > at; i--) {
            free_list[i] = free_list[i - 1];
        }
        free_list[at].start = start;
        free_list[at].len = len;
        free_len++;
    }
    return INSERT_OK;
}

/* Why a take was refused. */
enum take_result {
    TAKE_OK = 0,
    /* No hole is big enough, and growth is the caller's next move rather than
     * an error. */
    TAKE_NO_SPACE,
    /* A hole was big enough but splitting it needs a slot the array has not
     * got. Distinct from `TAKE_NO_SPACE` because growing the heap would not
     * help. */
    TAKE_FRAGMENTED,
};

/* Takes `size` bytes aligned to `MALLOC_ALIGN`, first fit.
 *
 * **First fit rather than best fit**, because best fit costs a full walk on
 * every allocation to buy a fragmentation improvement the literature has never
 * been able to show reliably. */
static enum take_result list_take(size_t size, uintptr_t *out) {
    for (size_t i = 0; i < free_len; i++) {
        struct extent held = free_list[i];
        uintptr_t start = align_up(held.start, MALLOC_ALIGN);
        if (start == 0) {
            continue;
        }
        /* The head is what alignment wasted; the tail is what is left over.
         * Both go back on the list, and either may be empty. */
        size_t head = (size_t)(start - held.start);
        if (start > UINTPTR_MAX - size) {
            continue;
        }
        uintptr_t used_end = start + size;
        uintptr_t held_end = held.start + held.len;
        if (used_end > held_end) {
            continue;
        }
        size_t tail = (size_t)(held_end - used_end);

        /* A split makes two holes out of one and so needs a slot. Checked
         * before anything is mutated, so a refusal leaves the list as it was. */
        if (head > 0 && tail > 0 && free_len == HOLES) {
            return TAKE_FRAGMENTED;
        }

        if (head == 0 && tail == 0) {
            list_remove(i);
        } else if (head == 0) {
            free_list[i].start = used_end;
            free_list[i].len = tail;
        } else {
            free_list[i].len = head;
            if (tail > 0) {
                for (size_t j = free_len; j > i + 1; j--) {
                    free_list[j] = free_list[j - 1];
                }
                free_list[i + 1].start = used_end;
                free_list[i + 1].len = tail;
                free_len++;
            }
        }
        *out = start;
        return TAKE_OK;
    }
    return TAKE_NO_SPACE;
}

/* Maps another object at the end of the heap and gives the range to the free
 * list. Returns 0, or the reason it could not.
 *
 * **The mapping is contiguous with what came before**, so the free list
 * coalesces it onto the tail hole and a program that grows often does not run
 * out of extents. It does not *rely* on that — `list_insert` handles a gap —
 * but a kernel that refused the address is reported rather than worked around.
 *
 * **The range is published only once the map has succeeded.** Telling the free
 * list about addresses before they are mapped would hand out memory that
 * faults on first touch, which is the one failure a heap must never have. */
static int heap_grow(void) {
    uint64_t bytes = GROW_BYTES;
    if (mapped > TESSERA_HEAP_MAX_BYTES - bytes) {
        return FAIL_GROW_CEILING;
    }
    uint64_t va = TESSERA_HEAP_BASE + mapped;

    tessera_kernel_memory_memory_create_args_t create = {
        .size = (uint32_t)sizeof(create),
        .version = 2,
        .flags = 0,
        .bytes = bytes,
        .constraints = 0,
        .alignment = 0,
        .address_limit = 0,
    };
    tessera_result_t handle = tessera_syscall2(TESSERA_KERNEL_SYSCALL_SYS_MEMORY_CREATE,
                                               (uint64_t)(uintptr_t)&create, 0);
    if (handle < 0) {
        return FAIL_GROW_CREATE;
    }

    tessera_kernel_memory_memory_map_args_t map = {
        .size = (uint32_t)sizeof(map),
        .version = 1,
        .flags = 0,
        .memory = (uint32_t)handle,
        .rights = TESSERA_KERNEL_MEMORY_MAP_RIGHTS_READ | TESSERA_KERNEL_MEMORY_MAP_RIGHTS_WRITE,
        .vaddr = va,
    };
    if (tessera_syscall2(TESSERA_KERNEL_SYSCALL_SYS_MEMORY_MAP, (uint64_t)(uintptr_t)&map, 0) < 0) {
        return FAIL_GROW_MAP;
    }

    if (list_insert((uintptr_t)va, (size_t)bytes) != INSERT_OK) {
        return FAIL_GROW_RECORD;
    }
    mapped += bytes;
    return 0;
}

void *malloc(size_t size) {
    /* A zero-size request gets a real block: see `<stdlib.h>` for why null is
     * the answer that costs. One byte, which the header's alignment rounds up
     * to a whole `MALLOC_ALIGN` anyway. */
    if (size == 0) {
        size = 1;
    }
    if (size > SIZE_MAX - MALLOC_HEADER) {
        report(FAIL_SIZE);
        return NULL;
    }
    size_t total = size + MALLOC_HEADER;

    uintptr_t base = 0;
    for (;;) {
        enum take_result took = list_take(total, &base);
        if (took == TAKE_OK) {
            break;
        }
        if (took != TAKE_NO_SPACE) {
            report(FAIL_TAKE);
            return NULL;
        }
        /* Not big enough yet. **Grown in a loop rather than once**, because one
         * object is capped at 64 KiB and a request larger than that needs
         * several — each mapped against the last, so the free list coalesces
         * them into the single run the request needs. The loop terminates on
         * the ceiling, which `heap_grow` refuses at. */
        int why = heap_grow();
        if (why != 0) {
            report((uint64_t)why);
            return NULL;
        }
    }

    *(size_t *)base = total;
    return (void *)(base + MALLOC_HEADER);
}

void free(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    uintptr_t base = (uintptr_t)ptr - MALLOC_HEADER;
    size_t total = *(size_t *)base;
    switch (list_insert(base, total)) {
    case INSERT_OK:
        return;
    case INSERT_OVERLAP:
        report(FAIL_FREE_OVERLAP);
        return;
    case INSERT_FRAGMENTED:
        report(FAIL_FREE_RECORD);
        return;
    }
}
