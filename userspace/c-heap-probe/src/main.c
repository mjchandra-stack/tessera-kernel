/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * **A C program on this machine that allocates.**
 *
 * `c-probe` is the language: a program the host toolchain compiled, entered at
 * a `crt0`, through `int main(void)`. This one is the first thing above the
 * language — `malloc` and `free` on this system's memory objects
 * (`docs/roadmap/04`, Phase 4; `build/README.md`, D316) — and it is a separate
 * program rather than three more lines in `c-probe` because the two fail
 * differently. A C program that cannot run and a heap that cannot allocate are
 * not the same finding, and a probe that reported one number for both would
 * make the first look like the second every time.
 *
 * **Every claim below is an address, not a success.** A heap check that only
 * asserts its allocations were non-null passes on a bump allocator that never
 * reclaims, and passes on one that hands the same range out twice. So each step
 * here names an address the allocator must return *because of* the step before
 * it:
 *
 * - **A block larger than any one memory object this kernel will make.**
 *   `MAX_OBJECT_PAGES` caps an object at 64 KiB, so 128 KiB cannot be one
 *   `MemoryCreate`; it exists only because two consecutive objects were mapped
 *   adjacently and the free list coalesced them. Every page of it is written
 *   and read back, so a mapping that was not really made faults here rather
 *   than passing.
 * - **A second block while the first is live**, which must not disturb it.
 * - **Reuse: free the first and ask again for the same size, and get the same
 *   address back.** This is the claim a bump allocator fails — it would answer
 *   with a higher one — and it is the only step here that cannot be satisfied
 *   by growing.
 * - **Coalescing: give everything back and take a block larger than any of
 *   them**, which must land at the heap's base. If the three freed ranges had
 *   not merged into one, this request would have grown the heap and been
 *   served above them.
 *
 * **What it reports is computed from the heap's own contents**, in `c-probe`'s
 * manner: the value is a mix of bytes read back out of allocated memory, so a
 * check that sees the number saw this machine store and reload them.
 */

#include <stdint.h>
#include <stdlib.h>

#include <tessera/syscall.h>

/* Larger than one memory object, which is what makes it interesting. Two
 * growths and a coalesce, or nothing. */
#define BIG (128u * 1024u)

/* The page this machine maps in; the stride the big block is tagged at. */
#define PAGE 4096u

/* How many words the second block holds. Sized so that it does not fit in what
 * the first growth left over, and so forces a third object of its own. */
#define WORDS 4096u

/* Reported when a step fails, with the step in the low byte. Distinct from
 * anything `libc`'s heap reports, so a log carrying both says which side gave
 * up. */
#define PROBE_FAIL ((uint64_t)0x4350524200000f00)

static uint64_t fail(uint64_t step) {
    tessera_debug_report(PROBE_FAIL | step);
    return step;
}

int main(void) {
    /* A block no single memory object could hold. */
    uint8_t *big = malloc(BIG);
    if (big == NULL) {
        return (int)fail(1);
    }
    /* Written across every page, so the seam between the two objects it spans
     * is touched from both sides. */
    for (uint32_t i = 0; i < BIG; i += PAGE) {
        big[i] = (uint8_t)(i / PAGE);
    }
    for (uint32_t i = 0; i < BIG; i += PAGE) {
        if (big[i] != (uint8_t)(i / PAGE)) {
            return (int)fail(2);
        }
    }

    /* A second block while the first is live. */
    uint64_t *second = malloc(WORDS * sizeof(uint64_t));
    if (second == NULL) {
        return (int)fail(3);
    }
    for (uint32_t j = 0; j < WORDS; j++) {
        second[j] = (uint64_t)j ^ 0xffu;
    }
    /* The first is undisturbed: two live allocations cannot overlap. */
    for (uint32_t i = 0; i < BIG; i += PAGE) {
        if (big[i] != (uint8_t)(i / PAGE)) {
            return (int)fail(4);
        }
    }

    /* **The reuse claim.** Give the large block back and ask for the same size
     * again: first fit must serve it out of the hole that just appeared, at
     * the very same address. An allocator that only ever bumped upward would
     * answer with a higher one and fail here having passed everything above. */
    uintptr_t was = (uintptr_t)big;
    free(big);
    uint8_t *again = malloc(BIG);
    if (again == NULL) {
        return (int)fail(5);
    }
    if ((uintptr_t)again != was) {
        return (int)fail(6);
    }

    /* The mix, computed from bytes that made the round trip through the heap
     * rather than from constants in this image. Unsigned, so the wrapping is
     * defined. */
    uint64_t witness = 0;
    /* Read back through `again` rather than `big`: same address, but a live
     * allocation. That the tags are still there is the reuse claim restated —
     * the range came back intact because it was handed out again rather than
     * grown past. */
    for (uint32_t i = 0; i < BIG; i += PAGE) {
        witness = witness * 31u + again[i];
    }
    for (uint32_t j = 0; j < WORDS; j++) {
        witness ^= second[j] << (j & 7u);
    }

    /* **The coalescing claim.** Everything goes back — three ranges that are
     * adjacent in address order — and a request larger than any one of them
     * must be served at the base. A free list that had not merged them would
     * have to grow the heap, and would answer above them. */
    free(again);
    free(second);
    uint8_t *whole = malloc(BIG + WORDS * sizeof(uint64_t));
    if (whole == NULL) {
        return (int)fail(7);
    }
    if ((uintptr_t)whole != was) {
        return (int)fail(8);
    }
    free(whole);

    tessera_debug_report(witness);
    return 0;
}
