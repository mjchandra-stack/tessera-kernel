/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * `malloc` and `free`.
 *
 * **The first header here with a standard name, and that is deliberate.**
 * `<tessera/syscall.h>` and `<tessera/layout.h>` are prefixed because they
 * describe this system and nothing else; a program that includes them was
 * written for this machine. This one is spelled the way C spells it, at the
 * include root, because the programs this tier exists for — a ported compiler,
 * a shell, every core utility — were written before this system and say
 * `#include <stdlib.h>`. A header they would have to be edited to find is a
 * header that has not been ported to.
 *
 * **What is deliberately not here yet**, on the rule this phase works to
 * (`build/README.md`, D306): the subset is discovered by running something and
 * seeing what it asks for. No `calloc` or `realloc` — each is a line in
 * `malloc.c` when something traps on it, and each is a decision (`calloc`'s
 * overflow check, `realloc`'s in-place growth) rather than a wrapper, so
 * writing them ahead of a caller means guessing at both. No `abort`, `exit`,
 * `atexit`, `getenv`, or string conversions.
 *
 * Normative: docs/roadmap/04-self-hosting.md ("Phase 4"),
 * docs/api/04-linux-and-posix-compatibility.md ("Tier 1")
 */

#ifndef TESSERA_STDLIB_H
#define TESSERA_STDLIB_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Allocates `size` bytes, suitably aligned for any type this port has, or
 * returns null.
 *
 * **`malloc(0)` returns a real allocation.** C permits either that or null,
 * and null is the choice that costs: a caller that checks the result for
 * failure — which every careful caller does — treats a zero-size request as an
 * out-of-memory condition and gives up, for a request the allocator was
 * perfectly able to serve. The pointer returned is distinct from every other
 * live one and must be freed like any other.
 *
 * **Null means the heap could not grow**, and the reason is reported on the
 * debug channel before the null is returned. A refusal a caller can only see
 * as "no" is not something this system leaves unsaid
 * (`docs/lifecycle/04`, "No silent fallback"). */
void *malloc(size_t size);

/* Returns an allocation to the heap. `ptr` must have come from [`malloc`] and
 * must not already have been freed; a null pointer is a no-op, which is the
 * standard's rule and the one thing about `free` every caller relies on.
 *
 * **A double free is detected rather than trusted.** The free list refuses an
 * extent that overlaps one already in it — it cannot coalesce them without
 * handing the same address out twice — so the second free is reported and
 * declined instead of corrupting the heap. That is a bound on the damage, not
 * a guarantee: a free of an interior pointer, or of an address this allocator
 * never issued, reads a length out of memory it does not own first. */
void free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* TESSERA_STDLIB_H */
