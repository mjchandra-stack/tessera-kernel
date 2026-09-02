/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * The two `<string.h>` functions something here actually asked for.
 *
 * **Not the four a freestanding implementation is usually told to provide.**
 * The standard reserves `memcpy`, `memmove`, `memset` and `memcmp` as calls a
 * compiler may emit on its own, and the obvious move was to write all four
 * before anything named them. Measured instead, which is the rule this phase
 * works to: gcc emits **no call to any of them** for this tree's programs under
 * this tree's flags. `-mgeneral-regs-only` denies it the vector expansions that
 * make a call worthwhile, and what is left on x86-64 is `rep movsb` and
 * `rep stosb` — one instruction, cheaper than a call at every size. A struct
 * assignment of eight kilobytes, a large zero initialiser and a copy whose
 * length the optimiser cannot see all inline. So the roadmap's prediction that
 * these are "the first thing any real C program traps on" is right about
 * programs that *name* them and wrong about the compiler, on this target
 * (`build/README.md`, D318).
 *
 * **What did ask.** A program printing its own arguments has to measure strings
 * whose length nobody gave it — `argv` carries terminators, not lengths — and
 * has to assemble a line out of them. That is `strlen` and `memcpy`, with a
 * caller each. `memmove`, `memset` and `memcmp` are not here, and the next
 * program is what decides which of them arrives first.
 *
 * Normative: docs/roadmap/04-self-hosting.md ("Phase 4"),
 * docs/api/04-linux-and-posix-compatibility.md ("Tier 1")
 */

#ifndef TESSERA_STRING_H
#define TESSERA_STRING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* How many bytes precede the first NUL. The string must have one; there is no
 * bound here and no `strnlen` yet, because the one caller has strings this
 * system's own runtime terminated. */
size_t strlen(const char *s);

/* Copies `n` bytes from `src` to `dst`, which **must not overlap**. Returns
 * `dst`, as the standard requires, so a caller can chain.
 *
 * Overlap is undefined rather than handled: that is `memmove`'s job, and
 * conflating them is how a program that needed the other one gets a copy that
 * works until the ranges happen to slide. `memmove` arrives when something
 * overlaps. */
void *memcpy(void *dst, const void *src, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* TESSERA_STRING_H */
