/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * `strlen` and `memcpy`. See `<string.h>` for why these two and not the four a
 * freestanding implementation is usually told to write.
 *
 * **The loop-to-library rewrite is disabled, and it changes nothing here.**
 * `-O2` is entitled to recognise the byte loop below and replace it with a call
 * to `memcpy`, which inside `memcpy` is unbounded recursion — the classic way a
 * freestanding runtime breaks. `-fno-tree-loop-distribute-patterns` in
 * `//build/rules:cprogram.bzl` forbids it. **Measured, and the hazard does not
 * arise on this target**: gcc emits `rep movsb` here rather than a call, and
 * the object file is byte-identical with the flag and without it. The flag is a
 * guard for the machine that would show the problem — AArch64 has no such
 * instruction and `tessera/syscall.h` already carries its syscall sequence —
 * and it is **unverified there**, because there is no C cross-compiler in this
 * environment to check with (`build/README.md`, D318).
 *
 * Normative: docs/roadmap/04-self-hosting.md ("Phase 4")
 */

#include <stddef.h>
#include <string.h>

size_t strlen(const char *s) {
    const char *p = s;
    while (*p != '\0') {
        p++;
    }
    return (size_t)(p - s);
}

void *memcpy(void *dst, const void *src, size_t n) {
    /* Byte at a time, deliberately. A word-at-a-time copy is the obvious
     * improvement and it is a different function: it needs alignment cases, and
     * every one of them is a place to be wrong for a gain nothing here has
     * measured. The callers move tens of bytes. */
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}
