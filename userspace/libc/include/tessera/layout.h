/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * Where a C program on this system may put things.
 *
 * **The second of the two per-architecture facts**, and the reason this file
 * exists separately from `<tessera/syscall.h>`. `userspace/uabi`'s module note
 * names them both: the syscall instruction and its register convention, and
 * *the addresses a program is entitled to assume* — a port's user half is
 * whatever its paging format makes it, so a window that is ordinary on one
 * machine is out of range on another. The first fact is in `syscall.h`. This
 * is the second.
 *
 * **Held against `tessera_uabi::layout` by a gate, not by a comment.**
 * `//tools/checks:layout_test` reads both files and fails when a constant here
 * stops equalling the one there. Without it this would be the fourth place the
 * heap window is written down and the only one with nothing to keep it honest
 * — which is the drift `//tools/checks:surface_test` exists to have already
 * caught once (`build/README.md`, D316).
 *
 * Normative: docs/roadmap/04-self-hosting.md ("Phase 4"),
 * docs/kernel/02-memory-model.md
 */

#ifndef TESSERA_LAYOUT_H
#define TESSERA_LAYOUT_H

#include <stdint.h>

#if defined(__x86_64__)

/* Base of the heap window. Clear of the device windows `tessera_uabi::layout`
 * places below it by a wide margin rather than by one page: those are placed by
 * a driver that knows how many devices it has, and this is placed by a heap
 * that does not know how large it will get. */
#define TESSERA_HEAP_BASE ((uint64_t)0x0000100001000000)

#elif defined(__aarch64__)

/* The same address, and that it is the same is a coincidence of two ports both
 * having a 2^48 user half rather than a shared constant. `uabi` writes it out
 * per architecture for that reason and so does this. */
#define TESSERA_HEAP_BASE ((uint64_t)0x0000100001000000)

#else
#error "tessera/layout.h: no heap window for this architecture"
#endif

/* How far the heap may grow before a program is told it cannot have more.
 *
 * A ceiling rather than a policy: what a program *should* be allowed is a
 * question for whoever started it, and nothing here can answer it. This is the
 * bound past which the arithmetic stops being safe. */
#define TESSERA_HEAP_MAX_BYTES ((uint64_t)64 * 1024 * 1024)

#endif /* TESSERA_LAYOUT_H */
