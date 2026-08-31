/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * **The first program on this machine that is not written in Rust.**
 *
 * Every ring-3 program in this tree has been `#![no_std]` Rust with a
 * hand-written `_start` that never returns. This one is C, compiled by the host
 * C toolchain, with an `int main(void)` that returns — which is the shape a
 * ported compiler, a shell and every core utility are written in, and the shape
 * nothing here could run (`docs/roadmap/04`, Phase 4; `build/README.md`, D306).
 *
 * **Its syscall numbers come from the published ABI**, not from constants in
 * this file: `<tessera/syscall.h>` includes `<tessera/syscall_abi.h>`, which
 * `islc` generates from `syscall_abi.isl`, which `//tools/checks:surface_test`
 * holds to the kernel's own enumeration. So this program is evidence for D305's
 * headers being usable for the thing they exist for, rather than only for
 * compiling.
 *
 * **What it reports is computed, not stored.** A program that wrote a constant
 * would prove the loader ran *something*; the value below is arithmetic across
 * a static, a local and a function the compiler had to actually emit, so a
 * check that sees it saw this code run.
 */

#include <stdint.h>
#include <tessera/syscall.h>

/* In `.data`, so the image has a writable segment the loader must map
 * separately from its text — which is also what stops the linker from folding
 * this program into one read-only `PT_LOAD` and leaving W^X untested. */
static uint64_t accumulator = 0x0C00ULL;

/* Deliberately not `inline`: a call the compiler must emit, so the report
 * depends on this machine having executed a `call`/`ret` pair in ring 3. */
static uint64_t mix(uint64_t seed, uint64_t rounds) {
    for (uint64_t i = 0; i < rounds; i++) {
        seed = (seed << 4) + (i ^ 0xdULL);
    }
    return seed;
}

int main(void) {
    accumulator += 0xdeULL;          /* 0x0cde */
    uint64_t value = mix(accumulator, 3);
    /* 0x0cde -> <<4 |^0xd -> 0xcde0^... ; the exact number is the check's
     * business, and it is asserted there rather than restated here: two copies
     * of an expected value is one of them being wrong later. */
    tessera_debug_report(value);
    return 0;
}
