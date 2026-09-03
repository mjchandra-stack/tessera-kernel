/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * **A C program told what to work on, rather than compiled knowing it.**
 *
 * `arg-probe` made this claim for Rust (`build/README.md`, D302) and the
 * reasoning there is the reasoning here: a compiler cannot be written with its
 * subject built in, because the file it compiles is the one thing about it that
 * changes on every run. What was missing on the C side was not the message —
 * `StartupArgs` has carried an argument vector since D302 — but the half that
 * turns it into `argc` and `argv`, which is now in `crt0.c` (D317).
 *
 * **What it proves, and why it cannot be faked.** The value it reports is a
 * fold over the argument *bytes*, and the strings are chosen by the check that
 * runs it, in the kernel. Nothing in this image contains them, so a program
 * that reported a constant could not report the right one — and the check runs
 * it **twice with different arguments and requires two different answers**,
 * which no constant satisfies at all.
 *
 * **Each string is walked to its NUL rather than to a length**, deliberately.
 * The wire carries `StartupArg::len` and C carries a terminator, and supplying
 * the byte between them is the entire thing `crt0` had to add; a probe that
 * asked for the length would be testing the message rather than the runtime.
 * The walk is bounded, so a missing terminator is a named failure instead of a
 * program running off its own frame.
 *
 * **And `argv[argc]` is checked to be null.** Much ported code walks the vector
 * until null rather than counting to `argc`, so a runtime that got that wrong
 * would be correct for this program and wrong for the ones this tier exists to
 * run.
 */

#include <stddef.h>
#include <stdint.h>

#include <tessera/syscall.h>

/* The longest argument `StartupArg` can carry, which bounds the walk. One more
 * than this many bytes without a NUL means there is no NUL. */
#define MAX_ARG_LEN 160

/* Reported when a step fails, with the step in the low byte. `CARG` in the high
 * half, so a value on the wire says this program gave up rather than `crt0` or
 * the heap. */
#define PROBE_FAIL ((uint64_t)0x4341524700000f00)

static int fail(uint64_t step) {
    tessera_debug_report(PROBE_FAIL | step);
    return (int)step;
}

int main(int argc, char **argv) {
    /* **Nothing to work on is a failure here**, though it is legitimate for a
     * program in general: this one is only ever started with arguments, so an
     * `argc` of zero means the message did not arrive rather than that none was
     * sent — which is a different fault from getting the wrong bytes and must
     * not report the same way. */
    if (argc <= 0) {
        return fail(1);
    }
    if (argv[argc] != NULL) {
        return fail(2);
    }

    uint64_t witness = (uint64_t)argc;
    for (int i = 0; i < argc; i++) {
        const char *p = argv[i];
        uint64_t len = 0;
        while (len <= MAX_ARG_LEN && p[len] != '\0') {
            witness = witness * 131u + (uint64_t)(unsigned char)p[len];
            len++;
        }
        if (len > MAX_ARG_LEN) {
            return fail(3);
        }
        /* The length is mixed in as well as the bytes, so two arguments that
         * differ only in where one ends cannot fold to the same value. */
        witness ^= len << 40;
    }

    tessera_debug_report(witness);
    return 0;
}
