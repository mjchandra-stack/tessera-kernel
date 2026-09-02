/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * **A C program on this machine that says something a person can read.**
 *
 * Every C program here so far has reported a number: `c-probe` a computed
 * constant, `c-heap-probe` a fold over its heap, `c-arg-probe` a fold over its
 * arguments. That was not a design decision — `<tessera/syscall.h>` said no
 * port had a console a ring-3 program could put text on, and it was wrong.
 * x86-64's `user_debug_write` has read up to 128 bytes out of the calling
 * process and printed them for as long as this port has had a syscall handler;
 * nothing in C could reach it (`build/README.md`, D318).
 *
 * **And it is what asked for `<string.h>`.** This program prints its own
 * arguments, which means measuring strings whose length nobody gave it — `argv`
 * carries terminators, not lengths — and assembling a line out of them. That is
 * `strlen` and `memcpy`, with a caller each, discovered by writing the program
 * rather than by predicting the subset.
 *
 * **The evidence is the text, and it is checked where text can be checked.**
 * The line goes to the kernel's console, so `tools/qemu/smoke_boot.sh` greps
 * the serial log for it; what this program reports is the byte count the
 * syscall answered with, which is the half the kernel-side check can see. Both
 * are needed: a count with no text is a syscall that accepted and printed
 * nothing, and text with no count is a line this program could have been lucky
 * to emit.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <tessera/syscall.h>

/* The console's own limit, from `user_debug_write`. A line past this is
 * truncated *by the kernel*, which answers with what it took — so the check
 * below compares rather than assuming. */
#define CONSOLE_MAX 128

/* What the line is prefixed with, so the grep in the boot script matches this
 * program rather than any line with these arguments in it. */
static const char TAG[] = "c-say:";

#define PROBE_FAIL ((uint64_t)0x4353415900000f00)

static int fail(uint64_t step) {
    tessera_debug_report(PROBE_FAIL | step);
    return (int)step;
}

int main(int argc, char **argv) {
    if (argc <= 0) {
        return fail(1);
    }

    char line[CONSOLE_MAX];
    size_t at = 0;

    /* `sizeof - 1` rather than `strlen` for the tag: its length is known where
     * it is written, and measuring a literal at run time is work to learn
     * something the compiler already knows. */
    memcpy(line, TAG, sizeof(TAG) - 1);
    at = sizeof(TAG) - 1;

    for (int i = 0; i < argc; i++) {
        /* **The length nobody gave us.** This is the call that made
         * `<string.h>` necessary: an argument arrives as a pointer and a
         * terminator, and the only way to know how much of it there is, is to
         * look. */
        size_t n = strlen(argv[i]);
        /* Refused rather than truncated here, so that a truncation seen in the
         * log is the *kernel's* and this program is not quietly complicit in
         * one of its own. */
        if (at + 1 + n >= sizeof(line)) {
            return fail(2);
        }
        line[at] = ' ';
        at++;
        memcpy(&line[at], argv[i], n);
        at += n;
    }

    tessera_result_t wrote = tessera_debug_write(line, at);
    if (wrote < 0) {
        return fail(3);
    }
    /* **The count is reported, not the text.** What the kernel-side check can
     * see is a number; what a person can see is the line. Reporting how many
     * bytes the console said it took is what ties the two together — a check
     * asserting the count and a boot script asserting the text are looking at
     * the same call. */
    tessera_debug_report((uint64_t)wrote);
    return 0;
}
