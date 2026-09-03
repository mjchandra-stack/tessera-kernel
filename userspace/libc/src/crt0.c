/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * The C runtime's floor: what runs before `main` and what happens after it
 * returns.
 *
 * **This is the smallest thing that makes a C program a C program.** Without it
 * every program on this system has to be written as `void _start(void)` that
 * never returns — which is what every ring-3 program here was, in Rust, and is
 * why none of them could have been compiled by a toolchain that expects to
 * find `main`. A ported compiler, a shell, and every core utility are written
 * against `int main(void)`; giving them somewhere to return to is the first
 * thing the POSIX tier owes them (`docs/roadmap/04`, Phase 4).
 *
 * **And what it is supposed to work on.** `argc` and `argv` are the second
 * thing (`build/README.md`, D317). A compiler cannot be written without them —
 * the file it compiles is the one thing about it that changes on every run,
 * which is why `docs/roadmap/04` made an argument vector Phase 1 and why
 * `StartupArgs` has carried one since D302. What was missing was the half that
 * turns that message into the two parameters C spells them with. The address
 * arrives in this function's own argument register, the message is decoded
 * through the *generated* `<tessera/process_abi.h>` rather than by hand, and
 * `argv` is built on this frame.
 *
 * **There is no `argv[0]` program name, and that is a refusal rather than an
 * omission.** POSIX puts the program's own name there and `StartupArgs` carries
 * no such field, so the choice was between mapping `args[i]` to `argv[i]` — a
 * vector whose indices do not mean what a ported program believes — and
 * inventing a name here. Inventing it is worse: it would be this file deciding
 * a fact the parent never stated, and every program that printed it would print
 * a lie. Mapped straight across, said out loud, and the first ported program
 * that genuinely needs one is the reason to add a field to the schema.
 *
 * **What it deliberately does not do yet.** No environment; no `atexit`; no
 * static constructors, because nothing here has any and running an empty
 * `.init_array` would be a mechanism with no subject. Each is a line in this
 * file when something traps on it, which is the rule this phase works to.
 */

#include <stddef.h>
#include <stdint.h>

#include <tessera/process_abi.h>
#include <tessera/syscall.h>

/* **Declared with arguments, and called with them whatever the program wrote.**
 * A program that says `int main(void)` — as `c-probe` does, and as most small C
 * programs do — is defined in another translation unit, so nothing here and
 * nothing in the linker sees the mismatch, and on both ABIs this system has a
 * syscall sequence for the extra registers are simply not read. Every C runtime
 * in existence does this, and the alternative is worse in the exact way Phase 4
 * exists to avoid: requiring the full signature would mean editing every ported
 * program that did not write it. */
int main(int argc, char **argv);

/* The schema's own bounds, named rather than spelled at the use site: the
 * array's length and each argument's capacity are facts about `StartupArgs`,
 * and a runtime that hard-coded different ones would read past what the parent
 * filled or ignore what it sent. */
#define MAX_ARGS 12
#define MAX_ARG_LEN 160

/* Reported when the startup message cannot be read, with the reason in the low
 * byte. `CRT0` in the high half, so a value on the wire says which layer gave
 * up as well as why. */
#define CRT0_FAIL ((uint64_t)0x4352543000000f00)

#define FAIL_SHAPE 0x01 /* wrong `size` or `version` for this runtime */
#define FAIL_COUNT 0x02 /* more arguments than the array can hold */
#define FAIL_LENGTH 0x03 /* an argument longer than its slot */

/* What a program exits with when its own startup could not be read.
 * `ExitStatus::SOFTWARE` from `process_abi.isl`, which is `sysexits.h`'s 70:
 * the program failed in a way it has no word for, which a parent should log
 * rather than interpret. */
#define CRT0_EXIT_SOFTWARE 70

/* Where a thread goes when it has nothing left to do.
 *
 * **Reached only if `tessera_exit` returned**, which it must not. `<tessera/
 * syscall.h>` declines to mark that call `_Noreturn` on the grounds that it is
 * a promise the header cannot keep for a port; this loop is what makes the
 * promise locally true anyway, so a port whose exit ever came back spins here
 * rather than executing whatever follows in memory. */
static _Noreturn void spin(void) {
    for (;;) {
#if defined(__x86_64__)
        __asm__ volatile("pause");
#elif defined(__aarch64__)
        __asm__ volatile("yield");
#endif
    }
}

/* Says why the startup message could not be read, and stops.
 *
 * `_Noreturn` because of [`spin`] rather than because of `tessera_exit`, which
 * is the only one of the two this file is entitled to promise — and it is what
 * lets each refusal below be one line that the compiler knows ends the
 * function, instead of a line the code after it has to be written around. */
static _Noreturn void die(uint64_t reason) {
    tessera_debug_report(CRT0_FAIL | reason);
    tessera_exit(CRT0_EXIT_SOFTWARE);
    spin();
}

/* The ELF entry point.
 *
 * The kernel starts this thread here with a stack the loader placed, `main`'s
 * arguments still on a page nobody has looked at, and nothing else set up.
 * `main`'s return value becomes the process's exit status, which is the
 * convention `ProcessWait` hands a parent and `ExitStatus` (D302) gives words
 * to.
 *
 * **`message_va` is a parameter rather than a constant** — the parent names the
 * address in `ProcessStartArgs::message_va` and the kernel passes it here, so
 * nothing depends on the two sides having compiled the same number. Zero is a
 * program that was given no message, which is most of them; that is `argc` of
 * zero and a `main` that runs, not a failure.
 *
 * **A message that will not decode is a failure, and a distinct one.** The
 * parent said something this program cannot read, so `main` is not run against
 * a guess at what was meant — that is the same refusal `arg-probe` makes, and
 * the same one `StartupArgs` asks for when it says a `count` past the bound is
 * refused rather than clamped.
 *
 * The loop after `tessera_exit` is unreachable and is not decoration: `_start`
 * may not return — there is nowhere to return *to* — so a port whose exit ever
 * came back would spin here rather than execute whatever followed this
 * function in memory.
 */
void _start(unsigned long message_va) {
    /* **On this frame rather than in `.bss`.** `_start` never returns, so it
     * outlives `main`, which is what makes pointers into it good for as long
     * as anything can hold them — and it is where a Unix kernel puts `argv`
     * too. In `.bss` this would be half a kilobyte in the image of every C
     * program on the system, including the ones that take no arguments.
     *
     * **Packed end to end, each string immediately after the one before its
     * terminator**, which is also how a Unix kernel lays `argv` out. Two
     * reasons, and the second is the load-bearing one. It is smaller, since a
     * short argument costs its own length rather than a whole slot. And it is
     * what makes the terminator *observable*: in a slot-per-argument layout the
     * byte after a string is padding this program never wrote, which on a fresh
     * frame is already zero — so a runtime that forgot to terminate would still
     * appear to work, and a check could not tell the difference. Packed, a
     * missing terminator runs the reader straight into the next argument. */
    char storage[MAX_ARGS * (MAX_ARG_LEN + 1)];
    char *argv[MAX_ARGS + 1];
    unsigned at = 0;
    int argc = 0;

    if (message_va != 0) {
        /* **Volatile, for the reason `tessera_uabi::read_kernel_filled`
         * gives.** The kernel wrote this page before this program's first
         * instruction and nothing in the language says so. The hazard is
         * weaker here than it is there — these bytes are behind a pointer this
         * program never stored through, so there is no cached value to hand
         * back — but the cost is a handful of loads that run once, and the
         * question is worth not having. */
        const volatile tessera_kernel_process_startup_args_t *msg =
            (const volatile tessera_kernel_process_startup_args_t *)message_va;

        /* Refused on its own terms before anything is read out of it: a
         * message of the wrong size or version is one this runtime does not
         * understand, whatever it happens to contain. */
        if (msg->size != sizeof(*msg) || msg->version != 2) {
            die(FAIL_SHAPE);
        }
        uint32_t count = msg->count;
        if (count > MAX_ARGS) {
            die(FAIL_COUNT);
        }

        /* **Measured before anything is copied**, so that every length is
         * refused or accepted before the first byte moves — a message that goes
         * wrong at its last argument must not leave `main` running against the
         * first few — and so that the fill below is the size of what actually
         * arrived rather than the size of what could have. That distinction was
         * worth nothing at four arguments of 128 bytes and is worth most of two
         * kilobytes at twelve of 160 (`build/README.md`, D319). */
        unsigned total = 0;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t len = msg->args[i].len;
            if (len > MAX_ARG_LEN) {
                die(FAIL_LENGTH);
            }
            total += len + 1;
        }

        /* **Every byte `main` can see is one this runtime wrote.**
         *
         * A stack page arrives zeroed on this system today, which means an
         * argument the loop below failed to terminate would still *look*
         * terminated — by a byte the kernel happened to leave. That is correct
         * by accident twice over: it is a property of anonymous mappings rather
         * than a promise to a C runtime, and a port that ever recycled a stack
         * page would hand `main` a string running into whatever was there.
         *
         * Filling with a non-NUL byte first is what makes the terminator below
         * load-bearing rather than decorative — and it is why the check that
         * runs this can see the difference. */
        for (unsigned b = 0; b < total; b++) {
            storage[b] = (char)0xff;
        }

        for (uint32_t i = 0; i < count; i++) {
            uint32_t len = msg->args[i].len;
            argv[i] = &storage[at];
            for (uint32_t b = 0; b < len; b++) {
                storage[at + b] = (char)msg->args[i].bytes[b];
            }
            /* **The one byte C requires and the wire does not carry.**
             * `StartupArg` is a length and a fixed array, deliberately, because
             * a path is not required to be a string; `argv` is an array of
             * pointers to NUL-terminated ones. The terminator is added here,
             * where the length is still in hand. */
            storage[at + len] = '\0';
            at += len + 1;
            argc++;
        }
    }
    /* `argv[argc]` is a null pointer: the standard requires it, and a program
     * that walks `argv` until null rather than counting to `argc` — which much
     * ported code does — reads past the end without it. */
    argv[argc] = NULL;

    tessera_exit(main(argc, argv));
    spin();
}
