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
 * **What it deliberately does not do yet.** No `argc`/`argv` — the startup
 * message that carries arguments is `StartupArgs` (D302) and decoding it needs
 * the wire codec, which is Rust; no environment; no `atexit`; no static
 * constructors, because nothing here has any and running an empty
 * `.init_array` would be a mechanism with no subject. Each is a line in this
 * file when something traps on it, which is the rule this phase works to.
 */

#include <tessera/syscall.h>

int main(void);

/* The ELF entry point.
 *
 * The kernel starts this thread here with a stack the loader placed, and
 * nothing else set up. `main`'s return value becomes the process's exit status,
 * which is the convention `ProcessWait` hands a parent and `ExitStatus` (D302)
 * gives words to.
 *
 * The loop after `tessera_exit` is unreachable and is not decoration: `_start`
 * may not return — there is nowhere to return *to* — so a port whose exit ever
 * came back would spin here rather than execute whatever followed this
 * function in memory.
 */
void _start(void) {
    tessera_exit(main());
    for (;;) {
#if defined(__x86_64__)
        __asm__ volatile("pause");
#elif defined(__aarch64__)
        __asm__ volatile("yield");
#endif
    }
}
