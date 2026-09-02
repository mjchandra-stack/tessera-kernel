/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * How a C program on this system traps to the kernel.
 *
 * **The C counterpart of `userspace/uabi`, and the same two facts.** That crate
 * is what a Rust program is supposed to know about the kernel: the syscall
 * instruction and its register convention, and the addresses a program may map
 * things at. Everything else is portable. This header is the first of those two
 * for C, and it exists because `docs/api/03`'s C bindings (D305) declare
 * numbers and structs and no *functions* — a header full of `#define`s cannot
 * make a call.
 *
 * **The numbers come from the generated header, never from a literal here.**
 * `<tessera/syscall_abi.h>` is emitted from `syscall_abi.isl`, which
 * `//tools/checks:surface_test` holds to the kernel's own enumeration. A stub
 * that spelled `1` for `DebugWrite` would be a fourth place the call surface is
 * written down, and the composition plan spent a phase removing the third.
 *
 * **Inline, and header-only.** A call this thin should not cost a call: the
 * whole body is one instruction and the register moves around it, and a
 * function that could not be inlined would be most of the cost of the syscall
 * it makes.
 *
 * Normative: docs/roadmap/04-self-hosting.md ("Phase 4"),
 * docs/api/01-system-call-interface.md ("The Result Word")
 */

#ifndef TESSERA_SYSCALL_H
#define TESSERA_SYSCALL_H

#include <stdint.h>
#include <tessera/syscall_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The result word. Negative is a kernel error whose domain and code are packed
 * into it (`docs/api/01`, "The Result Word"); zero or positive is the call's
 * own answer. Returned as-is rather than split, because which half a caller
 * wants is the caller's business. */
typedef int64_t tessera_result_t;

#if defined(__x86_64__)

/* `rax` carries the number and the result; `rdi` and `rsi` the arguments. The
 * CPU overwrites `rcx` and `r11` unconditionally on `syscall`, so both are
 * declared clobbered — a caller that omitted them would have the compiler keep
 * a live value in a register the hardware is about to destroy. */
static inline tessera_result_t tessera_syscall2(uint64_t number, uint64_t arg0,
                                                uint64_t arg1) {
    tessera_result_t ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(number), "D"(arg0), "S"(arg1)
                     : "rcx", "r11", "memory");
    return ret;
}

#elif defined(__aarch64__)

/* `x8` carries the number, `x0` the first argument and the result. Matches
 * `userspace/uabi`'s sequence exactly: the kernel reads one frame whichever
 * language the caller was written in. */
static inline tessera_result_t tessera_syscall2(uint64_t number, uint64_t arg0,
                                                uint64_t arg1) {
    register uint64_t x8 __asm__("x8") = number;
    register uint64_t x0 __asm__("x0") = arg0;
    register uint64_t x1 __asm__("x1") = arg1;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory");
    return (tessera_result_t)x0;
}

#else
#error "tessera/syscall.h: no syscall sequence for this architecture"
#endif

static inline tessera_result_t tessera_syscall1(uint64_t number, uint64_t arg0) {
    return tessera_syscall2(number, arg0, 0);
}

/* Writes to the kernel's debug console.
 *
 * **A value, not the buffer the ABI declares.** `syscall_abi.isl` declares
 * `DebugWrite` as an address and a length, and the length-zero case records the
 * argument register as a value instead — which is what every check in this tree
 * reads, through the observer watching the call rather than through its result.
 * This wrapper is honest about which of the two it does; [`tessera_debug_write`]
 * is the sibling for the other, which is the shape this comment asked for
 * before there was a port to write it against. */
static inline tessera_result_t tessera_debug_report(uint64_t value) {
    return tessera_syscall2(TESSERA_KERNEL_SYSCALL_SYS_DEBUG_WRITE, value, 0);
}

/* Writes `len` bytes of text to the kernel's debug console, and answers how
 * many it took.
 *
 * **The sibling this file said would come, and the claim it replaces was
 * false.** This comment used to read "no port has a console a ring-3 program
 * can put text on"; x86-64's `user_debug_write` has read up to 128 bytes out of
 * the calling process and printed them for as long as there has been a syscall
 * handler here. Nothing in C could reach it, so every C program on this machine
 * reported a number where a sentence would do (`build/README.md`, D318).
 *
 * **This is the kernel's console, not a program's output**, and the difference
 * is the one D303 was written about: a program complaining through `DebugWrite`
 * is talking to the kernel about something the kernel has no stake in. Real
 * output belongs on `diagnostic.isl`, over a channel a parent granted — which
 * C cannot speak yet. Spelled `debug_write` rather than `write` or `puts` so
 * that when it can, nothing has to be renamed to stop meaning `stdout`.
 *
 * **Truncation is the port's answer, not this wrapper's.** A length past what
 * the console will take comes back as the count it accepted, so a caller that
 * cares can compare — and one that does not is not lied to about how much was
 * printed. */
static inline tessera_result_t tessera_debug_write(const void *bytes, uint64_t len) {
    return tessera_syscall2(TESSERA_KERNEL_SYSCALL_SYS_DEBUG_WRITE, (uint64_t)(uintptr_t)bytes,
                            len);
}

/* Ends the calling process. Does not return, and is spelled as though it might:
 * a `noreturn` a port failed to honour would be a promise this header cannot
 * keep, and the caller's own loop after it costs two bytes. */
static inline void tessera_exit(int32_t status) {
    tessera_syscall2(TESSERA_KERNEL_SYSCALL_SYS_PROCESS_EXIT, (uint64_t)(uint32_t)status, 0);
}

#ifdef __cplusplus
}
#endif

#endif /* TESSERA_SYSCALL_H */
