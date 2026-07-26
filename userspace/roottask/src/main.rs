// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The Tessera root task: the first real user-space program, loaded from an ELF
//! by the kernel's loader (not copied as a raw blob). In M14 it is the
//! **user-space loader / parent**: it creates a child process, maps + populates
//! the child's code into it, and starts it — all through the three-phase
//! process-lifecycle syscalls (`ProcessCreate`/`AddressSpaceMap`/`ProcessStart`),
//! proving the docs' "kernel maps, user-space loads" model (docs/api/01, "the
//! loader operation"; build/README.md D42). This is the seed the component
//! manager grows from (docs/lifecycle/03).
//!
//! Freestanding: no std, no runtime, no `main` — `_start` is the ELF entry point
//! (per the linker script), and the kernel seeds RIP/RSP for it.

#![no_std]
#![no_main]

use core::arch::global_asm;

// The ring-3 loader/parent. SYSCALL ABI: rax = number, arg0 in rdi. ET_EXEC at a
// fixed address, so the syscall-argument structs live at known VAs (addressed
// RIP-relative) and the child blob's address is a link-time constant (`.quad
// child_blob`). Only the child handle returned by `ProcessCreate` (in rax) is
// patched in at runtime, into the map/start args' `process` field.
//
// The child is a tiny position-independent blob (no absolute addresses, no
// memory refs) that runs a `Null` syscall then exits with code 42 — a
// distinctive code the kernel checks to prove the child really ran.
//
// The DebugWrite message length is a hardcoded immediate: an assembler symbol in
// Rust's Intel-syntax global_asm assembles as a *memory reference*, not an
// immediate (the kernel's own ring-3 blobs hardcode their lengths for the same
// reason) — keep the `47` in sync with the message below.
global_asm!(
    r#"
.section .text._start, "ax"
.global _start
_start:
    # Phase 1 — create the child process under the seeded create-process job (0).
    lea rdi, [rip + create_args]
    mov eax, 8                                   # SyscallNumber::ProcessCreate
    syscall                                       # rax = child handle
    # Record the child handle into the map + start args' `process` field (off 16).
    mov dword ptr [rip + map_args_process], eax
    mov dword ptr [rip + start_args_process], eax
    # Phase 2 — map + populate the child's code at 0x400000 (R+X) from our blob.
    lea rdi, [rip + map_args]
    mov eax, 9                                   # SyscallNumber::AddressSpaceMap
    syscall
    # Phase 3 — start the child; it runs and exits, and rax returns its code.
    lea rdi, [rip + start_args]
    mov eax, 10                                  # SyscallNumber::ProcessStart
    syscall
    # Report and exit cleanly (the parent resumed after the child exited).
    lea rdi, [rip + message]
    mov esi, 47                                  # message length (keep in sync)
    mov eax, 1                                   # SyscallNumber::DebugWrite
    syscall
    xor edi, edi                                 # exit code 0
    mov eax, 5                                   # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b

# The child program (position-independent: no absolute addresses / memory refs).
# It proves it ran with a Null syscall, then exits 42.
.balign 16
child_blob:
    xor eax, eax                                 # SyscallNumber::Null
    syscall
    mov edi, 42                                  # exit code 42
    mov eax, 5                                   # SyscallNumber::ProcessExit
    syscall
2:
    jmp 2b
child_blob_end:

message:
    .ascii "root task: loaded and started a child in ring 3"

# Syscall-argument structs (patched fields live in the writable .data segment).
.section .data, "aw"
.balign 8
create_args:
    .long 24            # size = ProcessCreateArgs::WIRE_SIZE
    .long 1             # version
    .quad 0             # flags
    .long 0             # job handle (the seeded create-process job)
    .long 0             # reserved

.balign 8
map_args:
    .long 56            # size = AddressSpaceMapArgs::WIRE_SIZE
    .long 1             # version
    .quad 0             # flags
map_args_process:
    .long 0             # process handle (patched from ProcessCreate)
    .long 0             # reserved
    .quad 0x400000      # vaddr — the child's code base
    .quad child_blob_end - child_blob   # length — the blob size
    .quad 0x9           # rights = READ (0x1) | EXECUTE (0x8) — W^X code
    .quad child_blob    # src — our own VA of the blob (link-time constant)

.balign 8
start_args:
    .long 48            # size = ProcessStartArgs::WIRE_SIZE
    .long 1             # version
    .quad 0             # flags
start_args_process:
    .long 0             # process handle (patched from ProcessCreate)
    .long 0             # reserved
    .quad 0x400000      # entry — the child's code base
    .quad 0x68000000    # stack — CHILD_STACK_BASE (kernel maps the pages)
    .quad 0             # arg
"#
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
