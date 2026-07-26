/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * User layout for the ring-3 root task (the M14 loader/parent): a read+execute
 * text segment at the low-half user code base the kernel loader maps to
 * (0x400000), plus a page-aligned read+write data segment holding the syscall
 * argument structs it patches at runtime. Two segments so W^X holds per page
 * (text is executable+readable, data is writable, never both). ET_EXEC, fixed
 * address — no PIE/ASLR in v0 (build/README.md D42).
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5); /* PF_R | PF_X */
    data PT_LOAD FLAGS(6); /* PF_R | PF_W */
}

SECTIONS
{
    . = 0x400000;

    .text : {
        *(.text._start)
        *(.text .text.*)
        *(.rodata .rodata.*)
    } :text

    . = ALIGN(0x1000);

    .data : {
        *(.data .data.*)
    } :data

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame.*)
        *(.eh_frame_hdr)
        *(.debug*)
    }
}
