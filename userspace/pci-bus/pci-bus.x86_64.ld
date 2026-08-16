/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * User layout for the ring-3 x86-64 PCI bus driver: a read+execute text segment
 * at 0x400000 — this port's USER_CODE_VA, the address its root task has loaded
 * at since D42 — plus a page-aligned read+write data segment. Two segments so
 * W^X holds per page, which the kernel's loader rejects a violation of rather
 * than trusting this file. ET_EXEC, fixed address: no PIE/ASLR in v0.
 *
 * `.bss` lives in the data segment and not outside it, unlike the root task's
 * script, because this program has statics and a segment the loader never maps
 * is one whose first touch is a fault.
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
        *(.got .got.*)
    } :text

    . = ALIGN(0x1000);

    .data : {
        *(.data .data.*)
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame.*)
        *(.eh_frame_hdr)
        *(.debug*)
    }
}
