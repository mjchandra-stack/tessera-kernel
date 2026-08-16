/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * The layout every ring-3 RISC-V 64 program links at: a read+execute text
 * segment at the user code base the kernel's loader maps to (0x0000000010000000),
 * plus a page-aligned read+write data segment. Two segments so W^X holds per
 * page. ET_EXEC at a fixed address — no PIE/ASLR in v0 (build/README.md, D42).
 *
 * One file rather than one per program: the layout is the port's, not the
 * program's, and twenty-four copies of it differed only in which program the
 * header named.
 */

OUTPUT_FORMAT(elf64-littleriscv)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5); /* PF_R | PF_X */
    data PT_LOAD FLAGS(6); /* PF_R | PF_W */
}

SECTIONS
{
    . = 0x0000000010000000;

    .text : {
        *(.text._start)
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.got .got.*)
    } :text

    . = ALIGN(0x1000);

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.sbss .sbss.*)
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
