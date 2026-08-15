/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * User layout for the ring-3 RISC-V 64 block driver: a read+execute text
 * segment at the low-half user code base the kernel's loader maps to, plus a
 * page-aligned read+write data segment. Two segments so W^X holds per page.
 * ET_EXEC at a fixed address — no PIE/ASLR in v0, as on the other ports.
 *
 * The base sits low in Sv39's user half, which since the higher-half split
 * (build/README.md, D97) is empty and entirely the program's.
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

    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.data.rel.ro .data.rel.ro.*)
    } :data

    .bss (NOLOAD) : {
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
        *(.riscv.attributes)
    }
}
