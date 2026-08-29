/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * The layout every ring-3 ARM 32 program links at: a read+execute text
 * segment at the user code base the kernel's loader maps to (0x10000000), plus
 * a page-aligned read+write data segment. Two segments so W^X holds per page.
 * ET_EXEC at a fixed address — no PIE/ASLR in v0 (build/README.md, D42).
 *
 * The same base as every other port, and valid here for the same reason it is
 * on RISC-V 32: the TTBCR split puts this machine's user half in the low 2 GiB
 * and its RAM above (build/README.md, D110), so 0x10000000 is well inside it.
 *
 * `.ARM.exidx` is discarded, as the kernel's own script for this architecture
 * discards it. It is the unwind table, it has a section *type* of its own
 * (`SHT_ARM_EXIDX`) rather than being ordinary data, and a script that swept it
 * into `.text` fails the link outright — which is how this one first read. No
 * program here unwinds: every one of them is `no_std` with a panic handler that
 * exits.
 *
 * One file rather than one per program: the layout is the port's, not the
 * program's, and twenty-four copies of it differed only in which program the
 * header named.
 */

OUTPUT_FORMAT(elf32-littlearm)
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
        *(.got .got.*)
    } :text

    . = ALIGN(0x1000);

    .data : {
        *(.data .data.*)
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.ARM.exidx .ARM.exidx.*)
        *(.ARM.extab .ARM.extab.*)
        *(.ARM.attributes)
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame.*)
        *(.eh_frame_hdr)
        *(.debug*)
    }
}
