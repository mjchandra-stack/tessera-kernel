/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * User layout for the ring-3 network class client: identical shape to the
 * driver's (both processes have their own address space, so both link at the
 * low-half user code base 0x0000100000000000). Two PT_LOAD segments so W^X
 * holds per page. ET_EXEC, fixed address — no PIE/ASLR in v0.
 * Built with max-page-size=4096 so the 4 KiB per-page W^X protects apply.
 */

OUTPUT_FORMAT(elf64-littleaarch64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5); /* PF_R | PF_X */
    data PT_LOAD FLAGS(6); /* PF_R | PF_W */
}

SECTIONS
{
    . = 0x0000100000000000;

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
