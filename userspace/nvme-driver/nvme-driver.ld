/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * User layout for the ring-3 AArch64 NVMe class driver: a read+execute text
 * segment at the low-half user code base the kernel loader maps to
 * (0x0000100000000000, the port's USER_CODE_VA), plus a page-aligned
 * read+write data segment. Two segments so W^X holds per page. ET_EXEC, fixed
 * address — no PIE/ASLR in v0, like the x86 root task (build/README.md D42).
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
