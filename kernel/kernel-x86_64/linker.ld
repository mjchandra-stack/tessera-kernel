/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * Kernel layout for the Limine boot protocol on x86-64: higher-half link
 * address, one PT_LOAD per permission class so the bootloader maps W^X,
 * and a writable requests segment the bootloader fills in.
 * Modeled on the Limine C template's reference script.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    limine_requests PT_LOAD;
    text PT_LOAD;
    rodata PT_LOAD;
    data PT_LOAD;
}

SECTIONS
{
    /* Topmost 2 GiB, as the kernel code model and Limine both require. */
    . = 0xffffffff80000000;
    __kernel_virt_base = .;

    /* Section boundary symbols let the kernel map its own image with true
     * per-permission-class page protections once it owns the page tables.
     * The bootloader-written requests region is data (RW, NX). */
    __requests_start = .;
    .limine_requests : {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :limine_requests
    /* The GOT and relocated-read-only data hold absolute pointers the compiler
     * emits for indirect / cross-crate references. They are RW-but-never-
     * executable data; keep them inside this first (writable) segment so the
     * kernel's self-map covers them. A GOT that grew past the first page and
     * fell outside the mapped requests region faulted after the CR3 switch. */
    .got : { *(.got) *(.got.plt) } :limine_requests
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.* .data.rel.ro.local) } :limine_requests
    __requests_end = .;

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    __text_start = .;
    .text : {
        *(.text .text.*)
    } :text
    __text_end = .;

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    __rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata
    __rodata_end = .;

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    __data_start = .;
    .data : {
        *(.data .data.*)
    } :data

    /* .bss last in :data so the zeros stay out of the file. */
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    __data_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
