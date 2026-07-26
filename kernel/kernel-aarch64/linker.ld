/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * AArch64 kernel image layout for the QEMU `virt` virtual platform.
 *
 * Like the x86-64 image, this kernel is linked at a HIGHER-HALF virtual
 * address and runs out of TTBR1. It is entered with the MMU OFF, so the entry
 * stub must be position-independent (adrp/adr, never absolute loads) until it
 * has installed the coarse boot tables and branched to the high half; only
 * then do the linked (high) addresses become valid.
 *
 * QEMU's `virt` machine places RAM at 0x40000000 and the Arm boot convention
 * reserves the first 0x80000 bytes of it for the device tree and boot data,
 * so the image is LOADED at physical 0x40080000. It is LINKED at
 * KERNEL_VIRT_BASE + 0x40080000, where KERNEL_VIRT_BASE = 0xffff_0000_0000_0000
 * — chosen so a high virtual address maps to the physical frame named by its
 * low 48 bits (phys = virt & 0x0000_ffff_ffff_ffff).
 *
 * One PT_LOAD per permission class, so W^X is a property of the image rather
 * than a promise (docs/kernel/03-paging-faults-and-exceptions.md).
 *
 * Normative: docs/hardware/01-platform-and-cpu-support.md ("Virtual Platform
 * Support"), docs/lifecycle/02-build-and-test-infrastructure.md
 */

OUTPUT_FORMAT(elf64-littleaarch64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R|X */
    rodata PT_LOAD FLAGS(4); /* R   */
    data   PT_LOAD FLAGS(6); /* R|W */
}

KERNEL_VIRT_BASE = 0xffff000000000000;

SECTIONS
{
    . = KERNEL_VIRT_BASE + 0x40080000;
    __kernel_start = .;

    __text_start = .;
    .text : {
        /* The arm64 Image header must be the first 64 bytes of the image:
           the loader enters at offset 0 and reads the magic at 0x38. The
           entry stub follows it immediately, branched to from code0. */
        KEEP(*(.text.header))
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text
    . = ALIGN(4096);
    __text_end = .;

    __rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata
    . = ALIGN(4096);
    __rodata_end = .;

    __data_start = .;
    .data : {
        *(.data .data.*)
        *(.got .got.*)
        *(.data.rel.ro .data.rel.ro.*)
    } :data

    .bss (NOLOAD) : {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);

        /* The boot stack lives inside .bss so the entry stub's zeroing pass
           covers it; nothing is on the stack while that pass runs. Sized to
           hold the boot path's kcore objects built by value: a kcore Process
           carries a 1024-entry handle table, and an Executive a 64-channel
           table of 8-deep 256-byte-message queues (~400 KiB), each transiting
           the stack before it moves into its static. */
        __boot_stack_bottom = .;
        . += 0x200000; /* 2 MiB */
        __boot_stack_top = .;

        . = ALIGN(16);
        __bss_end = .;
    } :data
    . = ALIGN(4096);
    __data_end = .;

    /* The five coarse boot page tables the entry stub fills before the MMU is
       on. Kept OUTSIDE .bss (the high-half .bss-zeroing pass must not wipe
       them) but INSIDE __image_size (so the Image loader zero-inits them, like
       .bss). They are addressed physically via adrp while translation is off
       and abandoned once the real tables are switched in, so nothing maps
       them in the high half. */
    .boot_pt (NOLOAD) : ALIGN(4096) {
        boot_ttbr0_root      = .; . += 4096;
        boot_l1_low          = .; . += 4096;
        boot_ttbr1_root      = .; . += 4096;
        boot_l1_high_kernel  = .; . += 4096;
        boot_l1_high_direct  = .; . += 4096;
    } :data
    . = ALIGN(4096);

    __kernel_end = .;

    /* Declared in the Image header so the loader knows how much memory the
       image needs, including the .bss and boot tables the loader does not
       carry. */
    __image_size = __kernel_end - __kernel_start;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
    }
}
