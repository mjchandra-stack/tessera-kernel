/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * RISC-V 64 kernel image layout for the QEMU `virt` virtual platform.
 *
 * Unlike the other two ports this image is linked at its PHYSICAL load
 * address and runs identity-mapped. RISC-V enters S-mode with `satp` in Bare
 * mode — translation is not merely disabled, it does not exist yet — so the
 * kernel executes at the address the firmware loaded it to from the first
 * instruction, and the linked addresses are valid immediately. There is no
 * position-independent prologue and no boot page tables reserved here,
 * because there is no window in which the running address and the linked
 * address differ. The higher-half split is the next milestone on this port
 * (the AArch64 port took it as a separate one too).
 *
 * QEMU's `virt` machine places RAM at 0x80000000 and the firmware (OpenSBI)
 * occupies the first 2 MiB of it, handing control to the kernel at
 * 0x80200000 — the convention every S-mode payload on this machine follows.
 *
 * One PT_LOAD per permission class, so W^X is a property of the image rather
 * than a promise (docs/kernel/03-paging-faults-and-exceptions.md).
 *
 * Normative: docs/hardware/01-platform-and-cpu-support.md ("Virtual Platform
 * Support"), docs/lifecycle/02-build-and-test-infrastructure.md
 */

OUTPUT_FORMAT("elf64-littleriscv")
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R|X */
    rodata PT_LOAD FLAGS(4); /* R   */
    data   PT_LOAD FLAGS(6); /* R|W */
}

SECTIONS
{
    . = 0x80200000;
    __kernel_start = .;

    __text_start = .;
    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text
    . = ALIGN(4096);
    __text_end = .;

    __rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } :rodata
    . = ALIGN(4096);
    __rodata_end = .;

    __data_start = .;
    .data : {
        *(.data .data.*)
        /* The global pointer anchors the small-data sections, which the
           linker's relaxation rewrites into gp-relative accesses. The entry
           stub loads gp with relaxation disabled around it — otherwise the
           instruction that loads gp would itself be relaxed to depend on gp.
           Placed 0x800 in so a signed 12-bit offset reaches both directions. */
        . = ALIGN(8);
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.sdata .sdata.*)
        *(.got .got.*)
        *(.data.rel.ro .data.rel.ro.*)
    } :data

    .bss (NOLOAD) : {
        . = ALIGN(16);
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);

        /* The boot stack lives inside .bss so the entry stub's zeroing pass
           covers it; nothing is on the stack while that pass runs. Sized to
           hold the boot path's kcore objects built by value, matching the
           AArch64 image's reasoning. */
        __boot_stack_bottom = .;
        . += 0x200000; /* 2 MiB */
        __boot_stack_top = .;

        . = ALIGN(16);
        __bss_end = .;
    } :data
    . = ALIGN(4096);
    __data_end = .;

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
        *(.riscv.attributes)
    }
}
