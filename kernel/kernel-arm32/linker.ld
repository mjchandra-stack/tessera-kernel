/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * ARM 32-bit kernel image layout for the QEMU `virt` virtual platform.
 *
 * Like the RISC-V ports and unlike AArch64, this image is linked at its
 * PHYSICAL load address and runs identity-mapped: the CPU enters with the MMU
 * off and the kernel executes at the address it was loaded to, so there is no
 * position-independent prologue and no boot page tables reserved here. The
 * higher-half split (TTBR1, which LPAE provides exactly as AArch64 does) is a
 * later milestone.
 *
 * QEMU's `virt` machine places RAM at 0x40000000. The image is linked at
 * 0x40010000 because that is where QEMU loads a *raw* kernel image, and a raw
 * image is what this port must ship: handed an ELF, QEMU treats the file as
 * bare metal, jumps straight to its entry point with every register zero, and
 * builds no device tree at all. Handed a raw binary it takes the Linux path
 * instead — writing a small bootloader at the base of RAM that puts the
 * device-tree address in r2 before branching here. AArch64 reaches the same
 * outcome through an `Image` header; on 32-bit ARM the file simply not being
 * an ELF is the signal.
 *
 * One PT_LOAD per permission class, so W^X is a property of the image rather
 * than a promise (docs/kernel/03-paging-faults-and-exceptions.md).
 *
 * Normative: docs/hardware/01-platform-and-cpu-support.md ("Virtual Platform
 * Support"), docs/lifecycle/02-build-and-test-infrastructure.md
 */

OUTPUT_FORMAT("elf32-littlearm")
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R|X */
    rodata PT_LOAD FLAGS(4); /* R   */
    data   PT_LOAD FLAGS(6); /* R|W */
}

SECTIONS
{
    . = 0x40010000;
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

        /* Per-mode stacks. ARMv7-A banks SP per processor mode, so IRQ and
           abort mode each need their own — unlike AArch64, where SP_EL1 is
           shared across every exception the kernel takes. They are small: they
           carry one saved frame each, then the handler switches to the
           interrupted thread's stack discipline. */
        . = ALIGN(16);
        __irq_stack_bottom = .;
        . += 0x4000; /* 16 KiB */
        __irq_stack_top = .;
        __abort_stack_bottom = .;
        . += 0x4000; /* 16 KiB */
        __abort_stack_top = .;

        /* The boot (SVC-mode) stack lives inside .bss so the entry stub's
           zeroing pass covers it; nothing is on the stack while that pass
           runs. Sized like the other ports' for the boot path's by-value
           kcore objects. */
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
        *(.ARM.exidx*)
        *(.ARM.attributes)
    }
}
