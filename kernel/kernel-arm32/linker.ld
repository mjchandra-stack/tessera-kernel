/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * ARM 32-bit kernel image layout for the QEMU `virt` virtual platform.
 *
 * The image is linked in the HIGH half and loaded low, so the two differ by a
 * constant KERNEL_VIRT_BASE and the entry stub has to close that gap itself.
 * The CPU enters with the MMU off, so *no* linked address is valid until the
 * stub has filled the two boot root tables reserved below, programmed the
 * TTBCR split and enabled translation. LPAE gives this port the same two
 * translation-base registers AArch64 has: the kernel is walked out of TTBR1
 * and a process out of TTBR0, so a process's tables need no copy of the
 * kernel's at all.
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
/* Base of the TTBR1 region: the top 2 GiB, which is what TTBCR.T1SZ = 1
   selects. Every kernel address is its physical address plus this, and the
   whole low half is left to user processes. */
KERNEL_VIRT_BASE = 0x80000000;

/* The raw image is loaded and entered at its PHYSICAL address, so each
   section's load address is set with AT() even though every symbol is linked
   virtual. The entry point is the first byte of the image; QEMU's raw-image
   path branches there rather than reading an ELF header. */
ENTRY(_start_phys)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R|X */
    rodata PT_LOAD FLAGS(4); /* R   */
    data   PT_LOAD FLAGS(6); /* R|W */
}

SECTIONS
{
    . = KERNEL_VIRT_BASE + 0x40010000;
    __kernel_start = .;

    __text_start = .;
    .text : AT(ADDR(.text) - KERNEL_VIRT_BASE) {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text
    . = ALIGN(4096);
    __text_end = .;

    __rodata_start = .;
    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT_BASE) {
        *(.rodata .rodata.*)
    } :rodata
    . = ALIGN(4096);
    __rodata_end = .;

    __data_start = .;
    .data : AT(ADDR(.data) - KERNEL_VIRT_BASE) {
        *(.data .data.*)
        *(.got .got.*)
        *(.data.rel.ro .data.rel.ro.*)
    } :data

    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_VIRT_BASE) {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);

        /* The two page-table roots the entry stub fills before translation
           exists — one per translation-base register. TTBR0 gets an identity
           map so the stub can keep running while it enables the MMU; TTBR1
           gets the high map the kernel is linked for. A 2 GiB region with
           1 GiB blocks needs only two entries, so a whole page each is
           generously over-aligned, which is always legal and saves reasoning
           about the architecture's minimum.

           They are inside .bss because they must be zero before they are
           filled, and the stub's zeroing pass is what makes them so. */
        . = ALIGN(4096);
        boot_root0 = .;
        . += 4096;
        boot_root1 = .;
        . += 4096;

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

    /* The entry point as the loader sees it: the first byte of the raw image,
       at its physical load address. */
    _start_phys = _start - KERNEL_VIRT_BASE;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
        *(.ARM.exidx*)
        *(.ARM.attributes)
    }
}
