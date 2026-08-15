/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
 *
 * RISC-V 64 kernel image layout for the QEMU `virt` virtual platform.
 *
 * The image is linked in the UPPER HALF and loaded at a physical address, so
 * the two differ by a constant KERNEL_VIRT_BASE and the entry stub has to
 * close that gap itself. RISC-V enters S-mode with `satp` in Bare mode —
 * translation is not merely disabled, it does not exist yet — so *no* linked
 * address is valid at entry. The stub therefore runs position-independently
 * until it has filled the `boot_root` page reserved below, loaded `satp` and
 * jumped high; only then are the symbols in this file addresses of anything.
 *
 * The reservation is here rather than in a Rust static because it is needed
 * before Rust can run at all, and it is inside .bss because the stub's
 * zeroing pass has to have covered it before it is filled.
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

/* Base of Sv39's upper half — the lowest address whose bits 63:39 are all
   ones. The kernel is linked at this base plus its physical load address, so
   its virtual address is its physical address plus KERNEL_VIRT_BASE and the
   whole lower half is left to user processes. */
KERNEL_VIRT_BASE = 0xffffffc000000000;

/* The firmware enters with translation OFF, so the ELF's entry point must be
   a *physical* address even though every symbol is linked virtual. Each
   segment's load address is set with AT() for the same reason: the loader
   places bytes by physical address and knows nothing about the split. */
ENTRY(_start_phys)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R|X */
    rodata PT_LOAD FLAGS(4); /* R   */
    data   PT_LOAD FLAGS(6); /* R|W */
}

SECTIONS
{
    . = KERNEL_VIRT_BASE + 0x80200000;
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
        *(.srodata .srodata.*)
    } :rodata
    . = ALIGN(4096);
    __rodata_end = .;

    __data_start = .;
    .data : AT(ADDR(.data) - KERNEL_VIRT_BASE) {
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

    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_VIRT_BASE) {
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
        /* The one page-table page the entry stub fills before translation
           exists. A single Sv39 root of 1 GiB gigapages is enough to reach
           both aliases of everything the kernel needs to get to its real
           tables — which it then builds with an allocator, in Rust, in the
           high half. */
        . = ALIGN(4096);
        boot_root = .;
        . += 4096;

        __boot_stack_bottom = .;
        . += 0x200000; /* 2 MiB */
        __boot_stack_top = .;

        . = ALIGN(16);
        __bss_end = .;
    } :data
    . = ALIGN(4096);
    __data_end = .;

    __kernel_end = .;

    /* The entry point as the loader must see it. */
    _start_phys = _start - KERNEL_VIRT_BASE;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
        *(.riscv.attributes)
    }
}
