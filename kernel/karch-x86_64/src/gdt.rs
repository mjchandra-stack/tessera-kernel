// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel's own GDT and TSS. The bootloader's tables live in
//! reclaimable memory, so the kernel must install its own before that
//! memory is ever reused. The TSS carries a dedicated IST stack for double
//! faults, so even a kernel-stack failure produces a report instead of a
//! triple fault.
//!
//! Normative: docs/kernel/01-kernel-model.md ("Architecture Layer")
//! Budget: none (init path)

use core::arch::asm;
use core::mem::size_of;

pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
/// Ring-3 data/stack selector (GDT slot 3, DPL 3) with its RPL set to 3, as it
/// appears in a user segment register.
pub const USER_DATA_SELECTOR: u16 = 0x18 | 3;
/// Ring-3 code selector (GDT slot 4, DPL 3) with its RPL set to 3.
pub const USER_CODE_SELECTOR: u16 = 0x20 | 3;
const TSS_SELECTOR: u16 = 0x28;

/// The base selector SYSRET adds to when computing the return segments: it
/// loads CS = base + 16 and SS = base + 8 (both forced to RPL 3). With the GDT
/// laid out below (user data at 0x18, user code at 0x20), base = 0x10 yields
/// SS = 0x18 and CS = 0x20. `init_syscall` programs STAR from this.
pub const SYSRET_SELECTOR_BASE: u16 = 0x10;
const _: () = assert!(SYSRET_SELECTOR_BASE + 16 == (USER_CODE_SELECTOR & !3));
const _: () = assert!(SYSRET_SELECTOR_BASE + 8 == (USER_DATA_SELECTOR & !3));

/// IST slot (1-based) used by the double-fault gate.
pub const DOUBLE_FAULT_IST: u16 = 1;

/// IST slot (1-based) used by the page-fault gate, so a kernel-stack
/// guard-page overflow is delivered on a known-good stack with an
/// identifiable cause rather than escalating to a double fault
/// (docs/kernel/03-paging-faults-and-exceptions.md, "Kernel stacks carry
/// guard pages").
pub const EXCEPTION_IST: u16 = 2;

const DOUBLE_FAULT_STACK_SIZE: usize = 16 * 1024;
const EXCEPTION_STACK_SIZE: usize = 16 * 1024;

#[repr(C, packed)]
struct Tss {
    _reserved0: u32,
    rsp: [u64; 3],
    _reserved1: u64,
    ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16,
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

// 64-bit flat segments: bases and limits are ignored in long mode; the
// encodings below are the canonical G=1 code (L=1) and data descriptors. The
// user segments differ from the kernel ones only in DPL (3, access byte
// 0xfb/0xf3 vs 0x9b/0x93). Order is fixed by SYSRET (user data then user code,
// see SYSRET_SELECTOR_BASE). Slots: null, kernel code, kernel data, user data,
// user code, TSS low, TSS high.
static mut GDT: [u64; 7] = [
    0,
    0x00af_9b00_0000_ffff, // 0x08 kernel code (DPL0, L=1)
    0x00cf_9300_0000_ffff, // 0x10 kernel data (DPL0)
    0x00cf_f300_0000_ffff, // 0x18 user data   (DPL3)
    0x00af_fb00_0000_ffff, // 0x20 user code   (DPL3, L=1)
    0,                     // 0x28 TSS low
    0,                     // 0x28 TSS high
];

static mut TSS: Tss = Tss {
    _reserved0: 0,
    rsp: [0; 3],
    _reserved1: 0,
    ist: [0; 7],
    _reserved2: 0,
    _reserved3: 0,
    iomap_base: size_of::<Tss>() as u16, // no I/O permission bitmap
};

static mut DOUBLE_FAULT_STACK: [u8; DOUBLE_FAULT_STACK_SIZE] = [0; DOUBLE_FAULT_STACK_SIZE];
static mut EXCEPTION_STACK: [u8; EXCEPTION_STACK_SIZE] = [0; EXCEPTION_STACK_SIZE];

/// Builds and loads the GDT and TSS on the boot CPU.
///
/// # Safety
///
/// Call exactly once, on the boot CPU, before interrupts are enabled. No
/// other code may reference the GDT/TSS statics.
pub(crate) unsafe fn init_bsp() {
    // SAFETY: single boot-CPU call per this function's contract, so these
    // raw statics have no other live references. The descriptor encodings
    // and load sequence follow the SDM.
    unsafe {
        let df_stack_top = (&raw mut DOUBLE_FAULT_STACK) as u64 + DOUBLE_FAULT_STACK_SIZE as u64;
        (*(&raw mut TSS)).ist[(DOUBLE_FAULT_IST - 1) as usize] = df_stack_top;
        let exc_stack_top = (&raw mut EXCEPTION_STACK) as u64 + EXCEPTION_STACK_SIZE as u64;
        (*(&raw mut TSS)).ist[(EXCEPTION_IST - 1) as usize] = exc_stack_top;

        let tss_base = (&raw const TSS) as u64;
        let tss_limit = (size_of::<Tss>() - 1) as u64;
        let gdt = &mut *(&raw mut GDT);
        gdt[5] = (tss_limit & 0xffff)
            | ((tss_base & 0xff_ffff) << 16)
            | (0x89u64 << 40) // present, available 64-bit TSS
            | (((tss_limit >> 16) & 0xf) << 48)
            | (((tss_base >> 24) & 0xff) << 56);
        gdt[6] = tss_base >> 32;

        let gdtr = DescriptorTablePointer {
            limit: (size_of::<[u64; 7]>() - 1) as u16,
            base: (&raw const GDT) as u64,
        };
        // Load the GDT, reload CS with a far return, refresh the data
        // segments, and load the task register.
        asm!(
            "lgdt [{gdtr}]",
            "push {code_sel}",
            "lea {tmp}, [rip + 55f]",
            "push {tmp}",
            "retfq",
            "55:",
            "mov {tmp:x}, {data_sel:x}",
            "mov ds, {tmp:x}",
            "mov es, {tmp:x}",
            "mov ss, {tmp:x}",
            "xor {tmp:e}, {tmp:e}",
            "mov fs, {tmp:x}",
            "mov gs, {tmp:x}",
            "ltr {tss_sel:x}",
            gdtr = in(reg) &gdtr,
            code_sel = const KERNEL_CODE_SELECTOR as u64,
            data_sel = in(reg) KERNEL_DATA_SELECTOR as u64,
            tss_sel = in(reg) TSS_SELECTOR,
            tmp = out(reg) _,
        );
    }
}

/// Sets the kernel stack (TSS RSP0) the CPU loads when an interrupt or
/// exception enters from ring 3. Called on every switch to a user thread so a
/// fault taken in ring 3 lands on that thread's own kernel stack rather than
/// whatever RSP0 held before (docs/kernel/03, privilege-transition stacking).
/// SYSCALL does not use RSP0 — its entry stub loads the kernel stack from the
/// per-CPU block — but exceptions and IRQs from ring 3 do.
pub fn set_kernel_stack(top: u64) {
    // SAFETY: single-core; the TSS is installed once at boot and its RSP0 is
    // written only here, between privilege transitions, never concurrently.
    unsafe {
        (*(&raw mut TSS)).rsp[0] = top;
    }
}
