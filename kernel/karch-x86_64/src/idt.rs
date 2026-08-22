// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The interrupt descriptor table: all 32 exception vectors routed to the
//! trampolines in `trap.rs`. Device interrupt vectors are appended when
//! the interrupt controller work lands.
//!
//! Normative: docs/kernel/01-kernel-model.md ("Interrupts And Exceptions")
//! Budget: none (init path)

use crate::gdt::{DOUBLE_FAULT_IST, EXCEPTION_IST, KERNEL_CODE_SELECTOR};
use crate::trap::trap_stub_table;
use core::arch::asm;
use core::mem::size_of;

const DOUBLE_FAULT_VECTOR: usize = 8;
const PAGE_FAULT_VECTOR: usize = 14;

#[repr(C)]
#[derive(Clone, Copy)]
struct GateDescriptor {
    offset_low: u16,
    selector: u16,
    options: u16,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

impl GateDescriptor {
    const EMPTY: Self = Self {
        offset_low: 0,
        selector: 0,
        options: 0,
        offset_mid: 0,
        offset_high: 0,
        _reserved: 0,
    };

    fn interrupt_gate(handler: usize, ist: u16) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            // present | DPL 0 | 64-bit interrupt gate | IST slot
            options: 0x8e00 | (ist & 0x7),
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

static mut IDT: [GateDescriptor; 256] = [GateDescriptor::EMPTY; 256];

/// Loads the IDT on the CPU `index` names, filling it first if that CPU is the
/// boot CPU.
///
/// **One table, loaded by every CPU.** It is written once and read-only
/// afterwards, every gate is identical on every CPU, and the IST slot numbers
/// its gates carry resolve through whichever task-state segment the reading CPU
/// loaded — which is the per-CPU part, and lives in `gdt`. So the fill is the
/// boot CPU's and the load is everyone's.
///
/// # Safety
///
/// Call exactly once per CPU, on the CPU `index` names, after `gdt::init_cpu`
/// on that CPU (the gates reference the kernel code selector). Only the boot
/// CPU may be passed index 0, and no other code may touch `IDT`.
pub(crate) unsafe fn init_cpu(index: u32) {
    if index != 0 {
        // SAFETY: the table was filled by the boot CPU before any other CPU was
        // started, and is read-only from then on; `lidt` only points this CPU
        // at it.
        unsafe { load() };
        return;
    }
    // SAFETY: single boot-CPU call per this function's contract; the stub
    // table is generated alongside the trampolines and has exactly 32
    // valid entries.
    unsafe {
        let idt = &mut *(&raw mut IDT);
        for (vector, &stub) in trap_stub_table.iter().enumerate() {
            let ist = match vector {
                DOUBLE_FAULT_VECTOR => DOUBLE_FAULT_IST,
                PAGE_FAULT_VECTOR => EXCEPTION_IST,
                _ => 0,
            };
            idt[vector] = GateDescriptor::interrupt_gate(stub, ist);
        }
    }
    // SAFETY: the table has just been filled by this, the boot CPU.
    unsafe { load() };
}

/// Points this CPU at the shared table.
///
/// # Safety
///
/// The table must already be filled — the boot CPU's `init_cpu` does that
/// before any other CPU exists.
unsafe fn load() {
    let idtr = DescriptorTablePointer {
        limit: (size_of::<[GateDescriptor; 256]>() - 1) as u16,
        base: (&raw const IDT) as u64,
    };
    // SAFETY: `lidt` records the table's address and limit for this CPU and has
    // no other effect; the table is valid per this function's contract.
    unsafe { asm!("lidt [{0}]", in(reg) &idtr, options(nostack)) };
}
