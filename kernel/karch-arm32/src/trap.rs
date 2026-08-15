// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ARMv7-A exception vectors, and the hooks the boot glue installs on
//! them.
//!
//! # Three exception models, three shapes of vector
//!
//! x86-64 dispatches through a 256-entry descriptor table indexed by vector
//! number. AArch64 uses sixteen slots indexed by kind *and* origin, so the
//! hardware has classified the trap before any code runs. ARMv7-A is the
//! oldest of the three and the narrowest: **eight words**, each of which must
//! be an instruction — reset, undefined instruction, supervisor call,
//! prefetch abort, data abort, reserved, IRQ, FIQ. There is no room for
//! anything but a branch, so the table is eight branches and the real
//! handlers live elsewhere.
//!
//! # Banked modes are the thing with no counterpart
//!
//! Taking an exception here does not just change privilege, it changes
//! *processor mode*, and each mode has its own banked `SP` and `LR`. An IRQ
//! arrives in IRQ mode on the IRQ stack, with the interrupted `PC` in the IRQ
//! `LR` and the interrupted `CPSR` in `SPSR_irq`. Nothing about the
//! interrupted thread's stack is disturbed, which is convenient — and nothing
//! about it is *saved* either, which is why the return sequence is
//! `srsdb`/`rfeia` rather than a plain `ret`: those two instructions move the
//! return address and status between the banked registers and the stack
//! atomically, which is what makes the exception re-entrant-safe.
//!
//! `LR` also does not point where you would expect. On an IRQ or a data abort
//! it points *past* the instruction to resume, by 4 or 8 bytes depending on
//! the exception, so every handler adjusts it. Getting that wrong resumes one
//! instruction late and corrupts nothing visibly, which is the worst kind of
//! wrong; the adjustments are therefore written at each entry point rather
//! than centralised.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (the tick path is budgeted with the switch path)

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicUsize, Ordering};

/// What the fatal-trap handler is told about an exception. ARMv7-A reports a
/// fault through a pair of coprocessor registers per class — an address and a
/// status — rather than the single syndrome register AArch64 uses, so both
/// are captured and named.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrapFrame {
    /// Which vector was taken; see [`exception_name`].
    pub kind: u32,
    /// The instruction to resume at, already adjusted for the vector's own
    /// `LR` offset.
    pub pc: u32,
    /// The interrupted `CPSR`.
    pub spsr: u32,
    /// Faulting address: `DFAR` for a data abort, `IFAR` for a prefetch one.
    pub fault_address: u32,
    /// Fault status: `DFSR` for a data abort, `IFSR` for a prefetch one.
    pub fault_status: u32,
}

/// Vector kinds, in table order.
pub const KIND_UNDEFINED: u32 = 1;
pub const KIND_SUPERVISOR_CALL: u32 = 2;
pub const KIND_PREFETCH_ABORT: u32 = 3;
pub const KIND_DATA_ABORT: u32 = 4;

/// A fatal-trap handler. It never returns.
pub type TrapHandler = fn(&TrapFrame) -> !;
/// The periodic tick.
pub type TickHook = fn();
/// A device interrupt, by interrupt id. Returns true if a driver claimed it.
pub type DeviceIrqHook = fn(u32) -> bool;

static TRAP_HANDLER: AtomicUsize = AtomicUsize::new(0);
static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);
static DEVICE_IRQ_HOOK: AtomicUsize = AtomicUsize::new(0);
static UNEXPECTED_IRQS: AtomicUsize = AtomicUsize::new(0);

/// Installs the fatal-trap handler.
pub fn set_trap_handler(handler: TrapHandler) {
    TRAP_HANDLER.store(handler as usize, Ordering::Relaxed);
}

/// Installs the periodic-tick hook.
pub fn set_tick_hook(hook: TickHook) {
    TICK_HOOK.store(hook as usize, Ordering::Relaxed);
}

/// Installs the device-interrupt hook.
pub fn set_device_irq_hook(hook: DeviceIrqHook) {
    DEVICE_IRQ_HOOK.store(hook as usize, Ordering::Relaxed);
}

/// Interrupts that arrived with nothing listening. Counted, never silently
/// dropped (docs/lifecycle/04, "No Silent Fallback").
pub fn unexpected_irqs() -> usize {
    UNEXPECTED_IRQS.load(Ordering::Relaxed)
}

/// Stable name for a vector, so a fault names itself in the log.
pub const fn exception_name(kind: u32) -> &'static str {
    match kind {
        KIND_UNDEFINED => "undefined instruction",
        KIND_SUPERVISOR_CALL => "supervisor call",
        KIND_PREFETCH_ABORT => "prefetch abort",
        KIND_DATA_ABORT => "data abort",
        _ => "reserved",
    }
}

/// True when the trap was a write that faulted — `DFSR.WnR` (bit 11), the
/// classification the copy-on-write path needs.
pub const fn is_write_fault(frame: &TrapFrame) -> bool {
    frame.kind == KIND_DATA_ABORT && frame.fault_status & (1 << 11) != 0
}

// SAFETY: declares the symbol defined by the `global_asm!` block below; the
// block only declares it and introduces no unsafe operation.
unsafe extern "C" {
    fn exception_vectors();
}

/// Points `VBAR` at the vector table.
///
/// # Safety
///
/// Called once, on the boot CPU, with interrupts masked and the kernel's text
/// mapped executable at its current address.
pub unsafe fn init_vectors() {
    // SAFETY: `VBAR` (CP15 c12, c0, 0) holds the exception base address. The
    // table is 32-byte aligned by its `.align 5`, which the register requires.
    unsafe {
        asm!(
            "mcr p15, 0, {base}, c12, c0, 0",
            "isb",
            base = in(reg) exception_vectors as *const () as u32,
            options(nomem, nostack),
        );
    }
}

/// Rust half of the fatal vectors.
///
/// # Safety
///
/// Called only from the vector table, with `kind` naming the vector taken and
/// `pc`/`spsr` already adjusted by the entry stub.
#[unsafe(no_mangle)]
unsafe extern "C" fn arm32_fatal(kind: u32, pc: u32, spsr: u32) -> ! {
    let (mut fault_address, mut fault_status) = (0u32, 0u32);
    // SAFETY: the fault-address and fault-status registers (CP15 c6/c5) are
    // read-only descriptions of the fault in progress; reading them has no
    // side effect. The data and prefetch classes report through different
    // registers, so the right pair is chosen by the vector that was taken.
    unsafe {
        if kind == KIND_DATA_ABORT {
            asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) fault_address, options(nomem, nostack));
            asm!("mrc p15, 0, {}, c5, c0, 0", out(reg) fault_status, options(nomem, nostack));
        } else if kind == KIND_PREFETCH_ABORT {
            asm!("mrc p15, 0, {}, c6, c0, 2", out(reg) fault_address, options(nomem, nostack));
            asm!("mrc p15, 0, {}, c5, c0, 1", out(reg) fault_status, options(nomem, nostack));
        }
    }

    let frame = TrapFrame {
        kind,
        pc,
        spsr,
        fault_address,
        fault_status,
    };

    let handler = TRAP_HANDLER.load(Ordering::Relaxed);
    if handler != 0 {
        // SAFETY: the only writer is `set_trap_handler`, which stores a
        // `TrapHandler` function pointer.
        let handler: TrapHandler = unsafe { core::mem::transmute(handler) };
        handler(&frame);
    }
    // No handler installed: stop rather than return into the faulting
    // instruction, which would fault again forever.
    loop {
        // SAFETY: `wfi` is a hint with no memory effects.
        unsafe { asm!("wfi", options(nomem, nostack)) };
    }
}

/// Rust half of the IRQ vector: acknowledge at the GIC, dispatch, end.
///
/// # Safety
///
/// Called only from the IRQ vector, in IRQ mode on the IRQ stack, with
/// interrupts masked by the exception entry.
#[unsafe(no_mangle)]
unsafe extern "C" fn arm32_irq() {
    // SAFETY: the GIC CPU interface is mapped device memory and this is the
    // only acknowledging path.
    let acknowledgement = unsafe { tessera_karch_arm_common::gic::acknowledge() };
    if tessera_karch_arm_common::gic::is_spurious(acknowledgement) {
        return;
    }
    let id = tessera_karch_arm_common::gic::intid(acknowledgement);

    if id == crate::timer::TIMER_INTID {
        crate::timer::on_expiry();
        let hook = TICK_HOOK.load(Ordering::Relaxed);
        if hook != 0 {
            // SAFETY: the only writer is `set_tick_hook`, which stores a
            // `TickHook` function pointer.
            let hook: TickHook = unsafe { core::mem::transmute(hook) };
            hook();
        }
    } else {
        let hook = DEVICE_IRQ_HOOK.load(Ordering::Relaxed);
        let handled = if hook != 0 {
            // SAFETY: as above.
            let hook: DeviceIrqHook = unsafe { core::mem::transmute(hook) };
            hook(id)
        } else {
            false
        };
        if !handled {
            UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
        }
    }

    // SAFETY: ending the interrupt the acknowledge above returned is the
    // documented completion of the GIC handshake.
    unsafe { tessera_karch_arm_common::gic::end_of_interrupt(acknowledgement) };
}

// The vector table and the entry stubs.
//
// `.align 5` is required, not cosmetic: `VBAR` ignores the low five bits, so a
// misaligned table would be installed somewhere else entirely.
//
// Each fatal stub records which vector it was, adjusts `LR` by that vector's
// own offset, and hands `(kind, pc, spsr)` to Rust. It never returns, so it
// does not bother preserving anything.
//
// The IRQ stub does return, so it uses the pair the architecture provides for
// exactly this: `srsdb sp!, #0x12` pushes the (adjusted) return address and
// `SPSR` onto the IRQ stack, and `rfeia sp!` pops them back into `PC` and
// `CPSR` atomically. Between them the caller-saved set is preserved by hand,
// because the interrupted code is not expecting a function call.
global_asm!(
    r#"
.section .text
.align 5
.globl exception_vectors
exception_vectors:
    b       .                       // reset: never taken here
    b       vector_undefined
    b       vector_supervisor
    b       vector_prefetch_abort
    b       vector_data_abort
    b       .                       // reserved
    b       vector_irq
    b       .                       // fiq: not routed in this milestone

vector_undefined:
    mov     r0, #1
    mrs     r2, spsr
    mov     r1, lr
    b       arm32_fatal

vector_supervisor:
    mov     r0, #2
    mrs     r2, spsr
    mov     r1, lr
    b       arm32_fatal

vector_prefetch_abort:
    mov     r0, #3
    mrs     r2, spsr
    sub     r1, lr, #4
    b       arm32_fatal

vector_data_abort:
    mov     r0, #4
    mrs     r2, spsr
    sub     r1, lr, #8
    b       arm32_fatal

vector_irq:
    sub     lr, lr, #4
    srsdb   sp!, #0x12
    push    {{r0-r3, r12, lr}}
    and     r0, sp, #4
    sub     sp, sp, r0
    push    {{r0}}
    bl      arm32_irq
    pop     {{r0}}
    add     sp, sp, r0
    pop     {{r0-r3, r12, lr}}
    rfeia   sp!
"#
);
