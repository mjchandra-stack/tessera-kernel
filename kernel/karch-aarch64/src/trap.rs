// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Exception entry for EL1: the vector table, the saved frame, and the hooks
//! boot glue registers to decide what an exception means.
//!
//! The vector table is not an array of pointers the way x86-64's IDT is — it
//! is *code*, sixteen 128-byte slots the CPU branches into directly, grouped
//! by where the exception came from (current EL on SP0, current EL on SPx,
//! lower EL in AArch64, lower EL in AArch32) rather than by what happened.
//! What happened is in `ESR_EL1` instead, which the handler reads. So where
//! the x86-64 port needs 32 vector stubs to recover a vector number the CPU
//! did not pass, this needs four live entries and one register read.
//!
//! Until this module existed, a kernel fault was a *silent hang*: with
//! `VBAR_EL1` unset the CPU branched to address zero, faulted again, and
//! looped. A fault now reports its class, faulting address, and the
//! instruction that caused it, and exits the run — which is what makes the
//! write-XOR-execute enforcement provable rather than merely observable as a
//! timeout.
//!
//! The lower-EL AArch64 sync/IRQ entries route to EL0 handlers (a `svc` or a
//! user abort, and shared-with-EL1 interrupts); the remaining lower-EL entries
//! (FIQ, SError, AArch32) stay on the fatal path — nothing generates them, so
//! one arriving means the machine is not in the state we believe it to be.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md,
//! docs/hardware/01-platform-and-cpu-support.md ("Trap entry and return")
//! Budget: none in this milestone

use core::arch::global_asm;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Registers and syndrome captured on exception entry, in the order the
/// vector stubs write them. `#[repr(C)]` fixes the layout the assembly
/// depends on; `FRAME_BYTES` below must match its size.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrapFrame {
    /// `x0`-`x30`.
    pub x: [u64; 31],
    /// `SP_EL0` — the interrupted thread's own stack pointer, saved and
    /// restored with the rest of its state (per-CPU hardware state that
    /// would otherwise leak between EL0 threads across a context switch).
    pub sp: u64,
    /// Exception link register: the instruction that faulted, or the one to
    /// resume at.
    pub elr: u64,
    /// Saved processor state.
    pub spsr: u64,
    /// Exception syndrome: class and details of what happened.
    pub esr: u64,
    /// Faulting virtual address, for the classes that set it.
    pub far: u64,
}

/// Size of the saved frame. The assembly allocates exactly this much, so the
/// static assertion below is what keeps the two in step.
const FRAME_BYTES: usize = 288;
const _: () = assert!(core::mem::size_of::<TrapFrame>() == FRAME_BYTES);

/// Handles a fatal exception; never returns.
pub type TrapHandler = fn(&TrapFrame) -> !;
/// Called on each timer tick, with interrupts masked.
pub type TickHook = fn();
/// Handles a device interrupt, returning whether it recognized the ID.
pub type DeviceIrqHook = fn(u32) -> bool;
/// Handles a synchronous exception taken from EL0 (a `svc` or a user abort),
/// with the saved frame. It may modify the frame and return to resume EL0, or
/// switch away (never return) to abandon the faulting user thread.
pub type El0SyncHook = fn(&mut TrapFrame);

static TRAP_HANDLER: AtomicUsize = AtomicUsize::new(0);
static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);
static DEVICE_IRQ_HOOK: AtomicUsize = AtomicUsize::new(0);
static EL0_SYNC_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Registers the fatal-exception handler. Boot glue installs one before
/// anything can fault; without it a fault halts silently, which is the state
/// this module exists to end.
pub fn set_trap_handler(handler: TrapHandler) {
    TRAP_HANDLER.store(handler as usize, Ordering::Relaxed);
}

/// Registers the periodic tick callback.
pub fn set_tick_hook(hook: TickHook) {
    TICK_HOOK.store(hook as usize, Ordering::Relaxed);
}

/// Registers the device-interrupt callback.
pub fn set_device_irq_hook(hook: DeviceIrqHook) {
    DEVICE_IRQ_HOOK.store(hook as usize, Ordering::Relaxed);
}

/// Registers the EL0 synchronous-exception handler (`svc` + user aborts).
/// Without one, an EL0 exception is fatal like any other.
pub fn set_el0_sync_hook(hook: El0SyncHook) {
    EL0_SYNC_HOOK.store(hook as usize, Ordering::Relaxed);
}

/// True when the syndrome is an `SVC` executed from AArch64 EL0.
pub const fn is_svc(esr: u64) -> bool {
    (esr >> 26) & 0x3f == 0b010101
}

/// The 16-bit immediate of an `SVC` (`ESR_EL1[15:0]`).
pub const fn svc_imm(esr: u64) -> u16 {
    (esr & 0xffff) as u16
}

/// Count of interrupts that no hook claimed — a silent drop would otherwise
/// look exactly like a device that never fired.
static UNEXPECTED_IRQS: AtomicUsize = AtomicUsize::new(0);

/// Interrupts delivered that nothing claimed.
pub fn unexpected_irqs() -> usize {
    UNEXPECTED_IRQS.load(Ordering::Relaxed)
}

/// Installs the vector table on this CPU.
///
/// # Safety
///
/// Must run on the boot CPU before interrupts are unmasked, and the image's
/// text must be mapped executable at its current address.
pub unsafe fn init_vectors() {
    unsafe extern "C" {
        static exception_vectors: u8;
    }
    // SAFETY: `exception_vectors` is the 2 KiB-aligned table defined by the
    // `global_asm!` block below; writing `VBAR_EL1` only tells the CPU where
    // to branch on an exception, and `isb` makes that visible before one can
    // be taken.
    unsafe {
        let base = &raw const exception_vectors as u64;
        core::arch::asm!(
            "msr vbar_el1, {base}",
            "isb",
            base = in(reg) base,
            options(nomem, nostack),
        );
    }
}

/// Human-readable name for an exception class, for fault reports. The class
/// is `ESR_EL1[31:26]`.
pub fn exception_class_name(esr: u64) -> &'static str {
    match (esr >> 26) & 0x3f {
        0b000000 => "unknown",
        0b000111 => "SIMD/FP access trapped",
        0b001110 => "illegal execution state",
        0b010101 => "SVC from AArch64",
        0b100000 => "instruction abort, lower EL",
        0b100001 => "instruction abort, same EL",
        0b100010 => "PC alignment fault",
        0b100100 => "data abort, lower EL",
        0b100101 => "data abort, same EL",
        0b100110 => "SP alignment fault",
        0b101100 => "floating-point exception",
        0b111100 => "BRK instruction",
        _ => "unclassified",
    }
}

/// True when the syndrome describes a write rather than a read. Only
/// meaningful for the data-abort classes.
pub const fn is_write_fault(esr: u64) -> bool {
    // WnR, ESR_EL1[6], valid for data aborts.
    esr & (1 << 6) != 0
}

/// Fatal path shared by every exception this milestone cannot resume from.
fn fatal(frame: &TrapFrame) -> ! {
    let handler = TRAP_HANDLER.load(Ordering::Relaxed);
    if handler != 0 {
        // SAFETY: `TRAP_HANDLER` only ever holds a `TrapHandler` stored by
        // `set_trap_handler`, and a non-zero value means one was stored.
        let handler: TrapHandler = unsafe { core::mem::transmute::<usize, TrapHandler>(handler) };
        handler(frame);
    }
    // No handler registered: there is nowhere to report to, so stop rather
    // than return into a state we have already decided is unrecoverable.
    loop {
        // SAFETY: `wfi` is a hint with no memory effects.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

/// Synchronous exception at EL1 — a fault in the kernel itself.
///
/// # Safety
///
/// Called only from the vector stubs, with `frame` pointing at the frame they
/// just built on the current stack.
#[unsafe(no_mangle)]
extern "C" fn aarch64_sync_exception(frame: &TrapFrame) -> ! {
    fatal(frame)
}

/// An exception from a state that should be unreachable: EL1 running on
/// `SP_EL0`, or a lower exception level that does not exist yet.
///
/// # Safety
///
/// Called only from the vector stubs.
#[unsafe(no_mangle)]
extern "C" fn aarch64_unreachable_exception(frame: &TrapFrame) -> ! {
    fatal(frame)
}

/// Synchronous exception from EL0 — a `svc` or a user abort. Routes to the
/// registered EL0 hook, which resumes EL0 (returns) or switches away.
///
/// # Safety
///
/// Called only from the lower-EL sync vector stub, with `frame` on the current
/// (kernel) stack. The kernel is mapped and `SP_EL1` is a valid kernel stack.
#[unsafe(no_mangle)]
extern "C" fn aarch64_el0_sync(frame: &mut TrapFrame) {
    let hook = EL0_SYNC_HOOK.load(Ordering::Relaxed);
    if hook != 0 {
        // SAFETY: `EL0_SYNC_HOOK` only ever holds an `El0SyncHook` stored by
        // `set_el0_sync_hook`; non-zero means one was stored.
        let hook: El0SyncHook = unsafe { core::mem::transmute::<usize, El0SyncHook>(hook) };
        hook(frame);
        return;
    }
    // No EL0 hook: an EL0 exception with nothing to handle it is as fatal as
    // any other unrecoverable state.
    fatal(frame)
}

/// IRQ at EL1. Acknowledges at the controller, dispatches, and completes.
///
/// # Safety
///
/// Called only from the vector stub, with interrupts masked.
#[unsafe(no_mangle)]
extern "C" fn aarch64_irq_exception(_frame: &mut TrapFrame) {
    // SAFETY: interrupt context on a core whose GIC interface boot glue
    // initialized before unmasking interrupts.
    let acknowledgement = unsafe { tessera_karch_arm_common::gic::acknowledge() };
    if tessera_karch_arm_common::gic::is_spurious(acknowledgement) {
        // The one acknowledgement that must not be completed.
        return;
    }
    let id = tessera_karch_arm_common::gic::intid(acknowledgement);

    let mut claimed = false;
    if id == crate::timer::TIMER_INTID {
        crate::timer::on_expiry();
        let hook = TICK_HOOK.load(Ordering::Relaxed);
        if hook != 0 {
            // SAFETY: `TICK_HOOK` only ever holds a `TickHook` stored by
            // `set_tick_hook`; non-zero means one was stored.
            let hook: TickHook = unsafe { core::mem::transmute::<usize, TickHook>(hook) };
            hook();
        }
        claimed = true;
    } else {
        let hook = DEVICE_IRQ_HOOK.load(Ordering::Relaxed);
        if hook != 0 {
            // SAFETY: `DEVICE_IRQ_HOOK` only ever holds a `DeviceIrqHook`
            // stored by `set_device_irq_hook`; non-zero means one was stored.
            let hook: DeviceIrqHook = unsafe { core::mem::transmute::<usize, DeviceIrqHook>(hook) };
            claimed = hook(id);
        }
    }

    if !claimed {
        // Counted, never silently dropped: an unclaimed interrupt and a
        // device that never fired look identical otherwise.
        UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
    }

    // SAFETY: `acknowledgement` came from `acknowledge` on this core and is
    // not spurious (checked above).
    unsafe { tessera_karch_arm_common::gic::end_of_interrupt(acknowledgement) };
}

// The vector table and the frame save/restore.
//
// Each of the sixteen entries is a 128-byte slot the CPU branches into, so
// the table is code and must be 2 KiB aligned. Only the "current EL, SP_ELx"
// group is reachable today (the kernel runs EL1h); the rest jump to the
// unreachable-state handler rather than being left as padding, so taking one
// is reported instead of executing whatever follows.
//
// The frame layout must match `TrapFrame` exactly — the static assertion
// above guards its size, and the offsets here are its fields in order. `x30`
// is saved because `bl` into Rust overwrites it. `sp` is `SP_EL0` — the
// interrupted thread's own stack pointer — saved and RESTORED with the rest
// of its register state: `SP_EL0` is per-CPU hardware state, so without this
// an EL0 thread that resumes after another EL0 thread ran would continue on
// the other thread's stack pointer (found by D81's two-process driver host —
// every earlier EL0 program either never touched SP after a resume or never
// interleaved with another stack-using EL0 thread). For an EL1→EL1 trap the
// pair is a harmless save/rewrite of dead state.
global_asm!(
    r#"
.macro SAVE_FRAME
    sub     sp, sp, #288
    stp     x0, x1,   [sp, #0]
    stp     x2, x3,   [sp, #16]
    stp     x4, x5,   [sp, #32]
    stp     x6, x7,   [sp, #48]
    stp     x8, x9,   [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]
    mrs     x9, sp_el0
    str     x9,       [sp, #248]
    mrs     x9, elr_el1
    mrs     x10, spsr_el1
    stp     x9, x10,  [sp, #256]
    mrs     x9, esr_el1
    mrs     x10, far_el1
    stp     x9, x10,  [sp, #272]
.endm

.macro RESTORE_FRAME
    ldr     x9,       [sp, #248]
    msr     sp_el0, x9
    ldp     x9, x10,  [sp, #256]
    msr     elr_el1, x9
    msr     spsr_el1, x10
    ldp     x0, x1,   [sp, #0]
    ldp     x2, x3,   [sp, #16]
    ldp     x4, x5,   [sp, #32]
    ldp     x6, x7,   [sp, #48]
    ldp     x8, x9,   [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]
    add     sp, sp, #288
.endm

// One vector slot: branch to \target, padded to the architectural 128 bytes.
.macro VENTRY target
.balign 0x80
    b       \target
.endm

.text
.balign 2048
.globl exception_vectors
exception_vectors:
    // Current EL with SP_EL0 — the kernel runs EL1h, so never taken.
    VENTRY  el1_unreachable
    VENTRY  el1_unreachable
    VENTRY  el1_unreachable
    VENTRY  el1_unreachable

    // Current EL with SP_ELx — the kernel's own exceptions.
    VENTRY  el1_sync
    VENTRY  el1_irq
    VENTRY  el1_fiq
    VENTRY  el1_serror

    // Lower EL, AArch64 — EL0. Sync is a svc or a user abort (resumable, so
    // the handler can return to EL0); IRQ shares the EL1 IRQ path; FIQ/SError
    // from EL0 are as unexpected as at EL1.
    VENTRY  el0_sync
    VENTRY  el0_irq
    VENTRY  el1_unreachable
    VENTRY  el1_unreachable

    // Lower EL, AArch32 — never supported.
    VENTRY  el1_unreachable
    VENTRY  el1_unreachable
    VENTRY  el1_unreachable
    VENTRY  el1_unreachable

el1_sync:
    SAVE_FRAME
    mov     x0, sp
    bl      aarch64_sync_exception
    b       .

// FIQ and SError are fatal here for the same reason: nothing in this kernel
// generates them, so one arriving means the machine is not in the state we
// believe it to be.
el1_fiq:
el1_serror:
el1_unreachable:
    SAVE_FRAME
    mov     x0, sp
    bl      aarch64_unreachable_exception
    b       .

el1_irq:
    SAVE_FRAME
    mov     x0, sp
    bl      aarch64_irq_exception
    RESTORE_FRAME
    eret

// EL0 synchronous exception (svc / user abort). Resumable: if the handler
// returns, RESTORE_FRAME + eret goes back to EL0. If it switches away (an
// `exit` syscall or a contained fault), control never reaches the restore.
el0_sync:
    SAVE_FRAME
    mov     x0, sp
    bl      aarch64_el0_sync
    RESTORE_FRAME
    eret

// EL0 IRQ shares the EL1 interrupt path.
el0_irq:
    SAVE_FRAME
    mov     x0, sp
    bl      aarch64_irq_exception
    RESTORE_FRAME
    eret
"#
);
