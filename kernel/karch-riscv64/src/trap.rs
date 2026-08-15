// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Supervisor trap entry: one vector, one decoder, and the hooks the boot
//! glue installs on it.
//!
//! RISC-V funnels *everything* — every exception and every interrupt — through
//! a single address in `stvec`, with `scause` naming which. That is unlike
//! both siblings: x86-64 dispatches through a 256-entry IDT and AArch64
//! through a 16-slot vector table indexed by kind and origin, so on those two
//! the hardware has already classified the trap before any code runs. Here the
//! classification is the first thing this module does, and the cost of getting
//! it wrong is a fault reported as an interrupt or the reverse — which is why
//! the decode is a `match` on the architectural cause numbers rather than a
//! chain of guesses.
//!
//! `stvec` is programmed in **direct** mode rather than vectored. Vectored
//! mode spreads interrupt causes over separate entry points but leaves every
//! exception on entry zero, so it would split the decode across assembly and
//! Rust without removing it. One entry point keeps the whole classification in
//! one readable place.
//!
//! Everything here runs on the kernel stack of whatever was interrupted, and
//! this milestone has no unprivileged level, so there is no stack swap and
//! `sscratch` is untouched. That changes with ring 3, and the change is a
//! visible one: `sscratch` becomes the per-hart kernel-stack pointer the
//! vector swaps in, and — being per-thread hardware state — joins the set the
//! context switch must preserve.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (the tick path is budgeted with the switch path)

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Registers the trap vector saves, in the order the assembly stores them.
/// The layout is shared with `trap_vector` below and the static assertion at
/// the end of this module is what keeps the two in step.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrapFrame {
    pub ra: u64,
    pub t0: u64,
    pub t1: u64,
    pub t2: u64,
    pub t3: u64,
    pub t4: u64,
    pub t5: u64,
    pub t6: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub a7: u64,
    /// Where the trap was taken (`sepc`), and where `sret` resumes.
    pub sepc: u64,
    /// Why (`scause`): bit 63 set means an interrupt, clear means an
    /// exception, and the low bits are the cause number.
    pub scause: u64,
    /// The faulting address or offending instruction (`stval`).
    pub stval: u64,
    /// Supervisor status at the moment of the trap.
    pub sstatus: u64,
}

/// A fatal-trap handler. It never returns: an unexpected exception in this
/// kernel is a bug, and reporting then stopping beats resuming into it.
pub type TrapHandler = fn(&TrapFrame) -> !;
/// The periodic tick.
pub type TickHook = fn();
/// A device interrupt, by PLIC source number. Returns true if it was claimed
/// by a driver; false means nothing was listening, which is counted.
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

// SAFETY: declares the symbol defined by the `global_asm!` block below; the
// block only declares it and introduces no unsafe operation.
unsafe extern "C" {
    fn trap_vector();
}

/// Points `stvec` at the trap vector, in direct mode.
///
/// # Safety
///
/// Called once, on the boot CPU, with interrupts masked and the kernel's text
/// mapped executable at its current address.
pub unsafe fn init_vectors() {
    // SAFETY: `stvec` holds the supervisor trap-vector base. The low two bits
    // select the mode; the vector is 4-byte aligned by its `.align 2`, so
    // writing its address selects direct mode (mode 0).
    unsafe {
        asm!(
            "csrw stvec, {vector}",
            vector = in(reg) trap_vector as *const () as usize,
            options(nomem, nostack),
        );
    }
}

/// Interrupt causes, with `scause`'s top bit already stripped.
const INTERRUPT_SUPERVISOR_SOFTWARE: u64 = 1;
const INTERRUPT_SUPERVISOR_TIMER: u64 = 5;
const INTERRUPT_SUPERVISOR_EXTERNAL: u64 = 9;

/// Bit of `scause` that distinguishes an interrupt from an exception.
const SCAUSE_INTERRUPT: u64 = 1 << 63;

/// Stable name for an exception cause, so a fault names itself in the log
/// rather than printing a bare number.
pub fn exception_name(scause: u64) -> &'static str {
    match scause & !SCAUSE_INTERRUPT {
        0 => "instruction address misaligned",
        1 => "instruction access fault",
        2 => "illegal instruction",
        3 => "breakpoint",
        4 => "load address misaligned",
        5 => "load access fault",
        6 => "store/AMO address misaligned",
        7 => "store/AMO access fault",
        8 => "environment call from U-mode",
        9 => "environment call from S-mode",
        12 => "instruction page fault",
        13 => "load page fault",
        15 => "store/AMO page fault",
        18 => "software check",
        19 => "hardware error",
        _ => "reserved",
    }
}

/// True when `scause` describes a write that faulted — the classification the
/// copy-on-write path needs, kept here because the cause encoding is
/// architecture-private.
pub fn is_write_fault(scause: u64) -> bool {
    scause & SCAUSE_INTERRUPT == 0 && (scause & !SCAUSE_INTERRUPT) == 15
}

/// Rust half of the trap vector. Called with the saved general-purpose
/// registers; reads the cause CSRs itself rather than having the assembly
/// carry them, so the vector stays the same handful of stores.
///
/// # Safety
///
/// Called only by `trap_vector`, with `frame` pointing at the register block
/// it just pushed on the current stack.
#[unsafe(no_mangle)]
unsafe extern "C" fn trap_entry(frame: *mut TrapFrame) {
    let (sepc, scause, stval, sstatus): (u64, u64, u64, u64);
    // SAFETY: these four are read-only-to-us supervisor CSRs describing the
    // trap in progress; reading them has no side effect.
    unsafe {
        asm!("csrr {}, sepc", out(reg) sepc, options(nomem, nostack));
        asm!("csrr {}, scause", out(reg) scause, options(nomem, nostack));
        asm!("csrr {}, stval", out(reg) stval, options(nomem, nostack));
        asm!("csrr {}, sstatus", out(reg) sstatus, options(nomem, nostack));
    }

    // SAFETY: `frame` points at the vector's own register block on the
    // current stack, which is live for the whole call.
    let frame = unsafe { &mut *frame };
    frame.sepc = sepc;
    frame.scause = scause;
    frame.stval = stval;
    frame.sstatus = sstatus;

    if scause & SCAUSE_INTERRUPT != 0 {
        match scause & !SCAUSE_INTERRUPT {
            INTERRUPT_SUPERVISOR_TIMER => {
                crate::timer::on_expiry();
                let hook = TICK_HOOK.load(Ordering::Relaxed);
                if hook != 0 {
                    // SAFETY: the only writer is `set_tick_hook`, which stores
                    // a `TickHook` function pointer; a non-zero value is
                    // therefore one.
                    let hook: TickHook = unsafe { core::mem::transmute(hook) };
                    hook();
                }
            }
            INTERRUPT_SUPERVISOR_EXTERNAL => {
                // The PLIC hands over exactly one source per claim and expects
                // it back; claiming in a loop drains everything pending on
                // this hart before returning.
                while let Some(source) = tessera_karch_riscv_common::plic::claim() {
                    let hook = DEVICE_IRQ_HOOK.load(Ordering::Relaxed);
                    let handled = if hook != 0 {
                        // SAFETY: as the tick hook above.
                        let hook: DeviceIrqHook = unsafe { core::mem::transmute(hook) };
                        hook(source)
                    } else {
                        false
                    };
                    if !handled {
                        UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
                    }
                    tessera_karch_riscv_common::plic::complete(source);
                }
            }
            INTERRUPT_SUPERVISOR_SOFTWARE => {
                // Nothing raises one yet: software interrupts are the SMP
                // cross-hart doorbell, and this kernel is single-core (D8).
                // Counting beats ignoring.
                UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
                clear_software_interrupt();
            }
            _ => {
                UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
            }
        }
        return;
    }

    // An exception. Nothing in this milestone resumes from one.
    let handler = TRAP_HANDLER.load(Ordering::Relaxed);
    if handler != 0 {
        // SAFETY: the only writer is `set_trap_handler`, which stores a
        // `TrapHandler` function pointer.
        let handler: TrapHandler = unsafe { core::mem::transmute(handler) };
        handler(frame);
    }
    // No handler installed: stop rather than `sret` back into the faulting
    // instruction, which would fault again forever.
    loop {
        // SAFETY: `wfi` is a hint with no memory effects.
        unsafe { asm!("wfi", options(nomem, nostack)) };
    }
}

/// Clears this hart's pending supervisor software interrupt.
fn clear_software_interrupt() {
    // SAFETY: `sip` is the supervisor interrupt-pending CSR; clearing the SSIP
    // bit acknowledges a software interrupt and has no other effect.
    unsafe { asm!("csrc sip, {}", in(reg) 1u64 << 1, options(nomem, nostack)) };
}

// The vector. Saves the caller-saved registers the interrupted code expects to
// survive, calls the Rust half, restores, and returns.
//
// `.align 2` is required, not cosmetic: `stvec` stores the base in its upper
// bits and the mode in the low two, so a misaligned vector would be read as a
// different mode.
//
// Callee-saved registers are absent on purpose — `trap_entry` is an ordinary
// Rust function and the ABI already makes it preserve them.
global_asm!(
    r#"
.text
.align 2
.global trap_vector
trap_vector:
    addi    sp, sp, -160
    sd      ra,  0(sp)
    sd      t0,  8(sp)
    sd      t1,  16(sp)
    sd      t2,  24(sp)
    sd      t3,  32(sp)
    sd      t4,  40(sp)
    sd      t5,  48(sp)
    sd      t6,  56(sp)
    sd      a0,  64(sp)
    sd      a1,  72(sp)
    sd      a2,  80(sp)
    sd      a3,  88(sp)
    sd      a4,  96(sp)
    sd      a5,  104(sp)
    sd      a6,  112(sp)
    sd      a7,  120(sp)

    mv      a0, sp
    call    trap_entry

    ld      ra,  0(sp)
    ld      t0,  8(sp)
    ld      t1,  16(sp)
    ld      t2,  24(sp)
    ld      t3,  32(sp)
    ld      t4,  40(sp)
    ld      t5,  48(sp)
    ld      t6,  56(sp)
    ld      a0,  64(sp)
    ld      a1,  72(sp)
    ld      a2,  80(sp)
    ld      a3,  88(sp)
    ld      a4,  96(sp)
    ld      a5,  104(sp)
    ld      a6,  112(sp)
    ld      a7,  120(sp)
    addi    sp, sp, 160
    sret
"#
);

// The assembly reserves 160 bytes and stores sixteen registers at 0..128; the
// four CSR fields occupy 128..160, written by `trap_entry`. If `TrapFrame`
// ever grows past what the vector reserves, `trap_entry` would write past the
// block — so the sizes are checked here rather than trusted.
const _: () = assert!(core::mem::size_of::<TrapFrame>() == 160);
