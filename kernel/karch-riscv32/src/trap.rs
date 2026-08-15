// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Supervisor trap entry: one vector, one decoder, and the hooks the boot
//! glue installs on it. Structurally the 64-bit port's trap module; two things
//! change with the register width and both are the kind that fail silently if
//! copied across without thought.
//!
//! **The interrupt bit of `scause` is bit 31, not bit 63.** `scause` is XLEN
//! wide, so its top bit moves with the register. A vector that tested bit 63
//! here would classify *every* trap as an exception — including the timer
//! tick, which would then be reported as a fatal fault at whatever `sepc`
//! happened to hold.
//!
//! **The frame is 4-byte slots.** `sw`/`lw` rather than `sd`/`ld`, and the
//! frame size halves. The static assertion at the end of the module is what
//! keeps the assembly and the struct in step, as on the 64-bit port.
//!
//! Everything here runs on the kernel stack of whatever was interrupted, and
//! this milestone has no unprivileged level, so there is no stack swap and
//! `sscratch` is untouched.
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (the tick path is budgeted with the switch path)

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Registers the trap vector saves, in the order the assembly stores them.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrapFrame {
    pub ra: u32,
    pub t0: u32,
    pub t1: u32,
    pub t2: u32,
    pub t3: u32,
    pub t4: u32,
    pub t5: u32,
    pub t6: u32,
    pub a0: u32,
    pub a1: u32,
    pub a2: u32,
    pub a3: u32,
    pub a4: u32,
    pub a5: u32,
    pub a6: u32,
    pub a7: u32,
    /// Where the trap was taken (`sepc`), and where `sret` resumes.
    pub sepc: u32,
    /// Why (`scause`): **bit 31** set means an interrupt, clear means an
    /// exception, and the low bits are the cause number.
    pub scause: u32,
    /// The faulting address or offending instruction (`stval`).
    pub stval: u32,
    /// Supervisor status at the moment of the trap. `SPP` says which
    /// privilege level was interrupted, which is what makes a fault
    /// containable rather than fatal.
    pub sstatus: u32,
    /// The interrupted stack pointer — the *user* stack for a trap from
    /// U-mode, and the pre-frame kernel stack otherwise. The vector cannot
    /// leave it in `sp`, because `sp` is what it just swapped away.
    pub sp: u32,
}

/// A fatal-trap handler. It never returns: an unexpected exception in this
/// kernel is a bug, and reporting then stopping beats resuming into it.
pub type TrapHandler = fn(&TrapFrame) -> !;
/// The periodic tick.
pub type TickHook = fn();
/// A device interrupt, by PLIC source number. Returns true if it was claimed
/// by a driver; false means nothing was listening, which is counted.
pub type DeviceIrqHook = fn(u32) -> bool;
/// An exception taken from U-mode: a syscall, or a fault the kernel contains
/// rather than dies of.
///
/// It may return, in which case the vector resumes U-mode with whatever the
/// hook left in the frame — advancing `sepc` past an `ecall` is the hook's
/// job, because the architecture does not do it. It may equally *not* return,
/// by switching to another context, which is how a fatal user fault is
/// contained.
pub type UserTrapHook = fn(&mut TrapFrame);

static TRAP_HANDLER: AtomicUsize = AtomicUsize::new(0);
static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);
static DEVICE_IRQ_HOOK: AtomicUsize = AtomicUsize::new(0);
static USER_TRAP_HOOK: AtomicUsize = AtomicUsize::new(0);
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

/// Installs the hook for exceptions taken from U-mode. Without one, a user
/// exception falls through to the fatal handler — the honest behaviour for a
/// kernel that has not yet said what it wants done about one.
pub fn set_user_trap_hook(hook: UserTrapHook) {
    USER_TRAP_HOOK.store(hook as usize, Ordering::Relaxed);
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
/// Called once, on the boot hart, with interrupts masked and the kernel's text
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
const INTERRUPT_SUPERVISOR_SOFTWARE: u32 = 1;
const INTERRUPT_SUPERVISOR_TIMER: u32 = 5;
const INTERRUPT_SUPERVISOR_EXTERNAL: u32 = 9;

/// Bit of `scause` that distinguishes an interrupt from an exception. **31 on
/// this architecture** — see the module header.
const SCAUSE_INTERRUPT: u32 = 1 << 31;

/// `sstatus.SPP` — the privilege level the trap came *from*: 0 is U-mode, 1 is
/// S-mode. Bit 8, as on the 64-bit port: `sstatus` is narrower here, that bit
/// is not one of the ones that moved.
const SSTATUS_SPP: u32 = 1 << 8;

/// `sstatus.SUM` — permit supervisor access to user memory.
const SSTATUS_SUM: u32 = 1 << 18;

/// The `scause` of an `ecall` taken from U-mode: the syscall instruction.
pub const EXCEPTION_ECALL_FROM_USER: u32 = 8;

/// True when the trap interrupted unprivileged code.
pub fn from_user(sstatus: u32) -> bool {
    sstatus & SSTATUS_SPP == 0
}

/// Permits the kernel to dereference a validated user pointer.
///
/// Set once and left set, for the reason the 64-bit port recorded (D101): a
/// syscall that copies from user memory may then **block**, handing off inside
/// the window, and `sstatus` is per-hart — so a `SUM` scoped to each copy
/// would be set while an unrelated thread ran. Narrowing it means making `SUM`
/// per-thread state the context switch carries.
///
/// # Safety
///
/// Every user pointer the kernel follows must already have been validated
/// against the caller's tracked mappings (`kcore::syscall::read_user`).
pub unsafe fn allow_user_memory_access() {
    // SAFETY: `sstatus` is this hart's supervisor status register; setting SUM
    // changes only whether S-mode may access `U` pages.
    unsafe { asm!("csrs sstatus, {bit}", bit = in(reg) SSTATUS_SUM, options(nomem, nostack)) };
}

/// Stable name for an exception cause, so a fault names itself in the log
/// rather than printing a bare number.
pub fn exception_name(scause: u32) -> &'static str {
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
/// copy-on-write path needs.
pub fn is_write_fault(scause: u32) -> bool {
    scause & SCAUSE_INTERRUPT == 0 && (scause & !SCAUSE_INTERRUPT) == 15
}

/// Rust half of the trap vector.
///
/// # Safety
///
/// Called only by `trap_vector`, with `frame` pointing at the register block
/// it just pushed on the current stack.
#[unsafe(no_mangle)]
unsafe extern "C" fn trap_entry(frame: *mut TrapFrame) {
    let (sepc, scause, stval, sstatus): (u32, u32, u32, u32);
    // SAFETY: these four are read-only-to-us supervisor CSRs describing the
    // trap in progress; reading them has no side effect.
    unsafe {
        asm!("csrr {}, sepc", out(reg) sepc, options(nomem, nostack));
        asm!("csrr {}, scause", out(reg) scause, options(nomem, nostack));
        asm!("csrr {}, stval", out(reg) stval, options(nomem, nostack));
        asm!("csrr {}, sstatus", out(reg) sstatus, options(nomem, nostack));
    }

    // SAFETY: `frame` points at the vector's own register block on the current
    // stack, which is live for the whole call.
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
                UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
                clear_software_interrupt();
            }
            _ => {
                UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
            }
        }
        return;
    }

    // An exception from U-mode is the kernel's business, not its death: a
    // syscall to serve, or a fault to contain. Routed before the fatal handler
    // so that "the kernel faulted" and "a user program faulted" never share a
    // path.
    if from_user(sstatus) {
        let hook = USER_TRAP_HOOK.load(Ordering::Relaxed);
        if hook != 0 {
            // SAFETY: the only writer is `set_user_trap_hook`, which stores a
            // `UserTrapHook` function pointer; a non-zero value is one.
            let hook: UserTrapHook = unsafe { core::mem::transmute(hook) };
            hook(frame);
            return;
        }
    }

    // An exception in the kernel. Nothing resumes from one.
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
    unsafe { asm!("csrc sip, {}", in(reg) 1u32 << 1, options(nomem, nostack)) };
}

// The vector. Swaps to a kernel stack if the trap came from U-mode, saves the
// caller-saved registers the interrupted code expects to survive, calls the
// Rust half, restores, and returns.
//
// `.align 2` is required, not cosmetic: `stvec` stores the base in its upper
// bits and the mode in the low two, so a misaligned vector would be read as a
// different mode.
//
// Callee-saved registers are absent on purpose — `trap_entry` is an ordinary
// Rust function and the ABI already makes it preserve them.
//
// 96 bytes are reserved for an 84-byte frame so the stack stays 16-byte
// aligned, which the ABI requires of any stack a called function runs on at
// this word size just as at the other.
//
// `sscratch` holds a kernel stack top exactly while U-mode is running, and
// zero at every other instant — the invariant that makes the first branch
// exact even for a trap taken while handling a trap, and the reason this
// register needs no saving across a context switch (it is *derived* at every
// exit to U-mode, never carried). The 64-bit port's module header explains it
// at length; the mechanism here is identical at half the width.
global_asm!(
    r#"
.text
.align 2
.global trap_vector
trap_vector:
    csrrw   sp, sscratch, sp
    bnez    sp, 1f
    csrrw   sp, sscratch, sp
1:
    addi    sp, sp, -96
    sw      ra,  0(sp)
    sw      t0,  4(sp)
    sw      t1,  8(sp)
    sw      t2,  12(sp)
    sw      t3,  16(sp)
    sw      t4,  20(sp)
    sw      t5,  24(sp)
    sw      t6,  28(sp)
    sw      a0,  32(sp)
    sw      a1,  36(sp)
    sw      a2,  40(sp)
    sw      a3,  44(sp)
    sw      a4,  48(sp)
    sw      a5,  52(sp)
    sw      a6,  56(sp)
    sw      a7,  60(sp)

    // Record the interrupted stack pointer, and disarm sscratch so that a trap
    // taken from here on classifies as what it is.
    csrr    t0, sscratch
    beqz    t0, 2f
    sw      t0, 80(sp)
    csrw    sscratch, zero
    j       3f
2:
    addi    t0, sp, 96
    sw      t0, 80(sp)
3:
    mv      a0, sp
    call    trap_entry

    // sepc is written back because a resumable trap may have moved it: an
    // ecall must resume *after* the instruction, and the architecture does not
    // advance it.
    lw      t0, 64(sp)
    csrw    sepc, t0

    // Returning to U-mode? Re-arm sscratch with this thread's kernel stack top
    // — which is exactly where this frame ends.
    lw      t0, 76(sp)
    andi    t0, t0, 0x100
    bnez    t0, 4f
    addi    t0, sp, 96
    csrw    sscratch, t0
4:
    lw      ra,  0(sp)
    lw      t0,  4(sp)
    lw      t1,  8(sp)
    lw      t2,  12(sp)
    lw      t3,  16(sp)
    lw      t4,  20(sp)
    lw      t5,  24(sp)
    lw      t6,  28(sp)
    lw      a0,  32(sp)
    lw      a1,  36(sp)
    lw      a2,  40(sp)
    lw      a3,  44(sp)
    lw      a4,  48(sp)
    lw      a5,  52(sp)
    lw      a6,  56(sp)
    lw      a7,  60(sp)
    // Last, because it is the base every load above was relative to.
    lw      sp,  80(sp)
    sret
"#
);

// The assembly stores sixteen registers at 0..64, `trap_entry` writes the four
// CSR fields at 64..80, and the vector writes the interrupted stack pointer at
// 80. If `TrapFrame` ever grows past what the vector reserves, `trap_entry`
// would write past the block — so the size is checked here rather than trusted.
const _: () = assert!(core::mem::size_of::<TrapFrame>() == 84);
