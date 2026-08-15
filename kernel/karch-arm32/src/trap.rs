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

/// The user context an `svc` saves, in the order the vector stores it.
///
/// ARM banks `SP` and `LR` per mode, which does two thirds of this job for
/// free: entering SVC mode gives the kernel its own stack and leaves the
/// user's untouched, so there is no swap-through-a-scratch-register dance
/// like RISC-V's. What is *not* free is reading the user's banked pair at
/// all — only the `^` form of `ldm`/`stm` reaches it — which is why they are
/// two named fields here rather than something the frame gets by accident.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UserFrame {
    /// `r0`-`r12`. `r0` is both the first argument and the result.
    pub r: [u32; 13],
    /// The user-mode banked stack pointer.
    pub sp_usr: u32,
    /// The user-mode banked link register.
    pub lr_usr: u32,
    /// Where to resume: the instruction after the `svc`.
    pub pc: u32,
    /// The user `CPSR`, saved by the exception into `SPSR_svc`.
    pub cpsr: u32,
}

/// The processor mode a `CPSR`/`SPSR` names in its low five bits.
const MODE_MASK: u32 = 0x1f;
const MODE_USER: u32 = 0x10;

/// True when the saved status names User mode — i.e. the trap interrupted
/// unprivileged code.
pub const fn from_user(spsr: u32) -> bool {
    spsr & MODE_MASK == MODE_USER
}

/// An `svc` from User mode: the port's syscall entry.
///
/// It may return, in which case the vector resumes User mode with whatever
/// the hook left in the frame — including `pc`, which the vector already
/// advanced past the `svc` because ARM's `LR` points after it. It may equally
/// not return, by switching to another context.
pub type UserSyscallHook = fn(&mut UserFrame);

/// An abort taken from User mode: a fault the kernel contains rather than
/// dies of. It runs on the faulting thread's kernel stack, in SVC mode, and
/// is not expected to return — a contained user fault abandons the thread.
pub type UserAbortHook = fn(&TrapFrame);

/// A fatal-trap handler. It never returns.
pub type TrapHandler = fn(&TrapFrame) -> !;
/// The periodic tick.
pub type TickHook = fn();
/// A device interrupt, by interrupt id. Returns true if a driver claimed it.
pub type DeviceIrqHook = fn(u32) -> bool;

static TRAP_HANDLER: AtomicUsize = AtomicUsize::new(0);
static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);
static DEVICE_IRQ_HOOK: AtomicUsize = AtomicUsize::new(0);
static USER_SYSCALL_HOOK: AtomicUsize = AtomicUsize::new(0);
static USER_ABORT_HOOK: AtomicUsize = AtomicUsize::new(0);
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

/// Installs the syscall hook — the handler for an `svc` from User mode.
pub fn set_user_syscall_hook(hook: UserSyscallHook) {
    USER_SYSCALL_HOOK.store(hook as usize, Ordering::Relaxed);
}

/// Installs the hook for aborts taken from User mode. Without one, a user
/// abort falls through to the fatal handler — the honest behaviour for a
/// kernel that has not yet said what it wants done about one.
pub fn set_user_abort_hook(hook: UserAbortHook) {
    USER_ABORT_HOOK.store(hook as usize, Ordering::Relaxed);
}

/// Rust half of the `svc` vector.
///
/// # Safety
///
/// Called only by `vector_supervisor`, with `frame` pointing at the register
/// block it just built on the current thread's kernel stack.
#[unsafe(no_mangle)]
unsafe extern "C" fn arm32_user_syscall(frame: *mut UserFrame) {
    let hook = USER_SYSCALL_HOOK.load(Ordering::Relaxed);
    if hook == 0 {
        // Nothing installed: there is no sensible resumption, and returning
        // would re-execute nothing useful. Report through the fatal path.
        // SAFETY: `frame` is the vector's live block.
        let saved = unsafe { &*frame };
        // SAFETY: reaching the fatal handler with a synthesised frame is the
        // same contract `arm32_fatal` has; it does not return.
        unsafe { fatal_from_user(KIND_SUPERVISOR_CALL, saved.pc, saved.cpsr) }
    }
    // SAFETY: the only writer is `set_user_syscall_hook`, which stores a
    // `UserSyscallHook` function pointer; a non-zero value is one.
    let hook: UserSyscallHook = unsafe { core::mem::transmute(hook) };
    // SAFETY: `frame` points at the vector's own block on the current stack,
    // live for the whole call.
    hook(unsafe { &mut *frame });
}

/// Rust half of the abort vectors, for an abort that came from User mode.
///
/// Runs in SVC mode on the faulting thread's kernel stack — the abort vector
/// switches mode before calling this, because containing a fault means
/// switching contexts, and doing that from the abort mode would leave the CPU
/// in it.
///
/// # Safety
///
/// Called only by the abort vectors, with `kind` naming which one.
#[unsafe(no_mangle)]
unsafe extern "C" fn arm32_user_abort(kind: u32, pc: u32, spsr: u32) -> ! {
    // SAFETY: as `arm32_fatal` — the fault-address and fault-status registers
    // are read-only descriptions of the fault in progress.
    let (fault_address, fault_status) = unsafe { fault_registers(kind) };
    let frame = TrapFrame {
        kind,
        pc,
        spsr,
        fault_address,
        fault_status,
    };
    let hook = USER_ABORT_HOOK.load(Ordering::Relaxed);
    if hook != 0 {
        // SAFETY: the only writer is `set_user_abort_hook`.
        let hook: UserAbortHook = unsafe { core::mem::transmute(hook) };
        hook(&frame);
    }
    // Either no hook was installed or it returned, and there is nothing to
    // resume into: a user abort with no handler is as fatal as a kernel one.
    // SAFETY: the fatal path does not return.
    unsafe { fatal_from_user(kind, pc, spsr) }
}

/// Reads the fault-address/status pair the given vector reports through.
///
/// # Safety
///
/// Called only while handling a trap of that kind.
unsafe fn fault_registers(kind: u32) -> (u32, u32) {
    let (mut address, mut status) = (0u32, 0u32);
    // SAFETY: CP15 c6/c5 are read-only descriptions of the fault in progress;
    // reading them has no side effect, and the class chooses the pair.
    unsafe {
        if kind == KIND_DATA_ABORT {
            asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) address, options(nomem, nostack));
            asm!("mrc p15, 0, {}, c5, c0, 0", out(reg) status, options(nomem, nostack));
        } else if kind == KIND_PREFETCH_ABORT {
            asm!("mrc p15, 0, {}, c6, c0, 2", out(reg) address, options(nomem, nostack));
            asm!("mrc p15, 0, {}, c5, c0, 1", out(reg) status, options(nomem, nostack));
        }
    }
    (address, status)
}

/// Reports through the installed fatal handler and stops.
///
/// # Safety
///
/// Does not return; the caller must have nothing left to do.
unsafe fn fatal_from_user(kind: u32, pc: u32, spsr: u32) -> ! {
    // SAFETY: forwarded — reading the fault pair for the trap in progress.
    let (fault_address, fault_status) = unsafe { fault_registers(kind) };
    let frame = TrapFrame {
        kind,
        pc,
        spsr,
        fault_address,
        fault_status,
    };
    let handler = TRAP_HANDLER.load(Ordering::Relaxed);
    if handler != 0 {
        // SAFETY: the only writer is `set_trap_handler`.
        let handler: TrapHandler = unsafe { core::mem::transmute(handler) };
        handler(&frame);
    }
    loop {
        // SAFETY: `wfi` is a hint with no memory effects.
        unsafe { asm!("wfi", options(nomem, nostack)) };
    }
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

// The syscall entry. Entered in SVC mode, where `sp` is already this thread's
// kernel stack — ARM banks it, so there is nothing to swap. `lr` holds the
// address *after* the `svc`, which is the resume point, and `spsr` the user
// status.
//
// The user's own `sp` and `lr` are banked too, and the `^` form of `stm`/`ldm`
// is the only way to reach them from here. It forbids writeback, hence the
// separate address register; and the instruction after an `ldm ^` must not
// touch a banked register, hence the `nop`.
vector_supervisor:
    sub     sp, sp, #72
    stm     sp, {{r0-r12}}
    add     r0, sp, #52
    stm     r0, {{sp, lr}}^         // the *user* sp and lr
    str     lr, [sp, #60]          // resume address
    mrs     r1, spsr
    str     r1, [sp, #64]          // user CPSR
    mov     r0, sp
    bl      arm32_user_syscall
    ldr     r1, [sp, #64]
    msr     spsr_cxsf, r1
    add     r0, sp, #52
    ldm     r0, {{sp, lr}}^
    nop
    ldr     lr, [sp, #60]
    ldm     sp, {{r0-r12}}
    add     sp, sp, #72
    movs    pc, lr                 // return to User, CPSR from SPSR

// The abort vectors. A fault from the kernel is fatal exactly as before; one
// from User mode is contained, and containment means switching context — so
// the handler is reached in **SVC mode**, on the faulting thread's kernel
// stack, rather than on the abort stack this vector arrived on. Leaving the
// CPU in abort mode would be a slow-acting disaster: the next abort would
// overwrite the frame this one is standing on.
vector_prefetch_abort:
    sub     lr, lr, #4
    mrs     r2, spsr
    mov     r1, lr
    mov     r0, #3
    tst     r2, #0x0f              // User mode is 0x10: the low four bits are 0
    bne     arm32_fatal
    cps     #0x13
    b       arm32_user_abort

vector_data_abort:
    sub     lr, lr, #8
    mrs     r2, spsr
    mov     r1, lr
    mov     r0, #4
    tst     r2, #0x0f
    bne     arm32_fatal
    cps     #0x13
    b       arm32_user_abort

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
