// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! ARM 32-bit kernel-thread context switching: the callee-saved register set
//! and the stack pointer, saved into and restored from a thread's own kernel
//! stack. Shaped like every other port — a `Context` that is only a stack
//! pointer, with the real state parked on the stack that pointer names.
//!
//! The callee-saved set under AAPCS is `r4`-`r11` plus `lr`, nine registers,
//! and `stmdb`/`ldmia` move the whole set in one instruction each — the
//! reason this switch is shorter than any of the others. The frame carries
//! one pad slot so it stays 8-byte aligned, which the procedure call standard
//! requires at every public interface.
//!
//! Floating-point and Advanced SIMD state is deliberately absent: the VFP
//! unit is left disabled (`CPACR` untouched), so a stray FP instruction traps
//! as undefined rather than silently corrupting state no switch preserves.
//! The kernel emits none.
//!
//! [`UserContextOps`](tessera_karch::UserContextOps) is **not** implemented.
//! This port has no unprivileged level yet, and the trait split exists so
//! that absence is a compile error rather than a stub.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Scheduling"),
//! docs/hardware/01-platform-and-cpu-support.md ("Architecture Porting
//! Layer")
//! Budget: B7 (context switch)

use core::arch::global_asm;
use tessera_karch::{ContextOps, UserContextOps, VirtAddr};

/// Saved execution context: just the stack pointer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context {
    /// Saved kernel stack pointer. `#[repr(C)]` fixes this at offset 0, which
    /// the assembly relies on.
    sp: u32,
}

impl Context {
    /// An empty context (null stack pointer). Valid only as a `switch`
    /// *source* — the running code saves its real state here on first switch.
    pub const fn zeroed() -> Self {
        Self { sp: 0 }
    }
}

/// The context-switch operations for ARM 32-bit.
pub struct ContextSwitch;

/// 4-byte slots [`ContextOps::init`] lays on a new stack: `r4`-`r11`, `lr`,
/// and one pad slot so the frame stays 8-byte aligned.
const INIT_FRAME_SLOTS: u32 = 10;

/// Slot index of `r4`, which the trampoline reads as the entry point — the
/// first register `ldmia` restores.
const SLOT_R4: usize = 0;
/// Slot index of `r5`, which the trampoline reads as the entry argument.
const SLOT_R5: usize = 1;
/// Slot index of `r6`, which the *user* trampoline reads as the user stack
/// pointer. Unused by the kernel trampoline.
const SLOT_R6: usize = 2;
/// Slot index of `lr` — the address `context_switch` returns into, and
/// therefore where `init` puts the trampoline. Eight registers precede it.
const SLOT_LR: usize = 8;

// SAFETY: these declare symbols defined by the `global_asm!` blocks below; the
// block only declares them and introduces no unsafe operation.
unsafe extern "C" {
    fn context_switch(prev: *mut Context, next: *const Context);
    fn thread_trampoline() -> !;
    fn user_thread_trampoline() -> !;
}

/// Address of the assembly thread trampoline, as a `u32` for the `lr` slot.
fn thread_trampoline_addr() -> u32 {
    // Taking a function item's address performs no unsafe operation.
    (thread_trampoline as *const ()) as u32
}

impl ContextOps for ContextSwitch {
    type Context = Context;

    fn empty() -> Context {
        Context::zeroed()
    }

    // SAFETY: see the `ContextOps::init` contract — `stack_top` must top a
    // valid, mapped, exclusively-owned kernel stack with room for the frame.
    unsafe fn init(stack_top: VirtAddr, entry: extern "C" fn(usize) -> !, arg: usize) -> Context {
        // Lay down exactly the frame `context_switch` pops when it first
        // resumes this context: `ldmia` restores r4-r11 and lr from ascending
        // addresses and then returns through lr, so seeding lr with the
        // trampoline is what makes the first switch *arrive* somewhere, and
        // r4/r5 carry the entry point and its argument into it.
        let sp = (stack_top.as_u64() as u32) & !0x7;
        let frame = sp - INIT_FRAME_SLOTS * 4;
        let slots = frame as *mut u32;
        // SAFETY: the caller guarantees `stack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame.
        unsafe {
            for slot in 0..INIT_FRAME_SLOTS as usize {
                slots.add(slot).write(0);
            }
            slots.add(SLOT_R4).write(entry as usize as u32);
            slots.add(SLOT_R5).write(arg as u32);
            slots.add(SLOT_LR).write(thread_trampoline_addr());
        }
        Context { sp: frame }
    }

    // SAFETY: see the `ContextOps::switch` contract — both pointers reference
    // valid `Context` storage owned by the caller, and `*next` was produced by
    // `init` or a prior `switch`, so its stack holds a matching frame.
    unsafe fn switch(prev: *mut Context, next: *const Context) {
        unsafe { context_switch(prev, next) }
    }

    // `prepare_resume` keeps the trait's default no-op: there is no
    // unprivileged level to transition from and every thread runs in the one
    // kernel space. Both arrive with ring 3.
}

impl UserContextOps for ContextSwitch {
    // SAFETY: see the `UserContextOps::init_user` contract — `kstack_top` tops
    // a valid, exclusively-owned kernel stack with room for the frame, and the
    // user entry and stack are mapped user-accessible in the address space
    // that will be active when this thread first runs.
    unsafe fn init_user(
        kstack_top: VirtAddr,
        user_entry: VirtAddr,
        user_stack_top: VirtAddr,
        arg: usize,
    ) -> Context {
        // The same frame a kernel thread gets, differing only in where `lr`
        // points and what `r4`-`r6` carry. A user thread's first switch is an
        // ordinary switch; it is the trampoline that leaves privileged mode.
        let sp = (kstack_top.as_u64() as u32) & !0x7;
        let frame = sp - INIT_FRAME_SLOTS * 4;
        let slots = frame as *mut u32;
        // SAFETY: the caller guarantees `kstack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame.
        unsafe {
            for slot in 0..INIT_FRAME_SLOTS as usize {
                slots.add(slot).write(0);
            }
            slots
                .add(SLOT_LR)
                .write(user_thread_trampoline as *const () as u32);
            slots.add(SLOT_R4).write(user_entry.as_u64() as u32);
            slots.add(SLOT_R5).write(arg as u32);
            slots.add(SLOT_R6).write(user_stack_top.as_u64() as u32);
        }
        Context { sp: frame }
    }
}

// The switch itself. `stmdb`/`ldmia` move the whole callee-saved set in one
// instruction each; `#4` of padding keeps the frame 8-byte aligned.
//
// No barrier is needed: this is a change of stack and registers within one
// mode and one address space. Changing the address space is
// `AddressSpaceOps::activate`'s job and carries its own barriers.
global_asm!(
    r#"
.text
.globl context_switch
context_switch:
    sub     sp, sp, #4
    stmdb   sp!, {{r4-r11, lr}}
    str     sp, [r0]

    ldr     sp, [r1]
    ldmia   sp!, {{r4-r11, lr}}
    add     sp, sp, #4
    bx      lr
"#
);

// First entry into a fresh kernel thread. `init` seeded r4 with the entry
// point and r5 with its argument, so this moves the argument into the first
// parameter register and calls.
//
// Interrupts are unmasked here rather than in `init`, because this is the
// first instant the thread has a coherent stack and register state to take an
// interrupt on — the same reasoning as every other port's trampoline.
//
// `entry` is `-> !`. `udf` guards that contract: if it ever returns, trap
// here rather than branch through whatever `lr` happens to hold.
global_asm!(
    r#"
.text
.globl thread_trampoline
thread_trampoline:
    cpsie   i
    mov     r0, r5
    blx     r4
    udf     #0
"#
);

// First entry into a fresh *user* thread, and the only place in this kernel
// that leaves privileged mode for the first time. `init_user` seeded r4 with
// the user entry point, r5 with its argument and r6 with the user stack.
//
// Two things here have no counterpart on the other ports. The kernel stack
// needs no publishing at all — ARM banks `SP` per mode, so the `svc` that
// brings this thread back into the kernel arrives on whatever `SP_svc` holds,
// and `SP_svc` *is* this thread's kernel stack because the context switch put
// it there. And setting the user's stack pointer is not an assignment but an
// `ldm ... ^`, the only instruction form that reaches the User bank from a
// privileged mode; the `nop` after it is the architecture's banked-register
// hazard, not decoration.
//
// `SPSR` is built as User mode with `I` clear, so a tick can land on user code
// and the IRQ vector handles it. `movs pc, lr` is the return: it copies SPSR
// into CPSR and branches, which is the whole privilege transition.
global_asm!(
    r#"
.text
.globl user_thread_trampoline
user_thread_trampoline:
    mov     r0, #0x10
    msr     spsr_cxsf, r0
    sub     sp, sp, #8
    mov     r1, #0
    str     r6, [sp, #0]
    str     r1, [sp, #4]
    ldm     sp, {{sp, lr}}^
    nop
    add     sp, sp, #8
    mov     r0, r5
    mov     lr, r4
    movs    pc, lr
"#
);
