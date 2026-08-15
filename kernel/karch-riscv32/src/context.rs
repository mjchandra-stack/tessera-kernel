// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! RISC-V 32 kernel-thread context switching. The 64-bit port's context
//! module at half the register width: `sw`/`lw` instead of `sd`/`ld`, 4-byte
//! slots, and a `Context` that is still only a stack pointer with the real
//! state parked on the stack it names.
//!
//! The callee-saved set is unchanged — `ra` plus `s0`-`s11`, thirteen
//! registers — and the stack must still be 16-byte aligned, so the frame
//! carries three slots of padding here rather than one. Getting that wrong
//! is not a compile error and not an immediate fault; it surfaces later as a
//! misaligned trap frame, which is why the slot count is a named constant
//! rather than a literal in the assembly's offsets.
//!
//! [`UserContextOps`](tessera_karch::UserContextOps) is **not** implemented.
//! This port has no unprivileged level yet, and the trait split exists exactly
//! so that absence is a compile error at the call site rather than a stub.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Scheduling"),
//! docs/hardware/01-platform-and-cpu-support.md ("Architecture Porting
//! Layer")
//! Budget: B7 (context switch)

use core::arch::global_asm;
use tessera_karch::{ContextOps, VirtAddr};

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

/// The context-switch operations for RISC-V 32.
pub struct ContextSwitch;

/// 4-byte slots [`ContextOps::init`] lays on a new stack: `ra`, `s0`-`s11`,
/// and three pad slots so the frame is a multiple of 16 bytes.
const INIT_FRAME_SLOTS: u32 = 16;

/// Slot index of `ra` — the address `context_switch` returns into, and
/// therefore where `init` puts the trampoline.
const SLOT_RA: usize = 0;
/// Slot index of `s0`, which the trampoline reads as the entry point.
const SLOT_S0: usize = 1;
/// Slot index of `s1`, which the trampoline reads as the entry argument.
const SLOT_S1: usize = 2;

// SAFETY: these declare symbols defined by the `global_asm!` blocks below; the
// block only declares them and introduces no unsafe operation.
unsafe extern "C" {
    fn context_switch(prev: *mut Context, next: *const Context);
    fn thread_trampoline() -> !;
}

/// Address of the assembly thread trampoline, as a `u32` for the `ra` slot.
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
        // resumes this context: it restores ra and s0-s11 from ascending
        // addresses and then `ret`s through ra, so seeding ra with the
        // trampoline is what makes the first switch *arrive* somewhere, and
        // s0/s1 carry the entry point and its argument into it.
        //
        // `stack_top` is a 64-bit `VirtAddr` because the porting layer's
        // address type is one width everywhere; on this target it must fit a
        // pointer, and the truncating cast is guarded by the mask below only
        // for alignment, so the caller's contract ("a valid mapped stack") is
        // what makes the narrowing sound.
        let sp = (stack_top.as_u64() as u32) & !0xf;
        let frame = sp - INIT_FRAME_SLOTS * 4;
        let slots = frame as *mut u32;
        // SAFETY: the caller guarantees `stack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame, so
        // these sixteen in-bounds writes are valid.
        unsafe {
            for slot in 0..INIT_FRAME_SLOTS as usize {
                slots.add(slot).write(0);
            }
            slots.add(SLOT_RA).write(thread_trampoline_addr());
            slots.add(SLOT_S0).write(entry as usize as u32);
            slots.add(SLOT_S1).write(arg as u32);
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

// The switch itself. Storing to `0(a0)` and loading from `0(a1)` matches
// `Context`'s single field at offset 0, which `#[repr(C)]` guarantees.
//
// 64 bytes: thirteen saved registers at 0..52, then padding to a 16-byte
// multiple. The padding is what `INIT_FRAME_SLOTS` counts.
global_asm!(
    r#"
.text
.global context_switch
context_switch:
    addi    sp, sp, -64
    sw      ra,  0(sp)
    sw      s0,  4(sp)
    sw      s1,  8(sp)
    sw      s2,  12(sp)
    sw      s3,  16(sp)
    sw      s4,  20(sp)
    sw      s5,  24(sp)
    sw      s6,  28(sp)
    sw      s7,  32(sp)
    sw      s8,  36(sp)
    sw      s9,  40(sp)
    sw      s10, 44(sp)
    sw      s11, 48(sp)
    sw      sp,  0(a0)

    lw      sp,  0(a1)
    lw      ra,  0(sp)
    lw      s0,  4(sp)
    lw      s1,  8(sp)
    lw      s2,  12(sp)
    lw      s3,  16(sp)
    lw      s4,  20(sp)
    lw      s5,  24(sp)
    lw      s6,  28(sp)
    lw      s7,  32(sp)
    lw      s8,  36(sp)
    lw      s9,  40(sp)
    lw      s10, 44(sp)
    lw      s11, 48(sp)
    addi    sp, sp, 64
    ret
"#
);

// First entry into a fresh kernel thread. `init` seeded s0 with the entry
// point and s1 with its argument, so this moves the argument into the first
// parameter register and calls.
//
// Interrupts are unmasked here rather than in `init`, because this is the
// first instant the thread has a coherent stack and register state to take an
// interrupt on.
//
// `entry` is `-> !`. `unimp` guards that contract: if it ever returns, trap
// here rather than `ret` through whatever `ra` happens to hold.
global_asm!(
    r#"
.text
.global thread_trampoline
thread_trampoline:
    csrsi   sstatus, 2
    mv      a0, s1
    jalr    s0
    unimp
"#
);
