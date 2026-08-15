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
//! [`UserContextOps`] is implemented here: a user thread's first switch lands
//! on its kernel stack exactly like a kernel thread's, and the trampoline it
//! arrives in is what crosses the privilege boundary. The difference between
//! a kernel thread and a user thread on this port is four CSR writes and an
//! `sret` — the same as on the 64-bit one, at half the register width.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Scheduling"),
//! docs/hardware/01-platform-and-cpu-support.md ("Architecture Porting
//! Layer")
//! Budget: B7 (context switch)

use crate::paging::SATP_MODE_SV32;
use core::arch::{asm, global_asm};
use tessera_karch::{ContextOps, PhysAddr, UserContextOps, VirtAddr};

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
/// Slot index of `s2`, which the *user* trampoline reads as the user stack
/// pointer. Unused by the kernel trampoline.
const SLOT_S2: usize = 3;

// SAFETY: these declare symbols defined by the `global_asm!` blocks below; the
// block only declares them and introduces no unsafe operation.
unsafe extern "C" {
    fn context_switch(prev: *mut Context, next: *const Context);
    fn thread_trampoline() -> !;
    fn user_thread_trampoline() -> !;
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

    // SAFETY: see the `ContextOps::prepare_resume` contract — `space_root`, if
    // present, is a live Sv32 root that maps the kernel above 2 GiB.
    unsafe fn prepare_resume(_kernel_stack_top: VirtAddr, space_root: Option<PhysAddr>) {
        // Only half of this method's job exists on this architecture, and the
        // missing half is missing deliberately.
        //
        // Publishing the kernel stack is what `sscratch` would be for — but
        // writing it here would arm the trap vector's swap slot while the
        // kernel is still running, and a trap taken between here and the
        // actual `sret` would then run on a stack the interrupted kernel code
        // was already using. Every exit to U-mode arms it itself, from the
        // stack it is standing on.
        //
        // Installing the address space is real, and is the whole of Sv32's
        // per-process story: one root, one `satp`, so a switch is a write.
        if let Some(root) = space_root {
            // The root's physical address is 34 bits wide and `satp`'s PPN
            // field is 22 — the shift is what makes them meet, and the space
            // that produced this root was already refused if it sat above the
            // window (`build_kernel_space`).
            let satp = SATP_MODE_SV32 | ((root.as_u64() >> 12) as u32);
            // SAFETY: the caller guarantees `root` roots live tables that map
            // the kernel at its current addresses, so the instruction after
            // this one is still mapped. The `sfence.vma` drops translations
            // cached under the previous root.
            unsafe {
                asm!(
                    "csrw satp, {satp}",
                    "sfence.vma",
                    satp = in(reg) satp,
                    options(nostack, preserves_flags),
                );
            }
        }
    }
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
        // The same frame a kernel thread gets, differing only in where `ra`
        // points and what `s0`-`s2` carry. A user thread's first switch is an
        // ordinary switch; it is the trampoline that leaves S-mode.
        let sp = (kstack_top.as_u64() as u32) & !0xf;
        let frame = sp - INIT_FRAME_SLOTS * 4;
        let slots = frame as *mut u32;
        // SAFETY: the caller guarantees `kstack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame.
        unsafe {
            for slot in 0..INIT_FRAME_SLOTS as usize {
                slots.add(slot).write(0);
            }
            slots
                .add(SLOT_RA)
                .write(user_thread_trampoline as *const () as u32);
            slots.add(SLOT_S0).write(user_entry.as_u64() as u32);
            slots.add(SLOT_S1).write(arg as u32);
            slots.add(SLOT_S2).write(user_stack_top.as_u64() as u32);
        }
        Context { sp: frame }
    }
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

// First entry into a fresh *user* thread, and the only place in the kernel
// that leaves S-mode for the first time. `init_user` seeded s0 with the user
// entry point, s1 with its argument and s2 with the user stack pointer.
//
// `sscratch` is armed from `sp` rather than from a seeded value, and this is
// the instant that makes the trap vector's invariant hold: at trampoline entry
// `context_switch` has just popped its frame, so `sp` *is* this thread's
// kernel stack top — the stack the next trap from this thread must land on.
//
// The status bits: SPP = 0 so `sret` drops to U-mode; SPIE = 0 so the S-mode
// interrupt enable is clear on the way back in (it masks nothing in U-mode,
// where the architecture enables supervisor interrupts unconditionally at a
// lower privilege level). SUM is deliberately not touched here — it is the
// kernel's own permission to follow a validated user pointer, not this
// thread's.
global_asm!(
    r#"
.text
.global user_thread_trampoline
user_thread_trampoline:
    csrw    sscratch, sp
    csrw    sepc, s0
    li      t0, 0x100
    csrc    sstatus, t0
    li      t0, 0x20
    csrc    sstatus, t0
    mv      a0, s1
    mv      sp, s2
    sret
"#
);
