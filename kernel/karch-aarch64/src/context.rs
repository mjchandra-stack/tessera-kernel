// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! AArch64 kernel-thread context switching: the callee-saved register set and
//! the stack pointer, saved into and restored from a thread's own kernel
//! stack. The counterpart of `karch-x86_64/src/context.rs`, and shaped the
//! same way — a `Context` that is only a stack pointer, with the real state
//! parked on the stack that pointer names.
//!
//! What the architecture changes:
//!
//! * **The return address is a register, not a stack slot.** x86-64's `ret`
//!   consumes a pushed address, so its `init` writes the entry trampoline
//!   into the frame's last slot. AArch64 returns through `x30`, so `x30` is
//!   part of the saved set and `init` seeds it directly.
//! * **The callee-saved set is larger**: `x19`-`x28` plus the frame pointer
//!   `x29` and link register `x30` (AAPCS64), against x86-64's six.
//! * **The stack must stay 16-byte aligned** at every point where an
//!   exception can be taken, not merely at call boundaries, because
//!   `SP_EL1` alignment is checked on exception entry.
//!
//! Floating-point and SIMD state is deliberately absent: the kernel is built
//! for `aarch64-unknown-none-softfloat` and emits none, and EL1 access to it
//! is left trapping, so there is no FP state a switch could fail to preserve.
//! That stops being true the moment EL0 threads exist, and saving `Q0`-`Q31`
//! lands with them rather than being carried as untested dead weight now.
//!
//! [`UserContextOps::init_user`](tessera_karch::UserContextOps::init_user)
//! builds a context whose trampoline `eret`s to EL0 — the ring-3 entry the
//! trait split (M27) held open for. FP/SIMD is still not saved: EL0 access to
//! it is trapping like EL1's, so a user thread that touches FP faults rather
//! than silently corrupting unsaved state.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Scheduling"),
//! docs/hardware/01-platform-and-cpu-support.md ("Architecture Porting
//! Layer")
//! Budget: B7 (context switch)

use core::arch::{asm, global_asm};
use tessera_karch::{ContextOps, PhysAddr, UserContextOps, VirtAddr};

/// Saved execution context: just the stack pointer. Everything else lives on
/// that stack, pushed by [`context_switch`] and, for a new thread, laid down
/// by [`ContextOps::init`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context {
    /// Saved kernel stack pointer. `#[repr(C)]` fixes this at offset 0, which
    /// the assembly relies on.
    sp: u64,
}

impl Context {
    /// An empty context (null stack pointer). Valid only as a `switch`
    /// *source* — the running code saves its real state here on first switch.
    pub const fn zeroed() -> Self {
        Self { sp: 0 }
    }
}

/// The context-switch operations for AArch64.
pub struct ContextSwitch;

/// 8-byte slots [`ContextOps::init`] lays on a new stack: `x19`-`x28`, then
/// `x29` and `x30`. Twelve is already even, so a 16-aligned `stack_top`
/// leaves the frame 16-aligned too.
const INIT_FRAME_SLOTS: u64 = 12;

/// Slot index of `x30` (the link register) within that frame — the address
/// `context_switch` returns into, and therefore where `init` puts the
/// trampoline.
const SLOT_X30: usize = 11;
/// Slot index of `x19`, which the trampoline reads as the entry point.
const SLOT_X19: usize = 0;
/// Slot index of `x20`, which the trampoline reads as the entry argument.
const SLOT_X20: usize = 1;
/// Slot index of `x21`, which the user trampoline reads as the entry argument
/// (the kernel trampoline needs only two carried registers; the user one needs
/// three — user entry, user stack, and arg).
const SLOT_X21: usize = 2;

// SAFETY: these declare symbols defined by the `global_asm!` blocks below;
// the block only declares them and introduces no unsafe operation.
unsafe extern "C" {
    fn context_switch(prev: *mut Context, next: *const Context);
    fn thread_trampoline() -> !;
    fn user_thread_trampoline() -> !;
}

/// Address of the assembly thread trampoline, as a `u64` for the `x30` slot.
fn thread_trampoline_addr() -> u64 {
    // Taking a function item's address performs no unsafe operation.
    (thread_trampoline as *const ()) as u64
}

/// Address of the user-thread trampoline, as a `u64` for the `x30` slot.
fn user_thread_trampoline_addr() -> u64 {
    (user_thread_trampoline as *const ()) as u64
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
        // resumes this context. It restores x19-x28, x29, x30 from ascending
        // addresses and then `ret`s through x30, so seeding x30 with the
        // trampoline is what makes the first switch *arrive* somewhere, and
        // x19/x20 carry the entry point and its argument into it.
        let sp = stack_top.as_u64() & !0xf;
        let frame = sp - INIT_FRAME_SLOTS * 8;
        let slots = frame as *mut u64;
        // SAFETY: the caller guarantees `stack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame, so
        // these twelve in-bounds writes are valid.
        unsafe {
            for slot in 0..INIT_FRAME_SLOTS as usize {
                slots.add(slot).write(0);
            }
            slots.add(SLOT_X19).write(entry as usize as u64);
            slots.add(SLOT_X20).write(arg as u64);
            slots.add(SLOT_X30).write(thread_trampoline_addr());
        }
        Context { sp: frame }
    }

    // SAFETY: see the `ContextOps::switch` contract — both pointers reference
    // valid `Context` storage owned by the caller, and `*next` was produced
    // by `init` or a prior `switch`, so its stack holds a matching frame.
    unsafe fn switch(prev: *mut Context, next: *const Context) {
        unsafe { context_switch(prev, next) }
    }

    // The scheduler calls this before switching to a thread. Unlike x86-64,
    // which must reprogram `TSS.RSP0` because the ring-3→ring-0 transition
    // reloads the stack pointer from a fixed slot, AArch64 keeps `SP_EL1` across
    // the EL0→EL1 transition, and the register switch already leaves it at the
    // thread's kernel stack — so the only work here is to install the thread's
    // address space. `space_root` is `None` for a kernel thread (no change).
    //
    // SAFETY: see the `ContextOps::prepare_resume` contract — `space_root`,
    // when `Some`, is the resuming thread's live page-table root.
    unsafe fn prepare_resume(_kernel_stack_top: VirtAddr, space_root: Option<PhysAddr>) {
        if let Some(root) = space_root {
            // SAFETY: `root` is the resuming user thread's live `TTBR0` root.
            // The sequence is the architecturally required base-register-change
            // bracket: `dsb ish` retires table writes before the walker sees the
            // new root, the invalidate drops stale translations, and `isb` keeps
            // later instructions from having been fetched under the old regime.
            // A full flush (not per-ASID) because `space_root` carries no ASID.
            unsafe {
                asm!(
                    "dsb ish",
                    "msr ttbr0_el1, {root}",
                    "isb",
                    "tlbi vmalle1",
                    "dsb nsh",
                    "isb",
                    root = in(reg) root.as_u64(),
                    options(nostack, preserves_flags),
                );
            }
        }
    }
}

impl UserContextOps for ContextSwitch {
    // SAFETY: see the `UserContextOps::init_user` contract — `kstack_top` tops a
    // valid, exclusively-owned kernel stack; `user_entry`/`user_stack_top` are
    // valid, EL0-accessible mappings in the address space active when this
    // thread first runs.
    unsafe fn init_user(
        kstack_top: VirtAddr,
        user_entry: VirtAddr,
        user_stack_top: VirtAddr,
        arg: usize,
    ) -> Context {
        // The same frame `context_switch` pops, but x30 returns into the *user*
        // trampoline, which reads x19=user entry, x20=user stack, x21=arg and
        // `eret`s to EL0. The first switch runs on the kernel stack until that
        // `eret`.
        let sp = kstack_top.as_u64() & !0xf;
        let frame = sp - INIT_FRAME_SLOTS * 8;
        let slots = frame as *mut u64;
        // SAFETY: the caller guarantees `kstack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame.
        unsafe {
            for slot in 0..INIT_FRAME_SLOTS as usize {
                slots.add(slot).write(0);
            }
            slots.add(SLOT_X19).write(user_entry.as_u64());
            slots.add(SLOT_X20).write(user_stack_top.as_u64());
            slots.add(SLOT_X21).write(arg as u64);
            slots.add(SLOT_X30).write(user_thread_trampoline_addr());
        }
        Context { sp: frame }
    }
}

// The switch itself. `stp`/`ldp` move the callee-saved set in pairs, which is
// both the idiomatic encoding and half the instruction count of individual
// stores.
//
// The stack pointer cannot be named directly by `str`/`ldr`, hence the moves
// through x9: `mov x9, sp` then store, and the reverse on the way in. Storing
// to `[x0]` and loading from `[x1]` matches `Context`'s single field at
// offset 0, which `#[repr(C)]` guarantees.
//
// No barrier is needed around the switch: this is a change of stack and
// registers within one exception level and one address space. Changing the
// *address space* is `AddressSpaceOps::activate`'s job and carries its own
// `dsb`/`isb`.
global_asm!(
    r#"
.text
.global context_switch
context_switch:
    stp     x19, x20, [sp, #-96]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    mov     x9, sp
    str     x9, [x0]

    ldr     x9, [x1]
    mov     sp, x9
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    ldp     x19, x20, [sp], #96
    ret
"#
);

// First entry into a fresh kernel thread. `init` seeded x19 with the entry
// point and x20 with its argument, so this moves the argument into the first
// parameter register and calls.
//
// Interrupts are unmasked here rather than in `init`, because this is the
// first instant the thread has a coherent stack and register state to take an
// interrupt on — the same reasoning as the x86-64 trampoline's `sti`.
//
// `entry` is `-> !`. `brk #0` guards that contract: if it ever returns, stop
// here rather than `ret` through whatever x30 happens to hold.
global_asm!(
    r#"
.text
.global thread_trampoline
thread_trampoline:
    msr     daifclr, #2
    mov     x0, x20
    blr     x19
    brk     #0
"#
);

// First entry into a fresh *user* (EL0) thread. `init_user` seeded x19=user
// entry point, x20=user stack top, x21=arg. This programs the exception-return
// state and drops to EL0: `ELR_EL1` is where EL0 resumes, `SP_EL0` is its
// stack, `SPSR_EL1` selects EL0t (`M[3:0]=0`) with D/A/F masked and **IRQ
// unmasked** (`0x340`) — device interrupts must be takeable while EL0 runs or
// a driver parked on its interrupt port is never woken (D84; every earlier
// EL0 program was pure-cooperative and ran fully masked, `0x3c0`). Taking an
// IRQ at EL0 is transparent to the interrupted thread: the handler wakes
// waiters by queueing them Ready (no handoff), so cooperative interleavings
// are preserved. x0 carries the argument.
//
// `eret` never returns; if it somehow did, `brk #0` stops rather than run on.
global_asm!(
    r#"
.text
.global user_thread_trampoline
user_thread_trampoline:
    msr     sp_el0, x20
    msr     elr_el1, x19
    mov     x9, #0x340
    msr     spsr_el1, x9
    mov     x0, x21
    eret
    brk     #0
"#
);
