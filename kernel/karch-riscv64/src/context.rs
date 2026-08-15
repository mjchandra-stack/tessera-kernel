// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! RISC-V kernel-thread context switching: the callee-saved register set and
//! the stack pointer, saved into and restored from a thread's own kernel
//! stack. Shaped like both siblings — a `Context` that is only a stack
//! pointer, with the real state parked on the stack that pointer names.
//!
//! What the architecture changes:
//!
//! * **The return address is a register**, `ra`, as on AArch64 and unlike
//!   x86-64 where `ret` consumes a pushed address. So `ra` is part of the
//!   saved set and [`ContextOps::init`] seeds it directly.
//! * **The callee-saved set is `s0`-`s11` plus `ra`** — thirteen registers,
//!   an odd count, so the frame carries one slot of padding to keep the stack
//!   16-byte aligned as the ABI requires.
//! * **There is no equivalent of `SP_EL0`.** RISC-V swaps privilege stacks
//!   through `sscratch`, an explicit CSR the trap path owns, so nothing here
//!   has to preserve a second stack pointer. That is not merely a different
//!   spelling of the AArch64 arrangement whose unswitched `SP_EL0` cost that
//!   port a milestone (D81): `sscratch` is **derived** at every exit to
//!   U-mode from the stack pointer the exiting code is standing on — see
//!   [`user_thread_trampoline`] below and the trap vector's return path — so
//!   there is no instant at which a stale value is readable and nothing for
//!   the switch to carry. The general rule that per-thread hardware state
//!   must be switched is unchanged; this particular register escapes it by
//!   never being state that outlives a transition.
//!
//! Floating-point state is deliberately absent: `sstatus.FS` is left at
//! `Off`, so any FP instruction traps as illegal rather than silently
//! corrupting state no switch preserves. The kernel emits none.
//!
//! [`UserContextOps`] is implemented here: a user thread's first switch lands
//! on its kernel stack exactly like a kernel thread's, and the trampoline it
//! arrives in is what crosses the privilege boundary. The two trampolines are
//! deliberately the same shape — the difference between a kernel thread and a
//! user thread on this port is four CSR writes and an `sret`.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Scheduling"),
//! docs/hardware/01-platform-and-cpu-support.md ("Architecture Porting
//! Layer")
//! Budget: B7 (context switch)

use crate::paging::SATP_MODE_SV39;
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

/// The context-switch operations for RISC-V 64.
pub struct ContextSwitch;

/// 8-byte slots [`ContextOps::init`] lays on a new stack: `ra`, `s0`-`s11`,
/// and one pad slot so the frame is a multiple of 16 bytes.
const INIT_FRAME_SLOTS: u64 = 14;

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

// SAFETY: these declare symbols defined by the `global_asm!` blocks below;
// the block only declares them and introduces no unsafe operation.
unsafe extern "C" {
    fn context_switch(prev: *mut Context, next: *const Context);
    fn thread_trampoline() -> !;
    fn user_thread_trampoline() -> !;
}

/// Address of the assembly thread trampoline, as a `u64` for the `ra` slot.
fn thread_trampoline_addr() -> u64 {
    // Taking a function item's address performs no unsafe operation.
    (thread_trampoline as *const ()) as u64
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
        // resumes this context. It restores ra and s0-s11 from ascending
        // addresses and then `ret`s through ra, so seeding ra with the
        // trampoline is what makes the first switch *arrive* somewhere, and
        // s0/s1 carry the entry point and its argument into it.
        let sp = stack_top.as_u64() & !0xf;
        let frame = sp - INIT_FRAME_SLOTS * 8;
        let slots = frame as *mut u64;
        // SAFETY: the caller guarantees `stack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame, so
        // these fourteen in-bounds writes are valid.
        unsafe {
            for slot in 0..INIT_FRAME_SLOTS as usize {
                slots.add(slot).write(0);
            }
            slots.add(SLOT_RA).write(thread_trampoline_addr());
            slots.add(SLOT_S0).write(entry as usize as u64);
            slots.add(SLOT_S1).write(arg as u64);
        }
        Context { sp: frame }
    }

    // SAFETY: see the `ContextOps::switch` contract — both pointers reference
    // valid `Context` storage owned by the caller, and `*next` was produced
    // by `init` or a prior `switch`, so its stack holds a matching frame.
    unsafe fn switch(prev: *mut Context, next: *const Context) {
        unsafe { context_switch(prev, next) }
    }

    // SAFETY: see the `ContextOps::prepare_resume` contract — `space_root`, if
    // present, is a live Sv39 root that maps the kernel in its upper half.
    unsafe fn prepare_resume(_kernel_stack_top: VirtAddr, space_root: Option<PhysAddr>) {
        // Only half of this trait method's job exists on this architecture,
        // and the missing half is missing for a reason worth stating.
        //
        // Publishing the kernel stack is what `sscratch` would be for — but
        // writing it here would be *wrong*, not merely unnecessary: it would
        // arm the swap slot while the kernel is still running, and the trap
        // vector reads a non-zero `sscratch` as "U-mode was interrupted" and
        // swaps stacks accordingly. A trap taken between here and the actual
        // `sret` would then run on a stack the interrupted kernel code was
        // already using. The exits to U-mode arm it themselves, from the stack
        // they are standing on, which is both correct and unconditional.
        //
        // Installing the address space is real, and is the whole of Sv39's
        // per-process story: one root, one `satp`, so a switch is a write.
        if let Some(root) = space_root {
            let satp = SATP_MODE_SV39 | (root.as_u64() >> 12);
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
        let sp = kstack_top.as_u64() & !0xf;
        let frame = sp - INIT_FRAME_SLOTS * 8;
        let slots = frame as *mut u64;
        // SAFETY: the caller guarantees `kstack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame.
        unsafe {
            for slot in 0..INIT_FRAME_SLOTS as usize {
                slots.add(slot).write(0);
            }
            slots
                .add(SLOT_RA)
                .write(user_thread_trampoline as *const () as u64);
            slots.add(SLOT_S0).write(user_entry.as_u64());
            slots.add(SLOT_S1).write(arg as u64);
            slots.add(SLOT_S2).write(user_stack_top.as_u64());
        }
        Context { sp: frame }
    }
}

// The switch itself. Storing to `0(a0)` and loading from `0(a1)` matches
// `Context`'s single field at offset 0, which `#[repr(C)]` guarantees.
//
// No fence is needed around the switch: this is a change of stack and
// registers within one privilege level and one address space. Changing the
// *address space* is `AddressSpaceOps::activate`'s job and carries its own
// `sfence.vma`.
global_asm!(
    r#"
.text
.global context_switch
context_switch:
    addi    sp, sp, -112
    sd      ra,  0(sp)
    sd      s0,  8(sp)
    sd      s1,  16(sp)
    sd      s2,  24(sp)
    sd      s3,  32(sp)
    sd      s4,  40(sp)
    sd      s5,  48(sp)
    sd      s6,  56(sp)
    sd      s7,  64(sp)
    sd      s8,  72(sp)
    sd      s9,  80(sp)
    sd      s10, 88(sp)
    sd      s11, 96(sp)
    sd      sp,  0(a0)

    ld      sp,  0(a1)
    ld      ra,  0(sp)
    ld      s0,  8(sp)
    ld      s1,  16(sp)
    ld      s2,  24(sp)
    ld      s3,  32(sp)
    ld      s4,  40(sp)
    ld      s5,  48(sp)
    ld      s6,  56(sp)
    ld      s7,  64(sp)
    ld      s8,  72(sp)
    ld      s9,  80(sp)
    ld      s10, 88(sp)
    ld      s11, 96(sp)
    addi    sp, sp, 112
    ret
"#
);

// First entry into a fresh kernel thread. `init` seeded s0 with the entry
// point and s1 with its argument, so this moves the argument into the first
// parameter register and calls.
//
// Interrupts are unmasked here rather than in `init`, because this is the
// first instant the thread has a coherent stack and register state to take an
// interrupt on — the same reasoning as the x86-64 trampoline's `sti` and the
// AArch64 one's `daifclr`.
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
// The status bits, in the order they matter:
//   SPP  = 0  so `sret` drops to U-mode rather than returning to S-mode;
//   SPIE = 0  so the S-mode interrupt enable is left clear on the way back in.
//             It does not mask anything in U-mode — the architecture enables
//             supervisor interrupts unconditionally at a lower privilege level
//             — so a tick can and does land on user code, and the vector
//             handles it. What it governs is the state the kernel resumes in.
//   SUM   is deliberately *not* set: the kernel cannot dereference a user
//             pointer, and any attempt faults instead of quietly working.
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
