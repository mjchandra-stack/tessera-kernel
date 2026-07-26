// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! x86-64 kernel-thread context switch: save the callee-saved registers and
//! stack pointer of the outgoing thread, restore the incoming thread's, and
//! resume it. `switch` is symmetric — it works both to hand off to a running
//! thread and, via [`init`](ContextOps::init), to start a fresh one — so IPC
//! synchronous handoff (docs/kernel/04) can later reuse the same primitive
//! by switching to a specific thread rather than through a run queue.
//!
//! Only the System V callee-saved set (RBX, RBP, R12–R15) plus RSP is saved;
//! the caller-saved registers are spilled by the compiler around the call,
//! as for any function. Kernel threads share the kernel address space this
//! milestone, so no CR3 change is part of the switch.
//!
//! Normative: docs/kernel/01-kernel-model.md ("Architecture Layer"),
//! docs/kernel/04-synchronization-and-ipc-guarantees.md ("Synchronous Call
//! Scheduling")
//! Budget: B7 (context switch) — `switch`; unmeasured until the perf rig
//! lands (build/README.md, deviation D9).

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
    rsp: u64,
}

impl Context {
    /// An empty context (null stack pointer). Valid only as a `switch`
    /// *source* — the running code saves its real state here on first switch.
    pub const fn zeroed() -> Self {
        Self { rsp: 0 }
    }
}

/// The context-switch operations for x86-64.
pub struct ContextSwitch;

/// How many 8-byte slots [`ContextOps::init`] lays on a new stack: the six
/// callee-saved registers `context_switch` pops, plus the return address it
/// `ret`s into.
const INIT_FRAME_SLOTS: u64 = 7;

impl ContextOps for ContextSwitch {
    type Context = Context;

    fn empty() -> Context {
        Context::zeroed()
    }

    // SAFETY: see the `ContextOps::init` contract — `stack_top` must top a
    // valid, mapped, exclusively-owned kernel stack with room for the frame.
    unsafe fn init(stack_top: VirtAddr, entry: extern "C" fn(usize) -> !, arg: usize) -> Context {
        // Lay down the frame `context_switch` expects to pop when it first
        // resumes this context: six callee-saved slots then a return address.
        // `context_switch` pops R15,R14,R13,R12,RBX,RBP (lowest address
        // first) and `ret`s, so R15 carries `entry` and R14 carries `arg`
        // into `thread_trampoline`. With a 16-aligned `stack_top`, placing
        // the 7-slot frame just below it lands the trampoline's `call` on a
        // 16-aligned stack, as the System V ABI requires.
        let sp = stack_top.as_u64() & !0xf;
        let frame = sp - INIT_FRAME_SLOTS * 8;
        let slots = frame as *mut u64;
        // SAFETY: the caller guarantees `stack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame, so
        // these seven in-bounds writes are valid.
        unsafe {
            slots.add(0).write(entry as usize as u64); // R15 <- entry
            slots.add(1).write(arg as u64); // R14 <- arg
            slots.add(2).write(0); // R13
            slots.add(3).write(0); // R12
            slots.add(4).write(0); // RBX
            slots.add(5).write(0); // RBP
            slots.add(6).write(thread_trampoline_addr()); // return address
        }
        Context { rsp: frame }
    }

    // SAFETY: see the `ContextOps::switch` contract — both pointers reference
    // valid `Context` storage owned by the caller, and `*next` was produced by
    // `init` or a prior `switch`, so its stack holds a matching frame.
    unsafe fn switch(prev: *mut Context, next: *const Context) {
        // SAFETY: the caller guarantees both pointers reference valid
        // `Context` storage and that `*next` was produced by `init` or a
        // prior `switch`; `context_switch` swaps stacks and returns only when
        // something later switches back into `*prev`.
        unsafe { context_switch(prev, next) }
    }

    // SAFETY: see the `ContextOps::prepare_resume` contract — `kernel_rsp` tops
    // the resuming thread's kernel stack; `space_root`, if `Some`, is a live
    // page-table root mapping the kernel.
    unsafe fn prepare_resume(kernel_rsp: VirtAddr, space_root: Option<PhysAddr>) {
        // The kernel stack the CPU loads on a ring-3→ring-0 transition: TSS.RSP0
        // for interrupts/exceptions, and gs:[kernel_rsp] for the SYSCALL stub.
        crate::gdt::set_kernel_stack(kernel_rsp.as_u64());
        crate::percpu::set_kernel_rsp(kernel_rsp.as_u64());
        if let Some(root) = space_root {
            let current = crate::cpu::read_cr3() & 0x000f_ffff_ffff_f000;
            if current != root.as_u64() {
                // SAFETY: `root` is a live top-level page table that maps the
                // kernel (prepare_resume contract), so loading it as CR3 leaves
                // all kernel code/stacks addressable while switching the
                // low-half user mappings; it flushes non-global TLB entries.
                unsafe {
                    asm!("mov cr3, {}", in(reg) root.as_u64(), options(nostack, preserves_flags));
                }
            }
        }
    }
}

impl UserContextOps for ContextSwitch {
    // SAFETY: see the `UserContextOps::init_user` contract — `kstack_top` tops a
    // valid kernel stack; `user_entry`/`user_stack_top` are valid user mappings
    // in the address space that will be active when this thread first runs.
    unsafe fn init_user(
        kstack_top: VirtAddr,
        user_entry: VirtAddr,
        user_stack_top: VirtAddr,
        arg: usize,
    ) -> Context {
        // Same frame `context_switch` pops, but the return address is the user
        // trampoline, which reads R15=user RIP, R14=user RSP, R13=arg and drops
        // to ring 3 via `enter_user`. The first switch runs entirely on the
        // kernel stack until `enter_user`'s `iretq`.
        let sp = kstack_top.as_u64() & !0xf;
        let frame = sp - INIT_FRAME_SLOTS * 8;
        let slots = frame as *mut u64;
        // SAFETY: the caller guarantees `kstack_top` tops a valid, mapped,
        // exclusively-owned kernel stack with room for this initial frame, so
        // these seven in-bounds writes are valid.
        unsafe {
            slots.add(0).write(user_entry.as_u64()); // R15 <- user RIP
            slots.add(1).write(user_stack_top.as_u64()); // R14 <- user RSP
            slots.add(2).write(arg as u64); // R13 <- arg
            slots.add(3).write(0); // R12
            slots.add(4).write(0); // RBX
            slots.add(5).write(0); // RBP
            slots.add(6).write(user_thread_trampoline_addr()); // return address
        }
        Context { rsp: frame }
    }

    // SAFETY: see the `ContextOps::switch` contract — both pointers valid,
    // `*next` produced by `init` or a prior `switch`.
}

/// Address of the user-thread trampoline, as a `u64` for the return slot.
fn user_thread_trampoline_addr() -> u64 {
    // SAFETY: `user_thread_trampoline` is defined by the `global_asm!` block
    // below; taking its address performs no unsafe operation.
    (user_thread_trampoline as *const ()) as u64
}

/// Address of the assembly thread trampoline, as a `u64` for the return slot.
fn thread_trampoline_addr() -> u64 {
    // SAFETY: `thread_trampoline` is defined by the `global_asm!` block below;
    // taking its address performs no unsafe operation.
    (thread_trampoline as *const ()) as u64
}

// SAFETY: these declare symbols defined by the `global_asm!` block below; the
// extern block only names them and introduces no unsafe operation.
unsafe extern "C" {
    /// Swaps callee-saved state and the stack pointer from `*prev` to `*next`.
    fn context_switch(prev: *mut Context, next: *const Context);
    /// Entry stub for a freshly started thread (never called directly).
    fn thread_trampoline();
    /// Entry stub for a freshly started user thread (never called directly).
    fn user_thread_trampoline();
}

// `context_switch(prev=rdi, next=rsi)`: save the callee-saved set and RSP into
// `*prev` (RSP at offset 0), load `*next`'s, and resume it. `thread_trampoline`
// is where a new thread begins: `init` seeds R15=entry, R14=arg, so it calls
// `entry(arg)` on a 16-aligned stack. `sti` first, because a thread first
// resumed from within the timer interrupt would otherwise start with
// interrupts masked and never be preempted; a thread resumed from a prior
// preemption instead restores its flags through `iretq`. `entry` is `-> !`;
// `ud2` guards the contract that it never returns.
global_asm!(
    r#"
.text
.global context_switch
context_switch:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, [rsi]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.global thread_trampoline
thread_trampoline:
    sti
    mov rdi, r14
    call r15
    ud2
"#
);

// `user_thread_trampoline` begins a fresh *user* thread: `init_user` seeds
// R15=user RIP, R14=user RSP, R13=arg, so it forwards them to `enter_user`
// (rdi=rip, rsi=rsp, rdx=arg), which drops to ring 3 and never returns. No
// `sti`: this milestone runs no device interrupts in ring 3 (init_syscall's
// SFMASK also masks IF on any later syscall entry).
global_asm!(
    r#"
.text
.global user_thread_trampoline
user_thread_trampoline:
    mov rdi, r15
    mov rsi, r14
    mov rdx, r13
    jmp {enter_user}
"#,
    enter_user = sym crate::syscall::enter_user,
);
