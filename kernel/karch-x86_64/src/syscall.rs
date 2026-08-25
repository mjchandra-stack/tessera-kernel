// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The SYSCALL/SYSRET user↔kernel boundary and the first ring-3 entry.
//!
//! SYSCALL does not switch stacks or CR3: the entry stub `swapgs`es to the
//! kernel per-CPU block, loads this thread's kernel stack from
//! `gs:[kernel_rsp]`, builds a [`SyscallFrame`] from the argument registers,
//! and calls the registered Rust dispatch. On return it restores the user
//! RIP/RFLAGS/RSP — all three saved on that kernel stack, so a syscall that
//! blocks and resumes cannot pick up another thread's — and `sysretq`s back to
//! ring 3. `enter_user` performs the *first* transition into a fresh ring-3
//! thread with an `iretq` frame.
//!
//! Register ABI (this port's design; the docs leave the encoding to the
//! architecture layer, docs/kernel/01 "Architecture Layer"): `rax` = syscall
//! number in / result out; arguments in `rdi, rsi, rdx, r10, r8, r9` (`r10`
//! stands in for `rcx`, which SYSCALL overwrites with the return RIP).
//!
//! **What ring 3 gets back.** `rax` holds the result. The six argument
//! registers hold what the caller passed — the exit path pops the frame it
//! built rather than discarding it. `rcx` and `r11` hold the return RIP and
//! RFLAGS, because the instruction pair defines them that way. Everything else
//! is untouched: the callee-saved set survives the `extern "C"` dispatch, and
//! this target is soft-float, so there is no vector state to leak or restore.
//! No register reaches ring 3 holding a kernel value.
//!
//! Normative: docs/api/01-system-call-interface.md ("ABI Rules"),
//! docs/kernel/01-kernel-model.md ("Architecture Layer")
//! Budget: B1 (null syscall) — the entry/exit path; unmeasured until the perf
//! rig lands (build/README.md, D26)

use core::sync::atomic::{AtomicBool, Ordering};

use crate::cpu;
use crate::gdt::{
    KERNEL_CODE_SELECTOR, SYSRET_SELECTOR_BASE, USER_CODE_SELECTOR, USER_DATA_SELECTOR,
};
use crate::percpu::{KERNEL_RSP_OFFSET, USER_RSP_SCRATCH_OFFSET};
use core::arch::{asm, global_asm};

const IA32_EFER: u32 = 0xc000_0080;
const IA32_STAR: u32 = 0xc000_0081;
const IA32_LSTAR: u32 = 0xc000_0082;
const IA32_FMASK: u32 = 0xc000_0084;
/// EFER.SCE — enables SYSCALL/SYSRET.
const EFER_SCE: u64 = 1;
/// RFLAGS bits cleared on SYSCALL entry: TF (8), IF (9), DF (10) — the handler
/// runs with interrupts masked and a known direction flag.
const SYSCALL_FLAG_MASK: u64 = (1 << 8) | (1 << 9) | (1 << 10);
/// Initial ring-3 RFLAGS: reserved bit 1 set, IF clear by default — most demos
/// run no device interrupts in ring 3. A driver host opts into IF-set entry via
/// [`USER_IF_ON_ENTRY`] so it can receive its device interrupt.
const USER_RFLAGS: u64 = 0x2;
/// RFLAGS IF (interrupt enable), bit 9.
const RFLAGS_IF: u64 = 1 << 9;

/// When set, [`enter_user`] starts a ring-3 thread with IF set, so a driver host
/// can take its device interrupt in ring 3. Gated rather than a global
/// `USER_RFLAGS` change: only the driver-host milestone sets it (around its run),
/// so other demos keep IF clear — otherwise a later demo running under the
/// scheduler's `TICK_HOOK` would take the timer IRQ in ring 3 and drive the wrong
/// scheduler (build/README.md, D46).
pub static USER_IF_ON_ENTRY: AtomicBool = AtomicBool::new(false);

/// The register snapshot the entry stub hands to the dispatcher: the syscall
/// number and up to six arguments. Layout is load-bearing — it mirrors the
/// stub's push order.
#[repr(C)]
pub struct SyscallFrame {
    pub number: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
}

/// A syscall dispatcher: consumes the argument frame, returns the ABI result
/// word placed in the user's `rax`.
pub type SyscallHandler = fn(&mut SyscallFrame) -> i64;

/// The registered dispatcher. Set once at boot by the boot CPU before any ring-3
/// thread runs, read on every syscall.
static mut SYSCALL_HANDLER: Option<SyscallHandler> = None;

/// Registers the syscall dispatcher.
///
/// # Safety
///
/// Call once, on the boot CPU, before any ring-3 thread can issue a syscall.
pub unsafe fn set_syscall_handler(handler: SyscallHandler) {
    // SAFETY: the boot CPU, single writer before ring-3 exists per contract.
    unsafe {
        SYSCALL_HANDLER = Some(handler);
    }
}

/// The C-ABI trampoline the assembly entry stub calls with a pointer to the
/// freshly built [`SyscallFrame`]. Dispatches to the registered handler.
// SAFETY: exported unmangled solely so the assembly entry stub can `call` it;
// nothing else links against the symbol.
#[unsafe(no_mangle)]
extern "C" fn syscall_trampoline(frame: *mut SyscallFrame) -> i64 {
    // SAFETY: `frame` points at a live `SyscallFrame` the entry stub just built
    // on this thread's kernel stack; it outlives this call.
    let frame = unsafe { &mut *frame };
    // SAFETY: `SYSCALL_HANDLER` is set once at boot before ring 3 exists and is
    // only read here; written once by the boot CPU, no concurrent writer.
    let handler = unsafe { SYSCALL_HANDLER };
    match handler {
        Some(handler) => handler(frame),
        // A syscall taken before boot wires the dispatcher: a kernel-domain
        // "not implemented", from the one definition of the word rather than
        // this port's own. It said `-1` here, which negates to domain 0 — not
        // one of the six, so a caller decoding it by the documented rule gets
        // an error in no domain at all.
        None => tessera_karch::ENOSYS,
    }
}

// The SYSCALL entry stub. On entry RCX = user RIP, R11 = user RFLAGS, RSP =
// user RSP, GS = user. It swaps to the kernel per-CPU block and stack, builds
// the argument frame (7 qwords), dispatches, then restores the user
// RIP/RFLAGS/RSP and `sysretq`s. Interrupts are masked by SFMASK across the
// whole stub.
//
// **All three saved user registers live on the kernel stack, and that is the
// whole point.** The per-CPU scratch cell holds the user RSP for exactly two
// instructions — long enough to have somewhere to put it before there is a
// kernel stack to push onto — and it is copied out immediately.
//
// Leaving it there until the exit path would make it a per-CPU value describing
// a per-*thread* fact. A syscall that blocks (a `receive` with no message, a
// `call` awaiting its reply) parks its thread mid-stub and lets another thread
// run; that thread's own syscall would overwrite the cell, and the first thread
// would resume and `sysretq` onto the second thread's stack. Nothing would
// fault at the point of the mistake — the value is a plausible address in
// another address space — and the failure would surface as a wild jump much
// later. The kernel stack is per-thread by construction, so a copy taken there
// cannot be aliased by anyone.
//
// The two-instruction window is safe because SFMASK clears IF on entry: no
// interrupt can be taken between the store and the copy, and this port takes
// no NMI.
//
// **The frame is popped back into its registers, not dropped.** It used to be
// dropped with a single `add rsp, 56`, which left `rdi/rsi/rdx/r10/r8/r9`
// holding whatever the Rust dispatcher happened to leave in them — kernel stack
// addresses, pointers into the process table, anything derived from the
// randomized direct map — and `sysretq` handed all six to ring 3. The
// callee-saved set survives because the trampoline is `extern "C"`, and `rcx`
// and `r11` are reloaded because `sysretq` needs them, so those six were the
// whole of the exposure and they were exposed on every syscall.
//
// Restoring rather than zeroing, and the reason is a contract rather than a
// preference: `//userspace/uabi`'s wrapper declares the argument registers
// `in(...)` on all three ports that have one, which tells the compiler they
// survive the instruction. On AArch64 and RISC-V that is true — those ports
// restore the whole trap frame. Zeroing here would close the leak and leave
// that declaration false on this port alone, which is a miscompilation waiting
// for a user program that keeps something live in `rsi` across a call. Popping
// makes the same sentence true everywhere.
//
// Ten qwords are pushed before the `call`, so RSP is 16-aligned there given a
// 16-aligned stack top — the user RSP takes the slot the alignment pad used to
// occupy, which is why the pad is gone rather than the count having changed.
global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    "  swapgs",
    "  mov gs:[{scratch}], rsp",       // park user RSP: no kernel stack yet
    "  mov rsp, gs:[{kstack}]",        // switch to this thread's kernel stack
    "  push qword ptr gs:[{scratch}]", // and take it onto that stack at once
    "  push rcx",                      // save user RIP for sysret
    "  push r11",                      // save user RFLAGS for sysret
    "  push r9",                       // --- SyscallFrame (high field first) ---
    "  push r8",
    "  push r10",
    "  push rdx",
    "  push rsi",
    "  push rdi",
    "  push rax",                      // number @ lowest address
    "  mov rdi, rsp",                  // &SyscallFrame
    "  call {tramp}",                  // -> i64 in rax (becomes user rax)
    "  add rsp, 8",                    // the number slot: rax carries the result
    "  pop rdi",                       // --- restore the caller's arguments ---
    "  pop rsi",
    "  pop rdx",
    "  pop r10",
    "  pop r8",
    "  pop r9",
    "  pop r11",                       // restore user RFLAGS
    "  pop rcx",                       // restore user RIP
    "  pop rsp",                       // restore user RSP — this thread's own
    "  swapgs",
    "  sysretq",
    scratch = const USER_RSP_SCRATCH_OFFSET,
    kstack = const KERNEL_RSP_OFFSET,
    tramp = sym syscall_trampoline,
);

// SAFETY: declares the symbol defined by the global_asm block above; the extern
// block only names it and introduces no unsafe operation.
unsafe extern "C" {
    /// The assembly entry stub above; its address goes in LSTAR.
    fn syscall_entry();
}

/// Programs the SYSCALL/SYSRET MSRs on the boot CPU: enables EFER.SCE, points
/// LSTAR at the entry stub, sets STAR's segment bases, and masks TF/IF/DF on
/// entry. Panics if the CPU lacks SYSCALL (architectural on x86-64, but probed
/// rather than assumed).
pub fn init_syscall() {
    if !cpu::syscall_supported() {
        panic!("CPU does not support SYSCALL/SYSRET");
    }
    // SAFETY: one-shot boot programming of the syscall MSRs. STAR's SYSCALL
    // base (kernel code) and SYSRET base match the GDT layout (compile-checked
    // in gdt.rs); LSTAR is a valid kernel entry point; EFER.SCE only enables
    // the instruction pair.
    unsafe {
        let efer = cpu::read_msr(IA32_EFER);
        cpu::write_msr(IA32_EFER, efer | EFER_SCE);
        let star = ((SYSRET_SELECTOR_BASE as u64) << 48) | ((KERNEL_CODE_SELECTOR as u64) << 32);
        cpu::write_msr(IA32_STAR, star);
        cpu::write_msr(IA32_LSTAR, syscall_entry as *const () as u64);
        cpu::write_msr(IA32_FMASK, SYSCALL_FLAG_MASK);
    }
}

/// Enters ring 3 for the first time in a fresh user thread: builds an `iretq`
/// frame for `rip` with stack `user_rsp` and jumps to CPL 3, passing `arg` in
/// RDI (SysV first argument). Never returns — control re-enters the kernel only
/// via `syscall_entry` or a fault. `swapgs` moves the per-CPU block into
/// KERNEL_GS_BASE so the next kernel entry recovers it.
///
/// **Every register but `rdi` and `rsp` is zeroed before the `iretq`**, which is
/// the other half of the syscall path's restore. The two halves differ in what
/// the correct answer is, not in the rule: a syscall return has the caller's own
/// values to hand back, and a thread entering ring 3 for the first time has
/// none — so there is nothing to restore and the honest starting state is zero.
/// Without it a fresh thread inherits whatever the kernel left on the way here:
/// the seeded values `init_user` put in `r13`-`r15`, and in the scratch
/// registers whatever this function's own prologue computed, which is a kernel
/// address whenever the optimizer chooses to materialize one. That it usually
/// does not is a property of a code generator rather than of this code.
///
/// Zeroing `rbp` is deliberate rather than incidental: a null frame pointer is
/// what terminates a user-space backtrace, so the register that would otherwise
/// carry a kernel stack address into ring 3 carries the value a fresh frame
/// wants anyway.
///
/// # Safety
///
/// `rip` must point at valid, user-accessible code and `user_rsp` at a valid,
/// user-writable stack top in the currently active address space; the caller
/// is switching this CPU to ring 3.
pub unsafe extern "C" fn enter_user(rip: u64, user_rsp: u64, arg: u64) -> ! {
    // Driver hosts opt into IF-set entry so their device interrupt is delivered
    // in ring 3; every other thread enters IF-clear.
    let rflags = if USER_IF_ON_ENTRY.load(Ordering::Relaxed) {
        USER_RFLAGS | RFLAGS_IF
    } else {
        USER_RFLAGS
    };
    // SAFETY: the caller guarantees `rip`/`user_rsp` are valid user mappings in
    // the active address space. The iretq frame (SS, RSP, RFLAGS, CS, RIP) is
    // the canonical ring-3 return frame; swapgs parks the kernel GS. The
    // zeroing runs after every operand's last use — the five `reg` operands are
    // read by the pushes above it — and the block never returns, so no value
    // the compiler still needs is destroyed.
    unsafe {
        asm!(
            "swapgs",
            "push {ss}",
            "push {ursp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            // Nothing below here reads an operand: the frame is on the stack.
            // `xor r32, r32` clears the full 64-bit register and is a byte
            // shorter than the 64-bit form.
            "xor eax, eax",
            "xor ebx, ebx",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor esi, esi",
            "xor ebp, ebp",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            "iretq",
            ss = in(reg) USER_DATA_SELECTOR as u64,
            ursp = in(reg) user_rsp,
            rflags = in(reg) rflags,
            cs = in(reg) USER_CODE_SELECTOR as u64,
            rip = in(reg) rip,
            in("rdi") arg,
            options(noreturn),
        );
    }
}
