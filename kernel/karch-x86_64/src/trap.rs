// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Exception entry: assembly trampolines for all 32 CPU exception vectors,
//! saving a full register frame and dispatching to a registered Rust
//! handler. Routing through trampolines (instead of the unstable
//! `abi_x86_interrupt`) keeps the kernel's unstable-feature list empty and
//! gives the handler the complete frame for register-dump panics.
//!
//! Normative: docs/kernel/01-kernel-model.md ("Interrupts And
//! Exceptions"), docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (fatal paths only, this milestone)

use core::arch::global_asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use tessera_karch::{ExitCode, PlatformExit};

/// Everything pushed on exception entry, lowest address first. `vector`
/// and `error_code` are pushed by the per-vector stub (a dummy 0 for
/// vectors without a CPU error code); `rip` through `ss` by the CPU.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Fatal-trap handler: receives the frame, never returns.
pub type TrapHandler = fn(&TrapFrame) -> !;

static HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Registers the kernel's trap handler. Call before enabling anything that
/// can fault meaningfully; traps before registration exit with failure.
pub fn set_trap_handler(handler: TrapHandler) {
    HANDLER.store(handler as usize, Ordering::Release);
}

/// Page-fault resolver, consulted first for a #PF (vector 14). It inspects the
/// fault (CR2 + the error-code bits in the frame) and tries to repair the
/// mapping — demand-fill a lazy page, copy a copy-on-write page. Returns `true`
/// if it resolved the fault (the faulting instruction is then resumed via
/// iretq) or `false` to fall through to the contain/fatal paths. Unlike
/// [`UserFaultHandler`], it *returns* — that is the resolve-and-resume seam
/// (docs/kernel/03, "Fault Taxonomy": a resolvable fault is repaired and
/// retried).
pub type PageFaultResolver = fn(&mut TrapFrame) -> bool;

/// The registered page-fault resolver. Consulted before the fatal/contain
/// handlers for vector 14.
static PAGE_FAULT_RESOLVER: AtomicUsize = AtomicUsize::new(0);

/// Registers the page-fault resolver. Until set, a #PF goes straight to the
/// contain/fatal paths (the pre-demand-paging behavior).
pub fn set_page_fault_resolver(resolver: PageFaultResolver) {
    PAGE_FAULT_RESOLVER.store(resolver as usize, Ordering::Release);
}

/// The x86 page-fault vector.
const PAGE_FAULT_VECTOR: u64 = 14;

/// Handler for a synchronous exception taken in ring 3: it contains the fault
/// (terminates the faulting process and switches away), so it never returns.
pub type UserFaultHandler = fn(&TrapFrame) -> !;

/// The registered user-fault handler. A user-mode exception routes here instead
/// of the fatal kernel handler; kernel-mode faults stay fatal
/// (docs/kernel/03, "Kernel-Internal Exceptions").
static USER_FAULT_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Registers the handler for ring-3 faults. Call before entering user mode;
/// until then a user fault falls through to the fatal handler.
pub fn set_user_fault_handler(handler: UserFaultHandler) {
    USER_FAULT_HANDLER.store(handler as usize, Ordering::Release);
}

/// Optional per-tick preemption hook, invoked after the timer IRQ (IRQ0) is
/// acknowledged. The scheduler registers this to drive round-robin
/// preemption; a `switch` inside it resumes another thread and returns here
/// only when this thread is later scheduled again.
static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Registers a preemption hook called on every timer tick. Pass a plain
/// `fn()`; it runs in interrupt context with interrupts masked.
pub fn set_tick_hook(hook: fn()) {
    TICK_HOOK.store(hook as usize, Ordering::Release);
}

/// Optional device-IRQ hook, invoked after a non-timer PIC IRQ is acknowledged,
/// with the interrupt vector. A driver framework registers this to deliver the
/// interrupt to a user-space driver host (e.g. by signalling a port the driver
/// waits on). Mirrors [`set_tick_hook`], for device lines instead of the timer.
static DEVICE_IRQ_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Registers a device-IRQ hook called on every non-timer PIC IRQ, after EOI.
/// Pass a plain `fn(u64)` taking the vector; it runs in interrupt context with
/// interrupts masked.
pub fn set_device_irq_hook(hook: fn(u64)) {
    DEVICE_IRQ_HOOK.store(hook as usize, Ordering::Release);
}

/// Human-readable exception names, indexed by vector.
pub fn vector_name(vector: u64) -> &'static str {
    const NAMES: [&str; 32] = [
        "#DE divide error",
        "#DB debug",
        "NMI",
        "#BP breakpoint",
        "#OF overflow",
        "#BR bound range",
        "#UD invalid opcode",
        "#NM device not available",
        "#DF double fault",
        "coprocessor segment overrun",
        "#TS invalid TSS",
        "#NP segment not present",
        "#SS stack fault",
        "#GP general protection",
        "#PF page fault",
        "reserved (15)",
        "#MF x87 floating point",
        "#AC alignment check",
        "#MC machine check",
        "#XM SIMD floating point",
        "#VE virtualization",
        "#CP control protection",
        "reserved (22)",
        "reserved (23)",
        "reserved (24)",
        "reserved (25)",
        "reserved (26)",
        "reserved (27)",
        "#HV hypervisor injection",
        "#VC VMM communication",
        "#SX security",
        "reserved (31)",
    ];
    NAMES
        .get(vector as usize)
        .copied()
        .unwrap_or("unknown vector")
}

/// Called from `trap_common` with the frame pointer in `rdi`. Returning
/// resumes the interrupted context via `iretq`; the fatal-exception path
/// diverges instead.
// SAFETY: exported unmangled solely so the assembly above can `call` it;
// nothing else links against the symbol.
#[unsafe(no_mangle)]
extern "C" fn trap_dispatch(frame: &mut TrapFrame) {
    let vector = frame.vector;
    if (crate::timer::IRQ_BASE..crate::timer::IRQ_BASE + crate::timer::IRQ_COUNT).contains(&vector)
    {
        crate::timer::handle_irq(vector);
        // Drive preemption on the timer tick (IRQ0), after the controller is
        // acknowledged so the next tick can be delivered.
        if vector == crate::timer::IRQ_BASE {
            let raw = TICK_HOOK.load(Ordering::Acquire);
            if raw != 0 {
                // SAFETY: the only store to TICK_HOOK is `set_tick_hook`, which
                // always writes a valid `fn()` pointer.
                let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(raw) };
                hook();
            }
        } else {
            // A device IRQ (e.g. a driver host's UART): deliver it to the
            // registered device hook, after EOI, so the hook may re-enable and
            // wake a waiting driver.
            let raw = DEVICE_IRQ_HOOK.load(Ordering::Acquire);
            if raw != 0 {
                // SAFETY: the only store to DEVICE_IRQ_HOOK is
                // `set_device_irq_hook`, which always writes a valid `fn(u64)`.
                let hook: fn(u64) = unsafe { core::mem::transmute::<usize, fn(u64)>(raw) };
                hook(vector);
            }
        }
        return;
    }
    // A page fault may be *resolvable* — a lazy page to demand-fill or a
    // copy-on-write page to copy. Consult the resolver first; if it repairs the
    // mapping, simply return and the CPU iretq-retries the faulting instruction
    // (the same resume path IRQs use). Only an unresolved #PF falls through to
    // the contain/fatal handlers below (docs/kernel/03, "Fault Taxonomy").
    if vector == PAGE_FAULT_VECTOR {
        let raw = PAGE_FAULT_RESOLVER.load(Ordering::Acquire);
        if raw != 0 {
            // SAFETY: the only store to PAGE_FAULT_RESOLVER is
            // `set_page_fault_resolver`, which always writes a valid
            // `PageFaultResolver` function pointer.
            let resolver: PageFaultResolver = unsafe { core::mem::transmute(raw) };
            if resolver(frame) {
                return;
            }
        }
    }
    // A synchronous CPU exception (vector < 32) taken in ring 3 (CS RPL = 3) is
    // contained by the user-fault handler, which terminates the faulting
    // process and switches away — it never returns here. Kernel-mode faults
    // fall through to the fatal handler (docs/kernel/03, "Kernel-Internal
    // Exceptions": a kernel fault is a bug, panic/abort).
    if vector < 32 && (frame.cs & 3) == 3 {
        let raw = USER_FAULT_HANDLER.load(Ordering::Acquire);
        if raw != 0 {
            // SAFETY: the only store to USER_FAULT_HANDLER is
            // `set_user_fault_handler`, which always writes a valid
            // `UserFaultHandler`.
            let handler: UserFaultHandler = unsafe { core::mem::transmute(raw) };
            handler(frame);
        }
    }
    let raw = HANDLER.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: the only store to HANDLER is `set_trap_handler`, which
        // always writes a valid `TrapHandler` function pointer.
        let handler: TrapHandler = unsafe { core::mem::transmute(raw) };
        handler(frame);
    }
    // Exception before a handler was registered: nothing can report it.
    crate::cpu::DebugExit::exit(ExitCode::Failure)
}

// Per-vector stubs. Vectors 8, 10-14, 17, 21 push a CPU error code; the
// rest get a dummy so the frame layout is uniform. The stub table gives
// the IDT builder every stub address without 32 named externs.
global_asm!(
    r#"
.macro trap_stub vector, has_err
trap_stub_\vector:
.if \has_err == 0
    push 0
.endif
    push \vector
    jmp trap_common
.endm

trap_stub 0, 0
trap_stub 1, 0
trap_stub 2, 0
trap_stub 3, 0
trap_stub 4, 0
trap_stub 5, 0
trap_stub 6, 0
trap_stub 7, 0
trap_stub 8, 1
trap_stub 9, 0
trap_stub 10, 1
trap_stub 11, 1
trap_stub 12, 1
trap_stub 13, 1
trap_stub 14, 1
trap_stub 15, 0
trap_stub 16, 0
trap_stub 17, 1
trap_stub 18, 0
trap_stub 19, 0
trap_stub 20, 0
trap_stub 21, 1
trap_stub 22, 0
trap_stub 23, 0
trap_stub 24, 0
trap_stub 25, 0
trap_stub 26, 0
trap_stub 27, 0
trap_stub 28, 0
trap_stub 29, 0
trap_stub 30, 0
trap_stub 31, 0
trap_stub 32, 0
trap_stub 33, 0
trap_stub 34, 0
trap_stub 35, 0
trap_stub 36, 0
trap_stub 37, 0
trap_stub 38, 0
trap_stub 39, 0
trap_stub 40, 0
trap_stub 41, 0
trap_stub 42, 0
trap_stub 43, 0
trap_stub 44, 0
trap_stub 45, 0
trap_stub 46, 0
trap_stub 47, 0

trap_common:
    // Saved CS is at [rsp+24] here (vector@0, error_code@8, rip@16, cs@24).
    // A fault taken from ring 3 still has the user GS loaded, so swap to the
    // kernel per-CPU block before any gs-relative access. Ring-0 faults skip it.
    test qword ptr [rsp + 24], 3
    jz 1f
    swapgs
1:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cld
    mov rdi, rsp
    call trap_dispatch
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    // Saved CS is now at [rsp+8]. Restore the user GS when returning to ring 3.
    test qword ptr [rsp + 8], 3
    jz 2f
    swapgs
2:
    iretq

.section .rodata
.balign 8
.global trap_stub_table
trap_stub_table:
    .quad trap_stub_0
    .quad trap_stub_1
    .quad trap_stub_2
    .quad trap_stub_3
    .quad trap_stub_4
    .quad trap_stub_5
    .quad trap_stub_6
    .quad trap_stub_7
    .quad trap_stub_8
    .quad trap_stub_9
    .quad trap_stub_10
    .quad trap_stub_11
    .quad trap_stub_12
    .quad trap_stub_13
    .quad trap_stub_14
    .quad trap_stub_15
    .quad trap_stub_16
    .quad trap_stub_17
    .quad trap_stub_18
    .quad trap_stub_19
    .quad trap_stub_20
    .quad trap_stub_21
    .quad trap_stub_22
    .quad trap_stub_23
    .quad trap_stub_24
    .quad trap_stub_25
    .quad trap_stub_26
    .quad trap_stub_27
    .quad trap_stub_28
    .quad trap_stub_29
    .quad trap_stub_30
    .quad trap_stub_31
    .quad trap_stub_32
    .quad trap_stub_33
    .quad trap_stub_34
    .quad trap_stub_35
    .quad trap_stub_36
    .quad trap_stub_37
    .quad trap_stub_38
    .quad trap_stub_39
    .quad trap_stub_40
    .quad trap_stub_41
    .quad trap_stub_42
    .quad trap_stub_43
    .quad trap_stub_44
    .quad trap_stub_45
    .quad trap_stub_46
    .quad trap_stub_47
.text
"#
);

/// Vectors covered by the trampolines: 32 exceptions + 16 legacy IRQs.
pub(crate) const STUB_COUNT: usize = 48;

// SAFETY: the symbol is defined by the global_asm block above as exactly
// STUB_COUNT 8-byte stub addresses in .rodata; the declaration matches
// that layout.
unsafe extern "C" {
    /// Stub addresses, one per vector, from the assembly above.
    pub(crate) static trap_stub_table: [usize; STUB_COUNT];
}
