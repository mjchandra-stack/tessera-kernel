// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! CPU-level operations and the QEMU debug exit device.
//!
//! Normative: docs/kernel/01-kernel-model.md ("Architecture Layer")
//! Budget: none (init, idle, and exit paths)

use crate::io::outb;
use core::arch::asm;
use tessera_karch::{CpuOps, ExitCode, InterruptControl, PlatformExit};

pub struct Cpu;

impl CpuOps for Cpu {
    fn cpu_id() -> u32 {
        crate::percpu::current_cpu_id()
    }

    fn halt_until_interrupt() {
        // SAFETY: `hlt` only pauses the CPU until the next interrupt; no
        // memory or register state is affected.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }

    fn hw_random() -> Option<u64> {
        // RDRAND faults with #UD on CPUs that lack it (e.g. QEMU's default
        // model), so gate on CPUID before executing it.
        if !rdrand_supported() {
            return None;
        }
        const RETRIES: u32 = 10;
        for _ in 0..RETRIES {
            let value: u64;
            let ok: u8;
            // SAFETY: RDRAND writes a hardware random word to its
            // destination register and sets CF on success; it touches no
            // memory and has no effect other than those two register
            // writes. CF=0 means "not ready", handled by the retry loop.
            unsafe {
                asm!(
                    "rdrand {value}",
                    "setc {ok}",
                    value = out(reg) value,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 {
                return Some(value);
            }
        }
        None
    }
    fn counter_serialized() -> u64 {
        read_tsc_serialized()
    }

    fn counter_hz() -> Option<u64> {
        // The TSC's rate is not architecturally discoverable: CPUID leaf 0x15
        // reports it on some parts and not others, and the harness calibrates
        // against the PIT instead. Saying so beats returning a guess.
        None
    }
}

/// Whether the CPU supports the RDRAND instruction (CPUID leaf 1, ECX bit 30).
fn rdrand_supported() -> bool {
    let ecx: u32;
    // SAFETY: CPUID leaf 1 reads feature bits and has no side effects; RBX
    // (reserved by the compiler) is saved and restored around it.
    unsafe {
        asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov rbx, {tmp:r}",
            inout("eax") 1u32 => _,
            tmp = out(reg) _,
            out("ecx") ecx,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
    ecx & (1 << 30) != 0
}

/// The timestamp counter, a weak boot-time entropy source used only when the
/// CPU offers no RDRAND. It is not a substitute for the kernel CSPRNG.
pub fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC reads the cycle counter into EDX:EAX with no side effects.
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// A **serialized** timestamp read for microbenchmarking (docs/prototypes/01,
/// "Measurement Methodology"). Plain RDTSC can reorder around the measured
/// region under out-of-order execution; the `LFENCE` fences bound it so the read
/// happens exactly at the measurement point. Confined to the benchmark harness —
/// raw cycle counters are not application logic (docs/lifecycle/04).
pub fn read_tsc_serialized() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: LFENCE serializes prior loads and RDTSC reads the cycle counter
    // into EDX:EAX; neither touches memory or has side effects beyond ordering.
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Whether the CPU advertises an **invariant TSC** — one that ticks at a
/// constant rate independent of core frequency and does not stop in low-power
/// states (CPUID leaf `0x8000_0007`, EDX bit 8). The benchmark methodology
/// requires it; the harness reports this so an emulated environment that does
/// not advertise it is visible rather than silently trusted.
pub fn tsc_invariant() -> bool {
    let edx: u32;
    // SAFETY: CPUID with EAX=0x8000_0007 reads power-management feature bits and
    // has no side effects; RBX (reserved by the compiler) is saved and restored.
    unsafe {
        asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov rbx, {tmp:r}",
            inout("eax") 0x8000_0007u32 => _,
            tmp = out(reg) _,
            out("ecx") _,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    edx & (1 << 8) != 0
}

impl InterruptControl for Cpu {
    fn enable() {
        // SAFETY: setting IF only permits interrupt delivery; callers
        // sequence this after the IDT and interrupt controller are live.
        unsafe {
            asm!("sti", options(nomem, nostack));
        }
    }

    fn disable() {
        // SAFETY: clearing IF only masks maskable interrupts.
        unsafe {
            asm!("cli", options(nomem, nostack));
        }
    }

    fn are_enabled() -> bool {
        let flags: u64;
        // SAFETY: reads RFLAGS via the stack without other side effects.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        flags & (1 << 9) != 0
    }
}

/// Faulting address of the most recent page fault.
pub fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: reading CR2 has no side effects at CPL 0.
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// The current stack pointer. Used at boot to locate the bootloader-provided
/// stack before the kernel's own direct map is installed.
pub fn read_stack_pointer() -> u64 {
    let rsp: u64;
    // SAFETY: reading RSP has no side effects.
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    rsp
}

/// The active top-level page table (physical address plus flags).
pub fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: reading CR3 has no side effects at CPL 0.
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Reads a model-specific register.
///
/// # Safety
///
/// `msr` must name an MSR that is readable on this CPU; reading an
/// unimplemented MSR raises `#GP`.
pub unsafe fn read_msr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDMSR reads the MSR named in ECX into EDX:EAX and has no other
    // effect; the caller guarantees the MSR exists per this fn's contract.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Writes a model-specific register.
///
/// # Safety
///
/// `msr` must name a writable MSR and `value` be legal for it; the write
/// changes privileged CPU state (e.g. EFER, the syscall-entry MSRs, GS base).
pub unsafe fn write_msr(msr: u32, value: u64) {
    // SAFETY: WRMSR stores EDX:EAX into the MSR named in ECX; the caller
    // guarantees the MSR and value are valid per this fn's contract.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }
}

/// Whether the CPU implements SYSCALL/SYSRET (CPUID leaf `0x8000_0001`, EDX
/// bit 11). SYSCALL is architectural on x86-64, but the boot path probes it
/// rather than assume it, mirroring the RDRAND gate.
pub fn syscall_supported() -> bool {
    let edx: u32;
    // SAFETY: CPUID with EAX=0x8000_0001 reads extended feature bits with no
    // side effects; RBX (reserved by the compiler) is saved and restored.
    unsafe {
        asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov rbx, {tmp:r}",
            inout("eax") 0x8000_0001u32 => _,
            tmp = out(reg) _,
            out("ecx") _,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    edx & (1 << 11) != 0
}

/// QEMU `isa-debug-exit` at its conventional port. QEMU's exit status is
/// `(value << 1) | 1`, so success/failure below surface as 33 and 65 —
/// never 0, which keeps "kernel exited" distinguishable from "QEMU ran
/// fine" in the harness.
const DEBUG_EXIT_PORT: u16 = 0xf4;
const EXIT_VALUE_SUCCESS: u8 = 0x10; // QEMU exit status 33
const EXIT_VALUE_FAILURE: u8 = 0x20; // QEMU exit status 65

pub struct DebugExit;

impl PlatformExit for DebugExit {
    fn exit(code: ExitCode) -> ! {
        let value = match code {
            ExitCode::Success => EXIT_VALUE_SUCCESS,
            ExitCode::Failure => EXIT_VALUE_FAILURE,
        };
        // SAFETY: the debug-exit device terminates the VM on write; if the
        // device is absent (real hardware), the write is harmlessly ignored
        // and we halt forever below.
        unsafe {
            outb(DEBUG_EXIT_PORT, value);
        }
        loop {
            Cpu::halt_until_interrupt();
        }
    }
}
