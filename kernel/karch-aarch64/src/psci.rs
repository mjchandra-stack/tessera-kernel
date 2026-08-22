// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The firmware power-control interface: starting a CPU other than this one.
//!
//! # Why the kernel does not start CPUs itself
//!
//! On this architecture a CPU that has not been started is not merely idle —
//! it may be powered down, and nothing the kernel can write will wake it.
//! Power is firmware's, so the sequence is a call *out* of the kernel: name the
//! CPU, name the physical address it is to begin executing at, and firmware
//! does the rest. PSCI is the standard shape of that call.
//!
//! # Two numbers the kernel refuses to assume
//!
//! **The conduit.** Reaching firmware is one instruction, and which one depends
//! on where firmware sits relative to the kernel: `hvc` where it is reached
//! through the hypervisor call, `smc` where it is behind the secure monitor.
//! Both assemble, both are legal at EL1, and the wrong one on a given machine
//! does not produce a diagnosable failure — it takes an exception to a level
//! that is not listening, or returns a code for a function nobody implements.
//!
//! **The function identifier.** Fixed by the specification from version 0.2,
//! and *also* published in the device tree. This reads the tree's, because a
//! kernel that ignored the machine's own description in favour of its own
//! table would be right only for as long as the two agreed, and would have no
//! way to notice when they stopped.
//!
//! Both are therefore installed at boot from what the port discovered, and a
//! kernel that discovered neither starts no CPU and says so, rather than
//! issuing a guess.
//!
//! # The call
//!
//! `CPU_ON(target, entry, context)` is a 64-bit SMC-calling-convention call:
//! the function identifier in `x0`, arguments in `x1`–`x3`, the result back in
//! `x0`. `entry` is a **physical** address entered with translation off, at the
//! caller's own exception level. `context` arrives in the started CPU's `x0`
//! and is otherwise uninterpreted by firmware — which is what carries the dense
//! index across, since a CPU cannot work out its own.
//!
//! Normative: docs/roadmap/02-smp-bring-up-plan.md ("Phase 2"),
//! docs/hardware/01-platform-and-cpu-support.md ("Architecture Porting Layer")
//! Budget: none (bring-up path)

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use tessera_karch::CpuStartError;

/// Which instruction reaches firmware.
///
/// `tessera_devicetree::PsciConduit` carries the same two names and is a
/// different thing: that one is what a machine's description *said*, this one
/// is what this port will *issue*. The porting layer depends on no discovery
/// crate — reading a tree is above it, not beside it — so the boot glue maps
/// one to the other, as it already does for every device window it finds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Conduit {
    /// `hvc`, where firmware is reached through the hypervisor call.
    Hvc,
    /// `smc`, where firmware is reached through the secure-monitor call.
    Smc,
}

/// The installed interface, packed into one word so a reader gets a coherent
/// pair rather than a conduit from one boot-time write and a function
/// identifier from another. Zero means nothing was installed.
///
/// Layout: the function identifier in the low 32 bits, the conduit in bit 32,
/// and bit 33 set to mark the word written — without which a valid interface
/// whose identifier happened to be zero would read as absent.
static INTERFACE: AtomicU64 = AtomicU64::new(0);

const PRESENT: u64 = 1 << 33;
const CONDUIT_SMC: u64 = 1 << 32;

/// Records the interface the port found in the device tree.
///
/// Called once, on the boot CPU, before any CPU is started. Calling it never is
/// the supported case for a machine whose firmware offers no such interface;
/// [`cpu_on`] then reports [`CpuStartError::Unsupported`].
pub fn install(conduit: Conduit, cpu_on: u32) {
    let conduit = match conduit {
        Conduit::Hvc => 0,
        Conduit::Smc => CONDUIT_SMC,
    };
    INTERFACE.store(PRESENT | conduit | u64::from(cpu_on), Ordering::Release);
}

/// Starts the CPU whose `MPIDR_EL1` affinity is `target`, at the physical
/// address `entry`, with `context` in its `x0`.
///
/// # Safety
///
/// `entry` must be the physical address of code that is executable with the
/// MMU off at the caller's exception level, and that is prepared to be entered
/// by a CPU with no stack, no translation, and no kernel state of its own.
/// `context` must name resources — a stack above all — reserved for exactly
/// that CPU.
pub unsafe fn cpu_on(target: u64, entry: u64, context: u64) -> Result<(), CpuStartError> {
    let interface = INTERFACE.load(Ordering::Acquire);
    if interface & PRESENT == 0 {
        return Err(CpuStartError::Unsupported);
    }
    let function = interface as u32;

    // SAFETY: the call is the architecture's own firmware interface. The
    // register set is the SMC calling convention's: the function identifier and
    // three arguments in x0-x3, the result in x0, and x4-x17 caller-saved and
    // therefore clobbered. `nostack` is correct because firmware runs on its
    // own; the entry point's obligations are the caller's, restated above.
    let status: i64 = if interface & CONDUIT_SMC == 0 {
        unsafe { hvc(function, target, entry, context) }
    } else {
        // SAFETY: as the branch above — the same call through the other conduit.
        unsafe { smc(function, target, entry, context) }
    };

    match status {
        SUCCESS => Ok(()),
        NOT_SUPPORTED => Err(CpuStartError::Unsupported),
        INVALID_PARAMETERS | INVALID_ADDRESS => Err(CpuStartError::UnknownCpu),
        ALREADY_ON | ON_PENDING => Err(CpuStartError::AlreadyOn),
        DENIED => Err(CpuStartError::Denied),
        // Every other code, including INTERNAL_FAILURE, is firmware reporting a
        // failure of its own. They are not enumerated further because nothing
        // the kernel does differs between them.
        _ => Err(CpuStartError::Internal),
    }
}

// PSCI return codes (32-bit, sign-extended into the 64-bit result register).
const SUCCESS: i64 = 0;
const NOT_SUPPORTED: i64 = -1;
const INVALID_PARAMETERS: i64 = -2;
const DENIED: i64 = -3;
const ALREADY_ON: i64 = -4;
const ON_PENDING: i64 = -5;
const INVALID_ADDRESS: i64 = -9;

/// # Safety
///
/// As [`cpu_on`]: this issues a firmware call that starts a CPU.
unsafe fn hvc(function: u32, a1: u64, a2: u64, a3: u64) -> i64 {
    let status: i64;
    // SAFETY: the SMC calling convention's register assignment, with the
    // caller-saved argument registers declared clobbered. See `cpu_on`.
    unsafe {
        asm!(
            "hvc #0",
            inout("x0") u64::from(function) => status,
            inout("x1") a1 => _,
            inout("x2") a2 => _,
            inout("x3") a3 => _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _,
            options(nostack),
        );
    }
    status
}

/// # Safety
///
/// As [`cpu_on`]: this issues a firmware call that starts a CPU.
unsafe fn smc(function: u32, a1: u64, a2: u64, a3: u64) -> i64 {
    let status: i64;
    // SAFETY: as `hvc` above; the two differ in the instruction and nothing
    // else, which is the whole of what the conduit selects.
    unsafe {
        asm!(
            "smc #0",
            inout("x0") u64::from(function) => status,
            inout("x1") a1 => _,
            inout("x2") a2 => _,
            inout("x3") a3 => _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _,
            options(nostack),
        );
    }
    status
}
