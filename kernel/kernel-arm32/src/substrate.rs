// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **executive substrate on the last port**: an `Executive`, a process
//! table, and the hook that routes a user `svc` into the shared dispatcher.
//!
//! Until now this port reached ring 3 through a bespoke handler with two toy
//! syscalls and a hand-assembled blob — enough to show User mode can be entered
//! and contained, and nothing a compiled program could run on. What is here is
//! the same substrate the other four use, and **none of it is new code**
//! (build/README.md, D263).
//!
//! # What this machine changes
//!
//! **The result word.** A syscall answers one `i64` and `r0` is 32 bits, so a
//! result too wide to come back is refused rather than truncated — the kernel's
//! half of the agreement `//userspace/uabi` makes about arguments (D259).
//!
//! **No `pc` adjustment.** `LR` already points after the `svc`, where RISC-V's
//! `sepc` points *at* the `ecall`. The RISC-V hooks add four; this one must
//! not, and a port that copied them would resume one instruction late.
//!
//! **Nothing to guard.** The `TTBCR` split walks the kernel out of `TTBR1` and
//! a process out of `TTBR0`, so a process's tables carry no copy of the
//! kernel's (D110). The 4 MiB-root-entry hazard that shaped RISC-V 32's kernel
//! stacks (D260, D262) has no counterpart here: a kernel mapping made at any
//! time is reachable from every process, because it was never copied.
//!
//! Normative: docs/api/01-system-call-interface.md ("The Result Word"),
//! docs/hardware/01-platform-and-cpu-support.md ("Endianness And Word Size")

use crate::*;
use core::sync::atomic::AtomicU32;
use tessera_karch_arm32::KernelAddressSpace;

/// The process table, const-initialized in `.bss` for the large-object reason
/// every other port holds it that way.
pub(crate) static mut KCORE_PROCESSES: kcore::process::ProcessTable<KernelAddressSpace> =
    kcore::process::ProcessTable::new();

/// The executive owning this run's scheduler and channels.
pub(crate) static mut KCORE_EXEC: Option<kcore::exec::Executive<ContextSwitch>> = None;

/// The boot allocator, published for the duration of a run. Null outside one,
/// and a syscall arriving then is a check that forgot to publish it rather
/// than a null dereference.
pub(crate) static mut DISPATCH_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
    core::ptr::null_mut();

/// Why a run ended, when it ended badly.
pub(crate) static SUBSTRATE_FAULT: AtomicU32 = AtomicU32::new(0);

/// What a program reported through `DebugWrite`, keyed by order. Overflow is
/// counted rather than dropped: a check expecting two reports and getting three
/// sees three.
const MAX_REPORTS: usize = 4;
pub(crate) static REPORTS: [AtomicU32; MAX_REPORTS] = [const { AtomicU32::new(0) }; MAX_REPORTS];
pub(crate) static REPORT_COUNT: AtomicU32 = AtomicU32::new(0);

/// The executive, through one place — for the reason
/// `tools/ci/arch-lint-baseline.txt` gives.
///
/// # Safety
///
/// The caller must be the boot CPU with no other borrow of `KCORE_EXEC` live.
pub(crate) unsafe fn kcore_exec() -> Option<&'static mut kcore::exec::Executive<ContextSwitch>> {
    // SAFETY: the caller's obligation, stated above.
    unsafe { (*(&raw mut KCORE_EXEC)).as_mut() }
}

/// The process table, through one place — as [`kcore_exec`].
///
/// # Safety
///
/// The caller must be the boot CPU with no other borrow live.
pub(crate) unsafe fn kcore_processes()
-> &'static mut kcore::process::ProcessTable<KernelAddressSpace> {
    // SAFETY: the caller's obligation, stated above.
    unsafe { &mut *(&raw mut KCORE_PROCESSES) }
}

/// Builds or restarts the executive with `quantum` ticks per thread.
///
/// # Safety
///
/// The caller must be the boot CPU with no thread running.
pub(crate) unsafe fn kcore_exec_restart(quantum: u32) {
    // SAFETY: the caller's contract, restated.
    unsafe {
        match (&raw mut KCORE_EXEC).as_mut().and_then(Option::as_mut) {
            Some(exec) => exec.restart(quantum, 0),
            None => (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(quantum, 0))),
        }
    }
}

/// Narrows a dispatch result into `r0`, or answers `ResultTooLarge` for one
/// that does not fit — the kernel's half of D259's width agreement.
fn narrow_result(value: i64) -> u32 {
    if value > i32::MAX as i64 || value < i32::MIN as i64 {
        return tessera_karch::encode_error(tessera_karch::KError::ResultTooLarge) as u32;
    }
    value as u32
}

/// Ends the running thread and switches to the next ready one — to the boot
/// context only when nothing is runnable.
pub(crate) fn end_user_thread() {
    // SAFETY: the boot CPU, cooperative; the executive is built before any
    // thread runs.
    if let Some(exec) = unsafe { kcore_exec() } {
        exec.scheduler().exit_current();
    }
}

/// The address an abort was taken on, beside the kind.
///
/// **Both, because neither is enough.** A prefetch abort says the instruction
/// fetch failed and a data abort says a load or store did; which *address* is
/// what distinguishes "the program was mapped wrong" from "the program ran and
/// touched something it should not have".
pub(crate) static SUBSTRATE_FAULT_ADDR: AtomicU32 = AtomicU32::new(0);

/// An abort taken from User mode: record it and abandon the thread.
pub(crate) fn user_abort_hook(frame: &TrapFrame) {
    SUBSTRATE_FAULT.store(frame.kind | 0x8000_0000, Ordering::SeqCst);
    SUBSTRATE_FAULT_ADDR.store(frame.fault_address, Ordering::SeqCst);
    end_user_thread();
}

/// The user syscall hook: an `svc` from User mode goes to the shared
/// dispatcher, and what the dispatcher does not cover stays here.
pub(crate) fn user_dispatch_hook(frame: &mut UserFrame) {
    use kcore::dispatch::{DispatchEnv, DispatchOutcome, SyscallRequest, dispatch};
    use kcore::syscall::{SyscallNumber, encode_result};

    // SAFETY: the boot CPU, cooperative; nothing else borrows the executive
    // while a user thread is on the CPU.
    let Some(caller) = (unsafe { kcore_exec() }).and_then(|exec| {
        let slot = exec.scheduler().current()?;
        exec.scheduler().thread_id(slot)
    }) else {
        SUBSTRATE_FAULT.store(0xbad0, Ordering::SeqCst);
        end_user_thread();
        return;
    };
    // SAFETY: transient raw read of the run-scoped allocator pointer.
    let frames = unsafe { *(&raw const DISPATCH_FRAMES) };
    if frames.is_null() {
        SUBSTRATE_FAULT.store(0xbad2, Ordering::SeqCst);
        end_user_thread();
        return;
    }

    // The loader trio stays local: each needs this port's `LoaderSupport`, and
    // the seam is reachable only while a root-task run has published it.
    if let Some(number) = SyscallNumber::from_u64(u64::from(frame.r[7]))
        && matches!(
            number,
            SyscallNumber::ProcessCreate
                | SyscallNumber::AddressSpaceMap
                | SyscallNumber::ProcessStart
                | SyscallNumber::ProcessWait
        )
        // SAFETY: transient raw read of the run-scoped seam pointer.
        && unsafe { (*(&raw const crate::roottask::ROOT_LOADER)).is_some() }
    {
        frame.r[0] = narrow_result(root_loader_arm(number, caller, frame.r[0], frames));
        return;
    }

    let request = SyscallRequest {
        number: u64::from(frame.r[7]),
        args: [
            u64::from(frame.r[0]),
            u64::from(frame.r[1]),
            u64::from(frame.r[2]),
            u64::from(frame.r[3]),
            u64::from(frame.r[4]),
            u64::from(frame.r[5]),
        ],
    };
    // SAFETY: the boot CPU, cooperative. The statics are initialized before any
    // thread runs and the frame pointer names the boot allocator for the run's
    // duration (checked non-null above). A blocking channel operation parks
    // this frame — the borrows in `env` included — on the blocked thread's own
    // kernel stack, and nothing dereferences them until the handoff returns.
    let outcome = unsafe {
        let Some(exec) = kcore_exec() else {
            SUBSTRATE_FAULT.store(0xbad3, Ordering::SeqCst);
            end_user_thread();
            return;
        };
        let mut env = DispatchEnv {
            exec,
            processes: kcore_processes(),
            caller,
            alloc: &mut *frames,
            // No IOMMU on this machine, and no device interrupt routed through
            // the port facility yet. Both say so rather than defaulting.
            iommu: None,
            irqs: None,
            clock: crate::substrate::monotonic_nanos,
        };
        dispatch(&mut env, &request)
    };

    // **No `pc` adjustment on any path.** `LR` already points after the `svc`.
    match outcome {
        DispatchOutcome::Return(value) => frame.r[0] = narrow_result(value),
        DispatchOutcome::Unhandled => match SyscallNumber::from_u64(u64::from(frame.r[7])) {
            Some(SyscallNumber::DebugWrite) => {
                let slot = REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
                if let Some(cell) = REPORTS.get(slot) {
                    cell.store(frame.r[0], Ordering::SeqCst);
                }
                frame.r[0] = narrow_result(encode_result(Ok(0)));
            }
            Some(SyscallNumber::ProcessExit) => {
                // Mark the process exited and hand back whoever was waiting on
                // it before this thread leaves the CPU — the order is what
                // makes a supervisor's wait return.
                // SAFETY: the boot CPU, cooperative; both statics are this
                // run's, initialized before it started.
                unsafe {
                    if let Some(exec) = kcore_exec() {
                        kcore::loader::notify_exit(
                            exec,
                            kcore_processes(),
                            caller,
                            frame.r[0] as i32,
                        );
                    }
                }
                end_user_thread();
            }
            _ => {
                SUBSTRATE_FAULT.store(0xbad1, Ordering::SeqCst);
                end_user_thread();
            }
        },
    }
}

/// The four process-lifecycle syscalls, answered out of `kcore::loader` against
/// this port's `LoaderSupport`.
///
/// The lifecycle is not here: what is here is the routing and the seam.
fn root_loader_arm(
    number: kcore::syscall::SyscallNumber,
    caller: kcore::thread::ThreadId,
    args_ptr: u32,
    frames: *mut kcore::pmem::BumpFrameAllocator<'static>,
) -> i64 {
    use kcore::syscall::{SyscallNumber, encode_result};

    let args_ptr = u64::from(args_ptr);
    // SAFETY: the boot CPU, cooperative. `ROOT_LOADER` is published before the
    // root task's thread runs and taken after the run ends, so a borrow here
    // cannot outlive it; the frame pointer was checked non-null by the caller.
    unsafe {
        let Some(support) = crate::roottask::root_loader() else {
            return encode_result(Err(tessera_karch::KError::NotSupported));
        };
        let mut env = kcore::loader::LoaderEnv {
            support,
            objects: crate::roottask::kcore_objects(),
        };
        let processes = kcore_processes();
        let alloc = &mut *frames;
        match number {
            SyscallNumber::ProcessCreate => {
                kcore::loader::create(&mut env, processes, alloc, caller, args_ptr)
            }
            SyscallNumber::AddressSpaceMap => {
                kcore::loader::address_space_map(&mut env, processes, alloc, caller, args_ptr)
            }
            SyscallNumber::ProcessStart => {
                let Some(exec) = kcore_exec() else {
                    return encode_result(Err(tessera_karch::KError::NotSupported));
                };
                let result =
                    kcore::loader::start(&mut env, exec, processes, alloc, caller, args_ptr);
                if result >= 0 {
                    crate::roottask::note_launch();
                }
                result
            }
            _ => {
                let Some(exec) = kcore_exec() else {
                    return encode_result(Err(tessera_karch::KError::NotSupported));
                };
                kcore::loader::wait(&mut env, exec, processes, alloc, caller, args_ptr)
            }
        }
    }
}

/// Monotonic nanoseconds, for `ClockRead` (D281).
///
/// **The conversion is here rather than in `kcore`**, because `karch`'s
/// counter is deliberately unit-less and only the port knows its rate. A
/// machine whose counter frequency is unknown reports zero rather than a
/// number derived from a guess: a clock that is confidently wrong is worse
/// than one that says it does not know.
pub(crate) fn monotonic_nanos() -> u64 {
    use tessera_karch::CpuOps;
    use tessera_karch_arm32::Cpu;
    let ticks = <Cpu as CpuOps>::counter_serialized();
    match <Cpu as CpuOps>::counter_hz() {
        Some(hz) if hz > 0 => (ticks as u128 * 1_000_000_000u128 / hz as u128) as u64,
        _ => 0,
    }
}
