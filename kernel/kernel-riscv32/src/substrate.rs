// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **executive substrate on a 32-bit machine**: an `Executive`, a process
//! table, and the trap hook that routes a user `ecall` into the shared
//! dispatcher.
//!
//! Until now this port reached ring 3 through a bespoke handler with two toy
//! syscalls and a hand-assembled blob — enough to prove U-mode can be entered
//! and contained, and nothing a compiled program could run on. What is here is
//! the same substrate the three 64-bit ports use, and **none of it is new
//! code**: `Executive`, `ProcessTable`, `Thread` and `kcore::dispatch` compile
//! for this target already, because `//kernel/width-conformance` has been
//! building them at 32 bits on every `bazel build //...` since long before
//! there was anything here to run (build/README.md, D260).
//!
//! # What a 32-bit machine changes
//!
//! **The result word.** A syscall answers one `i64` (`docs/api/01`), and this
//! machine's `a0` is 32 bits. Widening a failure is lossless — six domains and
//! small codes — and so is a success that is a handle, a count or an address.
//! One that is not, the port refuses rather than truncates, exactly as
//! `//userspace/uabi` refuses an argument too wide to place (D259). Between
//! them the two halves of the boundary agree about width, and neither narrows
//! anything silently.
//!
//! Normative: docs/api/01-system-call-interface.md ("The Result Word"),
//! docs/hardware/01-platform-and-cpu-support.md ("Endianness And Word Size")

use crate::*;
use core::sync::atomic::{AtomicU32, Ordering};
use tessera_karch_riscv32::KernelAddressSpace;

/// The process table. A static, const-initialized in `.bss`, because a
/// `ProcessTable` is far too large to build on the boot stack — the same
/// large-object hazard every other port holds it for.
pub(crate) static mut KCORE_PROCESSES: kcore::process::ProcessTable<KernelAddressSpace> =
    kcore::process::ProcessTable::new();

/// The executive owning this check's scheduler and channels.
pub(crate) static mut KCORE_EXEC: Option<kcore::exec::Executive<ContextSwitch>> = None;

/// The boot allocator, published for the duration of a run.
///
/// A raw pointer because the trap hook is a bare function the vector calls
/// with nothing but a frame: anything a syscall needs has to reach it through
/// a fixed place. Null outside a run, and a syscall arriving then is a check
/// that forgot to publish it rather than a null dereference.
pub(crate) static mut DISPATCH_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
    core::ptr::null_mut();

/// What the running program reported, and why a run ended.
///
/// **`AtomicU32`, and on this port that is not a narrowing.** Every value here
/// arrives in a 32-bit register — an exit code, a `scause`, a reported word —
/// so a 64-bit cell would be a wider box around the same value. `core` has no
/// `AtomicU64` on this target at all (`kcore::atomic` supplies a
/// software-emulated one for the places that genuinely need the width), which
/// is the machine saying the same thing.
pub(crate) static USER_EXIT: AtomicU32 = AtomicU32::new(0);
pub(crate) static USER_EXITED: AtomicU32 = AtomicU32::new(0);
pub(crate) static SUBSTRATE_FAULT: AtomicU32 = AtomicU32::new(0);

/// The executive, through one place — for the reason
/// `tools/ci/arch-lint-baseline.txt` gives: every reach for a `static mut` is a
/// `deref_addrof` finding, and one accessor is one finding rather than as many
/// as it has callers.
///
/// # Safety
///
/// The caller must be the boot hart with no other borrow of `KCORE_EXEC` live.
pub(crate) unsafe fn kcore_exec() -> Option<&'static mut kcore::exec::Executive<ContextSwitch>> {
    // SAFETY: the caller's obligation, stated above.
    unsafe { (*(&raw mut KCORE_EXEC)).as_mut() }
}

/// The process table, through one place — as [`kcore_exec`].
///
/// # Safety
///
/// The caller must be the boot hart with no other borrow live.
pub(crate) unsafe fn kcore_processes()
-> &'static mut kcore::process::ProcessTable<KernelAddressSpace> {
    // SAFETY: the caller's obligation, stated above.
    unsafe { &mut *(&raw mut KCORE_PROCESSES) }
}

/// Builds or restarts the executive with `quantum` ticks per thread.
///
/// # Safety
///
/// The caller must be the boot hart with no thread running.
pub(crate) unsafe fn kcore_exec_restart(quantum: u32) {
    // SAFETY: the caller's contract, restated. `<*mut T>::as_mut` rather than
    // an immediate dereference, for the reason the accessors above give.
    unsafe {
        match (&raw mut KCORE_EXEC).as_mut().and_then(Option::as_mut) {
            Some(exec) => exec.restart(quantum, 0),
            None => (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(quantum, 0))),
        }
    }
}

/// The widest success a syscall result register holds on this machine.
///
/// **The kernel's half of D259's agreement.** `//userspace/uabi` refuses an
/// argument too wide for a register; this refuses a *result* too wide to come
/// back in one. Neither truncates, because a handle or an address that lost its
/// high half is a different handle or address and nothing downstream could
/// tell.
///
/// A failure is never affected: `-((domain << 16) | code)` over six domains and
/// small codes is far inside a signed 32-bit word.
const MAX_RESULT: i64 = i32::MAX as i64;

/// Narrows a dispatch result into this machine's return register, or answers
/// the kernel-domain `ResultTooLarge` for one that does not fit.
fn narrow_result(value: i64) -> u32 {
    if value > MAX_RESULT || value < i32::MIN as i64 {
        return tessera_karch::encode_error(tessera_karch::KError::ResultTooLarge) as u32;
    }
    value as u32
}

/// Ends the running thread and switches to the next ready one — to the boot
/// context only when nothing is runnable.
///
/// `exit_current`, not terminate-and-yield-to-boot: a run that ended at the
/// first exit would abandon a still-ready peer, which is the lesson D82 paid
/// for on another port and this one inherits rather than relearns.
pub(crate) fn end_user_thread() {
    // SAFETY: the boot hart, cooperative; the executive is built before any
    // thread runs.
    if let Some(exec) = unsafe { kcore_exec() } {
        exec.scheduler().exit_current();
    }
}

/// The user trap hook: a `ecall` from U-mode goes to the shared dispatcher, and
/// what the dispatcher does not cover stays here.
///
/// **`DebugWrite` and `ProcessExit` are port-local on every port**, because
/// their semantics genuinely diverge: what a console is and what an exit does
/// to a run are the machine's business. Everything else is `kcore::dispatch`.
pub(crate) fn user_dispatch_hook(frame: &mut TrapFrame) {
    use kcore::dispatch::{DispatchEnv, DispatchOutcome, SyscallRequest, dispatch};
    use kcore::syscall::{SyscallNumber, encode_result};

    if frame.scause != EXCEPTION_ECALL_FROM_USER {
        SUBSTRATE_FAULT.store(frame.scause, Ordering::SeqCst);
        end_user_thread();
        return;
    }
    // SAFETY: the boot hart, cooperative; nothing else borrows the executive
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
        // A check forgot to publish the allocator. Fail loudly, never by
        // dereferencing null inside a covered arm.
        SUBSTRATE_FAULT.store(0xbad2, Ordering::SeqCst);
        end_user_thread();
        return;
    }

    let request = SyscallRequest {
        number: u64::from(frame.a7),
        args: [
            u64::from(frame.a0),
            u64::from(frame.a1),
            u64::from(frame.a2),
            u64::from(frame.a3),
            u64::from(frame.a4),
            u64::from(frame.a5),
        ],
    };
    // SAFETY: the boot hart, cooperative. The statics are initialized before
    // any thread runs and the frame pointer names the boot allocator for the
    // run's duration (checked non-null above). A blocking channel operation
    // parks this frame — the borrows in `env` included — on the blocked
    // thread's own kernel stack, and nothing dereferences them until the
    // handoff returns here.
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
            // This machine has no IOMMU and routes no device interrupt through
            // the port facility yet, and both say so rather than defaulting: a
            // device the graph says translates and that this cannot install a
            // translation for is a refusal, never a physical address.
            iommu: None,
            irqs: None,
        };
        dispatch(&mut env, &request)
    };

    match outcome {
        DispatchOutcome::Return(value) => {
            frame.a0 = narrow_result(value);
            frame.sepc += 4;
        }
        DispatchOutcome::Unhandled => match SyscallNumber::from_u64(u64::from(frame.a7)) {
            Some(SyscallNumber::DebugWrite) => {
                // The argument register, not a string behind it: a program
                // reporting a *value* passes it here with a length of zero, and
                // this port has no console for a user string anyway.
                let slot = REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
                if let Some(cell) = REPORTS.get(slot) {
                    cell.store(frame.a0, Ordering::SeqCst);
                }
                frame.a0 = narrow_result(encode_result(Ok(0)));
                frame.sepc += 4;
            }
            Some(SyscallNumber::ProcessExit) => {
                USER_EXIT.store(frame.a0, Ordering::SeqCst);
                USER_EXITED.fetch_add(1, Ordering::SeqCst);
                // Mark the process exited and hand back whoever was waiting on
                // it **before** this thread leaves the CPU — the order is what
                // makes a supervisor's wait return, and it is `kcore::loader`'s
                // to get right rather than this port's.
                // SAFETY: the boot hart, cooperative; both statics are this
                // run's, initialized before it started.
                unsafe {
                    if let Some(exec) = kcore_exec() {
                        kcore::loader::notify_exit(
                            exec,
                            kcore_processes(),
                            caller,
                            frame.a0 as i32,
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

/// What a program reported through `DebugWrite`, keyed by order.
///
/// Overflow is counted rather than dropped silently: `REPORT_COUNT` keeps
/// counting past the array, so a check expecting two reports and getting three
/// sees three.
const MAX_REPORTS: usize = 4;
pub(crate) static REPORTS: [AtomicU32; MAX_REPORTS] = [const { AtomicU32::new(0) }; MAX_REPORTS];
pub(crate) static REPORT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Where the compiled program's stacks go. Clear of the base
/// `user-riscv32.ld` links at (`0x1000_0000`) and of the blob check's own
/// windows.
const PROGRAM_USER_STACK_VA: u64 = 0x3000_0000;
const PROGRAM_USER_STACK_PAGES: u64 = 4;
/// The 4 MiB region the program's kernel stack lives in, and the stack itself
/// one page into it.
///
/// **Above `USER_ADDRESS_MAX` and above this machine's RAM**, which are two
/// separate requirements and both were got wrong first. This port's
/// `DIRECT_MAP_BASE` is **zero** — the kernel is identity-mapped because RAM
/// starts at the 2 GiB boundary (D106) — so `DIRECT_MAP_BASE + offset` is a
/// *user* address here, and a kernel stack placed that way lands where the
/// program's own text is linked.
///
/// **And the region must exist in the kernel root before any process root is
/// taken.** A process root copies the kernel half **by value**, so it shares
/// the kernel's second-level tables: a mapping made afterwards *inside* an
/// existing root entry is seen, and one that needs a **new** root entry is not.
/// Sv32 root entries span 4 MiB — far finer than Sv39's gibibyte — so an
/// arbitrary window almost always needs a new one, and the thread faults on its
/// own kernel stack in the trap vector's first store. The guard page below the
/// stack is what puts the entry in the kernel root first, and it is a guard
/// page on its own merits.
const PROGRAM_KSTACK_REGION: u64 = 0x9800_0000;
const PROGRAM_KSTACK_VA: u64 = PROGRAM_KSTACK_REGION + FRAME_SIZE;
const PROGRAM_KSTACK_PAGES: u64 = 8;
const PROGRAM_ASID: u16 = 12;

/// What the run produced.
pub(crate) struct ProgramReport {
    /// The exit code the program asked for.
    pub(crate) exit: u32,
    /// How many processes the table held after teardown — zero, or the check
    /// left a corpse behind.
    pub(crate) live_processes: usize,
    /// Frames the run drew and did not give back.
    pub(crate) frames_leaked: u64,
}

/// Runs a **compiled** ring-3 program on this 32-bit machine.
///
/// **The first one.** Everything ring-3 here until now was a hand-assembled
/// blob copied into a page: enough to show U-mode can be entered and contained,
/// and not a program — it could not be given an argument, could not be linked,
/// and could not grow. This loads a real ELF32 that a real compiler and linker
/// produced (D258, D259), starts it as a `Process` with a `Thread` on an
/// `Executive`, and reads back what it exited with.
///
/// `//userspace/restart-probe` because it is the smallest program that proves
/// the whole path rather than part of it: it exits with the argument it was
/// started with, so a run that returned the right code cannot have skipped the
/// load, the entry, the argument register, the `ecall`, or the exit.
pub(crate) fn compiled_program_check(
    kernel_space: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    image: &[u8],
    arg: usize,
) -> Result<ProgramReport, u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let drawn_before = frames.handed_out();
    // SAFETY: the boot hart alone; no thread runs.
    unsafe {
        kcore_exec_restart(4);
    }
    USER_EXIT.store(0, Ordering::SeqCst);
    USER_EXITED.store(0, Ordering::SeqCst);
    SUBSTRATE_FAULT.store(0, Ordering::SeqCst);

    let process_obj = kcore::object::ObjectId::from_raw(90);

    // The guard page, **before** the user space exists — see
    // `PROGRAM_KSTACK_REGION` for why the order is the whole point. Mapped
    // through an alias of the kernel space rather than through `kernel_space`
    // itself, which this check only holds by shared reference.
    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // into the kernel half and is never torn down.
    let mut kernel_alias = {
        let arch =
            unsafe { KernelAddressSpace::from_root(kernel_space.root_phys(), DIRECT_MAP_BASE) };
        AddressSpace::from_arch(arch, Asid(0), 0)
    };
    kernel_alias
        .map_anonymous(
            VirtAddr::new(PROGRAM_KSTACK_REGION),
            FRAME_SIZE,
            PageFlags::rw(),
            frames,
        )
        .map_err(|_| 2u32)?;

    let user_arch = kernel_space
        .new_user(frames, PROGRAM_ASID)
        .map_err(|_| 1u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(PROGRAM_ASID), 0);
    // `Machine::RiscV32` — the same `e_machine` a 64-bit RISC-V image carries,
    // so what makes this the right target is the ELF *class* (D258).
    let entry = kcore::elf::load_into(
        image,
        &mut user_space,
        frames,
        kcore::elf::Machine::RiscV32,
        10,
    )?;

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(entry),
        arg,
        VirtAddr::new(PROGRAM_USER_STACK_VA),
        PROGRAM_USER_STACK_PAGES,
        VirtAddr::new(PROGRAM_KSTACK_VA),
        PROGRAM_KSTACK_PAGES,
        process_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 20u32)?;

    // SAFETY: transient raw access; no thread runs yet.
    let (thread_idx, proc_idx) = unsafe {
        let exec = kcore_exec().ok_or(21u32)?;
        let thread_idx = exec.add_thread(thread).map_err(|_| 22u32)?;
        let id = exec.scheduler().thread_id(thread_idx).ok_or(23u32)?;
        let mut process = kcore::process::Process::new(process_obj, user_space);
        process.add_thread(id).map_err(|_| 24u32)?;
        let proc_idx = kcore_processes().insert(process).map_err(|_| 25u32)?;
        (thread_idx, proc_idx)
    };

    // Publish the allocator and run. A check that forgets it gets a program
    // that dies at its first syscall with nothing to say.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the boot hart alone; cleared after the run, and read only from
    // the hook while this run is on the CPU. The transmute erases the borrow's
    // lifetime; the pointer is used strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_riscv32::set_user_trap_hook(user_dispatch_hook);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        kcore_exec().ok_or(26u32)?.run();
    }
    // SAFETY: the run is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };

    let fault = SUBSTRATE_FAULT.load(Ordering::SeqCst);
    if fault != 0 {
        kprintln!("program: fault {fault:#x}");
        return Err(30);
    }
    if USER_EXITED.load(Ordering::SeqCst) != 1 {
        return Err(31);
    }

    // **Teardown, and it has to be complete.** A reaped thread still claimed by
    // a `Process` is the shape that shows up later as `AccessDenied` on a valid
    // pointer, and this port's next check would be the one to find it.
    // SAFETY: transient raw access; the run has ended and the thread is
    // off-CPU.
    let live_processes = unsafe {
        let processes = kcore_processes();
        if let Some(exec) = kcore_exec()
            && let Some(thread) = exec.scheduler().reap(thread_idx)
        {
            let _ = kernel_alias.reclaim_range(
                thread.kernel_stack_base(),
                thread.stack_bytes(),
                frames,
            );
            if let Some(process) = processes.get_mut(proc_idx) {
                process.forget_thread(thread.id());
            }
        }
        if let Some(mut process) = processes.remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
        // The slot this check used, asked for by hand: a `ProcessTable` has no
        // count, and the number that matters here is not how many processes
        // exist but whether *this* one is gone.
        usize::from(processes.get(proc_idx).is_some())
    };

    Ok(ProgramReport {
        exit: USER_EXIT.load(Ordering::SeqCst),
        live_processes,
        frames_leaked: frames.handed_out() - drawn_before,
    })
}
