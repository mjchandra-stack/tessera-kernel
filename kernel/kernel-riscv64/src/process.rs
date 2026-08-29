// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kcore substrate: a real Process, Thread and Scheduler.
//!
//! The port stops running U-mode out of its own harness and runs it out of the
//! shared core, which is what makes a check here the same check as every other
//! port's.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// ---------------------------------------------------------------------------
// The kcore substrate: a real Process, Thread and Scheduler on this port
// ---------------------------------------------------------------------------

/// Where the kcore thread's kernel stack goes, and the constraint that fixes
/// it — which is a RISC-V problem the AArch64 port does not have.
///
/// The kernel half is copied **by value** into each process root
/// (`new_user`), so a kernel mapping made *after* a process exists is visible
/// to that process only if it needed no new **root** entry. A stack placed in
/// a fresh gigabyte slot would be mapped in the kernel space and absent from
/// every process — and the first trap taken by a user thread would fault on
/// its own kernel stack, with no stack to report it on.
///
/// So this sits in the gigabyte slot the direct map already populates, just
/// above where RAM ends on the reference machine. That is an assumption about
/// the platform, which is why the check *verifies* it from inside the process
/// space rather than trusting the arithmetic — and why a machine with enough
/// RAM to reach this address fails loudly at `map_anonymous` instead of
/// quietly overlapping the direct map.
pub(crate) const KCORE_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb000_0000;
pub(crate) const KCORE_KSTACK_PAGES: u64 = 4;

/// The kcore process's user mappings. Distinct from the D98/D99 addresses so
/// nothing is inherited from a space this check did not build.
pub(crate) const KCORE_USER_CODE_VA: u64 = 0x1100_0000;
pub(crate) const KCORE_USER_STACK_VA: u64 = 0x2100_0000;

/// ASID for the kcore process's space.
pub(crate) const KCORE_PROCESS_ASID: u16 = 3;

/// The value the thread logs through the syscall substrate.
pub(crate) const KCORE_SENTINEL: u64 = 0x7e55_e2a0_0000_0001;

/// The scheduler carrying the kcore U-mode thread. A static so the syscall
/// hook can reach it to end the thread; touched only through raw pointers on
/// the single-threaded boot CPU, never a held `&mut` across a switch.
pub(crate) static mut KCORE_SCHED: Option<kcore::sched::Scheduler<ContextSwitch>> = None;

/// The process table. A static in `.bss` because a `ProcessTable` is far too
/// large to build on a boot stack — the same reason the x86-64 and AArch64
/// kernels hold theirs this way.
pub(crate) static mut KCORE_PROCESSES: kcore::process::ProcessTable<
    tessera_karch_riscv64::KernelAddressSpace,
> = kcore::process::ProcessTable::new();

pub(crate) static KCORE_LOG: AtomicU64 = AtomicU64::new(0);
pub(crate) static KCORE_EXITED: AtomicU64 = AtomicU64::new(0);
pub(crate) static KCORE_FAULT: AtomicU64 = AtomicU64::new(0);

// The program the kcore thread runs: log the value it was started with, then
// exit. Two syscalls, both named by `kcore::syscall::SyscallNumber` rather
// than by this file — which is the difference between this check and D98's.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl kcore_blob_start
kcore_blob_start:
    mv      t0, a0
    li      a7, 1           // SyscallNumber::DebugWrite
    mv      a0, t0
    ecall
    li      a7, 5           // SyscallNumber::ProcessExit
    li      a0, 0
    ecall
    unimp
.globl kcore_blob_end
kcore_blob_end:
"#
);

// SAFETY: declares the blob's bounding symbols, defined above.
unsafe extern "C" {
    pub(crate) static kcore_blob_start: u8;
    pub(crate) static kcore_blob_end: u8;
}

/// Decodes a U-mode exception through kcore's syscall vocabulary.
///
/// Deliberately not routed through the shared `kcore::dispatch`: that requires
/// an `Executive`, and what this check is for is the layer below — that a
/// `Scheduler` can carry a `Thread` belonging to a `Process` on this port at
/// all.
pub(crate) fn kcore_user_trap(frame: &mut TrapFrame) {
    use kcore::syscall::{SyscallNumber, encode_result};
    if frame.scause == EXCEPTION_ECALL_FROM_USER {
        match SyscallNumber::from_u64(frame.a7) {
            Some(SyscallNumber::DebugWrite) => {
                KCORE_LOG.store(frame.a0, Ordering::SeqCst);
                frame.a0 = encode_result(Ok(0)) as u64;
                frame.sepc += 4;
                return;
            }
            Some(SyscallNumber::ProcessExit) => {
                KCORE_EXITED.store(1, Ordering::SeqCst);
            }
            _ => {
                KCORE_FAULT.store(u64::MAX, Ordering::SeqCst);
            }
        }
    } else {
        KCORE_FAULT.store(frame.scause, Ordering::SeqCst);
    }
    end_kcore_thread()
}

/// Ends the running kcore thread and returns to the scheduler's boot context —
/// the scheduler's own primitives, not D98's bespoke ping-pong.
pub(crate) fn end_kcore_thread() -> ! {
    // SAFETY: the boot CPU alone; `KCORE_SCHED` is initialized before `run`
    // and reached only transiently here. `yield_to_boot` switches to the saved
    // boot context and never returns into this abandoned trap frame.
    unsafe {
        let sched = &raw mut KCORE_SCHED;
        if let Some(s) = (*sched).as_mut() {
            if let Some(current) = s.current() {
                s.terminate(current);
            }
            s.yield_to_boot();
        }
    }
    // Not reachable: `yield_to_boot` does not come back.
    loop {
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// A real `kcore::Process` holding a `kcore::Thread`, scheduled by
/// `kcore::Scheduler`, entered in U-mode through `prepare_resume`, making a
/// syscall named by `kcore::syscall`, and exiting back to boot.
///
/// D99 proved the port can *hold* two address spaces. This proves the core can
/// *drive* one: from here the port shares the substrate every ring-3 feature
/// on AArch64 was built on, rather than a boot-glue harness that resembles it.
pub(crate) fn kcore_process_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // SAFETY: linker-provided bounds of the read-only blob above.
    let blob = unsafe {
        core::slice::from_raw_parts(
            &raw const kcore_blob_start,
            (&raw const kcore_blob_end as usize) - (&raw const kcore_blob_start as usize),
        )
    };

    let user_arch = kernel_space
        .new_user(frames, KCORE_PROCESS_ASID)
        .map_err(|_| 1u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(KCORE_PROCESS_ASID), 0);

    let code = frames.alloc_frame().ok_or(2u32)?;
    user_space.arch().zero_frame(code);
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(KCORE_USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 3u32)?;
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(KCORE_USER_CODE_VA), FRAME_SIZE);

    // A kcore wrapper *aliasing* the live kernel space, so the thread's kernel
    // stack is mapped into the real tables the trap vector walks — and, because
    // the kernel half is shared by pointer, into every process at once.
    // SAFETY: `kernel_space` is the active kernel space; this alias only maps
    // the kstack below and is never torn down (it owns none of its tables).
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(KCORE_USER_CODE_VA),
        KCORE_SENTINEL as usize,
        VirtAddr::new(KCORE_USER_STACK_VA),
        1,
        VirtAddr::new(KCORE_KSTACK_VA),
        KCORE_KSTACK_PAGES,
        kcore::object::ObjectId::from_raw(1),
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 4u32)?;

    // The stack was mapped into the *kernel* space after this process's root
    // was copied. On a single-root architecture that is only visible to the
    // process if it needed no new root entry — so it is checked, not assumed.
    // Getting this wrong faults on the first trap, with no stack to report on.
    if user_space
        .arch()
        .translate(VirtAddr::new(KCORE_KSTACK_VA))
        .is_none()
    {
        return Err(5);
    }

    // SAFETY: the boot CPU alone; the table is reached only through raw
    // pointers, and no `&mut` into it spans a context switch.
    let proc_idx = unsafe {
        let process =
            kcore::process::Process::new(kcore::object::ObjectId::from_raw(1), user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 6u32)?
    };

    KCORE_LOG.store(0, Ordering::SeqCst);
    KCORE_EXITED.store(0, Ordering::SeqCst);
    KCORE_FAULT.store(0, Ordering::SeqCst);

    // SAFETY: as above — initialized before any access, reached transiently.
    let thread_idx = unsafe {
        (&raw mut KCORE_SCHED).write(Some(kcore::sched::Scheduler::new(1, 0)));
        let sched = (*(&raw mut KCORE_SCHED)).as_mut().ok_or(7u32)?;
        sched.add_thread(thread).map_err(|_| 8u32)?
    };
    // The identity, not the slot: a slot is this hart's own numbering and the
    // process table is machine-wide.
    // SAFETY: transient raw access to the scheduler just written above.
    let thread_id = unsafe {
        (*(&raw mut KCORE_SCHED))
            .as_ref()
            .and_then(|s| s.thread_id(thread_idx))
            .ok_or(8u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process.add_thread(thread_id).map_err(|_| 9u32)?;
        }
    }

    tessera_karch_riscv64::set_user_trap_hook(kcore_user_trap);

    // SAFETY: transient raw access; `run` returns when the thread yields to
    // boot, which the hook does on exit or fault.
    unsafe {
        if let Some(sched) = (*(&raw mut KCORE_SCHED)).as_mut() {
            sched.run();
        }
    }

    // Control came back with the *process* root still in `satp`. Restore the
    // kernel's own space before anything frees the tables under it.
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if KCORE_EXITED.load(Ordering::SeqCst) != 1 || KCORE_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(10);
    }
    let logged = KCORE_LOG.load(Ordering::SeqCst);
    if logged != KCORE_SENTINEL {
        return Err(11);
    }

    // Teardown: reap the thread, unmap its kernel stack by hand (the alias
    // owns none of the tables it names and must never be torn down), then
    // remove the process, which reclaims the user space.
    // SAFETY: the thread is Exited and off-CPU, so reaping it is valid.
    unsafe {
        if let Some(sched) = (*(&raw mut KCORE_SCHED)).as_mut() {
            sched.reap(thread_idx);
        }
    }
    for page in 0..KCORE_KSTACK_PAGES {
        if let Ok(frame) = kernel_alias
            .arch_mut()
            .unmap(VirtAddr::new(KCORE_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }

    Ok(logged)
}
