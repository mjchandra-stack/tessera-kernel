// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Running a program at EL0: the address space it gets, the trap that brings
//! it back, and the process it becomes.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md

// The crate root holds this machine's statics, its layout constants and
// its object ids, and every check reaches for them. Naming them one by one
// would be a list to maintain rather than a boundary.
use crate::*;

pub(crate) fn alloc_asid() -> u16 {
    NEXT_ASID.fetch_add(1, Ordering::Relaxed) as u16
}

/// Where the harness resumes when the EL0 thread exits or faults, and the
/// throwaway the handler saves into on the way back. The EL0 thread never
/// resumes, so its abandoned kernel-stack frame is harmless.
pub(crate) static mut EL0_RETURN_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> = None;
pub(crate) static mut EL0_SCRATCH_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> = None;

pub(crate) static EL0_LOG: AtomicU64 = AtomicU64::new(0);
pub(crate) static EL0_EXITED: AtomicBool = AtomicBool::new(false);
/// Syndrome of the last EL0 abort, or 0 if none — an EL0 run either exits
/// cleanly or faults, never both.
pub(crate) static EL0_FAULT_ESR: AtomicU64 = AtomicU64::new(0);
pub(crate) static EL0_FAULT_FAR: AtomicU64 = AtomicU64::new(0);

/// True for a data abort taken from a lower exception level (`ESR` class
/// `0b100100`).
pub(crate) fn is_data_abort_lower(esr: u64) -> bool {
    (esr >> 26) & 0x3f == 0b100100
}

/// The EL0 synchronous-exception handler: a `log` records its argument and
/// returns to EL0; an `exit` or any abort records what happened and switches
/// back to the harness (never returning to EL0).
pub(crate) fn el0_sync_hook(frame: &mut tessera_karch_aarch64::TrapFrame) {
    if tessera_karch_aarch64::is_svc(frame.esr) {
        if frame.x[8] == SYS_LOG {
            EL0_LOG.store(frame.x[0], Ordering::SeqCst);
            frame.x[0] = 0; // syscall return value
            return; // resume EL0 after the svc
        }
        // SYS_EXIT (or an unrecognized number): the thread is done.
        EL0_EXITED.store(true, Ordering::SeqCst);
    } else {
        EL0_FAULT_ESR.store(frame.esr, Ordering::SeqCst);
        EL0_FAULT_FAR.store(frame.far, Ordering::SeqCst);
    }
    el0_switch_back();
}

/// Abandons the EL0 thread and resumes the harness at its saved continuation.
pub(crate) fn el0_switch_back() {
    use tessera_karch::ContextOps;
    // SAFETY: single-threaded boot; both contexts were written by `run_el0`
    // before entering EL0, and this switches to the harness continuation,
    // which never switches back into the scratch context.
    unsafe {
        let scratch = &raw mut EL0_SCRATCH_CTX;
        let ret = &raw const EL0_RETURN_CTX;
        if let (Some(s), Some(r)) = ((*scratch).as_mut(), (*ret).as_ref()) {
            ContextSwitch::switch(s, r);
        }
    }
}

/// Writes `blob` into the user code page, publishes it to the instruction
/// stream, enters EL0 with `arg` in `x0`, and returns when the EL0 thread
/// exits or faults (via [`el0_switch_back`]). `low` is the active low-half
/// (`TTBR0`) space the user code lives in.
pub(crate) fn run_el0(low: &mut KernelAddressSpace, code: PhysFrame, blob: &[u8], arg: usize) {
    use tessera_karch::{AddressSpaceOps, ContextOps, UserContextOps};
    low.write_bytes_to_frame(code, 0, blob);
    low.sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    EL0_EXITED.store(false, Ordering::SeqCst);
    EL0_FAULT_ESR.store(0, Ordering::SeqCst);
    EL0_FAULT_FAR.store(0, Ordering::SeqCst);
    EL0_LOG.store(0, Ordering::SeqCst);

    let user_stack_top = VirtAddr::new(USER_STACK_VA + FRAME_SIZE);
    let kstack_top = VirtAddr::new(EL0_KSTACK_VA + EL0_KSTACK_PAGES * FRAME_SIZE);
    // SAFETY: `kstack_top` tops the EL0 thread's exclusively-owned kernel
    // stack, and `USER_CODE_VA`/`user_stack_top` are the just-mapped user code
    // and stack, EL0-accessible in this (active) address space.
    let user_ctx = unsafe {
        ContextSwitch::init_user(kstack_top, VirtAddr::new(USER_CODE_VA), user_stack_top, arg)
    };

    // SAFETY: single-threaded boot; `EL0_RETURN_CTX`/`EL0_SCRATCH_CTX` are
    // written here before the switch that reads them.
    unsafe {
        (&raw mut EL0_RETURN_CTX).write(Some(ContextSwitch::empty()));
        (&raw mut EL0_SCRATCH_CTX).write(Some(ContextSwitch::empty()));
        let ret = &raw mut EL0_RETURN_CTX;
        if let Some(r) = (*ret).as_mut() {
            // Save the harness into the return context and drop to EL0; control
            // comes back here when the handler switches into that saved context.
            ContextSwitch::switch(r, &user_ctx);
        }
    }
}

/// Proves EL0 works: a user program enters ring 3, makes a syscall carrying a
/// register, its W^X violation faults, and its attempt to read kernel memory
/// faults — all contained, the kernel surviving each. Returns the logged
/// value, or the index of the first failing sub-check.
pub(crate) fn el0_check(
    high: &mut KernelAddressSpace,
    low: &mut KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use tessera_karch::AddressSpaceOps;

    // The user program's slice lands in the low half (`TTBR0`): user code (rx,
    // EL0) and user stack (rw, EL0). The EL0 thread's kernel stack is high-half
    // (`TTBR1`) kernel memory — the EL1 vector lands on it when EL0 traps. W^X
    // and the EL0/EL1 permission split are enforced by `map`'s flag handling.
    let code = frames.alloc().ok_or(1u32)?;
    low.map(
        VirtAddr::new(USER_CODE_VA),
        code,
        PageFlags::rx().user(),
        frames,
    )
    .map_err(|_| 2u32)?;
    let ustk = frames.alloc().ok_or(3u32)?;
    low.map(
        VirtAddr::new(USER_STACK_VA),
        ustk,
        PageFlags::rw().user(),
        frames,
    )
    .map_err(|_| 4u32)?;
    for page in 0..EL0_KSTACK_PAGES {
        let f = frames.alloc().ok_or(5u32)?;
        high.map(
            VirtAddr::new(EL0_KSTACK_VA + page * FRAME_SIZE),
            f,
            PageFlags::rw().global(),
            frames,
        )
        .map_err(|_| 6u32)?;
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_sync_hook);

    // 1: enter EL0, log a magic through a syscall, exit cleanly.
    const MAGIC: u64 = 0x5e17_c0de;
    run_el0(low, code, LOG_EXIT_BLOB, MAGIC as usize);
    if !EL0_EXITED.load(Ordering::SeqCst) {
        return Err(10);
    }
    if EL0_FAULT_ESR.load(Ordering::SeqCst) != 0 {
        return Err(11);
    }
    let logged = EL0_LOG.load(Ordering::SeqCst);
    if logged != MAGIC {
        return Err(12);
    }

    // 2: W^X — a store to the read-execute code page must fault, as a
    // write-direction data abort from EL0.
    run_el0(low, code, WX_BLOB, 0);
    let esr = EL0_FAULT_ESR.load(Ordering::SeqCst);
    if esr == 0 || !is_data_abort_lower(esr) || !tessera_karch_aarch64::is_write_fault(esr) {
        return Err(13);
    }

    // 3: the privilege boundary — EL0 reading a kernel address must fault. It
    // now rests on the half split itself: the kernel is only in `TTBR1`, which
    // grants no EL0 access, on top of the `AP=EL1-only` leaf bits. The kernel's
    // own text is the target.
    let kernel_addr = &raw const __text_start as usize;
    run_el0(low, code, KREAD_BLOB, kernel_addr);
    if EL0_FAULT_ESR.load(Ordering::SeqCst) == 0 {
        return Err(14); // EL0 must not be able to read kernel memory
    }

    Ok(logged)
}

/// Builds one process's low-half (`TTBR0`) address space: a fresh root with the
/// global device identity ([`build_low_space`]), its own ASID, and its user
/// code/stack/data pages — the data page seeded with `sentinel`. Returns the
/// space and its code frame (which [`run_el0`] writes the program into).
pub(crate) fn build_process(
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    sentinel: u64,
) -> Result<(KernelAddressSpace, PhysFrame), u32> {
    use tessera_karch::AddressSpaceOps;
    let mut space = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 30u32)?;
    space.set_asid(alloc_asid());

    let code = frames.alloc().ok_or(31u32)?;
    space
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 32u32)?;
    let stack = frames.alloc().ok_or(33u32)?;
    space
        .map(
            VirtAddr::new(USER_STACK_VA),
            stack,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 34u32)?;
    let data = frames.alloc().ok_or(35u32)?;
    space
        .map(
            VirtAddr::new(USER_DATA_VA),
            data,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 36u32)?;
    space.write_bytes_to_frame(data, 0, &sentinel.to_le_bytes());

    Ok((space, code))
}

/// Tears down a finished process space: unmap its user leaves (freeing those
/// frames) then free its page-table frames. The space must already be inactive.
pub(crate) fn free_process(space: &mut KernelAddressSpace, frames: &mut kcore::pmem::BumpFrameAllocator<'_>) {
    use tessera_karch::{AddressSpaceOps, FrameSource};
    for va in [USER_CODE_VA, USER_STACK_VA, USER_DATA_VA] {
        if let Ok(frame) = space.unmap(VirtAddr::new(va)) {
            frames.free_frame(frame);
        }
    }
    space.free_tables(frames);
}

/// Proves per-process address spaces: two EL0 processes run the same program in
/// **different** `TTBR0` spaces, each mapping [`USER_DATA_VA`] to its own frame,
/// and each reads back its own sentinel — so the per-process view is real and
/// isolated (a stale-TLB or shared-root bug would cross them). `high` maps the
/// shared EL0 kernel stack (already installed by [`el0_check`]); `boot_low` is
/// the device-bearing space to restore afterwards. Returns the two logged
/// sentinels, verified to match.
pub(crate) fn new_user_check(
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u64, u64), u32> {
    use tessera_karch::AddressSpaceOps;

    // Run one process to completion in its own space, returning its logged
    // value. `activate` swaps `TTBR0` (with the space's ASID) so the program
    // sees only this space's memory.
    let mut run = |sentinel: u64| -> Result<(u64, KernelAddressSpace), u32> {
        let (mut space, code) = build_process(frames, sentinel)?;
        // SAFETY: `space` maps this process's user pages; the kernel it returns
        // into is in TTBR1 (untouched by the TTBR0 swap) and the EL0 kernel
        // stack is the shared high-half one, so the swap is safe.
        unsafe { space.activate() };
        run_el0(&mut space, code, READ_DATA_BLOB, 0);
        if !EL0_EXITED.load(Ordering::SeqCst) || EL0_FAULT_ESR.load(Ordering::SeqCst) != 0 {
            return Err(40);
        }
        Ok((EL0_LOG.load(Ordering::SeqCst), space))
    };

    let (log_a, mut space_a) = run(SENTINEL_A)?;
    let (log_b, mut space_b) = run(SENTINEL_B)?;

    // Restore the device-bearing boot space before touching devices again or
    // freeing the process roots.
    // SAFETY: `boot_low` is the boot low-half space, which maps the device
    // identity the kernel needs; it was active before this check.
    unsafe { boot_low.activate() };
    free_process(&mut space_a, frames);
    free_process(&mut space_b, frames);

    // Each process read its own sentinel at the shared virtual address.
    if log_a != SENTINEL_A || log_b != SENTINEL_B {
        return Err(41);
    }
    Ok((log_a, log_b))
}

// --- EL0 on the kcore substrate (D75) ---

/// Kernel stack for the kcore-scheduled EL0 thread, mapped into the kernel
/// high half by `spawn_user`. Distinct from `EL0_KSTACK_VA` (which `el0_check`
/// already mapped into the same high half) so both coexist.
pub(crate) const KCORE_KSTACK_VA: u64 = 0xffff_0000_7000_0000;

/// Sentinel the kcore EL0 process stores at [`USER_DATA_VA`] in its own space
/// and reads back through the syscall — proving both that it was scheduled and
/// that its `TTBR0` was installed (an un-switched space would fault the read).
pub(crate) const KCORE_SENTINEL: u64 = 0xc0de_5ced_c0de_5ced;

/// EL0 program for the kcore path: read the u64 at [`USER_DATA_VA`], make a
/// `DebugWrite`(1) syscall carrying it, then `ProcessExit`(5). Same shape as
/// [`READ_DATA_BLOB`] but with kcore's syscall numbers in `x8`.
pub(crate) const KCORE_EL0_BLOB: &[u8] = &[
    0x01, 0x06, 0xa0, 0xd2, // movz x1, #0x30, lsl #16
    0x01, 0x00, 0xc2, 0xf2, // movk x1, #0x1000, lsl #32
    0x20, 0x00, 0x40, 0xf9, // ldr x0, [x1]
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1  (DebugWrite)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0xa8, 0x00, 0x80, 0xd2, // movz x8, #5  (ProcessExit)
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// The scheduler carrying the kcore EL0 thread. A static so the syscall hook
/// can reach it to end the thread; accessed only through raw pointers on the
/// single-threaded boot CPU (the executive-substrate discipline), never a held
/// `&mut` across a context switch.
pub(crate) static mut KCORE_SCHED: Option<kcore::sched::Scheduler<ContextSwitch>> = None;

/// The process table. A static (const-initialized, in `.bss`) because a
/// `ProcessTable` is far too large — 16 processes, each with a 1024-entry
/// handle table — to build on the 64 KiB boot stack (the large-object-on-stack
/// hazard); the x86 kernel holds `PROCESSES` the same way.
pub(crate) static mut KCORE_PROCESSES: kcore::process::ProcessTable<KernelAddressSpace> =
    kcore::process::ProcessTable::new();

pub(crate) static KCORE_EL0_LOG: AtomicU64 = AtomicU64::new(0);
pub(crate) static KCORE_EL0_EXITED: AtomicBool = AtomicBool::new(false);
pub(crate) static KCORE_EL0_FAULT: AtomicU64 = AtomicU64::new(0);

/// The kcore-substrate syscall hook: an EL0 `svc` is decoded through kcore's
/// `SyscallNumber` and handled minimally — `DebugWrite` records its argument
/// and resumes EL0; `ProcessExit` (or any abort) ends the thread and returns
/// to the scheduler's boot context.
///
/// Deliberately NOT routed through the shared `kcore::dispatch` (D79): this
/// check proves the pre-Executive bare-`Scheduler` substrate (D75), and the
/// dispatcher requires an `Executive`. The Executive-substrate checks all use
/// [`el0_dispatch_hook`].
pub(crate) fn kcore_el0_hook(frame: &mut tessera_karch_aarch64::TrapFrame) {
    use kcore::syscall::{SyscallNumber, encode_result};
    if tessera_karch_aarch64::is_svc(frame.esr) {
        match SyscallNumber::from_u64(frame.x[8]) {
            Some(SyscallNumber::DebugWrite) => {
                KCORE_EL0_LOG.store(frame.x[0], Ordering::SeqCst);
                frame.x[0] = encode_result(Ok(0)) as u64;
                return; // resume EL0 after the svc
            }
            Some(SyscallNumber::ProcessExit) => {
                KCORE_EL0_EXITED.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
    } else {
        KCORE_EL0_FAULT.store(frame.esr, Ordering::SeqCst);
    }
    end_kcore_thread();
}

/// Ends the running kcore EL0 thread and switches back to the scheduler's boot
/// context — the scheduler's own primitives, not the bespoke ping-pong.
pub(crate) fn end_kcore_thread() {
    // SAFETY: single-threaded boot; `KCORE_SCHED` was initialized before `run`
    // and is accessed only transiently here. `yield_to_boot` switches to the
    // saved boot context and never returns into this abandoned vector frame.
    unsafe {
        let sched = &raw mut KCORE_SCHED;
        if let Some(s) = (*sched).as_mut() {
            if let Some(cur) = s.current() {
                s.terminate(cur);
            }
            s.yield_to_boot();
        }
    }
}

/// Proves the kcore substrate carries an AArch64 EL0 process: a real
/// `kcore::Process` + `kcore::Thread` scheduled by `kcore::Scheduler`, entered
/// through the scheduler (which loads the process `TTBR0` via `prepare_resume`),
/// making a syscall decoded by `kcore::syscall`, and exiting back to boot.
/// Returns the logged sentinel, verified.
pub(crate) fn kcore_el0_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    // The process address space: a fresh low-half (TTBR0) root with the device
    // identity, wrapped by kcore. Map its code (with the program) and a data
    // page (with the sentinel) before it becomes the process's own.
    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 50u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(3), 0);

    let code = frames.alloc().ok_or(51u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 52u32)?;
    user_space
        .arch()
        .write_bytes_to_frame(code, 0, KCORE_EL0_BLOB);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    let data = frames.alloc().ok_or(53u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_DATA_VA),
            data,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 54u32)?;
    user_space
        .arch()
        .write_bytes_to_frame(data, 0, &KCORE_SENTINEL.to_le_bytes());

    // A kcore wrapper aliasing the live kernel high half, so `spawn_user` maps
    // the thread's kernel stack into the real kernel tables the EL1 vector uses.
    // SAFETY: `high` is the active kernel high-half space; the alias is only
    // used to map the kstack below and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(1),
        VirtAddr::new(USER_CODE_VA),
        KCORE_SENTINEL as usize,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(KCORE_KSTACK_VA),
        EL0_KSTACK_PAGES,
        kcore::object::ObjectId::from_raw(1),
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| 55u32)?;

    // A real kcore Process owns the address space, held in the static table.
    // SAFETY: single-threaded boot; the table is reached only through raw
    // pointers here (no held `&mut` spans a context switch).
    let proc_idx = unsafe {
        let process =
            kcore::process::Process::new(kcore::object::ObjectId::from_raw(1), user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 56u32)?
    };

    KCORE_EL0_LOG.store(0, Ordering::SeqCst);
    KCORE_EL0_EXITED.store(false, Ordering::SeqCst);
    KCORE_EL0_FAULT.store(0, Ordering::SeqCst);

    // SAFETY: single-threaded boot; initialized before any access, and the
    // scheduler is reached only through raw pointers here and in the hook.
    let thread_idx = unsafe {
        (&raw mut KCORE_SCHED).write(Some(kcore::sched::Scheduler::new(1, 0)));
        let s = (*(&raw mut KCORE_SCHED)).as_mut().ok_or(57u32)?;
        s.add_thread(thread).map_err(|_| 58u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| 59u32)?;
        }
    }

    tessera_karch_aarch64::set_el0_sync_hook(kcore_el0_hook);

    // Run the scheduler: it switches to the thread (loading its TTBR0 via
    // prepare_resume), the thread logs the sentinel and exits, and control
    // returns here when the hook yields to boot.
    // SAFETY: transient raw access; `run` returns when the thread yields to boot.
    unsafe {
        if let Some(s) = (*(&raw mut KCORE_SCHED)).as_mut() {
            s.run();
        }
    }

    // `yield_to_boot` returned here with the *process* TTBR0 still active;
    // restore the device-bearing boot space before its tables are freed (or
    // before the next console write).
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if !KCORE_EL0_EXITED.load(Ordering::SeqCst) || KCORE_EL0_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(60);
    }
    let logged = KCORE_EL0_LOG.load(Ordering::SeqCst);
    if logged != KCORE_SENTINEL {
        return Err(61);
    }

    // Teardown: reap the thread, free its kernel stack (mapped in the aliased
    // kernel space — unmap the leaves by hand, never tearing the alias down),
    // and remove the process (which reclaims the user space).
    // SAFETY: the thread is Exited and off-CPU, so reap is valid.
    unsafe {
        if let Some(s) = (*(&raw mut KCORE_SCHED)).as_mut() {
            s.reap(thread_idx);
        }
    }
    use tessera_karch::FrameSource;
    for page in 0..EL0_KSTACK_PAGES {
        if let Ok(frame) = kernel_space
            .arch_mut()
            .unmap(VirtAddr::new(KCORE_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }
    // Remove the process and reclaim its space — freeing the table slot so a
    // later run's threads do not collide with this one's stale thread index in
    // `process_of_thread` (the boot stack now has room to move the process out).
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }

    Ok(logged)
}

// --- IPC: a channel round-trip between two EL0 processes (D76) ---

/// The request magic the client sends and the server logs back — the proof the
/// message crossed the channel.
pub(crate) const IPC_MAGIC: u64 = 0xf00d_cafe_f00d_cafe;

/// Kernel stacks for the two IPC processes, in the kernel high half, distinct
/// from the other EL0 kstacks so all coexist.
pub(crate) const IPC_SERVER_KSTACK_VA: u64 = 0xffff_0000_8000_0000;
pub(crate) const IPC_CLIENT_KSTACK_VA: u64 = 0xffff_0000_9000_0000;
/// Deeper than the log/exit path: an IPC syscall handler parks on this stack
/// across a context switch (the channel `receive`/`call` block by switching).
pub(crate) const IPC_KSTACK_PAGES: u64 = 8;

/// Client program: build a `ChannelMsgArgs` (88 bytes, the ISL struct — D79,
/// widened by the installed-handle report)
/// on the tracked user stack page at `USER_STACK_VA`, describing the request
/// buffer at `USER_DATA_VA` (kernel-seeded with the magic), then
/// `ChannelCall`(14) and `ProcessExit`(5). Register ABI: x0=args-struct ptr,
/// x1=endpoint handle, x8=number.
pub(crate) const IPC_CLIENT_BLOB: &[u8] = &[
    0x09, 0x02, 0xa0, 0xd2, // movz x9, #0x10, lsl #16
    0x09, 0x00, 0xc2, 0xf2, // movk x9, #0x1000, lsl #32   (x9 = USER_STACK_VA)
    0x0a, 0x0b, 0x80, 0xd2, // movz x10, #0x58        (size = 88)
    0x8a, 0x00, 0xc0, 0xf2, // movk x10, #0x4, lsl #32     (| version 4 << 32)
    0x2a, 0x01, 0x00, 0xf9, // str x10, [x9]          (size|version)
    0x3f, 0x05, 0x00, 0xf9, // str xzr, [x9, #8]      (flags = 0)
    0x3f, 0x09, 0x00, 0xf9, // str xzr, [x9, #16]     (interface_id = 0)
    0x3f, 0x0d, 0x00, 0xf9, // str xzr, [x9, #24]     (txn_id = 0, kernel stamps)
    0x3f, 0x11, 0x00, 0xf9, // str xzr, [x9, #32]     (method_id|msg_flags = 0)
    0x0b, 0x06, 0xa0, 0xd2, // movz x11, #0x30, lsl #16
    0x0b, 0x00, 0xc2, 0xf2, // movk x11, #0x1000, lsl #32  (x11 = USER_DATA_VA)
    0x2b, 0x15, 0x00, 0xf9, // str x11, [x9, #40]     (inline_ptr)
    0x0c, 0x01, 0x80, 0xd2, // movz x12, #8
    0x2c, 0x19, 0x00, 0xf9, // str x12, [x9, #48]     (inline_len = 8)
    0x3f, 0x1d, 0x00, 0xf9, // str xzr, [x9, #56]     (handles_ptr = 0)
    0x3f, 0x21, 0x00, 0xf9, // str xzr, [x9, #64]     (handle_count = 0)
    0x3f, 0x25, 0x00, 0xf9, // str xzr, [x9, #72]     (installed_ptr = 0)
    0x3f, 0x29, 0x00, 0xf9, // str xzr, [x9, #80]     (installed_cap = 0)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0x01, 0x00, 0x80, 0xd2, // movz x1, #0            (endpoint handle 0)
    0xc8, 0x01, 0x80, 0xd2, // movz x8, #14           (ChannelCall)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0xa8, 0x00, 0x80, 0xd2, // movz x8, #5            (ProcessExit)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// Server program: build the same `ChannelMsgArgs` (its `inline_ptr`/`inline_len`
/// describe the receive buffer at `USER_DATA_VA`), `ChannelRecv`(13), read the
/// delivered magic and `DebugWrite`(1) it, then rewrite the descriptor to an
/// empty payload and `ChannelReply`(15). GPRs survive an svc (the trap frame
/// restores them), so x9/x11 stay live across the calls.
pub(crate) const IPC_SERVER_BLOB: &[u8] = &[
    0x09, 0x02, 0xa0, 0xd2, // movz x9, #0x10, lsl #16
    0x09, 0x00, 0xc2, 0xf2, // movk x9, #0x1000, lsl #32   (x9 = USER_STACK_VA)
    0x0a, 0x0b, 0x80, 0xd2, // movz x10, #0x58        (size = 88)
    0x8a, 0x00, 0xc0, 0xf2, // movk x10, #0x4, lsl #32     (| version 4 << 32)
    0x2a, 0x01, 0x00, 0xf9, // str x10, [x9]          (size|version)
    0x3f, 0x05, 0x00, 0xf9, // str xzr, [x9, #8]      (flags = 0)
    0x3f, 0x09, 0x00, 0xf9, // str xzr, [x9, #16]     (interface_id = 0)
    0x3f, 0x0d, 0x00, 0xf9, // str xzr, [x9, #24]     (txn_id = 0)
    0x3f, 0x11, 0x00, 0xf9, // str xzr, [x9, #32]     (method_id|msg_flags = 0)
    0x0b, 0x06, 0xa0, 0xd2, // movz x11, #0x30, lsl #16
    0x0b, 0x00, 0xc2, 0xf2, // movk x11, #0x1000, lsl #32  (x11 = USER_DATA_VA)
    0x2b, 0x15, 0x00, 0xf9, // str x11, [x9, #40]     (inline_ptr = recv buf)
    0x0c, 0x01, 0x80, 0xd2, // movz x12, #8
    0x2c, 0x19, 0x00, 0xf9, // str x12, [x9, #48]     (inline_len = 8)
    0x3f, 0x1d, 0x00, 0xf9, // str xzr, [x9, #56]     (handles_ptr = 0)
    0x3f, 0x21, 0x00, 0xf9, // str xzr, [x9, #64]     (handle_count = 0)
    0x3f, 0x25, 0x00, 0xf9, // str xzr, [x9, #72]     (installed_ptr = 0)
    0x3f, 0x29, 0x00, 0xf9, // str xzr, [x9, #80]     (installed_cap = 0)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0x01, 0x00, 0x80, 0xd2, // movz x1, #0            (endpoint handle 0)
    0xa8, 0x01, 0x80, 0xd2, // movz x8, #13           (ChannelRecv)
    0x01, 0x00, 0x00, 0xd4, // svc #0                 (returns n = 8)
    0x60, 0x01, 0x40, 0xf9, // ldr x0, [x11]          (x0 = delivered magic)
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1            (DebugWrite)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x3f, 0x15, 0x00, 0xf9, // str xzr, [x9, #40]     (inline_ptr = 0: empty reply)
    0x3f, 0x19, 0x00, 0xf9, // str xzr, [x9, #48]     (inline_len = 0)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0x01, 0x00, 0x80, 0xd2, // movz x1, #0            (endpoint handle 0)
    0xe8, 0x01, 0x80, 0xd2, // movz x8, #15           (ChannelReply)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// The executive carrying the IPC processes' threads and their channel. A
/// static reached only through raw pointers on the single-threaded boot CPU;
/// the channel ops re-enter it across a handoff, the executive-substrate
/// discipline (never a held `&mut` spanning a switch that a peer also borrows).
pub(crate) static mut KCORE_EXEC: Option<kcore::exec::Executive<ContextSwitch>> = None;

/// Shared result sinks for every Executive-substrate EL0 check (IPC,
/// MapDevice, DmaAlloc — D79). The checks run sequentially on the single boot
/// CPU; each resets them before `run()` and reads them after.
pub(crate) static EL0_SINK_LOG: AtomicU64 = AtomicU64::new(0);
pub(crate) static EL0_SINK_EXITED: AtomicBool = AtomicBool::new(false);
pub(crate) static EL0_SINK_FAULT: AtomicU64 = AtomicU64::new(0);
/// The cause the crashing EL0 thread was running under.
///
/// Captured at fault time because that is the last moment it exists: the
/// thread ends here, and the supervisor that answers the crash reaches it
/// through a yield back to boot, whose ambient context is boot's own id.
/// Without adopting this, every ladder record would root a fresh trace and
/// nothing would join a restart to the crash that provoked it — which is most
/// of what those records are for.
pub(crate) static EL0_SINK_FAULT_CORRELATION: AtomicU64 = AtomicU64::new(0);

/// The address a contained EL0 fault named (`FAR_EL1`).
///
/// Kept beside the syndrome rather than folded into it because the
/// crash-recovery ladder's first record is supposed to say *what killed the
/// host* — and "a data abort" without an address is a class of causes, not a
/// cause. A supervisor reporting only the syndrome would produce identical
/// records for a null dereference and a stray pointer.
pub(crate) static EL0_SINK_FAULT_ADDR: AtomicU64 = AtomicU64::new(0);

/// Reports kept **in order**, for checks that run one program more than once
/// and must tell the runs apart. [`EL0_SINK_LOG`] composes reporters by XOR,
/// which is the right shape for several programs reporting different things at
/// once, and the wrong one for the same program reporting the same thing twice
/// — those cancel. Both axes exist because both cases are real.
pub(crate) const MAX_EL0_REPORTS: usize = 4;
pub(crate) static EL0_REPORTS: [AtomicU64; MAX_EL0_REPORTS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
pub(crate) static EL0_REPORT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Clears the ordered reports before a check that reads them.
pub(crate) fn reset_el0_reports() {
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &EL0_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
}

/// The boot frame allocator, reachable from the (argument-less) dispatch hook
/// so covered syscalls can build page tables and DMA pages. A raw pointer
/// valid **only** while an Executive-substrate check runs (the allocator lives
/// on `kmain`'s stack); set before the process runs and cleared after.
pub(crate) static mut EL0_DISPATCH_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
    core::ptr::null_mut();

/// The SMMU, reachable from the same argument-less hook, so a `DmaAlloc` for a
/// device with an aperture can install the translation it hands back.
///
/// Null is not a default — it is this machine having no IOMMU, which every
/// boot without `iommu=smmuv3` genuinely is, and which the kernel core reports
/// on each grant (`DEVICE_DMA_UNSCOPED`). The same raw-pointer discipline as
/// [`EL0_DISPATCH_FRAMES`], except that the SMMU outlives one check: it is
/// brought up once and stays enabled, because disabling it between checks
/// would let a device reach memory in the gap.
pub(crate) static mut EL0_DISPATCH_IOMMU: *mut Smmu = core::ptr::null_mut();

