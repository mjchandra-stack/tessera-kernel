// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Wait-on-address, from ring 3.
//!
//! A thread parks on a word in its own memory and another wakes it — keyed on the
//! physical page, so two processes naming one page by different virtual addresses
//! wait on the same thing.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// ---- Wait-on-address (futex) ring-3 demo ------------------------------------

/// The futex word's user VA (kept in sync with the blob below). A dedicated
/// writable user page, separate from the read-execute code page.
pub(crate) const WAIT_WORD_VA: u64 = 0x0000_0000_0060_0000;
/// The futex word's **physical** address, published so the kernel waker keys
/// `wake` on the same word the ring-3 `wait` enrolled under.
///
/// The waker is a kernel thread with no user mapping of that page, so before
/// D240 it had to be told the process's address-space root and repeat the
/// user's virtual address. Physical keying is what makes the two agree without
/// either of them being in the other's address space — which is the whole
/// point of the change, stated in one static.
pub(crate) static WAIT_DEMO_PHYS: AtomicU64 = AtomicU64::new(0);
/// Set true when the ring-3 wait returned cleanly (woken, not error).
pub(crate) static WAIT_DEMO_WOKEN: AtomicBool = AtomicBool::new(false);
/// Threads the kernel waker reported waking (want 1).
pub(crate) static WAIT_DEMO_WAKE_COUNT: AtomicU64 = AtomicU64::new(u64::MAX);
/// The ring-3 exit code, stored `+1` so 0 means "not set".
pub(crate) static WAIT_DEMO_EXIT: AtomicU64 = AtomicU64::new(0);

// The ring-3 waiter. Publishes WAIT_EXPECTED into the futex word, waits on it
// (blocking in the kernel), and on wake exits with the wait's result — 0 for a
// clean wake. SYSCALL ABI: rax = number, args in rdi/rsi.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global wait_demo_program_start
.global wait_demo_program_end
wait_demo_program_start:
    mov rdi, 0x600000         # arg0 = futex word VA (keep == WAIT_WORD_VA)
    mov dword ptr [rdi], 1    # *word = 1 (the value we publish and wait on)
    mov esi, 1                # arg1 = expected value (matches the word above)
    mov eax, 6                # SyscallNumber::WaitOnAddress
    syscall                   # block until the kernel wakes us; rax = 0 on wake
    mov rdi, rax              # exit code = wait result (0 on clean wake)
    mov eax, 5                # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
wait_demo_program_end:
.text
"#
);

// SAFETY: names the wait-demo blob's bounds from the global_asm above; the
// extern block only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static wait_demo_program_start: u8;
    pub(crate) static wait_demo_program_end: u8;
}

/// The physical address `virt` resolves to in `process`, or `None` if it is
/// unmapped.
///
/// **The translation lives here and not in `kcore`**, for the same reason the
/// read of the futex word does: the address space and the validation of a user
/// pointer belong to the syscall entry. What `kcore` decides is only that a
/// futex key names physical memory (`kcore::wait`).
pub(crate) fn futex_phys(process: &Process<KernelAddressSpace>, virt: u64) -> Option<u64> {
    let (frame, _) = process.space().arch().translate(VirtAddr::new(virt))?;
    Some(frame.base().as_u64() + (virt % FRAME_SIZE))
}

/// What the futex check watches: that the ring-3 wait returned cleanly, and
/// with what code the waiter then exited.
///
/// `WaitOnAddress` and `WakeAddress` were this port's alone until D300 — the
/// only implementation of two syscall numbers in the tree lived in a demo
/// handler, so no other port could answer them and nothing outside this check
/// exercised the pair. They are `kcore::dispatch`'s now, and what stayed here
/// is the reading.
pub(crate) fn wait_observer(
    phase: crate::syscalls::Phase,
    number: SyscallNumber,
    frame: &SyscallFrame,
) {
    use crate::syscalls::Phase;
    match (phase, number) {
        (Phase::Answered(result), SyscallNumber::WaitOnAddress) if result >= 0 => {
            WAIT_DEMO_WOKEN.store(true, Ordering::Relaxed);
        }
        // Read on the way in: the exit never comes back to be answered.
        // Stored `+1` so 0 keeps meaning "the waiter never got here".
        (Phase::Entered, SyscallNumber::ProcessExit) => {
            WAIT_DEMO_EXIT.store(frame.arg0.wrapping_add(1), Ordering::Relaxed);
        }
        _ => {}
    }
}

/// The kernel waker: wakes the ring-3 waiter blocked on the futex word, then
/// parks so the scheduler runs the now-ready waiter (which returns from its wait
/// and exits). Never resumes after parking.
pub(crate) extern "C" fn wait_demo_waker(_arg: usize) -> ! {
    let exec = exec_ref();
    let woken = exec.wake(
        kcore::wait::WaitKey::at(WAIT_DEMO_PHYS.load(Ordering::Relaxed)),
        1,
    );
    WAIT_DEMO_WAKE_COUNT.store(woken as u64, Ordering::Relaxed);
    // Hand the CPU to the just-woken waiter by parking; it is now Ready.
    exec.scheduler().block_current();
    loop {
        core::hint::spin_loop();
    }
}

/// Wait-on-address: a ring-3 thread blocks on a user word via `WaitOnAddress`,
/// a kernel thread wakes the address, and the ring-3 thread resumes and exits
/// cleanly — proving the futex compare-and-block / wake path across the ring
/// boundary (the B6 primitive; docs/kernel/04 "Wait-On-Address"). The waiter
/// blocks *inside* its syscall and is resumed to return to ring 3.
pub(crate) fn wait_on_address_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(wait_observer);
    crate::syscalls::withdraw_frames();
    set_user_fault_handler(user_fault_handler);

    WAIT_DEMO_WOKEN.store(false, Ordering::Relaxed);
    WAIT_DEMO_EXIT.store(0, Ordering::Relaxed);
    WAIT_DEMO_WAKE_COUNT.store(u64::MAX, Ordering::Relaxed);

    // SAFETY: the boot CPU alone; the previous check's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    // The ring-3 waiter, built first so it runs first (and blocks) before the
    // kernel waker gets the CPU.
    let blob = &raw const wait_demo_program_start;
    let blob_len =
        (&raw const wait_demo_program_end as usize) - (&raw const wait_demo_program_start as usize);
    let (mut process, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        blob_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    // The futex word lives on its own writable page (the code page is rx).
    if let Err(e) = process.space_mut().map_anonymous(
        VirtAddr::new(WAIT_WORD_VA),
        FRAME_SIZE,
        PageFlags::rw().user(),
        frames,
    ) {
        panic!("wait demo: map word failed: {e:?}");
    }
    // ...and where that page physically is, which is what both sides key on.
    match futex_phys(&process, WAIT_WORD_VA) {
        Some(phys) => WAIT_DEMO_PHYS.store(phys, Ordering::Relaxed),
        None => panic!("wait demo: futex word has no translation"),
    }

    // The kernel waker, added second so the waiter is already parked when it
    // runs.
    let waker = match Thread::<ContextSwitch>::spawn(
        wait_demo_waker,
        0,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("wait demo: spawn waker failed: {e:?}"),
    };
    if exec_ref().add_thread(waker).is_err() {
        panic!("wait demo: add waker failed");
    }

    process.set_running();
    if processes_insert(process).is_err() {
        panic!("wait demo: insert process failed");
    }
    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let woken = WAIT_DEMO_WOKEN.load(Ordering::Relaxed);
    let wake_count = WAIT_DEMO_WAKE_COUNT.load(Ordering::Relaxed);
    let exit = WAIT_DEMO_EXIT.load(Ordering::Relaxed);
    let pass = woken && wake_count == 1 && exit == 1;
    report(&verdict(DemoId::WaitOnAddress, pass, [0; 8]));
    if !pass {
        kprintln!(
            "wait-demo: FAIL woken={woken} wake_count={wake_count} exit_code={}",
            (exit.wrapping_sub(1)) as i64
        );
    }
}
