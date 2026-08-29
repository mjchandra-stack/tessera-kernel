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

/// [`futex_phys`] as a key.
pub(crate) fn futex_key(
    process: &Process<KernelAddressSpace>,
    virt: u64,
) -> Option<kcore::wait::WaitKey> {
    futex_phys(process, virt).map(kcore::wait::WaitKey::at)
}

/// The wait-demo syscall dispatcher: `WaitOnAddress` reads the validated user
/// word and parks on the shared executive (blocking *inside* the syscall until
/// the kernel waker wakes the address); `WakeAddress` wakes; `ProcessExit`
/// records the code and yields to boot. Runs in kernel context on the user
/// thread's kernel stack, with the user address space active.
pub(crate) fn wait_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    // SAFETY: the boot CPU alone; USER_PROCESS is set before the ring-3 thread runs.
    let process = match unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        Some(process) => process,
        None => return syscall::ENOSYS,
    };
    match SyscallNumber::from_u64(frame.number) {
        Some(SyscallNumber::WaitOnAddress) => {
            let Some(key) = futex_key(process, frame.arg0) else {
                return encode_result(Err(KError::NotMapped));
            };
            let addr = frame.arg0;
            // **The word is read by the executive, not before it.** The
            // closure is this entry's own validated read; what changed is when
            // it runs — inside the hold that enrolls the waiter, so a wake on
            // another CPU cannot land between the read and the enrollment
            // (build/README.md, D240).
            let result = exec_ref().wait_on_address(key, frame.arg1, || {
                let mut word = [0u8; 4];
                read_user(process, addr, &mut word)?;
                Ok(u32::from_le_bytes(word) as u64)
            });
            if result.is_ok() {
                WAIT_DEMO_WOKEN.store(true, Ordering::Relaxed);
            }
            encode_result(result.map(|()| 0))
        }
        Some(SyscallNumber::WakeAddress) => {
            let Some(key) = futex_key(process, frame.arg0) else {
                return encode_result(Err(KError::NotMapped));
            };
            let woken = exec_ref().wake(key, frame.arg1 as u32);
            encode_result(Ok(woken as u64))
        }
        Some(SyscallNumber::ProcessExit) => {
            WAIT_DEMO_EXIT.store(frame.arg0.wrapping_add(1), Ordering::Relaxed);
            process.exit(frame.arg0 as i32);
            exec_ref().scheduler().yield_to_boot();
            0
        }
        _ => syscall::ENOSYS,
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
    unsafe { set_syscall_handler(wait_syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("wait demo: new_user failed: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(
        user_arch,
        alloc_asid(),
        1u64 << kcore::percpu::current_index(),
    );
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => panic!("wait demo: object create failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    let user = PageFlags::rw().user();
    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(USER_CODE_VA), code_len, user, frames)
    {
        panic!("wait demo: map code failed: {e:?}");
    }
    // The futex word lives on its own writable page (the code page becomes rx).
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(WAIT_WORD_VA), FRAME_SIZE, user, frames)
    {
        panic!("wait demo: map word failed: {e:?}");
    }
    // ...and where that page physically is, which is what both sides key on.
    match futex_phys(&process, WAIT_WORD_VA) {
        Some(phys) => WAIT_DEMO_PHYS.store(phys, Ordering::Relaxed),
        None => panic!("wait demo: futex word has no translation"),
    }

    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let exec = exec_ref();

    // The ring-3 waiter, added first so it runs first (and blocks) before the
    // kernel waker gets the CPU.
    let waiter = match Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("wait demo: spawn_user failed: {e:?}"),
    };
    let waiter_idx = match exec.add_thread(waiter) {
        Ok(idx) => idx,
        Err(e) => panic!("wait demo: add waiter failed: {e:?}"),
    };
    if process
        .add_thread(thread_id_of(waiter_idx).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        .is_err()
    {
        panic!("wait demo: process add_thread failed");
    }

    // The kernel waker.
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
    if exec.add_thread(waker).is_err() {
        panic!("wait demo: add waker failed");
    }

    // SAFETY: the user space shares the kernel higher-half; boot code, stack,
    // and the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(kcore::percpu::current_index()) };
    let code_src = &raw const wait_demo_program_start as *const u8;
    let code_bytes =
        (&raw const wait_demo_program_end as usize) - (&raw const wait_demo_program_start as usize);
    // SAFETY: the blob is in kernel rodata; USER_CODE_VA is a writable user page
    // in the now-active space with room for it.
    // The kernel means to reach a user page here: it is populating a
    // process it is building, in that process's own space. Declared
    // rather than assumed, because SMAP now faults an undeclared one.
    // SAFETY: the destination is a page this boot glue just mapped
    // into the space it activated; the window permits reaching it.
    {
        let _access = unsafe { kcore::useraccess::Window::open() };
        unsafe { core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes) };
    }
    if process
        .space_mut()
        .protect_range(
            VirtAddr::new(USER_CODE_VA),
            code_len,
            PageFlags::rx().user(),
        )
        .is_err()
    {
        panic!("wait demo: protect code failed");
    }
    // SAFETY: the boot CPU alone; publishing the running process.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }
    exec.run();
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
