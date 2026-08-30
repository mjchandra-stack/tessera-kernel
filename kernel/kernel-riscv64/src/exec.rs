// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The Executive: two U-mode processes exchange a message over a channel.
//!
//! The dispatcher is `kcore::dispatch` (D79) and the hook here only supplies the
//! machine's half of it. `sstatus.SUM` is required for the copies and cannot be
//! scoped per-copy on this architecture (D101).
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
// The Executive: two U-mode processes exchange a message over a channel
// ---------------------------------------------------------------------------

/// The request the client sends, handed to it as its thread argument rather
/// than compiled into the program, so the value that comes back is traceable
/// to something the kernel put there.
pub(crate) const IPC_MAGIC: u64 = 0xf00d_cafe_f00d_cafe;
/// What the server XORs into the request to make the reply. A reply that is
/// merely an echo would be satisfied by a channel that never carried anything.
pub(crate) const IPC_REPLY_XOR: u64 = 0x5a5a_5a5a;

/// The two processes' user mappings. Both use the *same* addresses — they have
/// their own roots, and D99 established what that means.
pub(crate) const IPC_USER_CODE_VA: u64 = 0x1200_0000;
pub(crate) const IPC_USER_STACK_VA: u64 = 0x2200_0000;

/// Kernel stacks, in the gigabyte slot the direct map already populates — the
/// D100 constraint, which every kernel mapping made after a process root is
/// copied has to respect.
pub(crate) const IPC_SERVER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb400_0000;
pub(crate) const IPC_CLIENT_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb800_0000;
/// Deeper than D100's: a blocking channel handoff parks a whole dispatch frame
/// on this stack.
pub(crate) const IPC_KSTACK_PAGES: u64 = 4;

pub(crate) const IPC_SERVER_ASID: u16 = 4;
pub(crate) const IPC_CLIENT_ASID: u16 = 5;

/// The executive carrying both threads, their channel, and the scheduler.
pub(crate) static mut KCORE_EXEC: Option<kcore::exec::Executive<ContextSwitch>> = None;

/// The boot allocator, exposed to the dispatch hook for the duration of a
/// check. Null outside it, and a null read is a distinct failure rather than a
/// dereference.
pub(crate) static mut DISPATCH_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
    core::ptr::null_mut();

/// Which scheduler slot each program landed in, so the hook can attribute a
/// report to the thread that made it. Distinguishing *who* logged what is the
/// difference between "a value crossed" and "the value crossed in the right
/// direction".
pub(crate) static IPC_SERVER_THREAD: AtomicU64 = AtomicU64::new(u64::MAX);
pub(crate) static IPC_CLIENT_THREAD: AtomicU64 = AtomicU64::new(u64::MAX);

/// Values reported by `DebugWrite`, in arrival order.
///
/// The IPC check attributes reports by *thread*, which separates two programs
/// making one report each. A single program making several needs the other
/// axis, so both exist: this array is keyed by order, which is a property of
/// the program rather than of the schedule.
pub(crate) const MAX_REPORTS: usize = 4;
pub(crate) static REPORTS: [AtomicU64; MAX_REPORTS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
pub(crate) static REPORT_COUNT: AtomicU64 = AtomicU64::new(0);

pub(crate) static IPC_SERVER_SAW: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPC_CLIENT_SAW: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPC_EXITS: AtomicU64 = AtomicU64::new(0);
pub(crate) static USER_FAULT: AtomicU64 = AtomicU64::new(0);
/// The address a contained user fault named (`stval`), and the cause the
/// crashing thread was running under.
///
/// Both are captured at fault time because that is the last moment they exist.
/// The address makes the crash-recovery ladder's first record say *what killed
/// the host* rather than merely which class of thing did; the cause is what
/// joins the restart to the crash, since the supervisor is reached through a
/// yield to boot whose ambient context is boot's own id.
pub(crate) static USER_FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
pub(crate) static USER_FAULT_CORRELATION: AtomicU64 = AtomicU64::new(0);

/// Whether a `DebugWrite` from a thread that is neither the IPC check's server
/// nor its client is expected.
///
/// The shared syscall hook flags an unrecognised reporter, which is right for
/// the IPC check — a third thread reporting there would mean the wrong process
/// answered. The driver checks collect reports from every driver they spawn
/// through `REPORTS`, so for them any thread is a legitimate reporter. Those
/// checks used to pass only because they ran *after* the IPC check and its
/// stale thread ids happened to match; saying so explicitly is what lets a
/// driver check run anywhere in the boot, which is how this was found.
pub(crate) static REPORTS_FROM_ANY_THREAD: AtomicBool = AtomicBool::new(false);

/// A `&mut` to the executive through its static. Provably initialized before
/// any thread runs.
/// The process table, through one place — for the reason
/// `tools/ci/arch-lint-baseline.txt` gives: every reach for a `static mut` is a
/// `deref_addrof` finding, and one accessor is one finding rather than as many
/// as there are callers.
///
/// # Safety
///
/// The caller must be the boot hart with no other borrow of `KCORE_PROCESSES`
/// live.
pub(crate) unsafe fn kcore_processes()
-> &'static mut kcore::process::ProcessTable<tessera_karch_riscv64::KernelAddressSpace> {
    // SAFETY: the caller's obligation, stated above.
    unsafe { &mut *(&raw mut KCORE_PROCESSES) }
}

/// The executive, or `None` before a check has built one — the fallible twin of
/// [`substrate_exec`], for the paths that must answer a syscall rather than end
/// the boot.
///
/// # Safety
///
/// The caller must be the boot hart with no other borrow of `KCORE_EXEC` live.
pub(crate) unsafe fn kcore_exec() -> Option<&'static mut kcore::exec::Executive<ContextSwitch>> {
    // SAFETY: the caller's obligation, stated above.
    unsafe { (*(&raw mut KCORE_EXEC)).as_mut() }
}

pub(crate) fn substrate_exec() -> &'static mut kcore::exec::Executive<ContextSwitch> {
    // As on the other ports (`kcore::exec::occupancy`).
    kcore::exec::occupancy::note_visit();
    // SAFETY: the boot CPU, cooperative; `KCORE_EXEC` is set in `ipc_check`
    // before any thread runs, and every channel handoff switches control, so
    // only one borrow is ever actively in flight.
    unsafe {
        match (*(&raw mut KCORE_EXEC)).as_mut() {
            Some(exec) => exec,
            None => {
                kprintln!("ipc: FATAL: executive used before it was built");
                TestFinisherExit::exit(ExitCode::Failure)
            }
        }
    }
}

/// Returns the executive to its starting state for the next demo.
///
/// **Restarts the one that exists rather than building a new one.** The two
/// are the same thing for the boot CPU and not for any other: since
/// build/README.md D233 each CPU has its own half of the executive, and a
/// fresh `Executive` brings fresh halves for all of them — so replacing it
/// would rebuild a running secondary's run queue underneath it, once per demo.
///
/// # Safety
///
/// The boot CPU alone, with no live borrow of the executive.
pub(crate) unsafe fn kcore_exec_restart(quantum: u32) {
    // SAFETY: the caller's contract, restated.
    unsafe {
        // `<*mut T>::as_mut` rather than an immediate dereference, for the
        // reason the accessor beside this one gives: it is the one form clippy
        // has no finding for.
        match (&raw mut KCORE_EXEC).as_mut().and_then(Option::as_mut) {
            Some(exec) => exec.restart(quantum, 0),
            None => (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(quantum, 0))),
        }
    }
}

/// Ends the running thread and switches to the next ready one — to the boot
/// context only when nothing is runnable. `exit_current`, not
/// terminate-and-yield-to-boot, which would end the whole run at the first
/// exit and abandon a still-ready peer (the D82 lesson, inherited rather than
/// relearned).
pub(crate) fn end_user_thread() {
    substrate_exec().scheduler().exit_current();
}

/// The port's syscall entry: a U-mode `ecall` decoded by the **shared**
/// `kcore::dispatch` (D79), with only the arch-coupled remainder handled here.
/// Shared by every Executive-substrate check on this port — a new syscall
/// needs nothing here, which is the substrate working as intended.
///
/// This is the whole point of the milestone. Nothing below knows what a
/// channel is; `dispatch` does, and it is the same code the other ports call.
/// What is port-local is the register ABI — `a7` names the syscall, `a0`-`a5`
/// carry its arguments, `a0` takes the result — and advancing `sepc`, which
/// this architecture leaves to the handler.
pub(crate) fn user_dispatch_hook(frame: &mut TrapFrame) {
    use kcore::dispatch::{DispatchEnv, DispatchOutcome, SyscallRequest, dispatch};
    use kcore::syscall::{SyscallNumber, encode_result};

    if frame.scause != EXCEPTION_ECALL_FROM_USER {
        USER_FAULT_ADDR.store(frame.stval, Ordering::SeqCst);
        USER_FAULT_CORRELATION.store(kcore::trace::current().correlation, Ordering::SeqCst);
        USER_FAULT.store(frame.scause, Ordering::SeqCst);
        end_user_thread();
        return;
    }
    let Some(caller) = substrate_exec().scheduler().current() else {
        USER_FAULT.store(0xbad0, Ordering::SeqCst);
        end_user_thread();
        return;
    };
    // Both, and they are not interchangeable — the same split `Executive::call`
    // makes: the slot indexes this hart's own arrays, the identity is what the
    // machine-wide process table holds.
    let Some(caller_id) = substrate_exec().scheduler().thread_id(caller) else {
        USER_FAULT.store(0xbad0, Ordering::SeqCst);
        end_user_thread();
        return;
    };
    // SAFETY: transient raw read of the check-scoped allocator pointer.
    let frames = unsafe { *(&raw const DISPATCH_FRAMES) };
    if frames.is_null() {
        // A check forgot to expose the allocator. Fail loudly, never by
        // dereferencing null inside a covered arm.
        USER_FAULT.store(0xbad2, Ordering::SeqCst);
        end_user_thread();
        return;
    }

    // The loader trio stays local; everything else the dispatcher answers.
    // They are local because each needs this port's `LoaderSupport` — the six
    // answers `kcore::loader` cannot give itself — and the seam is reachable
    // only while a root-task run has published it.
    if let Some(number) = SyscallNumber::from_u64(frame.a7)
        && matches!(
            number,
            SyscallNumber::ProcessCreate
                | SyscallNumber::AddressSpaceMap
                | SyscallNumber::ProcessStart
                | SyscallNumber::ProcessWait
        )
        // SAFETY: transient raw read of the check-scoped seam pointer; `None`
        // is a run with no root task, which answers `NotSupported` below.
        && unsafe { (*(&raw const roottask::ROOT_LOADER)).is_some() }
    {
        frame.a0 = root_loader_arm(number, caller_id, frame.a0, frames) as u64;
        frame.sepc += 4;
        return;
    }

    let request = SyscallRequest {
        number: frame.a7,
        args: [frame.a0, frame.a1, frame.a2, frame.a3, frame.a4, frame.a5],
    };
    let mut router = PlicRouter;
    // SAFETY: the boot CPU, cooperative. The statics are initialized by
    // `ipc_check` before `run()`, and `DISPATCH_FRAMES` points at the boot allocator
    // for the check's duration (checked non-null above). A blocking channel op
    // parks this frame — the borrows in `env` included — on the blocked
    // thread's own kernel stack, and nothing dereferences them until the
    // handoff returns here.
    let outcome = unsafe {
        let mut env = DispatchEnv {
            exec: match (*(&raw mut KCORE_EXEC)).as_mut() {
                Some(exec) => exec,
                None => {
                    USER_FAULT.store(0xbad3, Ordering::SeqCst);
                    end_user_thread();
                    return;
                }
            },
            processes: &mut *(&raw mut KCORE_PROCESSES),
            caller: caller_id,
            alloc: &mut *frames,
            // This machine has no IOMMU — `qemu-system-riscv64 -M virt` has no
            // IOMMU node at all — so no device has an aperture and every DMA
            // grant is unscoped, and says so (D121).
            iommu: None,
            // The interrupt controller, unlike the IOMMU, is not optional on
            // this machine: a departing capability whose route was dropped
            // from the graph but left unmasked at the PLIC is the
            // half-teardown the seam exists to prevent.
            irqs: Some(&mut router),
            clock: crate::exec::monotonic_nanos,
        };
        dispatch(&mut env, &request)
    };

    match outcome {
        DispatchOutcome::Return(value) => {
            frame.a0 = value as u64;
            frame.sepc += 4;
        }
        DispatchOutcome::Unhandled => match SyscallNumber::from_u64(frame.a7) {
            Some(SyscallNumber::DebugWrite) => {
                let slot = REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
                if slot < MAX_REPORTS {
                    REPORTS[slot].store(frame.a0, Ordering::SeqCst);
                }
                // Overflow is not silently dropped: `REPORT_COUNT` keeps
                // counting past the array, so a check that expected two
                // reports and got three sees three.
                let caller = caller as u64;
                if caller == IPC_SERVER_THREAD.load(Ordering::SeqCst) {
                    IPC_SERVER_SAW.store(frame.a0, Ordering::SeqCst);
                } else if caller == IPC_CLIENT_THREAD.load(Ordering::SeqCst) {
                    IPC_CLIENT_SAW.store(frame.a0, Ordering::SeqCst);
                } else if !REPORTS_FROM_ANY_THREAD.load(Ordering::SeqCst) {
                    USER_FAULT.store(0xbad4, Ordering::SeqCst);
                }
                frame.a0 = encode_result(Ok(0)) as u64;
                frame.sepc += 4;
            }
            Some(SyscallNumber::IrqComplete) => {
                // Arch-coupled: re-arming is an interrupt-controller write, so
                // it stays port-local rather than becoming a dispatch arm.
                frame.a0 = irq_complete(caller_id, frame.a0) as u64;
                frame.sepc += 4;
            }
            Some(SyscallNumber::ProcessExit) => {
                IPC_EXITS.fetch_add(1, Ordering::SeqCst);
                // Mark the process exited and hand back whoever was waiting on
                // it, **before** this thread leaves the CPU. The order is what
                // makes a supervisor's `ProcessWait` return, and it is
                // `kcore::loader`'s to get right rather than this port's.
                //
                // Without it a child exits, its thread ends, and the parent
                // stays parked on a wait nothing will complete: the run ends
                // with the root task still `Created` and no report at all,
                // which is a symptom that names neither the child nor the wait
                // (build/README.md, D257).
                // SAFETY: the boot CPU, cooperative; the executive and the
                // process table are this check's, initialized before it ran.
                unsafe {
                    if let Some(exec) = kcore_exec() {
                        kcore::loader::notify_exit(
                            exec,
                            kcore_processes(),
                            caller_id,
                            frame.a0 as i32,
                        );
                    }
                }
                end_user_thread();
            }
            _ => {
                USER_FAULT.store(0xbad1, Ordering::SeqCst);
                end_user_thread();
            }
        },
    }
}

/// The four process-lifecycle syscalls, answered out of `kcore::loader` against
/// this port's `LoaderSupport`.
///
/// **The lifecycle is not here.** What is here is the routing and the seam: the
/// creation, the mapping, the start and the wait are `kcore`'s, and they are
/// the same code x86-64 and AArch64 reach (build/README.md, D251, D257).
pub(crate) fn root_loader_arm(
    number: kcore::syscall::SyscallNumber,
    caller: kcore::thread::ThreadId,
    args_ptr: u64,
    frames: *mut kcore::pmem::BumpFrameAllocator<'static>,
) -> i64 {
    use kcore::syscall::{SyscallNumber, encode_result};

    // SAFETY: the boot CPU, cooperative. `ROOT_LOADER` is published by the
    // root-task check before its thread runs and taken after the run ends, so a
    // borrow here cannot outlive it; the frame pointer names the boot allocator
    // for the check's duration and was checked non-null by the caller.
    unsafe {
        let Some(support) = roottask::root_loader() else {
            return encode_result(Err(tessera_karch::KError::NotSupported));
        };
        let mut env = kcore::loader::LoaderEnv {
            support,
            objects: roottask::kcore_objects(),
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
                    roottask::note_launch();
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

// The two programs. Both build a `ChannelMsgArgs` (88 bytes, the ISL struct)
// on their own user stack — which `spawn_user` mapped through kcore's wrapper,
// so it is a *tracked* mapping and `validate_user_range` accepts a pointer
// into it. An untracked mapping would be a live page the syscall layer refuses
// to read, which is the intended behaviour and an easy self-inflicted wound.
//
// Register ABI: a7 = syscall number, a0 = args-struct pointer, a1 = endpoint
// handle (0 in both — the first install in a fresh handle table).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4

// Builds ChannelMsgArgs at sp+16 with an 8-byte inline buffer at sp+0.
.macro CHANNEL_ARGS
    li      t0, 88
    sw      t0, 16(sp)          // size
    li      t0, 4
    sw      t0, 20(sp)          // version — 4: v2 added the installed-handle
                                // report, v3 made the outgoing handle vector a
                                // HandleTransfer descriptor carrying the rights
                                // each capability arrives with, v4 gave that
                                // descriptor a TransferMode. All three are the
                                // same 88 bytes, so the kernel can only tell
                                // them apart by this word — it refuses a stale
                                // one rather than reading bare handle values
                                // as 16-byte descriptors.
    sd      zero, 24(sp)        // flags
    sd      zero, 32(sp)        // interface_id
    sd      zero, 40(sp)        // txn_id
    sw      zero, 48(sp)        // method_id
    sw      zero, 52(sp)        // msg_flags
    mv      t0, sp
    sd      t0, 56(sp)          // inline_ptr -> the buffer at sp+0
    li      t0, 8
    sd      t0, 64(sp)          // inline_len
    sd      zero, 72(sp)        // handles_ptr
    sd      zero, 80(sp)        // handle_count
    sd      zero, 88(sp)        // installed_ptr
    sd      zero, 96(sp)        // installed_cap
.endm

.globl ipc_server_blob_start
ipc_server_blob_start:
    addi    sp, sp, -128
    sd      zero, 0(sp)
    CHANNEL_ARGS
    addi    a0, sp, 16
    li      a1, 0
    li      a7, 13              // ChannelRecv — parks here until the client calls
    ecall
    bltz    a0, 91f             // a failed syscall must not look like a quiet
                                // zero in the buffer: report the code instead

    ld      a0, 0(sp)           // report what actually arrived
    li      a7, 1               // DebugWrite
    ecall

    ld      t1, 0(sp)           // reply = request ^ IPC_REPLY_XOR
    li      t2, 0x5a5a5a5a
    xor     t1, t1, t2
    sd      t1, 0(sp)
    addi    a0, sp, 16
    li      a1, 0
    li      a7, 27              // ChannelReplyContinue — reply and keep running.
                                // Plain ChannelReply would leave this thread
                                // blocked-but-unregistered; the project has
                                // paid for that lesson twice.
    ecall
    bltz    a0, 91f

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
91:                             // a0 holds the negative error code
    li      a7, 1               // DebugWrite
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl ipc_server_blob_end
ipc_server_blob_end:

.globl ipc_client_blob_start
ipc_client_blob_start:
    addi    sp, sp, -128
    sd      a0, 0(sp)           // a0 = the magic, handed over as the thread arg
    CHANNEL_ARGS
    addi    a0, sp, 16
    li      a1, 0
    li      a7, 14              // ChannelCall — blocks until the reply lands
    ecall
    bltz    a0, 92f

    ld      a0, 0(sp)           // the buffer is symmetric: request out, reply in
    li      a7, 1               // DebugWrite
    ecall

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
92:                             // a0 holds the negative error code
    li      a7, 1               // DebugWrite
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl ipc_client_blob_end
ipc_client_blob_end:
"#
);

// SAFETY: declares the blobs' bounding symbols, defined above.
unsafe extern "C" {
    pub(crate) static ipc_server_blob_start: u8;
    pub(crate) static ipc_server_blob_end: u8;
    pub(crate) static ipc_client_blob_start: u8;
    pub(crate) static ipc_client_blob_end: u8;
}

/// Builds one IPC process: its own root, its program, a user stack, a kernel
/// stack, and its endpoint installed at handle 0. Returns
/// `(thread_index, process_index)` — teardown needs both.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ipc_spawn_process(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blob: &[u8],
    kstack_va: u64,
    asid: u16,
    endpoint_object: kcore::object::ObjectId,
    arg: usize,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch = kernel_space.new_user(frames, asid).map_err(|_| base_err)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(asid), 0);

    // Mapped through the kcore wrapper rather than the arch space directly, so
    // the mapping is **tracked**: the syscall layer validates a user pointer
    // against this list, and an untracked page is one the kernel refuses to
    // read however live it is.
    user_space
        .map_anonymous(
            VirtAddr::new(IPC_USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| base_err + 1)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(IPC_USER_CODE_VA))
        .map(|(frame, _)| frame)
        .ok_or(base_err + 2)?;
    // Written through the direct map, which is how a read-execute page gets
    // its contents without ever being writable to anyone.
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(IPC_USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `kernel_space` is the active kernel space; this alias exists only
    // to map the kernel stack and is never torn down (it owns no tables).
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(IPC_USER_CODE_VA),
        arg,
        VirtAddr::new(IPC_USER_STACK_VA),
        1,
        VirtAddr::new(kstack_va),
        IPC_KSTACK_PAGES,
        endpoint_object,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| base_err + 3)?;

    // The D100 constraint, re-checked per process rather than assumed to hold
    // because it held once.
    if user_space
        .arch()
        .translate(VirtAddr::new(kstack_va))
        .is_none()
    {
        return Err(base_err + 4);
    }

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 5)?
            .add_thread(thread)
            .map_err(|_| base_err + 6)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(endpoint_object, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 7)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process
                .add_thread(thread_id_of(thread_idx)?)
                .map_err(|_| base_err + 8)?;
            // The first install in a fresh handle table lands at handle 0,
            // which both programs name.
            process
                .handles_mut()
                .install(endpoint_object, Rights::READ | Rights::WRITE)
                .map_err(|_| base_err + 9)?;
        }
    }
    Ok((thread_idx, proc_idx))
}

/// Two U-mode processes exchange a message over a channel.
///
/// The client `call`s with a magic and blocks; the server `receive`s it,
/// reports what arrived, `reply`s with a transform of it, and exits; the client
/// wakes with the reply in the same buffer it sent from and reports that.
/// Returns `(what the server saw, what the client got back, context switches)`.
///
/// Three things are being proven at once, and only the first is about IPC. The
/// message crosses an address-space boundary. The **scheduler chooses** — until
/// now this port had one runnable thread and could not tell a scheduler from a
/// jump. And the syscall arrives through `kcore::dispatch`, the same dispatcher
/// the other ports call, so this port stops having its own idea of what a
/// syscall is.
/// The identity of the thread in this hart's scheduler slot `idx`.
///
/// The process table is machine-wide and a slot is one hart's own numbering,
/// so a process claims the identity. Fails rather than guessing: a slot with no
/// thread in it has no identity to record, and recording a wrong one is how a
/// process comes to answer for somebody else's thread.
pub(crate) fn thread_id_of(idx: usize) -> Result<kcore::thread::ThreadId, u32> {
    // The executive's scheduler, because that is what admitted the thread at
    // every call site below. A slot means nothing outside the scheduler that
    // minted it, so asking the wrong one answers `None` for a slot that
    // certainly has a thread in it — which is how this first went wrong.
    substrate_exec().scheduler().thread_id(idx).ok_or(8u32)
}

pub(crate) fn ipc_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u64, u64, u64), u32> {
    use tessera_karch::AddressSpaceOps;

    // SAFETY: the boot CPU alone; written before any thread runs.
    unsafe {
        kcore_exec_restart(1);
    }
    let (server_ep, client_ep) = substrate_exec().channel_create().map_err(|_| 1u32)?;
    let server_obj = kcore::object::ObjectId::from_raw(20);
    let client_obj = kcore::object::ObjectId::from_raw(21);
    substrate_exec().bind_endpoint_object(server_ep, server_obj);
    substrate_exec().bind_endpoint_object(client_ep, client_obj);

    IPC_SERVER_SAW.store(0, Ordering::SeqCst);
    IPC_CLIENT_SAW.store(0, Ordering::SeqCst);
    IPC_EXITS.store(0, Ordering::SeqCst);
    USER_FAULT.store(0, Ordering::SeqCst);

    // SAFETY: linker-provided bounds of the read-only blobs above.
    let (server_blob, client_blob) = unsafe {
        (
            core::slice::from_raw_parts(
                &raw const ipc_server_blob_start,
                (&raw const ipc_server_blob_end as usize)
                    - (&raw const ipc_server_blob_start as usize),
            ),
            core::slice::from_raw_parts(
                &raw const ipc_client_blob_start,
                (&raw const ipc_client_blob_end as usize)
                    - (&raw const ipc_client_blob_start as usize),
            ),
        )
    };

    // The server is built first so it is scheduled first and is already parked
    // in `receive` when the client calls.
    let (server_idx, server_proc) = ipc_spawn_process(
        kernel_space,
        frames,
        server_blob,
        IPC_SERVER_KSTACK_VA,
        IPC_SERVER_ASID,
        server_obj,
        0,
        10,
    )?;
    let (client_idx, client_proc) = ipc_spawn_process(
        kernel_space,
        frames,
        client_blob,
        IPC_CLIENT_KSTACK_VA,
        IPC_CLIENT_ASID,
        client_obj,
        IPC_MAGIC as usize,
        30,
    )?;
    IPC_SERVER_THREAD.store(server_idx as u64, Ordering::SeqCst);
    IPC_CLIENT_THREAD.store(client_idx as u64, Ordering::SeqCst);

    // `dispatch` needs a live frame source; the channel arms allocate nothing
    // today, but a covered arm that does must not find a null pointer.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);
    let switches_before = substrate_exec().switch_count();
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.run();
        }
    }
    let switches = substrate_exec().switch_count() - switches_before;
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };

    // Control returned with a *process* root still in `satp`.
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(50);
    }
    let server_saw = IPC_SERVER_SAW.load(Ordering::SeqCst);
    if server_saw != IPC_MAGIC {
        return Err(51);
    }
    let client_saw = IPC_CLIENT_SAW.load(Ordering::SeqCst);
    if client_saw != IPC_MAGIC ^ IPC_REPLY_XOR {
        return Err(52);
    }
    if IPC_EXITS.load(Ordering::SeqCst) != 2 {
        return Err(53);
    }
    // A handoff, a wake and two exits cannot happen without the scheduler
    // actually switching. Asserting it beats inferring it from the values.
    if switches < 2 {
        return Err(54);
    }

    // SAFETY: transient raw access; both threads are Exited and off-CPU, and
    // each process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(server_idx);
        }
        for proc_idx in [client_proc, server_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
    }
    use tessera_karch::FrameSource;
    // SAFETY: as above — the alias owns no tables and is only used to unmap.
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = kernel_arch;
    for base in [IPC_SERVER_KSTACK_VA, IPC_CLIENT_KSTACK_VA] {
        for page in 0..IPC_KSTACK_PAGES {
            if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(base + page * FRAME_SIZE)) {
                frames.free_frame(frame);
            }
        }
    }

    Ok((server_saw, client_saw, switches))
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
    let ticks = <Cpu as CpuOps>::counter_serialized();
    match <Cpu as CpuOps>::counter_hz() {
        Some(hz) if hz > 0 => (ticks as u128 * 1_000_000_000u128 / hz as u128) as u64,
        _ => 0,
    }
}
