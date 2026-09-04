// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Ring 3: the isolation bet, and the handlers that hold it.
//!
//! A program in its own address space that reaches the kernel only through the
//! validated syscall boundary, and whose fault is contained — the process dies,
//! the kernel lives.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- User-mode (ring 3) demonstration ---
//
// The isolation bet: run a program in ring 3, in its own address space, that
// reaches the kernel only through the validated SYSCALL boundary — and prove a
// fault in that program is *contained* (the process dies, the kernel lives).
// A hand-assembled position-independent ring-3 blob (below) issues a handful of
// syscalls (debug-write, null, handle duplicate, handle query) and then
// deliberately dereferences a null pointer; the kernel services the syscalls,
// catches the fault via the user-fault handler, terminates the process under
// the default policy, and returns to boot. None of this can happen under the
// host mock (there is no CPU privilege level), so it is proven here on hardware.

/// Ring-3 text base (low half, user space).
pub(crate) const USER_CODE_VA: u64 = 0x0000_0000_0040_0000;
pub(crate) const USER_CODE_PAGES: u64 = 1;
/// Ring-3 stack (low half).
pub(crate) const USER_STACK_BASE: u64 = 0x0000_0000_7000_0000;
pub(crate) const USER_STACK_PAGES: u64 = 4;
/// The user thread's kernel syscall/exception stack. In the kernel VMAP slot
/// (384) whose page tables the user space shares, and clear of the IPC demo's
/// stacks (…5/6000_0000) so the mapping does not collide.
pub(crate) const USER_KSTACK_PAGES: u64 = 4;

/// The ring-3 programs this image carries.
///
/// Under Bazel this is `//components:<arch>`, generated from the one list of
/// what the image is composed of. Under the cargo inner loop there is no such
/// crate — cargo builds no ring-3 ELFs — so the programs are absent and every
/// check that needs one reports it absent rather than failing to build.
#[cfg(has_components)]
pub(crate) use tessera_components as components;
#[cfg(not(has_components))]
pub(crate) mod components {
    pub fn root_task() -> &'static [u8] {
        &[]
    }
    pub fn device_manager() -> &'static [u8] {
        &[]
    }
    pub fn pci_bus() -> &'static [u8] {
        &[]
    }
    pub fn blk_probe() -> &'static [u8] {
        &[]
    }
    pub fn blk_driver() -> &'static [u8] {
        &[]
    }
    pub fn block_service() -> &'static [u8] {
        &[]
    }
    pub fn blk_client() -> &'static [u8] {
        &[]
    }
    pub fn c_probe() -> &'static [u8] {
        &[]
    }
    pub fn c_heap_probe() -> &'static [u8] {
        &[]
    }
    pub fn c_arg_probe() -> &'static [u8] {
        &[]
    }
    pub fn c_say_probe() -> &'static [u8] {
        &[]
    }
}

/// Round-trip observations, published by the handlers and checked on boot.
pub(crate) static USER_SYSCALLS: AtomicU64 = AtomicU64::new(0);
pub(crate) static USER_RING3_REACHED: AtomicBool = AtomicBool::new(false);
/// New handle from `sys_handle_duplicate`, stored `+1` so 0 means "not set".
pub(crate) static USER_DUP_HANDLE: AtomicU64 = AtomicU64::new(0);
pub(crate) static USER_QUERY_RIGHTS: AtomicU64 = AtomicU64::new(u64::MAX);
pub(crate) static USER_FAULT_CONTAINED: AtomicBool = AtomicBool::new(false);
pub(crate) static USER_FAULT_VECTOR: AtomicU64 = AtomicU64::new(u64::MAX);
pub(crate) static USER_FAULT_ADDR: AtomicU64 = AtomicU64::new(0);

// --- Driver-host restart on crash (fault observation + supervise counters) --
/// Set by `driver_fault_handler` when a supervised driver host faults (a real
/// #PF crash); the supervisor clears it before each launch and checks it after.
pub(crate) static DRIVER_HOST_FAULTED: AtomicBool = AtomicBool::new(false);
/// Real crashes observed across a run — the restart proof (`== countdown`).
pub(crate) static DRIVER_HOST_FAULTS_SEEN: AtomicU64 = AtomicU64::new(0);
/// Host launches across a run — bounds the budget self-test (`== budget` capped).
pub(crate) static DRIVER_HOST_LAUNCHES: AtomicU64 = AtomicU64::new(0);
/// The causal id of the host thread that just crashed, handed from the fault
/// handler to the supervisor. The supervisor runs on the boot context, whose
/// ambient id is boot's own; adopting this makes the crash-recovery records a
/// continuation of the crash's trace instead of an unrelated root
/// (docs/observability/02 — a stage inherits the item's id).
pub(crate) static DRIVER_HOST_CRASH_CORRELATION: AtomicU64 = AtomicU64::new(0);

// --- M14: user-space loader (ring-3 create/populate/start of a child) ---

/// The shared process table for the executive substrate: every ring-3 demo that
/// runs on `EXEC` (the loader/component-manager parent+child, the channel peers,
/// the driver host+client) registers its processes here. A syscall resolves its
/// *caller* by the running thread (`process_of_thread`) and a *process handle* to
/// its target (`process_of_id`), so the live processes share one dispatcher (the
/// handle→process bridge, D42).
pub(crate) static mut PROCESSES: ProcessTable<KernelAddressSpace> = ProcessTable::new();
/// The parent thread parked inside `ProcessStart` awaiting the child it started
/// (the synchronous start handoff, mirroring `Executive::call`/`reply`). `None`
/// when no start is in flight; the child's exit/fault takes it to hand back.
pub(crate) static mut PARENT_WAITER: Option<usize> = None;
/// Raw pointers to the boot kernel address space and frame allocator, so the
/// loader syscalls (which run in trap context, from a ring-3 caller) can create
/// child spaces and map into them. `_start` never returns, so both live for the
/// kernel's lifetime (the `RESOLVER_FRAMES` pattern).
pub(crate) static mut LOADER_KERNEL_VM: *mut AddressSpace<KernelAddressSpace> =
    core::ptr::null_mut();
/// The exit code the most-recently-exited child stashed for its waiting parent
/// (`i32::MIN` = none yet).
pub(crate) static LOADER_CHILD_EXIT: AtomicI32 = AtomicI32::new(i32::MIN);
/// Set once the child process has run in ring 3 and exited (loader round-trip).
pub(crate) static LOADER_CHILD_RAN: AtomicBool = AtomicBool::new(false);
/// The child process handle the parent obtained from `ProcessCreate`, stored
/// `+1` so 0 means "not observed".
#[allow(dead_code)] // one of a block of loader observation slots; the `+1`
// encoding is what makes 0 mean "not observed", and a hole in the block would
// read as a slot that was never needed.
pub(crate) static LOADER_CHILD_HANDLE: AtomicU64 = AtomicU64::new(0);
/// Set once the parent has resumed after the child it started exited.
pub(crate) static LOADER_PARENT_RESUMED: AtomicBool = AtomicBool::new(false);
/// Count of children launched under the loader handler — now pure observability
/// (the demo measures launches as the delta over a run). Reset per `cm_run`; no
/// longer a kstack slot, because the kstack is reclaimed and the window reused.
pub(crate) static CHILD_LAUNCHES: AtomicU64 = AtomicU64::new(0);

/// What the root task's run reported through `DebugWrite`, keyed by order.
///
/// **Because a report word is not a string.** This port's `DebugWrite` reads a
/// buffer, and a driver reporting a *value* passes it in the pointer register
/// with a length of zero — so the text path sees nothing and the number would
/// be lost. AArch64 records the argument register for the same reason and keys
/// the slots by order (`EL0_REPORTS`); this is that, on the port whose
/// `DebugWrite` also has a string to print.
///
/// Order, not a tag: `blk-probe` packs its answer into the word it also returns
/// failures in, so no bit in it is free to identify the sender with.
pub(crate) static ROOT_REPORTS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
pub(crate) static ROOT_REPORT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Launches the root task's run must produce: 1 for the grant probe, 1 for the log service that collects what the
/// others report, 3 for the
/// argument probe, 41 to bring the recovering service up (it counts 40 down to
/// 0), 3 for the one it gives up on, and 2 for the driver framework — the
/// device manager and the driver it binds (build/README.md, D256).
///
/// The argument probe's 3 are one program run three ways (D302): a path it
/// accepts, no arguments at all, and a path it refuses.
///
/// Asserted exactly rather than as a floor. A supervisor that restarted more
/// than its policy allows is as wrong as one that stopped early, and only an
/// equality catches the first.
pub(crate) const EXPECTED_CHILD_LAUNCHES: u64 = 1 + 1 + 3 + 41 + 3 + 2;

/// Frames the whole root-task run may draw.
///
/// **Bounded rather than proportional, which is the point.** Forty-five
/// launches each costing a child's page tables and stack would be several
/// hundred; clearing this says the draw is the live set's and not the launch
/// count's.
pub(crate) const ROOT_TASK_FRAME_BOUND: u64 = 192;
/// The child's ring-3 stack size. Its base comes from the parent over the ABI
/// (`ProcessStartArgs::stack` — the root task passes `0x6800_0000`, clear of the
/// parent's `USER_STACK_BASE`); the kernel maps this many pages there.
pub(crate) const CHILD_STACK_PAGES: u64 = 4;
/// The loader parent runs `ProcessCreate` in a syscall, which builds a whole
/// `Process` (its ~26 KiB handle table + address space) by value on this kernel
/// stack. In the unoptimized kernel build (no copy-elision) that spans several
/// stacked frames (`loader_process_create` → `Process::new` → `HandleTable::new`)
/// totalling ~66 KiB, so the parent needs far more than the usual 4-page ring-3
/// kernel stack (the M13 loader built the process on the large boot stack
/// instead). 32 pages (128 KiB) leaves comfortable margin; the child keeps the
/// standard 4-page stack.
pub(crate) const LOADER_PARENT_KSTACK_PAGES: u64 = 32;

// The ring-3 program. Position-independent: it addresses its own data
// RIP-relative and passes the SYSCALL ABI (rax=number; args in rdi/rsi/…). It
// runs at USER_CODE_VA after being copied there. The blob lives in kernel
// rodata; nothing ever executes it at its kernel address.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global user_program_start
.global user_program_end
user_program_start:
    lea rdi, [rip + 3f]        # debug_write(msg, len)
    mov esi, 25               # length of the message at 3: (keep in sync)
    mov eax, 1
    syscall
    xor eax, eax              # null()
    syscall
    xor edi, edi              # handle_duplicate(source = seeded handle raw 0,
    mov esi, 1                #                  new_rights = READ)
    mov eax, 2
    syscall
    mov edi, eax              # handle_query_rights(new handle)
    mov eax, 3
    syscall
    xor rcx, rcx              # deliberate null read -> #PF, contained
    mov rax, [rcx]
6:
    jmp 6b
3:
    .ascii "hello from ring 3 (cpl=3)"
4:
user_program_end:
.text
"#
);

// SAFETY: these name the ring-3 blob's bounds, defined by the global_asm block
// above; the extern block only declares them and introduces no unsafe operation.
unsafe extern "C" {
    pub(crate) static user_program_start: u8;
    pub(crate) static user_program_end: u8;
}

/// `sys_debug_write`: validate and copy a user string (via the shared kcore
/// copy layer), then print it. The 128-byte clamp is this port's console
/// policy, applied before the copy so the validated range never exceeds it.
pub(crate) fn user_debug_write(process: &Process<KernelAddressSpace>, ptr: u64, len: u64) -> i64 {
    const MAX: usize = 128;
    let n = core::cmp::min(len as usize, MAX);
    let mut buf = [0u8; MAX];
    if let Err(e) = read_user(process, ptr, &mut buf[..n]) {
        return encode_result(Err(e));
    }
    if let Ok(text) = core::str::from_utf8(&buf[..n]) {
        // **Short because three things share one line's budget.** A ring-3
        // text line is the port's module path, then this envelope, then a
        // message the program chose — and the boot script holds the whole
        // thing to 150 characters. `[debug_write]` named the syscall a reader
        // can already see and cost thirteen characters of every such line;
        // dropping it gave the budget back to the half that carries meaning
        // (D321).
        kprint!("  user: {text}\n");
    }
    encode_result(Ok(n as u64))
}

/// A frame source that never allocates, for dispatch arms that provably need
/// no frames on this port: x86-64 registers no MMIO device objects, so
/// `MapDevice`/`DmaAlloc` fail at capability resolution before any allocation
/// (they were `ENOSYS` before D79 — now they are capability-gated like every
/// other port). A future x86 MMIO path must thread a real allocator instead.
pub(crate) struct NoFrames;

impl FrameSource for NoFrames {
    fn alloc_frame(&mut self) -> Option<PhysFrame> {
        None
    }
}

/// What the isolation check watches: the two handle operations whose *answer*
/// is the evidence.
///
/// The check used to implement `HandleDuplicate` and `HandleQueryRights` itself
/// so that it could keep what they returned. It never wanted to answer them
/// differently — `kcore::dispatch` has answered both for every other port since
/// D79 — it wanted to see the answer, which is what an observer is for (D300).
pub(crate) fn user_observer(
    phase: crate::syscalls::Phase,
    number: SyscallNumber,
    _frame: &SyscallFrame,
) {
    use crate::syscalls::Phase;
    // The ABI's success encoding: a non-negative result carries the value.
    let Phase::Answered(result) = phase else {
        return;
    };
    if result < 0 {
        return;
    }
    match number {
        // `+1` so that zero keeps meaning "not observed" — handle raw 0 is a
        // real handle, and this check's seeded one is exactly that.
        SyscallNumber::HandleDuplicate => {
            USER_DUP_HANDLE.store(result as u64 + 1, Ordering::Relaxed);
        }
        SyscallNumber::HandleQueryRights => {
            USER_QUERY_RIGHTS.store(result as u64, Ordering::Relaxed);
        }
        _ => {}
    }
}

/// Emits the exception report `docs/kernel/03` requires — "the report contains
/// fault type, faulting address ... and a correlation ID". The id and the thread
/// identity come from the ambient context, which the scheduler published when the
/// faulting thread was switched in, so the report joins the trace of whatever
/// caused the fault (D59).
///
/// Safe to call from the trap path: the ring lock is only ever held by kernel
/// code, and a *ring-3* fault cannot interrupt a kernel lock holder.
pub(crate) fn report_contained_fault(vector: u64, fault_addr: u64) {
    kcore::event::emit(
        kcore::event::EventKind::UserFaultContained,
        kcore::event::Severity::Error,
        kcore::event::Component::Exception,
        [vector, fault_addr, 0, 0],
    );
}

/// The registered ring-3 fault handler: contains the fault under the default
/// policy (terminate the faulting process, D23) and switches to boot. A
/// kernel-mode fault never reaches here — it stays on the fatal path.
///
/// **It finds the faulting process by asking who faulted.** It used to exit
/// `USER_PROCESS` and yield `USER_SCHEDULER`, which named the single-process
/// demos' one process and one scheduler — so every *other* check that installed
/// this handler (the channel demo, the device-manager demo, the driver hosts)
/// would, on a fault, have terminated a stale process from an earlier check and
/// yielded a scheduler it had never populated. Nothing noticed because none of
/// them faults. Resolving the caller through the process table is what makes
/// the handler true for whoever installed it (D300).
pub(crate) fn user_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    USER_FAULT_ADDR.store(tessera_karch_x86_64::read_cr2(), Ordering::Relaxed);
    report_contained_fault(frame.vector, tessera_karch_x86_64::read_cr2());
    if let Some(caller) = chan_current_id()
        && let Some(process) = crate::loader::root_processes().process_of_thread(caller)
    {
        process.exit(-1);
    }
    // SAFETY: the boot CPU alone; EXEC is set before any ring-3 thread runs.
    match unsafe { (*&raw mut EXEC).as_mut() } {
        Some(exec) => exec.scheduler().yield_to_boot(),
        None => DebugExit::exit(ExitCode::Failure),
    }
    // yield_to_boot switched to the boot context; this thread never resumes.
    loop {
        core::hint::spin_loop();
    }
}

/// Builds a ring-3 process from the embedded blob, runs it, and asserts the
/// isolation bet held: ring 3 executed, the syscalls round-tripped, and the
/// deliberate user fault was contained without a kernel panic.
///
/// **On the executive substrate, like every other ring-3 check here** (D300).
/// It ran on a `Scheduler` and a `Process` of its own until then — the pair the
/// four checks below it also used — and that is why it needed a syscall handler
/// of its own: a second process substrate has no process table, so it cannot
/// build a `DispatchEnv`, so it cannot reach the shared dispatcher, so it has
/// to answer the calls itself. One process in the machine's table is the same
/// check with none of that.
pub(crate) fn user_mode_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration, before any ring-3 thread runs.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(user_observer);
    crate::syscalls::withdraw_frames();
    set_user_fault_handler(user_fault_handler);

    USER_DUP_HANDLE.store(0, Ordering::Relaxed);
    USER_QUERY_RIGHTS.store(u64::MAX, Ordering::Relaxed);
    USER_FAULT_CONTAINED.store(false, Ordering::Relaxed);

    // A fresh table and executive, so this check's one thread cannot resolve to
    // a process an earlier check left behind.
    // SAFETY: the boot CPU alone; the previous check's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    let blob = &raw const user_program_start;
    let blob_len =
        (&raw const user_program_end as usize) - (&raw const user_program_start as usize);
    let (mut process, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        blob_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );

    // Seed one handle (raw value 0: slot 0, generation 0) for ring 3 to
    // duplicate and query.
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let seeded_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => panic!("user demo: seed object create failed: {e:?}"),
    };
    if process
        .handles_mut()
        .install(seeded_obj, Rights::READ | Rights::WRITE | Rights::DUPLICATE)
        .is_err()
    {
        panic!("user demo: seed handle insert failed");
    }

    process.set_running();
    let slot = match processes_insert(process) {
        Ok(slot) => slot,
        Err(e) => panic!("user demo: insert process failed: {e:?}"),
    };

    kprintln!("user: entering ring 3 at {USER_CODE_VA:#x} (own address space)");
    exec_ref().run();

    // Back on the boot context (the fault handler switched here). Restore the
    // kernel address space.
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    // Assert the bet held.
    if !USER_RING3_REACHED.load(Ordering::Relaxed) {
        panic!("user demo: no syscall arrived from ring 3");
    }
    let dup = USER_DUP_HANDLE.load(Ordering::Relaxed);
    if dup == 0 {
        panic!("user demo: handle duplicate did not succeed");
    }
    let queried = USER_QUERY_RIGHTS.load(Ordering::Relaxed);
    if queried != Rights::READ.bits() {
        panic!("user demo: queried rights {queried:#x} != READ");
    }
    if !USER_FAULT_CONTAINED.load(Ordering::Relaxed) {
        panic!("user demo: ring-3 fault was not contained");
    }
    // The process the table holds under the slot this check inserted, which is
    // the one that faulted.
    let state = crate::loader::root_processes()
        .get(slot)
        .map(Process::state);
    if !matches!(state, Some(ProcessState::Exited(_))) {
        panic!("user demo: process not marked Exited after the fault");
    }

    kprintln!(
        "user: {} syscalls serviced (null + debug_write + duplicate->handle {:#x} + query READ)",
        USER_SYSCALLS.load(Ordering::Relaxed),
        dup - 1,
    );
    kprintln!(
        "user: ring-3 fault (vector {}, addr {:#x}) contained; process terminated, kernel alive",
        USER_FAULT_VECTOR.load(Ordering::Relaxed),
        USER_FAULT_ADDR.load(Ordering::Relaxed),
    );
}
