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
}

/// The demo scheduler holding the single ring-3 thread. Static so the syscall
/// and fault handlers (which run in kernel entry context) can reach it.
pub(crate) static mut USER_SCHEDULER: Option<Scheduler<ContextSwitch>> = None;
/// The demo process (address space + handle table). Static for the same reason.
pub(crate) static mut USER_PROCESS: Option<Process<KernelAddressSpace>> = None;

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
pub(crate) static mut LOADER_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
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

/// Launches the root task's run must produce: 1 for the grant probe, 41 to
/// bring the recovering service up (it counts 40 down to 0), 3 for the one it
/// gives up on, and 2 for the driver framework — the device manager and the
/// driver it binds (build/README.md, D256).
///
/// Asserted exactly rather than as a floor. A supervisor that restarted more
/// than its policy allows is as wrong as one that stopped early, and only an
/// equality catches the first.
pub(crate) const EXPECTED_CHILD_LAUNCHES: u64 = 1 + 41 + 3 + 2;

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
        kprint!("  user[debug_write]: {text}\n");
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

/// The registered syscall dispatcher: runs in kernel context after the entry
/// stub, on the user thread's kernel stack, with the user address space still
/// active. Resolves the calling process and performs the operation.
pub(crate) fn user_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    USER_RING3_REACHED.store(true, Ordering::Relaxed);
    USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);

    // SAFETY: the boot CPU alone; `USER_PROCESS` is set before the ring-3 thread runs
    // and touched only on this boot CPU.
    let process = match unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        Some(process) => process,
        None => return syscall::ENOSYS,
    };
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };

    let number = match SyscallNumber::from_u64(frame.number) {
        Some(number) => number,
        None => return syscall::ENOSYS,
    };
    match number {
        SyscallNumber::Null => encode_result(Ok(0)),
        SyscallNumber::DebugWrite => user_debug_write(process, frame.arg0, frame.arg1),
        SyscallNumber::HandleDuplicate => {
            // Two registers, which is what `syscall_abi.isl` declares and what
            // `kcore::dispatch` has always read. This handler read a
            // `DuplicateArgs` struct through `arg0` until D298 — one syscall
            // number with two argument shapes in one tree, which is the defect
            // a published ABI cannot carry.
            let source = Handle::from_raw(frame.arg0 as u32);
            let new_rights = Rights::from_bits(frame.arg1);
            let result = sys_handle_duplicate(process, objects, source, new_rights);
            if let Ok(handle) = result {
                USER_DUP_HANDLE.store(handle + 1, Ordering::Relaxed);
            }
            encode_result(result)
        }
        SyscallNumber::HandleQueryRights => {
            let result = sys_handle_query_rights(process, Handle::from_raw(frame.arg0 as u32));
            if let Ok(bits) = result {
                USER_QUERY_RIGHTS.store(bits, Ordering::Relaxed);
            }
            encode_result(result)
        }
        // A closed device capability ends its DMA lease and its interrupt
        // route too. `None` for the IOMMU because this port has none — the
        // lease bookkeeping still runs, so the rule holds by construction
        // rather than by this port happening never to take a lease. The PIC is
        // real: this port's device interrupts do arrive through it.
        SyscallNumber::HandleClose => encode_result(sys_handle_close(
            process,
            objects,
            exec_ref(),
            None,
            Some(&mut PicRouter),
            Handle::from_raw(frame.arg0 as u32),
        )),
        SyscallNumber::ProcessExit => user_process_exit(frame.arg0 as i32),
        // Wait-on-address is exercised by its own demo/handler, not this one.
        SyscallNumber::WaitOnAddress | SyscallNumber::WakeAddress => syscall::ENOSYS,
        // The three-phase process-lifecycle ABI is defined (numbers +
        // process_abi.isl @abi structs, conformance-gated); the in-kernel loader
        // exercises the create/populate/start path directly. The ring-3
        // implementation awaits the object/handle bridge for processes (D42).
        SyscallNumber::ProcessCreate
        | SyscallNumber::AddressSpaceMap
        | SyscallNumber::ProcessStart => syscall::ENOSYS,
        // Channel IPC is exercised by `channel_ipc_demo`'s own handler (M15),
        // not this single-process one.
        SyscallNumber::ChannelCreate
        | SyscallNumber::ChannelSend
        | SyscallNumber::ChannelRecv
        | SyscallNumber::ChannelCall
        | SyscallNumber::ChannelReply => syscall::ENOSYS,
        // Ports and device I/O are exercised by `driver_host_demo`'s own handler
        // (M16), not this single-process one.
        SyscallNumber::PortCreate
        | SyscallNumber::PortBind
        | SyscallNumber::PortWait
        | SyscallNumber::DeviceIoRead
        | SyscallNumber::DeviceIoWrite => syscall::ENOSYS,
        // The ring-3 pager ops are exercised by `fs_service_demo`'s own handler
        // (M18), not this single-process one. `MemoryCreatePaged`/`MapObject`
        // are the shared kcore dispatcher's (D206), which this single-process
        // demo handler predates and does not route — the same reason
        // `MapDevice` and `DmaAlloc` are refused below.
        SyscallNumber::PageServe
        | SyscallNumber::PageSupply
        | SyscallNumber::MemoryCreatePaged
        | SyscallNumber::MapObject
        | SyscallNumber::MemoryDirtyPages
        | SyscallNumber::PageWrittenBack
        | SyscallNumber::MemoryUnmap => syscall::ENOSYS,
        // Mapping a device's MMIO window into a ring-3 driver, and allocating a
        // ring-3 DMA buffer, live in the shared kcore dispatcher (D79) on the
        // executive substrate; this single-process demo handler predates that
        // substrate and does not route them.
        SyscallNumber::MapDevice | SyscallNumber::DmaAlloc => syscall::ENOSYS,
        // The server-loop primitive (D82) is exercised by the AArch64 ring-3
        // driver host; x86's channel demos reply via their own local arms.
        SyscallNumber::ChannelReplyRecv => syscall::ENOSYS,
        // Interrupt re-arm (D84) is arch-coupled (a GIC operation) and
        // exercised by the AArch64 ring-3 device host.
        SyscallNumber::IrqComplete => syscall::ENOSYS,
        // Recording a driver-lifecycle transition (D128) belongs to a ring-3
        // device manager, and this port has none: its one device is a COM2
        // port range boot registered, bound by a kernel-driven supervisor
        // rather than brokered by a manager that could have a lifecycle to
        // declare. The ladder this port *does* run — crash, restart, give up —
        // is recorded by `kcore::supervise`, which needs no syscall.
        SyscallNumber::DriverLifecycle => syscall::ENOSYS,
        // The select-loop reply (D85) belongs to the AArch64 device host; the
        // x86 channel demos reply through their own local arms.
        SyscallNumber::ChannelReplyContinue => syscall::ENOSYS,
        // Asking what a device is (D115) answers from the resource graph, and
        // this port's graph holds no normalized identity: its one device is a
        // COM2 port range the boot glue registered, not something enumerated.
        // A ring-3 caller here would get `UNKNOWN`, which is the same answer
        // the shared arm gives — refusing outright is clearer than
        // implementing a path nothing on this port asks for.
        SyscallNumber::DeviceInfo => syscall::ENOSYS,
        // Memory objects (D131) need a frame allocator to create against, and
        // this port hands its dispatcher `NoFrames`: its ring-3 demos run out
        // of blob-mapped pages the boot glue placed, with no allocator alive
        // by the time a syscall arrives. `ENOSYS` says so rather than letting
        // a caller reach an arm that would fail obscurely on the first frame
        // it asked for.
        SyscallNumber::MemoryCreate | SyscallNumber::MemoryMap => syscall::ENOSYS,
        // Attaching a memory object to a device needs a memory object, which
        // this port cannot create (above), and an IOMMU, which this machine
        // does not have. Two reasons rather than one, and either alone would
        // be enough.
        SyscallNumber::DmaAttach | SyscallNumber::DmaDetach => syscall::ENOSYS,
        // Renewing a lease needs a lease, and this port's one device is behind
        // no IOMMU, so it never takes one.
        SyscallNumber::DmaRenew => syscall::ENOSYS,
        // This port's resource graph is flat: its devices are the legacy ones
        // the PIC and PIT sit on, which are not behind anything. A bus with no
        // children to derive is not a mechanism to implement here — and
        // answering "no children" would be indistinguishable from a working
        // implementation of a tree this port does not have.
        SyscallNumber::DeviceChild => syscall::ENOSYS,
        SyscallNumber::WakeSource => syscall::ENOSYS,
        SyscallNumber::WakeHold => syscall::ENOSYS,
        SyscallNumber::SystemSuspend => syscall::ENOSYS,
        // This is the single-process demo dispatcher, which has no device
        // graph to name an image's destination and no manager to hold the
        // authority. The port's driver-framework check routes its syscalls
        // through `kcore::dispatch`, which does implement it.
        SyscallNumber::FirmwareLoad => syscall::ENOSYS,
        // Likewise: this dispatcher has no memory-object table to classify
        // anything in. `kcore::dispatch` implements it, and the port's
        // framework check routes through that.
        SyscallNumber::MemoryClassify => syscall::ENOSYS,
        // Declaring a device and mapping its configuration space belong to a
        // bus controller and to the driver a controller handed a function to.
        // This dispatcher serves a single-process demo whose one device is a
        // COM2 port range with no bus above it and no configuration space at
        // all; the port's bus-driver check routes through `kcore::dispatch`,
        // which implements both.
        SyscallNumber::DeviceDeclare
        | SyscallNumber::MapConfig
        | SyscallNumber::ChannelRecvAny
        | SyscallNumber::PortSignal => syscall::ENOSYS,
        // Handing a capability to a child (D249) needs a child, and waiting
        // for one (D250) needs the same. This is the single-process demo
        // dispatcher: the one process it serves has no `ProcessCreate` here
        // either. The port's root-task check routes through the loader arms,
        // which implement both.
        SyscallNumber::ProcessGrant | SyscallNumber::ProcessWait => syscall::ENOSYS,
        // Routing a device's interrupts (D255) needs a device with a line in the
        // resource graph and a port to send it to; this demo dispatcher serves
        // one process holding neither. The root-task check reaches it through
        // the shared dispatcher, which is the only path that implements it.
        SyscallNumber::DeviceIrqBind => syscall::ENOSYS,
        // **Answered here as well as in the shared dispatcher** (D281). This
        // handler predates `kcore::dispatch` and serves the single-process
        // demo; a clock that existed on four ports and not on the fifth's
        // oldest path would be a surface that is true depending on which
        // program asked.
        // **This port composes nothing that could read a container off a
        // medium**, so there is no component to offer one and the store it uses
        // is the copy in its own image (D291). Refused rather than served: a
        // handler that installed whatever a single-process demo handed it would
        // be the delivery path without the composed path that gives it a point.
        SyscallNumber::SystemStoreInstall => syscall::ENOSYS,
        SyscallNumber::ClockRead => match kcore::syscall::ClockId::from_u64(frame.arg0) {
            Some(kcore::syscall::ClockId::Monotonic) => {
                encode_result(Ok(crate::loader::monotonic_nanos()))
            }
            Some(kcore::syscall::ClockId::Boot) => encode_result(Err(KError::NotSupported)),
            None => encode_result(Err(KError::InvalidArgument)),
        },
    }
}

/// `sys_process_exit`: terminate the process and switch to boot — never returns
/// to ring 3.
pub(crate) fn user_process_exit(code: i32) -> i64 {
    // SAFETY: the boot CPU alone; statics set before the ring-3 thread runs.
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.exit(code);
    }
    // SAFETY: the boot CPU alone; USER_SCHEDULER is set before the ring-3 thread runs.
    if let Some(scheduler) = unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        scheduler.yield_to_boot();
    }
    // Unreachable: yield_to_boot switched to boot and this thread never resumes.
    0
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
pub(crate) fn user_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    USER_FAULT_ADDR.store(tessera_karch_x86_64::read_cr2(), Ordering::Relaxed);
    report_contained_fault(frame.vector, tessera_karch_x86_64::read_cr2());
    // SAFETY: the boot CPU alone; statics set before the ring-3 thread runs.
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.exit(-1);
    }
    // SAFETY: the boot CPU alone; USER_SCHEDULER is set before the ring-3 thread runs.
    match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => scheduler.yield_to_boot(),
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
pub(crate) fn user_mode_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    // SAFETY: one-shot registration, before any ring-3 thread runs.
    unsafe { set_syscall_handler(user_syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    // A user address space that shares the kernel higher-half (so the kernel is
    // addressable under the user CR3 during syscalls/faults).
    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("user demo: new_user failed: {e:?}"),
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
        Err(e) => panic!("user demo: process object create failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    // Seed one handle (raw value 0: slot 0, generation 0) for ring 3 to
    // duplicate and query.
    let seeded_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => panic!("user demo: seed object create failed: {e:?}"),
    };
    if process
        .handles_mut()
        .insert(seeded_obj, Rights::READ | Rights::WRITE | Rights::DUPLICATE)
        .is_err()
    {
        panic!("user demo: seed handle insert failed");
    }

    // Map the ring-3 code page writable so we can copy the program into it.
    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    if let Err(e) = process.space_mut().map_anonymous(
        VirtAddr::new(USER_CODE_VA),
        code_len,
        PageFlags::rw().user(),
        frames,
    ) {
        panic!("user demo: map code page failed: {e:?}");
    }

    // Spawn the ring-3 thread (maps its user and kernel stacks).
    let thread = match Thread::<ContextSwitch>::spawn_user(
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
        Err(e) => panic!("user demo: spawn_user failed: {e:?}"),
    };
    // SAFETY: the boot CPU alone; the only initialization of USER_SCHEDULER.
    unsafe { USER_SCHEDULER = Some(Scheduler::new(1, 0)) };
    let thread_idx = match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => match scheduler.add_thread(thread) {
            Ok(idx) => idx,
            Err(e) => panic!("user demo: scheduler thread table full: {e:?}"),
        },
        None => panic!("user demo: scheduler uninitialized"),
    };
    if process
        .add_thread(thread_id_of(thread_idx).unwrap_or(kcore::thread::ThreadId::UNASSIGNED))
        .is_err()
    {
        panic!("user demo: process thread set full");
    }

    // Switch to the user address space, copy the program into the writable code
    // page, then lock it to read+execute (W^X). The kernel stays mapped, so
    // boot keeps running after the CR3 load.
    // SAFETY: the user space shares the kernel higher-half; this code, the boot
    // stack, and the direct map remain mapped after activation.
    unsafe { process.space().activate(kcore::percpu::current_index()) };
    let code_src = &raw const user_program_start;
    let code_bytes =
        (&raw const user_program_end as usize) - (&raw const user_program_start as usize);
    // SAFETY: [user_program_start, user_program_end) is the assembled ring-3
    // blob in kernel rodata; USER_CODE_VA is a writable user page in the now-
    // active space with room for `code_bytes` (< one page).
    unsafe {
        // The kernel means to reach a user page here: it is populating a
        // process it is building, in that process's own space. Declared
        // rather than assumed, because SMAP now faults an undeclared one.
        // SAFETY: the destination is a page this boot glue just mapped
        // into the space it activated; the window permits reaching it.
        {
            let _access = kcore::useraccess::Window::open();
            core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes);
        }
    }
    if let Err(e) = process.space_mut().protect_range(
        VirtAddr::new(USER_CODE_VA),
        code_len,
        PageFlags::rx().user(),
    ) {
        panic!("user demo: protect code page failed: {e:?}");
    }

    // Publish the process, mark it running, and run the thread.
    // SAFETY: the boot CPU alone; the only initialization of USER_PROCESS.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }

    kprintln!("user: entering ring 3 at {USER_CODE_VA:#x} (own address space)");
    // SAFETY: the boot CPU alone, path; USER_SCHEDULER was initialized above.
    match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => scheduler.run(),
        None => panic!("user demo: scheduler uninitialized"),
    }

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
    // SAFETY: the boot CPU alone, path; only this boot CPU touches USER_PROCESS.
    let state = unsafe { (*&raw const USER_PROCESS).as_ref() }.map(Process::state);
    let exited = matches!(state, Some(ProcessState::Exited(_)));
    if !exited {
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
