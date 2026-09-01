// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **process lifecycle**: create an empty process, populate its address
//! space, hand it capabilities, start it, and wait for it.
//!
//! **Why this is here and not in a port.** `kernel/boot-checks` states the rule:
//! *"A port's `main.rs` is its composition root: it knows a boot protocol, a
//! trap frame and an exit mechanism, and nothing else should."* Creating a
//! process is none of those three, and it lived in one port's `main.rs` for
//! long enough that the other four answered `ENOSYS` — so a root task was a
//! thing exactly one architecture could have, and the driver framework it is
//! meant to start lives on two others (build/README.md, D251).
//!
//! **What a port still lends, and why each item is genuinely its own.**
//! [`LoaderSupport`] is deliberately small, and nothing on it is here for
//! convenience:
//!
//! - **A fresh user address space.** `new_user` is an inherent method on each
//!   port's page tables with a *different signature* on each — x86-64 takes no
//!   address-space tag, the RISC-V and ARM ports take one — so it is not on
//!   `AddressSpaceOps` and cannot be called from here.
//! - **The kernel address space**, which a child's kernel stack is mapped into.
//!   Which alias of the kernel half a port hands over is the port's business.
//! - **Kernel-stack windows.** Where they live in the kernel half, and how many
//!   there are, is a port's address-space layout.
//! - **How much user stack a child gets**, which is drawn from this port's
//!   frames. Where it goes is the *caller's*, in `ProcessStartArgs::stack`: a
//!   program chooses its own layout, and the loader that placed its segments
//!   knows where they left room.
//!
//! Everything else — the authority checks, the W^X rule, the copy validation,
//! the reclaim, the waiter bookkeeping — is the same on every port and is
//! written once, here.
//!
//! **The parked-borrow discipline applies.** `wait` blocks the calling thread,
//! so no table borrow may be live across it; each phase re-resolves what it
//! needs. See `crate::dispatch`'s module note.
//!
//! Normative: docs/api/01-system-call-interface.md ("Process And Thread"),
//! docs/kernel/05-jobs-containment-and-resource-control.md
//! Budget: none (the loader is not on a hot path)

use crate::object::{ObjectTable, ObjectType};
use crate::process::{Process, ProcessState, ProcessTable};
use crate::rights::Rights;
use crate::syscall::{self, encode_result, read_user};
use crate::thread::{Thread, ThreadId};
use crate::vm::AddressSpace;
use tessera_karch::{
    AddressSpaceOps, ContextOps, FRAME_SIZE, FrameSource, KError, PageFlags, UserContextOps,
    VirtAddr,
};

/// What a port lends the loader: the things only it can make.
///
/// See the module note for why each of these is the port's and not this
/// module's. A port that implements none of it has no loader, which is the
/// honest state for one that starts no user processes.
pub trait LoaderSupport<A: AddressSpaceOps> {
    /// A fresh, empty user address space carrying whatever address-space tag
    /// this port assigns.
    fn new_user_space(&mut self, alloc: &mut dyn FrameSource) -> Result<AddressSpace<A>, KError>;

    /// The kernel address space a child's kernel stack is mapped into, and
    /// whose windows the reclaim unmaps.
    fn kernel_space(&mut self) -> &mut AddressSpace<A>;

    /// Takes a kernel-stack window for a child about to start, or `None` when
    /// every one is in use.
    ///
    /// Exhaustion is a refusal rather than a shared window: two threads on one
    /// kernel stack is not a resource shortage, it is corruption.
    fn take_kernel_stack(&mut self) -> Option<VirtAddr>;

    /// Gives a reclaimed child's window back.
    fn release_kernel_stack(&mut self, window: VirtAddr);

    /// Pages of user stack behind a child's initial stack pointer.
    ///
    /// The *address* is the caller's, in `ProcessStartArgs::stack`: a program
    /// chooses its own layout, and the loader that placed its segments is the
    /// thing that knows where they left room. How much stack a child gets is
    /// this port's, because it is drawn from this port's frames.
    fn user_stack_pages(&self) -> u64;

    /// Pages of kernel stack per child thread.
    fn kernel_stack_pages(&self) -> u64;
}

/// The loader's own slice of a dispatch environment: what a port lends, and
/// the object table a process is created in.
///
/// One value rather than two fields on `DispatchEnv`, because they are useless
/// apart: a loader that could make address spaces but not objects cannot create
/// a process, and a half-configured port would fail somewhere further in than
/// the place it was misconfigured.
pub struct LoaderEnv<'a, A: AddressSpaceOps> {
    pub support: &'a mut dyn LoaderSupport<A>,
    pub objects: &'a mut ObjectTable,
}

/// `ProcessCreate`: an empty, not-yet-started process under a job the caller
/// holds `create-process` on.
///
/// The authority gate is the job handle and nothing else: a caller that holds
/// no such job cannot make a process however many other capabilities it has.
pub fn create<A: AddressSpaceOps>(
    env: &mut LoaderEnv<'_, A>,
    processes: &mut ProcessTable<A>,
    alloc: &mut dyn FrameSource,
    caller: ThreadId,
    args_ptr: u64,
) -> i64 {
    let job = {
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut buf = [0u8; syscall::PROCESS_CREATE_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut buf) {
            return encode_result(Err(e));
        }
        match syscall::decode_process_create_args(&buf) {
            Ok(job) => job,
            Err(e) => return encode_result(Err(e)),
        }
    };
    {
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().rights(job) {
            Ok(rights) if rights.contains(Rights::CREATE_PROCESS) => {}
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        }
    }

    let child_space = match env.support.new_user_space(alloc) {
        Ok(space) => space,
        Err(e) => return encode_result(Err(e)),
    };
    let child_obj = match env.objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => return encode_result(Err(e)),
    };
    if processes
        .insert(Process::new(child_obj, child_space))
        .is_err()
    {
        return encode_result(Err(KError::OutOfMemory));
    }

    // The parent gets map + start authority over what it just made. It adopts
    // the object reference `create` minted, so nothing else has to release it.
    let Some(caller_process) = processes.process_of_thread(caller) else {
        return encode_result(Err(KError::AccessDenied));
    };
    match caller_process
        .handles_mut()
        .install(child_obj, Rights::READ | Rights::WRITE | Rights::MAP)
    {
        Ok(handle) => encode_result(Ok(u64::from(handle.raw()))),
        Err(e) => encode_result(Err(e)),
    }
}

/// `AddressSpaceMap`: place bytes in a created process's address space.
///
/// **Mapped writable, copied into, then re-protected**, which is how a
/// read-execute segment gets its contents without ever being writable and
/// executable at once. W^X is checked against the *requested* rights before
/// anything is mapped, so a caller asking for both is refused rather than
/// served a mapping it then cannot use.
///
/// `src == 0` maps zero-filled anonymous pages — a segment's `.bss` tail, which
/// has no bytes to copy.
pub fn address_space_map<A: AddressSpaceOps>(
    env: &mut LoaderEnv<'_, A>,
    processes: &mut ProcessTable<A>,
    alloc: &mut dyn FrameSource,
    caller: ThreadId,
    args_ptr: u64,
) -> i64 {
    let _ = &env.objects;
    let request = {
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut buf = [0u8; syscall::ADDRESS_SPACE_MAP_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut buf) {
            return encode_result(Err(e));
        }
        match syscall::decode_address_space_map_args(&buf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    if request.length == 0 {
        return encode_result(Err(KError::InvalidMapping));
    }
    let rights = rights_to_flags(request.rights);
    if rights.is_wx() {
        return encode_result(Err(KError::WXViolation));
    }

    let child_obj = {
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        // The source range is validated in the *caller's* space, which is the
        // active one: its bytes are read below while that root is loaded.
        if request.src != 0
            && let Err(e) = crate::syscall::validate_user_range(
                process.space(),
                request.src,
                request.length,
                false,
            )
        {
            return encode_result(Err(e));
        }
        match process.handles().lookup(request.process) {
            Ok((obj, r)) if r.contains(Rights::MAP) => obj,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        }
    };

    let page_len = request.length.div_ceil(FRAME_SIZE) * FRAME_SIZE;
    // The whole destination must land in the child's user half. Stated here
    // because this is where the address comes out of a caller's argument
    // struct, so this is where a caller learns its request was out of range
    // rather than out of memory.
    let Some(end) = request.vaddr.checked_add(page_len) else {
        return encode_result(Err(KError::InvalidMapping));
    };
    if end > A::USER_ADDRESS_MAX {
        return encode_result(Err(KError::InvalidMapping));
    }

    let Some(child) = processes.process_of_id(child_obj) else {
        return encode_result(Err(KError::BadHandle));
    };
    if let Err(e) = child.space_mut().map_anonymous(
        VirtAddr::new(request.vaddr),
        page_len,
        PageFlags::rw().user(),
        alloc,
    ) {
        return encode_result(Err(e));
    }
    if request.src != 0 {
        // SAFETY: `[src, src + length)` was validated user-readable in the
        // caller's space, which is the active one here, so the read cannot
        // fault. The window is what makes reaching a user page legal at all
        // where the hardware enforces it, and it spans the copy rather than
        // the slice — `copy_in` is what does the reading.
        let copied = {
            let _access = unsafe { crate::useraccess::Window::open() };
            // SAFETY: as above; the window permits reaching the range.
            let src = unsafe {
                core::slice::from_raw_parts(request.src as *const u8, request.length as usize)
            };
            child.space().copy_in(VirtAddr::new(request.vaddr), src)
        };
        if let Err(e) = copied {
            return encode_result(Err(e));
        }
    }
    if let Err(e) = child
        .space_mut()
        .protect_range(VirtAddr::new(request.vaddr), page_len, rights)
    {
        return encode_result(Err(e));
    }
    encode_result(Ok(request.length))
}

/// `ProcessStart`: make a created, populated process runnable.
///
/// **It returns as soon as the child is on a run queue.** It does not hand the
/// CPU over and it does not wait: a parent that could only ever have one
/// running child cannot compose a system (build/README.md, D250). The exit code
/// is [`wait`]'s to report.
/// Copies a parent's startup message into a page mapped in the child.
///
/// **Two address spaces, and the copy has to be staged through neither of
/// them at once.** The bytes are read from the parent's memory — validated
/// against its own mappings, as every syscall argument is — and written into a
/// frame this allocates, and only then is the frame mapped into the child.
/// Reading the parent while the child's space is active would be reading a
/// pointer into the wrong space, which is the mistake the whole `read_user`
/// discipline exists to make impossible.
///
/// The page is user-readable and **writable**: a child that wants to reuse the
/// page after reading its message may, and one that never writes loses nothing.
/// It is not executable, so a parent cannot deliver code this way.
fn deliver_startup_message<A: AddressSpaceOps>(
    processes: &mut ProcessTable<A>,
    alloc: &mut dyn FrameSource,
    caller: ThreadId,
    child_obj: crate::object::ObjectId,
    request: &syscall::ProcessStartRequest,
) -> Result<(), KError> {
    let len = usize::try_from(request.message_len).map_err(|_| KError::InvalidMapping)?;
    let mut staged = [0u8; syscall::MAX_STARTUP_MESSAGE as usize];
    {
        let parent = processes
            .process_of_thread(caller)
            .ok_or(KError::AccessDenied)?;
        let into = staged.get_mut(..len).ok_or(KError::InvalidMapping)?;
        read_user(parent, request.message_ptr, into)?;
    }
    let child = processes
        .process_of_id(child_obj)
        .ok_or(KError::BadHandle)?;
    child.space_mut().map_anonymous(
        VirtAddr::new(request.message_va),
        FRAME_SIZE,
        PageFlags::rw().user(),
        alloc,
    )?;
    // **`copy_in`, not `write_user`, and the difference is which address space
    // is on the CPU.** `write_user` validates against a process's mappings and
    // then copies through the *active* space — which here is the **parent's**,
    // because the child has never run. It faults on the child's address, and
    // that is not hypothetical: it is what this did first.
    //
    // `copy_in` translates through the child's own tables and writes the frame
    // it finds, which is the same path `address_space_map` populates a child's
    // segments with and works for the same reason.
    child
        .space()
        .copy_in(VirtAddr::new(request.message_va), &staged[..len])
}

pub fn start<A: AddressSpaceOps, C: UserContextOps>(
    env: &mut LoaderEnv<'_, A>,
    exec: &mut crate::exec::Executive<C>,
    processes: &mut ProcessTable<A>,
    alloc: &mut dyn FrameSource,
    caller: ThreadId,
    args_ptr: u64,
) -> i64 {
    let _ = &env.objects;
    let request = {
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut buf = [0u8; syscall::PROCESS_START_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut buf) {
            return encode_result(Err(e));
        }
        match syscall::decode_process_start_args(&buf) {
            Ok(request) => request,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let child_obj = {
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(request.process) {
            Ok((obj, r)) if r.contains(Rights::WRITE) => obj,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        }
    };
    // Started twice is refused: the second start would spawn a thread into a
    // process that already has one running against the same stack.
    match processes.process_of_id(child_obj).map(|p| p.state()) {
        Some(ProcessState::Created) => {}
        Some(_) => return encode_result(Err(KError::AccessDenied)),
        None => return encode_result(Err(KError::BadHandle)),
    }

    // **The startup message, before the thread exists.** Copied out of the
    // parent and into the child while the child is still `Created` and nothing
    // is running in it — the same window `ProcessGrant` installs handles in,
    // and for the same reason: what a child starts with is decided before it
    // starts.
    //
    // The kernel does not read the bytes. What is in them is an agreement
    // between the parent and the child it started; the kernel's part is that
    // they arrive whole, in the child's own memory, at the address the parent
    // named (build/README.md, D261).
    if request.message_len != 0
        && let Err(e) = deliver_startup_message(processes, alloc, caller, child_obj, &request)
    {
        return encode_result(Err(e));
    }

    let Some(kernel_stack) = env.support.take_kernel_stack() else {
        return encode_result(Err(KError::OutOfMemory));
    };
    let user_pages = env.support.user_stack_pages();
    let kernel_pages = env.support.kernel_stack_pages();

    let thread = {
        let Some(child) = processes.process_of_id(child_obj) else {
            env.support.release_kernel_stack(kernel_stack);
            return encode_result(Err(KError::BadHandle));
        };
        let root = child.space().arch().root_phys();
        // Split so the child's space and the kernel's are borrowed from
        // different owners: `spawn_user` needs both at once.
        let (child_space, kernel_space) = (child.space_mut(), env.support.kernel_space());
        match Thread::<C>::spawn_user(
            VirtAddr::new(request.entry),
            request.arg as usize,
            VirtAddr::new(request.stack),
            user_pages,
            kernel_stack,
            kernel_pages,
            child_obj,
            root,
            child_space,
            kernel_space,
            alloc,
        ) {
            Ok(thread) => thread,
            Err(e) => {
                env.support.release_kernel_stack(kernel_stack);
                return encode_result(Err(e));
            }
        }
    };
    let slot = match exec.add_thread(thread) {
        Ok(slot) => slot,
        Err(e) => {
            env.support.release_kernel_stack(kernel_stack);
            return encode_result(Err(e));
        }
    };
    let Some(id) = exec.scheduler().thread_id(slot) else {
        env.support.release_kernel_stack(kernel_stack);
        return encode_result(Err(KError::OutOfMemory));
    };
    let Some(child) = processes.process_of_id(child_obj) else {
        env.support.release_kernel_stack(kernel_stack);
        return encode_result(Err(KError::BadHandle));
    };
    if child.add_thread(id).is_err() {
        env.support.release_kernel_stack(kernel_stack);
        return encode_result(Err(KError::OutOfMemory));
    }
    child.set_running();
    encode_result(Ok(0))
}

/// `ProcessWait`: block until a child has exited, then reclaim it and report
/// its code.
///
/// **A process that has already exited returns immediately.** Without that
/// every supervisor is a race against its own child: a short-lived service can
/// be gone before its parent's next instruction, and a wait insisting on seeing
/// the transition would park for ever on a process that will never transition
/// again.
///
/// The reclaim is here because this is the first moment the child is both
/// finished and unreferenced: the scheduler slot, the kernel-stack window, the
/// address space and the parent's handle all go back. A supervisor that
/// restarts a service a hundred times is otherwise bounded by whichever table
/// fills first.
pub fn wait<A: AddressSpaceOps, C: ContextOps>(
    env: &mut LoaderEnv<'_, A>,
    exec: &mut crate::exec::Executive<C>,
    processes: &mut ProcessTable<A>,
    alloc: &mut dyn FrameSource,
    caller: ThreadId,
    args_ptr: u64,
) -> i64 {
    let handle = {
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut buf = [0u8; syscall::PROCESS_WAIT_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut buf) {
            return encode_result(Err(e));
        }
        match syscall::decode_process_wait_args(&buf) {
            Ok(handle) => handle,
            Err(e) => return encode_result(Err(e)),
        }
    };
    let child_obj = {
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        match process.handles().lookup(handle) {
            Ok((obj, r)) if r.contains(Rights::READ) => obj,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        }
    };

    // Enrol and park with no table borrow live across the switch.
    let parked = {
        let Some(child) = processes.process_of_id(child_obj) else {
            return encode_result(Err(KError::BadHandle));
        };
        match child.state() {
            ProcessState::Exited(_) => false,
            _ => {
                if child.add_waiter(caller).is_err() {
                    return encode_result(Err(KError::OutOfMemory));
                }
                true
            }
        }
    };
    if parked {
        exec.scheduler().block_current();
        // Resumed: the child's exit woke this thread (`notify_exit`).
    }

    let code = match processes.process_of_id(child_obj).map(|p| p.state()) {
        Some(ProcessState::Exited(code)) => code,
        // Woken without the child having exited is a defect in the wake path,
        // not something to report as an exit code.
        _ => return encode_result(Err(KError::Protocol)),
    };
    reclaim(env, exec, processes, alloc, child_obj);
    if let Some(parent) = processes.process_of_thread(caller) {
        let _ = parent.handles_mut().close(env.objects, handle);
    }
    encode_result(Ok(code as u32 as u64))
}

/// Returns an exited child's resources to their pools.
///
/// Threads are found by **identity** rather than by a slot recorded earlier: a
/// slot is reused and an identity never is, so a supervisor that reaped a
/// service and started a replacement used to reach the corpse's tables through
/// a recycled index.
fn reclaim<A: AddressSpaceOps, C: ContextOps>(
    env: &mut LoaderEnv<'_, A>,
    exec: &mut crate::exec::Executive<C>,
    processes: &mut ProcessTable<A>,
    alloc: &mut dyn FrameSource,
    child_obj: crate::object::ObjectId,
) {
    let threads = processes
        .process_of_id(child_obj)
        .map(|p| p.thread_ids())
        .unwrap_or_default();
    for id in threads.iter().flatten() {
        let Some(slot) = exec.scheduler().index_of(*id) else {
            continue;
        };
        if let Some(thread) = exec.scheduler().reap(slot) {
            let window = thread.kernel_stack_base();
            let _ = env
                .support
                .kernel_space()
                .reclaim_range(window, thread.stack_bytes(), alloc);
            env.support.release_kernel_stack(window);
        }
    }
    if let Some(index) = processes.index_of_id(child_obj)
        && let Some(mut child) = processes.remove(index)
    {
        // **The memory objects go with the process** (D307). Tearing down the
        // address space unmaps what the child had mapped and frees those
        // frames; it says nothing about the *objects* the child created, which
        // live in the executive's table and outlive their only holder. Every
        // kernel-side check has always called this at its own teardown — it was
        // the ring-3 reclaim path, the one a supervisor drives with
        // `ProcessWait`, that did not.
        //
        // Nothing noticed while the programs a parent started were small and
        // few: the first child to create an object per run, run twice, walked
        // the table into `NoBuffer` on a later and unrelated `Open`. A leak
        // whose symptom is somebody else's failure.
        exec.release_memory_of(child.id(), alloc, None);
        child.space_mut().teardown(alloc);
    }
}

/// Marks a process exited and hands back the threads waiting on it.
///
/// **Wake, then leave the CPU — in that order.** Marking a waiter `Ready`
/// before the exiting thread stops running means the scheduler has something to
/// pick when it does; parking first and waking afterwards is code that never
/// runs. The caller does the leaving, because how a port ends a thread is the
/// port's.
pub fn notify_exit<A: AddressSpaceOps, C: ContextOps>(
    exec: &mut crate::exec::Executive<C>,
    processes: &mut ProcessTable<A>,
    caller: ThreadId,
    code: i32,
) -> bool {
    let mut waiters = [None; crate::process::MAX_PROCESS_WAITERS];
    if let Some(process) = processes.process_of_thread(caller) {
        process.exit(code);
        waiters = process.take_waiters();
    }
    let mut woke = false;
    let scheduler = exec.scheduler();
    for id in waiters.iter().flatten() {
        if let Some(slot) = scheduler.index_of(*id) {
            scheduler.unblock_thread(slot, *id);
            woke = true;
        }
    }
    woke
}

/// The page flags an `AddressSpaceMapArgs` rights mask asks for.
fn rights_to_flags(rights: Rights) -> PageFlags {
    let mut flags = PageFlags::none().read().user();
    if rights.contains(Rights::WRITE) {
        flags = flags.write();
    }
    if rights.contains(Rights::EXECUTE) {
        flags = flags.execute();
    }
    flags
}

#[cfg(test)]
#[path = "tests/loader.rs"]
mod tests;
