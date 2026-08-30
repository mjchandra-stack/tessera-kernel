// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel `Thread` object: a schedulable execution context
//! (docs/architecture/01-system-architecture.md, "thread") with its own
//! guard-paged kernel stack and preallocated per-thread exception storage
//! (docs/kernel/03-paging-faults-and-exceptions.md, "exception report
//! storage is preallocated per thread"). Threads are created `Ready`; the
//! scheduler drives their state and the architecture context switch resumes
//! them.
//!
//! The kernel stack is mapped with an unmapped guard page immediately below
//! it, so a stack overflow faults onto the per-CPU exception stack instead
//! of silently corrupting a neighbour (docs/kernel/03, "Kernel stacks carry
//! guard pages"). Backing frames come from the address space's allocator and
//! are not reclaimed this milestone (the bump allocator has no free path).
//!
//! Generic over `ContextOps`/`AddressSpaceOps`, so thread creation and state
//! transitions are host-testable against `tessera-karch-mock`.
//!
//! Normative: docs/kernel/01-kernel-model.md ("Threads"),
//! docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (creation path)

use crate::object::ObjectId;
use crate::vm::AddressSpace;
use tessera_karch::{
    AddressSpaceOps, ContextOps, FRAME_SIZE, FrameSource, KError, PageFlags, PhysAddr,
    UserContextOps, VirtAddr,
};

/// A thread's identity, minted by the scheduler that admits it.
///
/// **Not chosen by whoever creates the thread.** It used to be: every caller
/// passed a hand-picked constant, which made this a debugging label rather than
/// an identifier — `ThreadId(1)` named four different threads across the tree
/// and `ThreadId(0x_d217_e021)` two. That is harmless for a decoration and
/// disqualifying for a key, and machine-wide tables need a key
/// (`docs/roadmap/02-smp-bring-up-plan.md`, Phase 1d).
///
/// The value is a CPU index in the high bits and a per-scheduler sequence in
/// the low ones. That is what makes it unique **without coordination**: two
/// CPUs minting at the same instant cannot collide, because the halves of the
/// value they are allowed to write are disjoint. A single shared counter would
/// need an atomic on a path that creates threads, and per-CPU-by-default
/// (`docs/kernel/08-multicore-scalability.md`) says not to reach for one where
/// the address space of the identifier can carry the answer instead.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ThreadId(pub u64);

impl ThreadId {
    /// A thread no scheduler has admitted. Zero is reserved for it: a minted id
    /// always has a non-zero sequence, so nothing else can produce this value.
    pub const UNASSIGNED: Self = Self(0);

    /// Bits reserved for the minting CPU's index. The remaining 48 are the
    /// sequence, which is more threads than a CPU can create in the life of a
    /// machine — and if it were not, [`Self::UNASSIGNED`] would stop being
    /// unique, so the scheduler refuses rather than wraps.
    pub const CPU_SHIFT: u32 = 48;

    /// The index of the CPU that minted this id.
    pub const fn cpu(self) -> u32 {
        (self.0 >> Self::CPU_SHIFT) as u32
    }

    /// The minting CPU's sequence number for this id.
    pub const fn sequence(self) -> u64 {
        self.0 & ((1 << Self::CPU_SHIFT) - 1)
    }
}

/// A thread's scheduling state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreadState {
    /// Runnable and waiting for a CPU.
    Ready,
    /// Currently executing on a CPU.
    Running,
    /// Waiting on an event; not runnable.
    Blocked,
    /// Finished; its context must never be resumed again.
    Exited,
}

/// Preallocated storage for a thread's most recent exception, filled by the
/// fault path rather than allocated at fault time (there is no allocation on
/// the exception path). Unpopulated this milestone — traps are still handled
/// globally — but reserved so the per-thread fault report needs no object
/// change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExceptionSlot {
    pub vector: u64,
    pub error_code: u64,
    pub faulting_ip: u64,
    pub valid: bool,
}

impl ExceptionSlot {
    const fn empty() -> Self {
        Self {
            vector: 0,
            error_code: 0,
            faulting_ip: 0,
            valid: false,
        }
    }
}

/// A kernel thread: identity, saved context, scheduling state, its stack, and
/// its exception slot.
pub struct Thread<C: ContextOps> {
    id: ThreadId,
    context: C::Context,
    state: ThreadState,
    /// Effective scheduling priority (higher is more urgent). Carried to a
    /// callee for a synchronous call's duration — the IPC-inheritance seam
    /// (docs/kernel/04, "Synchronous Call Scheduling"). The round-robin
    /// scheduler does not yet order by it (deviation D18).
    priority: u8,
    /// The causal id this thread's work currently belongs to — the sequence half
    /// of the 128-bit correlation id (`crate::trace`). "A thread carries a current
    /// correlation ID" (docs/observability/02); a synchronous call overwrites the
    /// callee's for the call's duration and restores it on return, the same
    /// carriage `priority` above gets. 0 until an origin mints one.
    correlation: u64,
    /// When this thread's blocking wait stops being worth waiting for, in
    /// monotonic nanoseconds, or `None` for a wait with no bound.
    ///
    /// **On the thread rather than on the endpoint**, because
    /// `ChannelRecvAny` registers one waiter on several endpoints and the
    /// deadline belongs to the wait, not to any one of them — a copy per
    /// endpoint is the same fact in several places, which is how they come to
    /// disagree (D282).
    ///
    /// The wait, not the receive: a caller blocked in `ChannelCall` sets it
    /// too, and one field serves both because the expiry pass asks the same
    /// question of every blocked thread — has this one waited long enough —
    /// and does not care which call it is waiting in (D283).
    blocked_deadline: Option<u64>,
    /// The thread's kernel stack (for a user thread, the stack the ring-3→
    /// ring-0 transitions land on; for a kernel thread, its only stack). Its
    /// guard page is the page just below `stack_base`.
    stack_base: VirtAddr,
    stack_pages: u64,
    /// Top-level page-table root (CR3-class) the thread runs under, or `None`
    /// for a kernel thread (which runs in whatever space is active — the kernel
    /// is mapped in all of them). Set for user threads so the scheduler can
    /// switch address space on resume.
    space_root: Option<PhysAddr>,
    /// The owning process, for a user thread; `None` for a kernel thread.
    process: Option<ObjectId>,
    exception: ExceptionSlot,
    /// Whether this thread was inside a validated user copy when it last left
    /// the CPU (`crate::useraccess`).
    ///
    /// **Per thread, because the hardware bit is per CPU and the fact is not.**
    /// A copy can fault on a page its pager has not supplied, and that fault
    /// blocks this thread and runs another — so the permission has to travel
    /// with the thread that opened it rather than stay on the CPU it was
    /// opened on. `false` for a thread that is not copying, which is nearly
    /// always.
    user_access: bool,
}

/// The default thread priority (mid-range).
pub const DEFAULT_PRIORITY: u8 = 16;

impl<C: ContextOps> Thread<C> {
    /// The deadline this thread's blocking wait carries, if any.
    pub fn blocked_deadline(&self) -> Option<u64> {
        self.blocked_deadline
    }

    /// Sets it. Cleared when the wait returns by any path — a deadline left
    /// behind would expire the *next* one.
    pub fn set_blocked_deadline(&mut self, deadline: Option<u64>) {
        self.blocked_deadline = deadline;
    }

    /// Creates a `Ready` thread that will begin at `entry(arg)`. Maps a
    /// `stack_pages`-page kernel stack at `stack_base` (leaving the page below
    /// it unmapped as a guard) in `space`, drawing frames from `frames`, and
    /// seeds the initial context. `stack_base` must be page-aligned; the
    /// caller owns the `[stack_base - one page, stack_base + stack)` virtual
    /// range.
    pub fn spawn<A: AddressSpaceOps>(
        entry: extern "C" fn(usize) -> !,
        arg: usize,
        stack_base: VirtAddr,
        stack_pages: u64,
        space: &mut AddressSpace<A>,
        frames: &mut dyn FrameSource,
    ) -> Result<Self, KError> {
        if stack_pages == 0 {
            return Err(KError::InvalidMapping);
        }
        let len = stack_pages * FRAME_SIZE;
        space.map_anonymous(stack_base, len, PageFlags::rw().global(), frames)?;
        let stack_top = VirtAddr::new(stack_base.as_u64() + len);
        // SAFETY: `[stack_base, stack_top)` was just mapped read-write and is
        // owned exclusively by this thread, so seeding the initial frame at
        // its top is valid.
        let context = unsafe { C::init(stack_top, entry, arg) };
        Ok(Self {
            id: ThreadId::UNASSIGNED,
            user_access: false,
            context,
            state: ThreadState::Ready,
            priority: DEFAULT_PRIORITY,
            correlation: 0,
            blocked_deadline: None,
            stack_base,
            stack_pages,
            space_root: None,
            process: None,
            exception: ExceptionSlot::empty(),
        })
    }
}

/// User-thread creation. Bounded on [`UserContextOps`] rather than
/// [`ContextOps`], so a port that has not yet built an unprivileged level
/// simply cannot reach this — the restriction is a compile error rather than
/// a runtime surprise.
impl<C: UserContextOps> Thread<C> {
    /// Creates a `Ready` **user** thread. Maps a ring-3 stack
    /// (`user_stack_pages`, `rw().user()`) at `user_stack_base` in the process
    /// address space, and a kernel syscall/exception stack (`kernel_stack_pages`)
    /// at `kernel_stack_base` in the shared kernel region; seeds the context so
    /// the first switch drops to ring 3 at `user_entry` (with `arg` in the first
    /// argument register). Records the owning `process` and its `space_root`
    /// (CR3) so the scheduler switches address space when it resumes this thread.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_user<A: AddressSpaceOps>(
        user_entry: VirtAddr,
        arg: usize,
        user_stack_base: VirtAddr,
        user_stack_pages: u64,
        kernel_stack_base: VirtAddr,
        kernel_stack_pages: u64,
        process: ObjectId,
        space_root: PhysAddr,
        user_space: &mut AddressSpace<A>,
        kernel_space: &mut AddressSpace<A>,
        frames: &mut dyn FrameSource,
    ) -> Result<Self, KError> {
        if user_stack_pages == 0 || kernel_stack_pages == 0 {
            return Err(KError::InvalidMapping);
        }
        // Ring-3 stack: user-accessible, not global (a per-process mapping).
        let user_len = user_stack_pages * FRAME_SIZE;
        user_space.map_anonymous(user_stack_base, user_len, PageFlags::rw().user(), frames)?;
        let user_stack_top = VirtAddr::new(user_stack_base.as_u64() + user_len);
        // Kernel stack: the same kind of guarded kernel stack a kernel thread
        // gets, mapped in the shared kernel region.
        let kernel_len = kernel_stack_pages * FRAME_SIZE;
        kernel_space.map_anonymous(
            kernel_stack_base,
            kernel_len,
            PageFlags::rw().global(),
            frames,
        )?;
        let kernel_stack_top = VirtAddr::new(kernel_stack_base.as_u64() + kernel_len);
        // SAFETY: the kernel stack `[kernel_stack_base, kernel_stack_top)` was
        // just mapped read-write and is owned exclusively by this thread, and
        // `user_entry`/`user_stack_top` are the just-mapped user code/stack in
        // the process address space that will be active when it runs.
        let context = unsafe { C::init_user(kernel_stack_top, user_entry, user_stack_top, arg) };
        Ok(Self {
            id: ThreadId::UNASSIGNED,
            user_access: false,
            context,
            state: ThreadState::Ready,
            priority: DEFAULT_PRIORITY,
            correlation: 0,
            blocked_deadline: None,
            stack_base: kernel_stack_base,
            stack_pages: kernel_stack_pages,
            space_root: Some(space_root),
            process: Some(process),
            exception: ExceptionSlot::empty(),
        })
    }
}

impl<C: ContextOps> Thread<C> {
    /// Assigns this thread's identity. The scheduler that admits it is the only
    /// caller — see [`ThreadId`] for why it is not the creator's to choose.
    pub(crate) fn set_id(&mut self, id: ThreadId) {
        self.id = id;
    }

    pub fn id(&self) -> ThreadId {
        self.id
    }

    pub fn state(&self) -> ThreadState {
        self.state
    }

    pub fn set_state(&mut self, state: ThreadState) {
        self.state = state;
    }

    /// The thread's effective scheduling priority.
    pub fn priority(&self) -> u8 {
        self.priority
    }

    /// Sets the effective priority (used to carry a caller's priority to a
    /// callee for a synchronous call's duration).
    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    /// The causal id this thread's work currently belongs to.
    pub fn correlation(&self) -> u64 {
        self.correlation
    }

    /// Sets the causal id (an origin minting for this thread, or a synchronous
    /// call carrying the caller's id to a callee for the call's duration).
    pub fn set_correlation(&mut self, correlation: u64) {
        self.correlation = correlation;
    }

    /// Whether this thread was inside a validated user copy when it last left
    /// the CPU — see the field.
    pub fn user_access(&self) -> bool {
        self.user_access
    }

    /// Records it. Written by `Scheduler::switch_to` and by nothing else: it
    /// is a snapshot of a per-CPU register taken at the one moment the thread
    /// stops being the one that register describes.
    pub fn set_user_access(&mut self, allowed: bool) {
        self.user_access = allowed;
    }

    /// The top of this thread's kernel stack — where a ring-3→ring-0
    /// transition (syscall entry, fault) lands. For a kernel thread this is the
    /// top of its only stack.
    pub fn kernel_stack_top(&self) -> VirtAddr {
        VirtAddr::new(self.stack_base.as_u64() + self.stack_pages * FRAME_SIZE)
    }

    /// Overrides the page-table root the thread resumes under. Normally set by
    /// [`spawn_user`](Self::spawn_user); the perf harness uses it to force a
    /// cross-address-space context switch between kernel threads (to measure the
    /// CR3-load cost) without entering ring 3.
    pub fn set_space_root(&mut self, space_root: Option<PhysAddr>) {
        self.space_root = space_root;
    }

    /// The page-table root (CR3-class) the thread runs under, or `None` for a
    /// kernel thread.
    pub fn space_root(&self) -> Option<PhysAddr> {
        self.space_root
    }

    /// The owning process, for a user thread; `None` for a kernel thread.
    pub fn process(&self) -> Option<ObjectId> {
        self.process
    }

    /// A copy of the saved context (for seeding a switch target).
    pub fn context(&self) -> C::Context {
        self.context
    }

    /// A pointer to the saved context, for the architecture switch to write
    /// (outgoing) or read (incoming).
    pub fn context_ptr(&mut self) -> *mut C::Context {
        &mut self.context
    }

    /// The thread's preallocated exception slot.
    pub fn exception_slot(&mut self) -> &mut ExceptionSlot {
        &mut self.exception
    }

    /// The unmapped guard page just below the stack; a fault here is a stack
    /// overflow.
    pub fn guard_page(&self) -> VirtAddr {
        VirtAddr::new(self.stack_base.as_u64() - FRAME_SIZE)
    }

    /// Total usable kernel-stack bytes (excluding the guard page).
    pub fn stack_bytes(&self) -> u64 {
        self.stack_pages * FRAME_SIZE
    }

    /// The base (low address) of this thread's kernel stack. Reclaim frees
    /// `[base, base + stack_bytes())` — the mapping `spawn`/`spawn_user`
    /// installed — when the thread is reaped (docs/kernel/05).
    pub fn kernel_stack_base(&self) -> VirtAddr {
        self.stack_base
    }
}

#[cfg(test)]
#[path = "tests/thread.rs"]
mod tests;
