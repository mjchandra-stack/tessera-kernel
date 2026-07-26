// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The porting-layer trait surface. The kernel core is generic over these
//! (static dispatch — the mock substitution for host tests is a type
//! parameter, not a link trick), so architecture leakage into the core is
//! a build error, not a review catch.

use crate::addr::{PhysAddr, VirtAddr};

/// Polled early console for boot-time and panic output. Must work before
/// memory management and interrupts exist and remain usable inside the
/// panic path.
pub trait EarlyConsole {
    fn write_bytes(&mut self, bytes: &[u8]);
}

/// Outcome reported when the kernel leaves a test or CI run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitCode {
    Success,
    Failure,
}

/// Terminating the platform (test/CI environments only — a debug exit
/// device or equivalent). Real hardware without such a device implements
/// this as a halt loop.
pub trait PlatformExit {
    fn exit(code: ExitCode) -> !;
}

/// Minimal per-CPU operations.
pub trait CpuOps {
    /// Identifier of the executing CPU, dense from 0.
    fn cpu_id() -> u32;
    /// Sleep until the next interrupt (the idle loop's core).
    fn halt_until_interrupt();
    /// A hardware random word for boot-time layout randomization, or `None`
    /// if the CPU offers no entropy source. This is a raw entropy tap for
    /// early KASLR only; general randomness flows through the kernel CSPRNG
    /// (docs/lifecycle/04-coding-guidelines.md, "Time And Secrets").
    fn hw_random() -> Option<u64>;

    /// A monotonic, invariant cycle- or tick-counter reading, ordered against
    /// the instructions around it so a region can be timed by the difference
    /// of two readings.
    ///
    /// The counter's *unit* is deliberately unspecified: x86-64's TSC counts
    /// at a fixed rate related to the core clock, while AArch64's `CNTVCT_EL0`
    /// counts at the system-counter frequency, which is typically far lower.
    /// Callers that need real time divide by [`counter_hz`](Self::counter_hz);
    /// callers that only need a difference — the observability timestamp, the
    /// correlation epoch — need neither.
    ///
    /// The serialization is the load-bearing part.
    /// docs/prototypes/01-ipc-benchmark-harness.md requires the counter to be
    /// read "with serialization before and after the measured region",
    /// because without it an out-of-order core will happily move the read
    /// across the work being measured.
    fn counter_serialized() -> u64;

    /// Frequency of [`counter_serialized`](Self::counter_serialized) in Hz, or
    /// `None` where the architecture does not report one and it must be
    /// calibrated instead.
    fn counter_hz() -> Option<u64>;
}

/// Saving and restoring a thread's execution context (the callee-saved
/// register set and stack pointer). The kernel core's scheduler is generic
/// over this; the actual register moves are architecture assembly.
///
/// `init`/`switch` are declared `unsafe` because they are genuine
/// capabilities (writing a raw stack, swapping the running stack); the
/// operations themselves live in the ports.
pub trait ContextOps {
    /// Opaque saved-context storage for this architecture. A freshly
    /// [`init`](ContextOps::init)ialized value, or one written by a prior
    /// [`switch`](ContextOps::switch), is the only valid input to `switch`.
    type Context: Copy;

    /// An empty placeholder context — the storage the *currently running*
    /// execution saves itself into on its first switch away. Valid only as a
    /// `switch` *source* until it has been written; never switch *to* one
    /// that has not yet been saved into.
    fn empty() -> Self::Context;

    /// Builds an initial context so that the first switch *into* it begins
    /// executing `entry(arg)` on the kernel stack topped by `stack_top`.
    /// `entry` must never return (it exits the thread instead).
    ///
    /// # Safety
    ///
    /// `stack_top` must be the top of a valid, exclusively-owned,
    /// suitably-aligned kernel stack with room for the initial frame.
    unsafe fn init(
        stack_top: VirtAddr,
        entry: extern "C" fn(usize) -> !,
        arg: usize,
    ) -> Self::Context;

    /// Saves the current execution context into `*prev` and resumes the one
    /// in `*next`. Does not return to the caller until something later
    /// switches back into `*prev`.
    ///
    /// # Safety
    ///
    /// Both pointers must reference valid `Context` storage; `*next` must
    /// have been produced by `init` or a prior `switch`. The caller must own
    /// both contexts and ensure the target stack is mapped.
    unsafe fn switch(prev: *mut Self::Context, next: *const Self::Context);

    /// Prepares the CPU to resume a thread, *before* the `switch` into it: sets
    /// the kernel stack the ring-3→ring-0 transitions (syscall entry, faults)
    /// will use to `kernel_stack_top`, and — for a user thread — loads its address
    /// space `space_root` (a CR3/TTBR-class root). `space_root` is `None` for a
    /// kernel thread, which runs in whatever address space is active (the
    /// kernel is mapped in all of them). Default: no-op, for ports/hosts with
    /// no privilege boundary yet.
    ///
    /// # Safety
    ///
    /// `kernel_stack_top` must top a valid kernel stack owned by the resuming thread;
    /// `space_root`, if `Some`, must be a live top-level page-table root that
    /// maps the kernel.
    unsafe fn prepare_resume(_kernel_stack_top: VirtAddr, _space_root: Option<PhysAddr>) {}
}

/// Entering an unprivileged execution level — the part of context handling
/// that only exists once a port has a user/kernel boundary.
///
/// This is separate from [`ContextOps`] rather than part of it because the
/// two are reached at different times in a port's life. Everything in
/// `ContextOps` is needed as soon as a port can run kernel threads at all;
/// dropping to user mode needs exception vectors, a syscall entry path, and a
/// per-process address space first. Splitting them lets a port implement the
/// kernel half completely and honestly, instead of supplying an `init_user`
/// that exists only to satisfy a bound and would panic or corrupt state if
/// anything called it. A port that does not implement this trait cannot
/// spawn a user thread — enforced at compile time, not by a comment.
pub trait UserContextOps: ContextOps {
    /// Builds an initial context for a **user** thread: the first switch into
    /// it runs on the kernel stack topped by `kstack_top`, then transitions to
    /// the unprivileged level at `user_entry` with user stack `user_stack_top`
    /// and `arg` in the first argument register. The user code and stack must
    /// be mapped in the address space that will be active when this thread
    /// first runs.
    ///
    /// # Safety
    ///
    /// `kstack_top` must top a valid, exclusively-owned kernel stack with room
    /// for the initial frame; `user_entry`/`user_stack_top` must be valid,
    /// user-accessible mappings in the thread's address space.
    unsafe fn init_user(
        kstack_top: VirtAddr,
        user_entry: VirtAddr,
        user_stack_top: VirtAddr,
        arg: usize,
    ) -> Self::Context;
}

/// Local interrupt masking. Enable/disable pairs are the caller's
/// responsibility; this milestone runs the boot CPU only.
pub trait InterruptControl {
    fn enable();
    fn disable();
    fn are_enabled() -> bool;
}

/// The boot CPU's periodic tick source.
pub trait TimerControl {
    /// Start a periodic tick at `hz`. Requires interrupt delivery to be
    /// initialized first.
    fn start_periodic(hz: u32);
    /// Ticks observed since `start_periodic`.
    fn ticks() -> u64;
}
