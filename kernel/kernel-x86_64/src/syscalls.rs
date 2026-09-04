// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! This port's **one** syscall implementation, and the seam a check watches it
//! through.
//!
//! Every check here used to install a handler of its own — sixteen
//! registrations over eight functions, each answering the trap with its own
//! subset of the ABI. That is where D298's divergences lived: `ChannelRecv`
//! ignoring the args struct the message lands in, `PortWait` ignoring the
//! register a `PortEventRecord` goes in, `PageSupply` meaning something else
//! entirely. None of them was a *decision* to answer a call differently; each
//! was a second implementation drifting from the first, which is what a second
//! implementation does.
//!
//! AArch64 has had the answer since D79: one `el0_dispatch_hook` that builds a
//! `DispatchEnv`, calls `kcore::dispatch`, and keeps only the arms the shared
//! dispatcher cannot answer — the loader trio, `DebugWrite`, `ProcessExit`, and
//! what is genuinely arch-coupled. `loader::syscall_handler` said as much in a
//! comment: the channel arms stay local *"until the observer seam lands"*.
//!
//! This is that seam. A check registers an [`Observer`], which is told what was
//! called and what it answered **after** the answer is decided, and can record
//! anything it likes — never change it. What a check cannot do any more is
//! implement a syscall.
//!
//! Normative: docs/api/01-system-call-interface.md,
//! docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

use crate::*;
use kcore::dispatch::{DispatchEnv, DispatchOutcome, SyscallRequest, dispatch};
use tessera_karch::FrameSource;

/// When an observer is being told.
///
/// **Two phases, because some of what a check measures is a difference.** The
/// channel demo's round trip is "how many context switches did this call take",
/// which is a reading before and a reading after; an observer told only the
/// answer could not compute it, and that is exactly the kind of thing a check
/// used to reach for by writing its own copy of the syscall.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The call has arrived and nothing has been decided.
    Entered,
    /// The answer, as the caller will receive it.
    Answered(i64),
}

/// What a check wants to see of its ring-3 program's syscalls: the phase, the
/// call, and the frame it arrived on.
///
/// Told rather than asked. An observer that could change the answer would be a
/// handler with a different name, and the thing this module exists to remove is
/// a second handler.
pub(crate) type Observer = fn(Phase, SyscallNumber, &SyscallFrame);

/// The check currently watching. One, because one check runs at a time.
static mut OBSERVER: Option<Observer> = None;

/// Watch every syscall for the rest of this check.
pub(crate) fn set_observer(observer: Observer) {
    // SAFETY: the boot CPU alone, before the check's ring-3 threads run.
    unsafe { OBSERVER = Some(observer) };
}

/// Stop watching. Called when a check ends, so the next one does not inherit a
/// predecessor's sinks — the failure mode a global handler had and a global
/// observer would keep.
pub(crate) fn clear_observer() {
    // SAFETY: the boot CPU alone, after the check's ring-3 threads are off-CPU.
    unsafe { OBSERVER = None };
}

fn observe(phase: Phase, number: SyscallNumber, frame: &SyscallFrame) {
    // SAFETY: the boot CPU alone; set before ring 3 runs and cleared after.
    if let Some(observer) = unsafe { *(&raw const OBSERVER) } {
        observer(phase, number, frame);
    }
}

/// Tell the watching check a call has arrived.
pub(crate) fn entering(number: SyscallNumber, frame: &SyscallFrame) {
    observe(Phase::Entered, number, frame);
}

/// The boot frame allocator a check published for its run.
static mut FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> = core::ptr::null_mut();

/// A source that refuses, for a check that published none.
static mut NO_FRAMES: NoFrames = NoFrames;

/// Lend the boot allocator to the syscall path for the rest of this check.
///
/// A driver mapping its register window needs page tables built *inside* the
/// syscall, which is why a check publishes one at all. Two checks published one
/// through two different statics before D299, for no reason but the order they
/// were written in — and a third built its environment with `NoFrames` because
/// it did not know either of them existed.
pub(crate) fn publish_frames(frames: &mut kcore::pmem::BumpFrameAllocator<'static>) {
    // SAFETY: the boot CPU alone, before the check's ring-3 threads run.
    unsafe { FRAMES = core::ptr::from_mut(frames) };
}

/// Take it back. The pointer outlives nothing: a check that ended must not
/// leave the next one's syscalls pointed at a borrow that has gone.
pub(crate) fn withdraw_frames() {
    // SAFETY: the boot CPU alone, after the check's ring-3 threads are off-CPU.
    unsafe { FRAMES = core::ptr::null_mut() };
}

/// The published allocator, or the one that refuses.
pub(crate) fn frames() -> &'static mut dyn FrameSource {
    // SAFETY: the boot CPU alone; published before ring 3 runs and withdrawn
    // after the last thread is off-CPU.
    let published = unsafe { *(&raw const FRAMES) };
    if published.is_null() {
        // SAFETY: a zero-sized refusing source, valid for the program's life.
        return unsafe { &mut *(&raw mut NO_FRAMES) };
    }
    // SAFETY: published from a live borrow that outlives the run, and only this
    // CPU dereferences it.
    unsafe { &mut *published }
}

/// This machine, as the shared dispatcher needs to be told about it.
///
/// Built in one place rather than copied into each caller. Every field is a
/// fact about this port, and a caller that assembled its own could get one
/// wrong without anything saying so — which is the whole reason this module
/// exists. The router is the caller's because it must outlive the borrow, and
/// there is nowhere else for a zero-sized value to live.
///
/// SAFETY: the boot CPU alone; EXEC/PROCESSES are populated before any ring-3
/// thread runs and touched only on this CPU. A blocking channel op — or a
/// page-in taken inside a fault — parks the caller's frame, these borrows
/// included, on the blocked thread's kernel stack, and nothing dereferences
/// them until the handoff returns.
fn machine(
    caller: kcore::thread::ThreadId,
    router: &mut PicRouter,
) -> DispatchEnv<'_, KernelAddressSpace, ContextSwitch> {
    // SAFETY: as above.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    DispatchEnv {
        exec: exec_ref(),
        processes,
        caller,
        alloc: frames(),
        // No IOMMU is wired on this port, so no device has an aperture and
        // every DMA grant is unscoped — and says so (D121).
        iommu: None,
        // The legacy PIC, which this port's device interrupts arrive through
        // (D87 tracks replacing it). Present rather than `None` because an
        // interrupt route dropped from the graph but left unmasked at the
        // controller is the half-teardown the seam exists to prevent.
        irqs: Some(router),
        clock: crate::loader::monotonic_nanos,
    }
}

/// Answer one syscall through the shared dispatcher, in this port's
/// environment.
pub(crate) fn shared(caller_idx: kcore::thread::ThreadId, frame: &SyscallFrame) -> DispatchOutcome {
    let req = SyscallRequest {
        number: frame.number,
        args: [
            frame.arg0, frame.arg1, frame.arg2, frame.arg3, frame.arg4, frame.arg5,
        ],
    };
    let mut router = PicRouter;
    let mut env = machine(caller_idx, &mut router);
    dispatch(&mut env, &req)
}

/// Resolve one ring-3 page fault through the shared dispatcher, in the same
/// environment.
///
/// **A fault is the other way into the dispatcher**, and until now this port
/// had no road from one to the other: `dpage`'s resolver repairs what it can
/// against the process table and grants a write to a clean pager page *without
/// the dirty accounting*, because it holds no `Executive` to record it in. A
/// page written that way is one the kernel believes unchanged — a write-back
/// never persists it and eviction throws it away — which is exactly why every
/// object handed to a client on this port has been read-only.
///
/// What only this port knows stays here: that the faulting address is in CR2,
/// that `#PF` error-code bit 1 says the access was a store, and which thread
/// was running. The classification, the repair, the page-in and the software
/// dirty bit are `kcore::dispatch`'s, shared with every other port.
///
/// **A page-in blocks inside this call.** The faulting thread parks on the
/// request to its object's pager and this frame parks with it on that thread's
/// kernel stack, exactly as a blocking channel syscall does.
pub(crate) fn shared_page_fault_resolver(frame: &mut TrapFrame) -> bool {
    let Some(caller) = chan_current_id() else {
        return false;
    };
    let va = VirtAddr::new(tessera_karch_x86_64::read_cr2());
    // `#PF` error-code bit 1: the access that faulted was a write.
    let write = (frame.error_code & 0b10) != 0;
    let mut router = PicRouter;
    let mut env = machine(caller, &mut router);
    kcore::dispatch::resolve_user_fault(&mut env, va, write)
        == kcore::dispatch::FaultVerdict::Resume
}

/// Tell the watching check what the call answered, and answer it.
pub(crate) fn answer(number: SyscallNumber, frame: &SyscallFrame, result: i64) -> i64 {
    observe(Phase::Answered(result), number, frame);
    result
}
